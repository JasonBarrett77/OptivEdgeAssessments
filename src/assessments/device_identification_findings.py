"""Finding generation for one appliance's device-identification state. PAN-IOT-001, PAN-IOT-003.

TWO CONTROLS, ONE MODEL, AND THEY ASSERT ON DISJOINT COLUMNS. PAN-IOT-001 is about whether there
IS a working means of identifying unadministered equipment - the entitlement and the wiring.
PAN-IOT-003 is about whether the classification data the firewall already holds is current. They
share a row because all three instruments behind it are device-wide, and `PARTS_BY_CONTROL` is
what keeps each finding's sentence to its own control's facts.

THE SENTENCE MUST SAY WHICH FALSE IT IS, which is the whole reason `licence_read_taken` exists.
An appliance holding no entitlement answers `{"licenses": None}` and an appliance nobody asked
produces exactly the same reply, so `device_id_licensed eq false` alone cannot tell a reader
whether the subscription is absent or the question was never put. Both arms report, at the same
severity, and a row can match both - in which case the report shows two findings about one
appliance rather than one wrong one.

THREE THINGS THE SENTENCE IS NOT ALLOWED TO SAY:

* THAT DELIVERY WAS TESTED. A populated edge-service address proves the WIRING exists and nothing
  more. Stage 4 wrote a `.invalid` hostname that cannot resolve and PAN-OS committed it clean, so
  the finding reports that the firewall is pointed at nothing and never that anything answered.
* THAT THE FEATURE STRING IS RIGHT. `device_id_licensed` rests on an exact match against a
  candidate set, `IOT_SECURITY_FEATURE_NAMES` in the normalizer, and NO APPLIANCE IN THE LAB
  HOLDS THE ENTITLEMENT - so no run has ever read the literal the vendor uses for it. The failure
  direction is the safe one, because a wrong or absent string leaves the column false and
  FIRING; but it fires on every appliance in every estate until the string is right, and the
  sentence says so rather than asserting a subscription is missing.
* HOW FAR BEHIND THE CURRENT RELEASE THE CONTENT IS. `device_dictionary_age_days` is the AGE of
  what is installed, counted from its own reported release date. The comparator - what the vendor
  is publishing NOW - is on no firewall read at all, so during a quiet publishing period a
  current appliance ages into a finding with nobody touching it. That limit is stage 5's and the
  sentence carries it.

AND THE INSTRUMENT THAT DISAGREES IS PRINTED BESIDE THE ONE THAT IS GRADED. `show iot icd
version` answers on all four lab appliances where the release date answers on two, and it ranks
the estate in the OPPOSITE order: its TimeBuilt is 2026-02-06 on the two PA-5220s against
2024-07-22 on pan-fw-111, while the content version is 82-406 on those PA-5220s against 249-772
on pan-fw-111 - a gap of 167 content releases. Grading on TimeBuilt would call the two most stale
appliances in the lab the freshest in it. Neither instrument is ranked above the other: one is
graded and the other is presented, so a reader can see the disagreement and check the finding.

THE SECOND HALF OF PAN-IOT-003 IS IN NO COLUMN AND NO SENTENCE CLAIMS IT. Whether new releases
arrive without anyone fetching them is an engineer's answer: the firewall's own content schedule
has no entry for this content type at all, so a configuration read cannot distinguish automatic
delivery from a change-controlled manual process.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_device_identification_control_queries
from assessments.models import (
    Control,
    DeviceIdentificationFinding,
    DeviceIdentificationFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import DeviceIdentificationState


def _entitlement(obj) -> list[str]:
    """PAN-IOT-001's first half: is there a paid-up means of identifying devices at all."""
    if obj.device_id_licensed:
        return []
    if not obj.licence_read_taken:
        # The honest arm. Do NOT report a missing subscription here: nobody asked.
        return [
            "NOBODY ASKED WHETHER THIS APPLIANCE IS ENTITLED: the license listing was never "
            "taken for it, so this is not a reading that the subscription is absent. The two "
            "are indistinguishable in the reply - an appliance holding nothing licensed answers "
            "exactly what an appliance nobody asked answers - and this column is the only thing "
            "that separates them",
        ]
    return [
        "no in-force entitlement for the vendor's device-identification service was found on "
        "this appliance: the license listing was taken and carries no unexpired row for that "
        "feature. The vendor returns NO ROW for an entitlement an appliance does not hold, so "
        "this is the absence of a row rather than a row reporting `expired`",
        "the match that establishes this is against a candidate set of feature names and NOT "
        "against a literal anybody has read - no appliance available to this project holds the "
        "entitlement, so the exact string the vendor uses for it is unmeasured. A wrong string "
        "leaves this reporting rather than passing, which is the safe direction and is also why "
        "a first estate should confirm the name before acting on a fleet of these",
    ]


def _wiring(obj) -> list[str]:
    """PAN-IOT-001's second half: is the subscription actually feeding the firewall."""
    if obj.edge_service_address:
        return []
    return [
        "and this appliance is pointed at no device-identification edge service: the "
        "configuration node that carries the service address holds nothing, so the firewall "
        "sends the service no traffic records and retrieves no device mappings from it",
        "THIS REPORTS THE WIRING AND NOT DELIVERY. A populated address would prove only that "
        "the configuration exists: an unresolvable hostname commits clean on this platform, so "
        "nothing here establishes that anything at the far end ever answered",
    ]


def _currency(obj) -> list[str]:
    """PAN-IOT-003's first half: is the installed classification data current."""
    if not obj.device_dictionary_release_date_known:
        parts = [
            "THE CURRENCY OF THIS APPLIANCE'S DEVICE CLASSIFICATION DATA COULD NOT BE "
            "ESTABLISHED: its own report of the installed content carries no release date, so "
            "there is no date to measure an age against. This is not a statement that the "
            "content is current - a row with no age passes every staleness threshold SQL can "
            "write, which is why it is reported here instead",
        ]
        if obj.device_dictionary_version:
            parts.append(
                f"the content version it does report is {obj.device_dictionary_version}, which "
                f"says which of two appliances is older and never by how long - it is not a date "
                f"and no currency measure can be computed from it alone")
        if obj.icd_built_at or obj.icd_build_version:
            parts.append(
                f"a SECOND instrument does answer on this appliance and it is not comparable "
                f"with the first: the classification-data build reports version "
                f"`{obj.icd_build_version or 'unreported'}` built at "
                f"`{obj.icd_built_at or 'unreported'}`. It is printed because it is the only "
                f"date available here, and it MUST NOT be read as the content's currency - it "
                f"has been measured ranking the most stale appliances in an estate as the "
                f"freshest in it")
        return parts
    if obj.device_dictionary_age_days is None:
        return []
    parts = [
        f"the device classification data installed on this appliance is "
        f"{obj.device_dictionary_age_days} days old, counted from the release date it reports "
        f"itself",
    ]
    if obj.device_dictionary_version:
        parts.append(f"the installed content version is {obj.device_dictionary_version}")
    parts.append(
        "WHAT THIS IS NOT is the distance behind the release the vendor is currently "
        "publishing: nothing on a firewall carries that, so this is the age of what is "
        "installed. The two coincide only while the vendor publishes continuously, and during a "
        "quiet period a perfectly current appliance ages into this finding")
    parts.append(
        "equipment types published since the installed data cannot be matched at all, so rules "
        "written for them are inert and the estate's own device reports understate what is on "
        "the network")
    return parts


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. The two controls share this model and assert on
#: disjoint columns, so a finding that printed every part would tell a reader about a control
#: that did not fire. PAN-IOT-003's second half - whether releases arrive without anyone fetching
#: them - is an engineer's answer with no column, so no part here speaks to it.
PARTS_BY_CONTROL = {
    "PAN-IOT-001": (_entitlement, _wiring),
    "PAN-IOT-003": (_currency,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"device identification on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, (_entitlement, _wiring, _currency)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_device_identification_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="device identification",
    control_type=Control.ControlType.DEVICE_IDENTIFICATION,
    finding_model=DeviceIdentificationFinding,
    link_model=DeviceIdentificationFindingControlQuery,
    subject_fk="device_identification_state",
    link_fk="device_identification_finding",
    queryset=lambda: DeviceIdentificationState.objects.select_related("appliance"),
    evaluate=evaluate_device_identification_control_queries,
    summary=build_device_identification_finding_summary,
    # The appliance, because all three readings are device-wide. No `subject_scope`: a hostname
    # is the scope, and there is no vsys axis on this subject at all.
    subject_name=lambda obj: obj.appliance.hostname,
)


def generate_device_identification_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_device_identification_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
