"""Finding generation for the management-channel control. PAN-HAP-005.

ONE CONTROL, TWO ASSERTIONS, TWO SEVERITIES, ONE ROW. Stage 3 wrote PAN-HAP-005 as two halves -
the firewall names every management appliance it is meant to reach (medium), and the channel to
them uses the customer's own certificate material with peer-name validation (low) - and a finding
is one row per control. The hardening half is the control's BASELINE TIER and the redundancy half
is a CALIBRATION above it, so either can match alone and a row failing both is reported at the
higher tier: `derive_control_query_severity_value` discards the baseline tier the moment a
calibration matches and takes the worst one. The sentence below describes whichever halves
matched, and `matched_query_names` on the row says which.

SO A ROW CAN CARRY BOTH HALVES' PROSE AND ONE SEVERITY. That is the honest shape rather than a
defect: the severity names the worse gap and the sentence names both, because suppressing the
gentler half's sentence would leave a reader with a medium finding and no account of the
certificate posture the same row also fails.

THREE THINGS THE SENTENCE IS NOT ALLOWED TO SAY, each from a measurement:

* THAT THE CHANNEL IS AUTHENTICATED, OR COULD BE MADE SO FROM THE FIREWALL. Custom Certificate
  Only and Check Authorization List are `secure-conn-server` leaves on the management appliance
  and exist on no firewall - verified mechanically by stage 2, which found the two switches
  present on Panorama and absent on both firewall platforms. So even all three firewall-side
  switches on leaves the appliance still able to accept the certificate every appliance of this
  make ships with, and every finding here says which part needs the station.
* THAT THE FIREWALL CHECKS WHO IS TALKING TO IT. `check-server-identity` is the FIREWALL checking
  the STATION's certificate common name against the configured address. The control's own words
  say "client identity verification", which is the appliance checking the firewall and lives on
  Panorama - a sentence reading this leaf for the control's words would report the wrong
  direction of trust as satisfied.
* THAT A SECOND MANAGEMENT ADDRESS IS MISSING WHEN THE ESTATE HAS ONE APPLIANCE.
  `management_estate_is_a_pair` is TRUE BY DEFAULT and false by nothing: the answer lives on the
  management station's own high-availability node, which `rules.md` puts out of assessment scope,
  so only an engineer can set it. True is the applying side - a false would suppress the control
  on every firewall - and the consequence is explicit on the row: on a single-appliance estate
  this fires everywhere and its remediation is wrong. The sentence says so rather than leaving a
  reader to find out.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_panorama_registration_control_queries
from assessments.models import (
    Control, PanoramaRegistrationFinding, PanoramaRegistrationFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import PanoramaRegistration

#: Said on every row of this control, whichever half fired. The half no firewall can answer.
STATION_HALF = ("the management appliance's own half of this is UNANSWERED and no firewall can "
                "answer it: whether it accepts only customer-issued certificates, and whether it "
                "checks each firewall against an authorization list, are switches on the station")

#: Said wherever the pair applicability decided the row. Not a caveat on the measurement - a
#: statement that the predicate was defaulted rather than read.
PAIR_ASSUMED = ("the control applied because the management estate was ASSUMED to be a redundant "
                "pair: that answer lives on the management appliance's own configuration, which "
                "is out of assessment scope, so no firewall can supply it and an engineer's "
                "answer should override it. On a single-appliance estate this finding's "
                "remediation would point a firewall at an appliance that does not exist")


def _not_collected(obj) -> list[str]:
    """The coverage sentence: we could not see, rather than you are wrong."""
    return ["the `local-panorama` and `secure-conn-client` subtrees were not collected for this "
            "appliance, so nothing here is a statement about its configuration - this reports "
            "that the setting was NOT ESTABLISHED, and it is cleared by collecting the appliance "
            "rather than by changing anything on it"]


def _redundancy(obj) -> list[str]:
    if obj.panorama_server_secondary:
        return []
    if not obj.management_config_collected:
        return _not_collected(obj)
    if not obj.panorama_server_primary:
        head = ("this firewall names NO management appliance at all - both address slots on "
                "`deviceconfig/system/panorama/local-panorama` are empty - so it is centrally "
                "managed by nothing")
    else:
        head = ("this firewall names ONE management appliance and the second address slot is "
                "empty, so losing that appliance takes central policy, central logging and "
                "central visibility with it. The firewall keeps passing traffic perfectly well, "
                "which is why nobody notices until a change has to be pushed or an "
                "investigation needs logs that were never collected")
    return [head, PAIR_ASSUMED]


def _hardening(obj) -> list[str]:
    if not obj.management_channel_not_hardened:
        return []
    if not obj.management_config_collected:
        return _not_collected(obj)
    if obj.client_certificate_type == PanoramaRegistration.CERTIFICATE_TYPE_LOCAL \
            and obj.client_certificate_name:
        bound = (f"a device certificate is bound ({obj.client_certificate_name})")
    elif obj.client_certificate_type == PanoramaRegistration.CERTIFICATE_TYPE_NONE:
        bound = ("no device certificate is bound: the `certificate-type` choice node holds its "
                 "`none` branch, which is the vendor's documented default stored as a present "
                 "key - the same meaning as an absent key and a different stored state")
    elif not obj.client_certificate_type:
        bound = ("no device certificate is bound: the `secure-conn-client` node or its "
                 "`certificate-type` key is absent")
    else:
        bound = (f"the device certificate type is `{obj.client_certificate_type}` and no local "
                 f"certificate is bound")
    missing = []
    if obj.secure_panorama_communication_enabled is not True:
        missing.append("no surface is switched to use a custom certificate for the management "
                       "connection (`enable-secure-panorama-communication`)")
    if obj.check_server_identity_enabled is not True:
        missing.append("the firewall does not check that the appliance answering is the one it "
                       "was told to reach (`check-server-identity`) - which is the firewall "
                       "validating the STATION's name, and not the station validating the "
                       "firewall")
    detail = bound
    if missing:
        detail += ", and " + "; ".join(missing)
    detail += (". So the management conversation runs on the predefined certificate pair every "
               "appliance of this make ships with, and anything holding those certificates can "
               "stand in the middle of it")
    # Said wherever the two nullable switches were never read, because their null is the
    # firing side here and a reader has to know which it is. No firewall-side oracle reports
    # either one: `show system state filter *panorama*` answers NO_MATCHES.
    if obj.secure_panorama_communication_enabled is None \
            or obj.check_server_identity_enabled is None:
        detail += (". The two switches are ABSENT from the configuration rather than read as "
                   "off, and no firewall-side reading reports what the connection actually "
                   "used, so this rests on the configuration's shape")
    return [detail, STATION_HALF]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. One control here and both halves mapped to it,
#: because either query can be the one that matched and a row can fail both. Each builder returns
#: nothing where its own half is satisfied, so a row carries only the prose of the halves it
#: actually fails - never the other half's remediation.
PARTS_BY_CONTROL = {
    "PAN-HAP-005": (_redundancy, _hardening),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"management channel on {obj.appliance}"]
    builders = PARTS_BY_CONTROL.get(control_id, (_redundancy, _hardening))
    for build in builders:
        parts.extend(build(obj))
    if len(parts) == 1:
        parts.extend(_not_collected(obj))
    return "; ".join(parts)


def build_panorama_registration_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="panorama registration",
    control_type=Control.ControlType.PANORAMA_REGISTRATION,
    finding_model=PanoramaRegistrationFinding,
    link_model=PanoramaRegistrationFindingControlQuery,
    subject_fk="panorama_registration",
    link_fk="panorama_registration_finding",
    queryset=lambda: PanoramaRegistration.objects.select_related("appliance"),
    evaluate=evaluate_panorama_registration_control_queries,
    summary=build_panorama_registration_finding_summary,
    subject_name=lambda obj: str(obj.appliance),
)


def generate_panorama_registration_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_panorama_registration_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
