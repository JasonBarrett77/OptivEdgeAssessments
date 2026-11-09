"""Finding generation for one SSL decryption exclusion the organization added. PAN-DEC-004.

ONE CONTROL AND ONE OF ITS TWO RECORDS. The half this module reports is that every exclusion the
organization added itself names, in writing on the entry, the application it protects and when the
exclusion is next due to be rechecked. The other half - that every departure from the VENDOR's
supplied list is deliberate and current - is a conclusion about a DIFFERENT model, and
`probe.relation_between SslDecryptionExclusion SslDecryptionVendorExclusionOptOut` finds no relation
between the two in either direction, so no query at either grain can carry both. That half is
silent; `ssl_decryption_vendor_exclusion_optout_findings` beside this file says what it would say
and why no estate can make it fire today.

WHY THIS HALF OWNS THE CONTROL ID rather than the other: the catalog row's own severity is medium
and its `minimum_value_descr` is "Local compatibility exclusions (certificate-pinned apps)
inventoried with owner and recheck date", which is stage 3's record 0 - this one. Record 1 is the
`preferred_gap_severity` half at low. Splitting PAN-DEC-004 into two catalog ids changes what a
customer's report contains and is not a build run's decision.

THE DISPATCH DEFAULTS TO `()`, the safe convention, even with one control on this type: the reason
a non-empty default is a hazard is that it fires for a control somebody ADDS later, and the type
having one control today is exactly when that is invisible.

WHAT A READER OF THIS FINDING HAS TO BE TOLD, and every sentence below carries it: the screen an
operator opens renders the organization's own exclusions AND the vendor's 330 or 385 in ONE grid,
distinguished only by a Location column. This finding only ever names the organization's own, so an
operator who counts rows on the screen and rows in the report will not get the same number - and the
vendor's entries would fail the date half of this assertion anyway, measured: all 385 carry a
description naming the application and the mechanism, and NOT ONE carries a date.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_ssl_decryption_exclusion_control_queries
from assessments.models import (
    Control,
    SslDecryptionExclusionFinding,
    SslDecryptionExclusionFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import SslDecryptionExclusion


def _no_stated_reason(obj) -> list[str]:
    """PAN-DEC-004's first record: the entry carries no reason text."""
    switched = (
        "it is IN FORCE" if obj.exclude
        else "it is SWITCHED OFF, which does not change this verdict - an entry somebody switched "
             "off is still an entry somebody should be able to account for, and the enable switch "
             "is deliberately not part of this assertion")
    return [
        "THIS EXCLUSION CARRIES NO DESCRIPTION, so nothing on the entry names the application it "
        "protects or when anybody is due to check whether it is still needed. The entry's own "
        f"text is the only on-box record there is, and {switched}",
        "AN EXCLUSION WITH NO STATED REASON CANNOT BE RETIRED, which is the harm: nobody who did "
        "not create it can tell whether the application still fails when the session is opened, "
        "so an accommodation granted for one broken product survives every vendor fix that would "
        "have let it be removed. Certificate pinning is exactly the behavior vendors drop",
        "THIS IS THE ORGANIZATION'S OWN LIST AND NOT THE VENDOR'S. The vendor ships 330 or 385 "
        "entries of its own at a different path, they update with content, and they are invisible "
        "to the read behind this row - while the web interface renders BOTH collections in ONE "
        "grid distinguished only by a Location column. So the screen shows more entries than this "
        "report names, and the vendor's own entries would fail the DATE half of this assertion "
        "anyway: measured, all of them carry a description naming the application and the "
        "mechanism and not one carries a date",
        "AND WHETHER A PRESENT REASON IS STILL TRUE IS THE APPLICATION OWNER'S ANSWER. What is "
        "delivered here is which locally added entries carry no reason text at all; the firewall "
        "cannot tell a current accommodation from one whose vendor has since dropped the "
        "behavior that caused it",
    ]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. The default is `()`.
PARTS_BY_CONTROL = {
    "PAN-DEC-004": (_no_stated_reason,),
}


def _where(obj) -> str:
    return f"{obj.scope}:{obj.vsys_name}" if obj.vsys_name else obj.scope


def _subject(obj, control_id: str) -> str:
    parts = [
        f"SSL decryption exclusion {obj.name} in the {_where(obj)} scope of "
        f"{obj.appliance.hostname}"
    ]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_ssl_decryption_exclusion_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="SSL decryption exclusion",
    control_type=Control.ControlType.SSL_DECRYPTION_EXCLUSION,
    finding_model=SslDecryptionExclusionFinding,
    link_model=SslDecryptionExclusionFindingControlQuery,
    subject_fk="ssl_decryption_exclusion",
    link_fk="ssl_decryption_exclusion_finding",
    queryset=lambda: SslDecryptionExclusion.objects.select_related("appliance"),
    evaluate=evaluate_ssl_decryption_exclusion_control_queries,
    summary=build_ssl_decryption_exclusion_finding_summary,
    # THE ONE SUBJECT IN THIS DOMAIN THAT COULD HAVE TAKEN THE DATACLASS DEFAULT: this model
    # inherits `ApplianceScopedObject`, so it DOES have `name`. It is passed explicitly anyway,
    # because stage 5 calls the column `exclusion_name` and the model carries that as a property
    # over this same field - a reader of either spelling should see which one the finding freezes.
    subject_name=lambda obj: obj.name,
    # REQUIRED: the shipped constraint is `(appliance, scope, vsys_name, name)`, so the same server
    # name may be excluded in a vsys AND in the appliance's own shared container, and those are two
    # different entries an operator removes in two different places.
    subject_scope=lambda obj: f"{obj.appliance.hostname} / {_where(obj)}"[:128],
)


def generate_ssl_decryption_exclusion_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_ssl_decryption_exclusion_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
