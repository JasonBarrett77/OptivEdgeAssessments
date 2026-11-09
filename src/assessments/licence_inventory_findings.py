"""Finding generation for one appliance's entitlement set. PAN-PLT-004, both of its halves.

THE FINDING NAMES WHICH HALF FAILED AND WHETHER THE TABLE WAS READABLE AT ALL, because the two
columns this control grades carry different remediations and the unreadable case is neither of
them. A lapsed protection subscription stops a content stream; a lapsed support entitlement stops
software updates and the vendor's help during an incident; an empty license element stops the
question being answerable.

THE EMPTY LICENSE ELEMENT IS THIS DOMAIN'S TRAP AND THE SENTENCE REFUSES TO SMOOTH IT OVER.
`request license info` answers `{"licenses": null}` on both PA-5220s in this estate: the element is
PRESENT and EMPTY, `bool(result)` is true while `bool(result["licenses"])` is false, and
`result["licenses"]["entry"]` raises outright. That is NOT "no licenses are needed" and it is not
"the read failed" either - it is a reply that carried no inventory, and `no_licence_rows_returned`
reports it as that. A customer told their entitlements are fine on the strength of a null element
has been told they are safe on the strength of nothing.

THE SUPPORT HALF IS AN ABSENCE AND AN ABSENCE HAS NO ROW OF ITS OWN, which is the whole reason this
control is stated over a conclusion about the table rather than over `LicenceEntitlement`. No
appliance in this estate carries a support row, so `absent_from_inventory` is the only value
measured - and it is a FINDING rather than a pass, because an absent row cannot be told apart from
a subscription nobody bought, and stage 3's rank 1 consequence is software updates gone until
renewal.

HOW A SUPPORT ENTITLEMENT IS RECOGNIZED, AND WHICH WAY THE ERROR RUNS. The normalizer matches a
word-boundary `support` in the feature name - the same test stage 6 made independently, and it
found nothing on either licensed appliance. A feature name containing `support` that is NOT a
support entitlement would be read as one and move an appliance off a finding and onto a pass, which
is the unsafe direction. It is named here because no appliance in this estate exercises either
reading.

TWO THINGS NO SENTENCE HERE MAY CLAIM:

* THAT AN ENTITLEMENT THE ORGANIZATION ONCE HELD IS VISIBLE. The reply lists what is present, so a
  subscription canceled last year is indistinguishable from one never bought.
* THAT AN UNREADABLE EXPIRY IS SAFE. A live license whose `expires` string no candidate format
  parses lands on the lowest graded band rather than on the passing token, deliberately: the
  vendor's own `expired` flag is read first and covers the failure that matters, so what an
  unreadable date leaves open is only HOW SOON a live entitlement lapses. `Never` is a real answer
  and is not that case.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_licence_inventory_control_queries
from assessments.models import (
    Control,
    LicenceInventoryFinding,
    LicenceInventoryFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import LicenceInventory


def _read_state(obj) -> str:
    """What the license reply was, in a reader's words. Three shapes and only one is an answer."""
    read = obj.licence_inventory_read or ""
    if read == "rows_returned":
        return (f"the license table answered with {obj.licence_row_count} "
                f"row{'s' if obj.licence_row_count != 1 else ''}")
    if read == "null_licenses_element":
        return ("the license table answered with an EMPTY `licenses` element - present and "
                "holding nothing, which is the shape both PA-5220s in this estate return and is "
                "not the same as the read failing")
    if read == "not_collected":
        return ("the license table was NEVER READ on this appliance, so nothing below is a "
                "measurement of what it is entitled to")
    return f"the license table's read state reads `{read or '(empty)'}`, which has no sentence here"


def _entitlements(obj) -> list[str]:
    """PAN-PLT-004 record 0: is every subscription a protection depends on active."""
    state = obj.entitlement_state or ""
    if state == "active_beyond_90_days":
        return []
    parts = [_read_state(obj)]
    if state == "expired_entitlement_present":
        parts.append(
            f"{obj.expired_entitlement_count} entitlement"
            f"{'s' if obj.expired_entitlement_count != 1 else ''} on this appliance "
            f"{'are' if obj.expired_entitlement_count != 1 else 'is'} ALREADY EXPIRED, by the "
            f"vendor's own `expired` flag on the row. The protection that entitlement delivers is "
            f"on a reduced cadence or stopped, and the firewall goes on enforcing with whatever it "
            f"last received - which looks identical to working")
    elif state == "expiring_within_30_days":
        parts.append(
            f"{obj.expiring_within_30_days_count} entitlement"
            f"{'s' if obj.expiring_within_30_days_count != 1 else ''} "
            f"{'lapse' if obj.expiring_within_30_days_count != 1 else 'lapses'} within THIRTY "
            f"DAYS. Nothing has stopped yet, which is why this is graded below the control's own "
            f"severity - what it costs is the lead time a renewal needs")
    elif state == "active_inside_90_days":
        parts.append(
            "an entitlement lapses inside the NINETY-DAY renewal horizon, or a live entitlement's "
            "expiry date could not be parsed at all. Both land here, and the second is why: the "
            "vendor's `expired` flag already covered the failure that matters, so an unreadable "
            "date leaves open only how soon a live entitlement lapses - and this band says that "
            "without asserting a thirty-day claim the device did not support")
    elif state == "no_licence_rows_returned":
        parts.append(
            "SO NO ENTITLEMENT COULD BE CHECKED, and this is reported as a finding rather than as "
            "a pass because the direction of the error decides it: the answer is not `no licenses "
            "are needed`, it is UNKNOWN. It is reported at the control's own severity because the "
            "entitlement that might have lapsed is unknown too")
    elif state == "inventory_not_collected":
        parts.append(
            "SO NO ENTITLEMENT COULD BE CHECKED. An unknown fires: a pass here would tell a "
            "customer their subscriptions are live on the strength of a reply nobody received")
    else:
        parts.append(
            f"this appliance's entitlement state reads `{state or '(empty)'}`, which this "
            f"generator has no sentence for - a token was added to the column and not to this "
            f"control. Treat the verdict as unexplained")
    if obj.entitlement_features_held:
        parts.append("features the table reported: "
                     + ", ".join(str(f) for f in obj.entitlement_features_held))
    return parts


def _support(obj) -> list[str]:
    """PAN-PLT-004 record 1: is the support entitlement active."""
    state = obj.support_entitlement_state or ""
    if state == "active_beyond_90_days":
        return []
    parts = []
    if state == "absent_from_inventory":
        parts.append(
            "NO SUPPORT ENTITLEMENT APPEARS IN THIS APPLIANCE'S LICENSE TABLE AT ALL, and an "
            "absence is reported rather than passed over because it cannot be told apart from a "
            "subscription nobody bought. Without one there are no software updates - so a "
            "vulnerability in PAN-OS itself cannot be patched until the entitlement is renewed - "
            "and no vendor assistance during an incident. HOW THIS IS RECOGNIZED, because the "
            "error runs the unsafe way: a support entitlement is a feature name carrying the word "
            "`support`, so a feature named that way which is NOT one would read as present and "
            "turn this finding into a pass")
    elif state == "expired":
        parts.append(
            "THE SUPPORT ENTITLEMENT ON THIS APPLIANCE IS EXPIRED, by the vendor's own `expired` "
            "flag on the row. Software updates have stopped and so has vendor assistance; the "
            "appliance goes on enforcing at the release it already holds")
    elif state == "expires_within_90_days":
        parts.append(
            "the support entitlement lapses inside the NINETY-DAY renewal horizon. Nothing has "
            "stopped yet, which is why this is graded below the control's own severity")
    elif state == "inventory_not_collected":
        parts.append(
            "the license table was never read, so whether a support entitlement exists is UNKNOWN "
            "rather than absent - and an unknown fires, at the control's own severity, because the "
            "entitlement that might be missing is the one that delivers software updates")
    else:
        parts.append(
            f"this appliance's support entitlement state reads `{state or '(empty)'}`, which this "
            f"generator has no sentence for")
    return parts


def _both_halves(obj) -> list[str]:
    """PAN-PLT-004 is one control stated as two records over one model, so one row carries both.

    EITHER HALF ALONE PRODUCES THIS FINDING, because `evaluate_queryset_control_queries` ORs every
    active query on the control. So a row whose subscriptions are all live and whose support
    entitlement is absent is reported here, and the sentence says which half failed - otherwise a
    reader has to guess from the severity, and the two halves share a severity at three of their
    nine graded placements.
    """
    parts = _entitlements(obj) + _support(obj)
    if not parts:
        return []
    parts.append(
        "WHAT THIS ROW CANNOT SAY: whether this organization ever HELD an entitlement it no longer "
        "holds. `request license info` lists what is present, so a subscription canceled last "
        "year and one never bought are the same absence here, and only the customer's purchase "
        "record separates them")
    return parts


#: One control, one reading. PAN-PLT-004 is the only control over this model, and both of its
#: assertion records land on it - which is why this is one callable over both halves rather than
#: two entries. The control has NO silent half and the stage 8 artifact declares none.
PARTS_BY_CONTROL = {
    "PAN-PLT-004": (_both_halves,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"license inventory on {obj.appliance} (serial {obj.appliance.serial_number})"]
    for build in PARTS_BY_CONTROL.get(control_id, (_both_halves,)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_licence_inventory_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="license inventory",
    control_type=Control.ControlType.LICENCE_INVENTORY,
    finding_model=LicenceInventoryFinding,
    link_model=LicenceInventoryFindingControlQuery,
    subject_fk="licence_inventory",
    link_fk="licence_inventory_finding",
    queryset=lambda: LicenceInventory.objects.select_related("appliance", "appliance_group"),
    evaluate=evaluate_licence_inventory_control_queries,
    summary=build_licence_inventory_finding_summary,
    # A DEVICE-WIDE SINGLETON, so the appliance IS the subject name and this model declares no
    # `subject_scope`. A LICENCE IS PER SERIAL, so on an HA pair the two peers' rows may
    # legitimately differ rather than merely duplicate - which is the one place this subject's
    # two-rows-per-pair shape is a fact and not an artefact.
    subject_name=lambda obj: str(obj.appliance),
)


def generate_licence_inventory_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_licence_inventory_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
