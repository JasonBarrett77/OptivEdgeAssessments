"""Finding generation for one security zone's Device-ID settings. PAN-IOT-002.

THE FIRST CONTROL EVER WRITTEN OVER A ZONE. The model had stored `enable_device_identification`
and both Device-ID ACLs for months and nothing had ever queried them.

TWO HALVES THAT CANNOT BOTH FIRE ON ONE ROW, which is why one finding is never double-counted:
the first half is about a zone where identification is OFF, and the second is only about
narrowing WITHIN a zone where it is on. The second half's applicability clause is the first
half's assertion, inverted.

THE FIRING STATE OF THE SECOND HALF IS A POPULATED LIST, AND A REVIEWER WHO HAS ALREADY SEEN THE
SWITCH ON LOOKS FOR THE OPPOSITE. With no device-acl node the grid renders INCLUDED NETWORKS
`any` and EXCLUDED `none` - identification applies to EVERY address in the zone, which is the
most permissive reading and the COMPLIANT one for this control. So the sentence has to say what
was found and why it is the finding, because "the include list is empty" is the state that passes.

WHAT THE NARROWING HALF IS NOT ALLOWED TO SAY. Stage 3 asserts that the list STILL COVERS the
equipment the zone was enabled for, and NO CONFIGURATION READ CAN ESTABLISH COVERAGE: a member
may be a literal address, a CIDR, an address object or an address GROUP, and nothing on the
firewall says what is plugged in. So the finding reports that identification in this zone is
narrowed and NAMES THE MEMBERS for a reviewer to confirm against the equipment. It does not claim
anything is uncovered.

AND THE REMEDIATION MAY BE ONE THIS FIREWALL REFUSES, in the normal case rather than the edge
one. `Zone` carries no scope, `config_source` or provenance column, so a zone pushed from a
Panorama template is indistinguishable in the row from a firewall-local one. 48 of the 50 zones
measured in the lab are unidentified, and a finding on a pushed zone names a local zone while the
box it tells an engineer to tick can only be ticked where the configuration comes from. The
sentence therefore says where to go rather than asserting the zone is local.

THE COVERAGE QUESTION STAGE 3 NEVER ASKED. Stage 3 records no engineer question on the narrowing
half, so `engineer_answers` was not available as a discharge even though whether the list still
covers the equipment is a question only a person can answer. Named in this domain's stage 8
handback; recorded here because a reader of this module will wonder why the residue has no owner.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_zone_control_queries
from assessments.models import (
    Control,
    ZoneFinding,
    ZoneFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import Zone

#: How many ACL members a finding prints before it stops. The members are what a reviewer checks
#: the narrowing against, so the list is the point of the sentence - but a zone scoped to a long
#: literal list would otherwise push the summary past anything readable.
_MEMBER_PRINT_LIMIT = 12


def _members(values) -> str:
    values = list(values or [])
    shown = ", ".join(f"`{value}`" for value in values[:_MEMBER_PRINT_LIMIT])
    if len(values) > _MEMBER_PRINT_LIMIT:
        shown += f" and {len(values) - _MEMBER_PRINT_LIMIT} more"
    return shown


def _identification_off(obj) -> list[str]:
    """PAN-IOT-002's first half: is identification on in the zones that carry the devices."""
    if obj.enable_device_identification:
        return []
    return [
        "device identification is NOT ENABLED on this zone, so nothing in it is identified by "
        "what the equipment is - the traffic is matched on addresses alone, and unadministered "
        "equipment in this zone appears in no device report and can be named by no rule",
        "WHICH ZONES SHOULD CARRY THIS IS NOT READABLE FROM A FIREWALL and the question is not "
        "asked as a condition here, on purpose: an unanswered question must leave the finding "
        "standing rather than suppress it. So this reports every zone with identification off, "
        "and whether this particular zone carries equipment nobody administers is the "
        "reviewer's to confirm",
        "AND CHECK WHERE THIS ZONE'S CONFIGURATION COMES FROM BEFORE ACTING. Nothing stored "
        "about a zone says whether it was configured on this firewall or pushed to it from a "
        "template, so the setting may only be changeable where it is defined",
    ]


def _narrowed(obj) -> list[str]:
    """PAN-IOT-002's second half: is identification narrowed away from those devices."""
    if not (obj.enable_device_identification and obj.device_identification_is_narrowed):
        return []
    parts = [
        "device identification is enabled on this zone and has been LIMITED to a named set of "
        "addresses rather than applied to everything in it - so equipment outside that set is "
        "in an identified zone and is not itself identified"
    ]
    if obj.device_include_acl:
        parts.append(
            f"identification is restricted to the included networks "
            f"{_members(obj.device_include_acl)}")
    if obj.device_exclude_acl:
        parts.append(
            f"and excluded from {_members(obj.device_exclude_acl)}")
    parts.append(
        "THE MEMBERS ARE PRINTED BECAUSE THE COVERAGE QUESTION IS YOURS AND NOT THIS CONTROL'S. "
        "A member may be a literal address, a range, an address object or an address GROUP, and "
        "nothing on the firewall says what is actually plugged in - so this finding reports that "
        "the scope was narrowed and makes no claim that any particular equipment falls outside "
        "it. Confirm the list against what the zone carries")
    return parts


def _lists_unread(obj) -> list[str]:
    """The companion arm: identification is on and nobody read what it is scoped to."""
    if not obj.enable_device_identification or obj.device_acl_lists_computed:
        return []
    return [
        "THE SCOPE OF IDENTIFICATION IN THIS ZONE COULD NOT BE ESTABLISHED: identification is "
        "enabled, and this row's Device-ID address lists were never read, so whether it applies "
        "to the whole zone or to a narrow set of addresses is unknown rather than answered",
        "it is reported rather than passed because an unread list is stored as an empty one, and "
        "an empty list is exactly the value of a zone that identifies EVERYTHING - the most "
        "permissive and most compliant state. Without this arm a zone nobody collected would "
        "have read as correctly configured",
    ]


def _user_identification_on(obj) -> list[str]:
    """PAN-UID-001's only half: is the User-ID switch on in this zone.

    ADDED 2026-11-01 BY THE `user-id` STAGE 8 RUN, AND THE REASON IT HAD TO BE IS THE DISPATCH
    BELOW. PAN-UID-001 reuses the `zone` control type rather than minting a second type for
    `integrations.Zone` - the type-to-model map is one-to-one and nothing in the suite asserts
    that, so a duplicate would have passed every gate. Reuse is correct and it is also silent:
    a reused type reuses this module's generator, and `_subject` DEFAULTS to PAN-IOT-002's three
    arms for any control id it does not recognise. Without this arm and its entry below, a
    PAN-UID-001 finding would have been described with PAN-IOT-002's claims - device
    identification off, narrowed, lists unread - which are answers to a different question about
    the same zone.

    THE DIRECTION IS THE OPPOSITE OF THE DEVICE-ID HALVES ABOVE: `True` is the finding here.
    User-ID being ON is what exposes internal username-to-IP mappings in a zone, where Device-ID
    being OFF is what PAN-IOT-002 reports. One zone can legitimately be in both states, and
    `build_zone_finding_summary` takes its control id from the FIRST matched query - so a zone
    matched by both controls gets one control's arms arbitrarily. That is not fixed here; it is
    raised in the stage 8 artifact for `user-id` under `needs_human`, because rewriting that loop
    to serve this control would change PAN-IOT-002's finding prose, which is a catalogue
    decision rather than a build one.
    """

    if not obj.enable_user_identification:
        return []
    parts = [
        "USER-ID IS ENABLED on this zone, so the firewall maps usernames to the addresses it "
        "sees here and those mappings become names in policy, in the traffic log and in every "
        "report that reads from them - on an untrusted or Internet-facing zone that leaks "
        "internal identity outward and can be probed to enumerate it",
        "WHICH SIDE OF THE FIREWALL THIS ZONE FACES IS NOT READABLE FROM A FIREWALL and the "
        "question is deliberately not asked as a condition here, for the reason the Device-ID "
        "half above gives: an unanswered question must leave the finding standing rather than "
        "suppress it. So this reports every zone with the switch on, and whether this zone "
        "carries the organisation's own user population is the reviewer's to confirm",
    ]
    if obj.include_acl or obj.exclude_acl:
        parts.append(
            f"this zone's own User-ID address lists are included "
            f"{_members(obj.include_acl) or '`none`'} and excluded "
            f"{_members(obj.exclude_acl) or '`none`'} - PRINTED AS CONTEXT AND NOT JUDGED HERE. "
            "What bounds User-ID discovery for a vsys is PAN-UID-002's subject, which is a "
            "different object, and these per-zone lists are neither that control's rows nor "
            "this control's assertion")
    parts.append(
        "AND CHECK WHERE THIS ZONE'S CONFIGURATION COMES FROM BEFORE ACTING. Nothing stored "
        "about a zone says whether it was configured on this firewall or pushed to it from a "
        "template, so the switch may only be changeable where the zone is defined")
    return parts


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. PAN-IOT-002: one control, three arms over two
#: halves, and no row can match the first arm together with either of the others. PAN-UID-001:
#: one arm, asserting the opposite polarity on a different switch of the same row - see that
#: arm's docstring for why reusing this type made the entry necessary rather than optional.
PARTS_BY_CONTROL = {
    "PAN-IOT-002": (_identification_off, _narrowed, _lists_unread),
    "PAN-UID-001": (_user_identification_on,),
}


def _subject(obj, control_id: str) -> str:
    appliance = obj.enforcement_point.appliance or obj.enforcement_point.appliance_group
    parts = [f"security zone {obj.name} in {obj.enforcement_point.vsys_name} on {appliance}"]
    for build in PARTS_BY_CONTROL.get(
            control_id, (_identification_off, _narrowed, _lists_unread)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_zone_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


def _appliance_scope(obj) -> str:
    appliance = obj.enforcement_point.appliance
    owner = str(appliance.hostname if appliance is not None
                else obj.enforcement_point.appliance_group)
    return f"{owner} / {obj.enforcement_point.vsys_name}"


SPEC = ObjectFindingSpec(
    label="security zone",
    control_type=Control.ControlType.ZONE,
    finding_model=ZoneFinding,
    link_model=ZoneFindingControlQuery,
    subject_fk="zone",
    link_fk="zone_finding",
    queryset=lambda: Zone.objects.select_related(
        "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group"),
    evaluate=evaluate_zone_control_queries,
    summary=build_zone_finding_summary,
    # The zone's own name, with the owner AND the vsys as scope: a zone name is unique only per
    # enforcement point, so the same name legitimately exists in several vsys of one appliance.
    subject_name=lambda obj: obj.name,
    subject_scope=_appliance_scope,
)


def generate_zone_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_zone_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
