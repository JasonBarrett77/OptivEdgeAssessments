"""Finding generation for one vsys's PAN-OS integrated User-ID agent settings.

THREE CONTROLS, ONE MODEL, FOUR COLUMNS. PAN-UID-003 asserts that WMI/NetBIOS client probing is
off, PAN-UID-004 that no privileged directory account is configured for server monitoring and
that session reading is off, PAN-UID-006 that IP-to-user mappings expire and that the lifetime is
bounded. One row per vsys carries all of it, so the three controls share a type, a model and this
generator.

THE DISPATCH HAS NO DEFAULT, AND THAT IS THE WHOLE POINT OF WRITING IT THIS WAY. `zone_findings`
keys its own `PARTS_BY_CONTROL` by control id and FALLS BACK to PAN-IOT-002's three arms for any
id it does not know, so a different control reusing the `zone` type has its finding described with
another control's compliance claims. That is a measured defect in a shipped module - recorded in
`reference/consumer-repo-notes.md`, 2026-11-01 - and a generator serving three controls from the
start is exactly where it would recur. So `_PARTS_BY_CONTROL.get(control_id, ())` returns an EMPTY
tuple: an unrecognised control id contributes the subject line and no claim at all. A missing arm
then reads as a finding that says what it found and nothing more, which is thin; a defaulted arm
reads as a confident statement about a setting this control never examined, which is wrong.

AN ABSENT ROW AND A COMPLIANT ROW ARE DIFFERENT STATES AND NO COLUMN HERE TELLS THEM APART.
Stage 4 measured `vsys/entry/user-id-collector/setting` absent on all four appliances and all
twenty vsys of the lab, so stage 7 writes the vendor implicits into the row and every clause is
answerable. A vsys whose merged configuration was never collected has NO ROW, is matched by
nothing, and is reported by nothing - which is a collection-coverage question rather than
something a sentence here can carry.

WHAT THE SERVICE-ACCOUNT HALF IS NOT ALLOWED TO SAY. PAN-UID-004 asserts a minimal-rights
service account, and NO CONFIGURATION READ CAN ESTABLISH WHAT RIGHTS AN ACCOUNT HOLDS: the
firewall stores the principal it authenticates as and nothing about its group memberships, which
live in the directory. Stage 5 discharges that half as `engineer_answers` for exactly that
reason. So the finding reports that a directory principal IS configured and NAMES it for a
reviewer to check directory-side. It does not claim the account is over-privileged.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_user_id_collector_control_queries
from assessments.models import (
    Control,
    UserIdCollectorFinding,
    UserIdCollectorFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import UserIdCollectorSettings


def _probing(obj) -> list[str]:
    """PAN-UID-003: is the agent probing endpoints with its own credentials."""
    if not obj.enable_probing:
        return []
    return [
        "WMI/NETBIOS CLIENT PROBING IS ENABLED on this vsys, so the User-ID agent sends its own "
        "credentials to endpoints to ask who is logged in - and anyone positioned on a probed "
        "segment can capture and relay those credentials, which is a documented "
        "lateral-movement primitive rather than a theoretical exposure",
        "the vendor recommends disabling it outright; identity from GlobalProtect, the Cloud "
        "Identity Engine or authentication logs needs no probe and carries no credential onto "
        "the segment being probed",
    ]


def _service_account(obj) -> list[str]:
    """PAN-UID-004's first half: is a directory principal configured for server monitoring."""
    if not obj.wmi_account:
        return []
    return [
        f"a directory account is configured for server monitoring on this vsys, stored as "
        f"`{obj.wmi_account}`",
        "WHAT THIS FINDING DOES NOT CLAIM, because no read can establish it: the firewall "
        "stores the principal it authenticates as and NOTHING about the rights that principal "
        "holds - group memberships live in the directory. So this names the account for a "
        "reviewer to check directory-side, and makes no claim that it is over-privileged. What "
        "is wanted is event-log-reader rights and nothing more: no domain or enterprise admin, "
        "no interactive or remote-desktop logon",
    ]


def _session_reading(obj) -> list[str]:
    """PAN-UID-004's second half: is the firewall reading user sessions off the servers."""
    if not obj.enable_session:
        return []
    return [
        "SESSION READING IS ENABLED, so the firewall enumerates user sessions on the monitored "
        "servers rather than only reading their security logs - which is the privilege that "
        "makes the service account's rights matter, and the reason to confirm them before "
        "treating this vsys as bounded",
    ]


def _expiry_off(obj) -> list[str]:
    """PAN-UID-006's first half: do mappings expire at all."""
    if obj.enable_mapping_timeout:
        return []
    return [
        "IP-TO-USER MAPPING EXPIRY IS SWITCHED OFF on this vsys, so a mapping never expires: "
        "traffic keeps being attributed to a user long after DHCP has reassigned the address, "
        "which corrupts identity-based policy and the audit trail that reads from it",
        "A STORED TIMEOUT VALUE BESIDE THIS IS NOT A MITIGATION and is the thing most likely to "
        f"mislead a reader of this row: the lifetime stored here is {obj.ip_user_mapping_timeout} "
        "minutes, and it is inert while expiry is off",
    ]


def _expiry_unbounded(obj) -> list[str]:
    """PAN-UID-006's second half: is the lifetime within the bound."""
    if not obj.enable_mapping_timeout or obj.ip_user_mapping_timeout <= 60:
        return []
    return [
        f"mappings on this vsys expire, but only after {obj.ip_user_mapping_timeout} minutes - "
        "beyond the sixty-minute bound, so identity outlives the DHCP lease that justified it "
        "by a margin nobody at the site has justified",
    ]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. Keyed by control id, and `_subject` takes NO
#: DEFAULT from it - see the module docstring. An id absent from here contributes no claim.
_PARTS_BY_CONTROL = {
    "PAN-UID-003": (_probing,),
    "PAN-UID-004": (_service_account, _session_reading),
    "PAN-UID-006": (_expiry_off, _expiry_unbounded),
}


def _scope(obj) -> str:
    point = obj.enforcement_point
    appliance = point.appliance
    return str(appliance.hostname if appliance is not None else point.appliance_group)


def _subject(obj, control_id: str) -> str:
    parts = [f"the User-ID collector on {_scope(obj)} {obj.enforcement_point.vsys_name}"]
    for build in _PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_user_id_collector_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="User-ID collector",
    control_type=Control.ControlType.USER_ID_COLLECTOR,
    finding_model=UserIdCollectorFinding,
    link_model=UserIdCollectorFindingControlQuery,
    subject_fk="user_id_collector",
    link_fk="user_id_collector_finding",
    queryset=lambda: UserIdCollectorSettings.objects.select_related(
        "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group"),
    evaluate=evaluate_user_id_collector_control_queries,
    summary=build_user_id_collector_finding_summary,
    # The VSYS name, with the appliance as scope. The row has no entry name of its own - the
    # subject is the enforcement point - so without the scope `vsys1` is the subject name on
    # every single-vsys firewall in the estate.
    subject_name=lambda obj: obj.enforcement_point.vsys_name,
    subject_scope=_scope,
)


def generate_user_id_collector_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_user_id_collector_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
