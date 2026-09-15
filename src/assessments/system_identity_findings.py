"""Finding generation for the system identity controls. PAN-SVC-007, 009 and 010.

Three controls, three settings, one row - and the sentence keeps them together on purpose.
009 (time zone) and 010 (factory hostname) were one control until 2026-09-15; they were split
because firing on either produced one finding for two independent defects with different
remediations. The SUBJECT sentence still describes the whole row, so a finding for either names
the device's name and its time zone; what each control ASSERTS is now separate. A device
that takes its management address from DHCP can also take its NAME from DHCP (Help p.701: the
server-provided hostname "overwrites any value specified in the Hostname field"), so the two
findings an engineer sees on this row can have one cause.

The addressing sentence says whether `static` was READ or RESOLVED. An absent `deviceconfig/
system/type` node is static - measured 2026-09-14, fw-core-tpa-b carries no such node and
compiles to `'ip-type': static` with `'disable-dhcp': True` - so absence is a pass here rather
than an unknown, which is the opposite of the usual reading and worth stating where it applies.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_system_identity_control_queries
from assessments.models import Control, SystemIdentityFinding, SystemIdentityFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import SystemIdentity


def _subject(obj) -> str:
    parts = []
    if obj.hostname_is_factory_default:
        parts.append(f"{obj.appliance} is still on its factory hostname "
                     f"({obj.hostname or 'unset, which PAN-OS renders as the model name'})")
    else:
        parts.append(f"{obj.appliance} is named {obj.hostname}")

    if not obj.timezone_is_utc:
        parts.append(f"its time zone is {obj.timezone or 'unset'} rather than UTC, so correlating "
                     f"its logs with another device's needs offset arithmetic")

    if obj.addressing_mode == SystemIdentity.AddressingMode.DHCP_CLIENT:
        detail = ("its management address comes from DHCP, so a rogue DHCP server on the "
                  "management segment can reassign its address, gateway and DNS")
        if obj.accept_dhcp_hostname or obj.accept_dhcp_domain:
            accepted = " and ".join(
                [n for n, on in (("hostname", obj.accept_dhcp_hostname),
                                 ("domain", obj.accept_dhcp_domain)) if on])
            detail += f" - and it accepts the {accepted} from that server too"
        parts.append(detail)
    elif not obj.addressing_mode_explicit:
        parts.append("its management address is static by default, with no `type` node written")
    return "; ".join(parts) + "."


def build_system_identity_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj).rstrip("."), matched_queries)


SPEC = ObjectFindingSpec(
    label="system identity",
    control_type=Control.ControlType.SYSTEM_IDENTITY,
    finding_model=SystemIdentityFinding,
    link_model=SystemIdentityFindingControlQuery,
    subject_fk="system_identity",
    link_fk="system_identity_finding",
    queryset=lambda: SystemIdentity.objects.select_related("appliance"),
    evaluate=evaluate_system_identity_control_queries,
    summary=build_system_identity_finding_summary,
    subject_name=lambda obj: str(obj.appliance),
)


def generate_system_identity_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_system_identity_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
