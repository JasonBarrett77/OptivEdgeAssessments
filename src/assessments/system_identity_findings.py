"""Finding generation for the system identity controls. PAN-SVC-007, 009 and 010.

Three controls, three settings, one row - and the sentence keeps them together on purpose.
009 (time zone) and 010 (factory hostname) were one control until 2026-09-15; they were split
because firing on either produced one finding for two independent defects with different
remediations. The SUBJECT sentence still describes the whole row, so a finding for either names
the device's name and its time zone; what each control ASSERTS is now separate. A device
that takes its management address from DHCP can also take its NAME from DHCP (Help p.701: the
server-provided hostname "overwrites any value specified in the Hostname field"), so the two
findings an engineer sees on this row can have one cause.

THE TIME-ZONE SENTENCE BRANCHES ON `timezone_declares_zero_offset` AND NOT ON
`timezone_is_utc`, changed by stage 8 of `device-services` on 2026-11-01 in the same pass as
PAN-SVC-009's baseline clause. The old column is one spelling of zero offset out of eighteen;
branching on it described a compliant appliance as needing offset arithmetic. See
`_timezone_sentence` for the measured instance.

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
from optivedge_integrations.integrations.models.device_services import (
    TimezoneOffsetClass,
)


def _timezone_sentence(obj) -> str:
    """What is wrong with this appliance's time zone, by CLASS and not by one spelling.

    THE SENTENCE THIS REPLACED WAS FALSE ON A REAL APPLIANCE and it is worth saying which. It
    branched on `timezone_is_utc` - `timezone.strip().upper() == "UTC"`, one spelling out of the
    eighteen the device offers that declare zero offset - and wrote "its time zone is
    Atlantic/Reykjavik rather than UTC, so correlating its logs with another device's needs
    offset arithmetic". That zone sits at zero offset every month of the year and observes no
    daylight rule, so no arithmetic is needed and the sentence told the reader the opposite of
    what the row holds. pan-fw-111 is in exactly that state and stage 6 built it for this.

    The classification is the normalizer's: `timezone_offset_class` separates a zone that
    DECLARES zero offset in its own key from one that merely sits there today, and the middle
    rank exists because the second kind can move with a vendor time-zone update and no
    configuration change. The three branches below are its three firing members.
    """
    zone = obj.timezone or "unset"
    if obj.timezone_offset_class == TimezoneOffsetClass.NO_ZONE_RECORDED:
        return ("no time zone is recorded, so its logs are written in whatever the platform "
                "default happens to be and correlating them rests on an assumption")
    if obj.timezone_offset_class == TimezoneOffsetClass.ZERO_TODAY_BUT_NOT_DECLARED:
        return (f"its time zone is {zone}, which sits at zero offset today and does not SAY so "
                f"in its own name - so its logs need no arithmetic now and a vendor time-zone "
                f"update could change that with no configuration change here")
    return (f"its time zone is {zone}, which does not declare zero offset, so correlating its "
            f"logs with another device's needs offset arithmetic")


def _subject(obj) -> str:
    parts = []
    if obj.hostname_is_factory_default:
        parts.append(f"{obj.appliance} is still on its factory hostname "
                     f"({obj.hostname or 'unset, which PAN-OS renders as the model name'})")
    else:
        parts.append(f"{obj.appliance} is named {obj.hostname}")

    if not obj.timezone_declares_zero_offset:
        parts.append(_timezone_sentence(obj))

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
