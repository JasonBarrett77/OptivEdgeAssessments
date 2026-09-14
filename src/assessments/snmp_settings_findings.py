"""Finding generation for the SNMP controls. PAN-SVC-004 and 005.

Every sentence says whether SNMP is actually REACHABLE, and that is the most useful thing on the
finding. The two halves live apart in PAN-OS: `snmp-setting` says how SNMP would answer, and
`disable-snmp` on each management surface says whether anything is listening. A device can hold a
v2c community string that no surface exposes - latent rather than live, the same shape as a
stored password on a profile-bound account - and an engineer triaging a high-severity SNMP
finding needs to know which of the two they have before they decide how fast to move.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_snmp_settings_control_queries
from assessments.models import Control, SnmpSettingsFinding, SnmpSettingsFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import SnmpSettings


def _subject(obj) -> str:
    if not obj.is_configured:
        # Neither control fires here - controls.json says an unused SNMP should be left
        # unconfigured - so this branch exists for completeness rather than for a finding.
        return f"{obj.appliance} has no SNMP configuration"

    version = obj.version or "no version"
    head = f"{obj.appliance} configures SNMP {version}"
    if obj.version_implicit:
        head += (" - the version is not written, and PAN-OS defaults the dialog to V2c "
                 "(Help p.740), so this rests on the vendor's stated default rather than on a "
                 "value read from the device")
    parts = [head]

    if obj.uses_v2c:
        if obj.community_is_default:
            parts.append("with a DEFAULT community string, which is a published password")
        elif obj.community_set:
            parts.append("with a non-default community string, sent in cleartext like any v2c "
                         "community")
        else:
            parts.append("with no community string set")
    elif obj.version == SnmpSettings.Version.V3:
        parts.append(f"with {obj.v3_user_count} user(s) and {obj.v3_view_count} view(s)")

    # The whole point of the sentence: configured is not the same as reachable.
    if obj.is_exposed:
        parts.append(f"and the SNMP service is ENABLED on {', '.join(obj.exposed_surfaces)}, so "
                     f"this is reachable now")
    else:
        parts.append("though no management surface currently enables the SNMP service, so it is "
                     "latent - it becomes live the moment SNMP is turned on for a surface")
    return "; ".join(parts) + "."


def build_snmp_settings_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj).rstrip("."), matched_queries)


SPEC = ObjectFindingSpec(
    label="SNMP",
    control_type=Control.ControlType.SNMP_SETTINGS,
    finding_model=SnmpSettingsFinding,
    link_model=SnmpSettingsFindingControlQuery,
    subject_fk="snmp_settings",
    link_fk="snmp_settings_finding",
    queryset=lambda: SnmpSettings.objects.select_related("appliance"),
    evaluate=evaluate_snmp_settings_control_queries,
    summary=build_snmp_settings_finding_summary,
    subject_name=lambda obj: str(obj.appliance),
)


def generate_snmp_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_snmp_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
