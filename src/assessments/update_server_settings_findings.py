"""Finding generation for the update server verification control. PAN-MGT-009.

Fires only on an EXPLICIT no: the key is implicitly yes, so a device that has never been touched
satisfies this control. That is the opposite of almost every other setting in this domain and is
the reason the sentence says "turned off" rather than "not enabled".
"""

from __future__ import annotations

from assessments.control_queries import evaluate_update_server_settings_control_queries
from assessments.models import (
    Control, UpdateServerSettingsFinding, UpdateServerSettingsFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import UpdateServerSettings


def _subject(obj) -> str:
    return (f"Update server identity verification is turned OFF on {obj.appliance} "
            f"- it is on by default and was explicitly disabled")


def build_update_server_settings_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="update server settings",
    control_type=Control.ControlType.UPDATE_SERVER,
    finding_model=UpdateServerSettingsFinding,
    link_model=UpdateServerSettingsFindingControlQuery,
    subject_fk="update_server_settings",
    link_fk="update_server_settings_finding",
    queryset=lambda: UpdateServerSettings.objects.select_related("appliance"),
    evaluate=evaluate_update_server_settings_control_queries,
    summary=build_update_server_settings_finding_summary,
    #: The policy has no name of its own, so the appliance IS the subject name.
    subject_name=lambda obj: str(obj.appliance),
)

UpdateServerSettingsFindingRunResult = ObjectFindingRunResult


def generate_update_server_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_update_server_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
