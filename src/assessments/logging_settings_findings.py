"""Finding generation for the high-DP-load logging control. PAN-MGT-011.

Fires on the DEFAULT, unlike its neighbour on the update server: absent means disabled, so an
untouched device reports. The sentence says so, because a finding that reads like a
misconfiguration when it is really an unset default sends an assessor looking for who changed it.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_logging_settings_control_queries
from assessments.models import (
    Control, LoggingSettingsFinding, LoggingSettingsFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import LoggingSettings


def _subject(obj) -> str:
    return (f"{obj.appliance} does not log when the data plane is under high load "
            f"- the setting is off, which is its default")


def build_logging_settings_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="logging settings",
    control_type=Control.ControlType.LOGGING_SETTINGS,
    finding_model=LoggingSettingsFinding,
    link_model=LoggingSettingsFindingControlQuery,
    subject_fk="logging_settings",
    link_fk="logging_settings_finding",
    queryset=lambda: LoggingSettings.objects.select_related("appliance"),
    evaluate=evaluate_logging_settings_control_queries,
    summary=build_logging_settings_finding_summary,
    #: The policy has no name of its own, so the appliance IS the subject name.
    subject_name=lambda obj: str(obj.appliance),
)

LoggingSettingsFindingRunResult = ObjectFindingRunResult


def generate_logging_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_logging_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
