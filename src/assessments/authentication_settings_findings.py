"""Finding generation for the device-wide authentication settings controls. PAN-AUTH-014 to 017.

The subject sentence states the LOCKOUT PAIR together, because neither number means anything
alone: `failed-attempts 0` is unlimited attempts whatever the lockout time says, and
`lockout-time 0` is "until an administrator releases it", which is the strictest value on that
field and reads as the weakest. Four controls share this row and fail independently.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_authentication_settings_control_queries
from assessments.models import (
    Control, AuthenticationSettingsFinding, AuthenticationSettingsFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import AuthenticationSettings


def _subject(obj) -> str:
    attempts = ("unlimited attempts" if not obj.lockout_failed_attempts
                else f"{obj.lockout_failed_attempts} failed attempts")
    held = ("held until released" if not obj.lockout_time_minutes
            else f"held {obj.lockout_time_minutes} min")
    idle = "no idle timeout" if not obj.idle_timeout_minutes else f"{obj.idle_timeout_minutes} min idle"
    return f"Authentication settings on {obj.appliance}: {attempts}, {held}, {idle}"


def build_authentication_settings_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="authentication settings",
    control_type=Control.ControlType.AUTHENTICATION_SETTINGS,
    finding_model=AuthenticationSettingsFinding,
    link_model=AuthenticationSettingsFindingControlQuery,
    subject_fk="authentication_settings",
    link_fk="authentication_settings_finding",
    queryset=lambda: AuthenticationSettings.objects.select_related("appliance"),
    evaluate=evaluate_authentication_settings_control_queries,
    summary=build_authentication_settings_finding_summary,
    #: The policy has no name of its own, so the appliance IS the subject name.
    subject_name=lambda obj: str(obj.appliance),
)

AuthenticationSettingsFindingRunResult = ObjectFindingRunResult


def generate_authentication_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_authentication_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
