"""Finding generation for password profile controls.

The subject sentence carries BOTH operands of the comparison, because the conclusion is only
checkable with them. "Weakens the global policy" tells an engineer nothing they can verify;
"expires after 180 days where the global policy expires after 90" tells them where to look and
what to change.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_password_profile_control_queries
from assessments.models import (
    Control, PasswordProfileFinding, PasswordProfileFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import PasswordProfile


def _period(days: int) -> str:
    """Zero is NEVER EXPIRES, not zero days - saying "0 days" inverts the meaning."""
    return "never expires" if days == 0 else f"expires after {days} days"


def _subject(obj) -> str:
    return (f"Password profile {obj.name} on {obj.appliance} {_period(obj.expiration_period)}, "
            f"where the global policy it overrides {_period(obj.global_expiration_period)}")


def build_password_profile_finding_summary(obj, matched_queries) -> str:
    """The one sentence this object type contributes to its findings."""
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="password profile",
    control_type=Control.ControlType.PASSWORD_PROFILE,
    finding_model=PasswordProfileFinding,
    link_model=PasswordProfileFindingControlQuery,
    subject_fk="password_profile",
    link_fk="password_profile_finding",
    queryset=lambda: PasswordProfile.objects.select_related("appliance"),
    evaluate=evaluate_password_profile_control_queries,
    summary=build_password_profile_finding_summary,
    subject_name=lambda obj: obj.name,
)

#: Kept so importers do not have to know the generator was factored out.
PasswordProfileFindingRunResult = ObjectFindingRunResult


def generate_password_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_password_profile_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
