"""Finding generation for the minimum password complexity controls. PAN-AUTH-001 to 013.

The subject is one row per appliance, so the sentence names the APPLIANCE and then the value
that fired. Thirteen controls share this subject and fail independently - a device can meet the
length minimum and enforce no character classes at all - so a finding has to say which value it
is about or the thirteen read as one.

`enabled` is stated on every sentence, because it is the switch the other twelve depend on: a
minimum length of 12 on a policy that is switched off is not a policy, and a finding that quoted
only the number would be describing something the device is not applying.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_password_complexity_control_queries
from assessments.models import (
    Control, PasswordComplexityFinding, PasswordComplexityFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import PasswordComplexityPolicy


def _subject(obj) -> str:
    state = "enabled" if obj.enabled else "NOT ENABLED"
    return (f"Minimum password complexity on {obj.appliance} is {state}, "
            f"minimum length {obj.minimum_length or 'none'}")


def build_password_complexity_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="password complexity",
    control_type=Control.ControlType.PASSWORD_COMPLEXITY,
    finding_model=PasswordComplexityFinding,
    link_model=PasswordComplexityFindingControlQuery,
    subject_fk="password_complexity_policy",
    link_fk="password_complexity_finding",
    queryset=lambda: PasswordComplexityPolicy.objects.select_related("appliance"),
    evaluate=evaluate_password_complexity_control_queries,
    summary=build_password_complexity_finding_summary,
    #: The policy has no name of its own, so the appliance IS the subject name.
    subject_name=lambda obj: str(obj.appliance),
)

PasswordComplexityFindingRunResult = ObjectFindingRunResult


def generate_password_complexity_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_password_complexity_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
