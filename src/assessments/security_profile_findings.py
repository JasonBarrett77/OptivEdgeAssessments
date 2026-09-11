"""Finding generation for anti-spyware and vulnerability profile controls. PAN-SPY-001, PAN-VLN-001.

The subject sentence names the severity that is not blocked AND why. Two profiles failing the same
severity can fail it for different reasons - an alert rule, or no catch-all rule at all - and the
fix differs. A predefined profile is named as predefined, with how many things use it: it cannot
be edited, so the remediation is to stop using it rather than to change it.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_security_profile_control_queries
from assessments.models import Control, SecurityProfileFinding, SecurityProfileFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import SecurityProfile

KIND_LABELS = dict(SecurityProfile.KIND_CHOICES)


def profile_owner(obj) -> str:
    """The appliance group for shared scope, `group / vsys` for vsys and predefined scope."""
    return obj.appliance_group.name if obj.appliance_group_id else str(obj.enforcement_point)


def _gaps(obj) -> list[str]:
    return [f"{severity}: {detail}" for severity, blocked, detail in (
        ("critical", obj.critical_blocked, obj.critical_detail),
        ("high", obj.high_blocked, obj.high_detail),
    ) if not blocked]


def _subject(obj) -> str:
    kind = KIND_LABELS.get(obj.kind, obj.kind)
    if obj.is_predefined:
        what = (f"The predefined {kind} profile {obj.name}, used by {obj.referrer_count} "
                f"rule{'s' if obj.referrer_count != 1 else ''} or profile group"
                f"{'s' if obj.referrer_count != 1 else ''} on {profile_owner(obj)},")
    else:
        what = f"{kind} profile {obj.name} on {profile_owner(obj)}"
    gaps = "; ".join(_gaps(obj))
    return f"{what} does not block every critical and high threat ({gaps})" if gaps else \
        f"{what} blocks critical and high threats"


def build_security_profile_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="security profile",
    control_type=Control.ControlType.SECURITY_PROFILE,
    finding_model=SecurityProfileFinding,
    link_model=SecurityProfileFindingControlQuery,
    subject_fk="security_profile",
    link_fk="security_profile_finding",
    queryset=lambda: SecurityProfile.objects.select_related(
        "enforcement_point__appliance_group", "appliance_group"),
    evaluate=evaluate_security_profile_control_queries,
    summary=build_security_profile_finding_summary,
    subject_name=lambda obj: obj.name,
    # Names repeat across scopes - every vsys has its own predefined `default` - so the finding
    # carries where the definition lives, not only its name.
    subject_scope=lambda obj: f"{obj.namespace_type}:{profile_owner(obj)}"[:128],
)

SecurityProfileFindingRunResult = ObjectFindingRunResult


def generate_security_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_security_profile_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
