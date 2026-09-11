"""Finding generation for the login banner controls. PAN-MGT-007 and 008.

The subject sentence QUOTES the banner, truncated, rather than saying whether one exists. "This
appliance has no login banner" is the whole of PAN-MGT-007, but PAN-MGT-008 fires on a banner
that is present and unacknowledged, and an assessor reading that finding needs to see the text
to judge whether it says anything useful.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_login_banner_control_queries
from assessments.models import (
    Control, LoginBannerFinding, LoginBannerFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import LoginBanner


def _subject(obj) -> str:
    if not obj.text:
        return f"{obj.appliance} has no login banner"
    quoted = obj.text if len(obj.text) <= 60 else obj.text[:60].rstrip() + "\u2026"
    ack = "must be acknowledged" if obj.acknowledgement_required else "needs no acknowledgement"
    return f"Login banner on {obj.appliance} ({ack}): {quoted!r}"


def build_login_banner_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="login banner",
    control_type=Control.ControlType.LOGIN_BANNER,
    finding_model=LoginBannerFinding,
    link_model=LoginBannerFindingControlQuery,
    subject_fk="login_banner",
    link_fk="login_banner_finding",
    queryset=lambda: LoginBanner.objects.select_related("appliance"),
    evaluate=evaluate_login_banner_control_queries,
    summary=build_login_banner_finding_summary,
    #: The policy has no name of its own, so the appliance IS the subject name.
    subject_name=lambda obj: str(obj.appliance),
)

LoginBannerFindingRunResult = ObjectFindingRunResult


def generate_login_banner_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_login_banner_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
