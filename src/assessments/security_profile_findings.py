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
    """The severities this profile fails, and why.

    `blocked is False` rather than `not blocked`: None means the profile does not assess that
    severity at all, which is not a gap.

    THREAT-RULE KINDS ONLY. This used to add that no control reaches it with a None, because
    the queries could not match a profile with no verdict row. PAN-AVW-001 and PAN-AVW-002 do -
    an antivirus profile has no severity rules at all - and the `blocked is False` test held,
    so the finding simply reported no gaps and the caller asserted the profile was fine.
    Guarding the value was not enough; the CALLER had to stop asking this kind the question.
    See `_antivirus_gaps`.
    """
    return [f"{severity}: {detail}" for severity, blocked, detail in (
        ("critical", obj.critical_blocked, obj.critical_detail),
        ("high", obj.high_blocked, obj.high_detail),
    ) if blocked is False]


def _antivirus_gaps(obj) -> list[str]:
    """What an ANTIVIRUS profile lets through, by verdict source.

    An antivirus profile has no severity rules, so `_gaps` - which reads the critical and high
    verdicts - returns nothing for one and the sentence fell through to "blocks critical and
    high threats". That was printed on every antivirus finding, including the shipped `default`
    profile that alerts on three mail decoders: the reassuring sentence, on the finding
    reporting the profile as failing. Measured against the lab 2026-10-08.

    Each entry names the verdict source as the UI column names it, because an engineer has to
    find the column to change it and the three look identical in the config.
    """
    gaps = []
    if obj.non_blocking_decoders:
        gaps.append(f"signature action allows on {', '.join(obj.non_blocking_decoders)}")
    if obj.non_blocking_wildfire_decoders:
        gaps.append("WildFire signature action allows on "
                    f"{', '.join(obj.non_blocking_wildfire_decoders)}")
    if obj.non_blocking_mlav_decoders:
        gaps.append("WildFire inline ML action allows on "
                    f"{', '.join(obj.non_blocking_mlav_decoders)}")
    if obj.non_blocking_application_overrides:
        gaps.append("application exceptions override the decoder for "
                    f"{', '.join(obj.non_blocking_application_overrides)}")
    if obj.non_blocking_ml_models:
        gaps.append("inline ML models not blocking: "
                    f"{', '.join(obj.non_blocking_ml_models)}")
    return gaps


def _subject(obj) -> str:
    kind = KIND_LABELS.get(obj.kind, obj.kind)
    if obj.is_predefined:
        what = (f"The predefined {kind} profile {obj.name}, used by {obj.referrer_count} "
                f"rule{'s' if obj.referrer_count != 1 else ''} or profile group"
                f"{'s' if obj.referrer_count != 1 else ''} on {profile_owner(obj)},")
    else:
        what = f"{kind} profile {obj.name} on {profile_owner(obj)}"

    # ANTIVIRUS DOES NOT ANSWER THE SEVERITY QUESTION. It has no severity rules, so the
    # critical/high verdicts are None and the threat-rule sentence below would assert that the
    # profile blocks them - which is a claim about a question this kind never asked.
    if obj.kind == SecurityProfile.KIND_VIRUS:
        gaps = "; ".join(_antivirus_gaps(obj))
        return (f"{what} lets malware through ({gaps})" if gaps
                else f"{what} blocks malware on every decoder")

    # TWO INDEPENDENT QUESTIONS, and a profile can fail either alone. Blocking the threat
    # (PAN-VLN-001) and blocking its SOURCE (PAN-VLN-002) are different: `reset-both` passes the
    # first and fails the second. Without the second clause a profile failing only PAN-VLN-002
    # printed "blocks critical and high threats" ON ITS OWN FINDING - the same reassuring
    # sentence on a failing profile that `_antivirus_gaps` exists to prevent.
    clauses = []
    gaps = "; ".join(_gaps(obj))
    if gaps:
        clauses.append(f"does not block every critical and high threat ({gaps})")
    # `is False` rather than falsy: None means this kind writes no row and makes no claim.
    if obj.brute_force_blocked_by_source is False:
        clauses.append("does not block the source of brute-force attempts"
                       f" ({obj.brute_force_detail})")
    if clauses:
        return f"{what} " + ", and ".join(clauses)
    return f"{what} blocks critical and high threats"


def build_security_profile_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="security profile",
    control_type=Control.ControlType.SECURITY_PROFILE,
    finding_model=SecurityProfileFinding,
    link_model=SecurityProfileFindingControlQuery,
    subject_fk="security_profile",
    link_fk="security_profile_finding",
    # The antivirus subject sentence walks all three, so without these it is one query per
    # profile per collection.
    queryset=lambda: SecurityProfile.objects.select_related(
        "enforcement_point__appliance_group", "appliance_group").prefetch_related(
        "decoders", "ml_models", "application_overrides", "severity_verdicts",
        "category_verdicts"),
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
