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


def _url_filtering_gaps(obj) -> list[str]:
    """What a URL FILTERING profile permits, by the question each control asks. PAN-URL-001 to
    -005.

    THE SAME DEFECT SHAPE `_antivirus_gaps` EXISTS TO PREVENT, met a second time. A url-filtering
    profile has no severity rules, so `_gaps` returns nothing for it, the DNS and brute-force
    verdicts are None, and `_subject`'s final clause asserted that the profile "blocks critical
    and high threats" - printed on the finding that was reporting it as failing. Measured on this
    domain's census, 2026-11-01. Guarding the values was not enough for antivirus and it is not
    enough here: the CALLER has to stop asking this kind the threat-rule question.

    EVERY VERDICT READ HERE IS A STORED CONCLUSION over the device's own category catalogue minus
    the profile's member lists, so each clause names the WORST member as well as the verdict - a
    reader has to know which category or header to go and change, and the catalogue is not in the
    profile.

    `is False` rather than falsy throughout, for the reason the threat-rule clauses give: these
    are non-null booleans today, but a null would mean this kind writes no row and makes no
    claim, which is not the same as a gap.
    """
    gaps = []
    if obj.all_hostile_categories_blocked is False:
        worst = obj.weakest_hostile_category_action or "an action that was not established"
        gaps.append("does not refuse the confirmed-hostile categories "
                    f"(command-and-control, malware, phishing; weakest action {worst})")
    if obj.all_reachable_categories_logged is False:
        worst = obj.worst_reachable_unlogged_category or "a category that was not established"
        gaps.append(f"permits categories without logging them (worst: {worst})")
    if obj.credential_detection_mode == SecurityProfile.CREDENTIAL_MODE_DISABLED:
        gaps.append("detects no corporate credential submissions at all")
    elif obj.all_reachable_categories_credential_restricted is False:
        worst = obj.worst_credential_permissive_category or "a category that was not established"
        gaps.append("accepts corporate credentials on categories it permits "
                    f"(worst: {worst})")
    if obj.records_all_request_headers is False:
        missing = ", ".join(obj.unrecorded_request_headers or []) or "a header not established"
        gaps.append(f"does not record the request headers {missing}")
    if obj.cloud_inline_categorization is False:
        gaps.append("has cloud-side inline categorization switched off")
    if obj.local_inline_categorization_on is False:
        # THE ONE CLAUSE THAT MAY BE WRONG ON THE ROW IT IS PRINTED ON, and it says so. On a
        # PA-VM an absent `local-inline-cat` key means the on-box engine IS ON; on a PA-5220 it
        # means off. Stage 4 measured the condition as the APPLIANCE and the normalizer stores
        # false for the absence, so this is a FALSE POSITIVE on every PA-VM profile that stores
        # nothing. `local_inline_categorization_undetermined` is true on exactly those rows.
        if obj.local_inline_categorization_undetermined:
            gaps.append("may have on-box inline categorization switched off - the key is absent "
                        "and what an absence means here depends on the platform, so this one "
                        "needs a look at the profile rather than a change to it")
        else:
            gaps.append("has on-box inline categorization switched off")
    if obj.inline_analysis_exemption_count:
        broadest = obj.broadest_inline_analysis_exemption_type or "a type that was not resolved"
        gaps.append(f"exempts {obj.inline_analysis_exemption_count} custom "
                    f"categor{'y' if obj.inline_analysis_exemption_count == 1 else 'ies'} from "
                    f"real-time analysis (broadest: {broadest})")
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

    # URL FILTERING DOES NOT ANSWER THE SEVERITY QUESTION EITHER. Same reasoning as antivirus
    # immediately above, and the same measured defect: without this branch a failing
    # url-filtering profile fell through to "blocks critical and high threats". The four shipped
    # kinds that reach this function are untouched by this guard.
    if obj.kind == SecurityProfile.KIND_URL_FILTERING:
        gaps = "; ".join(_url_filtering_gaps(obj))
        if gaps:
            return f"{what} {gaps}"
        # NOT "this profile is fine". A url-filtering profile can be reported by PAN-URL-006 for
        # being unreferenced while every verdict above passes, so the no-gap sentence must say
        # what was actually checked and no more.
        return (f"{what} refuses the confirmed-hostile categories, logs what it permits, "
                "restricts corporate credentials and runs both inline analysis engines")

    # TWO INDEPENDENT QUESTIONS, and a profile can fail either alone. Blocking the threat
    # (PAN-VLN-001) and blocking its SOURCE (PAN-VLN-002) are different: `reset-both` passes the
    # first and fails the second. Without the second clause a profile failing only PAN-VLN-002
    # printed "blocks critical and high threats" ON ITS OWN FINDING - the same reassuring
    # sentence on a failing profile that `_antivirus_gaps` exists to prevent.
    clauses = []
    gaps = "; ".join(_gaps(obj))
    if gaps:
        clauses.append(f"does not block every critical and high threat ({gaps})")
    # ANTI-SPYWARE ANSWERS A QUESTION OF ITS OWN. A profile can block every severity and still
    # not sinkhole malicious DNS, and the severity sentence would have called it fine - the
    # same shape as the brute-force clause below, on the other kind.
    if obj.dns_sinkholes_malicious_queries is False:
        clauses.append(f"does not sinkhole malicious DNS queries ({obj.dns_sinkhole_detail})")
    # A SECOND, INDEPENDENT DNS QUESTION. The same screen carries the DNS Security categories,
    # and a profile can sinkhole the Palo Alto Networks Content list while leaving every
    # malicious category at `default` - which the predefined profiles both do.
    if obj.dns_security_categories_enforced is False:
        clauses.append("does not enforce malicious DNS Security categories "
                       f"({obj.dns_security_category_detail})")
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
        "category_verdicts", "dns_signature_sources"),
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
