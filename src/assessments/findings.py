"""Finding generation for security-rule controls.

Same path as every other control type since 2026-09-16: an `ObjectFindingSpec` handed to
`generate_object_findings`, not a hand-rolled copy of it.

Two divergences were removed together, because one caused the other. Policy findings used to be
built by a private generator in this module - about 45 lines re-implementing the shared machinery
that `object_findings` exists to hold - and `RuleFinding` was built on `FindingBase` rather than
`ObjectFindingBase`, so it carried no `subject_name` and this module wrote no subject sentence. A
policy finding read "Matched control query: Baseline." and could not say which rule, in which
vsys, in which rulebase. Jason, 2026-09-16: "I want policy based controls and findings to follow
the same path as the non-policy based path where practical/reasonable."

What stays rule-specific is what should: the sentence describing the subject, written by hand
here, next to the controls it describes.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_control_queries
from assessments.models import Control, RuleFinding, RuleFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import (
    SecurityRule,
    SecurityRuleProfileVerdict,
)

#: How a rule's config source reads in prose. The stored values are storage, not English.
RULEBASE_LABEL = {
    SecurityRule.SOURCE_LOCAL: "local rulebase",
    SecurityRule.SOURCE_PUSHED_PRE: "Panorama pre-rulebase",
    SecurityRule.SOURCE_PUSHED_POST: "Panorama post-rulebase",
    SecurityRule.SOURCE_DEFAULT: "default rules",
}


def rule_scope(obj) -> str:
    """`<config_source>:<vsys>` - the axis a rule name can collide on.

    A rule name is unique only per enforcement point
    (`integrations_unique_security_rule_name_per_point`), so the same name legitimately exists in
    several vsys. The config source is carried too: a local rule and a Panorama pre-rule are
    different objects a reader must be able to tell apart.
    """
    return f"{obj.config_source}:{obj.enforcement_point.vsys_name}"[:128]


def _subject(obj) -> str:
    where = RULEBASE_LABEL.get(obj.config_source, obj.config_source)
    subject = (f"Rule {obj.name} at position {obj.effective_order} of the {where} "
               f"on {obj.enforcement_point}")
    detail = []
    if obj.action:
        detail.append(f"action {obj.action}")
    if obj.disabled:
        # A disabled rule enforces nothing. The finding is still real - the rule is in the
        # configuration and one click from taking effect - but a reader must not be left to
        # assume it is live.
        detail.append("DISABLED, so it is not currently enforcing")
    if detail:
        subject += f" ({', '.join(detail)})"
    return subject


#: Which assertion each threat-profile control reads, so a finding can say what is wrong with
#: the profile rather than only which rule matched. Keyed by control id because the sentence is
#: shared by every security-rule control and the twenty-odd PAN-POL ones must not grow a clause.
THREAT_PROFILE_CONTROL_ASSERTIONS = {
    "PAN-AVW-001": SecurityRuleProfileVerdict.ANTIVIRUS_BLOCKS_MALWARE,
    "PAN-AVW-002": SecurityRuleProfileVerdict.ANTIVIRUS_INLINE_ML,
    "PAN-SPY-001": SecurityRuleProfileVerdict.SPYWARE_SEVERITIES,
    "PAN-SPY-002": SecurityRuleProfileVerdict.SPYWARE_DNS_SINKHOLE,
    "PAN-SPY-003": SecurityRuleProfileVerdict.SPYWARE_DNS_CATEGORIES,
    "PAN-SPY-004": SecurityRuleProfileVerdict.SPYWARE_INLINE,
    "PAN-SPY-005": SecurityRuleProfileVerdict.SPYWARE_EXCEPTIONS,
    "PAN-VLN-001": SecurityRuleProfileVerdict.VULNERABILITY_SEVERITIES,
    "PAN-VLN-002": SecurityRuleProfileVerdict.VULNERABILITY_BRUTE_FORCE,
    "PAN-VLN-003": SecurityRuleProfileVerdict.VULNERABILITY_INLINE,
    "PAN-VLN-004": SecurityRuleProfileVerdict.VULNERABILITY_EXCEPTIONS,
}


def _threat_profile_clause(obj, matched_queries) -> str:
    """What is wrong with the profile in force, for the controls that ask about one.

    A rule finding says which rule, where, and that a query matched. For the nine controls
    converted from profile-based to rule-based on 2026-10-12 that is not enough on its own:
    the thing to go and fix is a PROFILE, and without naming it the finding sends a reader to
    the rule, where there is nothing to change.

    Varies by WHICH control matched, read off the matched queries, because this sentence is
    shared with every PAN-POL control and those should read exactly as they did before.
    """
    assertions = {
        THREAT_PROFILE_CONTROL_ASSERTIONS[query.control.control_id]
        for query in matched_queries
        if query.control.control_id in THREAT_PROFILE_CONTROL_ASSERTIONS
    }
    if not assertions:
        return ""
    parts = []
    for row in obj.profile_verdicts.all():
        # `is not True` rather than `is False`: a NULL verdict means no profile of that kind
        # reaches the rule, which fires these controls (Jason, 2026-10-12) - so the sentence
        # has to say it, and the row's detail is the only place that distinguishes "no profile"
        # from "a profile that does not do the job".
        if row.assertion not in assertions or row.satisfied is True:
            continue
        if not row.profile_name:
            parts.append(row.detail or "no profile of this kind is in force")
            continue
        parts.append(f"{row.profile_name}: {row.detail}" if row.detail else row.profile_name)
    return "; ".join(sorted(parts))


def build_rule_finding_summary(obj, matched_queries) -> str:
    subject = _subject(obj)
    clause = _threat_profile_clause(obj, matched_queries)
    if clause:
        # "is protected by X: <gap>" reads wrong for an ABSENT profile, where the clause is
        # already a sentence of its own.
        joiner = " - " if clause.startswith("no ") else " is protected by "
        subject += f"{joiner}{clause}"
    return matched_query_sentence(subject, matched_queries)


SPEC = ObjectFindingSpec(
    label="security rule",
    control_type=Control.ControlType.SECURITY_RULE,
    finding_model=RuleFinding,
    link_model=RuleFindingControlQuery,
    subject_fk="security_rule",
    link_fk="rule_finding",
    # `profile_verdicts` is prefetched because the subject sentence reads it for the
    # nine threat-profile controls; without it this is a query per rule per finding.
    queryset=lambda: SecurityRule.objects.select_related(
        "enforcement_point").prefetch_related("profile_verdicts"),
    evaluate=evaluate_control_queries,
    summary=build_rule_finding_summary,
    #: PAN-OS caps a rule name at 63 characters and the model allows 255; truncate rather than
    #: fail a whole run on a name that should not exist.
    subject_name=lambda obj: obj.name[:64],
    subject_scope=rule_scope,
)


def generate_rule_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_rule_findings() -> ObjectFindingRunResult:
    """Re-run security-rule controls alone. Every other kind already had this."""
    return regenerate_object_findings(SPEC)
