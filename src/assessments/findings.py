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
from optivedge_integrations.integrations.models import SecurityRule

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


def build_rule_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="security rule",
    control_type=Control.ControlType.SECURITY_RULE,
    finding_model=RuleFinding,
    link_model=RuleFindingControlQuery,
    subject_fk="security_rule",
    link_fk="rule_finding",
    queryset=lambda: SecurityRule.objects.select_related("enforcement_point"),
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
