"""Finding generation for security-rule controls.

Fills a run it is handed, like every other generator in `finding_run.GENERATORS`. Until
2026-09-16 this created a run of its own behind a separate "Run Policy Findings" button, so policy
and device findings never shared a run. Jason, 2026-09-16: "The split between policy and device
findings shouldn't exist."
"""

from __future__ import annotations

from django.db import transaction

from assessments.control_queries import evaluate_control_queries
from assessments.models import Control, RuleFinding, RuleFindingControlQuery
from optivedge_integrations.integrations.models import SecurityRule


def build_rule_finding_summary(matched_queries) -> str:
    query_names = [query.name for query in matched_queries]
    if not query_names:
        return ""
    if len(query_names) == 1:
        return f"Matched control query: {query_names[0]}."
    return f"Matched control queries: {', '.join(query_names)}."


def generate_rule_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    controls = list(
        Control.objects.filter(
            control_type=Control.ControlType.SECURITY_RULE,
            is_active=True,
        ).order_by("control_id")
    )
    base_queryset = SecurityRule.objects.all()
    findings_created = 0
    query_links_created = 0
    skipped_queries = 0

    with transaction.atomic():
        RuleFinding.objects.all().delete()

        for control in controls:
            _matched_queryset, _active_queries, control_skipped_queries, matched_by_rule, severity_by_rule_id = (
                evaluate_control_queries(base_queryset, control)
            )
            skipped_queries += control_skipped_queries

            # Sorted, so the run's reference numbers follow the rules in a stable order.
            for rule_id in sorted(matched_by_rule):
                matched_queries = matched_by_rule[rule_id]
                finding = RuleFinding.objects.create(
                    assessment_run=assessment_run,
                    control=control,
                    security_rule_id=rule_id,
                    severity=severity_by_rule_id[rule_id],
                    title=control.name,
                    summary=build_rule_finding_summary(matched_queries),
                    matched_query_names=[query.name for query in matched_queries],
                )
                findings_created += 1

                links = [
                    RuleFindingControlQuery(
                        rule_finding=finding,
                        control_query=control_query,
                    )
                    for control_query in matched_queries
                ]
                RuleFindingControlQuery.objects.bulk_create(links)
                query_links_created += len(links)

    return len(controls), findings_created, query_links_created, skipped_queries
