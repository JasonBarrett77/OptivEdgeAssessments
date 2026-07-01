"""Finding generation for assessment controls."""

from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from assessments.control_queries import evaluate_control_queries
from assessments.models import AssessmentRun, Control, RuleFinding, RuleFindingControlQuery
from optivedge.integrations.models import SecurityRule


@dataclass
class RuleFindingRunResult:
    assessment_run: AssessmentRun
    controls_evaluated: int
    findings_created: int
    query_links_created: int
    skipped_queries: int


def build_rule_finding_summary(matched_queries) -> str:
    query_names = [query.name for query in matched_queries]
    if not query_names:
        return ""
    if len(query_names) == 1:
        return f"Matched control query: {query_names[0]}."
    return f"Matched control queries: {', '.join(query_names)}."


def regenerate_rule_findings() -> RuleFindingRunResult:
    assessment_run = AssessmentRun.objects.create(
        name=f"Rule Findings {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        status=AssessmentRun.Status.RUNNING,
        started_at=timezone.now(),
    )
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

    try:
        with transaction.atomic():
            RuleFinding.objects.all().delete()

            for control in controls:
                _matched_queryset, _active_queries, control_skipped_queries, matched_by_rule, severity_by_rule_id = (
                    evaluate_control_queries(base_queryset, control)
                )
                skipped_queries += control_skipped_queries

                for rule_id, matched_queries in matched_by_rule.items():
                    finding = RuleFinding.objects.create(
                        assessment_run=assessment_run,
                        control=control,
                        security_rule_id=rule_id,
                        severity=severity_by_rule_id[rule_id],
                        title=control.name,
                        summary=build_rule_finding_summary(matched_queries),
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
    except Exception:
        assessment_run.mark_failed()
        assessment_run.save(update_fields=["status", "completed_at"])
        raise

    assessment_run.mark_completed()
    assessment_run.save(update_fields=["status", "completed_at"])
    return RuleFindingRunResult(
        assessment_run=assessment_run,
        controls_evaluated=len(controls),
        findings_created=findings_created,
        query_links_created=query_links_created,
        skipped_queries=skipped_queries,
    )
