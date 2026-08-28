"""Every non-policy control, in one run.

The UI offers two actions: policy, and everything else. That split is the one a user
recognises - "are my rules bad" versus "is my device configured badly" - whereas the
target-model split behind it is an implementation detail. A user pressing one button
expects one assessment run, so the per-type generators fill a run they are handed rather
than each creating their own.

Adding a control type means adding one line to GENERATORS. It should not mean adding a
button, because the number of buttons is a question about what a user is asking, not about
how many models back the answer.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.utils import timezone

from assessments.device_configuration_findings import generate_device_configuration_findings
from assessments.management_interface_findings import generate_management_interface_findings
from assessments.models import AssessmentRun

#: Ordered so a report reads device-wide settings before per-surface exposure.
GENERATORS = (
    ("device configuration", generate_device_configuration_findings),
    ("management interface", generate_management_interface_findings),
)


@dataclass
class ConfigurationFindingRunResult:
    assessment_run: AssessmentRun
    controls_evaluated: int
    findings_created: int
    query_links_created: int
    skipped_queries: int
    #: Per-generator counts, so a caller can say WHICH kind produced nothing.
    by_kind: dict


def regenerate_configuration_findings() -> ConfigurationFindingRunResult:
    assessment_run = AssessmentRun.objects.create(
        name=f"Configuration Findings {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        status=AssessmentRun.Status.RUNNING,
        started_at=timezone.now(),
    )
    totals = [0, 0, 0, 0]
    by_kind = {}
    try:
        for label, generate in GENERATORS:
            counts = generate(assessment_run)
            by_kind[label] = counts
            totals = [a + b for a, b in zip(totals, counts)]
    except Exception:
        # One generator failing fails the run. A partially-filled run reported as complete
        # would understate findings, which is the direction that hides problems.
        assessment_run.mark_failed()
        assessment_run.save(update_fields=["status", "completed_at"])
        raise

    assessment_run.mark_completed()
    assessment_run.save(update_fields=["status", "completed_at"])
    return ConfigurationFindingRunResult(
        assessment_run=assessment_run,
        controls_evaluated=totals[0], findings_created=totals[1],
        query_links_created=totals[2], skipped_queries=totals[3], by_kind=by_kind)
