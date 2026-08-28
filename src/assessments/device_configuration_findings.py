"""Finding generation for device configuration controls."""

from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from assessments.control_queries import evaluate_device_configuration_control_queries
from assessments.models import (
    AssessmentRun,
    Control,
    DeviceConfigurationFinding,
    DeviceConfigurationFindingControlQuery,
)
from optivedge_integrations.integrations.models import DeviceConfigurationProfile


@dataclass
class DeviceConfigurationFindingRunResult:
    assessment_run: AssessmentRun
    controls_evaluated: int
    findings_created: int
    query_links_created: int
    skipped_queries: int


def build_device_configuration_finding_summary(matched_queries) -> str:
    query_names = [query.name for query in matched_queries]
    if not query_names:
        return ""
    if len(query_names) == 1:
        return f"Matched control query: {query_names[0]}."
    return f"Matched control queries: {', '.join(query_names)}."


def generate_device_configuration_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped).

    Separate from the run's lifecycle so several control types can share one
    AssessmentRun - a user pressing one button expects one run, not one per target model.
    """
    controls = list(
        Control.objects.filter(
            control_type=Control.ControlType.DEVICE_CONFIGURATION,
            is_active=True,
        ).order_by("control_id")
    )
    base_queryset = DeviceConfigurationProfile.objects.all()
    findings_created = 0
    query_links_created = 0
    skipped_queries = 0

    try:
        with transaction.atomic():
            DeviceConfigurationFinding.objects.all().delete()

            for control in controls:
                (
                    _matched_queryset,
                    _active_queries,
                    control_skipped_queries,
                    matched_by_profile,
                    severity_by_profile_id,
                ) = evaluate_device_configuration_control_queries(base_queryset, control)
                skipped_queries += control_skipped_queries

                for profile_id, matched_queries in matched_by_profile.items():
                    finding = DeviceConfigurationFinding.objects.create(
                        assessment_run=assessment_run,
                        control=control,
                        device_configuration_profile_id=profile_id,
                        severity=severity_by_profile_id[profile_id],
                        title=control.name,
                        summary=build_device_configuration_finding_summary(matched_queries),
                    )
                    findings_created += 1

                    links = [
                        DeviceConfigurationFindingControlQuery(
                            device_configuration_finding=finding,
                            control_query=control_query,
                        )
                        for control_query in matched_queries
                    ]
                    DeviceConfigurationFindingControlQuery.objects.bulk_create(links)
                    query_links_created += len(links)
    except Exception:
        raise

    return len(controls), findings_created, query_links_created, skipped_queries


def regenerate_device_configuration_findings() -> DeviceConfigurationFindingRunResult:
    """One run covering device-configuration controls only. Kept for direct callers."""
    assessment_run = AssessmentRun.objects.create(
        name=f"Device Configuration Findings {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        status=AssessmentRun.Status.RUNNING,
        started_at=timezone.now(),
    )
    try:
        controls, findings, links, skipped = generate_device_configuration_findings(assessment_run)
    except Exception:
        assessment_run.mark_failed()
        assessment_run.save(update_fields=["status", "completed_at"])
        raise
    assessment_run.mark_completed()
    assessment_run.save(update_fields=["status", "completed_at"])
    return DeviceConfigurationFindingRunResult(
        assessment_run=assessment_run, controls_evaluated=controls,
        findings_created=findings, query_links_created=links, skipped_queries=skipped)
