"""Finding generation for management-surface controls.

One finding per SURFACE, not per appliance. An appliance carries several administrative
surfaces and each is a separate exposure, so a control asserting "management access is
restricted" legitimately produces several findings for one device. The subject name is
frozen onto the finding at generation time for the same reason `matched_query_names` is:
an interface can be renamed or a profile unbound, and a finding must still say what it
found when it found it.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from assessments.control_queries import evaluate_management_interface_control_queries
from assessments.management_interface_naming import surface_label
from assessments.models import (
    AssessmentRun,
    Control,
    ManagementInterfaceFinding,
    ManagementInterfaceFindingControlQuery,
)
from optivedge_integrations.integrations.models import ManagementInterface


@dataclass
class ManagementInterfaceFindingRunResult:
    assessment_run: AssessmentRun
    controls_evaluated: int
    findings_created: int
    query_links_created: int
    skipped_queries: int


def build_management_interface_finding_summary(surface, matched_queries) -> str:
    """Lead with the subject - a finding that does not name its door is not actionable."""
    names = [query.name for query in matched_queries]
    subject = f"{surface_label(surface)} on {surface.appliance}"
    if not names:
        return subject + "."
    if len(names) == 1:
        return f"{subject}. Matched control query: {names[0]}."
    return f"{subject}. Matched control queries: {', '.join(names)}."


def regenerate_management_interface_findings() -> ManagementInterfaceFindingRunResult:
    assessment_run = AssessmentRun.objects.create(
        name=f"Management Interface Findings {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        status=AssessmentRun.Status.RUNNING,
        started_at=timezone.now(),
    )
    controls = list(
        Control.objects.filter(
            control_type=Control.ControlType.MANAGEMENT_INTERFACE,
            is_active=True,
        ).order_by("control_id")
    )
    base_queryset = ManagementInterface.objects.select_related("appliance")
    findings_created = 0
    query_links_created = 0
    skipped_queries = 0

    try:
        with transaction.atomic():
            ManagementInterfaceFinding.objects.all().delete()

            for control in controls:
                (
                    _matched_queryset,
                    _active_queries,
                    control_skipped_queries,
                    matched_by_surface,
                    severity_by_surface_id,
                ) = evaluate_management_interface_control_queries(base_queryset, control)
                skipped_queries += control_skipped_queries

                surfaces = {
                    surface.pk: surface
                    for surface in base_queryset.filter(pk__in=matched_by_surface)
                }
                for surface_id, matched_queries in matched_by_surface.items():
                    surface = surfaces[surface_id]
                    finding = ManagementInterfaceFinding.objects.create(
                        assessment_run=assessment_run,
                        control=control,
                        management_interface=surface,
                        severity=severity_by_surface_id[surface_id],
                        title=control.name,
                        subject_name=surface_label(surface),
                        summary=build_management_interface_finding_summary(surface, matched_queries),
                        matched_query_names=[q.name for q in matched_queries],
                    )
                    findings_created += 1

                    links = [
                        ManagementInterfaceFindingControlQuery(
                            management_interface_finding=finding,
                            control_query=control_query,
                        )
                        for control_query in matched_queries
                    ]
                    ManagementInterfaceFindingControlQuery.objects.bulk_create(links)
                    query_links_created += len(links)
    except Exception:
        assessment_run.mark_failed()
        assessment_run.save(update_fields=["status", "completed_at"])
        raise

    assessment_run.mark_completed()
    assessment_run.save(update_fields=["status", "completed_at"])
    return ManagementInterfaceFindingRunResult(
        assessment_run=assessment_run,
        controls_evaluated=len(controls),
        findings_created=findings_created,
        query_links_created=query_links_created,
        skipped_queries=skipped_queries,
    )
