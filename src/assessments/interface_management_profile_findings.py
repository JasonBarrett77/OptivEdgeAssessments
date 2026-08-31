"""Finding generation for interface-management-profile controls.

One finding per profile per appliance. A profile pushed from a Panorama template to ten
firewalls and bound on two produces eight findings, and that is the honest count: eight
devices carry a profile that does nothing. Collapsing them to one would read better and
assert something the data does not support, since each device's binding state is its own
fact. If that proves too noisy the fix belongs in presentation, which is where the policy
plane already makes the equivalent choice.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from assessments.control_queries import evaluate_interface_management_profile_control_queries
from assessments.models import (
    AssessmentRun,
    Control,
    InterfaceManagementProfileFinding,
    InterfaceManagementProfileFindingControlQuery,
)
from optivedge_integrations.integrations.models import InterfaceManagementProfile


@dataclass
class InterfaceManagementProfileFindingRunResult:
    assessment_run: AssessmentRun
    controls_evaluated: int
    findings_created: int
    query_links_created: int
    skipped_queries: int


def build_interface_management_profile_finding_summary(profile, matched_queries) -> str:
    """Lead with the subject, and say what it is - not what it exposes, because it does not."""
    subject = f"Profile {profile.name} on {profile.appliance}"
    if profile.bound_interface_count == 0:
        subject += " is bound to no interface"
    else:
        subject += f" is bound to {', '.join(profile.bound_interface_names)}"
    names = [query.name for query in matched_queries]
    if not names:
        return subject + "."
    if len(names) == 1:
        return f"{subject}. Matched control query: {names[0]}."
    return f"{subject}. Matched control queries: {', '.join(names)}."


def generate_interface_management_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    controls = list(
        Control.objects.filter(
            control_type=Control.ControlType.INTERFACE_MANAGEMENT_PROFILE,
            is_active=True,
        ).order_by("control_id")
    )
    base_queryset = InterfaceManagementProfile.objects.select_related("appliance")
    findings_created = 0
    query_links_created = 0
    skipped_queries = 0

    with transaction.atomic():
        InterfaceManagementProfileFinding.objects.all().delete()

        for control in controls:
            (
                _matched_queryset,
                _active_queries,
                control_skipped_queries,
                matched_by_profile,
                severity_by_profile_id,
            ) = evaluate_interface_management_profile_control_queries(base_queryset, control)
            skipped_queries += control_skipped_queries

            profiles = {
                profile.pk: profile
                for profile in base_queryset.filter(pk__in=matched_by_profile)
            }
            for profile_id, matched_queries in matched_by_profile.items():
                profile = profiles[profile_id]
                finding = InterfaceManagementProfileFinding.objects.create(
                    assessment_run=assessment_run,
                    control=control,
                    interface_management_profile=profile,
                    severity=severity_by_profile_id[profile_id],
                    title=control.name,
                    subject_name=profile.name,
                    summary=build_interface_management_profile_finding_summary(
                        profile, matched_queries),
                    matched_query_names=[q.name for q in matched_queries],
                )
                findings_created += 1

                links = [
                    InterfaceManagementProfileFindingControlQuery(
                        interface_management_profile_finding=finding,
                        control_query=control_query,
                    )
                    for control_query in matched_queries
                ]
                InterfaceManagementProfileFindingControlQuery.objects.bulk_create(links)
                query_links_created += len(links)

    return len(controls), findings_created, query_links_created, skipped_queries


def regenerate_interface_management_profile_findings() -> InterfaceManagementProfileFindingRunResult:
    """One run covering profile controls only. Kept for direct callers."""
    assessment_run = AssessmentRun.objects.create(
        name=f"Interface Management Profile Findings {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        status=AssessmentRun.Status.RUNNING,
        started_at=timezone.now(),
    )
    try:
        controls, findings, links, skipped = generate_interface_management_profile_findings(
            assessment_run)
    except Exception:
        assessment_run.mark_failed()
        assessment_run.save(update_fields=["status", "completed_at"])
        raise
    assessment_run.mark_completed()
    assessment_run.save(update_fields=["status", "completed_at"])
    return InterfaceManagementProfileFindingRunResult(
        assessment_run=assessment_run, controls_evaluated=controls,
        findings_created=findings, query_links_created=links, skipped_queries=skipped)
