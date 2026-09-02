"""Finding generation for SSL/TLS service profile controls.

One finding per object per appliance per scope, for the reason
`interface_management_profile_findings` records: the same object pushed from a template
exists separately in each firewall's merged config, and aggregating the copies would read
better while asserting something the data does not support.

Scope is carried on the finding because a name is not unique on a device. `TLSv1.3_Default`
exists as both a predefined and a shared entry, measured 2026-09-02, and only one of them is
in force - a finding naming the profile without its scope would not say which was assessed.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from assessments.control_queries import evaluate_ssl_tls_service_profile_control_queries
from assessments.models import (
    AssessmentRun,
    Control,
    SslTlsServiceProfileFinding,
    SslTlsServiceProfileFindingControlQuery,
)
from optivedge_integrations.integrations.models import SslTlsServiceProfile


@dataclass
class SslTlsServiceProfileFindingRunResult:
    assessment_run: AssessmentRun
    controls_evaluated: int
    findings_created: int
    query_links_created: int
    skipped_queries: int


def build_ssl_tls_service_profile_finding_summary(obj, matched_queries) -> str:
    where = f"{obj.scope}:{obj.vsys_name}" if obj.vsys_name else obj.scope
    subject = f"SSL/TLS service profile {obj.name} ({where}) on {obj.appliance}"
    subject += f" sets a minimum protocol version of {obj.min_version or 'unset'}"
    names = [query.name for query in matched_queries]
    if not names:
        return subject + "."
    if len(names) == 1:
        return f"{subject}. Matched control query: {names[0]}."
    return f"{subject}. Matched control queries: {', '.join(names)}."


def generate_ssl_tls_service_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    controls = list(
        Control.objects.filter(
            control_type=Control.ControlType.SSL_TLS_SERVICE_PROFILE,
            is_active=True,
        ).order_by("control_id")
    )
    base_queryset = SslTlsServiceProfile.objects.select_related("appliance")
    findings_created = 0
    query_links_created = 0
    skipped_queries = 0

    with transaction.atomic():
        SslTlsServiceProfileFinding.objects.all().delete()

        for control in controls:
            (
                _matched_queryset,
                _active_queries,
                control_skipped_queries,
                matched_by_object,
                severity_by_object_id,
            ) = evaluate_ssl_tls_service_profile_control_queries(base_queryset, control)
            skipped_queries += control_skipped_queries

            objects = {obj.pk: obj for obj in base_queryset.filter(pk__in=matched_by_object)}
            for object_id, matched_queries in matched_by_object.items():
                obj = objects[object_id]
                finding = SslTlsServiceProfileFinding.objects.create(
                    assessment_run=assessment_run,
                    control=control,
                    ssl_tls_service_profile=obj,
                    severity=severity_by_object_id[object_id],
                    title=control.name,
                    subject_name=obj.name,
                    subject_scope=obj.scope,
                    summary=build_ssl_tls_service_profile_finding_summary(obj, matched_queries),
                    matched_query_names=[q.name for q in matched_queries],
                )
                findings_created += 1
                links = [
                    SslTlsServiceProfileFindingControlQuery(
                        ssl_tls_service_profile_finding=finding, control_query=control_query)
                    for control_query in matched_queries
                ]
                SslTlsServiceProfileFindingControlQuery.objects.bulk_create(links)
                query_links_created += len(links)

    return len(controls), findings_created, query_links_created, skipped_queries


def regenerate_ssl_tls_service_profile_findings() -> SslTlsServiceProfileFindingRunResult:
    assessment_run = AssessmentRun.objects.create(
        name=f"SSL/TLS service profile Findings {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        status=AssessmentRun.Status.RUNNING,
        started_at=timezone.now(),
    )
    try:
        controls, findings, links, skipped = generate_ssl_tls_service_profile_findings(assessment_run)
    except Exception:
        assessment_run.mark_failed()
        assessment_run.save(update_fields=["status", "completed_at"])
        raise
    assessment_run.mark_completed()
    assessment_run.save(update_fields=["status", "completed_at"])
    return SslTlsServiceProfileFindingRunResult(
        assessment_run=assessment_run, controls_evaluated=controls,
        findings_created=findings, query_links_created=links, skipped_queries=skipped)
