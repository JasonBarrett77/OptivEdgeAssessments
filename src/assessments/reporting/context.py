"""Report-oriented shaping for assessment findings."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from django.db.models import QuerySet

from assessments.control_queries import SEVERITY_RANK, severity_label
#: KNOWN INCOMPLETE, deliberately. Two of seven finding models. ManagementInterface,
#: InterfaceManagementProfile, SslTlsServiceProfile, CertificateProfile and Certificate
#: findings reach no client report. Not fixed yet because the enumeration is expected to
#: change as the remaining domains land - Jason, 2026-09-03. See views.FindingListView.
from assessments.models import AssessmentRun, DeviceConfigurationFinding, RuleFinding


RISK_RATING_BY_SEVERITY = {
    "critical": "D-1",
    "high": "D-2",
    "medium": "D-3",
    "low": "D-4",
    "informational": "D-5",
}


@dataclass(frozen=True)
class DetailRow:
    primary: str
    secondary: str
    description: str
    severity_label: str


@dataclass(frozen=True)
class DetailTable:
    title: str
    first_column_heading: str
    detail_rows: tuple[DetailRow, ...]


@dataclass(frozen=True)
class SummaryRow:
    sequence: int
    control_id: str
    observation: str
    recommendation: str
    importance: str
    finding_count: int
    scope_count: int
    query_names: tuple[str, ...]
    detail_table: DetailTable


@dataclass(frozen=True)
class FirewallDetailRow:
    line_reference: str
    description: str
    risk_rating: str
    severity: str
    rule_name: str
    scope_name: str


@dataclass(frozen=True)
class HealthCheckReportContext:
    assessment_run: AssessmentRun
    summary_rows: list[SummaryRow]
    firewall_detail_rows: list[FirewallDetailRow]


def get_latest_rule_assessment_run() -> AssessmentRun:
    run = (
        AssessmentRun.objects.filter(rule_findings__isnull=False)
        .distinct()
        .order_by("-created_at", "-pk")
        .first()
    )
    if run is None:
        raise ValueError("No assessment run with rule findings exists.")
    return run


def get_latest_device_configuration_assessment_run() -> AssessmentRun | None:
    return (
        AssessmentRun.objects.filter(device_configuration_findings__isnull=False)
        .distinct()
        .order_by("-created_at", "-pk")
        .first()
    )


def build_report_context(*, assessment_run: AssessmentRun | None = None) -> HealthCheckReportContext:
    selected_run = assessment_run or get_latest_rule_assessment_run()
    rule_findings = list(_rule_findings_for_run(selected_run))
    device_configuration_run = get_latest_device_configuration_assessment_run()
    device_configuration_findings = list(_device_configuration_findings_for_run(device_configuration_run)) if device_configuration_run else []
    return HealthCheckReportContext(
        assessment_run=selected_run,
        summary_rows=build_summary_rows(rule_findings, device_configuration_findings),
        firewall_detail_rows=build_firewall_detail_rows(rule_findings),
    )


def build_summary_rows(
    rule_findings: list[RuleFinding] | QuerySet[RuleFinding],
    device_configuration_findings: list[DeviceConfigurationFinding] | QuerySet[DeviceConfigurationFinding] | None = None,
) -> list[SummaryRow]:
    grouped_rows = _build_rule_summary_candidates(list(rule_findings))
    if device_configuration_findings:
        grouped_rows.extend(_build_device_configuration_summary_candidates(list(device_configuration_findings)))

    grouped_rows.sort(
        key=lambda row: (
            -SEVERITY_RANK[row["highest_severity"]],
            -int(row["finding_count"]),
            str(row["control_id"]),
        )
    )

    summary_rows: list[SummaryRow] = []
    for index, row in enumerate(grouped_rows, start=1):
        summary_rows.append(
            SummaryRow(
                sequence=index,
                control_id=str(row["control_id"]),
                observation=_build_observation_text(
                    control_name=str(row["control_name"]),
                    finding_count=int(row["finding_count"]),
                    scope_count=int(row["scope_count"]),
                    query_names=tuple(row["query_names"]),
                ),
                recommendation=str(row["recommendation"]),
                importance=severity_label(str(row["highest_severity"])),
                finding_count=int(row["finding_count"]),
                scope_count=int(row["scope_count"]),
                query_names=tuple(row["query_names"]),
                detail_table=row["detail_table"],
            )
        )
    return summary_rows


def build_firewall_detail_rows(findings: list[RuleFinding] | QuerySet[RuleFinding]) -> list[FirewallDetailRow]:
    detail_rows: list[FirewallDetailRow] = []
    if hasattr(findings, "order_by"):
        ordered_findings = findings.order_by(
            "-created_at",
            "security_rule__enforcement_point__vsys_name",
            "security_rule__effective_order",
            "security_rule__name",
            "pk",
        )
    else:
        ordered_findings = sorted(
            findings,
            key=lambda finding: (
                -finding.pk,
                finding.security_rule.enforcement_point.vsys_name,
                finding.security_rule.effective_order,
                finding.security_rule.name,
                finding.pk,
            ),
        )

    for finding in ordered_findings:
        security_rule = finding.security_rule
        scope_name = security_rule.enforcement_point.vsys_display_name or security_rule.enforcement_point.vsys_name
        detail_rows.append(
            FirewallDetailRow(
                line_reference=str(security_rule.rule_position or security_rule.effective_order),
                description=_build_firewall_description(finding),
                risk_rating=RISK_RATING_BY_SEVERITY[finding.severity],
                severity=severity_label(finding.severity),
                rule_name=security_rule.name,
                scope_name=scope_name,
            )
        )
    return detail_rows


def _format_rule_provenance_for_report(finding: RuleFinding) -> str:
    security_rule = finding.security_rule
    entry_prov = next(
        (fp for fp in security_rule.field_provenance.all() if fp.field_name == "__entry__"),
        None,
    )
    raw_value = (entry_prov.raw_value or "").strip() if entry_prov is not None else ""
    prov_type = (entry_prov.provenance_type or "") if entry_prov is not None else ""

    if security_rule.config_source in {
        security_rule.SOURCE_PUSHED_PRE,
        security_rule.SOURCE_PUSHED_POST,
    }:
        return f"Device group: {raw_value}" if raw_value else "Device group"

    if security_rule.config_source == security_rule.SOURCE_DEFAULT:
        if prov_type == "device_group":
            return f"Device group: {raw_value}" if raw_value else "Device group"
        return "Local firewall"

    if security_rule.config_source == security_rule.SOURCE_LOCAL:
        if prov_type == "device_group":
            return f"Local firewall: {raw_value}"
        return "Local firewall"

    return raw_value or "Not specified"


def _rule_findings_for_run(assessment_run: AssessmentRun) -> QuerySet[RuleFinding]:
    return (
        RuleFinding.objects.filter(assessment_run=assessment_run)
        .select_related(
            "control",
            "security_rule__enforcement_point",
            "security_rule__management_station",
        )
        .prefetch_related("control_queries", "security_rule__field_provenance")
    )


def _device_configuration_findings_for_run(assessment_run: AssessmentRun | None) -> QuerySet[DeviceConfigurationFinding]:
    if assessment_run is None:
        return DeviceConfigurationFinding.objects.none()
    return (
        DeviceConfigurationFinding.objects.filter(assessment_run=assessment_run)
        .select_related(
            "control",
            "device_configuration_profile__appliance",
            "device_configuration_profile__management_station",
        )
        .prefetch_related("control_queries")
    )


def _build_rule_summary_candidates(findings: list[RuleFinding]) -> list[dict[str, object]]:
    grouped_findings: dict[tuple[int, str], list[RuleFinding]] = defaultdict(list)
    for finding in findings:
        grouped_findings[(finding.control_id, finding.severity)].append(finding)

    grouped_rows: list[dict[str, object]] = []
    for control_findings in grouped_findings.values():
        first_finding = control_findings[0]
        control = first_finding.control
        grouped_rows.append(
            {
                "control_id": control.control_id,
                "control_name": control.name,
                "recommendation": _build_summary_recommendation(control.remediation),
                "highest_severity": _highest_severity([finding.severity for finding in control_findings]),
                "finding_count": len(control_findings),
                "scope_count": len(
                    {finding.security_rule.enforcement_point_id for finding in control_findings}
                ),
                "query_names": sorted(
                    {
                        query.name
                        for finding in control_findings
                        for query in finding.control_queries.all()
                    }
                ),
                "detail_table": DetailTable(
                    title=f"{control.name} ({severity_label(control_findings[0].severity)})",
                    first_column_heading="Rule name\nprovenance",
                    detail_rows=tuple(
                        DetailRow(
                            primary=finding.security_rule.name,
                            secondary=_format_rule_provenance_for_report(finding),
                            description=_build_firewall_description(finding),
                            severity_label=severity_label(finding.severity),
                        )
                        for finding in sorted(
                            control_findings,
                            key=lambda finding: (
                                finding.security_rule.enforcement_point.vsys_name,
                                finding.security_rule.effective_order,
                                finding.security_rule.name,
                                finding.pk,
                            ),
                        )
                    ),
                ),
            }
        )
    return grouped_rows


def _build_device_configuration_summary_candidates(findings: list[DeviceConfigurationFinding]) -> list[dict[str, object]]:
    grouped_findings: dict[tuple[int, str], list[DeviceConfigurationFinding]] = defaultdict(list)
    for finding in findings:
        grouped_findings[(finding.control_id, finding.severity)].append(finding)

    grouped_rows: list[dict[str, object]] = []
    for control_findings in grouped_findings.values():
        first_finding = control_findings[0]
        control = first_finding.control
        grouped_rows.append(
            {
                "control_id": control.control_id,
                "control_name": control.name,
                "recommendation": _build_summary_recommendation(control.remediation),
                "highest_severity": _highest_severity([finding.severity for finding in control_findings]),
                "finding_count": len(control_findings),
                "scope_count": len({finding.device_configuration_profile.appliance_id for finding in control_findings}),
                "query_names": [
                    query_name
                    for query_name in sorted(
                        {
                            query.name
                            for finding in control_findings
                            for query in finding.control_queries.all()
                        }
                    )
                    if query_name.lower() != "baseline"
                ],
                "detail_table": DetailTable(
                    title=f"{control.name} ({severity_label(control_findings[0].severity)})",
                    first_column_heading="Appliance\nsource",
                    detail_rows=tuple(
                        DetailRow(
                            primary=(
                                finding.device_configuration_profile.appliance.hostname
                                or finding.device_configuration_profile.appliance.serial_number
                            ),
                            secondary=(
                                finding.device_configuration_profile.management_station.hostname
                                or "Not specified"
                            ),
                            description=_build_device_configuration_description(finding),
                            severity_label=severity_label(finding.severity),
                        )
                        for finding in sorted(
                            control_findings,
                            key=lambda finding: (
                                finding.device_configuration_profile.appliance.hostname
                                or finding.device_configuration_profile.appliance.serial_number,
                                finding.pk,
                            ),
                        )
                    ),
                ),
            }
        )
    return grouped_rows


def _build_summary_recommendation(remediation: str) -> str:
    text = (remediation or "").strip()
    if not text:
        return "Review and remediate matching findings for this control."

    compact = " ".join(text.split())
    first_sentence = compact.split(". ", 1)[0].strip()
    if first_sentence and not first_sentence.endswith("."):
        first_sentence += "."
    return first_sentence or compact


def _highest_severity(severity_values: list[str]) -> str:
    if not severity_values:
        return "informational"
    return max(severity_values, key=lambda value: SEVERITY_RANK[value])


def _build_observation_text(
    *,
    control_name: str,
    finding_count: int,
    scope_count: int,
    query_names: tuple[str, ...] | list[str],
) -> str:
    finding_label = "finding" if finding_count == 1 else "findings"
    scope_label = "policy scope" if scope_count == 1 else "policy scopes"
    observation = f"{control_name}. {finding_count} matching {finding_label} across {scope_count} {scope_label}."
    if query_names:
        trigger_label = "Trigger" if len(query_names) == 1 else "Triggers"
        observation += f" {trigger_label}: {'; '.join(query_names)}."
    return observation


def _build_firewall_description(finding: RuleFinding) -> str:
    security_rule = finding.security_rule
    summary = finding.summary.strip() or finding.control.description.strip() or finding.control.name
    return summary


def _build_device_configuration_description(finding: DeviceConfigurationFinding) -> str:
    summary = finding.summary.strip() or finding.control.description.strip() or finding.control.name
    return summary
