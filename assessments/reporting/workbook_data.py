"""Workbook-oriented report shaping for detailed findings exports."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass

from assessments.models import Control, ManagementPlaneFinding, RuleFinding
from assessments.reporting.context import build_report_context, get_latest_management_assessment_run, get_latest_rule_assessment_run
from optivedge.integrations.models import ApplicationEnvironment


SHEET_NAME_LIMIT = 31


@dataclass(frozen=True)
class WorkbookSheet:
    sequence: int
    sheet_name: str
    control_name: str
    control_id: str
    control_type: str
    severity: str
    default_severity: str
    finding_count: int
    scope_count: int
    triggers: list[str]
    description: str
    rationale: str
    audit: str
    remediation: str
    rows: list[dict]


@dataclass(frozen=True)
class WorkbookExportData:
    client_name: str
    client_short_name: str
    opportunity_number: str
    generated_date: str
    sheets: list[WorkbookSheet]


def build_workbook_export_data(*, generated_date: str) -> WorkbookExportData:
    application_environment = _get_application_environment()
    context = build_report_context()
    rule_run = get_latest_rule_assessment_run()
    management_run = get_latest_management_assessment_run()

    rule_findings = list(
        RuleFinding.objects.filter(assessment_run=rule_run)
        .select_related(
            "control",
            "security_rule__management_station",
            "security_rule__enforcement_point",
            "security_rule__enforcement_point__appliance_group",
        )
        .prefetch_related(
            "control_queries",
            "security_rule__securityrulefromzones",
            "security_rule__securityruletozones",
            "security_rule__source_address_refs__address_object",
            "security_rule__source_address_refs__address_group",
            "security_rule__destination_address_refs__address_object",
            "security_rule__destination_address_refs__address_group",
            "security_rule__securityruleapplications",
            "security_rule__securityruleservices",
        )
    )
    management_findings = list(
        ManagementPlaneFinding.objects.filter(assessment_run=management_run).select_related(
            "control",
            "management_profile__management_station",
            "management_profile__appliance",
            "management_profile__appliance_group",
        ).prefetch_related("control_queries")
    ) if management_run else []

    sheets: list[WorkbookSheet] = []
    name_counts = Counter(row.control_id for row in context.summary_rows)
    used_sheet_names: set[str] = set()

    for summary_row in context.summary_rows:
        is_duplicate_control = name_counts[summary_row.control_id] > 1
        sheet_name = _build_sheet_name(
            base_name=summary_row.control_id and summary_row.control_id,
            control_name=summary_row.detail_table.title.split(" (", 1)[0],
            severity=summary_row.importance,
            duplicate_control=is_duplicate_control,
            used_sheet_names=used_sheet_names,
        )

        if summary_row.control_id.startswith("FW-"):
            matching = [
                finding for finding in rule_findings
                if finding.control.control_id == summary_row.control_id
                and finding.get_severity_display() == summary_row.importance
            ]
            control = matching[0].control
            rows = [_build_rule_row(finding) for finding in matching]
        else:
            matching = [
                finding for finding in management_findings
                if finding.control.control_id == summary_row.control_id
                and finding.get_severity_display() == summary_row.importance
            ]
            control = matching[0].control
            rows = [_build_management_row(finding) for finding in matching]

        sheets.append(
            WorkbookSheet(
                sequence=summary_row.sequence,
                sheet_name=sheet_name,
                control_name=control.name,
                control_id=control.control_id,
                control_type=control.get_control_type_display(),
                severity=summary_row.importance,
                default_severity=control.get_default_severity_display(),
                finding_count=summary_row.finding_count,
                scope_count=summary_row.scope_count,
                triggers=list(summary_row.query_names),
                description=control.description,
                rationale=control.rationale,
                audit=control.audit,
                remediation=control.remediation,
                rows=rows,
            )
        )

    return WorkbookExportData(
        client_name=application_environment.client_name,
        client_short_name=application_environment.client_short_name,
        opportunity_number=application_environment.opportunity_number,
        generated_date=generated_date,
        sheets=sheets,
    )


def export_data_as_dict(*, generated_date: str) -> dict:
    return asdict(build_workbook_export_data(generated_date=generated_date))


def _get_application_environment() -> ApplicationEnvironment:
    application_environments = list(ApplicationEnvironment.objects.order_by("pk")[:2])
    if len(application_environments) > 1:
        raise ValueError("Expected a single ApplicationEnvironment record for this deployment.")
    if not application_environments:
        raise ValueError("ApplicationEnvironment must be configured before generating the workbook.")
    return application_environments[0]


def _build_sheet_name(*, base_name: str, control_name: str, severity: str, duplicate_control: bool, used_sheet_names: set[str]) -> str:
    candidate = control_name.strip()
    if duplicate_control:
        candidate = f"{candidate} ({severity})"
    candidate = candidate[:SHEET_NAME_LIMIT].rstrip()
    if candidate not in used_sheet_names:
        used_sheet_names.add(candidate)
        return candidate

    counter = 2
    while True:
        suffix = f" {counter}"
        candidate_variant = f"{candidate[:SHEET_NAME_LIMIT - len(suffix)].rstrip()}{suffix}"
        if candidate_variant not in used_sheet_names:
            used_sheet_names.add(candidate_variant)
            return candidate_variant
        counter += 1


def _build_rule_row(finding: RuleFinding) -> dict:
    security_rule = finding.security_rule
    return {
        "severity": finding.get_severity_display(),
        "status": finding.get_status_display(),
        "station": str(security_rule.management_station),
        "vsys_name": security_rule.enforcement_point.vsys_name,
        "vsys_display_name": security_rule.enforcement_point.vsys_display_name,
        "rule_name": security_rule.name,
        "provenance": security_rule.provenance,
        "config_source": security_rule.config_source,
        "effective_order": security_rule.effective_order,
        "rule_position": security_rule.rule_position,
        "action": security_rule.action,
        "disabled": "Yes" if security_rule.disabled else "No",
        "rule_type": security_rule.rule_type,
        "description": security_rule.description,
        "from_zones": ", ".join(value.value for value in security_rule.securityrulefromzones.all()),
        "to_zones": ", ".join(value.value for value in security_rule.securityruletozones.all()),
        "source_addresses": ", ".join(_address_label(ref) for ref in security_rule.source_address_refs.all()),
        "destination_addresses": ", ".join(_address_label(ref) for ref in security_rule.destination_address_refs.all()),
        "applications": ", ".join(value.value for value in security_rule.securityruleapplications.all()),
        "services": ", ".join(value.value for value in security_rule.securityruleservices.all()),
        "matched_queries": ", ".join(query.name for query in finding.control_queries.all()),
        "finding_summary": finding.summary,
    }


def _build_management_row(finding: ManagementPlaneFinding) -> dict:
    profile = finding.management_profile
    appliance = profile.appliance
    group = profile.appliance_group
    return {
        "severity": finding.get_severity_display(),
        "status": finding.get_status_display(),
        "station": str(profile.management_station),
        "appliance": appliance.hostname or appliance.serial_number,
        "serial_number": appliance.serial_number,
        "model": appliance.model,
        "software_version": appliance.software_version,
        "appliance_group": group.name if group else "",
        "group_type": group.get_group_type_display() if group else "",
        "config_source": profile.config_source,
        "ha_required": "Yes" if profile.ha_required else "No",
        "ha_enabled": "Yes" if profile.ha_enabled else "No",
        "ha_state_sync_enabled": "Yes" if profile.ha_state_sync_enabled else "No",
        "ha_link_monitoring_enabled": "Yes" if profile.ha_link_monitoring_enabled else "No",
        "ntp_primary_server": profile.ntp_primary_server,
        "ntp_secondary_server": profile.ntp_secondary_server,
        "permitted_ip_count": profile.permitted_ip_count,
        "has_unrestricted_permitted_ips": "Yes" if profile.has_unrestricted_permitted_ips else "No",
        "idle_timeout_minutes": profile.idle_timeout_minutes,
        "login_banner": profile.login_banner,
        "matched_queries": ", ".join(query.name for query in finding.control_queries.all()),
        "finding_summary": finding.summary,
    }


def _address_label(address_ref) -> str:
    if address_ref.address_group is not None:
        return address_ref.address_group.name
    if address_ref.address_object is not None:
        return address_ref.address_object.name
    return address_ref.raw_value
