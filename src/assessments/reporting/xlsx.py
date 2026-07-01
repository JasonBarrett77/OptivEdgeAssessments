"""XLSX workbook rendering for detailed findings artifacts."""

from __future__ import annotations

from pathlib import Path

import xlsxwriter

from .workbook_data import WorkbookExportData


SEVERITY_COLOR_BY_LABEL = {
    "Critical": "#7F1D1D",
    "High": "#D9471F",
    "Medium": "#F59E0B",
    "Low": "#7DA243",
    "Informational": "#475569",
}


def render_health_check_workbook(*, output_path: str | Path, export_data: WorkbookExportData) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    workbook = xlsxwriter.Workbook(str(output_path))
    try:
        formats = _build_formats(workbook)
        _write_index_sheet(
            workbook=workbook,
            export_data=export_data,
            formats=formats,
        )
        for sheet in export_data.sheets:
            worksheet = workbook.add_worksheet(sheet.sheet_name)
            severity_color = SEVERITY_COLOR_BY_LABEL.get(sheet.severity, "#475569")
            worksheet.set_tab_color(severity_color)
            worksheet.hide_gridlines(2)

            table_start_row = _write_sheet_header(
                worksheet=worksheet,
                sheet=sheet,
                export_data=export_data,
                formats=formats,
                severity_color=severity_color,
            )
            _write_sheet_table(
                worksheet=worksheet,
                sheet=sheet,
                formats=formats,
                table_start_row=table_start_row,
            )
        workbook.close()
    except Exception:
        workbook.close()
        raise

    return output_path


def _write_sheet_header(*, worksheet, sheet, export_data, formats, severity_color: str) -> int:
    worksheet.merge_range("A1:F1", sheet.control_name, formats["title"])
    worksheet.write("G1", sheet.severity, formats["severity_badge"][severity_color])
    worksheet.write_url("H1", "internal:'Contents'!A1", formats["nav_link"], string="Return to Contents")

    metadata_rows = [
        ("Sequence", sheet.sequence, "Control Type", sheet.control_type),
        ("Control ID", sheet.control_id, "Default Severity", sheet.default_severity),
        ("Findings", sheet.finding_count, "Affected Scopes", sheet.scope_count),
        ("Client", export_data.client_name, "Opportunity", export_data.opportunity_number),
        ("Generated", export_data.generated_date, "", ""),
    ]
    row_number = 1
    for left_label, left_value, right_label, right_value in metadata_rows:
        worksheet.write(row_number, 0, left_label, formats["meta_label"])
        worksheet.write(row_number, 1, left_value, formats["meta_value"])
        if right_label:
            worksheet.write(row_number, 3, right_label, formats["meta_label"])
            worksheet.write(row_number, 4, right_value, formats["meta_value"])
        row_number += 1

    long_text_rows = [
        ("Description", sheet.description),
        ("Rationale", sheet.rationale),
        ("Audit", sheet.audit),
        ("Remediation", sheet.remediation),
    ]
    for label, value in long_text_rows:
        worksheet.write(row_number, 0, label, formats["meta_label"])
        worksheet.merge_range(row_number, 1, row_number, 6, value or "", formats["meta_value_wrap"])
        worksheet.set_row(row_number, 42)
        row_number += 1

    worksheet.write(row_number, 0, "Triggers", formats["meta_label"])
    worksheet.merge_range(
        row_number,
        1,
        row_number,
        6,
        ", ".join(sheet.triggers) or "None",
        formats["meta_value_wrap"],
    )
    worksheet.set_row(row_number, 54)
    row_number += 1

    worksheet.set_row(0, 24)
    worksheet.set_column("A:A", 18)
    worksheet.set_column("B:B", 22)
    worksheet.set_column("C:C", 4)
    worksheet.set_column("D:D", 18)
    worksheet.set_column("E:E", 26)
    worksheet.set_column("F:F", 18)
    worksheet.set_column("G:G", 14)
    worksheet.set_column("H:H", 20)
    return row_number + 1


def _write_sheet_table(*, worksheet, sheet, formats, table_start_row: int) -> None:
    headers = _ordered_headers(sheet)
    for col_index, header in enumerate(headers):
        worksheet.write(table_start_row, col_index, _display_header(header), formats["table_header"])

    for row_offset, row in enumerate(sheet.rows, start=1):
        for col_index, header in enumerate(headers):
            value = row.get(header, "")
            cell_format = formats["table_value_wrap"] if _is_long_text_column(header) else formats["table_value"]
            worksheet.write(table_start_row + row_offset, col_index, value, cell_format)

    last_data_row = table_start_row + max(len(sheet.rows), 1)
    last_col = max(len(headers) - 1, 0)
    worksheet.autofilter(table_start_row, 0, last_data_row, last_col)
    worksheet.freeze_panes(table_start_row + 1, 4)

    width_map = {
        "severity": 12,
        "status": 10,
        "station": 22,
        "vsys_name": 14,
        "vsys_display_name": 18,
        "rule_name": 34,
        "provenance": 24,
        "config_source": 14,
        "effective_order": 14,
        "rule_position": 12,
        "action": 10,
        "disabled": 10,
        "rule_type": 14,
        "description": 34,
        "from_zones": 18,
        "to_zones": 18,
        "source_addresses": 22,
        "destination_addresses": 22,
        "applications": 22,
        "services": 18,
        "matched_queries": 30,
        "finding_summary": 34,
        "appliance": 22,
        "serial_number": 18,
        "model": 18,
        "software_version": 16,
        "appliance_group": 20,
        "group_type": 16,
        "ha_required": 12,
        "ha_enabled": 12,
        "ha_state_sync_enabled": 18,
        "ha_link_monitoring_enabled": 20,
        "ntp_primary_server": 22,
        "ntp_secondary_server": 22,
        "permitted_ip_count": 14,
        "has_unrestricted_permitted_ips": 18,
        "idle_timeout_minutes": 14,
        "login_banner": 36,
    }
    for col_index, header in enumerate(headers):
        worksheet.set_column(col_index, col_index, width_map.get(header, 18))
    worksheet.set_row(table_start_row, 28)
    for row_index in range(table_start_row + 1, last_data_row + 1):
        worksheet.set_row(row_index, 36)


def _write_index_sheet(*, workbook, export_data, formats) -> None:
    worksheet = workbook.add_worksheet("Contents")
    worksheet.hide_gridlines(2)
    worksheet.freeze_panes(2, 0)

    worksheet.merge_range("A1:F1", f"{export_data.client_name} Health Check Workbook", formats["title"])

    headers = ["#", "Control", "Severity", "Findings", "Control Type", "Tab"]
    for col_index, header in enumerate(headers):
        worksheet.write(1, col_index, header, formats["table_header"])

    for row_index, sheet in enumerate(export_data.sheets, start=2):
        worksheet.write(row_index, 0, sheet.sequence, formats["table_value"])
        worksheet.write_url(
            row_index,
            1,
            _sheet_target(sheet.sheet_name),
            formats["nav_link"],
            string=sheet.control_name,
        )
        worksheet.write(row_index, 2, sheet.severity, formats["table_value"])
        worksheet.write(row_index, 3, sheet.finding_count, formats["table_value"])
        worksheet.write(row_index, 4, sheet.control_type, formats["table_value"])
        worksheet.write_url(
            row_index,
            5,
            _sheet_target(sheet.sheet_name),
            formats["nav_link"],
            string=sheet.sheet_name,
        )

    last_data_row = max(len(export_data.sheets) + 1, 2)
    worksheet.autofilter(1, 0, last_data_row, len(headers) - 1)
    worksheet.set_column("A:A", 6)
    worksheet.set_column("B:B", 48)
    worksheet.set_column("C:C", 12)
    worksheet.set_column("D:D", 10)
    worksheet.set_column("E:E", 18)
    worksheet.set_column("F:F", 28)
    worksheet.set_row(0, 24)
    worksheet.set_row(1, 24)


def _build_formats(workbook):
    return {
        "title": workbook.add_format(
            {"bold": True, "font_size": 16, "font_color": "#0F172A", "valign": "vcenter"}
        ),
        "nav_link": workbook.add_format(
            {"font_size": 10, "font_color": "#0F4C81", "underline": 1}
        ),
        "meta_label": workbook.add_format(
            {"bold": True, "font_size": 10, "font_color": "#334155", "bg_color": "#F1F5F9", "border": 1}
        ),
        "meta_value": workbook.add_format(
            {"font_size": 10, "font_color": "#0F172A", "border": 1}
        ),
        "meta_value_wrap": workbook.add_format(
            {"font_size": 10, "font_color": "#0F172A", "border": 1, "text_wrap": True, "valign": "top"}
        ),
        "table_header": workbook.add_format(
            {
                "bold": True,
                "font_size": 10,
                "font_color": "#0F4C81",
                "bottom": 1,
                "border_color": "#CBD5E1",
                "text_wrap": True,
                "valign": "top",
            }
        ),
        "table_value": workbook.add_format(
            {"font_size": 10, "font_color": "#111827", "bottom": 1, "border_color": "#E2E8F0", "valign": "top"}
        ),
        "table_value_wrap": workbook.add_format(
            {
                "font_size": 10,
                "font_color": "#111827",
                "bottom": 1,
                "border_color": "#E2E8F0",
                "text_wrap": True,
                "valign": "top",
            }
        ),
        "severity_badge": {
            color: workbook.add_format(
                {
                    "bold": True,
                    "align": "center",
                    "valign": "vcenter",
                    "font_color": "#FFFFFF" if color != "#F59E0B" else "#111827",
                    "bg_color": color,
                }
            )
            for color in SEVERITY_COLOR_BY_LABEL.values()
        },
    }


def _display_header(header: str) -> str:
    return header.replace("_", " ").title()


def _is_long_text_column(header: str) -> bool:
    return header in {
        "description",
        "from_zones",
        "to_zones",
        "source_addresses",
        "destination_addresses",
        "applications",
        "services",
        "matched_queries",
        "finding_summary",
        "login_banner",
    }


def _default_headers_for_sheet(control_type: str) -> list[str]:
    if control_type == "Security Rule":
        return [
            "severity",
            "station",
            "vsys_display_name",
            "rule_name",
            "provenance",
            "matched_queries",
            "finding_summary",
            "action",
            "config_source",
            "effective_order",
            "rule_position",
            "from_zones",
            "to_zones",
            "applications",
            "services",
            "source_addresses",
            "destination_addresses",
            "description",
            "status",
            "vsys_name",
            "disabled",
            "rule_type",
        ]
    return [
        "severity",
        "appliance",
        "station",
        "model",
        "software_version",
        "matched_queries",
        "finding_summary",
        "serial_number",
        "appliance_group",
        "group_type",
        "config_source",
        "ha_enabled",
        "ha_state_sync_enabled",
        "ha_link_monitoring_enabled",
        "idle_timeout_minutes",
        "permitted_ip_count",
        "has_unrestricted_permitted_ips",
        "ntp_primary_server",
        "ntp_secondary_server",
        "login_banner",
        "status",
        "ha_required",
    ]


def _ordered_headers(sheet) -> list[str]:
    if sheet.rows:
        available = list(sheet.rows[0].keys())
        desired = _default_headers_for_sheet(sheet.control_type)
        ordered = [header for header in desired if header in available]
        ordered.extend(header for header in available if header not in ordered)
        return ordered
    if sheet.control_type == "Security Rule":
        return _default_headers_for_sheet(sheet.control_type)
    return _default_headers_for_sheet(sheet.control_type)


def _sheet_target(sheet_name: str) -> str:
    escaped_name = sheet_name.replace("'", "''")
    return f"internal:'{escaped_name}'!A1"
