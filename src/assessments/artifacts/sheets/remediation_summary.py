"""The remediation workbook's first tab, and the only one written last.

The findings workbook's Summary is the model, and most of it is literally the same code: the
engagement block, the section headings, the column widths and the severity fills come from
`sheets.summary` rather than from a second copy, so the two deliverables cannot drift apart in
the places a reader compares them.

WHAT IT SAYS INSTEAD. A findings Summary lists domains and counts findings. This lists OBJECT
KINDS and counts, beside the findings, the number of PLACES - the edits. That second number is
the whole reason the surface exists: `Antivirus profile` is 2,049 findings and 30 places, and 30
is what somebody has to schedule. The column is headed `Places to edit` and not `Rows`, because
a row count is a fact about a table and this is a fact about the work.

Grouped by PAN-OS category, in the rail's order, exactly as the findings Summary groups its
tabs - the ordering Jason asked for on the web index on 2026-11-04, so all three surfaces file
an object in the same place.
"""
from __future__ import annotations

from collections import defaultdict

from assessments.configuration_navigation import CATEGORIES
from assessments.models import Control

from . import summary as findings_summary
from ..errors import ArtifactBuildError
from ..layout import (
    CELL_PADDING_CHARS, LINK_TEXT, MUTED_TEXT, SEVERITY_FILL, TABLE_STYLE, TAB_COLOURS,
    TITLE_FILL, column_width, plural, severity_group, write_header_block, write_sheet_link)

TITLE = "Summary"
SEVERITIES = findings_summary.SEVERITIES
#: `Places to edit` before `Findings`, which is the order they matter in: the work, then how
#: much of the report it answers.
HEADERS = ["Tab", "What it covers", "Places to edit", "Findings",
           *(Control.Severity(s).label for s in SEVERITIES)]
LAST_COL = len(HEADERS) - 1
FIRST_SEVERITY_COLUMN = 4
REFERENCE_HEADERS = ["Tab", "What it covers", "Rows"]
REFERENCE_SPACERS = [" " * (i + 1) for i in range(LAST_COL + 1 - 3)]


def write_sheet(build, sheet, infos) -> str:
    workbook = build.workbook
    reference = [info for info in infos if info.by_severity is None]
    groups = [info for info in infos if info.by_severity is not None]

    totals: dict = defaultdict(int)
    findings_total = places_total = 0
    for info in groups:
        for severity, count in info.by_severity.items():
            totals[severity] += count
            findings_total += count
        places_total += int(info.count.split()[0])

    top = write_header_block(
        build, sheet, title=TITLE, last_col=LAST_COL, back_link=False,
        tab_colour=TAB_COLOURS["summary"],
        count_groups=[
            [(places_total, plural(places_total, "place to edit"), None),
             (findings_total, plural(findings_total, "finding"), None),
             (len(groups), plural(len(groups), "object kind"), None)],
            severity_group(totals),
        ],
        rationale="Every finding, folded onto the object an engineer opens to clear it. One row "
                  "is one place you go.")

    label = workbook.add_format({"bold": True, "font_color": TITLE_FILL, "valign": "top",
                                 "indent": findings_summary.FIRST_COLUMN_INDENT})
    link = workbook.add_format({"font_color": LINK_TEXT, "underline": 1, "valign": "top",
                                "indent": findings_summary.FIRST_COLUMN_INDENT})
    tab_header = workbook.add_format({"bold": True,
                                      "indent": findings_summary.FIRST_COLUMN_INDENT})
    number_header = workbook.add_format({"bold": True, "align": "center"})
    value = workbook.add_format({"valign": "top", "text_wrap": True})
    muted = workbook.add_format({"valign": "top", "text_wrap": True, "font_color": MUTED_TEXT})
    number = workbook.add_format({"valign": "top", "align": "center"})

    engagement = findings_summary.engagement_rows(infos)
    sheet.set_column(0, 0, findings_summary.first_column_width(infos, engagement))
    sheet.set_column(1, 1, findings_summary.description_width(groups + reference))
    sheet.set_column(2, 3, 16)
    severity_width = max(column_width(col, HEADERS[col], 0, [], filter_button=False)
                         for col in range(FIRST_SEVERITY_COLUMN, LAST_COL + 1))
    sheet.set_column(FIRST_SEVERITY_COLUMN, LAST_COL, severity_width, number)

    row = top
    findings_summary.write_section_heading(workbook, sheet, row, "Engagement")
    row += 1
    for key, text in engagement:
        sheet.write(row, 0, key, label)
        sheet.write(row, 1, text, value)
        row += 1

    if reference:
        row += 1
        findings_summary.write_section_heading(workbook, sheet, row, "Reference")
        row += 1
        sheet.add_table(row, 0, row + len(reference), LAST_COL, {
            "name": "RemediationReference",
            "style": TABLE_STYLE,
            "autofilter": False,
            "columns": [{"header": h, **({"header_format": tab_header} if i == 0 else {})}
                        for i, h in enumerate(REFERENCE_HEADERS + REFERENCE_SPACERS)],
            "data": [[info.title, info.description, info.count] + [""] * len(REFERENCE_SPACERS)
                     for info in reference],
        })
        for i, info in enumerate(reference, start=1):
            write_sheet_link(build, sheet, row + i, 0, info.title, cell_format=link)
            sheet.write(row + i, 1, info.description, value)
            sheet.write(row + i, 2, info.count, muted)
        row += len(reference) + 1

    if groups:
        row += 1
        findings_summary.write_section_heading(workbook, sheet, row, "Remediation")
        row += 1
        by_category = defaultdict(list)
        for info in groups:
            by_category[info.category].append(info)
        uncategorised = sorted(set(by_category) - set(CATEGORIES))
        if uncategorised:
            raise ArtifactBuildError(f"remediation tabs in no PAN-OS category: {uncategorised}")

        for category in CATEGORIES:
            held = by_category.get(category)
            if not held:
                continue
            findings_summary.write_block_heading(workbook, sheet, row, category)
            row += 1
            sheet.add_table(row, 0, row + len(held), LAST_COL, {
                "name": f"Remediation{category}",
                "style": TABLE_STYLE,
                "autofilter": False,
                "columns": [{"header": h,
                             **({"header_format": tab_header} if i == 0 else {}),
                             **({"header_format": number_header} if i >= 2 else {})}
                            for i, h in enumerate(HEADERS)],
                "data": [[info.title, info.description, int(info.count.split()[0]),
                          sum(info.by_severity.values()),
                          *[info.by_severity.get(s, 0) for s in SEVERITIES]]
                         for info in held],
            })
            for i, info in enumerate(held, start=1):
                write_sheet_link(build, sheet, row + i, 0, info.title, cell_format=link)
                sheet.write(row + i, 1, info.description, value)
                sheet.write(row + i, 2, int(info.count.split()[0]), number)
                sheet.write(row + i, 3, sum(info.by_severity.values()), number)

            for offset, severity in enumerate(SEVERITIES):
                col = FIRST_SEVERITY_COLUMN + offset
                text = Control.Severity(severity).label
                fill = {"bg_color": SEVERITY_FILL[text], "bold": True, "align": "center"}
                if text == "Critical":
                    fill["font_color"] = "#FFFFFF"
                sheet.conditional_format(row + 1, col, row + len(held), col, {
                    "type": "cell", "criteria": ">", "value": 0,
                    "format": workbook.add_format(fill)})
            row += len(held) + 2

    return (f"{TITLE}: {len(infos)} tabs linked, {places_total} places to edit, "
            f"{findings_total} findings")
