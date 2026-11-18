"""The block workbook's Summary: the document's own Summary of Findings and Recommendations.

NOT THE FINDINGS WORKBOOK'S SUMMARY, which is a contents page - one row per tab, grouped by
PAN-OS category, counting what each tab holds. This file's reader is holding the health check
document, so its first tab is that document's first table: `# | Finding/Observation |
Recommendation | Importance`, in the same order, numbered the same way. A client who reads row
7 of the document opens tab `007` from row 7 here.

THE COLUMNS ARE THE DOCUMENT'S, plus two the document does not need. `Control ID` is here
because a spreadsheet is filtered and sorted rather than read in order, and the document's own
`Finding/Observation` cell carries the control's NAME; `Findings` is here because a workbook
reader wants the number in a column they can total rather than inside a sentence.

`Occurrences` reads `health_check.findings_phrase` verbatim - the same sentence the document
prints under the control name - so the two cannot drift. Same for `Recommendation`, which is
the control's `short_remediation`: the one imperative sentence, under 100 characters, that the
document's table carries.
"""
from __future__ import annotations

from assessments.models import Control

from ..layout import (fill_severity_column, plural, severity_group, write_header_block,
                      write_sheet_link, write_table)

TITLE = "Summary of Findings"

#: `(header, width, wrap)`. The widths are the document's proportions, read across: the finding
#: and the recommendation carry prose and everything else is a label or a number.
COLUMNS = [
    ("#", 6, False),
    ("Control ID", 14, False),
    ("Finding/Observation", 52, True),
    ("Occurrences", 26, True),
    ("Recommendation", 60, True),
    ("Importance", 14, False),
]


def summary_rows(blocks) -> list:
    """One row per block, in the document's order, numbered as the document numbers them."""
    from ..health_check import findings_phrase

    rows = []
    for number, detail in enumerate(blocks, start=1):
        rows.append([
            number,
            detail.control.control_id,
            detail.control.name,
            findings_phrase(detail),
            detail.control.short_remediation or "",
            Control.Severity(detail.severity).label,
        ])
    return rows


def write_sheet(build, sheet, blocks, infos) -> str:
    """Fill the Summary, which was created first so it is the first tab.

    `infos` is what each block tab reported about itself, in tab order - the same order as
    `blocks`, which `block_workbook` asserts before this is called. The Control ID cell links
    to the tab, so the Summary is the only navigation a reader of 264 tabs needs.

    THE LINK IS NOT ON `#`. That cell holds the document's block NUMBER as a number, so the
    column sorts back into the document's order after a reader has sorted by severity or by
    count; a hyperlink writes its text as a string, and a text column sorts 10 before 9.
    """
    workbook = build.workbook
    rows = summary_rows(blocks)
    findings = sum(sum(info.by_severity.values()) for info in infos)
    controls = len({detail.control.control_id for detail in blocks})

    top = write_header_block(
        build, sheet, title=TITLE, last_col=len(COLUMNS) - 1, back_link=False,
        count_groups=[
            [(len(rows), plural(len(rows), "block"), None),
             (controls, plural(controls, "control"), None),
             (findings, plural(findings, "finding"), None)],
            severity_group(blocks_by_severity(blocks)),
        ])
    write_table(build, sheet, top=top, name="BlockSummary", columns=COLUMNS, rows=rows,
                empty_text="No findings")

    headers = [header for header, _w, _wrap in COLUMNS]
    control_col = headers.index("Control ID")
    for index, info in enumerate(infos):
        write_sheet_link(build, sheet, top + 1 + index, control_col, info.title,
                         rows[index][control_col])

    # The grade a reader scans this table by, carrying the findings tabs' own severity fills
    # (Jason, 2026-11-18). `Importance` is the document's word for the column; the colors are
    # the same five the Severity cell of every findings tab uses, so one palette means one
    # thing across all four deliverables.
    fill_severity_column(build, sheet, first_row=top + 1, last_row=top + max(len(rows), 1),
                         col=headers.index("Importance"))
    return (f"{TITLE}: {len(rows)} {plural(len(rows), 'row')} over {controls} controls, "
            f"each linked to its tab")


def blocks_by_severity(blocks) -> dict:
    """How many BLOCKS carry each grade, not how many findings.

    The findings total is on the strip beside it, and a reader of this file is counting the
    sections of the document they have to work through. `severity_group` orders and colors it,
    which is why this returns the same `{severity: count}` shape a findings tab reports.
    """
    counted = {}
    for one in blocks:
        counted[one.severity] = counted.get(one.severity, 0) + 1
    return counted
