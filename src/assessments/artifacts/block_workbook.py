"""Build the block workbook: the health check document's detail section, one tab per block.

A THIRD DELIVERABLE, and the same bargain the second one struck. Jason, 2026-11-18: *"I want a
third workbook artifact that better aligns with the summary doc. In effect, a tab in the
workbook for each block in the doc's Detailed Findings and Recommendations, in the same order
as they appear in the doc. Include all the meta tabs (Management Stations, Appliances,
Enforcement Points, Controls)."* So `build_workbook` and `build_remediation_workbook` are
untouched, the four reference tabs are the findings workbook's own modules called with no
change, and everything shared stays in `layout`.

WHY A THIRD FILE AND NOT A THIRD VIEW. The three answer different questions and a reader of one
is not part-way through another. The findings workbook says what is wrong, grouped the way an
engineer works - one tab per settings domain. The remediation workbook says where to go, one
row per place to open. This one is the client's document with its evidence attached: the tab
strip IS the table of contents of Detailed Findings and Recommendations, and tab `007` is
block 7 is row 7 of the Summary of Findings and Recommendations.

THE ORDER IS READ, NOT RECOMPUTED. `health_check.read_control_detail` is the document's own
ordering function - worst severity first, then most findings, then the control's name - and
this walks its result. `check_tabs_follow_the_document` asserts the tab strip against it again
after the tabs are written, because the whole value of the file is that the two agree.

IT IS AS CHEAP AS THE OTHER TWO. Each domain's findings table is built once, by the same
`stored.stored_findings_table` the findings workbook calls, and the blocks that come out of it
are slices of `row_meta` - see `sheets.block.slice_for`. Measured on the lab 2026-11-18: 264
blocks over 76 domain tables, 13,520 rows, every block's slice exactly the count the document
prints for it.
"""
from __future__ import annotations

import io

import xlsxwriter

from .context import WorkbookBuild
from .errors import ArtifactBuildError
from .layout import link_budget_report
from . import scope
from .sheets import appliances as appliances_sheet
from .sheets import block as block_sheet
from .sheets import block_summary
from .sheets import controls as controls_sheet
from .sheets import enforcement_points as enforcement_points_sheet
from .sheets import management_stations as management_stations_sheet

#: The reference tabs, in the findings workbook's own order. Controls is LAST of the four and
#: before every block tab, because each block's rows link into its own control-and-severity
#: row - the same ordering constraint `workbook.SHEETS` records.
REFERENCE_SHEETS = (
    management_stations_sheet,
    appliances_sheet,
    enforcement_points_sheet,
    controls_sheet,
)


def document_blocks() -> tuple:
    """The document's blocks in the document's order, and the domain table each one cuts from.

    Returns `(blocks, tables)` where `tables` is keyed by control pk: every finding of a
    control is on exactly one domain tab, which `workbook.check_every_finding_reached_a_tab`
    is the standing proof of, so one table serves all of a control's blocks.
    """
    from .domains import DOMAINS
    from .health_check import measure, read_control_detail
    from .sheets import findings as findings_sheet
    from .stored import stored_findings_table

    blocks = read_control_detail(measure())
    tables = {}
    for domain in DOMAINS:
        table = stored_findings_table(domain.spec, tested=findings_sheet.WORKBOOK_TESTED_COLUMNS,
                                      head=findings_sheet.WORKBOOK_HEAD_COLUMNS)
        for control in table.controls:
            tables[control.pk] = table
    return blocks, tables


def check_every_block_has_a_table(blocks, tables) -> None:
    """A block whose control reaches no domain tab would be a tab this file cannot write.

    It cannot happen while `workbook.check_every_finding_reached_a_tab` passes - a control with
    findings and no tab fails that first - but this file would fail with a `KeyError` on a
    dictionary lookup rather than a sentence, and the next reader would be debugging the wrong
    module.
    """
    orphans = sorted({one.control.control_id for one in blocks
                      if one.control.pk not in tables})
    if orphans:
        raise ArtifactBuildError(
            f"no findings tab carries {', '.join(orphans)}, so the document has a block this "
            f"workbook cannot write a tab for. Add the control's domain to `artifacts.domains`.")


def check_tabs_follow_the_document(blocks, infos) -> None:
    """The tab strip and the document's detail section are one order, not two.

    Asserted on the TITLES the tabs were actually given rather than on the list they were
    generated from, so a tab renamed or written out of turn is caught here instead of by a
    client holding both files.
    """
    expected = [block_sheet.tab_title(number, one)
                for number, one in enumerate(blocks, start=1)]
    written = [info.title for info in infos]
    if written != expected:
        first = next((i for i, (a, b) in enumerate(zip(written, expected)) if a != b),
                     min(len(written), len(expected)))
        raise ArtifactBuildError(
            f"the block tabs are not in the document's order: tab {first + 1} is "
            f"{written[first:first + 1] or ['missing']} where the document's block "
            f"{first + 1} is {expected[first:first + 1] or ['missing']}")


def check_every_finding_reached_a_tab(blocks, infos) -> None:
    """Every finding the document counts is on exactly one block tab.

    The document's own count per block is `ControlDetail.findings`, computed from the finding
    tables by `health_check.measure`; the tab's is the length of the slice it drew. Equal block
    by block means no row was lost to a slice and none was drawn twice.
    """
    for number, (one, info) in enumerate(zip(blocks, infos), start=1):
        shown = sum(info.by_severity.values())
        if shown != one.findings:
            raise ArtifactBuildError(
                f"tab {info.title} holds {shown:,} findings and block {number} of the document "
                f"counts {one.findings:,}: the slice lost rows or drew somebody else's.")


def build_block_workbook() -> tuple[bytes, list[str]]:
    """The workbook as bytes, and the line each tab reported about itself.

    In memory and with no filename, for the reason `build_workbook` gives: the caller is the one
    that knows whether this is a download, a stored artifact or a test.
    """
    blocks, tables = document_blocks()
    check_every_block_has_a_table(blocks, tables)
    scope_lines = scope.scope_report()

    buffer = io.BytesIO()
    workbook = xlsxwriter.Workbook(buffer, {"in_memory": True})
    build = WorkbookBuild(workbook=workbook)
    try:
        # Created first so it is the first tab; filled last, from what the others report.
        summary_worksheet = workbook.add_worksheet(block_summary.TITLE)
        reference = [sheet.write_sheet(build) for sheet in REFERENCE_SHEETS]
        infos = [block_sheet.write_sheet(build, number=number, detail=one,
                                         table=tables[one.control.pk])
                 for number, one in enumerate(blocks, start=1)]
        check_tabs_follow_the_document(blocks, infos)
        check_every_finding_reached_a_tab(blocks, infos)
        summary_report = block_summary.write_sheet(build, summary_worksheet, blocks, infos)
        summary_worksheet.activate()
    except BaseException:
        workbook.close()
        raise
    workbook.close()
    reports = ([summary_report]
               + [info.report for info in reference]
               + [info.report for info in infos]
               + scope_lines
               + link_budget_report(build))
    return buffer.getvalue(), reports
