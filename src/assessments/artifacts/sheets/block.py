"""One tab per block of the health check document's Detailed Findings and Recommendations.

THE THIRD DELIVERABLE'S UNIT IS THE DOCUMENT'S BLOCK, not the domain. Jason, 2026-11-18: *"I
want a third workbook artifact that better aligns with the summary doc. In effect, a tab in the
workbook for each block in the doc's Detailed Findings and Recommendations, in the same order
as they appear in the doc."* The findings workbook groups by domain - one tab per settings
family, which is how an engineer reads a firewall; this groups by control AND severity, which
is how the client reads the report. The same findings, cut a third way.

THE ORDER IS THE DOCUMENT'S OWN, and not a second sort that happens to agree.
`health_check.read_control_detail` returns the blocks worst first, and the document's Summary
of Findings and Recommendations numbers them 1..n down that same list - so tab `007` IS row 7
of that table and block 7 of the section. `block_workbook.check_tabs_follow_the_document`
holds the two together.

THE ROWS ARE SLICED, NOT REBUILT. Each domain's table is built once by
`stored.stored_findings_table` - the same call the findings workbook makes, with the same
columns - and every row carries its control and severity in `row_meta`. A block tab is that
table filtered to one pair. Measured on the lab 2026-11-18: 264 blocks, 13,520 rows, and every
block's slice is exactly the finding count the document prints for it, 0 discrepancies. A
second query per tab would be 264 round trips and a second definition of what a block contains.

WHAT A TAB DOES NOT REPEAT. The Requirement, the Evidence sentences, the firing condition, the
audit path and the Remediation are on the Controls tab, one row per control and severity, and
the Control ID cell of every row links to it - the arrangement Jason settled on this morning
when the findings rows stopped restating their control. Printing them again on each of 264
tabs would be the same defect in a new file. `Risk` is here because it is one sentence and it
is what a reader triages on.
"""
from __future__ import annotations

from assessments.models import Control

from ..layout import (SheetInfo, TAB_COLOURS, fill_severity_column, plural, severity_group,
                      write_header_block, write_link, write_table)
from .findings import implicated_format


def tab_title(number: int, detail) -> str:
    """`007 PAN-POL-008 Critical` - the document's block number, then what the block is about.

    THE NUMBER LEADS because the tab strip's order is the deliverable's order, and 264 tabs
    sorted by anything else is a list nobody can hold. It is the Summary table's `#` column,
    so a client reading row 7 of the document opens tab `007`.

    IT FITS. Excel allows 31 characters: three digits, a control id of at most twelve, and
    `Informational`, the longest severity label, come to 30. The pair is unique by
    construction - one block per control and severity - so the number never has to break a tie.
    """
    return f"{number:03d} {detail.control.control_id} {Control.Severity(detail.severity).label}"


def table_name(number: int, detail) -> str:
    """Excel's own name for the tab's table: letters, digits and underscores, unique per file."""
    return (f"Block_{number:03d}_{detail.control.control_id}_{detail.severity}"
            .replace("-", "_"))


def slice_for(table, detail) -> tuple:
    """`(rows, implicated, row_meta)` for one block, out of its domain's whole table.

    `implicated` is re-indexed. It holds `(row index, column index)` against the domain table,
    and a tab that marked those row numbers would highlight whichever of ITS rows happened to
    sit there - a cell at fault on a row that is not at fault, which is worse than no mark.
    """
    keep = [index for index, meta in enumerate(table.row_meta)
            if meta["control"] == detail.control.pk and meta["severity"] == detail.severity]
    moved = {old: new for new, old in enumerate(keep)}
    return ([table.rows[index] for index in keep],
            [(moved[row], col) for row, col in table.implicated if row in moved],
            [table.row_meta[index] for index in keep])


def object_noun(detail) -> str:
    """What a CLIENT calls the things this block's findings are about, counted.

    `ControlDetail.object_nouns` is the finding registry's own `(plural, singular)`, written
    out per kind rather than pluralized, because pluralizing the registry's label hands a
    client "12 password complexities" - see `FindingKind.client_plural`. An empty singular
    means the plural serves, which it does for 44 of the 75 kinds.
    """
    nouns = detail.object_nouns
    if detail.objects == 1:
        return nouns[1] or nouns[0]
    return nouns[0]


def write_sheet(build, *, number: int, detail, table) -> SheetInfo:
    """One block: its title, its counts, its Risk sentence, and the findings behind it.

    `table` is the block's own domain table, built once by the caller and shared by every block
    that comes out of it.
    """
    workbook = build.workbook
    rows, implicated, row_meta = slice_for(table, detail)
    columns = table.columns
    title = tab_title(number, detail)
    sheet = workbook.add_worksheet(title)

    severity_label = Control.Severity(detail.severity).label
    firewalls = len(detail.reach)
    counts = [(len(rows), plural(len(rows), "finding"), None),
              (detail.objects, object_noun(detail), None)]
    if detail.places:
        counts.append((detail.places, plural(detail.places, "object"), None))
    reach = [(firewalls, plural(firewalls, "firewall"), None)]
    if detail.unnamed:
        reach.append((detail.unnamed, "naming no firewall", None))

    top = write_header_block(
        build, sheet,
        title=f"{detail.control.control_id}   {severity_label}   {detail.control.name}",
        last_col=len(columns) - 1,
        tab_colour=TAB_COLOURS[table.category],
        count_groups=[counts, reach, severity_group({detail.severity: len(rows)})],
        rationale=detail.control.why_it_matters or None,
        rationale_label="Risk")
    write_table(build, sheet, top=top, name=table_name(number, detail), columns=columns,
                rows=rows, empty_text="No findings")

    for row_index, col_index in implicated:
        _header, _width, wrap = columns[col_index]
        sheet.write(top + 1 + row_index, col_index, rows[row_index][col_index],
                    implicated_format(build, wrap))

    headers = [header for header, _width, _wrap in columns]
    # Every row on a block tab carries the SAME grade - that is what a block is - so this fill
    # says less here than on a findings tab, where it sorts a mixed column. It is here because
    # the two files are read side by side and a Severity cell that is colored on one and plain
    # on the other reads as a difference in the finding rather than in the tab.
    fill_severity_column(build, sheet, first_row=top + 1,
                         last_row=top + max(len(rows), 1),
                         col=headers.index("Severity"))
    control_col = headers.index("Control ID")
    for index, meta in enumerate(row_meta):
        key = (meta["control"], meta["severity"])
        if ("control", key) not in build.anchors:
            key = meta["control"]
        write_link(build, sheet, top + 1 + index, control_col, "control", key,
                   rows[index][control_col])

    return SheetInfo(
        title=title,
        description=detail.control.name,
        count=f"{len(rows):,} {plural(len(rows), 'finding')}",
        report=(f"{title}: {len(rows):,} {plural(len(rows), 'finding')} over "
                f"{detail.objects:,} {detail.object_nouns[0]}"),
        by_severity={detail.severity: len(rows)},
        category=table.category,
        runs=table.runs)
