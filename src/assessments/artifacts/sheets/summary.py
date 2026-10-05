"""Engineer-detail xlsx, prototype: the Summary tab. First in the workbook, written LAST.

Jason, 2026-09-15: "a tab, the first tab in the workbook, that contains some high level
information ... links to the other tabs (and on the other tabs, links back to the first tab)." The
values shared by every sheet - client, engagement, run - live here and nowhere else.

It is the first worksheet but is filled after the others, because its contents table and totals
are what the other sheets report about themselves (`common.SheetInfo`). xlsxwriter allows writing
to any worksheet until the workbook closes, so tab order and write order are independent.

Nothing on this tab is typed by hand except labels. Totals are the other sheets' own counts, so
the Summary cannot disagree with the tabs it summarises.
"""
from __future__ import annotations

from collections import defaultdict

from django.utils import timezone

from assessments.control_queries import SEVERITY_RANK
from assessments.environment import get_application_environment
from assessments.models import AssessmentRun, Control
from optivedge_integrations.integrations.models import (
    Appliance, EnforcementPoint, ManagementStation)

from . import appliances as appliances_sheet
from assessments.configuration_navigation import CATEGORIES

from ..layout import (
    LINK_TEXT, MUTED_TEXT, TAB_COLOURS, band, NONE, RULE_COLOUR, SEVERITY_FILL, SUMMARY_TITLE, TABLE_STYLE, TITLE_FILL,
    CELL_PADDING_CHARS, column_width, plural, severity_group, utc, write_header_block,
    write_sheet_link)
from ..errors import ArtifactBuildError

#: Every severity the catalog knows, worst first - so a column exists even where no sheet has a
#: finding at that severity, and a zero is visible rather than a missing column.
SEVERITIES = sorted(Control.Severity.values, key=lambda s: SEVERITY_RANK[s], reverse=True)
#: Two tables of links (Jason, 2026-09-15): informational tabs, and findings tabs with a severity
#: breakdown. Columns A-C are shared by both, so they share widths.
REFERENCE_HEADERS = ["Tab", "Description", "Count"]
FINDINGS_HEADERS = ["Tab", "Domain", "Findings", *(Control.Severity(s).label for s in SEVERITIES)]
LAST_COL = len(FINDINGS_HEADERS) - 1
FIRST_SEVERITY_COLUMN = 3
#: The Reference table has three columns and the Findings table eight, which left the two blocks
#: with a ragged right edge. The spare columns ride along as unheaded members of the reference
#: table so both end in the same place; Excel needs every header to be unique, hence the spaces.
REFERENCE_SPACERS = [" " * (i + 1) for i in range(LAST_COL + 1 - 3)]
#: Column C. Columns A and B are measured from what they hold.
COUNT_WIDTH = 24
#: A findings DOMAIN is a sentence and wraps to two or three lines by design; a REFERENCE
#: description is one line and should read as one. Column B is sized to the longest of those, with
#: padding - at a flat 80 the longest ran to 84 characters and wrapped, leaving one row of the
#: Reference table double height and Excel unable to auto-fit it back (Jason, 2026-09-18).
DESCRIPTION_MIN_WIDTH = 60
DESCRIPTION_MAX_WIDTH = 100


def engagement_rows(infos):
    env = get_application_environment()
    missing = "Not recorded"

    run_ids = sorted(set().union(*(info.runs for info in infos)))
    runs = list(AssessmentRun.objects.filter(pk__in=run_ids).order_by("pk"))
    completed = "\n".join(utc(r.completed_at) for r in runs)

    collected = sorted(
        appliances_sheet.collected_at_by_appliance(list(Appliance.objects.all())).values())
    if not collected:
        collected_text = "Not collected"
    elif collected[0] == collected[-1]:
        collected_text = utc(collected[0])
    else:
        collected_text = f"{utc(collected[0])} to {utc(collected[-1])}"

    return [
        ("Client", (env.client_name if env else "") or missing),
        ("Client short name", (env.client_short_name if env else "") or missing),
        ("Opportunity", (env.opportunity_number if env else "") or missing),
        ("Run completed (UTC)", completed or "No findings, so no run"),
        ("Configuration collected (UTC)", collected_text),
        ("Workbook generated (UTC)", utc(timezone.now())),
    ]


#: Column A is indented by one, the same as the title band above it (Jason, 2026-09-18). A short
#: value - "NTP", "Controls" - otherwise starts hard against the row selector, and the pointer
#: lands on the selector rather than on the cell's link often enough to be annoying. Indenting the
#: whole column also lines its text up with the title.
FIRST_COLUMN_INDENT = 2
#: The page's two heading levels: sections (Engagement, Reference, Findings) and, inside Findings,
#: the PAN-OS categories. Sized rather than coloured - see `write_block_heading` (Jason,
#: 2026-09-18).
SECTION_FONT_SIZE = 14
BLOCK_FONT_SIZE = 12
#: Headings sit further LEFT than the rows they head, so the indent carries the hierarchy: a
#: section at the margin, a category one in, the rows two (Jason, 2026-09-18).
SECTION_INDENT = 0
BLOCK_INDENT = 1
#: A second view of the tab above it sits further in again, so the tab strip's two policy tabs
#: read as a parent and its child rather than as two peers (Jason, 2026-09-18).
CHILD_INDENT = FIRST_COLUMN_INDENT + 2


def description_width(reference) -> int:
    """Wide enough that a reference description is one line, within sane bounds."""
    longest = max((len(info.description) for info in reference), default=0)
    return max(DESCRIPTION_MIN_WIDTH, min(DESCRIPTION_MAX_WIDTH, longest + CELL_PADDING_CHARS))


def first_column_width(infos, engagement) -> int:
    """Wide enough for the longest thing column A holds, plus its indent and a right margin.

    The column carries three kinds of text - section headings, engagement labels and tab names,
    a secondary one prefixed with an arrow and indented further - and every one of them is pushed
    right by the indent. A fixed width fitted the labels and clipped the longest tab name.
    """
    widest = max(
        [len(text) + SECTION_INDENT for text in ["Engagement", "Reference", "Findings"]]
        + [len(text) + BLOCK_INDENT for text in CATEGORIES]
        + [len(text) + FIRST_COLUMN_INDENT
           for text in ["Tab"] + [label for label, _v in engagement]]
        + [len(info.title) + (CHILD_INDENT + 2 if info.secondary else FIRST_COLUMN_INDENT)
           for info in infos])
    return widest + CELL_PADDING_CHARS


def write_block_heading(workbook, sheet, row, text):
    """The heading row above a table: the category name, and nothing else.

    Two colour treatments were tried on 2026-09-18 and both reverted - the row filled with the
    category's tab colour ("I don't like that, its too busy"), then the word in that colour. The
    page already carries the title, the counts strip and five table headers; the categories read
    as structure without being coloured, and the tab strip is where the colours belong.
    """
    heading = workbook.add_format({"bold": True, "font_size": BLOCK_FONT_SIZE,
                                   "font_color": TITLE_FILL, "indent": BLOCK_INDENT,
                                   "valign": "bottom"})
    sheet.write(row, 0, text, heading)
    sheet.set_row(row, 22)


def write_section_heading(workbook, sheet, row, text):
    heading = workbook.add_format({"bold": True, "font_size": SECTION_FONT_SIZE,
                                   "font_color": TITLE_FILL, "indent": SECTION_INDENT,
                                   "bottom": 1, "bottom_color": RULE_COLOUR, "valign": "bottom"})
    band(sheet, row, 0, LAST_COL, heading)
    sheet.write(row, 0, text, heading)
    sheet.set_row(row, 22)


def write_sheet(build, sheet, infos) -> str:
    workbook = build.workbook
    totals = defaultdict(int)
    findings_total = 0
    for info in infos:
        for severity, count in (info.by_severity or {}).items():
            totals[severity] += count
            findings_total += count
    stations = ManagementStation.objects.count()
    appliances = Appliance.objects.count()
    points = EnforcementPoint.objects.count()

    top = write_header_block(build, sheet, title=SUMMARY_TITLE, last_col=LAST_COL, back_link=False,
        tab_colour=TAB_COLOURS["summary"],
        count_groups=[
            [(stations, plural(stations, "management station"), None),
             (appliances, plural(appliances, "appliance"), None),
             (points, plural(points, "enforcement point"), None)],
            [(findings_total, plural(findings_total, "finding"), None)],
            severity_group(totals),
        ])

    label = workbook.add_format({"bold": True, "font_color": TITLE_FILL, "valign": "top",
                                 "indent": FIRST_COLUMN_INDENT})
    #: The link cells, indented to match. Underline and colour come from the shared link format.
    link = workbook.add_format({"font_color": LINK_TEXT, "underline": 1, "valign": "top",
                                "indent": FIRST_COLUMN_INDENT})
    #: And the header of that column, so the table reads as one column rather than two.
    tab_header = workbook.add_format({"bold": True, "indent": FIRST_COLUMN_INDENT})
    #: Centred over the numbers beneath them.
    number_header = workbook.add_format({"bold": True, "align": "center"})
    child_link = workbook.add_format({"font_color": LINK_TEXT, "underline": 1, "valign": "top",
                                      "indent": CHILD_INDENT})
    value = workbook.add_format({"valign": "top", "text_wrap": True})
    muted = workbook.add_format({"valign": "top", "text_wrap": True, "font_color": MUTED_TEXT})
    number = workbook.add_format({"valign": "top", "align": "center"})
    # Which tabs go in which table - needed before the columns, which are sized from them.
    reference = [info for info in infos if info.by_severity is None and not info.secondary]
    findings = [info for info in infos if info.by_severity is not None or info.secondary]
    engagement = engagement_rows(infos)
    sheet.set_column(0, 0, first_column_width(infos, engagement))
    sheet.set_column(1, 1, description_width(reference))
    sheet.set_column(2, 2, COUNT_WIDTH)
    # One width for every severity column, the widest header's, so they read as a grid.
    severity_width = max(column_width(col, FINDINGS_HEADERS[col], 0, [], filter_button=False)
                         for col in range(FIRST_SEVERITY_COLUMN, LAST_COL + 1))
    sheet.set_column(FIRST_SEVERITY_COLUMN, LAST_COL, severity_width, number)

    # Engagement: key/value pairs, not a table - nothing here is sorted or filtered.
    row = top
    write_section_heading(workbook, sheet, row, "Engagement")
    row += 1
    for key, text in engagement:
        sheet.write(row, 0, key, label)
        sheet.write(row, 1, text, value)
        row += 1


    # Reference: the informational tabs, linked.
    if reference:
        row += 1
        write_section_heading(workbook, sheet, row, "Reference")
        row += 1
        sheet.add_table(row, 0, row + len(reference), LAST_COL, {
            "name": "Reference",
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

    # Findings, grouped by PAN-OS's own top-level categories (Jason, 2026-09-18). One table per
    # category rather than one list with a category column: the grouping is the point, and it is
    # how an engineer already navigates the product. Empty categories are skipped - three of the
    # four hold a single tab today, and the shape of the estate will change that, not the report.
    if findings:
        row += 1
        write_section_heading(workbook, sheet, row, "Findings")
        row += 1
        by_category = defaultdict(list)
        for info in findings:
            by_category[info.category].append(info)
        uncategorised = sorted(set(by_category) - set(CATEGORIES))
        if uncategorised:
            raise ArtifactBuildError(f"findings tabs in no PAN-OS category: {uncategorised}")

        for category in CATEGORIES:
            group = by_category.get(category)
            if not group:
                continue
            write_block_heading(workbook, sheet, row, category)
            row += 1
            sheet.add_table(row, 0, row + len(group), LAST_COL, {
                "name": f"Findings{category}",
                "style": TABLE_STYLE,
                "autofilter": False,
                "columns": [{"header": h,
                             **({"header_format": tab_header} if i == 0 else {}),
                             **({"header_format": number_header} if i >= 2 else {})}
                            for i, h in enumerate(FINDINGS_HEADERS)],
                "data": [[info.title if not info.secondary else f"↳ {info.title}",
                          info.description,
                          "" if info.secondary else sum(info.by_severity.values()),
                          *([""] * len(SEVERITIES) if info.secondary
                            else [info.by_severity.get(s, 0) for s in SEVERITIES])]
                         for info in group],
            })
            for i, info in enumerate(group, start=1):
                # The arrow marks a second view of the findings above it, not a tab of its own.
                write_sheet_link(build, sheet, row + i, 0, info.title,
                                 cell_format=child_link if info.secondary else link,
                                 text=f"↳ {info.title}" if info.secondary else info.title)
                sheet.write(row + i, 1, info.description, muted if info.secondary else value)
                if not info.secondary:
                    sheet.write(row + i, 2, sum(info.by_severity.values()), number)

            # A non-zero count takes its severity's fill, as the Severity column does on a
            # findings sheet.
            for offset, severity in enumerate(SEVERITIES):
                col = FIRST_SEVERITY_COLUMN + offset
                label = Control.Severity(severity).label
                fmt = {"bg_color": SEVERITY_FILL[label], "bold": True, "align": "center"}
                if label == "Critical":
                    fmt["font_color"] = "#FFFFFF"
                sheet.conditional_format(row + 1, col, row + len(group), col, {
                    "type": "cell", "criteria": ">", "value": 0,
                    "format": workbook.add_format(fmt)})
            row += len(group) + 2

    return f"{SUMMARY_TITLE}: {len(infos)} tabs linked, {findings_total} findings in total"
