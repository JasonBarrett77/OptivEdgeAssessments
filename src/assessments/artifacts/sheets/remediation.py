"""The remediation workbook's tabs: one per object group, the shape its web page already has.

Jason, 2026-11-05: *"Remediation needs its own artifact, separate from the existing Findings
artifact. However, the existing findings (detail) artifact is an excellent example of features
and formatting."* So everything a findings tab does is done here by the SAME code - the title
band, the counts strip, the tab color by PAN-OS category, the real Excel table with its
autofilter and frozen header, the column widths measured from the values, the clipped row for a
cell holding more lines than fit, and the amber on the value that caused the finding. None of it
is reimplemented; `artifacts.layout` is imported, and the existing workbook is untouched.

ONE TAB PER GROUP, which is one tab per web page: `/assessments/remediation/group/<slug>/` and
the tab are the same table, as a findings tab and `/assessments/findings/<slug>/` are. The rows
come from `remediation.stored_group_rows`, so the workbook cannot describe an object differently
from the page - and it costs nothing to build, because Run Findings has already stored them.

WHAT THE COLUMNS ARE, and why they are not quite the page's. The page draws Findings, Severity,
Control ID and Control name as four columns of one line per control, read across as a sentence.
A spreadsheet is for sorting and filtering, and four columns of stacked lines filter on nothing,
so the row's own total and its worst severity are single values here - the shape a findings tab's
Severity column has, and the one the conditional fill can color - and the per-control detail is
one cell holding Jason's own sentence per line: *"3 findings of medium severity for control id
PAN-IOT-002 with control name Device-ID Enabled on IoT-Hosting Zones"*.

A POSTURE GROUP takes the same eight columns rather than the page's control-per-column layout.
Its subject is a virtual system's rulebase, so the Object column holds the virtual system and
the Location column is empty - which is what the row means, and what the page says in its own
way.
"""
from __future__ import annotations

from assessments import remediation as surface
from assessments.models import Control

from . import controls as controls_sheet  # noqa: F401  (imported for the reference tab's name)
from .findings import implicated_format
from ..errors import ArtifactBuildError
from ..layout import (
    NONE, SEVERITY_FILL, SheetInfo, TAB_COLOURS, plural, severity_group, write_header_block,
    write_table)

#: Excel's own limits on a worksheet name: 31 characters, and none of these in it.
SHEET_NAME_LIMIT = 31
ILLEGAL_IN_SHEET_NAME = ':\\/?*[]'


def sheet_title(group) -> str:
    """The tab's name: the group's label, within Excel's rules.

    Measured over the 69 groups: one label is 32 characters (`Vulnerability protection profile`)
    and one carries a slash (`SSL/TLS service profile`), so both rules bite and neither can be
    left to xlsxwriter, which truncates silently and raises on the slash. A slash becomes a
    hyphen rather than disappearing, because `SSLTLS` is not a word anybody searches for.
    """
    name = group.label
    for character in ILLEGAL_IN_SHEET_NAME:
        name = name.replace(character, "-")
    return name[:SHEET_NAME_LIMIT]


def check_tab_names_are_distinct(groups) -> None:
    """Two groups whose labels truncate to one tab name would be one tab, silently.

    None do today. This is here because the failure is invisible: xlsxwriter raises on a
    duplicate worksheet name, so the workbook would fail to build with a message about Excel
    rather than about the two groups that collided - and a reader of that message has no way to
    know which they were.
    """
    seen: dict = {}
    for group in groups:
        title = sheet_title(group)
        if title in seen:
            raise ArtifactBuildError(
                f"the remediation groups {seen[title]!r} and {group.slug!r} both want the tab "
                f"name {title!r}: shorten one of their labels")
        seen[title] = group.slug


#: (header, width, wrap). A width of None is measured from the longest LINE any value holds -
#: see `layout.column_width` - so no cell wraps mid-value.
#:
#: THE ORDER IS THE PAGE'S: where to go first (the plane, whether the edit survives, the
#: container), then what to open, then what it costs and what it buys.
WHERE_COLUMNS = (
    ("Edit on", None, True),
    ("Authority", 14, False),
    ("Location", None, True),
)
REACH_COLUMNS = (
    ("In force on", None, True),
    ("Findings", 10, False),
    ("Severity", 10, False),
    ("Controls", 56, True),
)


#: What the object column is called where the group's label is already a value column's heading.
GENERIC_OBJECT_HEADING = "Object"


def object_heading(group, value_headings) -> str:
    """The object column's header: the kind of object, or `Object` where that name is taken.

    The page heads it with the group's label, because `Object` says nothing a reader of one
    group's page does not already know. An Excel table additionally requires every header in it
    to be UNIQUE, and two groups collide: the Interfaces sheet has a column called `Interface`
    and the login-banner sheet one called `Login Banner`. Both have to stay - `Interface` does
    repeat the row's name, but `Login Banner` holds the banner's TEXT and the row is named for
    the appliance - and the value headings are the vocabulary this tab shares with its findings
    tab, so the one that gives way is mine. The tab's name and its title band still say which
    kind of object the rows are.
    """
    taken = {heading.casefold() for heading in value_headings}
    return GENERIC_OBJECT_HEADING if group.label.casefold() in taken else group.label


def columns_for(group, rows) -> list:
    """The fixed columns, the object column headed by the kind of object, then the value columns."""
    value_headings = [cell["heading"] for cell in rows[0]["cells"]] if rows else []
    return [*WHERE_COLUMNS,
            (object_heading(group, value_headings), None, True),
            *REACH_COLUMNS,
            *((heading, None, True) for heading in value_headings)]


def control_lines(row) -> str:
    """One line per control, read as a sentence - Jason, 2026-11-04: *"There should only be one
    'line' per control id."*

    `4 findings · High · PAN-AVW-001 · Antivirus profile blocks malware`. The count leads
    because it is the number a reader scans down, and the id is before the name because it is
    what they search the Controls tab for.
    """
    lines = []
    for line in row["control_lines"]:
        count = line["count"]
        lines.append(f"{count} {plural(count, 'finding')} · {line['severity']} · "
                     f"{line['control']} · {line['control_name']}")
    return "\n".join(lines) or NONE


def object_cell(row) -> str:
    """The object to change, and on an absence row the size of the absence.

    RULE OBJECTS, NOT FINDINGS, for the reason the page gives: Panorama Shared holds two rules
    with no antivirus profile and they materialise fourteen times, once per virtual system. Two
    edits, fourteen findings cleared; the Findings column counts the second.
    """
    if not row["missing"]:
        return row["name"]
    count = row["rule_objects"]
    return f"{row['name']}\non {count} {plural(count, 'rule')}"


def build_rows(group, rows) -> tuple[list, list]:
    """The cell values, and (row, column) of every cell holding a value at fault."""
    drawn, implicated = [], []
    for index, row in enumerate(rows):
        values = [
            "\n".join(row["managed_from"]) or NONE,
            row["authority"],
            "\n".join(container or NONE for container in row["defined_in"]) or NONE,
            object_cell(row),
            "\n".join(row["points"]) or NONE,
            row["findings"],
            row["severity"],
            control_lines(row),
        ]
        # THE FIXED COUNT, taken before the loop appends to `values`: using the growing list's
        # length as the base counted each value column from one cell further along than it is.
        fixed = len(values)
        for offset, cell in enumerate(row["cells"]):
            if cell["at_fault"]:
                implicated.append((index, fixed + offset))
            values.append("\n".join(cell["lines"]) or NONE)
        drawn.append(values)
    return drawn, implicated


def write_sheet(build, group) -> SheetInfo:
    workbook = build.workbook
    controls = surface.group_controls(group)
    rows = surface.stored_group_rows(group)
    if not surface.group_fold_is_complete(group, rows):
        # THE SAME REFUSAL A FINDINGS TAB MAKES over a row count it cannot account for. The page
        # draws a red banner and carries on, which is right for a page somebody is iterating on;
        # a client deliverable that quietly understates the work is not worth having.
        reached = sum(row["findings"] for row in rows)
        raise ArtifactBuildError(
            f"{group.label}: its rows account for {reached} findings, which is not every finding "
            f"of {', '.join(control.control_id for control in controls)}")

    columns = columns_for(group, rows)
    drawn, implicated = build_rows(group, rows)
    category = surface.group_category(group)

    by_severity: dict = {}
    for row in rows:
        for counts in row["findings_by_control"].values():
            for severity, count in counts.items():
                by_severity[severity] = by_severity.get(severity, 0) + count

    findings = sum(row["findings"] for row in rows)
    sheet = workbook.add_worksheet(sheet_title(group))
    top = write_header_block(
        build, sheet, title=group.label, last_col=len(columns) - 1,
        tab_colour=TAB_COLOURS[category],
        count_groups=[
            [(len(rows), plural(len(rows), "place to edit"), None),
             (findings, plural(findings, "finding"), None),
             (len(controls), plural(len(controls), "control"), None)],
            severity_group(by_severity),
        ],
        rationale=group.summary)
    write_table(build, sheet, top=top, name=f"Remediation{group.slug.replace('-', '')}",
                columns=columns, rows=drawn, empty_text="No findings")

    # The value that caused the finding, marked where it sits - the findings tabs' own amber, on
    # the object's own column. An absence row carries no mark: there is no object to describe,
    # and highlighting an empty cell would tell an engineer to change nothing.
    for row_index, col_index in implicated:
        _header, _width, wrap = columns[col_index]
        sheet.write(top + 1 + row_index, col_index, drawn[row_index][col_index],
                    implicated_format(build, wrap))

    severity_col = [header for header, _w, _wrap in columns].index("Severity")
    for text, colour in SEVERITY_FILL.items():
        fill = {"bg_color": colour, "bold": True}
        if text == "Critical":
            fill["font_color"] = "#FFFFFF"
        sheet.conditional_format(top + 1, severity_col, top + max(len(drawn), 1), severity_col, {
            "type": "cell", "criteria": "==", "value": f'"{text}"',
            "format": workbook.add_format(fill)})

    runs = set()
    for control in controls:
        model = surface._kind_for(control.control_type).model
        runs.update(model.objects.filter(control=control)
                    .values_list("assessment_run_id", flat=True).distinct())
    return SheetInfo(
        title=sheet_title(group),
        description=group.summary,
        count=f"{len(rows)} {plural(len(rows), 'place')}",
        report=f"{sheet_title(group)}: {len(rows)} places, {findings} findings, "
               f"{len(controls)} controls",
        by_severity=by_severity,
        category=category,
        runs=runs)
