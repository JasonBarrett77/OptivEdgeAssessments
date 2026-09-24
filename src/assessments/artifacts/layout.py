"""What every worksheet shares: the palette, column sizing, the header block and the table.

Imported through `assessments.artifacts`, so Django is already configured by the time
anything here runs.
"""
from __future__ import annotations

import datetime

import math
from dataclasses import dataclass, field

from xlsxwriter.utility import xl_range, xl_rowcol_to_cell

from optivedge_integrations.integrations.models import ApplianceGroup
from .errors import ArtifactBuildError


NONE = "—"
TABLE_STYLE = "Table Style Medium 2"
#: The first tab. Every other sheet links back to it from its title band.
SUMMARY_TITLE = "Summary"

#: The header block's palette, keyed to TABLE_STYLE so the block and the table read as one
#: object: its header blue, and its banded-row tint.
TITLE_FILL = "#1F3864"
STRIP_FILL = "#D9E1F2"
RULE_COLOUR = "#4472C4"
MUTED_TEXT = "#595959"
LINK_TEXT = "#0563C1"

#: Tab colours, by what a tab IS rather than by what it is called (Jason, 2026-09-18). The tab
#: strip is the workbook's own navigation: one colour per kind of tab means a reader can tell
#: reference material from findings, and one findings domain from another, before reading a word.
#: The blues are the header block's own family; policy and network step outside it because they
#: are different questions, not different device settings. `network` has no tab yet - it is named
#: here so the domain that lands next takes the colour that was reserved for it rather than
#: inventing one.
#: Keyed by PAN-OS's own top-level categories, so a tab's colour and its place on the Summary come
#: from one fact - which part of the product it assesses - rather than two judgements.
TAB_COLOURS = {
    "summary": "#1F3864",     # the title band's navy: the front page
    "reference": "#8497B0",   # blue-grey: supporting tables, not findings
    "Device": "#2E75B6",      # the device and its management plane
    "Policies": "#C55A11",    # what the firewall enforces
    "Network": "#548235",     # interfaces, zones and the profiles bound to them
    "Objects": "#7030A0",     # the things rules refer to
}


def category_of(model) -> str:
    """Which PAN-OS category a subject model belongs to - Policies, Objects, Network or Device.

    Read from `configuration_navigation.CONFIG_OBJECTS`, the app's own rail, which mirrors the
    product's. Deriving it means the workbook cannot disagree with the app about where an object
    lives, and a new domain arrives already placed. A model with no rail entry raises: the rail is
    the promise about what can be asked, and a findings tab for something not on it is a gap worth
    stopping for.
    """
    from assessments.configuration_navigation import CONFIG_OBJECTS

    label = f"integrations.{model.__name__}"
    for config_object in CONFIG_OBJECTS:
        if config_object.search_model == label:
            return config_object.category
    raise ArtifactBuildError(f"{label} has no entry in the configuration rail, so its category is "
                     f"unknown. Add it there, or give the sheet an explicit category.")
#: Text colours for severity counts - the darker kin of the findings sheets' Severity cell fills,
#: since a rich string can colour text but not fill a run of it.
SEVERITY_TEXT = {"critical": "#C00000", "high": "#C65911", "medium": "#9C6500",
                 "low": "#2F5597", "informational": "#595959"}
#: Cell fills for a severity, by its display label. Critical takes white text.
#: Low was #DDEBF7 until 2026-09-18 and did not read as a fill at all: the table style's banded
#: rows are #D9E1F2, a shade of the same pale blue, so on every other row it vanished. A severity
#: cell has to be legible on BOTH the banded and the unbanded row, which rules out any tint close
#: to the band. Informational keeps a grey for the same reason - no finding carries it yet, and
#: its fill has never been read on a real sheet.
SEVERITY_FILL = {"Critical": "#C00000", "High": "#F4B084", "Medium": "#FFE699",
                 "Low": "#9DC3E6", "Informational": "#D9D9D9"}

#: Excel widths are in characters of the default font. A table header is BOLD, which runs about a
#: tenth wider, and its filter button covers roughly the last three characters of the cell.
BOLD_HEADER_FACTOR = 1.1
FILTER_BUTTON_CHARS = 3
#: Breathing room for a data cell sized to its longest line - on BOTH sides. Two characters was
#: exactly the longest value plus a hair, which reads as text jammed against the next column
#: (Jason, 2026-09-18).
CELL_PADDING_CHARS = 3

#: A cell listing many values - a rule reaching thirty vsys - would otherwise make its row as tall
#: as the list, and three such rows fill a screen. Past this many lines the row is CLIPPED, leaving
#: the next line visibly cut: Excel cannot scroll inside a cell, and a clean cut would read as the
#: whole list (Jason, 2026-09-18). Widen the row, or the column, to read the rest.
#:
#: The fraction is 0.66 of a line rather than 0.5. At half a line these values - lowercase object
#: names with few ascenders and no descenders - were cut through the x-height, which reads as a
#: smudge rather than as text continuing (Jason, 2026-09-18, on the rendered sheet).
MAX_VISIBLE_LINES = 6
CLIPPED_ROW_HEIGHT = 6.66 * 15  # 15 points is one line of the default font


@dataclass
class SheetInfo:
    """What a worksheet tells the Summary tab about itself."""
    title: str
    description: str
    #: Short, for the Summary's contents table: "3 appliances".
    count: str
    #: One line for the console.
    report: str
    #: {severity value: count} on a findings sheet; None on a reference sheet.
    by_severity: dict | None = None
    #: Which PAN-OS category the tab's findings belong to - the Summary groups by it.
    category: str = ""
    #: A SECOND view of findings another tab already counts - the policy tabs are the same
    #: findings grouped two ways. It belongs with the findings tabs on the Summary, but carries no
    #: counts: totalling it would report the estate's findings twice (Jason, 2026-09-18).
    secondary: bool = False
    #: The assessment runs the sheet's findings came from.
    runs: set = field(default_factory=set)


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    return singular if count == 1 else (plural_form or f"{singular}s")


def column_width(col, header, width, rows, *, filter_button=True) -> int:
    """At least the header plus its filter button. A width of None fits the longest LINE of any
    value, so a sized column never wraps mid-line."""
    header_needs = (math.ceil(len(header) * BOLD_HEADER_FACTOR)
                    + (FILTER_BUTTON_CHARS if filter_button else CELL_PADDING_CHARS))
    if width is None:
        longest = max((len(line) for r in rows for line in str(r[col]).split("\n")), default=0)
        width = longest + CELL_PADDING_CHARS
    return max(width, header_needs)


def appliance_names(owner) -> str:
    """The appliances an owner covers, one per line: a group's members, or the one appliance.

    An enforcement point or a scoped object belongs to exactly one owner, and on a Panorama-managed
    estate that owner is always a group - a standalone firewall has a group of its own with one
    member. "None recorded" rather than a blank cell where nothing owns it.
    """
    from optivedge_integrations.integrations.models import ApplianceGroup

    if owner is None:
        return "None recorded"
    members = owner.appliances.all() if isinstance(owner, ApplianceGroup) else [owner]
    return "\n".join(sorted(a.hostname or a.serial_number for a in members)) or "None recorded"


def ha_role(appliance) -> str:
    group = appliance.appliance_group
    if group is None or group.group_type == ApplianceGroup.TYPE_STANDALONE:
        return "Standalone"
    if group.active_appliance_id is None:
        return "Active peer not recorded"
    return "Active" if group.active_appliance_id == appliance.pk else "Passive"


def utc(timestamp) -> str:
    """A timestamp as UTC, because every column header in the workbook says so.

    CONVERTED rather than formatted as-is. Under `USE_TZ` Django hands back aware UTC and the
    old `strftime` was correct by accident of settings; a naive or differently-zoned value
    would have printed under a header asserting UTC. A naive value is taken AS UTC - the only
    reading that matches where these come from, which is a `Snapshot.collected_at` Django
    stored in UTC - rather than as machine-local, which `astimezone` would assume.
    """
    if not timestamp:
        return NONE
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=datetime.timezone.utc)
    return timestamp.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def register_row_anchor(build, kind, pk, sheet_name, row, last_col):
    """Record where a row landed, so another sheet can link to it.

    The anchors live on the BUILD rather than in a module dict: they used to be global, which
    meant a second workbook in the same process inherited the first one's row numbers and
    linked to the wrong row. See `artifacts.context`.
    """
    quoted = sheet_name.replace("'", "''")
    build.anchors[(kind, pk)] = (
        f"internal:'{quoted}'!{xl_range(row, 0, row, last_col)}", sheet_name)


def sheet_target(title) -> str:
    """A link to the top of a worksheet."""
    return f"internal:'{title.replace(chr(39), chr(39) * 2)}'!A1"


def _link_format(build):
    return build.format("link", {"font_color": LINK_TEXT, "underline": 1, "valign": "top"})


def write_link(build, sheet, row, col, kind, pk, text):
    """Overwrite a table cell with a link to the row registered for (kind, pk)."""
    if (kind, pk) not in build.anchors:
        raise ArtifactBuildError(
            f"no {kind} row registered for pk {pk}: is the target sheet written before this one?")
    target, sheet_name = build.anchors[(kind, pk)]
    sheet.write_url(row, col, target, _link_format(build), string=text,
                    tip=f"Open on the {sheet_name} tab")


def write_sheet_link(build, sheet, row, col, title, text=None, cell_format=None):
    sheet.write_url(row, col, sheet_target(title), cell_format or _link_format(build),
                    string=text or title, tip=f"Open the {title} tab")


def severity_group(by_severity):
    """The counts-strip group for {severity: count}, worst first, zero counts omitted."""
    from assessments.control_queries import SEVERITY_RANK
    from assessments.models import Control

    ranked = sorted((s for s, n in by_severity.items() if n),
                    key=lambda s: SEVERITY_RANK[s], reverse=True)
    return [(by_severity[s], Control.Severity(s).label, SEVERITY_TEXT[s]) for s in ranked]


#: Two header shapes (Jason, 2026-09-15):
#:   - `write_simple_header` for INFORMATIONAL sheets (Appliances, Enforcement Points): the title
#:     band and nothing else. What they would count is on the Summary.
#:   - `write_header_block` for the Summary and the control/findings sheets, which carry the
#:     summary data: a counts strip and, on a findings sheet, the controls' rationale.
_BAND = {"valign": "vcenter", "indent": 1}


def band(sheet, row, first_col, last_col, cell_format):
    """Fill a header row cell by cell, NEVER with a merge.

    A merged cell spanning the sheet made Excel jump when scrolling, and a link landing on A1 -
    which is what every tab link does - put the cursor inside that merge and reproduced it every
    time (Jason, 2026-09-15). Filling each cell looks identical, and the text written into the
    first cell still spills across the blank ones beside it.
    """
    for col in range(first_col, last_col + 1):
        sheet.write_blank(row, col, None, cell_format)


def write_title_band(build, sheet, *, title, last_col, tab_colour=None):
    """Row 0: the title, right across the sheet, and the tab's colour."""
    workbook = build.workbook
    if tab_colour:
        sheet.set_tab_color(tab_colour)
    title_fmt = workbook.add_format({**_BAND, "bold": True, "font_size": 18,
                                     "font_color": "#FFFFFF", "bg_color": TITLE_FILL})
    band(sheet, 0, 0, last_col, title_fmt)
    sheet.write(0, 0, title, title_fmt)
    sheet.set_row(0, 36)


def write_strip(build, sheet, *, last_col, parts=(), back_link=True):
    """Row 1: the link back to the Summary, then whatever the sheet counts.

    The link leads the row (Jason, 2026-09-15), so it is in the same place on every tab and reads
    before the numbers rather than inside the title.
    """
    workbook = build.workbook
    strip_fmt = workbook.add_format({**_BAND, "bg_color": STRIP_FILL,
                                     "bottom": 2, "bottom_color": RULE_COLOUR})
    band(sheet, 1, 0, last_col, strip_fmt)
    first_col = 0
    if back_link:
        # The rule under the strip too: this cell REPLACES the banded one, so a format without it
        # leaves a gap in the line under the link (Jason, 2026-09-21).
        back_fmt = workbook.add_format({**_BAND, "font_color": LINK_TEXT, "underline": 1,
                                        "bg_color": STRIP_FILL,
                                        "bottom": 2, "bottom_color": RULE_COLOUR})
        write_sheet_link(build, sheet, 1, 0, SUMMARY_TITLE, f"← {SUMMARY_TITLE}", back_fmt)
        first_col = 1
    if parts and first_col <= last_col:
        sheet.write_rich_string(1, first_col, *parts, strip_fmt)
    # Taller than a data row, and closed by the same rule the header block ends with: the counts
    # are the first thing on the sheet worth reading, and at a data row's height they read as one
    # (Jason, 2026-09-18).
    sheet.set_row(1, 34)


def write_simple_header(build, sheet, *, title, last_col, tab_colour=None) -> int:
    """Title band, the strip carrying only the back link, then breathing room."""
    write_title_band(build, sheet, title=title, last_col=last_col, tab_colour=tab_colour)
    write_strip(build, sheet, last_col=last_col)
    sheet.set_row(2, 8)
    return 3


def write_header_block(build, sheet, *, title, last_col, count_groups, rationale=None,
                       back_link=True, tab_colour=None) -> int:
    """Title band, a counts strip and an optional rationale. Returns the table's header row.

    `count_groups` is a list of groups, each a list of (count, text, colour-or-None). Items in a
    group are separated by a dot, groups by a bar. Shared values - client, engagement, run - belong
    on the Summary tab, not here.
    """
    workbook = build.workbook
    base = _BAND
    write_title_band(build, sheet, title=title, last_col=last_col, tab_colour=tab_colour)

    words = workbook.add_format({"font_color": MUTED_TEXT, "font_size": 11})
    #: Pale, so the separators organise the numbers without competing with them.
    divider = workbook.add_format({"font_color": "#8EAADB", "font_size": 11})
    number_formats = {}

    def number_format(colour):
        if colour not in number_formats:
            number_formats[colour] = workbook.add_format(
                {"bold": True, "font_size": 16, "font_color": colour or TITLE_FILL})
        return number_formats[colour]

    parts = []
    for group in (g for g in count_groups if g):
        if parts:
            parts += [divider, "      |      "]
        for i, (count, text, colour) in enumerate(group):
            if i:
                parts += [divider, "   ·   "]
            parts += [number_format(colour), str(count), words, f" {text}"]

    write_strip(build, sheet, last_col=last_col, parts=parts, back_link=back_link)

    row = 2
    rule_fmt = workbook.add_format({**base, "bottom": 2, "bottom_color": RULE_COLOUR})
    band(sheet, row, 0, last_col, rule_fmt)
    if rationale:
        label = workbook.add_format({"bold": True, "font_color": TITLE_FILL})
        prose = workbook.add_format({"italic": True, "font_color": MUTED_TEXT})
        sheet.write_rich_string(row, 0, label, "Why it matters   ", prose, rationale, rule_fmt)
        sheet.set_row(row, 24)
    else:
        # The rule still closes the block, on a thin row of its own.
        sheet.set_row(row, 4)
    row += 1

    sheet.set_row(row, 8)  # breathing room above the table
    return row + 1


def write_table(build, sheet, *, top, name, columns, rows, empty_text, locked=False):
    """`columns` is a list of (header, width, wrap); see `column_width` for width None.

    `locked` protects the sheet, for a table other sheets link INTO: a link targets a fixed cell
    range, so sorting the table would send every link to the wrong row. Excel cannot filter a table
    on a protected sheet whatever the protection options say, so a locked table has no filter
    buttons rather than dead ones. No password - this guards against an accidental sort, not a
    determined user (Review > Unprotect Sheet).
    """
    workbook = build.workbook
    cell = workbook.add_format({"valign": "top"})
    wrap = workbook.add_format({"valign": "top", "text_wrap": True})
    for col, (header, width, wraps) in enumerate(columns):
        sheet.set_column(col, col, column_width(col, header, width, rows, filter_button=not locked),
                         wrap if wraps else cell)
    for i, row in enumerate(rows):
        tallest = max((str(value).count("\n") + 1 for value in row), default=1)
        if tallest > MAX_VISIBLE_LINES:
            sheet.set_row(top + 1 + i, CLIPPED_ROW_HEIGHT)
    sheet.add_table(top, 0, top + max(len(rows), 1), len(columns) - 1, {
        "name": name,
        "style": TABLE_STYLE,
        "autofilter": not locked,
        "columns": [{"header": h} for h, _, _ in columns],
        "data": rows or [[empty_text] + [NONE] * (len(columns) - 1)],
    })
    if locked:
        # Selecting stays allowed (a link must be able to select its row), and so does resizing.
        sheet.protect("", {"format_columns": True, "format_rows": True})
    # Header rows only. A frozen column splits the merged header block (tried 2026-09-15).
    sheet.freeze_panes(top + 1, 0)

    # Open with the first cell of the table selected, and scrolled to it. Without this the file
    # carries `<selection pane="bottomLeft"/>` with no active cell at all, and Excel picks one on
    # open - which is where the jump off the merged title rows comes from. `set_selection` cannot
    # say it: it returns early for A1, and `freeze_panes` overwrites whatever it did, so the
    # selection is set here, after the freeze, in the form freeze_panes carries into the pane.
    first_cell = xl_rowcol_to_cell(top + 1, 0)
    sheet.selections = [[None, first_cell, first_cell]]
