"""Paragraphs, tables, captions and rating cells, as WordprocessingML.

STYLES ARE NAMED BY ID, NOT BY DISPLAY NAME. python-docx's own `add_paragraph(style=...)` looks
a style up by its display name and translates the built-in ones through `BabelFish` - measured
2026-11-05 on the scaffold, `Heading1`'s stored name is `heading 1` and `Caption`'s is `caption`,
both lowercase, and BabelFish is what turns `Heading 1` back into the first of those. That works,
and it is still the wrong contract for a generator: the thing that ends up in `document.xml` is
`<w:pStyle w:val="Heading1"/>`, the id, so the id is what a guard can check against styles.xml
and what a test can assert the output references. Naming the display name would leave a layer of
translation between what this module says and what the file contains.

WIDTHS AND SPANS ARE MEASURED OFF THE TEMPLATE. Every table in Optiv's body uses
`Optiv (Light Grey Borders)` and states its own grid, and the two shapes that matter here were
measured on `PAN Health Check Deliverable Template 2026 (1).dotx` (2026-11-05):

    the observation tables   tblW 5000 pct   grid 3408 / 5227 / 1589   cells 1667 / 2556 / 777
    the fixed-width tables   tblW 10224 dxa  grid per table

So a caller passes the template's own numbers rather than inventing a layout, and the first row
of the header is spanned the way the template spans it.

`tblHeader` IS SET ON EVERY FIRST ROW, which the template does not do. The template's tables are
a handful of specimen rows; ours run to pages - the firewall observation table alone is 23 rows
and the Summary of Findings is around sixty - and a table that crosses a page break without a
repeated header leaves the reader with three unlabelled columns.
"""

from __future__ import annotations

import copy

from dataclasses import dataclass, field

from docx.oxml.ns import qn
from docx.oxml.shared import OxmlElement

#: Paragraph style ids, measured off the scaffold. The build-time guard in `scaffold` refuses a
#: scaffold missing any of them, so these names are the contract with Optiv's template.
NORMAL = "Normal"
HEADING_1 = "Heading1"
HEADING_2 = "Heading2"
HEADING_3 = "Heading3"
#: `Heading1-AppendixList` carries `<w:numPr w:numId="52"/>`, which is what prints the
#: `Appendix A: ` part. So its paragraph text is the appendix's NAME only - "Reports", not
#: "Appendix A: Reports", which would print the prefix twice. The template's own headings are
#: bare names and its table of contents reads `Appendix A: Reports`, which settles it.
HEADING_APPENDIX = "Heading1-AppendixList"
TOC_HEADING = "TOCHeading"
BULLET = "ListBullet"
CAPTION = "Caption"
SCREENSHOT = "Screenshot"
TABLE_HEADING = "Table-Heading"
TABLE_TEXT = "Table-Text"
TABLE_TEXT_BOLD = "Table-TextBoldTotal"
TABLE_BULLET = "Table-ListBullet1"

#: The severity cell's style, by `Control.Severity` value. Jason, 2026-11-05: *"We are not going
#: to use 'No Deviation' for now. that can be replaced with Informational."* With D-5 retired the
#: template's five grades are 1:1 with the catalogue's five severities, which is why the template
#: already ships a `Rating - Informational` style it never uses.
RATING_STYLES = {
    "critical": "Rating-Critical",
    "high": "Rating-High",
    "medium": "Rating-Medium",
    "low": "Rating-Low",
    "informational": "Rating-Informational",
}

#: The table style every table in the template's body uses.
TABLE_STYLE = "OptivLightGreyBorders"

#: The Latin typeface every run this module emits names OUT LOUD.
#:
#: IT IS THE ONE OPTIV'S DEFAULTS ALREADY SPECIFY, and `scaffold.check_fonts` refuses a scaffold
#: that says anything else - so this is not a face chosen here, it is the template's own face
#: written where a reader can see it. Without it a run names no font at all and inherits
#: `w:docDefaults`, which reads
#: `<w:rFonts w:ascii="Arial" w:eastAsiaTheme="minorHAnsi" w:hAnsi="Arial" w:cstheme="minorBidi"/>`:
#: Latin text renders Arial, but two of the four slots are linked to the theme, whose minor font
#: is `Tw Cen MT` - and Word's font box names the theme rather than Arial. Jason, 2026-11-06:
#: *"I'm seeing frequent use of a font I don't recognize, called Tw Cen MT (Body)."* Nothing
#: rendered in it, but a consultant checking a client deliverable should not have to take that
#: on trust.
BODY_FONT = "Arial"

#: The size body prose is written at, in half-points. 10pt.
#:
#: THREE STYLES IN OPTIV'S TEMPLATE CARRY NO SIZE AT ALL - `Normal`, `List Bullet` and
#: `Screenshot` - and neither does `w:docDefaults`, so a paragraph in any of them falls through
#: to whatever the reader's Word uses. Measured 2026-11-06: that is 12pt, against the 9 and 10
#: Optiv sets everywhere it does state a size. Jason, 2026-11-06: *"I'm noticing a lot of the
#: paragraph text is 12 pt instead of 10 pt. Can you ensure the paragraph text is explicitly set
#: to 10 pt."*
#:
#: WRITTEN ONLY ON THE STYLES THAT STATE NOTHING. A heading is 20, 16 or 12pt and a table cell
#: is 9pt because Optiv said so, and `scaffold.check_sizes` refuses a scaffold where one of
#: these three has grown a size of its own - at which point this override would be fighting the
#: template rather than filling a gap in it.
BODY_SIZE = "20"
UNSIZED_STYLES = (NORMAL, BULLET, SCREENSHOT)


def _fonts():
    """`<w:rFonts>` naming `BODY_FONT` for both Latin slots.

    The two theme-linked slots are left alone: `eastAsia` and `cs` are for scripts this document
    does not carry, and overriding them would be a claim about text nobody is writing.
    """
    element = OxmlElement("w:rFonts")
    element.set(qn("w:ascii"), BODY_FONT)
    element.set(qn("w:hAnsi"), BODY_FONT)
    return element


def _run_properties(*, bold: bool = False, size: str | None = None):
    """`<w:rPr>` in schema order: `rFonts`, then `b`, then `sz` and `szCs`."""
    properties = OxmlElement("w:rPr")
    properties.append(_fonts())
    if bold:
        properties.append(OxmlElement("w:b"))
    if size:
        for tag in ("w:sz", "w:szCs"):
            element = OxmlElement(tag)
            element.set(qn("w:val"), size)
            properties.append(element)
    return properties

#: Every style id this module can emit, for the scaffold guard to check in one call. Derived
#: rather than listed a second time: a style added above and forgotten here would be the one
#: that silently falls back to Normal.
EMITTED_PARAGRAPH_STYLES = (
    NORMAL, HEADING_1, HEADING_2, HEADING_3, HEADING_APPENDIX, TOC_HEADING, BULLET, CAPTION,
    SCREENSHOT, TABLE_HEADING, TABLE_TEXT, TABLE_TEXT_BOLD, TABLE_BULLET,
    *RATING_STYLES.values(),
)
EMITTED_TABLE_STYLES = (TABLE_STYLE,)


def rating_style(severity: str) -> str:
    """The `Rating - <Severity>` style for a severity value, or KeyError naming the value.

    Deliberately not `.get(...)` with a fallback: a severity this does not know about is a
    catalogue change, and grading it Informational - which is what a fallback would do - would
    print a pass over a finding.
    """
    return RATING_STYLES[severity]


def paragraph(style: str, text: str = "", *, bold: bool = False, tight: bool = False):
    """One `<w:p>` in `style`, carrying `text` as a single run.

    An EMPTY text is a real paragraph and not a mistake: the `Screenshot` style is an empty
    paragraph whose border frames the image a consultant pastes in, and the spacing paragraphs
    between a table and the next heading are the template's own.

    `bold` is for the one place the template bolds inside a style rather than through it - the
    Area column of both observation tables, which is `Table - Text` with `<w:b/>` on the run.
    """
    element = OxmlElement("w:p")
    properties = OxmlElement("w:pPr")
    style_element = OxmlElement("w:pStyle")
    style_element.set(qn("w:val"), style)
    properties.append(style_element)
    if tight:
        # NO SPACE ABOVE OR BELOW. `w:docDefaults` puts 3pt either side of every paragraph, so
        # a cell holding one line per firewall spends 6pt between each of them saying nothing.
        # BEFORE `w:rPr`, which is where `w:pPr`'s sequence puts it.
        spacing = OxmlElement("w:spacing")
        spacing.set(qn("w:before"), "0")
        spacing.set(qn("w:after"), "0")
        properties.append(spacing)
    # THE PARAGRAPH MARK CARRIES IT TOO. Word reports the formatting of the mark when the caret
    # sits at the end of a line or the paragraph is empty, and an empty `Screenshot` paragraph
    # is nothing but its mark.
    size = BODY_SIZE if style in UNSIZED_STYLES else None
    properties.append(_run_properties(bold=bold, size=size))
    element.append(properties)
    if text:
        element.append(_run(text, bold=bold, size=size))
    return element


def lead_paragraph(style: str, lead: str, text: str, *, tight: bool = False):
    """One paragraph that OPENS with a bold label - `Where to confirm it.  Device > ...`.

    `paragraph` bolds the whole run, which is what the observation tables want for a label row
    and wrong for a sentence whose first words are its own label. The Control Detail section's
    one prose line is written that way in the mock-up Jason agreed on 2026-11-06, so the
    paragraph carries two runs and they share the style's font and size.
    """
    element = paragraph(style, "", tight=tight)
    size = BODY_SIZE if style in UNSIZED_STYLES else None
    element.append(_run(lead, bold=True, size=size))
    if text:
        # The space BELONGS TO THE SECOND RUN and `_run` preserves it, so the bold does not
        # run on into the gap between the label and the sentence.
        element.append(_run(f" {text}", size=size))
    return element


def _run(text: str, *, bold: bool = False, size: str | None = None):
    run = OxmlElement("w:r")
    run.append(_run_properties(bold=bold, size=size))
    element = OxmlElement("w:t")
    # Word collapses leading and trailing space in a run unless told not to, and the measured
    # sentences here end in a period rather than a space - but a value read off the database
    # can, so this is set unconditionally rather than on inspection.
    element.set(qn("xml:space"), "preserve")
    element.text = text
    run.append(element)
    return run


def run_like(source, text: str):
    """A run carrying `text`, formatted the way `source` is formatted.

    Used where a run the TEMPLATE wrote has to be replaced by one we write - see
    `scaffold._write_date_fields`. The properties are copied rather than rebuilt from
    `_run_properties`, because they are Optiv's: the copyright year on the back cover is white
    on a dark panel, and a replacement built from our own defaults would print it in black.
    """
    run = OxmlElement("w:r")
    properties = source.find(qn("w:rPr"))
    if properties is not None:
        run.append(copy.deepcopy(properties))
    element = OxmlElement("w:t")
    element.set(qn("xml:space"), "preserve")
    element.text = text
    run.append(element)
    return run


def toc_field(instruction: str = 'TOC \\o "1-3" \\h \\z \\u'):
    """The table of contents as an EMPTY field, MARKED DIRTY, which Word fills on open.

    A generated document has no page numbers until Word lays it out, so there is nothing to
    write into the field's cached result.

    `w:dirty` IS WHAT ASKS WORD TO BUILD IT, and it asks for this field alone. The scaffold
    used to carry `<w:updateFields w:val="true"/>` in `word/settings.xml`, which told Word to
    recalculate everything - and made it stop and ask first: *"This document contains fields
    that may refer to other files. Do you want to update the fields in this document?"*
    (Jason, 2026-11-07). Nothing in here refers to another file; Word words it that way for
    any document that asks. A dirty field is updated without the question, so
    `Scaffold.write_date_fields` drops the setting and writes the dates as text, and this is
    the one field left that genuinely cannot be written ahead of time.
    """
    element = OxmlElement("w:p")
    properties = OxmlElement("w:pPr")
    style = OxmlElement("w:pStyle")
    style.set(qn("w:val"), NORMAL)
    properties.append(style)
    # This paragraph builds its own `w:pPr` rather than going through `paragraph`, so it has to
    # name the face itself - see `BODY_FONT`.
    properties.append(_run_properties(size=BODY_SIZE))
    element.append(properties)

    begin = OxmlElement("w:r")
    char = OxmlElement("w:fldChar")
    char.set(qn("w:fldCharType"), "begin")
    char.set(qn("w:dirty"), "true")
    begin.append(char)
    element.append(begin)

    instruction_run = OxmlElement("w:r")
    text = OxmlElement("w:instrText")
    text.set(qn("xml:space"), "preserve")
    text.text = f" {instruction} "
    instruction_run.append(text)
    element.append(instruction_run)

    separate = OxmlElement("w:r")
    char = OxmlElement("w:fldChar")
    char.set(qn("w:fldCharType"), "separate")
    separate.append(char)
    element.append(separate)

    # The placeholder Word replaces. Written as a sentence rather than left blank so that a
    # reader who opens the file in something that does not calculate fields - a browser preview,
    # a converter - sees why the contents are missing instead of a gap.
    element.append(_run("Right-click and choose Update Field to build the table of contents.",
                        size=BODY_SIZE))

    end = OxmlElement("w:r")
    char = OxmlElement("w:fldChar")
    char.set(qn("w:fldCharType"), "end")
    end.append(char)
    element.append(end)
    return element


@dataclass
class Cell:
    """One table cell: the paragraphs in it, and how wide and how many columns it covers.

    A cell is a LIST OF PARAGRAPHS because the template's cells are - a bold label followed by
    bullets is how both observation tables and all three recommendation tables carry anything
    longer than a phrase, and collapsing that to one string would lose the shape the reader is
    being shown.
    """

    paragraphs: list = field(default_factory=list)
    #: `(value, unit)` from the template's own `<w:tcW>`; unit is `pct` or `dxa`.
    width: tuple | None = None
    #: How many grid columns this cell covers. The header row of an observation table covers
    #: all three.
    span: int = 1
    #: `center` on the rating cells, which is what the template sets on them.
    valign: str | None = None
    #: `(fill, themeFill)` for the cell's background, or None for the style's own.
    shading: tuple | None = None


def bullet_cell(lead: str, lines, *, width=None, lead_style: str = TABLE_TEXT,
                bold_lead: bool = False) -> Cell:
    """A cell holding a lead paragraph and then one bullet per line - the template's own shape
    for an observation or a recommendation with more than one thing to say."""
    paragraphs = [paragraph(lead_style, lead, bold=bold_lead)] if lead else []
    paragraphs += [paragraph(TABLE_BULLET, line) for line in lines]
    if not paragraphs:
        paragraphs = [paragraph(lead_style, "")]
    return Cell(paragraphs=paragraphs, width=width)


def text_cell(text: str, *, width=None, style: str = TABLE_TEXT, bold: bool = False,
              shading: tuple | None = None, tight: bool = False) -> Cell:
    return Cell(paragraphs=[paragraph(style, text, bold=bold, tight=tight)], width=width,
                shading=shading)


#: The grey Optiv's own table style paints its emphasis row with - `accent5`, measured on the
#: scaffold 2026-11-06. Named as the THEME colour as well as the literal, so a reissued template
#: that restyles its palette carries this with it rather than leaving one grey behind.
BAND_SHADING = ("CCCCCC", "accent5")


def rating_cell(severity: str | None, label: str, *, width=None) -> Cell:
    """The severity cell, in its own `Rating - <Severity>` style, centred as the template centres
    it - or, for an area nothing assessed, an EMPTY `Table - Text` cell.

    Jason's ruling retires `No Deviation`, so there is no grade left that means "we looked and
    found nothing wrong": Informational means a control ran and passed. An area with no control
    behind it has to leave the cell blank, because every value it could hold would be a claim.
    """
    if severity is None:
        return Cell(paragraphs=[paragraph(TABLE_TEXT, label)], width=width, valign="center")
    return Cell(paragraphs=[paragraph(rating_style(severity), label)],
                width=width, valign="center")


def table(rows, grid, *, style: str = TABLE_STYLE, width=(5000, "pct")):
    """A `<w:tbl>` of `Cell` rows over `grid` (the template's own `<w:gridCol>` widths).

    The first row gets `tblHeader`, so it repeats after a page break - see the module docstring.
    """
    element = OxmlElement("w:tbl")
    properties = OxmlElement("w:tblPr")
    style_element = OxmlElement("w:tblStyle")
    style_element.set(qn("w:val"), style)
    properties.append(style_element)
    table_width = OxmlElement("w:tblW")
    table_width.set(qn("w:w"), str(width[0]))
    table_width.set(qn("w:type"), width[1])
    properties.append(table_width)
    look = OxmlElement("w:tblLook")
    # 0420 with firstRow on is what every body table in the template declares: band the header
    # row, band nothing else. The style paints the rest.
    look.set(qn("w:val"), "0420")
    look.set(qn("w:firstRow"), "1")
    look.set(qn("w:lastRow"), "0")
    look.set(qn("w:firstColumn"), "0")
    look.set(qn("w:lastColumn"), "0")
    look.set(qn("w:noHBand"), "1")
    look.set(qn("w:noVBand"), "1")
    properties.append(look)
    element.append(properties)

    grid_element = OxmlElement("w:tblGrid")
    for column in grid:
        column_element = OxmlElement("w:gridCol")
        column_element.set(qn("w:w"), str(column))
        grid_element.append(column_element)
    element.append(grid_element)

    for index, cells in enumerate(rows):
        element.append(_row(cells, header=index == 0))
    return element


def _row(cells, *, header: bool):
    row = OxmlElement("w:tr")
    properties = OxmlElement("w:trPr")
    if header:
        properties.append(OxmlElement("w:tblHeader"))
    height = OxmlElement("w:trHeight")
    # The template sets a 20-twip minimum on every observation row, which lets a one-line row
    # be one line high instead of inheriting the style's default.
    height.set(qn("w:val"), "20")
    properties.append(height)
    row.append(properties)
    for cell in cells:
        row.append(_cell(cell))
    return row


def _cell(cell: Cell):
    element = OxmlElement("w:tc")
    properties = OxmlElement("w:tcPr")
    if cell.width is not None:
        width = OxmlElement("w:tcW")
        width.set(qn("w:w"), str(cell.width[0]))
        width.set(qn("w:type"), cell.width[1])
        properties.append(width)
    if cell.span > 1:
        span = OxmlElement("w:gridSpan")
        span.set(qn("w:val"), str(cell.span))
        properties.append(span)
    if cell.shading is not None:
        # AFTER `gridSpan` AND BEFORE `vAlign`: `w:tcPr` is a sequence, and out of order Word
        # reports unreadable content - the same class of defect as the namespace one.
        fill, theme_fill = cell.shading
        shading = OxmlElement("w:shd")
        shading.set(qn("w:val"), "clear")
        shading.set(qn("w:color"), "auto")
        shading.set(qn("w:fill"), fill)
        if theme_fill:
            shading.set(qn("w:themeFill"), theme_fill)
        properties.append(shading)
    if cell.valign is not None:
        valign = OxmlElement("w:vAlign")
        valign.set(qn("w:val"), cell.valign)
        properties.append(valign)
    element.append(properties)
    # A `<w:tc>` with no `<w:p>` in it is invalid and Word repairs the document rather than
    # opening it, so an empty cell carries an empty paragraph.
    for child in cell.paragraphs or [paragraph(TABLE_TEXT, "")]:
        element.append(child)
    return element


@dataclass
class CaptionCounters:
    """Table and figure numbers, LITERAL rather than `SEQ` fields.

    The document is generated whole, so the numbers are known at build time, and a literal
    number is right even for a reader who never refreshes fields - which the table of contents
    already asks them to do once. Two counters, advanced in document order, so a section that
    emits a table and then a figure numbers both correctly without knowing where it sits.
    """

    tables: int = 0
    figures: int = 0

    def table(self, title: str):
        self.tables += 1
        return paragraph(CAPTION, f"Table {self.tables}: {title}")

    def figure(self, title: str):
        self.figures += 1
        return paragraph(CAPTION, f"Figure {self.figures}: {title}")
