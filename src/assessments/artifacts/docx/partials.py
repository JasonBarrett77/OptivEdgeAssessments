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
`Optiv (Light Gray Borders)` and states its own grid, and the two shapes that matter here were
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

from ..errors import ArtifactBuildError

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
#: The entry style for a heading at outline level 1, 2 and 3 - the three levels
#: `TOC \o "1-3"` collects. `table_of_contents` writes those lines itself, so these are
#: styles this module emits rather than ones left for Word to fill in.
TOC_ENTRIES = ("TOC1", "TOC2", "TOC3")
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

#: THE TEMPLATE'S OWN CHARACTER STYLE FOR A LINK: Optiv blue `0057B8` and a single underline -
#: the same blue `Table - Heading` labels are in, not Word's generic hyperlink blue. Carried on
#: the run inside a `w:hyperlink`, which is what makes a link in this document LOOK like one.
HYPERLINK = "Hyperlink"

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
#: SIX STYLES IN OPTIV'S TEMPLATE CARRY NO SIZE AT ALL - `Normal`, `List Bullet`,
#: `Screenshot` and the three `toc` entry styles - and neither does `w:docDefaults`, so a
#: paragraph in any of them falls through to whatever the reader's Word uses. Measured 2026-11-06: that is 12pt, against the 9 and 10
#: Optiv sets everywhere it does state a size. Jason, 2026-11-06: *"I'm noticing a lot of the
#: paragraph text is 12 pt instead of 10 pt. Can you ensure the paragraph text is explicitly set
#: to 10 pt."*
#:
#: WRITTEN ONLY ON THE STYLES THAT STATE NOTHING. A heading is 20, 16 or 12pt and a table cell
#: is 9pt because Optiv said so, and `scaffold.check_sizes` refuses a scaffold where one of
#: these has grown a size of its own - at which point this override would be fighting the
#: template rather than filling a gap in it.
BODY_SIZE = "20"
UNSIZED_STYLES = (NORMAL, BULLET, SCREENSHOT, *TOC_ENTRIES)


def _fonts():
    """`<w:rFonts>` naming `BODY_FONT` for both Latin slots.

    The two theme-linked slots are left alone: `eastAsia` and `cs` are for scripts this document
    does not carry, and overriding them would be a claim about text nobody is writing.
    """
    element = OxmlElement("w:rFonts")
    element.set(qn("w:ascii"), BODY_FONT)
    element.set(qn("w:hAnsi"), BODY_FONT)
    return element


def _run_properties(*, bold: bool = False, size: str | None = None,
                    style: str | None = None):
    """`<w:rPr>` in schema order: `rStyle`, `rFonts`, then `b`, then `sz` and `szCs`.

    `rStyle` IS FIRST and that is not a preference: `w:rPr` is a sequence, and a `w:rStyle`
    after `w:rFonts` is the defect Word reports as unreadable content rather than ignoring.
    """
    properties = OxmlElement("w:rPr")
    if style:
        element = OxmlElement("w:rStyle")
        element.set(qn("w:val"), style)
        properties.append(element)
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
    NORMAL, HEADING_1, HEADING_2, HEADING_3, HEADING_APPENDIX, TOC_HEADING, *TOC_ENTRIES,
    BULLET, CAPTION,
    SCREENSHOT, TABLE_HEADING, TABLE_TEXT, TABLE_TEXT_BOLD, TABLE_BULLET,
    *RATING_STYLES.values(),
)
EMITTED_TABLE_STYLES = (TABLE_STYLE,)
EMITTED_CHARACTER_STYLES = (HYPERLINK,)


def rating_style(severity: str) -> str:
    """The `Rating - <Severity>` style for a severity value, or KeyError naming the value.

    Deliberately not `.get(...)` with a fallback: a severity this does not know about is a
    catalog change, and grading it Informational - which is what a fallback would do - would
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


def _run(text: str, *, bold: bool = False, size: str | None = None,
         style: str | None = None):
    run = OxmlElement("w:r")
    run.append(_run_properties(bold=bold, size=size, style=style))
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
    """The table of contents as a `TOC` field with a placeholder result, which
    `table_of_contents` fills with one line per heading.

    NOT MARKED DIRTY, AND THAT IS THE WHOLE POINT. The scaffold carried
    `<w:updateFields w:val="true"/>` in `word/settings.xml`, which made Word stop and ask
    *"This document contains fields that may refer to other files. Do you want to update the
    fields in this document?"* (Jason, 2026-11-07). Nothing in here refers to another file;
    Word words it that way for any document that asks it to recalculate on open. So the build
    dropped the setting and marked this one field dirty instead, on the understanding that a
    dirty field is updated silently - and Word asked the same question anyway: *"It asks, but
    it asks when opening the file now instead of enable editing. It also takes longer for word
    to open the new file."* (Jason, 2026-11-07.) A field Word has to update as the file opens
    is that question, however it is flagged, and the wait was Word laying out two hundred
    pages to number them.

    So nothing is left for Word to do. The entries are written here, the field is left clean,
    and a consultant who wants Optiv's page numbers right-clicks and updates once.
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

    # The placeholder `table_of_contents` replaces. It survives only in a document with no
    # headings at all, and is written as a sentence rather than left blank so that case reads
    # as an instruction rather than a gap.
    element.append(_run("Right-click and choose Update Field to build the table of contents.",
                        size=BODY_SIZE))

    end = OxmlElement("w:r")
    char = OxmlElement("w:fldChar")
    char.set(qn("w:fldCharType"), "end")
    end.append(char)
    element.append(end)
    return element


#: The outline level each heading style sits at, which decides the entry style its line gets.
HEADING_LEVELS = {HEADING_1: 1, HEADING_2: 2, HEADING_3: 3, HEADING_APPENDIX: 1}

#: Where the bookmarks a contents entry links to start numbering. The scaffold's own bookmark
#: ids run to 463, and Word allocates more of its own the first time somebody updates the
#: field, so this starts well clear of both. `_Toc` is the prefix Word uses for the same job,
#: and a name beginning with an underscore is hidden from Word's Bookmark dialog - a reader
#: looking for the bookmarks they placed themselves does not want two hundred of ours listed.
BOOKMARK_BASE = 10_000


def table_of_contents(elements: list) -> int:
    """Fill the `TOC` field in `elements` with one link per heading. Returns the line count.

    READ BACK OFF THE DOCUMENT, NOT BUILT FROM THE SECTION LIST, so the contents cannot
    disagree with the pages: every heading a build just produced is bookmarked where it
    stands, and the entries link to those bookmarks.

    NO PAGE NUMBERS, BECAUSE THERE ARE NONE YET. A generated document has no page numbers
    until Word lays it out, and a number this cannot know is better left off than guessed. The
    entries are links, which is what a reader on screen uses anyway, and the field is still a
    `TOC` field - Update Field replaces all of this with Optiv's numbered version whenever
    somebody wants it. See `toc_field` for why Word is not asked to do that on open.
    """
    index = _toc_index(elements)
    entries, appendices = [], 0
    for element in _every_paragraph(elements):
        style = _style_of(element)
        level = HEADING_LEVELS.get(style)
        if level is None:
            continue
        text = "".join(node.text or "" for node in element.iter(qn("w:t")))
        if style == HEADING_APPENDIX:
            # `Heading1-AppendixList` PRINTS `Appendix A: ` from `w:numId 52` and the paragraph
            # text is the bare name, so the entry has to carry the prefix itself or the contents
            # would read `Reports` where the page reads `Appendix A: Reports`. The template's
            # own contents reads the long form, which settles it.
            text = f"Appendix {chr(ord('A') + appendices)}: {text}"
            appendices += 1
        name = f"_Toc{BOOKMARK_BASE + len(entries)}"
        bookmark(element, name, BOOKMARK_BASE + len(entries))
        entries.append(_toc_entry(level, text, name))
    if not entries:
        return 0
    _carry_field_runs(elements[index], entries[0], entries[-1])
    elements[index:index + 1] = entries
    return len(entries)


def _every_paragraph(elements: list):
    """Every paragraph in the document in reading order, INCLUDING THE ONES INSIDE A TABLE.

    The contents used to read the top level only, which was right while every heading stood on
    its own. A control detail block now carries its heading in the first row of its own table -
    see `health_check.control_detail_rows` - and a heading the contents cannot see is a section
    missing from the contents. Word's own `TOC` field collects a heading wherever it stands,
    so reading the top level only would also have made our contents disagree with the one Word
    builds on Update Field.
    """
    for element in elements:
        if element.tag == qn("w:p"):
            yield element
        elif element.tag == qn("w:tbl"):
            yield from element.iter(qn("w:p"))


def _toc_index(elements: list) -> int:
    """Where the `TOC` field sits in `elements`. Exactly one, or the build stops.

    A second one would be filled with the same entries and leave the document contradicting
    itself; none means `write_contents` stopped emitting the field and the deliverable would
    ship with no contents page at all.
    """
    found = [index for index, element in enumerate(elements)
             if element.tag == qn("w:p")
             and any((node.text or "").strip().startswith("TOC")
                     for node in element.iter(qn("w:instrText")))]
    if len(found) != 1:
        raise ArtifactBuildError(
            f"the document carries {len(found)} TOC fields and the table of contents is "
            f"written into exactly one - see partials.table_of_contents")
    return found[0]


def _toc_entry(level: int, text: str, name: str):
    """One contents line: the heading's text, linked to the bookmark on the heading."""
    element = paragraph(TOC_ENTRIES[level - 1])
    link = OxmlElement("w:hyperlink")
    link.set(qn("w:anchor"), name)
    link.append(_run(text, size=BODY_SIZE))
    element.append(link)
    return element


def _carry_field_runs(field, first, last) -> None:
    """Move the field's own runs onto the first and last entry, which is where Word puts them.

    A `TOC` field's result is a run of paragraphs, so the field opens inside the first line and
    closes inside the last rather than sitting in a paragraph of its own. The runs are moved
    rather than rebuilt so the instruction that reaches Word is the one `toc_field` wrote.
    """
    runs = [run for run in field.iterchildren(qn("w:r"))
            if run.find(qn("w:fldChar")) is not None
            or run.find(qn("w:instrText")) is not None]
    for offset, run in enumerate(runs[:-1]):
        # AFTER `w:pPr`, which is the paragraph's first child.
        first.insert(1 + offset, run)
    last.append(runs[-1])


#: Where the bookmarks a SUMMARY ROW links to start numbering, clear of `BOOKMARK_BASE` and
#: of anything Word allocates for itself. `_Ref` is the prefix Word uses for a cross-reference,
#: and like `_Toc` it is hidden from the Bookmark dialog.
REFERENCE_BASE = 20_000


def bookmark(paragraph_element, name: str, number: int) -> None:
    """Wrap a heading's content in a bookmark, which is what a link elsewhere points at."""
    start = OxmlElement("w:bookmarkStart")
    start.set(qn("w:id"), str(number))
    start.set(qn("w:name"), name)
    end = OxmlElement("w:bookmarkEnd")
    end.set(qn("w:id"), str(number))
    paragraph_element.insert(1 if paragraph_element.find(qn("w:pPr")) is not None else 0, start)
    paragraph_element.append(end)


def _style_of(element):
    """The paragraph's style id, or None for one carrying no `w:pStyle`."""
    properties = element.find(qn("w:pPr"))
    style = properties.find(qn("w:pStyle")) if properties is not None else None
    return style.get(qn("w:val")) if style is not None else None


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


def link_paragraph(style: str, text: str, anchor: str, *, tight: bool = False):
    """One paragraph whose whole text links to a bookmark in this document, and LOOKS like it.

    IT WAS DELIBERATELY UNSTYLED, on the reasoning that the `Hyperlink` style is blue and
    underlined and would paint every row of a summary table reading down a page of control
    names - Word's own table of contents does the same thing, and a reader finds those by the
    cursor. That reasoning did not survive contact: Jason, 2026-11-12, asked whether each row
    of the Summary of Findings table could link to its detail block, and it already did. Every
    row had been a link since 2026-11-09. A link the author of the document cannot find is a
    link a client will not find either, so the cue is on the page now rather than under the
    cursor, in the template's own `Hyperlink` style - Optiv blue, not Word's.

    THE TABLE OF CONTENTS IS NOT AFFECTED. Its entries are links too and they are built by
    `_toc_entry`, which writes its own runs; Word styles a real TOC itself.
    """
    element = paragraph(style, tight=tight)
    link = OxmlElement("w:hyperlink")
    link.set(qn("w:anchor"), anchor)
    link.append(_run(text, size=BODY_SIZE if style in UNSIZED_STYLES else None,
                     style=HYPERLINK))
    element.append(link)
    return element


def link_cell(text: str, anchor: str, *, width=None, style: str = TABLE_TEXT,
              tight: bool = False) -> Cell:
    """A cell whose text is a link to `anchor` - see `link_paragraph`."""
    return Cell(paragraphs=[link_paragraph(style, text, anchor, tight=tight)], width=width)


def rating_cell(severity: str | None, label: str, *, width=None) -> Cell:
    """The severity cell, in its own `Rating - <Severity>` style, centered as the template centers
    it - or, for an area nothing assessed, an EMPTY `Table - Text` cell.

    Jason's ruling retires `No Deviation`, so there is no grade left that means "we looked and
    found nothing wrong": Informational means a control ran and passed. An area with no control
    behind it has to leave the cell blank, because every value it could hold would be a claim.
    """
    if severity is None:
        return Cell(paragraphs=[paragraph(TABLE_TEXT, label)], width=width, valign="center")
    return Cell(paragraphs=[paragraph(rating_style(severity), label)],
                width=width, valign="center")


def table(rows, grid, *, style: str = TABLE_STYLE, width=(5000, "pct"),
          keep_together: bool = False):
    """A `<w:tbl>` of `Cell` rows over `grid` (the template's own `<w:gridCol>` widths).

    The first row gets `tblHeader`, so it repeats after a page break - see the module docstring.

    `keep_together` HOLDS THE WHOLE TABLE ON ONE PAGE. Jason, 2026-11-13: *"a table should be
    fully contained on a page. In other words, no page breaks inside a table."* The table style
    already carries `w:cantSplit`, which keeps one ROW off two pages and says nothing about the
    table; Word has no "keep this table together" setting, and the way to ask for one is
    `w:keepNext` on every paragraph except the last row's - each row then has to stay with the
    row below it, so the whole table moves to the next page rather than breaking. See
    `_keep_with_next`.

    PASS IT ONLY FOR A TABLE THAT FITS ON A PAGE. A table taller than the text area still
    breaks - Word has nowhere else to put it - so asking for this on the Summary of Findings
    table, which runs to 263 rows, would buy a page break before it and nothing else.
    """
    rows = list(rows)
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
        row = _row(cells, header=index == 0)
        if keep_together and index < len(rows) - 1:
            _keep_with_next(row)
        element.append(row)
    return element


def _keep_with_next(row) -> None:
    """`w:keepNext` on every paragraph in one table row, so the row cannot be the last on a page.

    IN SCHEMA ORDER, which for `w:pPr` means directly after `w:pStyle` and before the spacing
    and `w:rPr` that `paragraph` writes - out of order, Word reports unreadable content rather
    than ignoring it, the same class of defect as a `w:rStyle` written after `w:rFonts`.
    """
    for element in row.iter(qn("w:p")):
        properties = element.find(qn("w:pPr"))
        if properties is None:
            properties = OxmlElement("w:pPr")
            element.insert(0, properties)
        if properties.find(qn("w:keepNext")) is not None:
            continue
        style = properties.find(qn("w:pStyle"))
        index = list(properties).index(style) + 1 if style is not None else 0
        properties.insert(index, OxmlElement("w:keepNext"))


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
