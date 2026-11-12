"""The committed style donor: opened read-only, filled, and returned as new bytes.

`docx/health-check-scaffold.docx` is Optiv's `PAN Health Check Deliverable Template 2026 (1).dotx`
with its specimen body stripped out and a marker paragraph in its place - see
`management/commands/derive_health_check_scaffold.py`, which is the only thing that writes it.
Measured 2026-11-05: 1.49 MB, 74 parts, 471 styles, 15 media files including the cover artwork as
EMF, five headers, four footers, and three sections with distinct first/even/default headers.

THE MARKER IS THE CONTRACT, not an index. The scaffold's body is sixteen children today - cover
0-6, the marker at 7, back cover 8-14, the final `sectPr` at 15 - and nothing here depends on
that: a build FINDS the paragraph whose text is exactly `{{OEA-BODY}}`, inserts its content
before it, and removes it. A visible sentinel rather than a bookmark, deliberately, so that a
build which fails to remove it says so on the page instead of hiding in the XML.

NOTHING IS MODIFIED IN PLACE. Jason, 2026-11-05: *"modifying something in place comes with its
own challenges. If possible, I'd rather copy the style visually, build our own partials that can
easily be generated from the data, and create a new .docx file every time."* So the file on disk
is read into memory as bytes and python-docx is handed a `BytesIO` over them; the package data is
never opened for writing and two builds never share a file.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path

from docx import Document
from docx.oxml.ns import qn

from . import partials
from ..errors import ArtifactBuildError

#: Where the scaffold lives, relative to the `assessments` package. `pyproject.toml` lists
#: `docx/*.docx` under package-data; without it the wheel ships the code and not the file, and
#: the first build on a deployed install is the one that finds out.
SCAFFOLD_PATH = Path(__file__).resolve().parents[2] / "docx" / "health-check-scaffold.docx"

#: The paragraph a build inserts before and then removes. Must match
#: `derive_health_check_scaffold.BODY_MARKER`.
BODY_MARKER = "{{OEA-BODY}}"

#: The cover's three placeholders, substituted in its runs.
COVER_CLIENT = "[Client Long Name, Inc.]"
COVER_OPPORTUNITY = "[op_number]"
COVER_REVISION = "[revision_number]"

#: `[Shortname]` appears in the template's own body prose, which we re-emit, and nowhere on the
#: cover. It is substituted by the section writers rather than here.
SHORTNAME = "[Shortname]"


@dataclass
class Scaffold:
    """One scaffold, opened for one build."""

    document: object
    #: {style id: `paragraph` | `table` | ...}, read off this scaffold's own styles.xml.
    styles: dict

    @property
    def body(self):
        return self.document.element.body

    def marker(self):
        """The marker paragraph, or a refusal naming the scaffold.

        A scaffold with no marker is a scaffold somebody re-derived from a template this command
        could not slice, and inserting at the end of the body would put the whole report AFTER
        Optiv's back cover - a file that looks finished and is wrong, which is exactly what the
        workbook guards exist to prevent.
        """
        for element in self.body.iterchildren(qn("w:p")):
            if "".join(node.text or "" for node in element.iter(qn("w:t"))) == BODY_MARKER:
                return element
        raise ArtifactBuildError(
            f"{SCAFFOLD_PATH.name} has no {BODY_MARKER} paragraph, so there is nowhere to put "
            f"the report. Re-derive it with manage.py derive_health_check_scaffold.")

    def insert(self, elements) -> None:
        """Put the report before the marker, then take the marker out."""
        marker = self.marker()
        for element in elements:
            marker.addprevious(element)
        marker.getparent().remove(marker)

    def substitute_cover(self, replacements: dict) -> None:
        """Replace the cover's placeholders, run by run, and refuse one that is still there.

        RUN BY RUN because that is how Word stores them: `Opportunity Number: OP-[op_number]` is
        one paragraph but several runs, and Word splits a run wherever the proofing state or the
        revision id changes. Each placeholder measured on this scaffold sits whole inside one
        run, so a run-level replace finds all three - and the check below is what says so for the
        next reissue rather than assuming it.
        """
        for node in self.body.iter(qn("w:t")):
            text = node.text or ""
            for placeholder, value in replacements.items():
                if placeholder in text:
                    text = text.replace(placeholder, value)
            node.text = text
        remaining = sorted(
            placeholder for placeholder in replacements
            if any(placeholder in (node.text or "") for node in self.body.iter(qn("w:t"))))
        if remaining:
            raise ArtifactBuildError(
                f"the cover still carries {', '.join(remaining)} after substitution: the "
                f"placeholder is split across runs in this scaffold and the replacement has to "
                f"join them")

    def write_date_fields(self, replacements: dict) -> int:
        """Replace Word's own DATE fields with the dates this build writes, and stop Word
        offering to update the fields when a reader opens the file. Returns how many it wrote.

        TWO THINGS THAT HAVE TO HAPPEN TOGETHER. Jason, 2026-11-07, opening the deliverable:
        *"after I click 'Enable Editing' in Word, I get a message: 'This document contains
        fields that may refer to other files. Do you want to update the fields in this
        document?'"* That prompt is `<w:updateFields w:val="true"/>` in `word/settings.xml`,
        carried over from Optiv's template, and Word words it that way for any document that
        asks - nothing in here refers to another file. Taking the setting out on its own,
        though, would leave the cover reading `February 4, 2026`, the day Optiv last saved the
        template, because that is the cached result sitting in the field.

        SO THE DATES STOP BEING FIELDS. A `DATE` field is *the day the document is opened*,
        which on a dated deliverable is wrong even when it refreshes: a health check is issued
        on a date, the Version Control section already states that date, and a cover that
        disagrees with it by the time a client reads it is the kind of thing a client notices.
        The build knows the date. It writes it, and the field goes.

        The table of contents keeps its field, but nothing asks Word to update it:
        `partials.table_of_contents` writes the entries, so the file opens with a contents page
        already in it and no question. That the prompt survived a first attempt at this - a
        dirty field rather than the setting - is written up in `partials.toc_field`.
        """
        written = 0
        for paragraph in self.body.iter(qn("w:p")):
            written += _write_date_fields(paragraph, replacements)
        if written != FROZEN_DATE_FIELDS:
            raise ArtifactBuildError(
                f"{SCAFFOLD_PATH.name} has {written} DATE "
                f"{'field' if written == 1 else 'fields'} this build can write and "
                f"{FROZEN_DATE_FIELDS} were expected. A reissued template has moved them, or "
                f"asks for a date in a format this build does not write; see "
                f"Scaffold.write_date_fields.")
        settings = self.document.settings.element
        for element in settings.findall(qn("w:updateFields")):
            settings.remove(element)
        return written

    def to_bytes(self) -> bytes:
        buffer = io.BytesIO()
        self.document.save(buffer)
        return buffer.getvalue()


#: The `DATE` fields this scaffold carries, by the picture switch that says which is which -
#: the cover wants the delivery date written out, the back cover's copyright line wants the
#: year. THREE FIELDS, TWO PICTURES: measured on this scaffold 2026-11-07, the year appears
#: once on each of the two back-cover panels. Both are named here so
#: `Scaffold.write_date_fields` can refuse a reissue that has moved one, lost one or grown a
#: fourth, rather than quietly leaving a template date on a client's cover.
FROZEN_DATE_PICTURES = ('"MMMM d, yyyy"', '"yyyy"')
FROZEN_DATE_FIELDS = 3


def _write_date_fields(paragraph, replacements: dict) -> int:
    """Rewrite each DATE field in one paragraph as the text it should show. Returns how many.

    A Word field is not an element: it is a RUN SAYING `begin`, a run carrying the instruction,
    a run saying `separate`, the runs holding the last calculated result, and a run saying
    `end`. So this walks the paragraph's runs, and replaces the whole sequence with one run
    carrying our text - copied from the result run, so it keeps the formatting the template
    gave it. The copyright year is white on a dark back cover, and a replacement that dropped
    its `w:rPr` would print the year in black on black.
    """
    written = 0
    field = None
    for run in list(paragraph.iterchildren(qn("w:r"))):
        marker = run.find(qn("w:fldChar"))
        kind = marker.get(qn("w:fldCharType")) if marker is not None else None
        if kind == "begin":
            field = {"runs": [run], "instruction": "", "result": []}
            continue
        if field is None:
            continue
        field["runs"].append(run)
        instruction = run.find(qn("w:instrText"))
        if instruction is not None:
            field["instruction"] += instruction.text or ""
        elif kind is None and field["result"] is not None:
            field["result"].append(run)
        if kind != "end":
            continue
        picture = next((p for p in replacements if p in field["instruction"]), None)
        if "DATE" in field["instruction"] and picture is not None:
            # The result run's own properties, or - for a field Word has never calculated and
            # so has no result run for - the run that carried the instruction.
            source = field["result"][0] if field["result"] else field["runs"][1]
            frozen = partials.run_like(source, replacements[picture])
            field["runs"][0].addprevious(frozen)
            for run_element in field["runs"]:
                paragraph.remove(run_element)
            written += 1
        field = None
    return written


def read_styles(document) -> dict:
    """{style id: its `w:type`} for this scaffold.

    Read off the file rather than trusted, because the ids are the contract with Optiv's
    template and a reissue that renames one has to fail loudly. Keyed by ID and not by display
    name for the reason `partials` gives: the id is what lands in `document.xml`.
    """
    styles = {}
    for element in document.styles.element.iterchildren(qn("w:style")):
        styles[element.get(qn("w:styleId"))] = element.get(qn("w:type"))
    return styles


def check_styles(styles: dict) -> None:
    """Refuse a scaffold missing any style we name, or holding one of the wrong kind.

    The same bargain the workbook guards make - `ArtifactBuildError` rather than a file we
    cannot vouch for. Style names are the contract with Optiv's template, and a reissue that
    renames one must fail loudly rather than silently fall back to Normal: a `Rating - Critical`
    cell that lost its style is a critical finding rendered as body text, on a page a client
    reads.

    THE TYPE IS CHECKED TOO. `Optiv (Light Gray Borders)` is a TABLE style, `Hyperlink` is a
    CHARACTER style and the rest are PARAGRAPH styles, and a `w:pStyle` naming a table style is
    not an error Word reports - it ignores it, which is the silent fallback again.
    """
    missing, wrong = [], []
    for expected_type, names in (("paragraph", partials.EMITTED_PARAGRAPH_STYLES),
                                 ("table", partials.EMITTED_TABLE_STYLES),
                                 ("character", partials.EMITTED_CHARACTER_STYLES)):
        for name in names:
            if name not in styles:
                missing.append(name)
            elif styles[name] != expected_type:
                wrong.append(f"{name} is a {styles[name]} style, not a {expected_type} one")
    if missing or wrong:
        raise ArtifactBuildError(
            f"{SCAFFOLD_PATH.name} cannot carry this report: "
            + "; ".join(filter(None, [
                f"it has no {', '.join(sorted(missing))}" if missing else "",
                "; ".join(wrong)])))


def check_bookmarks(document) -> None:
    """Refuse a scaffold whose bookmarks do not pair up.

    WHY A GUARD AND NOT A COMMENT. A `bookmarkStart` with no `bookmarkEnd` is the one defect in
    this file that does not show up anywhere until a client opens it: Word reports "Word found
    unreadable content", offers to recover the document, and the recovered copy has lost
    formatting. Nothing in the build can see it, every test passes, and the deliverable is
    already out.

    It happened once. Deriving the scaffold cuts the template's specimen body out, and three
    bookmarks started on the cover and ended in what was cut - `derive_health_check_scaffold`
    closes them now, and this is what says so on every build rather than trusting that it did.
    """
    starts, ends = {}, set()
    for element in document.element.body.iter():
        if element.tag == qn("w:bookmarkStart"):
            starts[element.get(qn("w:id"))] = element.get(qn("w:name")) or ""
        elif element.tag == qn("w:bookmarkEnd"):
            ends.add(element.get(qn("w:id")))
    unopened = sorted(ends - set(starts))
    unclosed = sorted(f"{name or identifier}" for identifier, name in starts.items()
                      if identifier not in ends)
    if unclosed or unopened:
        raise ArtifactBuildError(
            f"{SCAFFOLD_PATH.name} has bookmarks that do not pair up, and Word will refuse to "
            f"open a document built from it: "
            + "; ".join(filter(None, [
                f"nothing closes {', '.join(unclosed)}" if unclosed else "",
                f"nothing opens bookmark id {', '.join(unopened)}" if unopened else ""]))
            + ". Re-derive it with manage.py derive_health_check_scaffold.")


#: The attribute that lists the namespace prefixes a reader may ignore if it does not know
#: them. Every prefix it names has to resolve to a declaration in scope.
MC_IGNORABLE = "{http://schemas.openxmlformats.org/markup-compatibility/2006}Ignorable"


def check_markup_compatibility(document) -> None:
    """Refuse a scaffold whose `mc:Ignorable` names a namespace prefix nothing declares.

    THIS IS WHAT WORD WAS REFUSING. `w:document` carries
    `mc:Ignorable="w14 w15 w16 w16cex w16cid w16du w16sdtdh w16sdtfl w16se wp14"`. Deriving the
    scaffold used to round-trip the part through `xml.etree`, which declares only the
    namespaces something in the output uses - and cutting the specimen body out took the last
    user of eight of them with it. The attribute went on naming all ten, eight of them
    resolving to nothing, which makes the part invalid under the markup compatibility rules.

    Word's answer is "Word found unreadable content", then "Word experienced an error trying to
    open the file" if you decline the recovery. Nothing else sees it: the XML is well formed,
    every style resolves, every table spans its grid, and python-docx opens it without a
    murmur. Jason, 2026-11-06, is the only reason it was found.
    """
    root = document.element.getroottree().getroot()
    listed = (root.get(MC_IGNORABLE) or "").split()
    declared = {prefix for prefix in root.nsmap if prefix}
    missing = sorted(prefix for prefix in listed if prefix not in declared)
    if missing:
        raise ArtifactBuildError(
            f"{SCAFFOLD_PATH.name} declares no namespace for {', '.join(missing)}, which its "
            f"own mc:Ignorable names - Word refuses to open a document in that state. "
            f"Re-derive it with manage.py derive_health_check_scaffold.")


def check_fonts(document) -> None:
    """Refuse a scaffold whose own default typeface is not the one `partials` writes.

    `partials.BODY_FONT` is written onto every run so that the file NAMES its face rather than
    inheriting it - see that constant. Naming it is only honest while it is the face Optiv's own
    defaults specify: a reissued template that set a different one would otherwise be overridden
    silently by direct formatting, which is the real cost of writing a font on every run. So the
    two are tied together here, and a reissue that changes it fails the build instead.
    """
    defaults = document.styles.element.find(qn("w:docDefaults"))
    fonts = None
    if defaults is not None:
        run_defaults = defaults.find(qn("w:rPrDefault"))
        properties = run_defaults.find(qn("w:rPr")) if run_defaults is not None else None
        fonts = properties.find(qn("w:rFonts")) if properties is not None else None
    specified = fonts.get(qn("w:ascii")) if fonts is not None else None
    if specified != partials.BODY_FONT:
        raise ArtifactBuildError(
            f"{SCAFFOLD_PATH.name} sets its default typeface to "
            f"{specified or 'nothing'}, and this generator writes {partials.BODY_FONT} on every "
            f"run. Change partials.BODY_FONT to match the template, or stop writing it.")


def check_sizes(document) -> None:
    """Refuse a scaffold where a style this generator sizes has grown a size of its own.

    `partials.BODY_SIZE` is written onto every run of `Normal`, `List Bullet` and `Screenshot`
    because Optiv's template states no size for them and none for `w:docDefaults` either, so
    their text falls through to whatever the reader's Word uses - 12pt, measured 2026-11-06.
    Filling that gap is safe. OVERRIDING A SIZE OPTIV CHOSE IS NOT, and the difference is one
    reissue away, so it is checked rather than assumed.
    """
    styles = document.styles.element
    sized = []
    for style in styles.iterchildren(qn("w:style")):
        if style.get(qn("w:styleId")) not in partials.UNSIZED_STYLES:
            continue
        properties = style.find(qn("w:rPr"))
        size = properties.find(qn("w:sz")) if properties is not None else None
        if size is not None:
            sized.append(f"{style.get(qn('w:styleId'))} is "
                         f"{int(size.get(qn('w:val'))) / 2:.0f}pt")
    defaults = styles.find(qn("w:docDefaults"))
    run_defaults = defaults.find(qn("w:rPrDefault")) if defaults is not None else None
    properties = run_defaults.find(qn("w:rPr")) if run_defaults is not None else None
    if properties is not None and properties.find(qn("w:sz")) is not None:
        sized.append("w:docDefaults states a size")
    if sized:
        raise ArtifactBuildError(
            f"{SCAFFOLD_PATH.name} now sizes the body text itself ({'; '.join(sized)}), and "
            f"this generator writes {int(partials.BODY_SIZE) / 2:.0f}pt onto every run of it. "
            f"Drop partials.BODY_SIZE, or change it to match the template.")


def open_scaffold(path: Path | None = None) -> Scaffold:
    """The scaffold, read into memory and checked, for one build.

    The bytes are read and handed to python-docx as a `BytesIO`, so the package data is never
    opened for writing - see the module docstring.
    """
    path = path or SCAFFOLD_PATH
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise ArtifactBuildError(
            f"the health-check scaffold is not installed at {path}. It is package data "
            f"(`docx/*.docx` in pyproject.toml); derive it with manage.py "
            f"derive_health_check_scaffold.")
    document = Document(io.BytesIO(data))
    styles = read_styles(document)
    check_styles(styles)
    check_bookmarks(document)
    check_markup_compatibility(document)
    check_fonts(document)
    check_sizes(document)
    return Scaffold(document=document, styles=styles)
