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

#: The cover's three placeholders, substituted in its runs. Its dates are Word DATE fields and
#: need nothing from us.
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

    def to_bytes(self) -> bytes:
        buffer = io.BytesIO()
        self.document.save(buffer)
        return buffer.getvalue()


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

    THE TYPE IS CHECKED TOO. `Optiv (Light Grey Borders)` is a TABLE style and the rest are
    PARAGRAPH styles, and a `w:pStyle` naming a table style is not an error Word reports - it
    ignores it, which is the silent fallback again.
    """
    missing, wrong = [], []
    for expected_type, names in (("paragraph", partials.EMITTED_PARAGRAPH_STYLES),
                                 ("table", partials.EMITTED_TABLE_STYLES)):
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
    return Scaffold(document=document, styles=styles)
