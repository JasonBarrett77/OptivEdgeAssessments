"""Derive the health-check scaffold from Optiv's .dotx template. A one-off, run again on reissue.

WHY A SCAFFOLD. The deliverable is generated fresh every time and nothing is ever edited in
place (Jason, 2026-11-05: *"modifying something in place comes with its own challenges ... I'd
rather copy the style visually, build our own partials that can easily be generated from the
data, and create a new .docx file every time."*). Copying the style VISUALLY is the one part of
that not worth doing: the template carries 471 styles, Optiv's theme, 15 media files including
the cover artwork as EMF, five headers, four footers and three sections with distinct
first/even/default headers. Re-deriving that by eye would look nearly right, be wrong, lose the
covers, and drift at the next reissue.

So the template becomes a STYLE DONOR. This command strips its body - every heading, table and
paragraph of the specimen content - and keeps everything that makes a page look like Optiv's:
styles.xml, numbering.xml, the theme, the headers and footers, the media, the section
properties, the cover and the back cover. The result is committed as package data, opened
READ-ONLY by every build, and never written to.

WHAT IS KEPT, by position in the template's own body (measured 2026-11-05 on
`PAN Health Check Deliverable Template 2026 (1).dotx`, which has 249 top-level body children):

    0-6      the cover page, ending in the section break that gives it its own header
    7-239    the table of contents and the whole specimen body        <- DROPPED
    240-247  the back cover: Optiv's boilerplate and the copyright line
    248      the final sectPr - page size, margins, header and footer references

In place of the dropped body the scaffold carries ONE marker paragraph whose text is
`{{OEA-BODY}}`. A build inserts its content before that paragraph and then removes it, which is
why the generator never needs to know these indices: it looks for the marker. A visible sentinel
rather than a bookmark, deliberately - if a build ever fails to remove it, it says so on the
page instead of hiding in the XML.

The positions ARE checked rather than trusted: the command refuses a template whose body does
not look like the one above, because a silently mis-sliced scaffold would ship a deliverable
with half the specimen content still in it.
"""
from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from lxml import etree

from django.core.management.base import BaseCommand, CommandError

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

#: Where the scaffold is kept, and the name the generator opens it by.
SCAFFOLD_NAME = "health-check-scaffold.docx"
#: The paragraph a build inserts its content before.
BODY_MARKER = "{{OEA-BODY}}"
#: A .dotx declares its main part a TEMPLATE; a .docx declares it a DOCUMENT. Everything else
#: about the two formats is identical, which is why this is a string swap and not a conversion.
TEMPLATE_CONTENT_TYPE = "wordprocessingml.template.main+xml"
DOCUMENT_CONTENT_TYPE = "wordprocessingml.document.main+xml"


def w(tag: str) -> str:
    return f"{{{W}}}{tag}"


#: WHY LXML AND NOT `xml.etree`, WHICH THIS COMMAND USED UNTIL 2026-11-06.
#:
#: ElementTree declares only the namespaces something in the output actually uses. Cutting the
#: specimen body out took the last user of eight of them with it, so `w:document` came back
#: declaring 15 namespaces where Optiv's template declares 35 - and the root still carried
#: `mc:Ignorable="w14 w15 w16 w16cex w16cid w16du w16sdtdh w16sdtfl w16se wp14"`, which NAMES
#: eight prefixes that were no longer declared anywhere.
#:
#: A prefix in `mc:Ignorable` that resolves to nothing makes the part invalid under the markup
#: compatibility rules, and Word will not open it: "Word found unreadable content", then "Word
#: experienced an error trying to open the file" if you decline the recovery (Jason,
#: 2026-11-06, with both dialogue boxes). The same happened to `word/settings.xml`, the other
#: part this command rewrites.
#:
#: lxml keeps every declaration the element was parsed with, so a part this command only slices
#: comes back out declaring exactly what it came in with.


def tostring(element) -> bytes:
    return etree.tostring(element, xml_declaration=True, encoding="UTF-8", standalone=True)


def section_break_index(children) -> int:
    """The index of the paragraph carrying the cover's section break, which ends the cover."""
    for index, child in enumerate(children):
        if child.tag != w("p"):
            continue
        pr = child.find(w("pPr"))
        if pr is not None and pr.find(w("sectPr")) is not None:
            return index
    raise CommandError("no section break found: this template's cover cannot be identified")


def back_cover_index(children) -> int:
    """Where the back cover starts - the run of empty NoSpacing paragraphs before Optiv's
    boilerplate table, which is the last table in the body."""
    last_table = max(i for i, child in enumerate(children) if child.tag == w("tbl"))
    index = last_table
    while index > 0:
        previous = children[index - 1]
        if previous.tag != w("p"):
            break
        pr = previous.find(w("pPr"))
        style = pr.find(w("pStyle")) if pr is not None else None
        if style is None or style.get(w("val")) != "NoSpacing":
            break
        index -= 1
    return index


def close_orphaned_bookmarks(body) -> list[str]:
    """Drop every bookmark whose other half was in the content this command cuts out.

    WHAT IT COSTS TO SKIP. Three of this template's bookmarks - `_Hlk47707859`,
    `_Toc417055643` and `_Toc410994106` - START on the cover and END inside the specimen body.
    Cutting the body left three `bookmarkStart` elements with nothing to close them, and Word
    will not open a document in that state: it reports "Word found unreadable content", offers
    to recover it, and the recovered file has lost formatting (Jason, 2026-11-06, with the
    dialogue box). The template itself is balanced, 321 starts and 321 ends; the imbalance is
    made here, so it is closed here.

    DROPPED RATHER THAN CLOSED WITH A NEW `bookmarkEnd`. The two `_Toc` names are stale entries
    from some earlier table of contents and `_Hlk` is Word's own edit-tracking mark; all three
    point at content this scaffold no longer has, so an end tag placed anywhere would be
    inventing a span rather than restoring one.
    """
    parents = {child: parent for parent in body.iter() for child in parent}
    starts, ends = {}, {}
    for element in body.iter():
        if element.tag == w("bookmarkStart"):
            starts[element.get(w("id"))] = element
        elif element.tag == w("bookmarkEnd"):
            ends[element.get(w("id"))] = element

    dropped = []
    for identifier, element in list(starts.items()):
        if identifier not in ends:
            dropped.append(element.get(w("name")) or f"id {identifier}")
            parents[element].remove(element)
    for identifier, element in list(ends.items()):
        if identifier not in starts:
            dropped.append(f"end of id {identifier}")
            parents[element].remove(element)
    return sorted(dropped)


#: Parts that belong to the content this command cuts out, and must go with it.
#:
#: THE COMMENTS ARE OPTIV'S OWN REVIEW NOTES. The template carries 139 of them, every one
#: anchored in the specimen body - so cutting the body left 139 comments with nothing to point
#: at, riding in every deliverable this generator has built. A client opening the Comments pane
#: would have read an internal drafting conversation. Word drops them when it repairs the file,
#: which is how they were found.
#:
#: THE THUMBNAIL IS A PICTURE OF THE TEMPLATE. `docProps/thumbnail.emf` is the preview an
#: explorer shows, rendered from the document Optiv saved - not from anything this builds - and
#: it is 1.0 MB of the 1.5 MB file. A stale preview of somebody else's document is wrong as
#: well as large.
DROPPED_PARTS = (
    "word/comments.xml",
    "word/commentsExtended.xml",
    "word/commentsIds.xml",
    "word/people.xml",
    "docProps/thumbnail.emf",
)


def without_parts(rels_xml: bytes, dropped: set) -> bytes:
    """The same `.rels`, minus every relationship pointing at a part that is going."""
    root = etree.fromstring(rels_xml)
    for relationship in list(root):
        target = (relationship.get("Target") or "").lstrip("/")
        if target.rsplit("/", 1)[-1] in {part.rsplit("/", 1)[-1] for part in dropped}:
            root.remove(relationship)
    return tostring(root)


def without_overrides(content_types_xml: bytes, dropped: set) -> bytes:
    """The same `[Content_Types].xml`, minus the Override of every part that is going, and with
    the main part declared a document rather than a template."""
    root = etree.fromstring(content_types_xml)
    gone = {"/" + part for part in dropped}
    for override in list(root):
        if override.get("PartName") in gone:
            root.remove(override)
        elif override.get("ContentType", "").endswith(TEMPLATE_CONTENT_TYPE):
            override.set("ContentType",
                         override.get("ContentType").replace(TEMPLATE_CONTENT_TYPE,
                                                             DOCUMENT_CONTENT_TYPE))
    return tostring(root)


def marker_paragraph():
    """The `{{OEA-BODY}}` paragraph, built with the `w` prefix the root already declares.

    lxml resolves a Clark-notation tag against the nsmap of wherever the element lands, so this
    serialises as `w:p` once it is inside the body rather than carrying a declaration of its
    own.
    """
    p = etree.Element(w("p"))
    run = etree.SubElement(p, w("r"))
    etree.SubElement(run, w("t")).text = BODY_MARKER
    return p


class Command(BaseCommand):
    help = "Derive the health-check scaffold from Optiv's .dotx template."

    def add_arguments(self, parser):
        parser.add_argument("template", help="Path to the Optiv .dotx template")
        parser.add_argument("--out", help=f"Where to write it (default: the package's "
                                          f"docx/{SCAFFOLD_NAME})")

    def handle(self, *args, **options):
        source = Path(options["template"]).expanduser()
        if not source.is_file():
            raise CommandError(f"no template at {source}")
        destination = Path(options["out"]) if options.get("out") else (
            Path(__file__).resolve().parents[2] / "docx" / SCAFFOLD_NAME)
        destination.parent.mkdir(parents=True, exist_ok=True)

        archive = zipfile.ZipFile(source)
        root = etree.fromstring(archive.read("word/document.xml"))
        body = root.find(w("body"))
        children = list(body)

        cover_end = section_break_index(children)
        back_cover_start = back_cover_index(children)
        sectpr = body.find(w("sectPr"))
        if sectpr is None:
            raise CommandError("the template's body has no final sectPr")
        if not 0 < cover_end < back_cover_start < len(children):
            raise CommandError(
                f"this template does not slice as expected: cover ends at {cover_end}, the back "
                f"cover starts at {back_cover_start}, and the body has {len(children)} children")

        kept = children[:cover_end + 1] + children[back_cover_start:]
        dropped = len(children) - len(kept)
        for child in children:
            body.remove(child)
        for child in kept[:cover_end + 1]:
            body.append(child)
        body.append(marker_paragraph())
        for child in kept[cover_end + 1:]:
            body.append(child)
        orphans = close_orphaned_bookmarks(body)

        # UPDATE FIELDS WHEN WORD OPENS IT. The table of contents is a field, and a generated
        # document has no page numbers until Word lays it out - so the build emits the field
        # empty and this makes Word fill it. Set on the scaffold rather than per build: it is a
        # property of the file's shape, not of its content.
        settings = etree.fromstring(archive.read("word/settings.xml"))
        if settings.find(w("updateFields")) is None:
            element = etree.Element(w("updateFields"))
            element.set(w("val"), "true")
            settings.insert(0, element)

        temporary = destination.with_suffix(".partial")
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as out:
            for item in archive.infolist():
                # Word leaves a `[trash]` part behind after some edits; it is not referenced by
                # any relationship and carries whatever was deleted last.
                if item.filename.startswith("[trash]"):
                    continue
                if item.filename in DROPPED_PARTS:
                    continue
                data = archive.read(item.filename)
                if item.filename == "word/document.xml":
                    data = tostring(root)
                elif item.filename == "word/settings.xml":
                    data = tostring(settings)
                elif item.filename == "[Content_Types].xml":
                    data = without_overrides(data, set(DROPPED_PARTS))
                elif item.filename.endswith(".rels"):
                    data = without_parts(data, set(DROPPED_PARTS))
                out.writestr(item, data)
        shutil.move(temporary, destination)

        self.stdout.write(
            f"{destination}\n"
            f"  kept the cover (0-{cover_end}) and the back cover "
            f"({back_cover_start}-{len(children) - 1})\n"
            f"  dropped {dropped} body children, and put {BODY_MARKER} in their place\n"
            f"  closed {len(orphans)} bookmarks the cut left half of"
            + (f": {', '.join(orphans)}\n" if orphans else "\n")
            + f"  dropped {len(DROPPED_PARTS)} parts that belonged to the cut body: "
              f"{', '.join(DROPPED_PARTS)}\n"
            + f"  {len(archive.namelist())} parts in, "
              f"{len(zipfile.ZipFile(destination).namelist())} out")
