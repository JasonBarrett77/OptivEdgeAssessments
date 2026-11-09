"""The PAN Health Check document - the third deliverable, generated into Optiv's own template.

Jason, 2026-11-05: *"I'm wary of using the .dotx, because modifying something in place comes
with its own challenges. If possible, I'd rather copy the style visually, build our own partials
that can easily be generated from the data, and create a new .docx file every time."* And then:
*"Go with the scaffold approach."*

So these tests check three things, and the second is the one that makes the whole shape safe:

* that the document builds on an empty estate and on a seeded one, and says what it contains
* that the FILE it produces is a valid document in Optiv's styles - every `pStyle` and
  `tblStyle` it references exists in the scaffold's own `styles.xml` and is of the right kind,
  every table row spans its grid, the marker is gone, the cover's placeholders are substituted,
  the captions number without gaps, and the media, headers, footers and final `sectPr` survive
* that the Area mapping is honest: a control id that is not in the catalog stops the build, an
  Area with no controls is never graded, and no active control is silently left off the spine

They read the OUTPUT rather than what built it, for the reason `test_remediation_workbook`
reads the workbook's own table XML: a generator that agrees with itself and disagrees with Word
is exactly the failure a test over the builder's return value cannot see.
"""

from __future__ import annotations

import datetime as dt
import io
import re
import zipfile
from unittest import mock
from xml.etree import ElementTree as ET

from django.test import SimpleTestCase, TestCase

from docx.oxml.ns import qn

from assessments.artifacts import (
    ArtifactBuildError, build_health_check_document, build_remediation_workbook, build_workbook,
    health_check_filename)
from assessments.artifacts import health_check
from assessments.artifacts.docx import partials, scaffold as scaffold_module
from assessments.finding_run import regenerate_findings
import collections

from assessments.control_queries import SEVERITY_RANK
from assessments.finding_registry import FINDING_KINDS
from assessments.models import Control, ControlQuery
from assessments.tests._seed import seed_controls, seed_specs
from assessments.tests.test_artifacts import sheet_names
from assessments.tests.test_findings_views import build_estate
from optivedge.models import ApplicationEnvironment

from django.contrib.contenttypes.models import ContentType

from optivedge_integrations.integrations.models import (
    Appliance, DeviceGroup, FieldProvenance, ManagementStation)

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
DOCX_MAGIC = b"PK"


def w(tag: str) -> str:
    return f"{{{W}}}{tag}"


def document_xml(content: bytes):
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        return ET.fromstring(archive.read("word/document.xml"))


def all_text(content: bytes) -> str:
    return "".join(node.text or "" for node in document_xml(content).iter(w("t")))


def _text(node) -> str:
    return "".join(child.text or "" for child in node.iter(w("t")))


def style_of(paragraph):
    """The paragraph's style id, or None - which is how the generated paragraphs are found."""
    properties = paragraph.find(w("pPr"))
    style = properties.find(w("pStyle")) if properties is not None else None
    return style.get(w("val")) if style is not None else None


def _names_the_face(properties) -> bool:
    fonts = properties.find(w("rFonts")) if properties is not None else None
    return fonts is not None and fonts.get(w("ascii")) == partials.BODY_FONT


def generated_paragraphs(body) -> list:
    """The paragraphs THIS GENERATOR wrote, told apart by their style.

    Optiv's cover and back cover are carried over verbatim and must not be rewritten - "nothing
    is modified in place" - and they use ten styles of their own (`Cover-Title`,
    `BackCover-Text`, `Footer` and so on), not one of which is in
    `partials.EMITTED_PARAGRAPH_STYLES`. So the style says who wrote the paragraph, and a test
    over the output can hold this generator to a contract without claiming anything about the
    template's own pages.
    """
    emitted = set(partials.EMITTED_PARAGRAPH_STYLES)
    found = []
    for para in body.iter(w("p")):
        style = style_of(para)
        if style not in emitted:
            continue
        # THE STYLES BOTH SIDES USE. The scaffold's own body carries an empty `TOC3` paragraph,
        # so a contents style alone does not say who wrote the line - a generated entry is the
        # one with a link in it. See `partials.table_of_contents`.
        if style in partials.TOC_ENTRIES and para.find(w("hyperlink")) is None:
            continue
        found.append(para)
    return found


def _text_of_cell(cell) -> str:
    """The text of one `partials.Cell`, across its paragraphs."""
    return " ".join(_text(paragraph) for paragraph in cell.paragraphs).strip()


def heading_texts(body) -> list:
    """The generated headings, in the order the document reaches them - its outline.

    TEXT ORDER IS NO LONGER THE OUTLINE. The contents page names every heading before the
    document arrives at any of them, so `all_text` holds each one twice and the first of the
    two is on page two. A test about where a section SITS has to read the headings.
    """
    return [_text(paragraph) for paragraph in body.iter(w("p"))
            if style_of(paragraph) in partials.HEADING_LEVELS]


def contents_entries(body) -> list:
    """The contents lines this build wrote, in order.

    TOLD APART BY THE LINK, not by the style alone: the scaffold's own body carries an empty
    `TOC3` paragraph, and it comes first in the file.
    """
    return [paragraph for paragraph in body.iter(w("p"))
            if style_of(paragraph) in partials.TOC_ENTRIES
            and paragraph.find(w("hyperlink")) is not None]


def heading_at(headings: list, text: str) -> int:
    """Where the first heading naming `text` sits, so a test can state an order without
    depending on a heading's exact wording."""
    for index, heading in enumerate(headings):
        if text in heading:
            return index
    raise AssertionError(f"no heading names {text!r} - found {headings}")


def spanned_columns(row) -> int:
    """How many grid columns one row covers, counting a `gridSpan` cell as the columns it
    spans - which is how `DocumentStructureTests` holds every table to its own grid."""
    spanned = 0
    for cell in row.findall(w("tc")):
        properties = cell.find(w("tcPr"))
        span = properties.find(w("gridSpan")) if properties is not None else None
        spanned += int(span.get(w("val"))) if span is not None else 1
    return spanned


def unnamed_runs(body) -> list:
    """The text of every generated run carrying text that does NOT name `partials.BODY_FONT`."""
    found = []
    for para in generated_paragraphs(body):
        for run in para.iter(w("r")):
            if not _text(run):
                continue            # a field character carries no text and needs no face
            if not _names_the_face(run.find(w("rPr"))):
                found.append(_text(run)[:40])
    return sorted(found)


def unnamed_marks(body) -> list:
    """The text of every generated paragraph whose MARK does not name `partials.BODY_FONT`."""
    found = []
    for para in generated_paragraphs(body):
        properties = para.find(w("pPr"))
        if not _names_the_face(properties.find(w("rPr"))):
            found.append(_text(para)[:40])
    return sorted(found)


def ignorable_and_declared(content: bytes) -> tuple:
    """`(prefixes mc:Ignorable names, prefixes the root declares)` for `word/document.xml`."""
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        head = archive.read("word/document.xml")[:8000].decode("utf-8", "replace")
    start = re.search(r"<w:document\b[^>]*>", head, re.S).group(0)
    ignorable = re.search(r'mc:Ignorable="([^"]*)"', start)
    return ((ignorable.group(1).split() if ignorable else []),
            set(re.findall(r"xmlns:([A-Za-z0-9_]+)=", start)))


def bookmark_ids(body) -> tuple:
    """`(ids that open, ids that close)` for one body, as sorted lists.

    A bookmark whose other half is missing is the one defect in this file that nothing short of
    Word notices - see `ScaffoldTests.test_every_bookmark_in_the_scaffold_pairs_up`.
    """
    starts = sorted(element.get(w("id")) for element in body.iter(w("bookmarkStart")))
    ends = sorted(element.get(w("id")) for element in body.iter(w("bookmarkEnd")))
    return starts, ends


def parts(content: bytes) -> list:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        return archive.namelist()


def scaffold_styles() -> dict:
    """{style id: its type}, read off the committed scaffold."""
    with zipfile.ZipFile(scaffold_module.SCAFFOLD_PATH) as archive:
        root = ET.fromstring(archive.read("word/styles.xml"))
    return {element.get(w("styleId")): element.get(w("type"))
            for element in root.findall(w("style"))}


class StyleContractTests(SimpleTestCase):
    """The style ids are the contract with Optiv's template, so they are checked against the
    file rather than trusted - and a scaffold that lost one has to fail loudly rather than fall
    back to Normal, because a `Rating - Critical` cell without its style is a critical finding
    rendered as body text on a page a client reads."""

    def test_every_style_the_partials_can_emit_is_in_the_scaffold(self):
        styles = scaffold_styles()

        for name in partials.EMITTED_PARAGRAPH_STYLES:
            with self.subTest(name):
                self.assertEqual(styles.get(name), "paragraph")
        for name in partials.EMITTED_TABLE_STYLES:
            with self.subTest(name):
                self.assertEqual(styles.get(name), "table")

    def test_a_paragraph_names_its_typeface_on_the_run_and_on_the_mark(self):
        """The contract itself, asserted where it is made. The two tests over the built document
        count what this one pins exactly."""
        element = partials.paragraph(partials.HEADING_2, "PAN Firewall(s)")

        run_fonts = element.find(w("r")).find(w("rPr")).find(w("rFonts"))
        mark_fonts = element.find(w("pPr")).find(w("rPr")).find(w("rFonts"))

        self.assertEqual(run_fonts.get(w("ascii")), partials.BODY_FONT)
        self.assertEqual(run_fonts.get(w("hAnsi")), partials.BODY_FONT)
        self.assertEqual(mark_fonts.get(w("ascii")), partials.BODY_FONT)

    def test_the_bold_lead_still_comes_after_the_typeface(self):
        """`w:rPr` is a sequence and `w:rFonts` comes before `w:b`. Out of order, Word reports
        unreadable content - the same class of defect as P545."""
        element = partials.paragraph(partials.TABLE_TEXT, "Administrator authentication",
                                     bold=True)

        children = [child.tag.split("}")[1]
                    for child in element.find(w("r")).find(w("rPr"))]

        self.assertEqual(children, ["rFonts", "b"])

    def test_a_paragraph_that_opens_with_a_label_carries_two_runs(self):
        """`Where to confirm it.` is bold and the path after it is not, in one paragraph - the
        shape the Control Detail mock-up agreed on 2026-11-06. Both runs name the typeface, and
        the space between them belongs to the second so the bold stops at the label."""
        element = partials.lead_paragraph(partials.NORMAL, "Where to confirm it.",
                                          "Device > Server Profiles > LDAP.")

        runs = element.findall(w("r"))
        self.assertEqual(len(runs), 2)
        self.assertIsNotNone(runs[0].find(w("rPr")).find(w("b")))
        self.assertIsNone(runs[1].find(w("rPr")).find(w("b")))
        self.assertEqual(_text(runs[1]), " Device > Server Profiles > LDAP.")
        for run in runs:
            self.assertEqual(run.find(w("rPr")).find(w("rFonts")).get(w("ascii")),
                             partials.BODY_FONT)

    def test_no_style_constant_is_left_out_of_the_emitted_lists(self):
        """`EMITTED_PARAGRAPH_STYLES` is what the scaffold guard checks, and it is written out
        by hand. A style constant added to `partials` and forgotten there is exactly the one the
        guard would not notice, and it would fall back to Normal on a client's page.

        Any module-level constant whose value is a style id in Optiv's own styles.xml is a style
        this module can emit, so it has to appear in one of the two lists.
        """
        known = set(partials.EMITTED_PARAGRAPH_STYLES) | set(partials.EMITTED_TABLE_STYLES)
        in_the_scaffold = scaffold_styles()

        for name, value in vars(partials).items():
            if not name.isupper() or not isinstance(value, str):
                continue
            if value not in in_the_scaffold:
                continue
            with self.subTest(f"{name} = {value}"):
                self.assertIn(value, known)

    def test_a_scaffold_missing_a_style_is_refused(self):
        styles = {name: "paragraph" for name in partials.EMITTED_PARAGRAPH_STYLES}
        styles[partials.TABLE_STYLE] = "table"
        del styles[partials.RATING_STYLES["critical"]]

        with self.assertRaises(ArtifactBuildError) as caught:
            scaffold_module.check_styles(styles)

        self.assertIn("Rating-Critical", str(caught.exception))

    def test_a_style_of_the_wrong_kind_is_refused(self):
        """A `w:pStyle` naming a table style is not an error Word reports - it ignores it, which
        is the silent fallback this guard exists to prevent."""
        styles = {name: "paragraph" for name in partials.EMITTED_PARAGRAPH_STYLES}
        styles[partials.TABLE_STYLE] = "paragraph"

        with self.assertRaises(ArtifactBuildError) as caught:
            scaffold_module.check_styles(styles)

        self.assertIn("OptivLightGreyBorders is a paragraph style", str(caught.exception))

    def test_a_severity_the_catalogue_grows_is_not_quietly_graded_informational(self):
        """`rating_style` raises rather than falling back: grading an unknown severity
        Informational would print a pass over a finding."""
        with self.assertRaises(KeyError):
            partials.rating_style("catastrophic")

    def test_every_catalogue_severity_has_a_rating_style(self):
        """Jason, 2026-11-05: *"We are not going to use 'No Deviation' for now. that can be
        replaced with Informational."* With D-5 retired the template's five grades are 1:1 with
        the catalog's five severities."""
        self.assertEqual(set(partials.RATING_STYLES), set(Control.Severity.values))


class SubjectTests(TestCase):
    """The observation table's headings, which are DERIVED rather than mapped.

    They replaced a 594-line file in which every control was assigned to one of 24 hand-written
    Areas, with three guards whose only job was to notice when somebody forgot. Jason,
    2026-11-06: *"We should seek to minimize any statically set data and instead generate the
    data from the control and finding information."* The grouping is `FindingKind.common_name`,
    joined to the control by `control_type`, so nothing has to be kept in step by hand - which
    is what these tests hold.
    """

    def test_every_active_control_has_an_object_name(self):
        """The join is what makes the grouping total. A control whose type no finding kind
        claims would have no heading to sit under, so it would silently vanish from the client's
        document rather than appear in the wrong place."""
        seed_controls(list(seed_specs()))
        kinds = {kind.control_type for kind in FINDING_KINDS}

        unnamed = sorted(control.control_id
                         for control in Control.objects.filter(is_active=True)
                         if control.control_type not in kinds)

        self.assertEqual(unnamed, [])

    def test_a_control_no_finding_kind_claims_stops_the_build(self):
        seed_controls(["PAN-MGT-007"])
        Control.objects.update(control_type="no_such_type")

        with self.assertRaises(ArtifactBuildError) as caught:
            health_check.read_control_detail(health_check.measure())

        self.assertIn("PAN-MGT-007", str(caught.exception))
        self.assertIn("finding_registry", str(caught.exception))

    def test_several_finding_kinds_share_one_object_name(self):
        """The common name is COARSER than the per-kind label, which is the whole reason it is a
        second field: a gateway, its agent configuration and its authentication rows are one
        thing to the person reading the report."""
        folded = collections.Counter(kind.common_name for kind in FINDING_KINDS)

        self.assertGreater(folded["GlobalProtect Gateway"], 1)
        self.assertEqual(len({kind.label for kind in FINDING_KINDS}), len(FINDING_KINDS))

    def test_every_kind_names_its_object_for_a_client(self):
        """A kind added tomorrow cannot reach a client document without a name, because the
        field is required - this checks the names are written the way the table prints them."""
        for kind in FINDING_KINDS:
            with self.subTest(kind.label):
                self.assertTrue(kind.common_name.strip())
                self.assertTrue(kind.common_name[0].isupper(),
                                f"{kind.common_name!r} should read as a heading")
                self.assertFalse(kind.common_name.endswith("."))


class FilenameTests(SimpleTestCase):
    def test_it_is_named_for_the_deliverable_and_is_a_docx(self):
        self.assertEqual(health_check_filename(today=dt.date(2026, 11, 5)),
                         "health-check-2026-11-05.docx")


class EmptyEstateTests(TestCase):
    """A fresh deployment, or one whose collection has not run. The document still builds, which
    is what `WorkbookBuildTests.test_it_builds_on_an_estate_with_nothing_in_it` asks of the
    findings workbook - and here it matters more, because the first thing a consultant does with
    a new engagement is look at the shape of the deliverable."""

    def test_it_builds_with_nothing_in_the_database(self):
        content, reports = build_health_check_document(today=dt.date(2026, 11, 5))

        self.assertEqual(content[:2], DOCX_MAGIC)
        self.assertIn("Detailed Findings and Recommendations", " ".join(reports))

    def test_an_estate_with_no_devices_says_so_rather_than_leaving_the_scope_blank(self):
        text = all_text(build_health_check_document()[0])

        self.assertIn("Firewall(s): none were collected.", text)
        self.assertIn("Panorama(s): none were collected.", text)
        self.assertIn("Device group(s): none were collected.", text)
        self.assertIn("Template(s): none are named in the configuration collected.", text)

    def test_with_no_panorama_container_the_methodology_says_so_rather_than_printing_a_header(self):
        """A standalone pair of firewalls is a real estate, and a table of nothing but its own
        header row under a caption is the shape that makes a reader doubt the rest."""
        text = all_text(build_health_check_document()[0])

        self.assertIn("No setting read in this review was defined in a Panorama container",
                      text)
        self.assertNotIn("Panorama Containers", text)

    def test_with_no_environment_the_cover_asks_for_the_clients_name(self):
        """A deployment without an `ApplicationEnvironment` is a real state - the lab spends its
        first minutes in it - and `naming.workbook_filename` already declines to refuse a
        download over it. A client document cannot leave the cover blank, so it says so."""
        text = all_text(build_health_check_document()[0])

        self.assertIn("MANUAL: set the client's long name", text)

    def test_nothing_at_all_is_graded_with_no_catalogue(self):
        """With no catalog, nothing has been assessed - and nothing is graded. Informational
        would be a pass on a question nobody asked, which is the one thing a health check must
        not do. The only Rating-* paragraphs left are the five rows of the legend."""
        root = document_xml(build_health_check_document()[0])

        rating_styles = set(partials.RATING_STYLES.values())
        graded = [
            "".join(node.text or "" for node in para.iter(w("t")))
            for para in root.iter(w("p"))
            if (para.find(w("pPr")) is not None
                and para.find(w("pPr")).find(w("pStyle")) is not None
                and para.find(w("pPr")).find(w("pStyle")).get(w("val")) in rating_styles)]

        self.assertEqual(sorted(graded),
                         ["Critical", "High", "Informational", "Low", "Medium"])

    def test_the_executive_summary_says_nothing_was_assessed_rather_than_no_findings(self):
        """"No findings were identified in the configuration reviewed" over an estate with no
        controls applied is true and reads as a pass - it is the sentence a client would quote
        back."""
        text = all_text(build_health_check_document()[0])

        self.assertIn("No controls are active in this deployment's catalog", text)
        self.assertNotIn("No findings were identified in the configuration reviewed", text)


class ContainerTests(TestCase):
    """The Panorama containers in Scope and under Approach/Methodology.

    Jason, 2026-11-06: *"If we have information about the device groups and templates from
    provenance, that information can be included in the document's sections that talk about
    scope, methodology, or summarize locations of findings."*

    The estate is built by hand here rather than taken from `build_estate`, because what these
    rows have to survive is the gap between the two sources: Panorama returns a container named
    `Shared` and the values it holds are marked `shared`, a device group can exist and have
    pushed nothing, and a template is never collected at all.
    """

    @classmethod
    def setUpTestData(cls):
        station = ManagementStation.objects.create(name="pano-1",
                                                   hostname="pano-1.example.test")
        shared = DeviceGroup.objects.create(management_station=station, name="Shared",
                                            is_shared=True)
        parent = DeviceGroup.objects.create(management_station=station, name="dg_core",
                                            parent=shared)
        DeviceGroup.objects.create(management_station=station, name="dg_edge", parent=parent)
        DeviceGroup.objects.create(management_station=station, name="dg_empty", parent=shared)

        profile = ContentType.objects.get_for_model(Appliance)
        other = ContentType.objects.get_for_model(ManagementStation)
        marks = [
            # Shared carries FOUR marks over THREE objects under TWO ids, so the right answer
            # tells the two wrong ones apart: counting rows gives 4 and counting ids gives 2.
            # Two fields of ONE object.
            (profile, 1, "a", "device_group", "shared"),
            (profile, 1, "b", "device_group", "shared"),
            # The same object id on a DIFFERENT model.
            (other, 1, "a", "device_group", "shared"),
            (profile, 9, "a", "device_group", "shared"),
            (profile, 2, "a", "device_group", "dg_core"),
            (profile, 3, "a", "template", "tpl_base"),
            (profile, 4, "a", "template", "tpl_base"),
            # A device group the hierarchy never returned.
            (profile, 5, "a", "device_group", "dg_unknown"),
        ]
        for content_type, object_id, field, provenance_type, value in marks:
            FieldProvenance.objects.create(
                content_type=content_type, object_id=object_id, field_name=field,
                provenance_type=provenance_type,
                raw_key="@loc" if provenance_type == "device_group" else "@ptpl",
                raw_value=value)

    def built(self) -> str:
        return all_text(build_health_check_document(today=dt.date(2026, 11, 6))[0])

    def rows(self) -> dict:
        return {container.name: container for container in health_check.read_containers()[0]}

    def test_the_scope_names_every_device_group_and_every_template(self):
        """The Scope section is the first thing a client checks their own estate against, so a
        container left out of it is the deliverable understating what was reviewed."""
        text = self.built()

        self.assertIn("Device group(s): dg_core, dg_edge, dg_empty, dg_unknown", text)
        self.assertIn("Template(s): tpl_base", text)

    def test_shared_is_not_in_the_device_group_bullet_and_is_in_the_table(self):
        """Panorama presents Shared as a container and it is not a device group. Listing it
        among them would be a name a client cannot find in their own Device Groups tab."""
        text = self.built()

        self.assertNotIn("Device group(s): Shared", text)
        self.assertEqual(self.rows()["Shared"].kind, "Shared")

    def test_shared_is_one_container_although_the_two_sources_spell_it_differently(self):
        """The one real trap. `show dg-hierarchy` is synthesised into a row named `Shared` and
        every value it holds is marked `shared`; matching those literally files the Shared-held
        objects under a second container nobody has, and leaves the real row reading zero."""
        rows = self.rows()

        self.assertNotIn("shared", rows)
        self.assertEqual(rows["Shared"].objects, 3)


    def test_an_object_is_counted_once_however_many_of_its_fields_are_marked(self):
        """Counting provenance rows would rank a container by how many columns its objects carry,
        which is a number about the schema rather than about the estate. Shared holds four marks
        over three objects, so the row count would read 4."""
        rows = self.rows()

        self.assertEqual(rows["Shared"].objects, 3)
        self.assertEqual(rows["dg_core"].objects, 1)

    def test_the_same_id_on_two_models_is_two_objects(self):
        """`object_id` is unique per model, not globally. Shared's three objects sit under two
        ids, so counting ids alone would read 2."""
        self.assertEqual(self.rows()["Shared"].objects, 3)

    def test_a_group_that_has_pushed_nothing_is_still_in_scope_and_says_so(self):
        """`DeviceGroupBinding`: "a group that has pushed nothing this collection reached has no
        bindings and is still a real group". Printing 0 would read as a group holding nothing."""
        text = self.built()

        self.assertEqual(self.rows()["dg_empty"].objects, 0)
        self.assertIn("none in this collection", text)

    def test_a_container_named_only_in_the_configuration_is_still_printed(self):
        """A deployment whose Panorama was never collected has the markers and no hierarchy, and
        dropping those rows would have the document claim a managed estate has no containers."""
        rows = self.rows()

        self.assertEqual(rows["dg_unknown"].kind, "Device group")
        self.assertEqual(rows["dg_unknown"].within, health_check.NO_PARENT)
        self.assertIn("dg_unknown", self.built())

    def test_a_device_group_says_what_it_sits_inside(self):
        rows = self.rows()

        self.assertEqual(rows["dg_edge"].within, "dg_core")
        self.assertEqual(rows["dg_core"].within, "Shared")
        self.assertEqual(rows["Shared"].within, health_check.NO_PARENT)

    def test_the_device_groups_are_printed_in_panoramas_own_tree_order(self):
        """Shared, then its children by name, depth first. A flat alphabetical list would put
        `dg_edge` beside `dg_core` rather than under it."""
        names = [container.name for container in health_check.read_containers()[0]
                 if container.kind != "Template"]

        self.assertEqual(names, ["Shared", "dg_core", "dg_edge", "dg_empty", "dg_unknown"])

    def test_the_table_is_captioned_and_the_later_captions_moved_up_with_it(self):
        """The caption numbers are literal, so a table inserted in the middle renumbers every
        one after it - which is the thing a reader of the table of contents would catch."""
        text = self.built()

        self.assertIn("Table 2: Panorama Containers", text)
        self.assertIn("Table 3: Risk Ratings", text)

    def test_it_says_where_the_rows_came_from(self):
        """The strongest claim in the deliverable is the one a client can check on their own
        Panorama, and it is only strong if the document says what it was read from."""
        text = self.built()

        self.assertIn("Every setting read carries a marker naming where it was defined", text)
        self.assertIn("Panorama's template list was not", text)


class _SeededEstate(TestCase):
    """The estate the findings tests build, with findings generated over it."""

    @classmethod
    def setUpTestData(cls):
        build_estate()
        seed_controls(["PAN-MGT-007", "PAN-MGT-001", "PAN-POL-008"])
        regenerate_findings()

    def built(self) -> bytes:
        return build_health_check_document(today=dt.date(2026, 11, 5))[0]


class DocumentStructureTests(_SeededEstate):
    """What the FILE is, read out of the file."""

    def test_the_marker_paragraph_is_gone_and_appears_nowhere(self):
        """A visible sentinel rather than a bookmark, deliberately: a build that failed to
        remove it would say so on the page. Which means a build that DID remove it has to be
        checked, because that is the whole bargain."""
        content = self.built()

        self.assertNotIn(scaffold_module.BODY_MARKER, all_text(content))
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            for name in archive.namelist():
                if name.endswith(".xml"):
                    self.assertNotIn(b"OEA-BODY", archive.read(name), name)

    def test_the_built_document_declares_every_prefix_it_says_may_be_ignored(self):
        """Checked on the OUTPUT too: the scaffold guard covers what a build inherits, and this
        covers python-docx's own re-serialisation of the part on save.

        Read off the BYTES rather than off a parse tree, because the declarations are what Word
        reads and a parser that resolved them has already thrown the question away.
        """
        listed, declared = ignorable_and_declared(self.built())

        self.assertTrue(listed)
        self.assertEqual(sorted(prefix for prefix in listed if prefix not in declared), [])

    def test_every_run_the_document_carries_names_its_typeface(self):
        """Jason, 2026-11-06: *"I'm seeing frequent use of a font I don't recognize, called Tw
        Cen MT (Body)."* Nothing was ever rendered in it - every run resolved to Arial through
        Optiv's `w:docDefaults` - but two of the four font slots in those defaults are linked to
        the theme, whose minor font is Tw Cen MT, and Word's font box names the theme rather
        than the face. Naming the face on the run is what makes the box agree with the page.

        SCOPED TO WHAT THIS GENERATOR WROTE, because Optiv's cover and back cover are carried
        over verbatim and must not be rewritten - "nothing is modified in place". The paragraph
        style is what tells them apart; see `generated_paragraphs`.
        """
        root = document_xml(self.built())

        self.assertTrue(generated_paragraphs(root))
        self.assertEqual(unnamed_runs(root), [])

    def test_the_paragraph_mark_names_it_too(self):
        """Word reports the mark's formatting when the caret is at the end of a line, and an
        empty `Screenshot` paragraph is nothing but its mark. Measured against the scaffold for
        the reason above."""
        root = document_xml(self.built())

        self.assertTrue(generated_paragraphs(root))
        self.assertEqual(unnamed_marks(root), [])

    def test_every_bookmark_in_the_built_document_pairs_up(self):
        """Checked on the OUTPUT as well as on the scaffold: the scaffold guard covers what this
        build inherited, and this covers anything a section writes from now on."""
        root = document_xml(self.built())

        starts, ends = bookmark_ids(root.find(w("body")))

        self.assertEqual(starts, ends)

    def test_every_style_the_output_references_exists_and_is_of_the_right_kind(self):
        """Read off the OUTPUT, not off the list of styles the partials can emit: a section that
        writes a `pStyle` directly tomorrow is covered by this and not by that."""
        root = document_xml(self.built())
        styles = scaffold_styles()

        for element in root.iter(w("pStyle")):
            with self.subTest(element.get(w("val"))):
                self.assertEqual(styles.get(element.get(w("val"))), "paragraph")
        for element in root.iter(w("tblStyle")):
            with self.subTest(element.get(w("val"))):
                self.assertEqual(styles.get(element.get(w("val"))), "table")

    def test_the_covers_three_placeholders_are_substituted_and_none_remains(self):
        ApplicationEnvironment.objects.create(
            client_name="Acme Corporation", client_short_name="Acme",
            opportunity_number="OP-1234567")

        text = all_text(self.built())

        self.assertIn("Acme Corporation", text)
        self.assertIn("Opportunity Number: OP-1234567", text)
        for placeholder in (scaffold_module.COVER_CLIENT, scaffold_module.COVER_OPPORTUNITY,
                            scaffold_module.COVER_REVISION, scaffold_module.SHORTNAME):
            self.assertNotIn(placeholder, text)

    def test_the_opportunity_number_is_not_doubly_prefixed(self):
        """The template's cover run already reads `Opportunity Number: OP-[op_number]`, and the
        stored value is `OP-1234567`."""
        ApplicationEnvironment.objects.create(
            client_name="Acme Corporation", client_short_name="Acme",
            opportunity_number="OP-1234567")

        self.assertNotIn("OP-OP-", all_text(self.built()))

    def test_captions_are_numbered_from_one_with_no_gaps(self):
        """Literal numbers rather than `SEQ` fields: the document is generated whole, so the
        numbers are known, and a literal number is right even for a reader who never refreshes
        fields."""
        text = all_text(self.built())

        tables = [int(number) for number in re.findall(r"Table (\d+):", text)]
        figures = [int(number) for number in re.findall(r"Figure (\d+):", text)]

        self.assertEqual(tables, list(range(1, len(tables) + 1)))
        self.assertGreater(len(tables), 5)
        # NO FIGURES. The only ones were the screenshot frames under the rulebase tables, and
        # those went when the tables did (Jason, 2026-11-06). The numbering still has to be
        # gapless if a section ever emits one, which is what the first assertion says.
        self.assertEqual(figures, list(range(1, len(figures) + 1)))

    def test_the_caption_counters_advance_in_document_order(self):
        """Two counters, advanced as the body is written, so a section that emits a table and
        then a figure numbers both without knowing where it sits."""
        root = document_xml(self.built())
        seen = {"Table": 0, "Figure": 0}

        for para in root.iter(w("p")):
            properties = para.find(w("pPr"))
            style = properties.find(w("pStyle")) if properties is not None else None
            if style is None or style.get(w("val")) != partials.CAPTION:
                continue
            kind, number = "".join(
                node.text or "" for node in para.iter(w("t"))).split(":")[0].split(" ")
            seen[kind] += 1
            self.assertEqual(int(number), seen[kind])

    def test_a_rating_cell_carries_the_style_for_the_severity_in_it(self):
        root = document_xml(self.built())
        by_style = {style: word for style, word in
                    ((partials.RATING_STYLES[value], Control.Severity(value).label)
                     for value in Control.Severity.values)}
        checked = 0

        for para in root.iter(w("p")):
            properties = para.find(w("pPr"))
            style = properties.find(w("pStyle")) if properties is not None else None
            name = style.get(w("val")) if style is not None else None
            if name in by_style:
                checked += 1
                self.assertEqual("".join(node.text or "" for node in para.iter(w("t"))),
                                 by_style[name])
        self.assertGreater(checked, 5)

    def test_an_ungraded_row_carries_no_rating_style(self):
        """A row nobody has graded must not look graded. Grading it would print a verdict over
        a question nobody answered, which is the one thing a health check must not do.

        The surviving instance is the Process Observations table, whose five rows are interview
        findings a consultant writes: each carries `[MANUAL: grade]` where a severity would go.
        The rulebase tables used to contribute "Not assessed" rows of their own and no longer
        exist.
        """
        root = document_xml(self.built())
        rating_styles = set(partials.RATING_STYLES.values())
        ungraded = 0

        for para in root.iter(w("p")):
            text = _text(para)
            if "[MANUAL: grade]" not in text:
                continue
            ungraded += 1
            properties = para.find(w("pPr"))
            style = properties.find(w("pStyle")) if properties is not None else None
            self.assertNotIn(style.get(w("val")), rating_styles)
        self.assertEqual(ungraded, 5)

    def test_the_media_headers_footers_and_the_single_final_sectpr_survive(self):
        """The scaffold's whole reason for existing: 74 parts, Optiv's theme, 15 media files
        including the cover artwork as EMF, five headers and four footers. A build that lost the
        covers would look nearly right."""
        content = self.built()
        with zipfile.ZipFile(scaffold_module.SCAFFOLD_PATH) as donor:
            expected = sorted(name for name in donor.namelist()
                              if name.startswith("word/media/"))
            donor_parts = len(donor.namelist())
            media = {name: donor.read(name) for name in expected}

        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            self.assertEqual(sorted(name for name in archive.namelist()
                                    if name.startswith("word/media/")), expected)
            for name, data in media.items():
                self.assertEqual(archive.read(name), data, name)
            self.assertEqual(len(archive.namelist()), donor_parts)
            for name in ("word/header1.xml", "word/header5.xml", "word/footer1.xml",
                         "word/footer4.xml", "word/theme/theme1.xml", "word/numbering.xml"):
                self.assertIn(name, archive.namelist())
            # `updateFields` is the one setting a build takes OUT - see FieldTests.
            self.assertNotIn(b"updateFields", archive.read("word/settings.xml"))

        body = document_xml(content).find(w("body"))
        self.assertEqual(len([child for child in body if child.tag == w("sectPr")]), 1)
        self.assertEqual(body[-1].tag, w("sectPr"))
        # The cover's own section break, which is what gives it its own header.
        inline = [child for child in body
                  if child.tag == w("p") and child.find(w("pPr")) is not None
                  and child.find(w("pPr")).find(w("sectPr")) is not None]
        self.assertEqual(len(inline), 1)

    def test_word_is_not_asked_to_update_the_fields_when_the_file_opens(self):
        """Jason, 2026-11-07, opening the deliverable: *"after I click 'Enable Editing' in Word,
        I get a message: 'This document contains fields that may refer to other files. Do you
        want to update the fields in this document?'"*

        The prompt is `<w:updateFields w:val="true"/>`, inherited from Optiv's template. Word
        words it that way for any document that asks, and nothing in this one refers to another
        file.
        """
        content = self.built()

        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            settings = archive.read("word/settings.xml").decode("utf-8")
        self.assertNotIn("updateFields", settings)

    def test_the_only_field_left_in_the_body_is_the_table_of_contents(self):
        """A `DATE` field is the day the document is OPENED, so a cover carrying one says it was
        issued whenever the client got round to reading it - and the cached result underneath it
        is the day Optiv last saved the template. The build knows the date, so it writes it.

        The table of contents keeps its field because page numbers do not exist until Word lays
        the document out. There is nothing else left to recalculate.
        """
        content = self.built()
        body = document_xml(content).find(w("body"))

        instructions = [node.text for node in body.iter(w("instrText"))]
        self.assertEqual([text.strip() for text in instructions],
                         ['TOC \\o "1-3" \\h \\z \\u'])

    def test_no_field_is_marked_dirty(self):
        """Jason, 2026-11-07, on the first attempt at this - `updateFields` out and the TOC
        field marked dirty instead: *"It asks, but it asks when opening the file now instead of
        enable editing. It also takes longer for word to open the new file."*

        A field Word has to update as the file opens is the prompt, however it is flagged. So
        the contents are written out and nothing is left dirty.
        """
        body = document_xml(self.built()).find(w("body"))

        dirty = [marker for marker in body.iter(w("fldChar"))
                 if marker.get(w("dirty")) == "true"]
        self.assertEqual(dirty, [])

    def test_the_table_of_contents_lists_every_heading_and_links_to_it(self):
        """What replaces the update: the entries, written by the build. Each one is a link to a
        bookmark on the heading it names, so the contents page works on open."""
        body = document_xml(self.built()).find(w("body"))

        entries = contents_entries(body)
        self.assertEqual(len(entries), len(heading_texts(body)))
        self.assertGreater(len(entries), 20)

        bookmarks = {node.get(w("name")) for node in body.iter(w("bookmarkStart"))}
        for entry in entries:
            link = entry.find(w("hyperlink"))
            self.assertIsNotNone(link)
            self.assertIn(link.get(w("anchor")), bookmarks)

    def test_the_field_opens_in_the_first_entry_and_closes_in_the_last(self):
        """Where Word puts a TOC field's own runs: a contents list is the field's result, so the
        field cannot sit in a paragraph beside it. Update Field has to replace all of it."""
        body = document_xml(self.built()).find(w("body"))
        entries = contents_entries(body)

        def chars(paragraph):
            return [node.get(w("fldCharType")) for node in paragraph.iter(w("fldChar"))]

        self.assertEqual(chars(entries[0]), ["begin", "separate"])
        self.assertEqual(chars(entries[-1]), ["end"])
        for entry in entries[1:-1]:
            self.assertEqual(chars(entry), [])

    def test_an_appendix_entry_carries_the_prefix_its_numbering_prints(self):
        """`Heading1-AppendixList` prints `Appendix A: ` from its numbering, so the heading's
        own text is the bare name. An entry copying that text would read `Reports` where the
        page reads `Appendix A: Reports`."""
        body = document_xml(self.built()).find(w("body"))
        entries = [_text(paragraph) for paragraph in contents_entries(body)]

        appendices = [entry for entry in entries if entry.startswith("Appendix ")]
        self.assertGreater(len(appendices), 1)
        self.assertEqual([entry[:11] for entry in appendices],
                         [f"Appendix {chr(ord('A') + i)}:" for i in range(len(appendices))])

    def test_the_cover_carries_the_date_the_document_was_built(self):
        """The date the template asked Word for, written by the build instead - and the same
        date the Version Control section states, rather than one that disagrees with it."""
        content = build_health_check_document(today=dt.date(2026, 11, 5))[0]

        text = all_text(content)
        self.assertIn("November 5, 2026", text)
        self.assertNotIn("February 4, 2026", text)

    def test_a_scaffold_whose_dates_have_moved_refuses_the_build(self):
        """The guard the rest of this module's checks are built on: a reissued template that
        moved or renamed a date field must fail loudly rather than leave a template date on a
        client's cover."""
        with mock.patch.object(scaffold_module, "FROZEN_DATE_FIELDS", 4):
            with self.assertRaises(ArtifactBuildError) as raised:
                build_health_check_document(today=dt.date(2026, 11, 5))

        self.assertIn("DATE", str(raised.exception))
        self.assertIn("3", str(raised.exception))

    def test_every_table_row_spans_exactly_its_grid(self):
        """A row whose cells span more or fewer columns than the grid is a document Word offers
        to repair rather than open, and nothing in the build would notice."""
        for table in document_xml(self.built()).iter(w("tbl")):
            columns = len(table.find(w("tblGrid")).findall(w("gridCol")))
            for index, row in enumerate(table.findall(w("tr"))):
                spanned = 0
                for cell in row.findall(w("tc")):
                    properties = cell.find(w("tcPr"))
                    span = (properties.find(w("gridSpan"))
                            if properties is not None else None)
                    spanned += int(span.get(w("val"))) if span is not None else 1
                    # A `w:tc` with no `w:p` is invalid.
                    self.assertTrue(cell.findall(w("p")))
                with self.subTest(row=index):
                    self.assertEqual(spanned, columns)

    def test_our_tables_repeat_their_header_row(self):
        """`tblHeader`, which the template does not set: its tables are a handful of specimen
        rows and ours run to pages."""
        checked = 0
        for table in document_xml(self.built()).iter(w("tbl")):
            style = table.find(w("tblPr")).find(w("tblStyle"))
            if style is None or style.get(w("val")) != partials.TABLE_STYLE:
                continue
            checked += 1
            properties = table.find(w("tr")).find(w("trPr"))
            self.assertIsNotNone(properties)
            self.assertIsNotNone(properties.find(w("tblHeader")))
        self.assertGreater(checked, 5)

    def test_an_appendix_heading_does_not_print_its_own_prefix(self):
        """`Heading1-AppendixList` declares `<w:numPr w:numId="52"/>`, which is what prints
        `Appendix A: `. Writing the prefix would print it twice.

        THE CONTENTS ENTRY DOES CARRY IT, and has to: numbering prints on the page and not into
        a line that copies the heading's text. See `partials.table_of_contents`.
        """
        content = self.built()
        headings = heading_texts(document_xml(content).find(w("body")))

        self.assertEqual([name for name in headings if name.startswith("Appendix")], [])
        self.assertIn("Devices Included in Review", all_text(content))

    def test_it_reopens_as_a_word_document(self):
        import docx

        document = docx.Document(io.BytesIO(self.built()))

        self.assertGreater(len(document.tables), 10)


class ContentTests(_SeededEstate):
    """What the document SAYS, where what it says is a decision rather than a layout."""

    def summary_of_findings(self):
        """The `# | Finding/Observation | Recommendation | Importance` table, by its header."""
        for table in document_xml(self.built()).iter(w("tbl")):
            header = [_text(cell) for cell in list(table.iter(w("tr")))[0].iter(w("tc"))]
            if header[:2] == ["#", "Finding/Observation"]:
                return table
        self.fail("the document has no Summary of Findings and Recommendations table")

    def test_the_finding_column_names_the_control_and_counts_what_it_names(self):
        """Jason, 2026-11-06: *"We can remove the control.id and just use the name that's on
        there now."* The id stays in the detail block, where the reader is an engineer
        following a finding into the workbook. Here the reader is deciding what to fund.

        AND THE COUNT IS THE NAMED CONTROL'S OWN. This cell used to carry a REMEDIATION GROUP's
        total under its worst control's name - 75,664 findings beside
        `Source/Destination Address Breadth Bounded`, whose own findings were 5,428 (Jason,
        2026-11-09). Both numbers are here now and both are about this control at this grade.
        """
        rows = list(self.summary_of_findings().iter(w("tr")))[1:]

        findings = [_text(list(row.iter(w("tc")))[1]) for row in rows]

        self.assertTrue(findings)
        for cell in findings:
            with self.subTest(cell):
                self.assertNotIn("places to edit", cell)
                self.assertIsNone(re.search(r"[A-Z]{2,4}-[A-Z]{2,5}-\d{3}", cell))
                self.assertRegex(cell, r"^.+[\d,]+ findings?( ,|,)? ?.*$")

    def test_every_row_counts_exactly_the_control_it_names(self):
        """The defect this table was rebuilt for. A row named after one control carried the
        whole remediation group's total, so Table 1 and the detail could not be reconciled by
        the engineer reading them, let alone by a client (Jason, 2026-11-09)."""
        measured = health_check.measure()
        detail, _coverage = health_check.split_coverage(
            health_check.read_control_detail(measured))
        rows = list(self.summary_of_findings().iter(w("tr")))[1:]

        self.assertEqual(len(rows), len(detail))
        for row, one in zip(rows, detail):
            cell = _text(list(row.iter(w("tc")))[1])
            with self.subTest(one.control.control_id):
                self.assertTrue(cell.startswith(one.control.name), cell)
                self.assertIn(f"{one.findings:,} ", cell)
                self.assertNotIn(f"{one.findings:,} findings on {one.objects:,}", cell)

    def test_every_observation_is_measured_rather_than_a_question(self):
        """Turning the template's questions into measured observations IS the job: 68 of its 139
        comments say *"Make sure the risk is changed to correspond with the level for each."*"""
        text = all_text(self.built())

        for question in ("Are licenses correct and current?",
                         "Is GlobalProtect being used?",
                         "Are templates used?",
                         "Are DoS protection rules being utilized?"):
            self.assertNotIn(question, text)

    def test_the_rating_scale_uses_the_severity_words_and_not_the_d_codes(self):
        """Jason, 2026-11-05: *"We are not going to use 'No Deviation' for now. that can be
        replaced with Informational."* With D-5 retired the scale is 1:1 with the catalog."""
        text = all_text(self.built())

        for code in ("D-1", "D-2", "D-3", "D-4", "D-5"):
            self.assertNotIn(code, text)
        self.assertNotIn("No Deviation", text)
        self.assertIn("Critical Deviation", text)

    def test_the_informational_description_is_ours_and_not_the_templates_pass(self):
        """The template's D-5 sentence describes a PASS and would contradict a row graded
        Informational."""
        text = all_text(self.built())

        self.assertNotIn("Meets or exceeds industry, vendor, and Optiv standards", text)
        self.assertIn("carries no risk to the network and security infrastructure on its own",
                      text)

    def test_no_rulebase_gets_a_table_of_its_own(self):
        """Jason, 2026-11-06: *"remove table 6 and all other tables/content all the way down to
        'Assessment Coverage'"*. Every finding those tables carried is in the observation table
        already, against the control that raised it - so they said the same thing twice.

        Nothing is said about the rulebases this assessment does not read either: naming them
        would organize our findings around the template's categories rather than around what
        was measured.
        """
        text = all_text(self.built())

        for label in ("Security", "Decryption", "DoS", "NAT", "QoS", "PBF", "App Override",
                      "Captive Portal"):
            self.assertNotIn(f"Risks in {label} Rules", text)
            self.assertNotIn(f"{label} rules were not reviewed", text)
        self.assertNotIn("this assessment does not collect them", text)
        self.assertIn("Detailed Findings and Recommendations", text)

    def test_every_control_with_a_finding_has_a_row_and_no_other_does(self):
        """What the "outside the template" paragraph used to be for. 47 of the 218 controls
        answered questions the hand-written Area list did not ask, so they were named in a
        sentence and left out of the table. With the headings derived from the object a finding
        is about, there is nowhere to be outside.

        A control that found nothing has no row either (Jason, 2026-11-06), so the claim is
        exactly: the rows are the controls with findings.
        """
        measured = health_check.measure()
        detail = health_check.read_control_detail(measured)

        named = {one.control.name for one in detail}
        firing = {control.name
                  for control in Control.objects.filter(is_active=True)
                  if measured.count([control.control_id])}

        self.assertEqual(named, firing)
        self.assertLess(len(firing), Control.objects.filter(is_active=True).count())

    def test_the_rows_run_worst_first(self):
        """Jason, 2026-11-06: *"Can you sort within each section heading by severity?"*, and
        from 2026-11-09 there is one list rather than a heading each: the summary table and the
        detail section walk it together, so a single order settles both.

        By the ROW's severity, not the control's. A control with findings at three severities
        is three rows, and ordering by the control's worst put a High below a Medium belonging
        to a worse control - so the severity column did not run downhill.
        """
        detail = health_check.read_control_detail(health_check.measure())

        ranks = [SEVERITY_RANK[one.severity] for one in detail]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_the_severity_column_of_the_built_table_never_rises(self):
        """Asserted on the OUTPUT as well, because the order a reader sees is the order the
        cells are in, not the order the dataclass was sorted in."""
        order = {label: n for n, label in enumerate(
            ["Critical", "High", "Medium", "Low", "Informational"])}
        root = document_xml(self.built())

        for table in root.iter(w("tbl")):
            seen = []
            for row in table.iter(w("tr")):
                cells = list(row.iter(w("tc")))
                if len(cells) != 3:
                    seen = []            # a spanning row: a new heading, so the run restarts
                    continue
                grade = _text(cells[-1])
                if grade in order:
                    seen.append(order[grade])
            with self.subTest(_text(list(table.iter(w("tr")))[0])[:40]):
                self.assertEqual(seen, sorted(seen))

    def test_a_control_that_passed_everywhere_is_nowhere(self):
        """Jason, 2026-11-06: a control that raised nothing gets no row - an earlier draft gave
        every control one so the table read as a record of the review, and on the lab that was
        twelve rows saying only that nothing was wrong."""
        measured = health_check.measure()
        detail = health_check.read_control_detail(measured)

        self.assertTrue(detail)
        for one in detail:
            with self.subTest(one.control.control_id):
                self.assertGreater(one.findings, 0)

    def test_the_subjects_of_an_area_are_counted_once_each(self):
        """Counting per control and adding up was the first version, and sixteen controls report
        on the security rulebase: the Security row read "2,635 findings across 2,635 objects",
        two numbers that look like a measurement and are the same number twice.

        The key carries the MODEL as well as the pk, because twenty-four finding models each
        number their own subjects and a set of bare ids would merge two different objects.
        """
        measured = health_check.Measured()
        measured.subjects["PAN-POL-004"] |= {("RuleFinding", 1), ("RuleFinding", 2)}
        measured.subjects["PAN-POL-005"] |= {("RuleFinding", 1), ("RuleFinding", 3)}
        measured.subjects["PAN-ZON-001"] |= {("ZoneFinding", 1)}

        self.assertEqual(measured.distinct_subjects(["PAN-POL-004", "PAN-POL-005"]), 3)
        self.assertEqual(
            measured.distinct_subjects(["PAN-POL-004", "PAN-POL-005", "PAN-ZON-001"]), 4)

    def test_the_manual_placeholders_are_marked_and_counted(self):
        """Not prose invented to make the document look finished: a health check's environment
        description and its interview findings are things a person did."""
        content, reports = build_health_check_document(today=dt.date(2026, 11, 5))
        text = all_text(content)

        self.assertIn("[MANUAL: describe the sites this health check covers", text)
        self.assertIn("[MANUAL: peer reviewer]", text)
        # The count is over the FINISHED document and so includes the cover's own, which a
        # deployment with no `ApplicationEnvironment` gets two of.
        placeholders = text.count("[MANUAL:")
        self.assertGreater(placeholders, 10)
        self.assertIn(f"Placeholders: {placeholders} marked MANUAL", " ".join(reports))

    def test_each_section_reports_one_line_about_itself(self):
        """As the sheets report themselves - what the engineer sees when a build finishes."""
        reports = build_health_check_document(today=dt.date(2026, 11, 5))[1]

        self.assertTrue(any(line.startswith("Summary of Findings") for line in reports))
        # No Panorama line and, since 2026-11-09, no firewall one: every control reads a
        # firewall's own configuration, and the observation table that stood under that heading
        # printed what every detail block prints.
        self.assertTrue(any(line.startswith("Detailed Findings and Recommendations:")
                            for line in reports))
        self.assertTrue(any(line.startswith("Captions:") for line in reports))

    def test_findings_from_two_runs_are_refused(self):
        """The same refusal `artifact_store` explains for the workbooks: this reads some thirty
        tables one after another, and a document whose executive summary and whose observation
        tables describe different runs is worse than no document."""
        with mock.patch.object(health_check, "measure") as measure:
            measure.return_value = health_check.Measured(runs={1, 2})

            with self.assertRaises(ArtifactBuildError) as caught:
                build_health_check_document()

        self.assertIn("2 different runs", str(caught.exception))

    def test_a_finding_against_a_control_in_no_area_would_not_be_printed_silently(self):
        """Counted in FINDINGS rather than in controls, which is the number that would be
        missing from the page."""
        measured = health_check.measure()
        measured.by_severity["PAN-NOPE-001"]["high"] = 7

        with self.assertRaises(ArtifactBuildError) as caught:
            health_check.check_every_finding_reached_the_spine(measured)

        self.assertIn("7 findings", str(caught.exception))
        self.assertIn("PAN-NOPE-001", str(caught.exception))


def control_detail_blocks(content: bytes) -> list:
    """Every block of the Control Detail section, read out of the built document.

    `(object heading, control heading, {label: value}, the line under the table)`. Read off the
    output rather than off the dataclasses, for the reason the module docstring gives: a
    generator that agrees with itself and disagrees with Word is the failure a test over the
    builder's return value cannot see.
    """
    body = document_xml(content).find(w("body"))
    blocks, inside, subject, control, lines, trailing = [], False, None, None, {}, []

    def close():
        if control is not None:
            blocks.append((subject, control, dict(lines), list(trailing)))

    for element in body:
        tag = element.tag.split("}")[1]
        if tag == "p":
            properties = element.find(w("pPr"))
            style = properties.find(w("pStyle")) if properties is not None else None
            style = style.get(w("val")) if style is not None else ""
            body_text = _text(element)
            if style == partials.HEADING_1:
                close()
                control, lines, trailing = None, {}, []
                inside = body_text == "Detailed Findings and Recommendations"
            elif not inside:
                continue
            elif style == partials.HEADING_2:
                close()
                subject, control, lines, trailing = body_text, None, {}, []
            elif style == partials.HEADING_3:
                close()
                control, lines, trailing = body_text, {}, []
            elif control is not None and body_text:
                trailing.append(body_text)
        elif tag == "tbl" and inside and control is not None:
            for row in element.findall(w("tr")):
                cells = [_text(cell) for cell in row.findall(w("tc"))]
                # LABEL, VALUE, LABEL, VALUE: the first row carries two pairs, because the
                # control's id and its severity share it.
                for index in range(0, len(cells) - 1, 2):
                    lines[cells[index]] = cells[index + 1]
    close()
    return blocks


class ControlDetailTests(_SeededEstate):
    """Detailed Findings and Recommendations, 2026-11-09 - the section that was Control Detail.

    It is no longer optional and no longer one block per control: the summary table and this
    section are one ordered list walked twice, a block per control AND severity, each linked
    from its row. Jason, 2026-11-09: *"Control Detail is no longer optional. We can remove that
    code entirely"*, and *"There is a separate detail block per severity, this allows us to be
    more specific about the query/parameters that caused the finding too."*
    """

    def with_detail(self) -> bytes:
        return build_health_check_document(today=dt.date(2026, 11, 5))[0]

    def test_every_build_carries_it(self):
        """It was a parameter defaulting to OFF until the counts broke out here and nowhere
        else. A build without it would ship a summary whose rows link into empty space."""
        content, reports = build_health_check_document(today=dt.date(2026, 11, 5))

        self.assertIn("Detailed Findings and Recommendations", all_text(content))
        self.assertTrue(any(line.startswith("Detailed Findings and Recommendations:")
                            for line in reports))

    def test_there_is_one_block_per_control_and_severity(self):
        measured = health_check.measure()
        detail, _coverage = health_check.split_coverage(
            health_check.read_control_detail(measured))

        blocks = control_detail_blocks(self.with_detail())

        self.assertEqual(len(blocks), len(detail))
        self.assertEqual([control for _severity, control, _lines, _after in blocks],
                         [one.control.name for one in detail])

    def test_the_severity_is_a_heading_and_so_is_the_control(self):
        """Jason, 2026-11-06, on the first mock-up: real headings rather than a shaded band, so
        both reach the table of contents and Word's navigation pane. That is how a reader gets
        to one control in forty pages. The outer heading is the GRADE from 2026-11-09, because
        that is the order the summary table is in."""
        blocks = control_detail_blocks(self.with_detail())

        grades = {grade for grade, _control, _lines, _after in blocks}
        self.assertTrue(grades)
        self.assertTrue(grades <= {Control.Severity(severity).label
                                   for severity in health_check.WORST_FIRST})
        for grade, control, lines, _after in blocks:
            self.assertTrue(grade and control)
            self.assertEqual(lines["Severity"], grade)

    def test_a_summary_row_links_to_its_own_block(self):
        """Jason, 2026-11-09: *"the summary is a doc link to the detail."* Every row's control
        name is a hyperlink, and the bookmark it names is on that block's heading."""
        body = document_xml(self.with_detail()).find(w("body"))

        anchors = [link.get(w("anchor")) for link in body.iter(w("hyperlink"))
                   if (link.get(w("anchor")) or "").startswith("_Ref")]
        bookmarks = {node.get(w("name")) for node in body.iter(w("bookmarkStart"))}

        self.assertTrue(anchors)
        self.assertEqual(len(anchors), len(set(anchors)))
        for anchor in anchors:
            self.assertIn(anchor, bookmarks)

    def test_the_block_says_what_was_matched(self):
        """What the per-severity split buys. A control grades its findings differently because
        a different query matched, and `ControlQuery.short_description` is already written for
        a reader - so the block can say what this grade means."""
        lines = {control: block for _grade, control, block, _after
                 in control_detail_blocks(self.with_detail())}
        control = Control.objects.get(control_id="PAN-MGT-007")
        wanted = set(ControlQuery.objects.filter(control=control)
                     .exclude(short_description="")
                     .values_list("short_description", flat=True))

        matched = lines[control.name]["What was matched"]
        self.assertTrue(wanted, "the fixture's control has no query sentence to print")
        for sentence in wanted:
            self.assertIn(sentence, matched)

    def test_the_table_carries_the_control_id_and_the_three_catalogue_lines(self):
        """The id is in the table because a client who follows one of these up quotes it - and
        because the catalog's validator refuses a line that names the control's own id, the
        row above having said it already."""
        blocks = {control: lines for _subject, control, lines, _after
                  in control_detail_blocks(self.with_detail())}
        control = Control.objects.get(control_id="PAN-MGT-007")

        lines = blocks[control.name]
        self.assertEqual(lines["Control"], "PAN-MGT-007")
        self.assertEqual(lines["What it checks"], control.what_it_checks)
        self.assertEqual(lines["Why it matters"], control.why_it_matters)
        self.assertEqual(lines["What to change"], control.what_to_change)
        self.assertNotIn("Where to confirm", lines)

    def test_the_id_and_the_severity_share_the_first_row(self):
        """Jason, 2026-11-06: *"Control id and severity can probably be on the same row."* Two
        label-and-value pairs on one row, and every row under it one label and one value."""
        body = document_xml(self.with_detail()).find(w("body"))
        tables = [table for table in body.iter(w("tbl"))
                  if tuple(int(column.get(w("w")))
                           for column in table.find(w("tblGrid")).findall(w("gridCol")))
                  == health_check.DETAIL_GRID]

        self.assertTrue(tables)
        for table in tables:
            rows = table.findall(w("tr"))
            first = [_text(cell) for cell in rows[0].findall(w("tc"))]
            self.assertEqual([first[0], first[2]], ["Control", "Severity"])
            for row in rows[1:]:
                self.assertEqual(len(row.findall(w("tc"))), 2)

    def test_where_to_confirm_is_the_one_line_outside_the_table(self):
        """Jason, 2026-11-06: *"Move 'Why it matters.' and 'What to change' to the table."*
        - which left this one, the screen path, as prose under it."""
        after = {control: lines for _subject, control, _lines, lines
                 in control_detail_blocks(self.with_detail())}
        control = Control.objects.get(control_id="PAN-MGT-007")

        self.assertIn(f"Where to confirm it. {control.where_to_confirm}", after[control.name])

    def test_the_line_says_how_many_findings_and_what_they_are_about(self):
        measured = health_check.measure()
        lines = {control: block for _subject, control, block, _after
                 in control_detail_blocks(self.with_detail())}
        control = Control.objects.get(control_id="PAN-MGT-007")

        findings = measured.count([control.control_id])
        objects = len(measured.subjects_by_severity[(control.control_id, "low")])
        # The SINGULAR at one object: the seeded estate has one banner, and
        # "1 finding on 1 login banners" was the first version of this line.
        self.assertEqual(findings, objects, "a finding is one control failing on one object")
        self.assertRegex(lines[control.name]["Findings"],
                         rf"^{findings} finding(s)?(, \d+ places? to edit)?$")
        self.assertEqual(lines[control.name]["Severity"], "Low")

    def test_the_blocks_run_worst_first(self):
        """The section's own first line says so, and a reader who scans it is reading the order
        rather than the grades. One list, so one claim."""
        detail = health_check.read_control_detail(health_check.measure())

        ranks = [SEVERITY_RANK[one.severity] for one in detail]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_a_control_that_found_nothing_has_no_block(self):
        """A heading over nothing reads as a section somebody forgot to fill in."""
        detail = health_check.read_control_detail(health_check.measure())

        self.assertTrue(detail)
        for one in detail:
            self.assertTrue(one.findings)

    def test_the_section_sits_just_before_the_recommendations(self):
        """Where Jason asked for it, which is also where it belongs: the summary says what was
        found, this says it control by control, and the recommendations follow from both."""
        headings = heading_texts(document_xml(self.with_detail()).find(w("body")))

        self.assertLess(heading_at(headings, "Detailed Findings and Recommendations"),
                        heading_at(headings, "High-Level Recommendations"))
        self.assertGreater(heading_at(headings, "Detailed Findings and Recommendations"),
                           heading_at(headings, "Summary of Findings and Recommendations"))

    def test_a_catalogue_line_nobody_wrote_is_marked_rather_than_left_blank(self):
        """The catalog's validator requires all four of an active control, so this is a
        control somebody added through the UI - and an empty cell under a client's heading is
        worse than a placeholder saying who has to write it."""
        Control.objects.filter(control_id="PAN-MGT-007").update(
            what_it_checks="", where_to_confirm="")

        content, reports = build_health_check_document(today=dt.date(2026, 11, 5))

        text = all_text(content)
        self.assertIn("[MANUAL: write the what it checks line for PAN-MGT-007", text)
        self.assertIn("[MANUAL: write the where to confirm line for PAN-MGT-007", text)
        self.assertTrue(any("2 lines marked MANUAL" in line for line in reports))

    def test_the_section_reports_itself_and_its_tables_keep_the_contract(self):
        """One build, and the three structural rules the rest of the document is held to:
        every row spans its grid, the first row repeats over a page break, and every run and
        every paragraph mark names Optiv's own typeface."""
        content, reports = build_health_check_document(today=dt.date(2026, 11, 5))
        body = document_xml(content).find(w("body"))

        self.assertTrue(any(line.startswith("Detailed Findings and Recommendations:")
                            and "over" in line for line in reports))
        self.assertEqual(unnamed_runs(body), [])
        self.assertEqual(unnamed_marks(body), [])
        for table in body.iter(w("tbl")):
            style = table.find(w("tblPr")).find(w("tblStyle"))
            if style is None or style.get(w("val")) != partials.TABLE_STYLE:
                continue            # the template's own cover tables, carried over verbatim
            columns = len(table.find(w("tblGrid")).findall(w("gridCol")))
            for row in table.findall(w("tr")):
                # Counted in SPANS, not in cells: an observation table's subject heading is one
                # cell covering all three columns.
                self.assertEqual(spanned_columns(row), columns)
            self.assertIsNotNone(table.find(w("tr")).find(w("trPr")).find(w("tblHeader")))


class SummaryRowTests(SimpleTestCase):
    """The summary table, over blocks handed to it - so its claims are pinned where they are
    written rather than only where a fixture happens to produce them."""

    def block(self, severity, findings, **overrides):
        fields = dict(
            control=Control(control_id="PAN-CRT-002", name="Certificate Key Strength Minimums",
                            short_remediation="Reissue the keys below the floor."),
            severity=severity, findings=findings, objects=findings,
            object_nouns=("certificates", "certificate"),
            reach=((("pan-fw-111",), findings),), others=0, matched=(),
            places=findings, subject="Certificate",
            anchor=f"_Ref2000{severity[:1]}")
        fields.update(overrides)
        return health_check.ControlDetail(**fields)

    def test_a_control_graded_two_ways_is_two_rows_carrying_their_own_counts(self):
        """Jason, 2026-11-09: *"If there are 10000 medium and 1 critical, that would be a
        misrepresentation of the facts."* One row carrying the worse grade and both counts says
        the wrong thing about ten thousand of them."""
        rows = health_check.summary_of_findings_rows(
            [self.block("critical", 1), self.block("medium", 10_000)])[0][1:]

        cells = [[_text_of_cell(cell) for cell in row] for row in rows]
        self.assertEqual([cell[3] for cell in cells], ["Critical", "Medium"])
        self.assertIn("1 finding, 1 place to edit", cells[0][1])
        self.assertIn("10,000 findings, 10,000 places to edit", cells[1][1])

    def test_the_recommendation_repeats_on_each_of_a_controls_rows(self):
        """Jason, 2026-11-09, asked which way and answered it: *"leave it"*. 61 of the lab's
        264 rows repeat the row above them this way, and the alternative - a blank cell on the
        second and third - costs a reader skimming one severity band the remedy for what they
        are looking at."""
        rows = health_check.summary_of_findings_rows(
            [self.block("critical", 1), self.block("medium", 2)])[0][1:]

        remedies = [_text_of_cell(row[2]) for row in rows]
        self.assertEqual(remedies, ["Reissue the keys below the floor."] * 2)

    def test_every_row_links_to_its_own_block(self):
        rows = health_check.summary_of_findings_rows(
            [self.block("critical", 1), self.block("medium", 2)])[0][1:]

        anchors = [paragraph.find(w("hyperlink")).get(w("anchor"))
                   for row in rows for paragraph in row[1].paragraphs
                   if paragraph.find(w("hyperlink")) is not None]
        self.assertEqual(anchors, ["_Ref2000c", "_Ref2000m"])


class DetailPhraseTests(SimpleTestCase):
    """The measured lines of a detail block, which are sentences built out of counts - so each
    is pinned where it is written rather than only on the built document."""

    def detail(self, **overrides) -> health_check.ControlDetail:
        fields = dict(
            control=Control(control_id="PAN-AAA-001", name="LDAP Server Profiles Require SSL"),
            severity="critical", findings=4, objects=4,
            object_nouns=("AAA server profiles", "AAA server profile"),
            reach=((("pan-fw-111",), 4),), others=0, matched=(),
            places=4, subject="AAA Server Profile")
        fields.update(overrides)
        return health_check.ControlDetail(**fields)

    def test_the_findings_line_counts_the_findings_and_the_edits(self):
        """Jason, 2026-11-09: *"Remediation one object may clear multiple findings. That's the
        number I'm looking for."* The first version printed the findings count beside the count
        of objects the findings are ABOUT, which is the same number by construction."""
        self.assertEqual(health_check.findings_phrase(self.detail()),
                         "4 findings, 4 places to edit")

    def test_one_edit_clearing_many_findings_is_the_point_of_the_line(self):
        """Measured on the lab: PAN-VLN-003 raised 1,067 findings, one per rule, and all of
        them are cleared by editing sixteen vulnerability protection profiles."""
        detail = self.detail(findings=1_067, objects=1_067, places=16)

        self.assertEqual(health_check.findings_phrase(detail),
                         "1,067 findings, 16 places to edit")

    def test_one_of_each_is_singular_twice(self):
        detail = self.detail(findings=1, objects=1, places=1)

        self.assertEqual(health_check.findings_phrase(detail),
                         "1 finding, 1 place to edit")

    def test_a_control_the_remediation_surface_has_no_row_for_says_only_the_findings(self):
        """8 of the lab's 264 blocks - the ones whose subject is the review rather than the
        estate. A zero there would read as "nothing to do"."""
        detail = self.detail(places=0)

        self.assertEqual(health_check.findings_phrase(detail), "4 findings")

    def test_the_noun_is_the_registry_s_own_word_for_a_client(self):
        """Printed as `FindingKind.client_plural` carries it, with no pluralizer over it. The
        kind this reads is the one that forced the field: `plural_noun` over its label put
        "12 password complexities" under a heading reading Minimum Password Complexity."""
        kind, = (k for k in FINDING_KINDS if k.label == "password complexity")
        detail = self.detail(severity="medium", findings=14, objects=12, places=12,
                             object_nouns=(kind.client_plural, kind.client_singular))

        self.assertEqual(health_check.findings_phrase(detail),
                         "14 findings, 12 places to edit")

    def test_what_was_matched_is_the_querys_own_sentence(self):
        """`ControlQuery.short_description` is written for a reader, so the block prints it
        rather than describing the query in words of ours."""
        detail = self.detail(matched=("Profiles that let malware through on a decoder.",))

        self.assertEqual(health_check.matched_phrase(detail),
                         "Profiles that let malware through on a decoder.")

    def test_a_query_nobody_described_is_marked_rather_than_left_blank(self):
        """48 of the lab's 579 queries carry no sentence, and an empty row under a client's
        heading is worse than a placeholder saying who has to write it."""
        matched = health_check.matched_phrase(self.detail(matched=()))

        self.assertIn("[MANUAL: write a short_description for the PAN-AAA-001 critical query",
                      matched)

    def test_a_noun_that_is_already_plural_is_left_alone(self):
        """Measured over all 75 finding kinds 2026-11-06: seven of their labels already end in
        `s` - `logging settings`, `session settings`, `firewall content streams` - and the `es`
        English wants after a sibilant made every one of them "settingses"."""
        self.assertEqual(health_check.plural_noun(8, "logging settings"), "logging settings")
        self.assertEqual(health_check.plural_noun(2, "rulebase device match"),
                         "rulebase device matches")
        self.assertEqual(health_check.plural_noun(2, "license inventory"),
                         "license inventories")
        self.assertEqual(health_check.plural_noun(1, "logging settings"), "logging settings")

    def test_an_ha_pair_is_named_once_and_the_rest_are_counted(self):
        detail = self.detail(reach=((("fw-core-tpa-a", "fw-core-tpa-b"), 6),
                                    (("pan-fw-111",), 2)),
                             others=3)

        self.assertEqual(health_check.firewalls_phrase(detail),
                         "fw-core-tpa-a/b (6), pan-fw-111 (2), and 3 other firewalls")

    def test_one_other_firewall_is_singular(self):
        detail = self.detail(reach=((("pan-fw-111",), 9),), others=1)

        self.assertEqual(health_check.firewalls_phrase(detail),
                         "pan-fw-111 (9), and 1 other firewall")

    def test_a_finding_no_snapshot_attributes_says_so_rather_than_nothing(self):
        """Every one of the lab's 17,555 findings resolves to a firewall, so this is the
        snapshot taken from somewhere that is not an appliance - and a blank cell in a client
        document is a question rather than an answer."""
        self.assertEqual(health_check.firewalls_phrase(self.detail(reach=(), others=0)),
                         health_check.NO_FIREWALL_NAMED)


class NumberTests(SimpleTestCase):
    """How a count is printed, which on this estate is a five-figure number."""

    def test_a_count_is_grouped_at_the_thousand(self):
        """The first lab build printed "4647 findings across 1083 places to edit". A client
        reading a serial number in place of a count is a presentation defect in the one sentence
        the Summary of Findings leads with.
        """
        self.assertEqual(health_check.tally(4647), "4,647")
        self.assertEqual(health_check.tally(1), "1")
        self.assertEqual(health_check.tally(999), "999")
        self.assertEqual(health_check.tally(17555), "17,555")

    def test_a_control_line_groups_its_count(self):
        """The helper is only worth having if the sentences use it, so one of them is checked
        here rather than trusted."""
        measured = health_check.Measured()
        measured.by_severity["PAN-POL-008"]["high"] = 4647
        control = Control(control_id="PAN-POL-008", name="Security Profiles on All Allow Rules")

        line = health_check.control_line(control, measured)

        self.assertIn("4,647 findings", line)
        self.assertNotIn("4647", line)


class CellPropertyTests(_SeededEstate):
    """`w:tcPr`, whose children Word reads as a SEQUENCE rather than a set.

    This was `BandTests`, over the shaded subject headings of the observation table. That table
    went on 2026-11-09 and nothing this generator writes is shaded any more - but the ordering
    rule it caught applies to every cell, so the test it was really carrying stays.
    """

    def test_the_shading_sits_where_the_schema_wants_it(self):
        """`w:tcPr` is a sequence: `shd` comes after `gridSpan` and before `vAlign`. Out of
        order Word reports unreadable content, which is how this document lost a day."""
        root = document_xml(self.built())
        order = ["cnfStyle", "tcW", "gridSpan", "hMerge", "vMerge", "tcBorders", "shd",
                 "noWrap", "tcMar", "textDirection", "tcFitText", "vAlign", "hideMark"]

        for properties in root.iter(w("tcPr")):
            seen = [child.tag.split("}")[1] for child in properties]
            with self.subTest(seen):
                self.assertEqual(seen, sorted(seen, key=order.index))


class ReachTests(SimpleTestCase):
    """The Firewalls line of a detail block: which firewalls carry a control's findings.

    Jason, 2026-11-06: *"present counts by firewall instead of subject ... If the number of
    firewalls exceeds 5, then state something like and 'n' others"*, and *"the five named
    should be the worst affected by count"*.
    """

    def test_the_worst_affected_are_named_first(self):
        counts = collections.Counter({("a",): 3, ("b",): 9, ("c",): 5})

        reach, others = health_check.worst_affected(counts)

        self.assertEqual([name for name, _ in reach], [("b",), ("c",), ("a",)])
        self.assertEqual(others, 0)

    def test_beyond_five_firewalls_the_rest_are_counted_not_named(self):
        counts = collections.Counter({(chr(97 + n),): 10 - n for n in range(8)})

        reach, others = health_check.worst_affected(counts)

        self.assertEqual(len(reach), health_check.FIREWALLS_NAMED)
        self.assertEqual(others, 3)

    def test_a_tie_is_broken_by_name_so_a_rebuild_does_not_reshuffle(self):
        counts = collections.Counter({("b",): 4, ("a",): 4})

        reach, _ = health_check.worst_affected(counts)

        self.assertEqual([name for name, _ in reach], [("a",), ("b",)])


class ScaffoldTests(SimpleTestCase):
    def test_the_scaffold_ships_with_the_package(self):
        """`pyproject.toml` lists `docx/*.docx` under package-data; without it the wheel ships
        the generator and not the file it needs."""
        self.assertTrue(scaffold_module.SCAFFOLD_PATH.is_file())

    def test_the_scaffolds_body_is_the_shape_the_command_wrote(self):
        """Not an assertion the BUILD makes - it finds the marker - but one worth holding here,
        because a re-derived scaffold that sliced differently would still build and would ship
        half the specimen content."""
        scaffold = scaffold_module.open_scaffold()
        body = scaffold.body

        self.assertEqual(len(list(body)), 16)
        self.assertEqual(body[-1].tag, w("sectPr"))
        self.assertIsNotNone(scaffold.marker())

    def test_the_package_data_file_is_never_opened_for_writing(self):
        """Jason, 2026-11-05: *"modifying something in place comes with its own challenges."*
        Two builds must not share a file, so the bytes are read and handed to python-docx as a
        BytesIO."""
        before = scaffold_module.SCAFFOLD_PATH.read_bytes()

        scaffold = scaffold_module.open_scaffold()
        scaffold.insert([partials.paragraph(partials.NORMAL, "anything")])
        scaffold.to_bytes()

        self.assertEqual(scaffold_module.SCAFFOLD_PATH.read_bytes(), before)

    def test_a_scaffold_with_no_marker_is_refused(self):
        """Inserting at the end of the body would put the whole report AFTER Optiv's back
        cover - a file that looks finished and is wrong."""
        scaffold = scaffold_module.open_scaffold()
        marker = scaffold.marker()
        marker.getparent().remove(marker)

        with self.assertRaises(ArtifactBuildError) as caught:
            scaffold.marker()

        self.assertIn("{{OEA-BODY}}", str(caught.exception))

    def test_every_bookmark_in_the_scaffold_pairs_up(self):
        """The defect that shipped. Deriving the scaffold cuts the template's specimen body out,
        and three bookmarks - `_Hlk47707859`, `_Toc417055643`, `_Toc410994106` - started on the
        cover and ended inside what was cut. Word will not open a document with an unclosed
        bookmark: Jason, 2026-11-06, got "Word found unreadable content ... Do you want to
        recover the contents of this document?", and answering No gave "Word experienced an
        error trying to open the file."

        Nothing else in this suite could see it. The file was valid XML, every style resolved,
        every table spanned its grid, and the document only failed in Word.
        """
        scaffold = scaffold_module.open_scaffold()

        starts, ends = bookmark_ids(scaffold.body)

        self.assertEqual(starts, ends)

    def test_a_scaffold_with_an_unclosed_bookmark_is_refused(self):
        """A guard rather than a comment, because this defect is invisible until a client opens
        the file - and by then the deliverable has been sent."""
        scaffold = scaffold_module.open_scaffold()
        for element in scaffold.body.iter(w("bookmarkEnd")):
            element.getparent().remove(element)
            break

        with self.assertRaises(ArtifactBuildError) as caught:
            scaffold_module.check_bookmarks(scaffold.document)

        self.assertIn("Word will refuse to open", str(caught.exception))
        self.assertIn("derive_health_check_scaffold", str(caught.exception))

    def test_a_bookmark_that_ends_without_starting_is_refused_too(self):
        scaffold = scaffold_module.open_scaffold()
        for element in scaffold.body.iter(w("bookmarkStart")):
            element.getparent().remove(element)
            break

        with self.assertRaises(ArtifactBuildError) as caught:
            scaffold_module.check_bookmarks(scaffold.document)

        self.assertIn("nothing opens bookmark id", str(caught.exception))

    def test_every_prefix_mc_ignorable_names_is_declared(self):
        """The defect Word was actually refusing. `w:document` carries
        `mc:Ignorable="w14 w15 w16 w16cex w16cid w16du w16sdtdh w16sdtfl w16se wp14"`, and
        deriving the scaffold through `xml.etree` dropped the declarations of eight of them -
        it declares only the namespaces something in the output uses, and cutting the specimen
        body took the last user of those eight with it.

        A prefix in `mc:Ignorable` that resolves to nothing makes the part invalid, and Word
        answers "Word found unreadable content" and then, if you decline the recovery, "Word
        experienced an error trying to open the file" (Jason, 2026-11-06, with both boxes).
        Every other check in this suite passed on that file.
        """
        scaffold = scaffold_module.open_scaffold()
        root = scaffold.document.element.getroottree().getroot()

        listed = (root.get(scaffold_module.MC_IGNORABLE) or "").split()
        declared = {prefix for prefix in root.nsmap if prefix}

        self.assertTrue(listed, "the scaffold declares no mc:Ignorable at all")
        self.assertEqual(sorted(prefix for prefix in listed if prefix not in declared), [])

    def test_a_scaffold_missing_a_declaration_is_refused(self):
        scaffold = scaffold_module.open_scaffold()
        root = scaffold.document.element.getroottree().getroot()
        root.set(scaffold_module.MC_IGNORABLE,
                 (root.get(scaffold_module.MC_IGNORABLE) or "") + " nosuchprefix")

        with self.assertRaises(ArtifactBuildError) as caught:
            scaffold_module.check_markup_compatibility(scaffold.document)

        self.assertIn("nosuchprefix", str(caught.exception))
        self.assertIn("Word refuses to open", str(caught.exception))

    def test_the_scaffold_carries_none_of_optivs_review_comments(self):
        """The template holds 139 comments, every one anchored in the specimen body. Cutting the
        body left them anchored to nothing and riding in the deliverable, where a client opening
        the Comments pane would have read Optiv's internal drafting conversation.
        """
        with zipfile.ZipFile(io.BytesIO(scaffold_module.SCAFFOLD_PATH.read_bytes())) as archive:
            names = archive.namelist()

        self.assertNotIn("word/comments.xml", names)
        self.assertNotIn("word/commentsExtended.xml", names)
        self.assertNotIn("word/people.xml", names)

    def test_the_scaffold_carries_no_preview_of_somebody_elses_document(self):
        """`docProps/thumbnail.emf` is the preview Windows shows, rendered from the document
        Optiv saved rather than from anything this builds - and 1.0 MB of a 1.5 MB file."""
        with zipfile.ZipFile(io.BytesIO(scaffold_module.SCAFFOLD_PATH.read_bytes())) as archive:
            self.assertNotIn("docProps/thumbnail.emf", archive.namelist())

    def test_the_face_written_on_every_run_is_the_templates_own(self):
        """Writing a font on every run is direct formatting, and direct formatting beats a
        style - so it is only honest while it names the face Optiv's own defaults specify. A
        reissued template that changed it has to fail the build rather than be overridden."""
        scaffold = scaffold_module.open_scaffold()
        defaults = scaffold.document.styles.element.find(qn("w:docDefaults"))
        fonts = (defaults.find(qn("w:rPrDefault")).find(qn("w:rPr")).find(qn("w:rFonts")))

        self.assertEqual(fonts.get(qn("w:ascii")), partials.BODY_FONT)
        self.assertEqual(fonts.get(qn("w:hAnsi")), partials.BODY_FONT)

    def test_a_template_that_changed_its_typeface_is_refused(self):
        scaffold = scaffold_module.open_scaffold()

        with mock.patch.object(partials, "BODY_FONT", "Franklin Gothic Book"):
            with self.assertRaises(ArtifactBuildError) as caught:
                scaffold_module.check_fonts(scaffold.document)

        self.assertIn("Franklin Gothic Book", str(caught.exception))
        self.assertIn("Arial", str(caught.exception))

    def test_a_missing_scaffold_says_how_to_make_one(self):
        from pathlib import Path

        with self.assertRaises(ArtifactBuildError) as caught:
            scaffold_module.open_scaffold(Path("/nonexistent/health-check-scaffold.docx"))

        self.assertIn("derive_health_check_scaffold", str(caught.exception))


class OtherDeliverablesTests(_SeededEstate):
    def test_building_it_changes_nothing_about_either_workbook(self):
        """The findings workbook remains the detailed findings artifact and the remediation
        workbook its own - Jason, 2026-11-03: *"do not modify the existing xlsx artifact."*"""
        findings_before = sheet_names(build_workbook()[0])
        remediation_before = sheet_names(build_remediation_workbook()[0])

        build_health_check_document()

        self.assertEqual(sheet_names(build_workbook()[0]), findings_before)
        self.assertEqual(sheet_names(build_remediation_workbook()[0]), remediation_before)
