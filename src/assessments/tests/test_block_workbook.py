"""The block workbook - the health check document's detail section as a tab strip.

Jason, 2026-11-18: *"I want a third workbook artifact that better aligns with the summary doc.
In effect, a tab in the workbook for each block in the doc's Detailed Findings and
Recommendations, in the same order as they appear in the doc. Include all the meta tabs
(Management Stations, Appliances, Enforcement Points, Controls)."*

The whole value of the file is that its tab strip and the document's section are ONE order, so
that is what most of these check: against `read_control_detail`, which is the function the
document itself walks, rather than against a list repeated here. The rest check that a tab's
rows are its own block's findings and nobody else's - the slice is the one new piece of
machinery and the one that could lose a row quietly.
"""

from __future__ import annotations

import datetime as dt

from django.test import SimpleTestCase, TestCase

from assessments.artifacts import ArtifactBuildError, build_block_workbook
from assessments.artifacts import block_workbook
from assessments.artifacts.health_check import measure, read_control_detail
from assessments.artifacts.naming import block_workbook_filename
from assessments.artifacts.sheets import block as block_sheet
from assessments.finding_run import regenerate_findings
from assessments.models import Control, GeneratedArtifact
from assessments.tests._seed import seed_controls
from assessments.tests.test_artifacts import sheet_names
from assessments.tests.test_findings_views import build_estate

REFERENCE_TABS = ["Management Stations", "Appliances", "Enforcement Points", "Controls"]


class TabTitleTests(SimpleTestCase):
    """Excel caps a worksheet name at 31 characters, and 264 of them have to stay distinct."""

    def title_for(self, control_id, severity, number=7):
        detail = _Detail(control=_Control(control_id), severity=severity)
        return block_sheet.tab_title(number, detail)

    def test_the_number_leads_so_the_tab_strip_is_the_documents_order(self):
        self.assertEqual(self.title_for("PAN-POL-008", Control.Severity.CRITICAL),
                         "007 PAN-POL-008 Critical")

    def test_the_longest_possible_title_fits_excels_limit(self):
        """Three digits, a twelve-character control id and `Informational` come to 30."""
        title = self.title_for("PAN-XXXX-001", Control.Severity.INFORMATIONAL, number=264)

        self.assertEqual(title, "264 PAN-XXXX-001 Informational")
        self.assertLessEqual(len(title), 31)

    def test_no_title_carries_a_character_excel_forbids_in_a_sheet_name(self):
        for severity in Control.Severity.values:
            with self.subTest(severity):
                self.assertFalse(set(self.title_for("PAN-POL-002", severity)) & set(r":\/?*[]"))


class _Control:
    def __init__(self, control_id):
        self.control_id = control_id


class _Detail:
    """Enough of a `ControlDetail` for the naming, which reads two attributes."""

    def __init__(self, control, severity):
        self.control, self.severity = control, severity


class FilenameTests(SimpleTestCase):
    def test_it_is_named_for_what_it_is_to_the_reader(self):
        """`-blocks` is this codebase's word for a section of the document and means nothing to
        a client with three spreadsheets in a directory."""
        self.assertEqual(block_workbook_filename(today=dt.date(2026, 11, 18)),
                         "findings-detail-2026-11-18.xlsx")


class EmptyEstateTests(TestCase):
    """A fresh deployment, or one whose collection has not run - the same thing the other two
    workbooks are asked to survive."""

    def test_it_builds_with_nothing_in_the_database(self):
        content, reports = build_block_workbook()

        self.assertTrue(content)
        self.assertIn("Summary of Findings", reports[0])

    def test_the_summary_is_first_and_the_reference_tabs_follow_it(self):
        """Controls is last of the four and before every block tab, because each block's rows
        link into its own control-and-severity row."""
        names = sheet_names(build_block_workbook()[0])

        self.assertEqual(names[:5], ["Summary of Findings"] + REFERENCE_TABS)


class SeededEstateTests(TestCase):
    """Three controls over one appliance, which is enough for several blocks."""

    @classmethod
    def setUpTestData(cls):
        build_estate(hostname="fw-blocks")
        seed_controls(["PAN-MGT-007", "PAN-MGT-001", "PAN-POL-008"])
        regenerate_findings()

    def blocks(self):
        return read_control_detail(measure())

    def test_there_is_one_tab_per_block_and_nothing_else(self):
        names = sheet_names(build_block_workbook()[0])
        blocks = self.blocks()

        self.assertTrue(blocks)
        self.assertEqual(len(names), len(blocks) + 1 + len(REFERENCE_TABS))

    def test_the_tab_strip_is_the_documents_own_order(self):
        """Asserted against `read_control_detail`, which is what the document walks, rather
        than against an order repeated here - the two would then agree by coincidence."""
        names = sheet_names(build_block_workbook()[0])[1 + len(REFERENCE_TABS):]

        self.assertEqual(names, [block_sheet.tab_title(number, one)
                                 for number, one in enumerate(self.blocks(), start=1)])

    def test_a_tab_holds_its_own_blocks_findings_and_no_others(self):
        """The count the document prints for a block, drawn from the slice rather than from
        the thing that made it: `build_block_workbook` asserts the two are equal, so this
        asserts the assertion is reachable by reading the reports it wrote."""
        _content, reports = build_block_workbook()
        blocks = self.blocks()

        for number, one in enumerate(blocks, start=1):
            with self.subTest(one.control.control_id, severity=one.severity):
                line = next(line for line in reports
                            if line.startswith(block_sheet.tab_title(number, one) + ":"))
                self.assertIn(f"{one.findings:,} finding", line)

    def test_a_block_whose_control_reaches_no_findings_tab_is_refused(self):
        """It cannot happen while the findings workbook's own check passes, but the failure
        would otherwise be a KeyError in a dictionary lookup and send the next reader to the
        wrong module."""
        blocks = self.blocks()

        with self.assertRaises(ArtifactBuildError) as refusal:
            block_workbook.check_every_block_has_a_table(blocks, {})

        self.assertIn(blocks[0].control.control_id, str(refusal.exception))

    def test_tabs_out_of_the_documents_order_are_refused(self):
        """The one failure this file exists to prevent, so it is raised rather than reported."""
        blocks = self.blocks()
        infos = [_Info(block_sheet.tab_title(number, one))
                 for number, one in enumerate(blocks, start=1)]
        # Renamed rather than swapped: a seeded estate can hold a single block, and swapping
        # the first with the last would then be a test that asserts nothing.
        infos[0] = _Info("001 PAN-XXX-999 Critical")

        with self.assertRaises(ArtifactBuildError) as refusal:
            block_workbook.check_tabs_follow_the_document(blocks, infos)

        self.assertIn("not in the document's order", str(refusal.exception))

    def test_a_tab_that_lost_a_row_is_refused(self):
        blocks = self.blocks()
        infos = [_Info(block_sheet.tab_title(number, one), {one.severity: one.findings})
                 for number, one in enumerate(blocks, start=1)]
        infos[0] = _Info(infos[0].title, {blocks[0].severity: blocks[0].findings - 1})

        with self.assertRaises(ArtifactBuildError) as refusal:
            block_workbook.check_every_finding_reached_a_tab(blocks, infos)

        self.assertIn("the slice lost rows", str(refusal.exception))


class _Info:
    """Enough of a `SheetInfo` for the two checks, which read a title and the severity counts."""

    def __init__(self, title, by_severity=None):
        self.title, self.by_severity = title, by_severity or {}


class KindTests(SimpleTestCase):
    def test_the_deliverable_has_its_own_kind_and_builder(self):
        """A fourth kind rather than an option on the first: `artifact_store` dispatches the
        run of record, the refusals and the background thread by kind."""
        from assessments import artifact_store

        name, filename = artifact_store.BUILDERS[GeneratedArtifact.Kind.BLOCKS]

        self.assertEqual(name, "build_block_workbook")
        self.assertIs(filename, block_workbook_filename)
