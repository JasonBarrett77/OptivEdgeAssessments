"""The remediation workbook - the second deliverable, built from the same findings.

Jason, 2026-11-05: *"Remediation needs its own artifact, separate from the existing Findings
artifact. However, the existing findings (detail) artifact is an excellent example of features
and formatting."*

So these tests check two things: that the file carries the features the findings workbook has -
a Summary first, a tab per group in the Summary's order, a real table with an autofilter and a
frozen header, tab colours by PAN-OS category - and that building it changes nothing about the
findings workbook, which remains the detailed findings artifact.
"""

from __future__ import annotations

import io
import re
import zipfile

from django.test import SimpleTestCase, TestCase

from assessments.artifacts import (
    ArtifactBuildError, build_remediation_workbook, build_workbook,
    remediation_workbook_filename)
from assessments.artifacts.remediation_workbook import groups_in_summary_order
from assessments.artifacts.sheets import remediation as remediation_sheet
from assessments.configuration_navigation import CATEGORIES
from assessments.remediation import REMEDIATION_GROUPS, group_category
from assessments.tests.test_artifacts import sheet_names


def table_definitions(content: bytes) -> dict:
    """{table name: its XML}, read from the file rather than from what built it."""
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        tables = {}
        for name in archive.namelist():
            if name.startswith("xl/tables/"):
                xml = archive.read(name).decode("utf-8")
                tables[re.search(r'name="([^"]+)"', xml).group(1)] = xml
    return tables


def worksheet_xml(content: bytes, index: int) -> str:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        return archive.read(f"xl/worksheets/sheet{index}.xml").decode("utf-8")


class TabNameTests(SimpleTestCase):
    """Excel caps a worksheet name at 31 characters and forbids `: \\ / ? * [ ]` in it. Both
    rules bite on the groups as they stand, so neither is left to xlsxwriter - which truncates
    silently and raises on the slash with a message about Excel rather than about the group."""

    def test_a_long_label_is_cut_to_excels_limit(self):
        group = next(g for g in REMEDIATION_GROUPS
                     if g.slug == "vulnerability-protection-profile")
        self.assertEqual(len(group.label), 32)

        self.assertEqual(remediation_sheet.sheet_title(group),
                         "Vulnerability protection profil")

    def test_a_slash_becomes_a_hyphen_rather_than_disappearing(self):
        """`SSLTLS` is not a word anybody searches for."""
        group = next(g for g in REMEDIATION_GROUPS if g.slug == "ssl-tls-service-profile")

        self.assertEqual(remediation_sheet.sheet_title(group), "SSL-TLS service profile")

    def test_every_group_has_a_tab_name_of_its_own(self):
        remediation_sheet.check_tab_names_are_distinct(REMEDIATION_GROUPS)

    def test_two_groups_that_would_share_a_tab_name_are_refused(self):
        """The failure is otherwise invisible - xlsxwriter's own message names Excel's rule and
        not the two groups that collided."""
        from assessments.remediation import RemediationGroup

        collide = [
            RemediationGroup(slug="one", label="A label that is far too long to fit in Excel",
                             control_ids=(), subject_type="zone", summary=""),
            RemediationGroup(slug="two", label="A label that is far too long to fit anywhere",
                             control_ids=(), subject_type="zone", summary=""),
        ]

        with self.assertRaises(ArtifactBuildError) as caught:
            remediation_sheet.check_tab_names_are_distinct(collide)

        self.assertIn("'one'", str(caught.exception))
        self.assertIn("'two'", str(caught.exception))


class OrderTests(SimpleTestCase):
    def test_the_tabs_are_in_the_summarys_category_order(self):
        """The tab strip and the Summary are one order, not two - the invariant
        `workbook.check_tabs_follow_the_summary` holds for the findings tabs."""
        ranks = [CATEGORIES.index(group_category(group))
                 for group in groups_in_summary_order()]

        self.assertEqual(ranks, sorted(ranks))

    def test_every_group_gets_a_tab(self):
        self.assertEqual(len(groups_in_summary_order()), len(REMEDIATION_GROUPS))


class FilenameTests(SimpleTestCase):
    def test_it_is_named_for_what_it_answers(self):
        """Not the findings workbook's name plus a suffix: a consultant with both in a directory
        is choosing between "what did we find" and "where do I go"."""
        import datetime as dt

        self.assertEqual(remediation_workbook_filename(today=dt.date(2026, 11, 5)),
                         "remediation-2026-11-05.xlsx")


class EmptyEstateTests(TestCase):
    """A fresh deployment, or one whose collection has not run. Every tab still draws, which is
    the same thing `WorkbookBuildTests.test_it_builds_on_an_estate_with_nothing_in_it` asks of
    the findings workbook."""

    def test_it_builds_with_nothing_in_the_database(self):
        content, reports = build_remediation_workbook()

        self.assertTrue(content)
        self.assertIn("places to edit", reports[0])

    def test_the_summary_is_the_first_tab_and_the_controls_tab_is_second(self):
        """The Controls tab carries each control's remediation sentence, and it is written
        before the group tabs for the reason the findings workbook writes it first: a tab that
        links into another's rows must come after it."""
        names = sheet_names(build_remediation_workbook()[0])

        self.assertEqual(names[:2], ["Summary", "Controls"])

    def test_there_is_a_tab_for_every_group(self):
        names = sheet_names(build_remediation_workbook()[0])

        self.assertEqual(len(names), len(REMEDIATION_GROUPS) + 2)
        for group in REMEDIATION_GROUPS:
            with self.subTest(group.slug):
                self.assertIn(remediation_sheet.sheet_title(group), names)

    def test_a_group_tab_carries_the_features_a_findings_tab_carries(self):
        content = build_remediation_workbook()[0]
        names = sheet_names(content)
        index = names.index("Security rule") + 1
        sheet = worksheet_xml(content, index)
        table = table_definitions(content)["Remediationsecurityrule"]

        # The tab's colour is its PAN-OS category's - Policies, here.
        self.assertIn('<tabColor rgb="FFC55A11"/>', sheet)
        # Header rows frozen, as every findings tab freezes them.
        self.assertIn('state="frozen"', sheet)
        # A real Excel table, with its filter buttons.
        self.assertIn("autoFilter", table)

    def test_the_object_column_is_headed_by_the_kind_of_object(self):
        content = build_remediation_workbook()[0]
        table = table_definitions(content)["Remediationzone"]

        headers = re.findall(r'<tableColumn [^>]*name="([^"]+)"', table)
        self.assertEqual(headers[:8], ["Edit on", "Authority", "Location", "Zone",
                                       "In force on", "Findings", "Severity", "Controls"])

    def test_the_object_column_gives_way_where_a_value_column_has_its_name(self):
        """An Excel table requires unique headers. The Interfaces sheet has a column called
        `Interface` and the login-banner sheet one called `Login Banner`, and both have to stay:
        `Login Banner` holds the banner's text while the row is named for the appliance."""
        group = next(g for g in REMEDIATION_GROUPS if g.slug == "interface")

        self.assertEqual(remediation_sheet.object_heading(group, ["Interface", "LLDP enabled"]),
                         "Object")
        self.assertEqual(remediation_sheet.object_heading(group, ["LLDP enabled"]), "Interface")

    def test_building_it_does_not_change_the_findings_workbook(self):
        """It remains the detailed findings artifact - Jason, 2026-11-03: *"do not modify the
        existing xlsx artifact with the remediation views were working on right now."*"""
        before = sheet_names(build_workbook()[0])

        build_remediation_workbook()

        self.assertEqual(sheet_names(build_workbook()[0]), before)
        self.assertNotIn("Remediation", before)
