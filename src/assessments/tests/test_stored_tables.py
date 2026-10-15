"""Findings tables kept for their run - see `artifacts/stored.py`.

A stored table is only worth having if it is the table a fresh build would draw. So the first
test here compares the two for every domain, both the pages' version and the workbook's; the
rest pin the conditions under which a stored copy must NOT be used.
"""

from __future__ import annotations

import re
from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from assessments.artifacts import ALL_TESTED_COLUMNS, build_findings_table
from assessments.artifacts import stored
from assessments.artifacts.domains import DOMAINS
from assessments.artifacts.sheets import rules_by_device_group
from assessments.finding_run import open_findings_run, regenerate_findings
from assessments.models import AssessmentRun, Control, PresentedTable
#: Through the module, never by name: a TestCase in this module's namespace would run here too.
from assessments.tests import test_artifacts

RULE_TABLE = re.compile(r'FROM "integrations_securityrule"(?:\s|$)')


def comparable(table):
    return (table.columns, table.rows, sorted(table.implicated), table.row_meta,
            table.by_severity, table.runs)


class StoredTablesTests(TestCase):
    """On the rule estate `test_artifacts.RuleTabsDoNotQueryPerRowTests` builds: every
    security-rule control seeded, and rules that fire all of them - so every rule tab has rows."""

    def setUp(self):
        test_artifacts.RuleTabsDoNotQueryPerRowTests.setUp(self)
        test_artifacts.RuleTabsDoNotQueryPerRowTests.add_rules(self, 3)

    def rule_domains(self):
        return test_artifacts.RuleTabsDoNotQueryPerRowTests.rule_domains(self)

    def test_run_findings_stores_every_table(self):
        keys = set(PresentedTable.objects.values_list("key", flat=True))

        for domain in self.rule_domains():
            self.assertIn(domain.spec.table_name, keys)
        self.assertIn("RulesByDeviceGroup", keys)

    def test_a_stored_table_is_the_table_a_build_draws(self):
        for domain in DOMAINS:
            for tested in (None, ALL_TESTED_COLUMNS):
                with self.subTest(domain.slug, tested=tested):
                    self.assertEqual(
                        comparable(stored.stored_findings_table(domain.spec, tested=tested)),
                        comparable(build_findings_table(domain.spec, tested=tested)))

    def test_the_folded_tab_is_the_fold(self):
        self.assertEqual(rules_by_device_group.stored_fold(), rules_by_device_group.fold())

    def test_a_stored_table_reads_no_subject(self):
        """The point of keeping it: no rules, no member sets."""
        for domain in self.rule_domains():
            with self.subTest(domain.slug), CaptureQueriesContext(connection) as captured:
                table = stored.stored_findings_table(domain.spec)

            self.assertTrue(table.rows)
            self.assertFalse([q for q in captured if RULE_TABLE.search(q["sql"])])

    def test_a_discarded_run_takes_its_tables(self):
        AssessmentRun.objects.all().delete()

        self.assertFalse(PresentedTable.objects.exists())

    def test_a_control_edited_after_the_run_is_not_shown_as_it_was(self):
        """The catalog is part of the fingerprint: a stored table naming the old control would
        disagree with the Controls page."""
        domain = self.rule_domains()[0]
        control = stored.selected_controls(domain.spec).first()
        Control.objects.filter(pk=control.pk).update(name="Renamed after the run")

        table = stored.stored_findings_table(domain.spec)

        self.assertIn("Renamed after the run", {row[2] for row in table.rows})

    def test_new_presentation_code_is_not_shown_the_old_layout(self):
        domain = self.rule_domains()[0]
        before = PresentedTable.objects.get(key=domain.spec.table_name).fingerprint

        with mock.patch.object(stored, "layout_version", return_value="a later release"):
            stored.stored_findings_table(domain.spec)

        self.assertNotEqual(
            PresentedTable.objects.get(key=domain.spec.table_name).fingerprint, before)

    def test_a_count_that_disagrees_is_rebuilt_not_shown(self):
        domain = self.rule_domains()[0]
        row = PresentedTable.objects.get(key=domain.spec.table_name)
        payload = stored._decode(row.payload)
        payload["count"] += 1
        payload["rows"] = []
        PresentedTable.objects.filter(pk=row.pk).update(payload=stored._encode(payload))

        table = stored.stored_findings_table(domain.spec)

        self.assertTrue(table.rows)

    def test_nothing_is_stored_for_a_run_still_filling(self):
        """A page opened mid-run would otherwise keep half a run's findings."""
        PresentedTable.objects.all().delete()
        AssessmentRun.objects.update(status=AssessmentRun.Status.RUNNING)

        for domain in self.rule_domains():
            stored.stored_findings_table(domain.spec)

        self.assertFalse(PresentedTable.objects.exists())


class FindingsPagePagingTests(TestCase):
    def setUp(self):
        test_artifacts.RuleTabsDoNotQueryPerRowTests.setUp(self)
        test_artifacts.RuleTabsDoNotQueryPerRowTests.add_rules(self, 3)
        self.domain = max(test_artifacts.RuleTabsDoNotQueryPerRowTests.rule_domains(self),
                          key=lambda d: len(build_findings_table(d.spec).rows))
        self.total = len(build_findings_table(self.domain.spec).rows)

    def test_a_domain_is_paged_and_its_counts_cover_all_of_it(self):
        url = reverse("assessment_findings_domain", args=[self.domain.slug])
        with mock.patch("assessments.views.FINDINGS_PAGE_SIZE", 2):
            first = self.client.get(url)
            last = self.client.get(url, {"page": 999})

        self.assertEqual(len(first.context["rows"]), 2)
        self.assertEqual(first.context["finding_count"], self.total)
        self.assertContains(first, "data-findings-pager")
        self.assertContains(first, f"{self.total} finding")
        self.assertEqual(len(last.context["rows"]), self.total - 2 * ((self.total - 1) // 2))
        references = [cells[0]["value"] for cells in first.context["rows"]]
        self.assertEqual(references, sorted(references))
