"""Every Assessments table shows its values whole.

Jason, 2026-09-27: "ensure lines do no break on '-', no truncation, and tables can scroll
horizontally." The three are one rule - a cell shows its value whole and the TABLE scrolls -
and it is carried by `assessments/partials/table_styles.html` keyed on the `oea-table` class.

Static because the CSS cannot be checked by rendering: a page can carry the stylesheet and a
table that does not use the class, and nothing at runtime would say so.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import TestCase
from django.urls import reverse

import assessments

TEMPLATES = Path(assessments.__file__).parent / "templates" / "assessments"
STYLES = "assessments/partials/table_styles.html"


def templates_with_tables():
    return sorted(p for p in TEMPLATES.rglob("*.html") if "<table" in p.read_text(encoding="utf-8"))


class TableMarkupTests(TestCase):
    def test_every_table_asks_for_the_shared_behaviour(self):
        """A table without the class wraps at hyphens again, and only that table does - which
        is the kind of difference nobody notices until a value reads wrong."""
        offenders = []
        for path in templates_with_tables():
            text = path.read_text(encoding="utf-8")
            for tag in re.findall(r"<table[^>]*>", text):
                if "oea-table" not in tag:
                    offenders.append(f"{path.relative_to(TEMPLATES)}: {tag}")

        self.assertEqual(offenders, [])

    def test_no_table_fixes_its_layout(self):
        """`table-layout: fixed` hands each column a width and makes the content fit it, which
        is the other half of truncation."""
        offenders = [str(p.relative_to(TEMPLATES)) for p in TEMPLATES.rglob("*.html")
                     if "table-fixed" in p.read_text(encoding="utf-8")]

        self.assertEqual(offenders, [])

    def test_nothing_clips_a_cell(self):
        offenders = []
        for path in templates_with_tables():
            for line in path.read_text(encoding="utf-8").split("\n"):
                if ("<td" in line or "<th" in line) and ("truncate" in line
                                                         or "text-ellipsis" in line
                                                         or "line-clamp" in line):
                    offenders.append(f"{path.relative_to(TEMPLATES)}: {line.strip()[:70]}")

        self.assertEqual(offenders, [])

    def test_the_stylesheet_says_what_it_is_for(self):
        """The hyphen is the whole reason: it is a soft wrap opportunity per UAX #14, so
        `aes256-gcm` was fair game for the line breaker."""
        text = (TEMPLATES / "partials" / "table_styles.html").read_text(encoding="utf-8")

        self.assertIn("white-space: nowrap", text)
        self.assertIn("table-layout: auto", text)
        # Prose opts back in; a description held on one line scrolls the page for no reason.
        self.assertIn(".oea-prose", text)


class RenderedPageTests(TestCase):
    """The stylesheet has to REACH the page. Several of these pages extend base.html directly
    and had no head block at all, so an include on the explorer's base would have missed them."""

    def test_every_table_page_carries_the_stylesheet(self):
        for name in ("assessment_control_list", "assessment_catalog_list",
                     "assessment_findings_summary", "assessment_configuration_index"):
            with self.subTest(name):
                response = self.client.get(reverse(name))
                self.assertContains(response, "white-space: nowrap")

    def test_a_findings_domain_page_carries_it(self):
        response = self.client.get(
            reverse("assessment_findings_domain", kwargs={"slug": "login-banner"}))

        self.assertContains(response, "white-space: nowrap")
        self.assertContains(response, "oea-table")

    def test_a_query_page_carries_it(self):
        response = self.client.get(
            reverse("assessment_configuration_object", args=["network", "interface-mgmt"]))

        self.assertContains(response, "white-space: nowrap")
        self.assertContains(response, "oea-table")
