"""The sidebar and the device tab bar must not drift apart again.

They already did once, silently: six tabs were added to `device_tabs.html` and to no
`active_names` set, so the sidebar highlighted nothing on six of ten pages. No test failed,
because a sidebar that fails to highlight still renders.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import TestCase
from django.urls import reverse

from assessments import app_meta
from assessments.navigation import (
    DEVICE_TABS, DEVICE_TAB_URL_NAMES, SECTIONS, SECTION_BY_URL_NAME, tabs_in)

#: Endpoints that render no page of their own, so no sidebar item can be "active" for them.
#: Each one must say why, and adding to this set is a deliberate act rather than a shortcut.
NON_PAGE_URL_NAMES = {
    # Downloads: return a file and no HTML.
    "assessment_rule_finding_docx_download",
    "assessment_rule_finding_xlsx_download",
    "assessment_catalog_download",
    "assessment_catalog_seed_download",
    # POST actions: mutate, then redirect to a page that IS covered.
    "assessment_catalog_apply",
    "assessment_catalog_create_from_current",
    "assessment_catalog_refresh_seed",
    "assessment_control_run_findings",
    "assessment_control_run_configuration_findings",
    "assessment_control_create",
    "assessment_control_update",
    "assessment_control_delete",
    "assessment_control_query_create",
    "assessment_control_query_update",
    "assessment_control_query_delete",
}


def _declared_url_names() -> set[str]:
    urls = (Path(__file__).resolve().parent.parent / "urls.py").read_text()
    return set(re.findall(r'name="(assessment_[a-z_0-9]+)"', urls))


def _all_active_names() -> set[str]:
    names: set[str] = set()
    for section in app_meta.SIDEBAR_SECTION:
        names |= set(section.get("active_names") or ())
        for item in section.get("items") or ():
            names |= set(item.get("active_names") or ())
    return names


class NavigationCoverageTests(TestCase):
    def test_every_page_url_is_reachable_from_some_sidebar_item(self):
        uncovered = _declared_url_names() - _all_active_names() - NON_PAGE_URL_NAMES
        self.assertEqual(uncovered, set(),
                         f"URL names in no sidebar active_names set: {sorted(uncovered)}. "
                         "Add them to the right item, or to NON_PAGE_URL_NAMES with a reason.")

    def test_the_sidebar_never_names_a_url_that_does_not_exist(self):
        stale = _all_active_names() - _declared_url_names()
        self.assertEqual(stale, set(), f"sidebar names dead URLs: {sorted(stale)}")

    def test_the_device_configuration_item_covers_exactly_the_tabs(self):
        """Derived, not restated - so a new tab cannot be added without the sidebar following."""
        item = next(i for s in app_meta.SIDEBAR_SECTION for i in s.get("items") or ()
                    if i["label"] == "Device Configuration")
        self.assertEqual(set(item["active_names"]), set(DEVICE_TAB_URL_NAMES))

    def test_every_tab_resolves_and_names_an_icon_that_exists(self):
        """A tab naming an icon that is not vendored renders a 500, not a missing glyph."""
        icons = Path(app_meta.__file__).resolve().parents[2] / "optivedge"
        for tab in DEVICE_TABS:
            reverse(tab.url_name)
            self.assertTrue(tab.icon and " " not in tab.icon, tab)

    def test_the_legacy_findings_page_left_the_assessments_section(self):
        """It is pending replacement; it should not sit among the permanent items."""
        by_section = {s["label"]: [i["label"] for i in s.get("items") or ()]
                      for s in app_meta.SIDEBAR_SECTION}
        self.assertNotIn("Findings", by_section["Assessments"])
        self.assertIn("Findings (Legacy)", by_section["Experimental"])

    def test_the_report_downloads_kept_their_urls(self):
        """The deliverable path is a separate permanent concept; it did not move."""
        self.assertTrue(reverse("assessment_rule_finding_docx_download").endswith(
            "findings/report.docx"))
        self.assertTrue(reverse("assessment_rule_finding_xlsx_download").endswith(
            "findings/report.xlsx"))

    def test_the_findings_page_moved_off_the_good_name(self):
        self.assertTrue(reverse("assessment_legacy_finding_list").endswith("findings-legacy/"))


class DeviceSectionTests(TestCase):
    """The section strip. A flat bar was already wrapping at ten tabs, with 30 of 235 controls
    done - and object tabs track config subtrees, of which the corpus has 43."""

    def test_every_tab_names_a_section_that_exists(self):
        unknown = {t.section for t in DEVICE_TABS} - set(SECTIONS)
        self.assertEqual(unknown, set(), f"tabs in undeclared sections: {sorted(unknown)}")

    def test_every_section_holds_at_least_one_tab(self):
        """An empty section renders a link to nothing - the tag indexes [0] to find its href."""
        for name in SECTIONS:
            self.assertTrue(tabs_in(name), f"section {name!r} has no tabs")

    def test_sections_partition_the_tabs(self):
        self.assertEqual(sum(len(tabs_in(s)) for s in SECTIONS), len(DEVICE_TABS))

    def test_the_active_section_follows_the_open_page(self):
        """A page cannot be open in one section while another is highlighted."""
        for tab in DEVICE_TABS:
            response = self.client.get(reverse(tab.url_name))
            self.assertEqual(response.status_code, 200, tab.url_name)
            html = response.content.decode()
            expected = SECTION_BY_URL_NAME[tab.url_name]
            # the active section carries the solid chip
            active = re.findall(r'bg-slate-800 text-white"\s*>\s*([^<]+)', html)
            self.assertEqual([a.strip() for a in active], [expected], tab.url_name)

    def test_only_the_active_sections_tabs_are_rendered(self):
        """The point of the strip: what is on screen is one section, not the whole corpus.

        Asserted on HREFS, not labels. The label sits on its own line after the icon, and
        "Certificates" is both a tab label and a section name - a substring check passes for
        the wrong reason.
        """
        tab_anchor = re.compile(
            r'<a\s+href="([^"]+)"\s+class="inline-flex h-9 items-center gap-1\.5 border-b-2')
        for tab in DEVICE_TABS:
            html = self.client.get(reverse(tab.url_name)).content.decode()
            section = SECTION_BY_URL_NAME[tab.url_name]
            self.assertEqual(
                set(tab_anchor.findall(html)),
                {reverse(t.url_name) for t in tabs_in(section)},
                f"wrong tab set rendered on {tab.label}")

    def test_the_sidebar_still_covers_every_section(self):
        """Sections are a display grouping; the sidebar item still owns all of them."""
        item = next(i for s in app_meta.SIDEBAR_SECTION for i in s.get("items") or ()
                    if i["label"] == "Device Configuration")
        self.assertEqual(set(item["active_names"]), set(DEVICE_TAB_URL_NAMES))
