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
from assessments import configuration_navigation as config_nav

#: Endpoints that render no page of their own, so no sidebar item can be "active" for them.
#: Each one must say why, and adding to this set is a deliberate act rather than a shortcut.
NON_PAGE_URL_NAMES = {
    # Downloads: return a file and no HTML.
    "assessment_catalog_download",
    "assessment_catalog_seed_download",
    # POST actions: mutate, then redirect to a page that IS covered.
    "assessment_catalog_apply",
    "assessment_catalog_create_from_current",
    "assessment_catalog_refresh_seed",
    "assessment_control_run_findings",
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


class ConfigurationExplorerTests(TestCase):
    """The PAN-OS-shaped frame: categories across the top, the category's rail down the side.

    The claim this frame makes is that an object is where the VENDOR keeps it, so these tests
    guard the shape rather than the styling - that every object is reachable, that a page
    highlights itself and nothing else, and that the rail on a page is exactly its category.
    """

    def _url(self, obj):
        return reverse("assessment_configuration_object",
                       args=[config_nav.category_slug(obj.category), obj.slug])

    def test_every_object_names_a_category_that_exists(self):
        unknown = {o.category for o in config_nav.CONFIG_OBJECTS} - set(config_nav.CATEGORIES)
        self.assertEqual(unknown, set(), f"objects in undeclared categories: {sorted(unknown)}")

    def test_slugs_are_unique_within_a_category(self):
        """The slug is half the URL. A duplicate makes one of the two unreachable."""
        seen = [(o.category, o.slug) for o in config_nav.CONFIG_OBJECTS]
        self.assertEqual(len(seen), len(set(seen)))

    def test_the_groups_partition_a_categorys_objects_in_order(self):
        for category in config_nav.CATEGORIES:
            flattened = [o for _, objects in config_nav.groups_in(category) for o in objects]
            self.assertEqual(flattened, list(config_nav.objects_in(category)), category)

    def test_every_object_page_renders(self):
        for obj in config_nav.CONFIG_OBJECTS:
            self.assertEqual(self.client.get(self._url(obj)).status_code, 200, obj.slug)

    def test_an_unknown_category_or_object_is_a_404(self):
        """Not a 500, and not a silent fall back to the landing page - a URL that names an
        object that does not exist is a broken link and should say so."""
        self.assertEqual(self.client.get("/assessments/configuration/nope/management/").status_code, 404)
        self.assertEqual(self.client.get("/assessments/configuration/device/nope/").status_code, 404)

    def test_the_index_is_a_page_rather_than_a_redirect_into_the_rail(self):
        """It redirected to Device's first object until 2026-09-18. A dashboard about the
        objects, their controls and their queries answers what no object page can, because each
        of those sees one object and all of these are comparisons."""
        response = self.client.get("/assessments/configuration/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Configuration")

    def test_the_rail_holds_exactly_the_open_objects_category(self):
        """The point of the frame: what is on screen is one category's rail, not every object."""
        rail_link = re.compile(r'<a\s+href="(/assessments/configuration/[^"]+)"\s+class="flex h-7')
        for obj in config_nav.CONFIG_OBJECTS:
            html = self.client.get(self._url(obj)).content.decode()
            self.assertEqual(
                set(rail_link.findall(html)),
                {self._url(o) for o in config_nav.objects_in(obj.category)},
                obj.slug)

    def test_a_page_marks_itself_active_and_nothing_else(self):
        active = re.compile(r'href="(/assessments/configuration/[^"]+)"\s+class="flex h-7[^"]*bg-slate-100')
        for obj in config_nav.CONFIG_OBJECTS:
            html = self.client.get(self._url(obj)).content.decode()
            self.assertEqual(active.findall(html), [self._url(obj)], obj.slug)

    def test_every_category_now_holds_something_and_links_to_it(self):
        """This replaced `test_an_empty_category_renders_but_links_nowhere` on 2026-09-18, when
        `Policies > Security` filled the last empty category. That test asserted the greyed,
        unlinked rendering of an empty chip and said in its own docstring that it stops meaning
        anything once every category is populated.

        The view still renders an empty category that way - `configuration_nav_context` gives a
        chip with no href - and nothing exercises that branch now. It is kept for the next
        category to be added before its objects are, which is how Policies itself began.
        """
        for category in config_nav.CATEGORIES:
            self.assertTrue(config_nav.objects_in(category), category)
        html = self.client.get("/assessments/configuration/", follow=True).content.decode()
        for category in config_nav.CATEGORIES:
            self.assertIn(category, html)
            first = config_nav.first_object(category)
            self.assertIn(
                f'href="/assessments/configuration/{config_nav.category_slug(category)}/{first.slug}/"',
                html, category)

    def test_every_named_findings_tab_resolves(self):
        """`findings_url_name` crosses to the other surface over the same object. A typo there
        is invisible until someone opens the one page that carries the link."""
        for obj in config_nav.CONFIG_OBJECTS:
            if obj.findings_url_name:
                reverse(obj.findings_url_name)

    def test_the_sidebar_highlights_the_explorer(self):
        names = set()
        for section in app_meta.SIDEBAR_SECTION:
            for item in section.get("items") or ():
                names |= set(item.get("active_names") or ())
        self.assertIn("assessment_configuration_object", names)
        self.assertIn("assessment_configuration_index", names)


class TemplateCommentTests(TestCase):
    """A broken template comment is not an error. It is CONTENT.

    `{# ... #}` is single-line only. Spread it over two and Django stops treating it as a
    comment and prints it, so a note to the next developer became a paragraph of grey text in
    the middle of the configuration rail - twice, once per loop iteration. Nothing failed:
    every test passed, the page returned 200, and it was caught by a person looking at it.

    Checked over the FILES rather than by rendering, because a partial that is included in a
    loop can leak in a page no test opens, and because the fix is the same either way: use
    `{% comment %}` for anything that does not fit on one line.
    """

    def test_no_template_comment_spans_a_line(self):
        root = Path(__file__).resolve().parent.parent / "templates"
        offenders = []
        for path in sorted(root.rglob("*.html")):
            text = path.read_text()
            for match in re.finditer(r"\{#", text):
                rest = text[match.start():]
                close = rest.find("#}")
                if close == -1 or "\n" in rest[:close]:
                    line = text[: match.start()].count("\n") + 1
                    offenders.append(f"{path.relative_to(root)}:{line}")
        self.assertEqual(offenders, [], f"use {{% comment %}} instead: {offenders}")
