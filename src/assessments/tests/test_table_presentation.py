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
from django.utils import timezone

import assessments
from optivedge_integrations.integrations.models import (
    Appliance, ManagementStation, Snapshot)

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


class MultiValueCellTests(TestCase):
    """A cell holding several values puts one on each line.

    Jason, 2026-09-27, about the management-SSH page: "In fields where multiple values may
    exist, the values should be separated by new lines." The three algorithm cells were
    comma-joined, which read as a paragraph - and reads as a very WIDE paragraph now that a
    data cell does not wrap (see `TableMarkupTests`).

    The split is made here as text, on newlines, and the template runs every cell through
    `linebreaksbr`: device-supplied values stay escaped, and the workbook already does the
    same, so a page and its tab agree.
    """

    def test_no_presentation_module_comma_joins_a_list(self):
        """Every one of these was a multi-value cell: SSH algorithms, unauthenticated NTP
        servers, SNMP surfaces, revocation checks, sequence members, matched query names."""
        import assessments

        root = Path(assessments.__file__).parent
        offenders = []
        for name in ("configuration_results.py", "views.py"):
            for number, line in enumerate((root / name).read_text(encoding="utf-8").split("\n"), 1):
                if '", ".join' in line:
                    offenders.append(f"{name}:{number} {line.strip()[:70]}")

        self.assertEqual(
            offenders, [],
            "a multi-value cell joins on newlines, not commas; if this really is prose, say so "
            "in a comment and exempt it here")

    def test_the_ssh_algorithm_cells_break_on_newlines(self):
        from optivedge_integrations.integrations.models import ManagementSshSettings

        from assessments import configuration_results as config_results

        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.rows")
        appliance = Appliance.objects.create(
            management_station=station, serial_number="S-rows", hostname="fw-rows")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        settings = ManagementSshSettings.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            profile_name="p", profile_found=True,
            ciphers_below_preferred=True, non_preferred_ciphers=["aes128-cbc", "3des-cbc"],
            kex_below_preferred=True, non_preferred_kex=["diffie-hellman-group1-sha1"],
            macs_below_preferred=True, non_preferred_macs=["hmac-sha1", "hmac-md5"],
            host_key_type="RSA", host_key_bits=2048)

        row = config_results.RESULTS["management-ssh"].row(settings)
        ciphers, macs = row[2], row[4]

        self.assertEqual(ciphers, "aes128-cbc\n3des-cbc")
        self.assertEqual(macs, "hmac-sha1\nhmac-md5")
        self.assertNotIn(", ", ciphers)

    def test_a_sequence_keeps_its_chain_marker_on_the_following_lines(self):
        """The order is the meaning - it is the fallback order - so one per line keeps the
        marker rather than dropping it with the commas."""
        from assessments import configuration_results as config_results

        class FakeSequence:
            member_names = ["first", "second"]
            member_methods = ["ldap", None]
            appliance = "fw"
            scope = "shared"
            vsys_name = ""
            name = "seq"
            has_local_member = False
            is_administrative = True
            referrer_count = 0

        cell = config_results.RESULTS["authentication-sequence"].row(FakeSequence())[3]

        self.assertEqual(cell, "first (ldap)\n> second (not found)")
