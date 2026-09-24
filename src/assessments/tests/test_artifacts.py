"""The engineer-detail workbook, once it stopped being a script.

The layout was proven by building it against the lab over and over; what was never proven is
the part that only matters inside a long-running process. Two globals and a `SystemExit` were
harmless while the prototype built one workbook and exited, and are not harmless here:

* the anchor map was a module dict, so a second workbook inherited the first one's row
  numbers and linked to the WRONG ROW - silently
* the format caches were keyed by `id(workbook)`, and CPython reuses an address once an
  object is freed
* `SystemExit` derives from `BaseException`, so a guard would take a worker down rather than
  return an error

So these tests are mostly about isolation and refusal, not about layout.
"""

from __future__ import annotations

import datetime
import io
import re
import zipfile
from pathlib import Path

from django.test import TestCase
from django.utils import timezone

from assessments.artifacts import ArtifactBuildError, build_workbook
from assessments.artifacts import layout, workbook as workbook_module
from assessments.artifacts.context import WorkbookBuild
from assessments.finding_run import regenerate_findings
from assessments.models import LoginBannerFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    LoginBanner,
    ManagementStation,
    Snapshot,
)

ARTIFACTS = Path(layout.__file__).resolve().parent


def sheet_names(content: bytes) -> list[str]:
    """The tab names, read from the file itself rather than from what built it."""
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        book = archive.read("xl/workbook.xml").decode("utf-8")
    return re.findall(r'<sheet name="([^"]+)"', book)


def shared_strings(content: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        return archive.read("xl/sharedStrings.xml").decode("utf-8")


class WorkbookBuildTests(TestCase):
    def test_it_builds_on_an_estate_with_nothing_in_it(self):
        """A fresh deployment, or one whose collection has not run. Every tab still draws."""
        content, reports = build_workbook()

        self.assertTrue(content.startswith(b"PK"))
        self.assertIn("Summary: 27 tabs linked, 0 findings in total", reports[0])

    def test_the_summary_is_the_first_tab(self):
        names = sheet_names(build_workbook()[0])

        self.assertEqual(names[0], "Summary")
        self.assertEqual(len(names), 28)

    def test_a_control_type_with_no_active_control_still_draws_its_tab(self):
        """It used to raise IndexError: the category came from the controls that LOADED, and
        deactivating the one control of a type left none to read it from."""
        seed_controls(["PAN-MGT-007"])
        from assessments.models import Control

        Control.objects.update(is_active=False)

        self.assertIn("Login Banner", sheet_names(build_workbook()[0]))


class WorkbookContentTests(TestCase):
    def setUp(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.artifact")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-artifact",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-artifact", hostname="fw-artifact")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            text="", acknowledgement_required=False)
        seed_controls(["PAN-MGT-007"])
        self.run = regenerate_findings().assessment_run

    def test_a_finding_reaches_its_tab_by_its_reference(self):
        finding = LoginBannerFinding.objects.get()
        content, _reports = build_workbook()

        self.assertIn(finding.reference, shared_strings(content))

    def test_the_appliance_it_is_about_is_named(self):
        content, _reports = build_workbook()

        self.assertIn("fw-artifact", shared_strings(content))


class WorkbookIsolationTests(TestCase):
    """Two workbooks in one process must not share anything. This is the whole reason the
    move was not a copy."""

    def test_anchors_do_not_survive_between_builds(self):
        first = WorkbookBuild(workbook=object())
        layout.register_row_anchor(first, "control", 7, "Controls", 5, 9)
        second = WorkbookBuild(workbook=object())

        self.assertIn(("control", 7), first.anchors)
        self.assertEqual(second.anchors, {})

    def test_a_format_belongs_to_one_workbook(self):
        class FakeWorkbook:
            def add_format(self, properties):
                return ("format", id(self), tuple(sorted(properties.items())))

        first = WorkbookBuild(workbook=FakeWorkbook())
        second = WorkbookBuild(workbook=FakeWorkbook())

        self.assertNotEqual(first.format("link", {"bold": True}),
                            second.format("link", {"bold": True}))
        self.assertEqual(first.format("link", {"bold": True}),
                         first.format("link", {"bold": True}))

    def test_the_module_holds_no_build_state(self):
        """The bug was invisible for as long as the process exited after one workbook."""
        source = (ARTIFACTS / "layout.py").read_text(encoding="utf-8")

        self.assertNotIn("ANCHORS", source)
        self.assertNotIn("id(workbook)", source)

    def test_building_twice_gives_two_good_workbooks(self):
        first, _ = build_workbook()
        second, _ = build_workbook()

        self.assertEqual(sheet_names(first), sheet_names(second))
        self.assertTrue(second.startswith(b"PK"))


class WorkbookGuardTests(TestCase):
    def test_a_finding_on_no_tab_refuses_the_build(self):
        """The guard that matters most: a workbook silently missing a finding is worse than
        no workbook, because it is the reference document."""
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.guard")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-guard",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-guard", hostname="fw-guard")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            text="", acknowledgement_required=False)
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()

        with self.assertRaises(ArtifactBuildError) as raised:
            workbook_module.check_every_finding_reached_a_tab([])

        self.assertIn("is on no tab", str(raised.exception))

    def test_tabs_out_of_the_summary_order_refuse_the_build(self):
        from assessments.artifacts.layout import SheetInfo

        out_of_order = [
            SheetInfo(title="a", description="", count="", category="Device",
                      by_severity={"high": 1}, report=""),
            SheetInfo(title="b", description="", count="", category="Policies",
                      by_severity={"high": 1}, report=""),
        ]

        with self.assertRaises(ArtifactBuildError):
            workbook_module.check_tabs_follow_the_summary(out_of_order)

    def test_no_guard_reaches_for_SystemExit(self):
        """It derives from BaseException: under a web server it takes the worker down, and a
        caller's `except Exception` never sees it."""
        offenders = [
            path.relative_to(ARTIFACTS)
            for path in sorted(ARTIFACTS.rglob("*.py"))
            # `raise SystemExit`, not the word - errors.py explains why it is gone.
            if "raise SystemExit" in path.read_text(encoding="utf-8")
        ]

        self.assertEqual(offenders, [])


class TimestampTests(TestCase):
    """Every timestamp column in the workbook is headed "(UTC)"."""

    def test_an_aware_timestamp_is_converted_rather_than_printed_as_it_stands(self):
        somewhere_else = datetime.timezone(datetime.timedelta(hours=-4))
        moment = datetime.datetime(2026, 9, 24, 8, 30, 0, tzinfo=somewhere_else)

        self.assertEqual(layout.utc(moment), "2026-09-24 12:30:00")

    def test_a_naive_timestamp_is_read_as_utc(self):
        """Which is where they come from - a `collected_at` Django stored in UTC - and not
        machine-local, which is what `astimezone` would have assumed."""
        moment = datetime.datetime(2026, 9, 24, 8, 30, 0)

        self.assertEqual(layout.utc(moment), "2026-09-24 08:30:00")

    def test_nothing_is_an_em_dash(self):
        self.assertEqual(layout.utc(None), layout.NONE)
