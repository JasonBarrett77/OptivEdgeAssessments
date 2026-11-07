"""What the engagement assessed, and that the artifacts list nothing else.

Jason, 2026-11-07: *"In at least two of the artifacts ... the firewalls/enforcement points
being listed are outside of the list of in-scope enforcement points"*, then *"an out-of-scope
firewall should vanish from Reviewed Devices"* and *"findings measured on an out-of-scope vsys
should leave the counts as well as the lists"*.
"""

from __future__ import annotations

import datetime as dt
import io
import re
import zipfile

from django.test import TestCase
from django.utils import timezone

from assessments.artifacts import (
    ArtifactBuildError, build_health_check_document, build_workbook)
from assessments.artifacts import scope
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementNode, EnforcementPoint, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.flows import get_in_scope_appliances


def sheet_text(content: bytes, title: str) -> str:
    """One worksheet's text, read out of the built file rather than off what built it."""
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        book = archive.read("xl/workbook.xml").decode("utf-8")
        rels = dict(re.findall(r'Id="rId(\d+)"[^>]*Target="(worksheets/[^"]+)"',
                               archive.read("xl/_rels/workbook.xml.rels").decode("utf-8")))
        rid = dict(re.findall(r'<sheet name="([^"]+)"[^>]*r:id="rId(\d+)"', book))[title]
        shared = re.findall(r"<t[^>]*>([^<]*)</t>",
                            archive.read("xl/sharedStrings.xml").decode("utf-8"))
        sheet = archive.read("xl/" + rels[rid]).decode("utf-8")
    used = [int(index) for index in re.findall(r'<c [^>]*t="s"[^>]*><v>(\d+)</v>', sheet)]
    return "\n".join(shared[index] for index in used if index < len(shared))


class _Estate(TestCase):
    """Two firewalls on one Panorama: one in scope, one the inventory merely found.

    THE OUT-OF-SCOPE ONE HAS AN ENFORCEMENT POINT, not none. That is what normalizing `show
    managed devices` produces - a row per vsys it observes, `in_scope` defaulting False - and
    it is the shape the whole fix is about. It has NO SNAPSHOT, because a device is only
    collected through an in-scope point.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            hostname="panorama-1.example.net",
            station_type=ManagementStation.StationType.PAN_PANORAMA)
        self.in_group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-in",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.inside = Appliance.objects.create(
            management_station=self.station, appliance_group=self.in_group,
            serial_number="S-in", hostname="fw-in-scope")
        self.in_point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.in_group,
            vsys_name="vsys1", vsys_display_name="trust", in_scope=True)
        EnforcementNode.objects.create(management_station=self.station, appliance=self.inside,
                                       enforcement_point=self.in_point)
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.inside,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

        self.out_group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-out",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.outside = Appliance.objects.create(
            management_station=self.station, appliance_group=self.out_group,
            serial_number="S-out", hostname="fw-out-of-scope")
        self.out_point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.out_group,
            vsys_name="vsys1", vsys_display_name="dmz")
        EnforcementNode.objects.create(management_station=self.station, appliance=self.outside,
                                       enforcement_point=self.out_point)


class ScopeTests(_Estate):
    def test_only_the_firewall_with_an_in_scope_point_is_in_scope(self):
        self.assertEqual(list(scope.appliances_in_scope()), [self.inside])

    def test_it_agrees_with_the_rule_collection_itself_follows(self):
        """The reason this module resolves scope through `get_in_scope_appliances` rather than
        writing the join again: the devices this engagement assessed are exactly the devices
        collection visited, and a second copy of that rule is a second chance to disagree."""
        expected = set()
        for station in ManagementStation.objects.all():
            expected.update(get_in_scope_appliances(station))

        self.assertEqual(set(scope.appliances_in_scope()), expected)
        self.assertTrue(expected)

    def test_a_retired_point_is_not_in_scope(self):
        """What filled the No rows on the lab: nine points left behind when the fw-core-tpa-a/b
        pair came up, scope carried to their replacements and cleared on them."""
        self.in_point.in_scope = False
        self.in_point.is_missing = True
        self.in_point.save(update_fields=["in_scope", "is_missing"])

        self.assertNotIn(self.inside, scope.appliances_in_scope())

    def test_an_estate_with_no_enforcement_points_has_everything_in_scope(self):
        """Nothing in this suite's fixtures models an enforcement point, because a control test
        seeds the configuration a control reads. Treating those as out of scope would build an
        empty workbook for every artifact test."""
        EnforcementNode.objects.all().delete()
        EnforcementPoint.objects.all().delete()

        self.assertEqual(set(scope.appliances_in_scope()),
                         {self.inside, self.outside})
        self.assertEqual(set(scope.management_stations_in_scope()), {self.station})

    def test_an_estate_with_points_and_none_in_scope_refuses_the_build(self):
        """Not filtered down to an empty deliverable, which would read as "we found nothing".
        `integrations.views` calls this state `scope_needs_attention`."""
        EnforcementPoint.objects.update(in_scope=False)

        with self.assertRaises(ArtifactBuildError) as raised:
            scope.check_findings_are_in_scope()

        self.assertIn("is in scope", str(raised.exception))

    def test_a_snapshot_on_a_point_unticked_after_collection_refuses_the_build(self):
        """The one way a finding can sit outside scope: the point was in scope when it was
        collected and was unticked afterwards. A guard rather than a filter, Jason 2026-11-07 -
        quietly dropping it would answer a question about the estate by hiding it."""
        self.snapshot.enforcement_point = self.in_point
        self.snapshot.save(update_fields=["enforcement_point"])
        self.in_point.in_scope = False
        self.in_point.save(update_fields=["in_scope"])
        self.out_point.in_scope = True
        self.out_point.save(update_fields=["in_scope"])

        with self.assertRaises(ArtifactBuildError) as raised:
            scope.check_findings_are_in_scope()

        self.assertIn("outside the engagement's scope", str(raised.exception))
        self.assertIn("vsys1", str(raised.exception))


class ArtifactScopeTests(_Estate):
    """The lists a client reads, built from an estate that holds one firewall it must not name."""

    def test_the_appliances_tab_leaves_out_the_firewall_nobody_assessed(self):
        content, _reports = build_workbook()

        text = sheet_text(content, "Appliances")
        self.assertIn("fw-in-scope", text)
        self.assertNotIn("fw-out-of-scope", text)

    def test_the_enforcement_points_tab_lists_only_the_vsys_in_scope(self):
        content, _reports = build_workbook()

        text = sheet_text(content, "Enforcement Points")
        self.assertIn("trust", text)
        self.assertNotIn("dmz", text)

    def test_reviewed_devices_leaves_it_out_of_the_document(self):
        """Jason, 2026-11-07: *"an out-of-scope firewall should vanish from Reviewed
        Devices."*"""
        content, _reports = build_health_check_document(today=dt.date(2026, 11, 7))

        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            text = archive.read("word/document.xml").decode("utf-8")
        self.assertIn("fw-in-scope", text)
        self.assertNotIn("fw-out-of-scope", text)

    def test_the_counts_count_what_was_assessed(self):
        """One firewall, not two - the Project Overview line a client reads first."""
        _content, reports = build_health_check_document(today=dt.date(2026, 11, 7))

        overview = next(line for line in reports if line.startswith("Project Overview:"))
        self.assertIn("1 firewall", overview)
