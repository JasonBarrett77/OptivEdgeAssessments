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
from assessments.finding_run import regenerate_findings
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementNode, EnforcementPoint, LoginBanner,
    ManagementStation, Snapshot)
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
        # A real finding, because the guard asks the finding models what they point AT - a
        # snapshot on its own is history, not a deliverable. PAN-MGT-007 on an empty banner is
        # the cheapest one finding in this suite.
        LoginBanner.objects.create(
            management_station=self.station, appliance=self.inside,
            source_snapshot=self.snapshot, text="", acknowledgement_required=False)
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()

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
            scope.scope_report()

        self.assertIn("is in scope", str(raised.exception))

    def test_a_retired_point_whose_vsys_is_still_in_scope_is_not_outside_it(self):
        """THE PRODUCTION BLOCKER, 2026-11-07. `retire_superseded_enforcement_points` clears
        `in_scope` on the points an appliance moved away from when an HA pair comes up and
        carries the choice to the new rows. Jason: *"I haven't changed scope recently, and I
        really don't want to go through a collection again."* He had not: the vsys was in scope
        through a replacement row while the configuration behind the findings hung off the
        retired one, and the first version of this refused the build over it.
        """
        self.snapshot.enforcement_point = self.in_point
        self.snapshot.save(update_fields=["enforcement_point"])
        self.in_point.in_scope = False
        self.in_point.is_missing = True
        self.in_point.save(update_fields=["in_scope", "is_missing"])
        # The replacement row, which is what the retirement creates: the pair comes up, the
        # appliance moves into the new HA group, and the point is recreated THERE - one point
        # per (group, vsys), which is why the old row is left behind rather than updated.
        pair = ApplianceGroup.objects.create(
            management_station=self.station, name="ha-pair-in",
            group_type=ApplianceGroup.TYPE_HA_PAIR)
        self.inside.appliance_group = pair
        self.inside.save(update_fields=["appliance_group"])
        replacement = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=pair,
            vsys_name="vsys1", vsys_display_name="trust", in_scope=True)
        EnforcementNode.objects.create(management_station=self.station, appliance=self.inside,
                                       enforcement_point=replacement)

        self.assertEqual(scope.findings_outside_scope(), [])
        self.assertEqual(scope.scope_report(), [])

    def test_a_vsys_with_no_in_scope_row_anywhere_is_reported_not_refused(self):
        """Reported beside the other counts rather than blocking the deliverable: a device is
        only ever collected through an in-scope point, so what reaches here is a row the estate
        reorganized, and the remedy is a collection the engineer may not want to run today."""
        self.snapshot.enforcement_point = self.in_point
        self.snapshot.save(update_fields=["enforcement_point"])
        self.in_point.in_scope = False
        self.in_point.save(update_fields=["in_scope"])
        self.out_point.vsys_name = "vsys9"
        self.out_point.in_scope = True
        self.out_point.save(update_fields=["vsys_name", "in_scope"])

        report = scope.scope_report()

        self.assertEqual(len(report), 1)
        self.assertIn("login banner on fw-in-scope / vsys1", report[0])
        self.assertIn("no longer the one in scope for its vsys", report[0])

    def test_the_build_still_produces_a_workbook_and_says_so_in_its_report(self):
        """What the refusal cost: the engineer got no file at all."""
        self.snapshot.enforcement_point = self.in_point
        self.snapshot.save(update_fields=["enforcement_point"])
        self.in_point.in_scope = False
        self.in_point.save(update_fields=["in_scope"])
        self.out_point.vsys_name = "vsys9"
        self.out_point.in_scope = True
        self.out_point.save(update_fields=["vsys_name", "in_scope"])

        content, reports = build_workbook()

        self.assertTrue(content.startswith(b"PK"))
        self.assertTrue(any(line.startswith("Scope:") for line in reports))


    def test_a_collection_from_before_scope_changed_does_not_refuse_the_build(self):
        """Snapshots ACCUMULATE - nothing deletes one - so an estate holds collections from
        before scope last changed. The first version of this guard asked whether any snapshot
        was out of scope and would have refused a build over history rather than over anything
        in the deliverable. On the lab that is 1,062 snapshots against the 10 its findings
        reference.
        """
        self.out_point.vsys_name = "vsys9"
        self.out_point.save(update_fields=["vsys_name"])
        stale = Snapshot.objects.create(
            management_station=self.station, appliance=self.outside,
            enforcement_point=self.out_point, source_type="show_merged_config",
            collected_at=timezone.now(), payload={})

        self.assertIn(stale.pk, set(
            scope.snapshots_out_of_scope().values_list("pk", flat=True)))
        self.assertEqual(scope.findings_outside_scope(), [])   # nothing points at it: history



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
