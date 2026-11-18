"""`print_device_identity`: every row one firewall has, and which of them scope is on.

A scope tick lives on one `EnforcementPoint`; the rules, snapshots and findings hang off
whichever point the collection used. When a device accumulates rows - `Appliance` is unique
per (station, serial number), so one that re-registers gets a new row each time - those can be
different points, and then the engagement is on a vsys that carries nothing while the
configuration that WAS assessed belongs to a firewall no artifact lists. Jason, 2026-11-18, on
a cloud NGFW in production: *"On the enforcement-points tab, I see ten rows with this appliance
name, and two of the rows have a Last Sync that isn't null."*

The lab cannot show it - its four appliances hold one identity each - so these tests build the
shape the command exists to read.
"""

from __future__ import annotations

import datetime as dt
import io

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from assessments.tests.test_findings_views import build_estate
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementNode, EnforcementPoint, ManagementStation, Snapshot)


class DeviceIdentityCommandTests(TestCase):
    """One hostname, two appliance rows, two points: the tick on one, the work on the other."""

    @classmethod
    def setUpTestData(cls):
        build_estate(hostname="cfw-001")
        cls.station = ManagementStation.objects.first()
        cls.collected = Appliance.objects.get(hostname="cfw-001")
        cls.collected_point = cls.point(cls.collected, cls.collected.appliance_group,
                                        in_scope=False)
        cls.registered_again = Appliance.objects.create(
            management_station=cls.station, hostname="cfw-001", serial_number="S-SECOND",
            appliance_group=ApplianceGroup.objects.create(
                management_station=cls.station, name="standalone-S-SECOND",
                group_type=ApplianceGroup.TYPE_STANDALONE))
        cls.ticked_point = cls.point(cls.registered_again,
                                     cls.registered_again.appliance_group, in_scope=True)
        Snapshot.objects.filter(appliance=cls.collected).update(
            appliance=None, enforcement_point=cls.collected_point)

    @classmethod
    def point(cls, appliance, group, *, in_scope: bool):
        point = EnforcementPoint.objects.create(
            management_station=cls.station, appliance_group=group, vsys_name="vsys1",
            in_scope=in_scope)
        EnforcementNode.objects.create(management_station=cls.station, enforcement_point=point,
                                       appliance=appliance)
        return point

    def run_command(self, *args) -> str:
        out = io.StringIO()
        call_command("print_device_identity", *args, stdout=out)
        return out.getvalue()

    def test_it_names_every_appliance_row_the_hostname_holds(self):
        """Two rows, one name. The serial is what tells them apart, so it is printed."""
        output = self.run_command("--name", "cfw-001")

        self.assertIn("appliance rows whose hostname or serial contains 'cfw-001': 2", output)
        self.assertIn(self.collected.serial_number, output)
        self.assertIn("S-SECOND", output)

    def test_a_serial_finds_the_row_as_well_as_a_hostname(self):
        """Which matters precisely because the hostname does not distinguish them."""
        output = self.run_command("--name", "S-SECOND")

        self.assertIn("appliance rows whose hostname or serial contains 'S-SECOND': 1", output)
        self.assertIn(f"appliance {self.registered_again.pk}", output)

    def test_it_says_when_the_tick_and_the_work_are_on_different_rows(self):
        """The sentence the command exists for. One point is in scope and empty; the other
        carries every snapshot and is not."""
        output = self.run_command("--name", "cfw-001")

        self.assertIn(f"in scope: point {self.ticked_point.pk} vsys1", output)
        self.assertIn("THE TICK AND THE WORK ARE ON DIFFERENT ROWS", output)
        self.assertIn(f"point {self.collected_point.pk}", output)

    def test_an_in_scope_row_that_carries_its_own_work_raises_nothing(self):
        """The healthy shape says so by omission: no warning, and the appliance is held."""
        EnforcementPoint.objects.filter(pk=self.collected_point.pk).update(in_scope=True)

        output = self.run_command("--name", self.collected.serial_number)

        self.assertNotIn("THE TICK AND THE WORK ARE ON DIFFERENT ROWS", output)
        self.assertIn("holds 1 of 1 appliance row", output)

    def test_a_name_that_matches_nothing_is_refused_rather_than_printed_empty(self):
        with self.assertRaises(CommandError):
            self.run_command("--name", "no-such-firewall")

    def test_it_writes_nothing(self):
        """A reader runs this against production. It reads five tables and touches none."""
        points = list(EnforcementPoint.objects.values_list("id", "in_scope", "is_missing"))
        appliances = list(Appliance.objects.values_list("id", "appliance_group_id", "hostname"))
        snapshots = list(Snapshot.objects.values_list("id", "enforcement_point_id",
                                                      "collected_at"))

        self.run_command("--name", "cfw-001")

        self.assertEqual(list(EnforcementPoint.objects.values_list(
            "id", "in_scope", "is_missing")), points)
        self.assertEqual(list(Appliance.objects.values_list(
            "id", "appliance_group_id", "hostname")), appliances)
        self.assertEqual(list(Snapshot.objects.values_list(
            "id", "enforcement_point_id", "collected_at")), snapshots)
        self.assertEqual(Snapshot.objects.filter(
            collected_at__gt=dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc)).count(), 0)

    def test_a_row_that_has_never_synced_says_so_rather_than_printing_a_blank(self):
        """Eight of the production device's ten rows have no Last Sync at all, and a blank
        cell there reads as a value nobody recorded rather than as a sync that never ran."""
        Appliance.objects.filter(pk=self.registered_again.pk).update(
            last_synced_at=None)
        Appliance.objects.filter(pk=self.collected.pk).update(
            last_synced_at=timezone.now())

        output = self.run_command("--name", "cfw-001")

        self.assertIn("last synced:  never", output)
