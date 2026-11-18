"""`remove_decommissioned_devices`: the rows a replaced device left behind, and only those.

A cloud NGFW instance registers with its own serial, so a redeploy leaves a whole identity
behind - appliance row, standalone group, vsys1 enforcement point, snapshots, rules, findings -
and nothing retires it. On a production estate 2026-11-18 that was half of one firewall's
45,948 findings, read from instances that had ceased to exist.

This command writes, so what it REFUSES matters as much as what it removes: an appliance the
engagement is on, a point in scope, or a point shared with a device that is still live. Each
of those means the ids are wrong.
"""

from __future__ import annotations

import io

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from assessments import finding_registry
from assessments.finding_run import regenerate_findings
from assessments.tests._seed import seed_controls
from assessments.tests.test_findings_views import build_estate
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementNode, EnforcementPoint, ManagementStation, Snapshot)


class RemoveDecommissionedDevicesTests(TestCase):
    """One live instance and one replaced one, each a whole identity of its own."""

    def setUp(self):
        build_estate(hostname="cfw-live")
        seed_controls(["PAN-MGT-007", "PAN-MGT-001"])
        regenerate_findings()
        self.station = ManagementStation.objects.first()
        self.live = Appliance.objects.get(hostname="cfw-live")
        self.live_point = self.point(self.live, self.live.appliance_group, in_scope=True)
        self.dead, self.dead_point = self.instance("S-DEAD")
        self.dead_snapshot = Snapshot.objects.create(
            management_station=self.station, enforcement_point=self.dead_point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload={})

    def instance(self, serial: str):
        """A whole identity: its own appliance row, its own group, its own vsys1 point."""
        group = ApplianceGroup.objects.create(
            management_station=self.station, name=f"standalone-{serial}",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=group, hostname="cfw-live",
            serial_number=serial)
        return appliance, self.point(appliance, group, in_scope=False)

    def point(self, appliance, group, *, in_scope: bool):
        point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=group, vsys_name="vsys1",
            in_scope=in_scope)
        EnforcementNode.objects.create(management_station=self.station, enforcement_point=point,
                                       appliance=appliance)
        return point

    def run_command(self, *args) -> str:
        out = io.StringIO()
        call_command("remove_decommissioned_devices", *args, stdout=out)
        return out.getvalue()

    def test_it_removes_the_identity_and_leaves_the_live_one_alone(self):
        output = self.run_command("--appliances", str(self.dead.pk))

        self.assertFalse(Appliance.objects.filter(pk=self.dead.pk).exists())
        self.assertFalse(EnforcementPoint.objects.filter(pk=self.dead_point.pk).exists())
        self.assertFalse(Snapshot.objects.filter(pk=self.dead_snapshot.pk).exists())
        self.assertFalse(ApplianceGroup.objects.filter(name="standalone-S-DEAD").exists())
        self.assertIn("Appliance removed:", output)

        self.assertTrue(Appliance.objects.filter(pk=self.live.pk).exists())
        self.assertTrue(EnforcementPoint.objects.filter(pk=self.live_point.pk).exists())

    def test_a_finding_read_from_a_doomed_snapshot_goes_first_rather_than_blocking(self):
        """`FindingBase.snapshot` is PROTECT. A finding left pointing at one of these snapshots
        raises ProtectedError and rolls the whole removal back, so they are deleted here -
        which is also the point of the exercise, since those findings are the stale half of
        the report."""
        kind = next(kind for kind in finding_registry.FINDING_KINDS
                    if kind.model.objects.exists())
        kind.model.objects.update(snapshot=self.dead_snapshot)
        doomed = kind.model.objects.count()
        self.assertTrue(doomed)

        output = self.run_command("--appliances", str(self.dead.pk))

        self.assertEqual(kind.model.objects.count(), 0)
        self.assertIn(f"findings removed:        {doomed:>9,}", output)

    def test_it_refuses_an_appliance_the_engagement_is_on(self):
        with self.assertRaises(CommandError) as refusal:
            self.run_command("--appliances", str(self.live.pk))

        self.assertIn("this engagement is on", str(refusal.exception))
        self.assertTrue(Appliance.objects.filter(pk=self.live.pk).exists())

    def test_it_refuses_a_point_that_is_in_scope(self):
        """An appliance out of scope whose group carries a ticked point is a contradiction,
        not a licence.

        Reaching this needs the point ticked while the appliance stays OUT of scope, which
        `get_in_scope_appliances` allows in exactly one way: it prefers a point's node rows
        over its group's members, so a ticked point on the dead group whose node names a live
        appliance puts that one in scope and not this one.
        """
        ticked = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.dead.appliance_group,
            vsys_name="vsys2", in_scope=True)
        EnforcementNode.objects.create(management_station=self.station,
                                       enforcement_point=ticked, appliance=self.live)

        with self.assertRaises(CommandError) as refusal:
            self.run_command("--appliances", str(self.dead.pk))

        self.assertIn(f"point {ticked.pk}", str(refusal.exception))
        self.assertTrue(Appliance.objects.filter(pk=self.dead.pk).exists())

    def test_it_refuses_a_point_shared_with_an_appliance_that_was_not_named(self):
        """An HA pair where only one member was named: removing the point would take the other
        member's configuration with it."""
        other, _point = self.instance("S-PEER")
        EnforcementNode.objects.create(management_station=self.station,
                                       enforcement_point=self.dead_point, appliance=other)

        with self.assertRaises(CommandError) as refusal:
            self.run_command("--appliances", str(self.dead.pk))

        self.assertIn("shared with an appliance that was not named", str(refusal.exception))
        self.assertTrue(EnforcementPoint.objects.filter(pk=self.dead_point.pk).exists())

    def test_an_id_no_appliance_has_is_refused_rather_than_skipped(self):
        """Silently removing four of five named rows would read as success."""
        with self.assertRaises(CommandError) as refusal:
            self.run_command("--appliances", str(self.dead.pk), "999999")

        self.assertIn("999999", str(refusal.exception))
        self.assertTrue(Appliance.objects.filter(pk=self.dead.pk).exists())

    def test_a_group_still_holding_an_appliance_is_left_where_it_is(self):
        """Only the groups the removal itself emptied go. A shared group is a live row."""
        survivor = Appliance.objects.create(
            management_station=self.station, appliance_group=self.dead.appliance_group,
            hostname="cfw-live", serial_number="S-STILL-HERE")

        self.run_command("--appliances", str(self.dead.pk))

        self.assertTrue(Appliance.objects.filter(pk=survivor.pk).exists())
        self.assertTrue(ApplianceGroup.objects.filter(
            pk=survivor.appliance_group_id).exists())
