"""PAN-AAA-012 - a local fallback inside a sequence an administrator authenticates through.

The administrative clause is the control: the Help recommends putting a local profile last in
every sequence for resilience, so without it this fires on the vendor's own advice everywhere.
The lab carries the pair these tests mirror - `oep-seq-fallback-local` bound to an
administrator, and `oep-seq-portal`, the identical members behind an authentication object.
"""

from django.test import TestCase
from django.utils import timezone

from assessments.authentication_sequence_findings import generate_authentication_sequence_findings
from assessments.models import AssessmentRun, AuthenticationSequenceFinding, Control
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication import (
    normalize_authentication_profiles)
from optivedge_integrations.integrations.platforms.pan_os.normalization.authentication_sequences import (
    normalize_authentication_sequences)

PROFILES = [
    {"@name": "radius-p", "method": {"radius": {"server-profile": "r"}}},
    {"@name": "tacacs-p", "method": {"tacplus": {"server-profile": "t"}}},
    {"@name": "local-p", "method": {"local-database": None}},
    {"@name": "none-p", "method": {"none": None}},
]


class SequenceFallbackTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.aseq")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-aseq",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-ASEQ", hostname="fw-aseq")
        seed_controls(["PAN-AAA-012"], control_type=Control.ControlType.AUTHENTICATION_SEQUENCE)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _fired(self, members, *, admin=True, device_wide=False):
        config = {
            "shared": {"authentication-profile": {"entry": PROFILES},
                       "authentication-sequence": {"entry": [
                           {"@name": "seq", "authentication-profiles": {"member": members}}]}},
            "devices": {"entry": [{"@name": "localhost.localdomain"}]},
        }
        if admin and device_wide:
            config["devices"]["entry"][0]["deviceconfig"] = {
                "system": {"authentication-profile": "seq"}}
        elif admin:
            config["mgt-config"] = {"users": {"entry": [
                {"@name": "a", "authentication-profile": "seq"}]}}
        else:
            config["devices"]["entry"][0]["vsys"] = {"entry": [
                {"@name": "vsys1", "authentication-object": {"entry": [
                    {"@name": "portal", "authentication-profile": "seq"}]}}]}
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        normalize_authentication_profiles(self.appliance)
        normalize_authentication_sequences(self.appliance)
        generate_authentication_sequence_findings(self.run)
        return list(AuthenticationSequenceFinding.objects.filter(
            authentication_sequence__name="seq"))

    def test_an_administrator_sequence_falling_back_to_local_fires(self):
        findings = self._fired(["radius-p", "local-p"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")
        # The summary lists the members in order with their methods - the order is the meaning.
        self.assertIn("radius-p (RADIUS), then local-p (the local user database)",
                      findings[0].summary)

    def test_the_same_members_behind_captive_portal_do_not_fire(self):
        """The pair: identical members, and no administrator reaches it."""
        self.assertEqual(self._fired(["radius-p", "local-p"], admin=False), [])

    def test_an_all_external_administrator_sequence_does_not_fire(self):
        self.assertEqual(self._fired(["radius-p", "tacacs-p"]), [])

    def test_the_device_wide_binding_reaches_it_too(self):
        """The device-wide leaves refuse a local-database PROFILE and accept a sequence
        containing one - measured 2026-09-11. This is that route."""
        self.assertEqual(len(self._fired(["radius-p", "local-p"], device_wide=True)), 1)

    def test_a_method_none_member_is_a_local_member(self):
        """`none` checks nothing off the box, which is at least as bad as the local store."""
        self.assertEqual(len(self._fired(["radius-p", "none-p"])), 1)

    def test_local_first_fires_as_well_as_local_last(self):
        self.assertEqual(len(self._fired(["local-p", "radius-p"])), 1)

    def test_an_unresolvable_member_is_not_counted_as_local(self):
        """It proves nothing either way; `unresolved_member_count` carries it instead."""
        self.assertEqual(self._fired(["radius-p", "ghost"]), [])
