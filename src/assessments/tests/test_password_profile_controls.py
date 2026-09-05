"""PAN-AUTH-026 - password profiles that weaken the global policy.

The whole control is one comparison, and the comparison is not `profile > global`. Zero is a
sentinel on BOTH sides: it means the password NEVER EXPIRES, which is the weakest setting on the
field rather than the strictest.

The corpus note says to "flag any larger value". The lab holds the case that breaks it - a
profile with expiration-period 365 on a device whose global is 0 - where the profile is
numerically larger and semantically STRONGER. Flagging it would report a profile that improves
the policy it overrides.
"""

from __future__ import annotations

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import (
    AssessmentRun, Control, ControlQuery, PasswordProfileFinding)
from assessments.password_profile_findings import generate_password_profile_findings
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ManagementStation, PasswordProfile, Snapshot,
    expiration_weakens)


class ExpirationComparisonTests(SimpleTestCase):
    """The rule alone, with no database - it is the entire control."""

    def test_a_global_that_never_expires_cannot_be_weakened(self):
        """The lab's real case. 365 is larger than 0 and stronger than it."""
        self.assertFalse(expiration_weakens(365, 0))
        self.assertFalse(expiration_weakens(0, 0))

    def test_a_profile_that_never_expires_weakens_one_that_does(self):
        self.assertTrue(expiration_weakens(0, 90))

    def test_a_longer_period_weakens(self):
        self.assertTrue(expiration_weakens(180, 90))

    def test_a_shorter_or_equal_period_does_not(self):
        self.assertFalse(expiration_weakens(60, 90))
        self.assertFalse(expiration_weakens(90, 90))

    def test_the_naive_rule_is_wrong_in_BOTH_directions(self):
        """Documents the corpus note's error rather than describing it.

        "Flag any larger value" does not merely miss a nuance - it produces a false positive AND
        a false negative, one at each sentinel:

            profile 365, global 0   naive FLAGS a profile that is stronger than the policy
            profile 0,   global 90  naive PASSES a profile that never expires at all

        The second is the dangerous one. A profile that exempts its accounts from expiry
        entirely is exactly what this control exists to find, and the obvious comparison walks
        straight past it.
        """
        cases = [(365, 0), (0, 90), (180, 90), (60, 90), (90, 90), (0, 0)]
        naive = {c: c[0] > c[1] for c in cases}
        actual = {c: expiration_weakens(*c) for c in cases}
        self.assertEqual(sorted(c for c in cases if naive[c] != actual[c]),
                         [(0, 90), (365, 0)])
        self.assertTrue(naive[(365, 0)] and not actual[(365, 0)])      # false positive
        self.assertTrue(actual[(0, 90)] and not naive[(0, 90)])        # false negative


class PasswordProfileControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.pp")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-pp",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-PP", hostname="fw-pp")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        spec = {c["control_id"]: c
                for c in load_seed_payload()["catalogs"][0]["controls"]}["PAN-AUTH-026"]
        control = Control.objects.create(
            control_id="PAN-AUTH-026", name=spec["name"],
            control_type=Control.ControlType.PASSWORD_PROFILE,
            description=spec["description"], default_severity=spec["default_severity"],
            target_model=spec["target_model"])
        for query in spec["queries"]:
            ControlQuery.objects.create(
                control=control, name=query["name"],
                canonical_query=query["canonical_query"],
                is_baseline=query["is_baseline"], is_active=query["is_active"])
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _profile(self, name, period, global_period):
        return PasswordProfile.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot, name=name,
            expiration_period=period, global_expiration_period=global_period,
            weakens_global_expiration=expiration_weakens(period, global_period))

    def _fires(self, name):
        generate_password_profile_findings(self.run)
        return PasswordProfileFinding.objects.filter(
            password_profile__name=name).exists()

    def test_the_lab_case_does_not_fire(self):
        self._profile("stronger", 365, 0)
        self.assertFalse(self._fires("stronger"))

    def test_a_never_expiring_profile_over_an_expiring_global_fires(self):
        self._profile("never", 0, 90)
        self.assertTrue(self._fires("never"))

    def test_a_longer_period_fires(self):
        self._profile("longer", 180, 90)
        self.assertTrue(self._fires("longer"))

    def test_a_shorter_period_does_not(self):
        self._profile("shorter", 30, 90)
        self.assertFalse(self._fires("shorter"))

    def test_the_finding_names_both_operands(self):
        """A conclusion an engineer cannot check is not actionable."""
        self._profile("longer", 180, 90)
        generate_password_profile_findings(self.run)
        summary = PasswordProfileFinding.objects.get(
            password_profile__name="longer").summary
        self.assertIn("expires after 180 days", summary)
        self.assertIn("expires after 90 days", summary)
