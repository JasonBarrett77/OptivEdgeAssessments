"""The one "Run Configuration Findings" button must reach every non-policy control.

It did not, twice, and nothing failed either time. `GENERATORS` is a hand-kept tuple: the
administrator and AAA-server generators were never added to it, and when the device-configuration
aggregate was split into seven models on 2026-09-10 none of the seven was added either - so the
button silently produced no findings for 22 controls that had worked the day before.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.configuration_findings import GENERATORS, regenerate_configuration_findings
from assessments.finding_registry import FINDING_KINDS
from assessments.models import Control, LoginBannerFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, LoginBanner, ManagementStation, Snapshot)


class ConfigurationRunCoverageTests(TestCase):
    def test_every_non_policy_finding_kind_has_a_generator_in_the_run(self):
        covered = {control_type for _, control_type, _ in GENERATORS}
        expected = {k.control_type for k in FINDING_KINDS} - {Control.ControlType.SECURITY_RULE}
        self.assertEqual(expected - covered, set(), "finding kinds the button never generates")
        self.assertEqual(covered - expected, set(), "generators for kinds the registry does not know")

    def test_the_button_path_produces_a_finding_for_a_moved_control(self):
        """End to end through the same entry point the view calls, on one of the controls the
        split moved: PAN-MGT-007 fires on an appliance with no login banner."""
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.run")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-run", group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-RUN", hostname="fw-run")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.create(management_station=station, appliance=appliance,
                                   source_snapshot=snapshot, text="")
        seed_controls(["PAN-MGT-007"], control_type=Control.ControlType.LOGIN_BANNER)

        result = regenerate_configuration_findings()
        self.assertEqual(result.by_kind["login banner"][1], 1)
        self.assertTrue(LoginBannerFinding.objects.filter(
            control__control_id="PAN-MGT-007", login_banner__appliance=appliance).exists())
