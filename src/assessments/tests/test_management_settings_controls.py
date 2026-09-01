"""PAN-MGT-007/008/009/011 — the four management settings, end to end.

The defaults are the whole risk here. `server-verification` absent means ENABLED and
`enable-log-high-dp-load` absent means DISABLED, measured from the UI on a device with both
keys absent. One shared assumption would have flagged every device for 009 and no device for
011 — wrong in both directions at once — so each control is tested against a profile built
from an EMPTY payload, which is what an untouched device produces.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.controls_catalog.registry import load_seed_payload
from assessments.device_configuration_findings import generate_device_configuration_findings
from assessments.models import (
    AssessmentRun, Control, ControlQuery, DeviceConfigurationFinding)
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, DeviceConfigurationProfile, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_device_configuration)

CONTROLS = ("PAN-MGT-007", "PAN-MGT-008", "PAN-MGT-009", "PAN-MGT-011")


class ManagementSettingsControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.set")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-set",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        specs = {c["control_id"]: c for c in load_seed_payload()["catalogs"][0]["controls"]}
        for control_id in CONTROLS:
            spec = specs[control_id]
            control = Control.objects.create(
                control_id=control_id, name=spec["name"],
                control_type=Control.ControlType.DEVICE_CONFIGURATION,
                description=spec["description"],
                default_severity=spec["default_severity"],
                target_model=spec["target_model"])
            for query in spec["queries"]:
                ControlQuery.objects.create(
                    control=control, name=query["name"],
                    canonical_query=query["canonical_query"],
                    is_baseline=query["is_baseline"], is_active=query["is_active"])
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _profile(self, hostname, deviceconfig):
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=f"S-{hostname}", hostname=hostname)
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": {"deviceconfig": deviceconfig}}}})
        normalize_appliance_device_configuration(appliance)
        return DeviceConfigurationProfile.objects.get(appliance=appliance)

    def _findings(self):
        generate_device_configuration_findings(self.run)
        return {
            (f.control.control_id, f.device_configuration_profile.appliance.hostname)
            for f in DeviceConfigurationFinding.objects.select_related(
                "control", "device_configuration_profile__appliance")
        }

    def test_an_untouched_device_fires_007_and_011_only(self):
        """The shape both PA-5220s are actually in: nothing set at all.

        009 must NOT fire - absence means the update server IS verified. 008 must not fire
        either, because without a banner PAN-OS greys the setting out and 007 is the finding
        that matters.
        """
        self._profile("fw-bare", {"system": {}})
        self.assertEqual(self._findings(), {
            ("PAN-MGT-007", "fw-bare"),
            ("PAN-MGT-011", "fw-bare"),
        })

    def test_turning_off_the_default_on_setting_fires_009(self):
        self._profile("fw-off", {"system": {"server-verification": "no"}})
        self.assertIn(("PAN-MGT-009", "fw-off"), self._findings())

    def test_a_fully_hardened_device_fires_nothing(self):
        self._profile("fw-good", {
            "system": {"login-banner": "Authorized users only.",
                       "ack-login-banner": "yes"},
            "setting": {"management": {"enable-log-high-dp-load": "yes"}},
        })
        self.assertEqual(
            {c for c, host in self._findings() if host == "fw-good"}, set())

    def test_a_banner_without_acknowledgement_fires_008_not_007(self):
        self._profile("fw-banner", {
            "system": {"login-banner": "Authorized users only."},
            "setting": {"management": {"enable-log-high-dp-load": "yes"}},
        })
        found = {c for c, host in self._findings() if host == "fw-banner"}
        self.assertEqual(found, {"PAN-MGT-008"})

    def test_008_stays_quiet_without_a_banner_because_panos_greys_it_out(self):
        """Acknowledgement cannot be required without a banner to acknowledge, so reporting
        both would be two findings for one missing thing."""
        self._profile("fw-nobanner", {
            "system": {}, "setting": {"management": {"enable-log-high-dp-load": "yes"}}})
        found = {c for c, host in self._findings() if host == "fw-nobanner"}
        self.assertEqual(found, {"PAN-MGT-007"})
