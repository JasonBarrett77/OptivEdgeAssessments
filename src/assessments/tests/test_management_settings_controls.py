"""PAN-MGT-007/008/009/011 — the four management settings, end to end.

The four now live on FOUR subjects, all cut out of `DeviceConfigurationProfile` on 2026-09-10:
`LoginBanner` for 007 and 008, `UpdateServerSettings` for 009, `LoggingSettings` for 011. They
stay in one test module because the assertion that matters spans them - an untouched device
fires three of the four, and getting that right needs the two OPPOSITE defaults read correctly
at once, which is exactly what a per-model test file would stop checking.

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
from assessments.logging_settings_findings import generate_logging_settings_findings
from assessments.login_banner_findings import generate_login_banner_findings
from assessments.update_server_settings_findings import (
    generate_update_server_settings_findings)
from assessments.models import (
    AssessmentRun, Control, ControlQuery, LoggingSettingsFinding, LoginBannerFinding,
    UpdateServerSettingsFinding)
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_login_banner, normalize_appliance_services_settings)

CONTROLS = ("PAN-MGT-007", "PAN-MGT-008", "PAN-MGT-009", "PAN-MGT-011")
#: Which subject each control now reads. Two of the four have moved.
CONTROL_TYPE = {
    "PAN-MGT-007": Control.ControlType.LOGIN_BANNER,
    "PAN-MGT-008": Control.ControlType.LOGIN_BANNER,
    "PAN-MGT-009": Control.ControlType.UPDATE_SERVER,
    "PAN-MGT-011": Control.ControlType.LOGGING_SETTINGS,
}


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
                control_type=CONTROL_TYPE[control_id],
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
        normalize_appliance_login_banner(appliance)
        normalize_appliance_services_settings(appliance)
        return appliance

    def _findings(self):
        """All three generators, unioned. The controls are still four; the subjects are now
        four, and a caller asking "what fired on this device" should not have to know which."""
        generate_login_banner_findings(self.run)
        generate_update_server_settings_findings(self.run)
        generate_logging_settings_findings(self.run)
        found = set()
        for model, subject in ((LoginBannerFinding, "login_banner"),
                               (UpdateServerSettingsFinding, "update_server_settings"),
                               (LoggingSettingsFinding, "logging_settings")):
            for f in model.objects.select_related("control", f"{subject}__appliance"):
                found.add((f.control.control_id, getattr(f, subject).appliance.hostname))
        return found

    def test_an_untouched_device_fires_007_008_and_011(self):
        """The shape both PA-5220s are actually in: nothing set at all.

        009 must NOT fire - absence means the update server IS verified, so an untouched
        device satisfies it. The other three all report, including 008 on a device with no
        banner: acknowledgement being off is its own gap, and remediating it happens to
        require a banner first.
        """
        self._profile("fw-bare", {"system": {}})
        self.assertEqual(self._findings(), {
            ("PAN-MGT-007", "fw-bare"),
            ("PAN-MGT-008", "fw-bare"),
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

    def test_008_reports_without_a_banner_too(self):
        """The two are independent gaps, reported independently.

        PAN-OS greys acknowledgement out until a banner exists, so remediation is ordered -
        but an unordered pair of findings is what the assessor is owed, not one standing in
        for the other.
        """
        self._profile("fw-nobanner", {
            "system": {}, "setting": {"management": {"enable-log-high-dp-load": "yes"}}})
        found = {c for c, host in self._findings() if host == "fw-nobanner"}
        self.assertEqual(found, {"PAN-MGT-007", "PAN-MGT-008"})
