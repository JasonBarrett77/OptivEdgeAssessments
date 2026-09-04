"""PAN-AUTH-014 through 017 - admin lockout, idle timeout, API key lifetime.

Four controls on one PAN-OS screen, and three different shapes. The trap they share is that
ZERO IS NOT A LOW VALUE on any of them - it is a different meaning each time, and on two of
them it is the implicit value, so getting it wrong misreports every unconfigured device in an
estate rather than an unusual one.

    PAN-AUTH-014  0 = lockout DISABLED        worst value, and the default
    PAN-AUTH-015  0 = locked until released   BEST value, and the default
    PAN-AUTH-016  0 = never times out         worst value; the default is 60
    PAN-AUTH-017  0 = keys never expire       the only finding, and the default

014 and 015 sit on the same screen, are set by the same administrator in the same sitting, and
their zeros mean opposite things. Every implicit value here was read off the unconfigured
Authentication Settings form on 2026-09-04 rather than assumed.
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

CONTROLS = ["PAN-AUTH-014", "PAN-AUTH-015", "PAN-AUTH-016", "PAN-AUTH-017"]
#: An untouched device: no lockout, no key expiry, and an hour-long idle session. NOT 015 -
#: its zero is compliant.
UNCONFIGURED = {"PAN-AUTH-014", "PAN-AUTH-016", "PAN-AUTH-017"}


class AdminSessionControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.auth")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-auth",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        specs = {c["control_id"]: c for c in load_seed_payload()["catalogs"][0]["controls"]}
        for control_id in CONTROLS:
            spec = specs[control_id]
            control = Control.objects.create(
                control_id=control_id, name=spec["name"],
                control_type=Control.ControlType.DEVICE_CONFIGURATION,
                description=spec["description"], default_severity=spec["default_severity"],
                severity_scale=spec.get("severity_scale") or {},
                target_model=spec["target_model"])
            for query in spec["queries"]:
                ControlQuery.objects.create(
                    control=control, name=query["name"],
                    canonical_query=query["canonical_query"],
                    is_baseline=query["is_baseline"], is_active=query["is_active"])
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _profile(self, hostname, management=None):
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=f"S-{hostname}", hostname=hostname)
        entry = {"deviceconfig": {"system": {}}}
        if management is not None:
            entry["deviceconfig"]["setting"] = {"management": management}
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": entry}}})
        normalize_appliance_device_configuration(appliance)
        return DeviceConfigurationProfile.objects.get(appliance=appliance)

    def _findings(self, hostname):
        generate_device_configuration_findings(self.run)
        return {f.control.control_id: f
                for f in DeviceConfigurationFinding.objects.select_related(
                    "control", "device_configuration_profile__appliance")
                if f.device_configuration_profile.appliance.hostname == hostname
                and f.control.control_id in set(CONTROLS)}

    # --- implicit values -------------------------------------------------------------

    def test_an_untouched_device_reports_three_of_the_four(self):
        """The whole setting/management node absent. 015 must NOT fire: its zero is compliant."""
        profile = self._profile("fw-bare")
        self.assertEqual(profile.admin_lockout_failed_attempts, 0)
        self.assertEqual(profile.admin_lockout_time_minutes, 0)
        self.assertEqual(profile.api_key_lifetime_minutes, 0)
        self.assertEqual(profile.idle_timeout_minutes, 60)
        self.assertEqual(set(self._findings("fw-bare")), UNCONFIGURED)

    def test_the_idle_timeout_default_of_sixty_is_what_fires_016(self):
        """Had the implicit value been 0, this device would hit the sentinel instead - a
        different severity and a different sentence. The 60 is measured, not documented."""
        self._profile("fw-idle")
        finding = self._findings("fw-idle")["PAN-AUTH-016"]
        self.assertEqual(finding.severity, "medium")   # 11-60 band, not the 0 sentinel

    # --- 014: zero is the worst value ------------------------------------------------

    def test_lockout_disabled_is_worse_than_a_large_attempt_count(self):
        self._profile("fw-nolock", {"admin-lockout": {"failed-attempts": "0"}})
        self._profile("fw-loose", {"admin-lockout": {"failed-attempts": "9"}})
        self.assertEqual(self._findings("fw-nolock")["PAN-AUTH-014"].severity, "high")
        self.assertEqual(self._findings("fw-loose")["PAN-AUTH-014"].severity, "medium")

    def test_a_reasonable_attempt_count_does_not_fire(self):
        self._profile("fw-ok", {"admin-lockout": {"failed-attempts": "5"}})
        self.assertNotIn("PAN-AUTH-014", self._findings("fw-ok"))

    # --- 015: zero is the best value -------------------------------------------------

    def test_only_the_excluded_middle_fires_015(self):
        """0 is stricter than any duration; 15+ meets the floor; 1-14 is the finding."""
        self._profile("fw-manual", {"admin-lockout": {"lockout-time": "0"}})
        self._profile("fw-short", {"admin-lockout": {"lockout-time": "5"}})
        self._profile("fw-good", {"admin-lockout": {"lockout-time": "30"}})
        self.assertNotIn("PAN-AUTH-015", self._findings("fw-manual"))
        self.assertIn("PAN-AUTH-015", self._findings("fw-short"))
        self.assertNotIn("PAN-AUTH-015", self._findings("fw-good"))

    def test_the_two_lockout_controls_disagree_about_zero(self):
        """One device, one screen, both keys zero: 014 fires and 015 does not."""
        self._profile("fw-zero", {"admin-lockout": {"failed-attempts": "0",
                                                    "lockout-time": "0"}})
        found = self._findings("fw-zero")
        self.assertIn("PAN-AUTH-014", found)
        self.assertNotIn("PAN-AUTH-015", found)

    # --- 016: bounded at both ends ---------------------------------------------------

    def test_idle_timeout_fires_at_both_ends_and_not_in_the_middle(self):
        self._profile("fw-never", {"idle-timeout": "0"})
        self._profile("fw-long", {"idle-timeout": "120"})
        self._profile("fw-tight", {"idle-timeout": "10"})
        self.assertEqual(self._findings("fw-never")["PAN-AUTH-016"].severity, "high")
        self.assertEqual(self._findings("fw-long")["PAN-AUTH-016"].severity, "high")
        self.assertNotIn("PAN-AUTH-016", self._findings("fw-tight"))

    def test_a_naive_less_than_comparison_would_pass_the_never_case(self):
        """The specific error this control is written to avoid: 0 sorts below every
        threshold, so 'idle_timeout > 10' alone silently passes a session that never ends."""
        self._profile("fw-never2", {"idle-timeout": "0"})
        self.assertIn("PAN-AUTH-016", self._findings("fw-never2"))

    # --- 017: one value ---------------------------------------------------------------

    def test_any_non_zero_api_key_lifetime_satisfies_the_floor(self):
        self._profile("fw-keys", {"api": {"key": {"lifetime": "1440"}}})
        self._profile("fw-forever", {"api": {"key": {"lifetime": "0"}}})
        self.assertNotIn("PAN-AUTH-017", self._findings("fw-keys"))
        self.assertIn("PAN-AUTH-017", self._findings("fw-forever"))

    def test_a_fully_hardened_device_fires_none_of_the_four(self):
        self._profile("fw-hard", {
            "admin-lockout": {"failed-attempts": "3", "lockout-time": "30"},
            "idle-timeout": "10",
            "api": {"key": {"lifetime": "1440"}},
        })
        self.assertEqual(self._findings("fw-hard"), {})
