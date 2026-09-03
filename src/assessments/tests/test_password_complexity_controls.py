"""PAN-AUTH-001 through 013 - password complexity.

Thirteen controls over one object, and the risk is that they look like thirteen copies of the
same assertion. They are not. Three directions live here:

    AT LEAST   most of them - a value below the floor is a finding
    AT MOST    012 and 013 - the secure value is ZERO, which is also the default, so these
               fire only where somebody deliberately allowed expired credentials to work
    BOUNDED    010 - zero means passwords NEVER expire and a large value means they expire too
               rarely, so both ends are wrong and only the middle passes

Every default is the insecure one except the two inverted ones. Writing all thirteen the same
way would report every device as failing two controls it satisfies, and would pass a 365-day
password expiry.

The other thing pinned here is INDEPENDENCE. These settings are inert while complexity is
disabled, and it would be natural to assess them only when it is on. That was tried and
rejected: gating makes the finding set change shape the moment the engine is switched on, so
remediating correctly looks like making things worse.
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

CONTROLS = [f"PAN-AUTH-{n:03d}" for n in range(1, 14)]
#: What a default device reports: everything except the two inverted ones.
ALL_BUT_INVERTED = {c for c in CONTROLS if c not in ("PAN-AUTH-012", "PAN-AUTH-013")}


class PasswordComplexityControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.pw")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-pw",
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

    def _profile(self, hostname, complexity=None):
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=f"S-{hostname}", hostname=hostname)
        config = {"devices": {"entry": {"deviceconfig": {"system": {}}}}}
        if complexity is not None:
            # mgt-config sits at the TOP of the merged config, beside devices and shared.
            config["mgt-config"] = {"password-complexity": complexity}
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        normalize_appliance_device_configuration(appliance)
        return DeviceConfigurationProfile.objects.get(appliance=appliance)

    def _findings(self, hostname):
        generate_device_configuration_findings(self.run)
        return {f.control.control_id
                for f in DeviceConfigurationFinding.objects.select_related(
                    "control", "device_configuration_profile__appliance")
                if f.device_configuration_profile.appliance.hostname == hostname
                and f.control.control_id.startswith("PAN-AUTH")}

    def test_an_untouched_device_fires_everything_except_the_inverted_two(self):
        """The shape both lab PA-5220s were in before anyone touched them.

        012 and 013 must NOT fire: their secure value is 0 and 0 is the default, so a device
        that has never been configured already satisfies them.
        """
        self._profile("fw-bare")
        self.assertEqual(self._findings("fw-bare"), ALL_BUT_INVERTED)

    def test_enabling_alone_removes_exactly_one_finding(self):
        """The independence decision, checked rather than argued.

        A device differing from the untouched one by a single setting must differ by a single
        finding. Under the gating design this device would have reported ten findings against
        the other's one.
        """
        self._profile("fw-enabled", {"enabled": "yes"})
        self.assertEqual(self._findings("fw-enabled"), ALL_BUT_INVERTED - {"PAN-AUTH-001"})

    def test_a_fully_compliant_device_fires_nothing(self):
        self._profile("fw-good", {
            "enabled": "yes",
            "minimum-length": "15",
            "minimum-uppercase-letters": "1",
            "minimum-lowercase-letters": "1",
            "minimum-numeric-letters": "1",
            "minimum-special-characters": "1",
            "block-username-inclusion": "yes",
            "new-password-differs-by-characters": "8",
            "password-history-count": "24",
            "password-change": {
                "expiration-period": "60",
                "expiration-warning-period": "14",
                "post-expiration-admin-login-count": "0",
                "post-expiration-grace-period": "0",
            },
        })
        self.assertEqual(self._findings("fw-good"), set())

    def test_the_inverted_two_fire_only_when_expired_credentials_are_permitted(self):
        self._profile("fw-permissive", {
            "enabled": "yes", "minimum-length": "15",
            "minimum-uppercase-letters": "1", "minimum-lowercase-letters": "1",
            "minimum-numeric-letters": "1", "minimum-special-characters": "1",
            "block-username-inclusion": "yes",
            "new-password-differs-by-characters": "8", "password-history-count": "24",
            "password-change": {
                "expiration-period": "60", "expiration-warning-period": "14",
                "post-expiration-admin-login-count": "3",
                "post-expiration-grace-period": "30",
            },
        })
        self.assertEqual(self._findings("fw-permissive"),
                         {"PAN-AUTH-012", "PAN-AUTH-013"})

    def test_expiration_period_is_wrong_at_both_ends(self):
        """A less-than comparison would pass a 365-day expiry and fail the preferred 60."""
        base = {"enabled": "yes", "minimum-length": "15",
                "minimum-uppercase-letters": "1", "minimum-lowercase-letters": "1",
                "minimum-numeric-letters": "1", "minimum-special-characters": "1",
                "block-username-inclusion": "yes",
                "new-password-differs-by-characters": "8", "password-history-count": "24"}
        for hostname, period, should_fire in (
            ("fw-never", "0", True),      # never expires
            ("fw-preferred", "60", False),
            ("fw-minimum", "90", False),
            ("fw-too-long", "365", True),
        ):
            self._profile(hostname, {**base, "password-change": {
                "expiration-period": period, "expiration-warning-period": "14",
                "post-expiration-admin-login-count": "0",
                "post-expiration-grace-period": "0"}})
        self.assertIn("PAN-AUTH-010", self._findings("fw-never"))
        self.assertNotIn("PAN-AUTH-010", self._findings("fw-preferred"))
        self.assertNotIn("PAN-AUTH-010", self._findings("fw-minimum"))
        self.assertIn("PAN-AUTH-010", self._findings("fw-too-long"))

    def test_a_weak_value_fires_even_while_the_engine_is_off(self):
        """Independence again, from the other side.

        The setting is inert here - the device enforces nothing - and the finding is still
        true: the value IS below the floor, and it will bite the moment complexity is enabled.
        """
        profile = self._profile("fw-off-but-weak", {
            "enabled": "no", "minimum-length": "8"})
        self.assertEqual(profile.password_minimum_length, 8)
        findings = self._findings("fw-off-but-weak")
        self.assertIn("PAN-AUTH-001", findings)
        self.assertIn("PAN-AUTH-002", findings)

    def test_absent_keys_normalize_to_the_measured_defaults(self):
        """PAN-OS writes only the flag; the zeros on the form are never stored."""
        profile = self._profile("fw-flag-only", {"enabled": "yes"})
        self.assertTrue(profile.password_complexity_enabled)
        self.assertEqual(profile.password_minimum_length, 0)
        self.assertEqual(profile.password_history_count, 0)
        self.assertEqual(profile.password_post_expiration_grace_period, 0)
        self.assertFalse(profile.password_block_username_inclusion)
