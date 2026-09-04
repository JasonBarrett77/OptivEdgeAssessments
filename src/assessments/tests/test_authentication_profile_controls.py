"""PAN-AUTH-018 and 020 - authentication profile lockout and MFA.

Three things are pinned here, and each was measured rather than reasoned about.

ZERO IS UNLIMITED. `lockout_failed_attempts` of 0 does not mean a strict limit, it means the
profile never locks out, and it is the implicit value - so a control written as "more than 5
fires" passes every unconfigured profile in an estate.

A LOCKOUT TIME OF 0 DOES NOT DISABLE THE LOCKOUT. The Web Interface Help says on p.840 that it
does. Measured false on 2026-09-04: a profile with failed-attempts 2 and lockout-time 0 locked
the account after three failed logins and held it until an administrator released it. So 018
asserts on failed-attempts alone.

SAML PROFILES ARE EXCLUDED. The Help prefixes both lockout fields "(All authentication types
except SAML)", so a lockout finding against a SAML profile asserts something the platform does
not implement. The lab has such a profile and it fired before the exclusion existed.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.authentication_profile_findings import (
    generate_authentication_profile_findings)
from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import (
    AssessmentRun, AuthenticationProfileFinding, Control, ControlQuery)
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, AuthenticationProfile, ManagementStation, Snapshot)

CONTROLS = ["PAN-AUTH-018", "PAN-AUTH-020"]


class AuthenticationProfileControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.ap")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-ap",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-AP", hostname="fw-ap")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        specs = {c["control_id"]: c for c in load_seed_payload()["catalogs"][0]["controls"]}
        for control_id in CONTROLS:
            spec = specs[control_id]
            control = Control.objects.create(
                control_id=control_id, name=spec["name"],
                control_type=Control.ControlType.AUTHENTICATION_PROFILE,
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

    def _profile(self, name, **fields):
        return AuthenticationProfile.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot,
            name=name, scope="shared", **fields)

    def _findings(self, name):
        generate_authentication_profile_findings(self.run)
        return {f.control.control_id
                for f in AuthenticationProfileFinding.objects.select_related(
                    "control", "authentication_profile")
                if f.authentication_profile.name == name}

    def test_zero_failed_attempts_is_unlimited_and_fires(self):
        self._profile("p-none", method="local-database", lockout_failed_attempts=0)
        self.assertIn("PAN-AUTH-018", self._findings("p-none"))

    def test_a_reasonable_limit_passes(self):
        self._profile("p-ok", method="local-database", lockout_failed_attempts=3)
        self.assertNotIn("PAN-AUTH-018", self._findings("p-ok"))

    def test_too_many_attempts_fires(self):
        self._profile("p-loose", method="local-database", lockout_failed_attempts=9)
        self.assertIn("PAN-AUTH-018", self._findings("p-loose"))

    def test_a_zero_lockout_time_does_not_excuse_the_profile(self):
        """Measured: lockout-time 0 holds the account until released, it does not disable the
        lockout. A profile with a good attempt limit and lockout-time 0 is compliant."""
        self._profile("p-manual", method="local-database", lockout_failed_attempts=2,
                      lockout_time_minutes=0)
        self.assertNotIn("PAN-AUTH-018", self._findings("p-manual"))

    def test_a_saml_profile_is_excluded_from_the_lockout_control(self):
        """The platform does not implement a lockout for SAML, so a finding would be one
        nobody can act on. It fires 020 in the same breath, because MFA IS meaningful there."""
        self._profile("p-saml", method="saml-idp", lockout_failed_attempts=0)
        found = self._findings("p-saml")
        self.assertNotIn("PAN-AUTH-018", found)
        self.assertIn("PAN-AUTH-020", found)

    def test_mfa_off_fires_regardless_of_method(self):
        for name, method in [("m-none", "none"), ("m-local", "local-database"),
                             ("m-radius", "radius")]:
            self._profile(name, method=method, lockout_failed_attempts=3)
        for name in ("m-none", "m-local", "m-radius"):
            self.assertIn("PAN-AUTH-020", self._findings(name))

    def test_mfa_on_passes(self):
        self._profile("m-on", method="radius", lockout_failed_attempts=3,
                      mfa_enabled=True, mfa_factor_count=1)
        self.assertNotIn("PAN-AUTH-020", self._findings("m-on"))

    def test_a_fully_hardened_profile_fires_nothing(self):
        self._profile("p-good", method="radius", lockout_failed_attempts=3,
                      lockout_time_minutes=30, mfa_enabled=True, mfa_factor_count=1)
        self.assertEqual(self._findings("p-good"), set())
