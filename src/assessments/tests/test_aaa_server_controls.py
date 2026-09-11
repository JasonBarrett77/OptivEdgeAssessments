"""The auth-servers domain - PAN-AAA-001, 002, 004, 006, 008, 009 and 013.

Two things are pinned here and both would fail silently.

EVERY CONTROL MUST CLAUSE ON `kind`. Six kinds share one table, so the measured implicit values
sit on every row: `ldap_verify_server_certificate` is FALSE on a RADIUS profile too, and a
PAN-AAA-002 that forgot the kind clause would report every RADIUS, TACACS+, Kerberos, SAML and
MFA profile in an estate for not verifying an LDAP certificate.

TWO OF THE THREE IMPLICIT VALUES INVERT. `ssl` and both SAML flags are implicit YES, so those
controls fire only on an EXPLICIT `no`; `verify-server-certificate`, four lines away in the same
dialog, is implicit NO and fires on absence.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.models import AssessmentRun, Control, ServerProfileFinding
from assessments.server_profile_findings import generate_server_profile_findings
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ManagementStation, ServerProfile, Snapshot)

CONTROL_IDS = ("PAN-AAA-001", "PAN-AAA-002", "PAN-AAA-004", "PAN-AAA-006",
               "PAN-AAA-008", "PAN-AAA-009", "PAN-AAA-013")


class AaaServerControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.aaa")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-aaa",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-AAA", hostname="fw-aaa")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        seed_controls(CONTROL_IDS, control_type=Control.ControlType.SERVER_PROFILE)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _profile(self, name, kind, **fields):
        # Defaults mirror the MEASURED implicit values, so a test that says nothing about a
        # field gets what a device would actually report.
        base = {"scope": "shared", "vsys_name": "", "referrer_count": 1,
                "ldap_ssl": True, "ldap_verify_server_certificate": False,
                "saml_validate_idp_certificate": True,
                "saml_want_auth_requests_signed": True}
        base.update(fields)
        return ServerProfile.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot,
            name=name, kind=kind, **base)

    def _fired(self, name):
        generate_server_profile_findings(self.run)
        return set(ServerProfileFinding.objects.filter(server_profile__name=name)
                   .values_list("control__control_id", flat=True))

    def _severity(self, name, control_id):
        generate_server_profile_findings(self.run)
        return ServerProfileFinding.objects.get(
            server_profile__name=name, control__control_id=control_id).severity

    # --- the kind clause -------------------------------------------------------------
    def test_a_radius_profile_does_not_fire_the_LDAP_controls(self):
        """The failure this whole file exists for. `ldap_verify_server_certificate` is False on
        a RADIUS row too, because the column is measured-implicit-False for every row."""
        self._profile("r", ServerProfile.Kind.RADIUS, protocol="PEAP-MSCHAPv2")
        fired = self._fired("r")
        self.assertNotIn("PAN-AAA-001", fired)
        self.assertNotIn("PAN-AAA-002", fired)

    def test_an_ldap_profile_does_not_fire_the_RADIUS_or_SAML_controls(self):
        self._profile("l", ServerProfile.Kind.LDAP, ldap_ssl=False)
        fired = self._fired("l")
        self.assertNotIn("PAN-AAA-004", fired)
        self.assertNotIn("PAN-AAA-008", fired)
        self.assertNotIn("PAN-AAA-009", fired)

    # --- the implicit values that invert ---------------------------------------------
    def test_an_ldap_profile_that_says_nothing_about_ssl_PASSES_001(self):
        """`ssl` is implicit YES. Reading absence as off would report every unedited LDAP
        profile in an estate as cleartext."""
        self._profile("quiet", ServerProfile.Kind.LDAP)
        self.assertNotIn("PAN-AAA-001", self._fired("quiet"))

    def test_an_explicit_no_fires_001(self):
        self._profile("plain", ServerProfile.Kind.LDAP, ldap_ssl=False)
        self.assertIn("PAN-AAA-001", self._fired("plain"))

    def test_an_ldap_profile_that_says_nothing_about_verification_FIRES_002(self):
        """The neighbour four lines up the same dialog, and the opposite default."""
        self._profile("quiet", ServerProfile.Kind.LDAP)
        self.assertIn("PAN-AAA-002", self._fired("quiet"))

    def test_002_fires_even_where_ssl_is_on(self):
        """Encryption without verification stops an eavesdropper and not an interceptor."""
        self._profile("tls-only", ServerProfile.Kind.LDAP, ldap_ssl=True)
        self.assertIn("PAN-AAA-002", self._fired("tls-only"))

    def test_a_saml_profile_that_says_nothing_passes_both_flags(self):
        self._profile("quiet", ServerProfile.Kind.SAML_IDP)
        fired = self._fired("quiet")
        self.assertNotIn("PAN-AAA-008", fired)
        self.assertNotIn("PAN-AAA-009", fired)

    def test_an_explicit_no_fires_both_saml_controls(self):
        self._profile("off", ServerProfile.Kind.SAML_IDP,
                      saml_validate_idp_certificate=False,
                      saml_want_auth_requests_signed=False)
        fired = self._fired("off")
        self.assertIn("PAN-AAA-008", fired)
        self.assertIn("PAN-AAA-009", fired)

    # --- the two-tier protocol control ------------------------------------------------
    def test_radius_PAP_reports_the_control_default(self):
        self._profile("pap", ServerProfile.Kind.RADIUS, protocol="PAP")
        self.assertEqual(self._severity("pap", "PAN-AAA-004"), "high")

    def test_radius_CHAP_meets_the_minimum_and_reports_medium(self):
        """The corpus's own two tiers: CHAP is the minimum, PEAP-MSCHAPv2 the preferred. The
        second query carries the preferred-gap severity."""
        self._profile("chap", ServerProfile.Kind.RADIUS, protocol="CHAP")
        self.assertEqual(self._severity("chap", "PAN-AAA-004"), "medium")

    def test_radius_inside_TLS_passes(self):
        for name, protocol in (("peap", "PEAP-MSCHAPv2"), ("ttls", "EAP-TTLS-with-PAP"),
                               ("gtc", "PEAP-with-GTC")):
            self._profile(name, ServerProfile.Kind.RADIUS, protocol=protocol)
            self.assertNotIn("PAN-AAA-004", self._fired(name), protocol)

    def test_tacacs_PAP_fires_and_CHAP_does_not(self):
        self._profile("t-pap", ServerProfile.Kind.TACPLUS, protocol="PAP")
        self._profile("t-chap", ServerProfile.Kind.TACPLUS, protocol="CHAP")
        self.assertIn("PAN-AAA-006", self._fired("t-pap"))
        self.assertNotIn("PAN-AAA-006", self._fired("t-chap"))

    # --- hygiene ----------------------------------------------------------------------
    def test_013_fires_on_any_kind_with_no_referrer(self):
        """An orphan is an orphan whatever it authenticates, so this one does NOT clause kind."""
        for name, kind in (("o-ldap", ServerProfile.Kind.LDAP),
                           ("o-mfa", ServerProfile.Kind.MFA),
                           ("o-krb", ServerProfile.Kind.KERBEROS)):
            self._profile(name, kind, referrer_count=0)
            self.assertIn("PAN-AAA-013", self._fired(name), kind)

    def test_013_does_not_fire_on_a_referenced_profile(self):
        self._profile("used", ServerProfile.Kind.KERBEROS, referrer_count=2)
        self.assertNotIn("PAN-AAA-013", self._fired("used"))

    def test_the_summary_names_the_kind_and_the_value(self):
        """Six kinds share a table, so "corp does not require SSL" needs to say which screen."""
        self._profile("corp", ServerProfile.Kind.LDAP, ldap_ssl=False)
        generate_server_profile_findings(self.run)
        summary = ServerProfileFinding.objects.get(
            server_profile__name="corp", control__control_id="PAN-AAA-001").summary
        self.assertIn("LDAP server profile corp", summary)
        self.assertIn("SSL/TLS OFF", summary)
