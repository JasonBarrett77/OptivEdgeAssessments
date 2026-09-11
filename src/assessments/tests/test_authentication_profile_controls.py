"""PAN-AUTH-018 - authentication profile lockout.

Three things are pinned here, and each was measured rather than reasoned about.

ZERO IS UNLIMITED. `lockout_failed_attempts` of 0 does not mean a strict limit, it means the
profile never locks out, and it is the implicit value - so a control written as "more than N
fires" passes every unconfigured profile in an estate.

THE THRESHOLD IS 3, NOT 5. Jason, 2026-09-09: "failed-attempts should be 3 or less. There's no
finding if the setting is more aggressive than our preferred." The corpus carries
minimum_value 5 and preferred_value 3, and the same reasoning as PAN-AUTH-021 applies - report
against the preferred value and let the consultant relax it, because nobody re-reads an
understated finding. A limit BELOW 3 is stricter, not worse, and does not fire.

A LOCKOUT TIME OF 0 DOES NOT DISABLE THE LOCKOUT. The Web Interface Help says on p.840 that it
does. Measured false on 2026-09-04: a profile with failed-attempts 2 and lockout-time 0 locked
the account after three failed logins and held it until an administrator released it. So 018
asserts on failed-attempts alone.

PAN-AUTH-020 IS NO LONGER HERE. It was built over this model and left inactive because the
scope was wrong, and on 2026-09-08 it moved to AdminUser: the finding is about a PERSON, and a
profile row cannot say which administrators are exposed. Its tests are in
`test_admin_user_controls.py`. Nothing about the MFA columns on this model changed - they are
still read, just through the account's binding.

SAML PROFILES ARE EXCLUDED. The Help prefixes both lockout fields "(All authentication types
except SAML)", so a lockout finding against a SAML profile asserts something the platform does
not implement. The lab has such a profile and it fired before the exclusion existed.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.authentication_profile_findings import (
    generate_authentication_profile_findings)
from assessments.tests._seed import seed_controls
from assessments.models import (
    AssessmentRun, AuthenticationProfileFinding, Control, ControlQuery)
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, AuthenticationProfile, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_authentication_profiles)

CONTROLS = ["PAN-AUTH-018", "PAN-AUTH-025", "PAN-AAA-010", "PAN-AAA-011"]


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
        seed_controls(CONTROLS, control_type=Control.ControlType.AUTHENTICATION_PROFILE)
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

    def test_the_preferred_limit_passes(self):
        self._profile("p-ok", method="local-database", lockout_failed_attempts=3)
        self.assertNotIn("PAN-AUTH-018", self._findings("p-ok"))

    def test_a_stricter_limit_than_preferred_is_not_a_finding(self):
        """More aggressive than we ask for is not a weakness. Only 0 inverts, and it is a
        sentinel rather than a small number."""
        for name, attempts in (("p-strict-1", 1), ("p-strict-2", 2)):
            self._profile(name, method="local-database", lockout_failed_attempts=attempts)
            self.assertNotIn("PAN-AUTH-018", self._findings(name))

    def test_four_and_five_fire_at_low(self):
        """The band that moved with the threshold. These meet the corpus MINIMUM of 5 and miss
        the preferred 3, so they report - and they report `low`, not the control's default.

        Before the threshold moved they did not fire at all, and had they started firing
        without the bands moving they would have landed on a null band and been reported
        `high` - worse than the 6-to-10 band above them."""
        for name, attempts in (("p-four", 4), ("p-five", 5)):
            self._profile(name, method="local-database", lockout_failed_attempts=attempts)
            generate_authentication_profile_findings(self.run)
            finding = AuthenticationProfileFinding.objects.get(
                authentication_profile__name=name, control__control_id="PAN-AUTH-018")
            self.assertEqual(finding.severity, "low")

    def test_too_many_attempts_fires(self):
        self._profile("p-loose", method="local-database", lockout_failed_attempts=9)
        self.assertIn("PAN-AUTH-018", self._findings("p-loose"))

    def test_the_bands_apply_at_all(self):
        """Three severities from one control, all from queries.

        018 once shipped with four declarative bands that never applied at all, and every
        finding reported `high`. The bands are operator queries now; this asserts they land."""
        self._profile("p-off", method="local-database", lockout_failed_attempts=0)
        self._profile("p-mid", method="local-database", lockout_failed_attempts=8)
        self._profile("p-worst", method="local-database", lockout_failed_attempts=40)
        generate_authentication_profile_findings(self.run)
        got = {f.authentication_profile.name: f.severity
               for f in AuthenticationProfileFinding.objects.select_related(
                   "authentication_profile").filter(control__control_id="PAN-AUTH-018")}
        self.assertEqual(got, {"p-off": "high", "p-mid": "medium", "p-worst": "high"})

    def test_a_zero_lockout_time_does_not_excuse_the_profile(self):
        """Measured: lockout-time 0 holds the account until released, it does not disable the
        lockout. A profile with a good attempt limit and lockout-time 0 is compliant."""
        self._profile("p-manual", method="local-database", lockout_failed_attempts=2,
                      lockout_time_minutes=0)
        self.assertNotIn("PAN-AUTH-018", self._findings("p-manual"))

    def test_a_saml_profile_is_excluded_from_the_lockout_control(self):
        """The platform does not implement a lockout for SAML, so a finding would be one
        nobody can act on."""
        self._profile("p-saml", method="saml-idp", lockout_failed_attempts=0)
        self.assertNotIn("PAN-AUTH-018", self._findings("p-saml"))

    def test_a_fully_hardened_profile_fires_nothing(self):
        """Hardened AND referenced. The two are different questions and 025 asks the second:
        a perfectly configured profile nobody uses is still configuration debt."""
        self._profile("p-good", method="radius", lockout_failed_attempts=3,
                      lockout_time_minutes=30, mfa_enabled=True, mfa_factor_count=1,
                      referrer_count=1, referrer_paths=["/mgt-config/users/entry[a]"])
        self.assertEqual(self._findings("p-good"), set())

    def test_a_hardened_profile_nobody_references_still_fires_025(self):
        self._profile("p-good-orphan", method="radius", lockout_failed_attempts=3,
                      lockout_time_minutes=30, mfa_enabled=True, mfa_factor_count=1)
        self.assertEqual(self._findings("p-good-orphan"), {"PAN-AUTH-025"})


class UnusedProfileTests(TestCase):
    """PAN-AUTH-025 - a profile nothing on the appliance references.

    The reference count is computed by walking the WHOLE merged payload rather than visiting the
    eight paths the CLI grammar lists, so these exercise the walk: a reference nested several
    entries deep must be found, and a vsys referrer must land on the definition it resolves to
    rather than on a same-named neighbour.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.un")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-un",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-UN", hostname="fw-un")

    def _snapshot(self, payload):
        return Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload=payload)

    def _payload(self, *, shared=(), vsys=None, referrers=None):
        vsys_entries = []
        for name, profiles in (vsys or {}).items():
            entry = {"@name": name,
                     "authentication-profile": {"entry": [{"@name": p} for p in profiles]}}
            vsys_entries.append(entry)
        for name, node in (referrers or {}).get("vsys", {}).items():
            match = next((v for v in vsys_entries if v["@name"] == name), None)
            if match is None:
                match = {"@name": name}
                vsys_entries.append(match)
            match.update(node)
        config = {
            "shared": {"authentication-profile": {"entry": [{"@name": p} for p in shared]}},
            "devices": {"entry": [{"@name": "localhost.localdomain",
                                   "vsys": {"entry": vsys_entries}}]},
            "mgt-config": (referrers or {}).get("mgt-config", {}),
        }
        return {"config": config}

    def _normalize(self, payload):
        self._snapshot(payload)
        normalize_appliance_authentication_profiles(self.appliance)
        return {(p.scope, p.vsys_name, p.name): p.referrer_count
                for p in AuthenticationProfile.objects.filter(appliance=self.appliance)}

    def test_a_profile_nothing_names_counts_zero(self):
        counts = self._normalize(self._payload(shared=["orphan"]))
        self.assertEqual(counts[("shared", "", "orphan")], 0)

    def test_an_administrator_reference_counts(self):
        counts = self._normalize(self._payload(
            shared=["corp"],
            referrers={"mgt-config": {"users": {"entry": [
                {"@name": "jason", "authentication-profile": "corp"}]}}}))
        self.assertEqual(counts[("shared", "", "corp")], 1)

    def test_a_reference_nested_deep_inside_a_vsys_entry_is_found(self):
        """GlobalProtect hides its references several entries down. A scan that only visited
        known paths would miss a path the grammar list did not have; the walk cannot."""
        counts = self._normalize(self._payload(
            shared=["corp"],
            referrers={"vsys": {"vsys1": {"global-protect": {"global-protect-gateway": {
                "entry": [{"@name": "gw1", "client-auth": {
                    "entry": [{"@name": "ca1", "authentication-profile": "corp"}]}}]}}}}}))
        self.assertEqual(counts[("shared", "", "corp")], 1)

    def test_the_second_device_wide_leaf_counts_too(self):
        """`non-ui-authentication-profile` appears nowhere in the Help and only in the grammar."""
        counts = self._normalize({"config": {
            "shared": {"authentication-profile": {"entry": [{"@name": "corp"}]}},
            "devices": {"entry": [{"@name": "localhost.localdomain", "deviceconfig": {
                "system": {"non-ui-authentication-profile": "corp"}}}]}}})
        self.assertEqual(counts[("shared", "", "corp")], 1)

    def test_a_vsys_referrer_resolves_to_the_VSYS_profile_not_the_shared_one(self):
        """Both scopes hold `corp`. The reference is inside vsys1, so it belongs to vsys1's -
        and the shared one is genuinely unused. Attributing it to shared would report the real
        one as unused and the orphan as in use, in one move."""
        counts = self._normalize(self._payload(
            shared=["corp"], vsys={"vsys1": ["corp"]},
            referrers={"vsys": {"vsys1": {"captive-portal": {"authentication-profile": "corp"}}}}))
        self.assertEqual(counts[("vsys", "vsys1", "corp")], 1)
        self.assertEqual(counts[("shared", "", "corp")], 0)

    def test_a_vsys_referrer_falls_back_to_shared_when_the_vsys_has_none(self):
        counts = self._normalize(self._payload(
            shared=["corp"],
            referrers={"vsys": {"vsys1": {"captive-portal": {"authentication-profile": "corp"}}}}))
        self.assertEqual(counts[("shared", "", "corp")], 1)

    def test_the_same_profile_named_twice_counts_twice(self):
        counts = self._normalize(self._payload(
            shared=["corp"],
            referrers={"mgt-config": {"users": {"entry": [
                {"@name": "a", "authentication-profile": "corp"},
                {"@name": "b", "authentication-profile": "corp"}]}}}))
        self.assertEqual(counts[("shared", "", "corp")], 2)


class AdministratorMFADeliveryTests(TestCase):
    """PAN-AAA-011 - an MFA factor on a profile administrators log in through.

    PAN-OS invokes MFA server profiles through Authentication Policy only. Guide p.221: "For
    remote user authentication to GlobalProtect portals and gateways and for administrator
    authentication to the Panorama and PAN-OS web interface, the firewall integrates with MFA
    vendors using RADIUS and SAML only."

    So this control fires on MFA being PRESENT, which is the opposite direction from every other
    control on this model, and the administrative clause is the entire control: the same profile
    serving Authentication Policy is correct configuration. The two tests that matter are the
    pair - identical factor, one administrator-bound.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.mfa")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-mfa",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-MFA", hostname="fw-mfa")
        seed_controls(["PAN-AAA-011"],
                      control_type=Control.ControlType.AUTHENTICATION_PROFILE)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _normalize(self, mfa, administrator=True):
        entry = {"@name": "corp", "method": {"local-database": None},
                 "allow-list": {"member": ["cn=admins"]}}
        if mfa is not None:
            entry["multi-factor-auth"] = mfa
        config = {
            "shared": {"authentication-profile": {"entry": [entry]}},
            "devices": {"entry": [{"@name": "localhost.localdomain"}]},
        }
        if administrator:
            config["mgt-config"] = {"users": {"entry": [
                {"@name": "jason", "authentication-profile": "corp"}]}}
        else:
            config["devices"]["entry"][0]["vsys"] = {"entry": [
                {"@name": "vsys1", "authentication-object": {"entry": [
                    {"@name": "portal", "authentication-profile": "corp"}]}}]}
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        normalize_appliance_authentication_profiles(self.appliance)
        return AuthenticationProfile.objects.get(appliance=self.appliance, name="corp")

    def _fired(self):
        generate_authentication_profile_findings(self.run)
        return set(AuthenticationProfileFinding.objects
                   .filter(authentication_profile__name="corp")
                   .values_list("control__control_id", flat=True))

    ENABLED = {"mfa-enable": "yes", "factors": {"member": ["duo"]}}

    def test_an_administrator_bound_profile_with_a_factor_fires(self):
        profile = self._normalize(self.ENABLED)
        self.assertTrue(profile.is_administrative)
        self.assertEqual(profile.mfa_factor_count, 1)
        self.assertIn("PAN-AAA-011", self._fired())

    def test_the_same_profile_serving_authentication_policy_does_NOT_fire(self):
        """The lab pair: oep-auth-hardened and oep-auth-mfa-portal carry the identical factor,
        the identical method, allow list and lockout, and differ only in whether an
        administrator is bound. Vendor-API MFA is exactly right on this one."""
        profile = self._normalize(self.ENABLED, administrator=False)
        self.assertFalse(profile.is_administrative)
        self.assertEqual(profile.mfa_factor_count, 1)
        self.assertNotIn("PAN-AAA-011", self._fired())

    def test_an_administrator_bound_profile_with_no_mfa_does_NOT_fire(self):
        """Missing MFA is PAN-AUTH-019's subject and it reports on the account, not here. This
        control asserts nothing about a profile that never claimed a second factor."""
        profile = self._normalize(None)
        self.assertTrue(profile.is_administrative)
        self.assertNotIn("PAN-AAA-011", self._fired())

    def test_factors_listed_but_disabled_does_NOT_fire(self):
        """`mfa-enable: no` leaves the box unchecked, so nothing claims a second factor and
        nothing is silently ignored. Both operands are in the query for this row."""
        profile = self._normalize({"mfa-enable": "no", "factors": {"member": ["duo"]}})
        self.assertFalse(profile.mfa_enabled)
        self.assertEqual(profile.mfa_factor_count, 1)
        self.assertNotIn("PAN-AAA-011", self._fired())

    def test_enabled_with_no_factors_does_NOT_fire(self):
        """The other half of the same pair: the checkbox is on and there is nothing to invoke."""
        profile = self._normalize({"mfa-enable": "yes"})
        self.assertTrue(profile.mfa_enabled)
        self.assertEqual(profile.mfa_factor_count, 0)
        self.assertNotIn("PAN-AAA-011", self._fired())

    def test_the_device_wide_binding_also_makes_it_administrative(self):
        """`deviceconfig/system/authentication-profile` binds every administrator who has no
        profile of their own, and the corpus xpath for these controls does not mention it."""
        config = {
            "shared": {"authentication-profile": {"entry": [
                {"@name": "corp", "method": {"local-database": None},
                 "multi-factor-auth": self.ENABLED}]}},
            "devices": {"entry": [{"@name": "localhost.localdomain", "deviceconfig": {
                "system": {"authentication-profile": "corp"}}}]},
        }
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        normalize_appliance_authentication_profiles(self.appliance)
        profile = AuthenticationProfile.objects.get(appliance=self.appliance, name="corp")
        self.assertTrue(profile.is_administrative)
        self.assertIn("PAN-AAA-011", self._fired())


class AllowListScopingTests(TestCase):
    """PAN-AAA-010 - an administrator-bound profile open to the whole directory.

    `all` is not a value somebody chose; it is what the Add form leaves behind, and all nine
    profiles on the lab carry it. So the ADMINISTRATIVE clause is what makes this control a
    finding rather than a census - without it, it fires on every authentication profile in
    every estate.

    Administrative is derived from the referrer walk: something under `mgt-config/users` or
    `deviceconfig/system` names the profile. A profile referenced only by captive portal or an
    authentication object is referenced and NOT administrative, which is the case that shows the
    derivation is doing real work.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.al")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-al",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-AL", hostname="fw-al")
        seed_controls(["PAN-AAA-010"],
                      control_type=Control.ControlType.AUTHENTICATION_PROFILE)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _normalize(self, referrers, allow=("all",)):
        config = {
            "shared": {"authentication-profile": {"entry": [
                {"@name": "corp",
                 "allow-list": {"member": list(allow)},
                 "method": {"local-database": None}}]}},
            "devices": {"entry": [{"@name": "localhost.localdomain"}]},
        }
        config["devices"]["entry"][0].update(referrers.get("device", {}))
        if "mgt-config" in referrers:
            config["mgt-config"] = referrers["mgt-config"]
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        normalize_appliance_authentication_profiles(self.appliance)
        return AuthenticationProfile.objects.get(appliance=self.appliance, name="corp")

    def _fired(self):
        generate_authentication_profile_findings(self.run)
        return set(AuthenticationProfileFinding.objects
                   .filter(authentication_profile__name="corp")
                   .values_list("control__control_id", flat=True))

    def test_an_administrator_bound_profile_open_to_all_fires(self):
        profile = self._normalize({"mgt-config": {"users": {"entry": [
            {"@name": "jason", "authentication-profile": "corp"}]}}})
        self.assertTrue(profile.is_administrative)
        self.assertTrue(profile.allow_list_is_all)
        self.assertIn("PAN-AAA-010", self._fired())

    def test_the_device_wide_binding_also_makes_it_administrative(self):
        profile = self._normalize({"device": {"deviceconfig": {
            "system": {"authentication-profile": "corp"}}}})
        self.assertTrue(profile.is_administrative)
        self.assertIn("PAN-AAA-010", self._fired())

    def test_a_captive_portal_profile_open_to_all_does_NOT_fire(self):
        """Referenced twice and not administrative - the lab's `oep-auth-nolockout`. Jason,
        2026-09-04: "GlobalProtect, Captive Portal, and even unused authentication profiles are
        very much separate controls." """
        profile = self._normalize({"device": {"vsys": {"entry": [
            {"@name": "vsys1", "captive-portal": {"authentication-profile": "corp"}}]}}})
        self.assertEqual(profile.referrer_count, 1)
        self.assertFalse(profile.is_administrative)
        self.assertNotIn("PAN-AAA-010", self._fired())

    def test_an_unreferenced_profile_open_to_all_does_NOT_fire(self):
        profile = self._normalize({})
        self.assertFalse(profile.is_administrative)
        self.assertNotIn("PAN-AAA-010", self._fired())

    def test_a_scoped_allow_list_passes_even_when_administrative(self):
        profile = self._normalize(
            {"mgt-config": {"users": {"entry": [
                {"@name": "jason", "authentication-profile": "corp"}]}}},
            allow=("cn=firewall-admins,ou=groups,dc=example,dc=com",))
        self.assertTrue(profile.is_administrative)
        self.assertFalse(profile.allow_list_is_all)
        self.assertNotIn("PAN-AAA-010", self._fired())

    def test_all_is_matched_whatever_its_casing(self):
        profile = self._normalize(
            {"mgt-config": {"users": {"entry": [
                {"@name": "jason", "authentication-profile": "corp"}]}}},
            allow=("All",))
        self.assertTrue(profile.allow_list_is_all)

    def test_all_alongside_a_group_still_counts_as_all(self):
        """The boundary the exposure classifier got wrong once: a list CONTAINING the wildcard
        is as open as the wildcard alone."""
        profile = self._normalize(
            {"mgt-config": {"users": {"entry": [
                {"@name": "jason", "authentication-profile": "corp"}]}}},
            allow=("cn=firewall-admins", "all"))
        self.assertTrue(profile.allow_list_is_all)
        self.assertIn("PAN-AAA-010", self._fired())
