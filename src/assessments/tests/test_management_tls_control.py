"""PAN-MGT-010 - the SSL/TLS service profile bound to the management interface.

The control asserts a floor that lives one hop away from the thing it inspects: the binding
is a NAME, and the TLS 1.2+ assertion belongs to the profile that name resolves to. Every
test here pins a resolution rule that was MEASURED on hardware and would otherwise be an
inviting guess.

The rule that matters most: PREDEFINED BEATS SHARED. Writing a custom profile under the
shipped name TLSv1.3_Default and binding it leaves the device negotiating the predefined
profile's TLS 1.3 and serving the predefined certificate - the custom entry is discarded
whole, settings and certificate alike. Guessing the other way round is what a reader would
naturally do, since a locally written object beating a vendor default is the ordinary rule
elsewhere, and `region` genuinely does extend its predefined namesake.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.controls_catalog.registry import load_seed_payload
from assessments.device_configuration_findings import generate_device_configuration_findings
from assessments.models import (
    AssessmentRun, Control, ControlQuery, DeviceConfigurationFinding)
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, DeviceConfigurationProfile, ManagementStation,
    NormalizationIssue, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_device_configuration)

CONTROL_ID = "PAN-MGT-010"


class ManagementTlsControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.tls")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-tls",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        spec = {c["control_id"]: c
                for c in load_seed_payload()["catalogs"][0]["controls"]}[CONTROL_ID]
        control = Control.objects.create(
            control_id=CONTROL_ID, name=spec["name"],
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

    def _profile(self, hostname, *, bound=None, shared=None, predefined=None):
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=f"S-{hostname}", hostname=hostname)
        system = {}
        if bound is not None:
            system["ssl-tls-service-profile"] = bound
        config = {"devices": {"entry": {"deviceconfig": {"system": system}}}}
        if shared is not None:
            config["shared"] = {"ssl-tls-service-profile": {"entry": shared}}
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        # The predefined catalog is a SEPARATE snapshot on purpose: it does not travel in
        # `show config merged`. Passing None models an appliance collected before that read
        # existed, which is a different state from an appliance that has no predefined
        # profiles - the PA-VM genuinely has none, and returns an empty result.
        if predefined is not None:
            Snapshot.objects.create(
                management_station=self.station, appliance=appliance,
                source_type="config_predefined_ssl_tls_service_profiles",
                collected_at=timezone.now(),
                payload={"ssl-tls-service-profile": {"entry": predefined}})
        normalize_appliance_device_configuration(appliance)
        return DeviceConfigurationProfile.objects.get(appliance=appliance)

    def _findings(self):
        generate_device_configuration_findings(self.run)
        return {f.device_configuration_profile.appliance.hostname
                for f in DeviceConfigurationFinding.objects.select_related(
                    "control", "device_configuration_profile__appliance")
                if f.control.control_id == CONTROL_ID}

    def _entry(self, name, minimum, maximum, certificate="cert"):
        return [{"@name": name,
                 "protocol-settings": {"min-version": minimum, "max-version": maximum},
                 "certificate": certificate}]

    def test_nothing_bound_is_a_finding(self):
        """Absence fails rather than passing by default.

        Measured 2026-09-02: an unbound PA-5220 management interface accepts TLS 1.1, and
        refuses only TLS 1.0. So the device is genuinely below the floor - this is not a
        conservative choice made in the absence of evidence.
        """
        profile = self._profile("fw-unbound")
        self.assertEqual(profile.ssl_tls_service_profile_name, "")
        self.assertEqual(profile.ssl_tls_profile_scope, "")
        self.assertIn("fw-unbound", self._findings())

    def test_a_shared_profile_at_tls_1_2_passes(self):
        profile = self._profile(
            "fw-shared", bound="hardened",
            shared=self._entry("hardened", "tls1-2", "tls1-3"))
        self.assertEqual(
            profile.ssl_tls_profile_scope,
            DeviceConfigurationProfile.SSL_TLS_SCOPE_SHARED)
        self.assertEqual(profile.ssl_tls_min_version, "tls1-2")
        self.assertNotIn("fw-shared", self._findings())

    def test_a_shared_profile_below_tls_1_2_is_a_finding(self):
        self._profile("fw-weak", bound="legacy",
                      shared=self._entry("legacy", "tls1-0", "tls1-2"))
        self.assertIn("fw-weak", self._findings())

    def test_the_predefined_definition_beats_a_same_named_shared_one(self):
        """The measured rule, and the one a reader is most likely to get backwards.

        The shared entry here would PASS on its own settings. The predefined entry under the
        same name is what is actually in force, and it also passes - so the assertion is on
        the resolved SCOPE and VALUES, not on the verdict, which would be identical either
        way and would therefore prove nothing.
        """
        profile = self._profile(
            "fw-collide", bound="TLSv1.3_Default",
            shared=self._entry("TLSv1.3_Default", "tls1-2", "tls1-2", certificate="mine"),
            predefined=self._entry("TLSv1.3_Default", "tls1-3", "tls1-3",
                                   certificate="TLSv1.3_Default"))
        self.assertEqual(
            profile.ssl_tls_profile_scope,
            DeviceConfigurationProfile.SSL_TLS_SCOPE_PREDEFINED)
        self.assertEqual(profile.ssl_tls_min_version, "tls1-3")
        self.assertEqual(profile.ssl_tls_certificate_name, "TLSv1.3_Default")

    def test_a_weak_predefined_entry_would_beat_a_strong_shared_one(self):
        """The same rule where the verdict DOES turn on it.

        Contrived - the shipped profile is TLS 1.3 only - but it is the test that would fail
        if resolution order were ever flipped to shared-first, which the previous test cannot
        catch on its own.
        """
        self._profile("fw-shadowed", bound="collide",
                      shared=self._entry("collide", "tls1-2", "tls1-3"),
                      predefined=self._entry("collide", "tls1-0", "tls1-3"))
        self.assertIn("fw-shadowed", self._findings())

    def test_a_binding_that_resolves_nowhere_is_reported_not_passed(self):
        """An unknown floor is not evidence of an acceptable one."""
        profile = self._profile("fw-dangling", bound="missing-profile")
        self.assertEqual(
            profile.ssl_tls_profile_scope,
            DeviceConfigurationProfile.SSL_TLS_SCOPE_UNRESOLVED)
        self.assertEqual(profile.ssl_tls_min_version, "")
        self.assertIn("fw-dangling", self._findings())
        self.assertTrue(
            NormalizationIssue.objects.filter(
                appliance__hostname="fw-dangling",
                kind="ssl_tls_service_profile_unresolved").exists(),
            "a dangling binding must say why it could not be resolved")

    def test_a_profile_without_protocol_settings_is_reported_not_passed(self):
        """Resolved, but silent about its floor.

        What an absent protocol-settings node means for a profile that exists has never been
        measured, so it is reported rather than assumed benign. If it is ever measured, this
        test is the place the assumption is recorded.
        """
        profile = self._profile(
            "fw-silent", bound="bare",
            shared=[{"@name": "bare", "certificate": "cert"}])
        self.assertEqual(
            profile.ssl_tls_profile_scope,
            DeviceConfigurationProfile.SSL_TLS_SCOPE_SHARED)
        self.assertEqual(profile.ssl_tls_min_version, "")
        self.assertIn("fw-silent", self._findings())
