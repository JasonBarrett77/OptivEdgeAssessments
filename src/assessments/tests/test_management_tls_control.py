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
CERT_CONTROL_ID = "PAN-CRT-006"


class ManagementTlsControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.tls")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-tls",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        specs = {c["control_id"]: c
                 for c in load_seed_payload()["catalogs"][0]["controls"]}
        for control_id in (CONTROL_ID, CERT_CONTROL_ID):
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

    def _profile(self, hostname, *, bound=None, shared=None, predefined=None,
                 shared_certs=None, predefined_certs=None):
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=f"S-{hostname}", hostname=hostname)
        system = {}
        if bound is not None:
            system["ssl-tls-service-profile"] = bound
        config = {"devices": {"entry": {"deviceconfig": {"system": system}}}}
        if shared is not None:
            config.setdefault("shared", {})["ssl-tls-service-profile"] = {"entry": shared}
        if shared_certs is not None:
            config.setdefault("shared", {})["certificate"] = {"entry": shared_certs}
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
        if predefined_certs is not None:
            Snapshot.objects.create(
                management_station=self.station, appliance=appliance,
                source_type="config_predefined_certificates",
                collected_at=timezone.now(),
                payload={"certificate": {"entry": predefined_certs}})
        normalize_appliance_device_configuration(appliance)
        return DeviceConfigurationProfile.objects.get(appliance=appliance)

    def _findings(self, control_id=CONTROL_ID):
        generate_device_configuration_findings(self.run)
        return {f.device_configuration_profile.appliance.hostname
                for f in DeviceConfigurationFinding.objects.select_related(
                    "control", "device_configuration_profile__appliance")
                if f.control.control_id == control_id}

    def _cert(self, name, *, subject_hash, issuer_hash, issuer):
        return [{"@name": name, "subject-hash": subject_hash,
                 "issuer-hash": issuer_hash, "issuer": issuer, "subject": issuer}]

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


class ManagementCertificateControlTests(ManagementTlsControlTests):
    """PAN-CRT-006 - the certificate half, split out of PAN-MGT-010.

    The split exists because the two fail independently, and the lab proves it on one row:
    fw-core-tpa-b binds a profile at min tls1-2 with a self-signed certificate, so it PASSES
    010 and FAILS 014. Testing them together in one class keeps that relationship visible.
    """

    def test_the_shipped_profile_passes_the_floor_and_fails_the_certificate(self):
        """The single most important row, and the reason these are two controls.

        TLSv1.3_Default is the obvious remediation for PAN-MGT-010 - it is shipped, needs no
        certificate work, and gives the strongest floor available. Measured 2026-09-02, its
        certificate is /config/predefined/certificate's TLSv1.3_Default, which is the
        DEVICE'S OWN factory certificate: common-name equal to the chassis serial, and
        self-signed. So taking the easy fix for 010 leaves 014 failing, and a single merged
        control would have reported that device as compliant.
        """
        profile = self._profile(
            "fw-shipped", bound="TLSv1.3_Default",
            predefined=self._entry("TLSv1.3_Default", "tls1-3", "tls1-3",
                                   certificate="TLSv1.3_Default"),
            predefined_certs=self._cert("TLSv1.3_Default", subject_hash="a95dc92c",
                                        issuer_hash="a95dc92c", issuer="013201001085"))
        self.assertEqual(profile.ssl_tls_min_version, "tls1-3")
        self.assertEqual(profile.ssl_tls_certificate_trust,
                         DeviceConfigurationProfile.TRUST_SELF_SIGNED)
        self.assertNotIn("fw-shipped", self._findings(CONTROL_ID))
        self.assertIn("fw-shipped", self._findings(CERT_CONTROL_ID))

    def test_a_ca_issued_certificate_passes(self):
        profile = self._profile(
            "fw-ca", bound="hardened",
            shared=self._entry("hardened", "tls1-2", "tls1-3", certificate="corp"),
            shared_certs=self._cert("corp", subject_hash="1111aaaa",
                                    issuer_hash="2222bbbb", issuer="/CN=Corp Issuing CA"))
        self.assertEqual(profile.ssl_tls_certificate_trust,
                         DeviceConfigurationProfile.TRUST_CA_ISSUED)
        self.assertEqual(profile.ssl_tls_certificate_issuer, "/CN=Corp Issuing CA")
        self.assertNotIn("fw-ca", self._findings(CERT_CONTROL_ID))

    def test_self_signed_is_decided_by_hashes_not_by_comparing_names(self):
        """The DN strings are formatted differently between scopes.

        Measured 2026-09-02: a shared certificate reports subject "/CN=oep-tls-test.lab" while
        a predefined one reports a bare "013201001085". Comparing subject to issuer as TEXT
        happens to work within one scope and silently stops working across them, so PAN-OS's
        own hashes are the oracle. This fixture makes the two disagree on purpose: identical
        hashes with differently-formatted names must still read self-signed.
        """
        profile = self._profile(
            "fw-hashes", bound="p",
            shared=self._entry("p", "tls1-2", "tls1-3", certificate="c"),
            shared_certs=[{"@name": "c", "subject-hash": "dead", "issuer-hash": "dead",
                           "subject": "/CN=thing", "issuer": "thing"}])
        self.assertEqual(profile.ssl_tls_certificate_trust,
                         DeviceConfigurationProfile.TRUST_SELF_SIGNED)

    def test_nothing_bound_still_reports(self):
        """Follows the precedent set for PAN-MGT-008.

        With no profile bound the device serves its own self-signed certificate, so the gap is
        real even though remediating it requires binding a profile first - exactly the shape
        of a missing banner acknowledgement, which was ruled to report regardless of whether a
        banner exists.
        """
        profile = self._profile("fw-none")
        self.assertEqual(profile.ssl_tls_certificate_trust, "")
        self.assertIn("fw-none", self._findings(CERT_CONTROL_ID))

    def test_a_certificate_that_resolves_nowhere_is_undetermined_not_passed(self):
        profile = self._profile(
            "fw-nocert", bound="p",
            shared=self._entry("p", "tls1-2", "tls1-3", certificate="missing"))
        self.assertEqual(profile.ssl_tls_certificate_trust,
                         DeviceConfigurationProfile.TRUST_UNDETERMINED)
        self.assertIn("fw-nocert", self._findings(CERT_CONTROL_ID))
        self.assertNotIn("fw-nocert", self._findings(CONTROL_ID))

    def test_a_certificate_without_hashes_is_undetermined(self):
        profile = self._profile(
            "fw-nohash", bound="p",
            shared=self._entry("p", "tls1-2", "tls1-3", certificate="c"),
            shared_certs=[{"@name": "c", "issuer": "/CN=Something"}])
        self.assertEqual(profile.ssl_tls_certificate_trust,
                         DeviceConfigurationProfile.TRUST_UNDETERMINED)
        self.assertIn("fw-nohash", self._findings(CERT_CONTROL_ID))
