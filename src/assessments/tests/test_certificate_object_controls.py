"""PAN-CRT-004 and PAN-CRT-005 - the two certificate-domain object controls.

Both assess objects rather than surfaces, which is what separates them from PAN-MGT-010: that
control asks what the management interface has bound, these ask about every profile on the
device whether or not anything uses it.

The defaults are the risk, as they were for the management settings. For certificate profiles
all six booleans default OFF, so a profile that sets nothing performs no revocation checking -
and for SSL/TLS profiles an absent algorithm key means ENABLED, which is the opposite
direction and is why neither was assumed from the other.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.controls_catalog.registry import load_seed_payload
from assessments.certificate_profile_findings import generate_certificate_profile_findings
from assessments.ssl_tls_service_profile_findings import (
    generate_ssl_tls_service_profile_findings)
from assessments.models import (
    AssessmentRun, CertificateProfileFinding, Control, ControlQuery,
    SslTlsServiceProfileFinding)
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, CertificateProfile, ManagementStation, Snapshot,
    SslTlsServiceProfile)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_certificate_objects)

TYPES = {
    "certificate_profile": Control.ControlType.CERTIFICATE_PROFILE,
    "ssl_tls_service_profile": Control.ControlType.SSL_TLS_SERVICE_PROFILE,
}


class CertificateObjectControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.crt")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-crt",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        specs = {c["control_id"]: c for c in load_seed_payload()["catalogs"][0]["controls"]}
        for control_id in ("PAN-CRT-004", "PAN-CRT-005"):
            spec = specs[control_id]
            control = Control.objects.create(
                control_id=control_id, name=spec["name"],
                control_type=TYPES[spec["control_type"]],
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

    def _appliance(self, hostname, *, shared=None, vsys=None):
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=f"S-{hostname}", hostname=hostname)
        device = {"deviceconfig": {"system": {}}}
        if vsys:
            device["vsys"] = {"entry": [{"@name": "vsys1", **vsys}]}
        config = {"devices": {"entry": device}}
        if shared:
            config["shared"] = shared
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": config})
        normalize_appliance_certificate_objects(appliance)
        return appliance

    def _tls_findings(self):
        generate_ssl_tls_service_profile_findings(self.run)
        return {(f.subject_name, f.subject_scope)
                for f in SslTlsServiceProfileFinding.objects.all()}

    def _cert_findings(self):
        generate_certificate_profile_findings(self.run)
        return {(f.subject_name, f.subject_scope)
                for f in CertificateProfileFinding.objects.all()}

    # ---- PAN-CRT-004 -----------------------------------------------------------------

    def test_a_profile_that_sets_nothing_fires(self):
        """The shape pan-fw-111 is actually in: a CA list and nothing else.

        All six booleans default off, so this profile validates certificates against a CA and
        never asks whether they were revoked.
        """
        self._appliance("fw-bare", shared={"certificate-profile": {"entry": [
            {"@name": "quick", "CA": {"entry": [{"@name": "some-ca"}]}}]}})
        self.assertEqual(self._cert_findings(), {("quick", "shared")})
        profile = CertificateProfile.objects.get(name="quick")
        self.assertFalse(profile.use_crl)
        self.assertFalse(profile.use_ocsp)
        self.assertEqual(profile.crl_receive_timeout, 5)
        self.assertEqual(profile.ca_certificate_names, ["some-ca"])

    def test_either_leaf_satisfies_the_floor(self):
        """The corpus says CRL or OCSP - not both. Two profiles, one of each, neither fires."""
        self._appliance("fw-ok", shared={"certificate-profile": {"entry": [
            {"@name": "crl-only", "use-crl": "yes"},
            {"@name": "ocsp-only", "use-ocsp": "yes"}]}})
        self.assertEqual(self._cert_findings(), set())

    def test_an_explicit_no_fires_like_an_absent_key(self):
        """Both mean no revocation checking, so both must report.

        The measured default is what makes this correct rather than convenient: absent is
        DISABLED, so writing `no` changes nothing about behaviour and must not change the
        verdict either.
        """
        self._appliance("fw-explicit", shared={"certificate-profile": {"entry": [
            {"@name": "off", "use-crl": "no", "use-ocsp": "no"}]}})
        self.assertEqual(self._cert_findings(), {("off", "shared")})

    # ---- PAN-CRT-005 -----------------------------------------------------------------

    def test_a_tls_1_0_floor_fires_and_a_1_2_floor_does_not(self):
        self._appliance("fw-mixed", shared={"ssl-tls-service-profile": {"entry": [
            {"@name": "legacy", "certificate": "c",
             "protocol-settings": {"min-version": "tls1-0", "max-version": "tls1-2"}},
            {"@name": "modern", "certificate": "c",
             "protocol-settings": {"min-version": "tls1-2", "max-version": "tls1-3"}}]}})
        self.assertEqual(self._tls_findings(), {("legacy", "shared")})

    def test_a_profile_with_no_protocol_settings_is_reported_not_passed(self):
        """An unknown floor is not evidence of an acceptable one.

        What an absent min-version means was never measured - no lab profile omits it - so it
        is reported rather than assumed benign.
        """
        self._appliance("fw-silent", shared={"ssl-tls-service-profile": {"entry": [
            {"@name": "bare", "certificate": "c"}]}})
        self.assertEqual(self._tls_findings(), {("bare", "shared")})

    def test_absent_algorithm_keys_are_stored_as_ENABLED(self):
        """The measurement that made the key-set correction matter.

        A profile carrying only a version range renders with every algorithm ticked in the UI,
        so it permits SHA-1 and CBC. Storing only what the config contains would make the most
        permissive profile on the device look like the most restrictive one. This control does
        not fire on it - the corpus asserts the floor - but the data must be right.
        """
        self._appliance("fw-implicit", shared={"ssl-tls-service-profile": {"entry": [
            {"@name": "floor-only", "certificate": "c",
             "protocol-settings": {"min-version": "tls1-2", "max-version": "tls1-3"}}]}})
        profile = SslTlsServiceProfile.objects.get(name="floor-only")
        self.assertTrue(profile.protocol_algorithms["auth-algo-sha1"])
        self.assertTrue(profile.protocol_algorithms["enc-algo-aes-128-cbc"])
        self.assertEqual(profile.explicit_algorithms, [],
                         "nothing was written, so nothing is explicit")
        self.assertNotIn("fw-implicit", {n for n, _ in self._tls_findings()})

    def test_explicit_and_implicit_are_distinguishable(self):
        """Two profiles identical once expanded, and different to remediate.

        tpa-b omits every algorithm key; pan-fw-111 writes them all as `yes`. The effective
        settings are the same and the work to fix them is not, so the distinction is stored.
        """
        self._appliance("fw-explicit-algos", shared={"ssl-tls-service-profile": {"entry": [
            {"@name": "written", "certificate": "c",
             "protocol-settings": {"min-version": "tls1-2", "auth-algo-sha1": "yes",
                                   "enc-algo-aes-128-cbc": "yes"}}]}})
        profile = SslTlsServiceProfile.objects.get(name="written")
        self.assertTrue(profile.protocol_algorithms["auth-algo-sha1"])
        self.assertEqual(profile.explicit_algorithms,
                         ["auth-algo-sha1", "enc-algo-aes-128-cbc"])

    def test_scope_is_recorded_and_a_name_is_not_unique(self):
        """Two profiles, one name, two scopes - and the finding must say which."""
        self._appliance(
            "fw-scoped",
            shared={"ssl-tls-service-profile": {"entry": [
                {"@name": "dup", "certificate": "c",
                 "protocol-settings": {"min-version": "tls1-2"}}]}},
            vsys={"ssl-tls-service-profile": {"entry": [
                {"@name": "dup", "certificate": "c",
                 "protocol-settings": {"min-version": "tls1-0"}}]}})
        self.assertEqual(SslTlsServiceProfile.objects.filter(name="dup").count(), 2)
        self.assertEqual(self._tls_findings(), {("dup", "vsys")})
        finding = SslTlsServiceProfileFinding.objects.get()
        self.assertEqual(finding.ssl_tls_service_profile.vsys_name, "vsys1")

    def test_a_removed_profile_does_not_leave_a_stale_row(self):
        """A stale object row is a false finding, which hygiene controls cannot afford."""
        appliance = self._appliance("fw-churn", shared={"ssl-tls-service-profile": {"entry": [
            {"@name": "gone", "certificate": "c",
             "protocol-settings": {"min-version": "tls1-0"}}]}})
        self.assertEqual(self._tls_findings(), {("gone", "shared")})
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": {"deviceconfig": {"system": {}}}},
                                "shared": {}}})
        normalize_appliance_certificate_objects(appliance)
        self.assertEqual(SslTlsServiceProfile.objects.filter(appliance=appliance).count(), 0)
        self.assertEqual(self._tls_findings(), set())
