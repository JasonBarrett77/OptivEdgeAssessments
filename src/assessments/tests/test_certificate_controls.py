"""PAN-CRT-002 and PAN-CRT-003 - key strength and signature algorithm.

Neither value exists in any PAN-OS configuration field. `algorithm` reports RSA or EC, the KEY
algorithm; the size and the signature come from decoding the X.509 blob PAN-OS stores under
`public-key`. So these tests exercise real certificates rather than fixture dictionaries - the
PEMs are generated in-process, because a test asserting on a hand-written dict would prove the
query and not the decoding.

The case worth protecting is the EC one. 256-bit EC is strong and 256-bit RSA is broken, so a
control written as `key_size_bits < 2048` passes review, reads sensibly, and flags the vendor's
own TLSv1.3_Default certificate on every appliance.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from django.test import TestCase
from django.utils import timezone

from assessments.certificate_findings import generate_certificate_findings
from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import AssessmentRun, CertificateFinding, Control, ControlQuery
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, Certificate, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_certificate_objects)

CONTROLS = ("PAN-CRT-002", "PAN-CRT-003")


#: A REAL SHA-1 signed certificate, embedded as a literal because it cannot be generated here:
#: `cryptography` 50 refuses to SIGN with SHA-1, while still parsing certificates signed with
#: it - which is exactly the asymmetry this control lives in. The estate contains SHA-1
#: certificates that no current library would produce, so the decoder must handle what it
#: cannot create.
#:
#: Captured 2026-09-03 from oep-cert-sha1 on fw-core-tpa-b, generated there by
#: `request certificate generate ... digest sha1`. Public certificate only - no private key.
SHA1_SIGNED_PEM = """-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUL6Uw2WGg3hBODervc0pGsOn8ebUwDQYJKoZIhvcNAQEF
BQAwFzEVMBMGA1UEAwwMb2VwLXNoYTEubGFiMB4XDTI2MDkwMzE3NTU0NFoXDTI3
MDkwMzE3NTU0NFowFzEVMBMGA1UEAwwMb2VwLXNoYTEubGFiMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz0t4SHkY4rvsEQIOGhPxDqbI8DW40WrvISOf
nPp4WaBoe43+HkiUkPWVG/Y50kGGAMPHf7b6BKN4nqOJC5RufS1Ez2VYa4DiDmHd
XP07EcS6MqEh3g7CAZfsJh5jbWMKq93DFceZBQr4V96pImEDtW/AODP0vhuQN3tA
9Q+7ysBrXdBkhXWEQiElj3HedJiFIRgaD634ic49BtCBXwsgJkbVpiIp+Eop51CY
G+fk5YDhxWS04XWrRM8OS2vPTt9vQHY9CGec5uOCZoHrOPpQwNQz0NbBhsKSo/it
OjIX8KTZz+ZYDOutRfQxL7sHjutvO47SULXaHbnFLISKWrcQKwIDAQABo2UwYzAM
BgNVHRMEBTADAQH/MAsGA1UdDwQEAwICBDAdBgNVHQ4EFgQUFJ5bxfqSXFYtB9Dv
wXFIitKFms8wJwYDVR0lBCAwHgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcD
CTANBgkqhkiG9w0BAQUFAAOCAQEAvorDQ+incP5jT/vcSatg/LLs7Z5zwEqnx0N0
YEu3kNabqVGqSqg3U9pznv4YXw8fiYeRyyR6PuAKSMbi7KxUZX2BoP0lmnU/5tdp
BnMVp0tzqdSsFcYaWsOsTPFzowQ4rCk5WXLrOIb2qQevnjoQH6adGnlR+QedcD7J
0Z0+iBuZrVL+la1jdPA8Wdsv2B9RxBPYOWqOPtZnwvTbxiCmEFkrMz5tBnMVibSg
CXwCllMhgxueH34kueRIBo5QwXY0MMuO6apAPpItvAny2YMllXsejrjQMM/Uwj9e
w2leUkTo7GeBGGAVZ+JSk2W5FC0t/eJUyHye/GBsFDaSMP/3ww==
-----END CERTIFICATE-----
"""


def make_pem(*, key, signature_hash, common_name):
    """A real certificate, so the decoding path is exercised rather than mocked."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, signature_hash)
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


class CertificateControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.cert")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-cert",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        specs = {c["control_id"]: c for c in load_seed_payload()["catalogs"][0]["controls"]}
        for control_id in CONTROLS:
            spec = specs[control_id]
            control = Control.objects.create(
                control_id=control_id, name=spec["name"],
                control_type=Control.ControlType.CERTIFICATE,
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

    def _appliance(self, hostname, certificates):
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=f"S-{hostname}", hostname=hostname)
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {
                "devices": {"entry": {"deviceconfig": {"system": {}}}},
                "shared": {"certificate": {"entry": certificates}}}})
        normalize_appliance_certificate_objects(appliance)
        return appliance

    def _findings(self, control_id):
        generate_certificate_findings(self.run)
        return {f.subject_name for f in CertificateFinding.objects.select_related("control")
                if f.control.control_id == control_id}

    def test_ec_256_passes_while_rsa_1024_fires(self):
        """The whole reason the threshold is per algorithm.

        A control written as `key_size_bits < 2048` would flag the EC certificate here - which
        is the vendor's own TLSv1.3_Default shape - and it is the stronger of the two.
        """
        self._appliance("fw-mixed", [
            {"@name": "ec-256", "public-key": make_pem(
                key=ec.generate_private_key(ec.SECP256R1()),
                signature_hash=hashes.SHA256(), common_name="ec")},
            {"@name": "rsa-1024", "public-key": make_pem(
                key=rsa.generate_private_key(public_exponent=65537, key_size=1024),
                signature_hash=hashes.SHA256(), common_name="rsa1024")},
        ])
        self.assertEqual(self._findings("PAN-CRT-002"), {"rsa-1024"})
        ec_certificate = Certificate.objects.get(name="ec-256")
        self.assertEqual(ec_certificate.key_size_bits, 256)
        self.assertIn("EC", ec_certificate.key_algorithm)
        self.assertIn("secp256r1", ec_certificate.key_algorithm,
                      "the curve name must travel with the size, or 256 misleads")

    def test_rsa_2048_passes(self):
        self._appliance("fw-ok", [
            {"@name": "rsa-2048", "public-key": make_pem(
                key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
                signature_hash=hashes.SHA256(), common_name="rsa2048")},
        ])
        self.assertEqual(self._findings("PAN-CRT-002"), set())

    def test_sha1_fires_but_sha256_does_not(self):
        """The SHA-1 certificate is a captured artifact, not a generated one.

        `cryptography` refuses to sign with SHA-1 while still parsing it, which is the exact
        asymmetry the control lives in: the estate contains certificates no current library
        would produce, and the decoder has to read what it cannot create.
        """
        self._appliance("fw-sigs", [
            {"@name": "signed-sha1", "public-key": SHA1_SIGNED_PEM},
            {"@name": "signed-sha256", "public-key": make_pem(
                key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
                signature_hash=hashes.SHA256(), common_name="sha256")},
        ])
        self.assertEqual(self._findings("PAN-CRT-003"), {"signed-sha1"})
        self.assertEqual(
            Certificate.objects.get(name="signed-sha1").signature_algorithm,
            "sha1WithRSAEncryption")

    def test_the_two_controls_are_independent(self):
        """A weak key with a strong signature fires one, not both."""
        self._appliance("fw-split", [
            {"@name": "weak-key-strong-sig", "public-key": make_pem(
                key=rsa.generate_private_key(public_exponent=65537, key_size=1024),
                signature_hash=hashes.SHA256(), common_name="a")},
            {"@name": "strong-key-weak-sig", "public-key": SHA1_SIGNED_PEM},
        ])
        self.assertEqual(self._findings("PAN-CRT-002"), {"weak-key-strong-sig"})
        self.assertEqual(self._findings("PAN-CRT-003"), {"strong-key-weak-sig"})

    def test_an_undecodable_certificate_is_reported_by_both(self):
        """An unreadable certificate is not a compliant one.

        It also must not slip through the numeric clause: key_size_bits is NULL, and SQL drops
        NULLs from an inequality, so `< 2048` would silently not match it.
        """
        self._appliance("fw-broken", [
            {"@name": "garbage", "public-key": "-----BEGIN CERTIFICATE-----\nnope\n"},
        ])
        certificate = Certificate.objects.get(name="garbage")
        self.assertTrue(certificate.parse_error)
        self.assertIsNone(certificate.key_size_bits)
        self.assertEqual(self._findings("PAN-CRT-002"), {"garbage"})
        self.assertEqual(self._findings("PAN-CRT-003"), {"garbage"})

    def test_a_certificate_with_no_blob_is_reported(self):
        self._appliance("fw-empty", [{"@name": "no-blob"}])
        self.assertEqual(Certificate.objects.get(name="no-blob").parse_error,
                         "no certificate data")
        self.assertEqual(self._findings("PAN-CRT-002"), {"no-blob"})

    def test_self_signed_needs_both_hashes_present(self):
        """Two blanks compare equal, which would mark every unhashed certificate self-signed."""
        self._appliance("fw-hashes", [
            {"@name": "no-hashes", "public-key": make_pem(
                key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
                signature_hash=hashes.SHA256(), common_name="c")},
        ])
        self.assertFalse(Certificate.objects.get(name="no-hashes").is_self_signed)
