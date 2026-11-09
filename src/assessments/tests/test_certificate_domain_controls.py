"""The certificate domain's four Certificate-model controls, and the severity calibrations.

`test_certificate_controls.py` already covers PAN-CRT-002 and PAN-CRT-003's assertions against
real decoded certificates. What is here is what those tests cannot see, because they seed the
catalog's queries WITHOUT `adjusted_severity` and so never exercise the calibration half:

* PAN-CRT-001 and PAN-CRT-008, which had no catalog entry at all until 2026-10-30, and which
  read ONE column in OPPOSITE senses - `not_relied_on eq false` is "in use, or nobody could
  tell" and fires on an incomplete reference walk; `eq true` is "the walk ran and found
  nothing" and is silent until it has. Both directions are asserted here, because the whole
  argument for the polarity is that the destructive finding stays quiet and the other one does
  not.
* The two severity calibrations, which are the part a diff against an expectation cannot check
  on its own: a row firing at the right severity through the WRONG query is a control that is
  right about this object by accident.
* The two cases the queries these replaced got WRONG, both of which pass silently rather than
  erroring: an algorithm the floor set does not carry, and a signature identifier that names no
  hash. Each one is a certificate that reads perfectly, carries no parse error, and passed every
  query written over the evidence columns.

Every query is seeded from `seed.json` rather than written here, including `adjusted_severity`,
so a test passing is a statement about the shipped catalog and not about a fixture.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID
from django.test import TestCase
from django.utils import timezone

from assessments.certificate_findings import generate_certificate_findings
from assessments.models import AssessmentRun, CertificateFinding, Control
from assessments.tests._seed import seed_controls
from assessments.tests.test_certificate_controls import SHA1_SIGNED_PEM
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, Certificate, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_appliance_certificate_objects)
from optivedge_integrations.integrations.platforms.pan_os.normalization.certificates import (
    key_strength_band)

CONTROLS = ("PAN-CRT-001", "PAN-CRT-002", "PAN-CRT-003", "PAN-CRT-008")


def make_pem(*, key, signature_hash, common_name, days_valid=365, days_ago=0,
             is_ca=False, pss=False):
    """One self-signed certificate as PEM. Public half only - no private key is stored.

    `days_ago` moves BOTH bounds back, which is how an already-expired certificate is built:
    the decoder reads the dates out of the blob and nothing else on the device is consulted.
    """
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    begins = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(begins)
        .not_valid_after(begins + datetime.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if pss:
        certificate = builder.sign(
            key, signature_hash,
            rsa_padding=padding.PSS(mgf=padding.MGF1(signature_hash),
                                    salt_length=padding.PSS.DIGEST_LENGTH))
    else:
        certificate = builder.sign(key, signature_hash)
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def rsa_key(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


class CertificateDomainControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.crtdom")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-crtdom",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        # `_seed.seed_controls` and NOT a loop written here. Its own docstring records why: every
        # control test used to hand-roll this and each copy chose its own subset of the fields the
        # importer sets, which hid `adjusted_severity` for a month and `asserted_fields` for two
        # days. This module needs both, so a private copy would have been the same defect again.
        seed_controls(CONTROLS)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _appliance(self, hostname, certificates, *, tls=None, profiles=None):
        """One appliance, its certificates, and OPTIONALLY the objects that reference them.

        The referrers are not decoration. `not_relied_on` is computed by a walk that runs on
        every normalization over the rows it is about to write, so a fixture holding
        certificates and nothing else produces `not_relied_on = True` for every one of them -
        which SILENCES PAN-CRT-001 and FIRES PAN-CRT-008. A test for either control that omits
        the referrers is testing the empty-estate case without meaning to.
        """
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=f"S-{hostname}", hostname=hostname)
        shared = {"certificate": {"entry": certificates}}
        if tls:
            shared["ssl-tls-service-profile"] = {"entry": tls}
        if profiles:
            shared["certificate-profile"] = {"entry": profiles}
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {
                "devices": {"entry": {"deviceconfig": {"system": {}}}},
                "shared": shared}})
        normalize_appliance_certificate_objects(appliance)
        return appliance

    @staticmethod
    def _presenting(profile_name, certificate_name):
        return {"@name": profile_name, "certificate": certificate_name,
                "protocol-settings": {"min-version": "tls1-2"}}

    def _findings(self, control_id):
        generate_certificate_findings(self.run)
        return {f.subject_name: f for f in CertificateFinding.objects.select_related("control")
                if f.control.control_id == control_id}

    # ---- PAN-CRT-001 -------------------------------------------------------------------

    def test_an_expired_certificate_reports_and_a_current_one_does_not(self):
        self._appliance(
            "fw-expiry",
            [{"@name": "lapsed", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(),
                common_name="lapsed", days_valid=30, days_ago=400)},
             {"@name": "current", "public-key": make_pem(
                 key=rsa_key(), signature_hash=hashes.SHA256(),
                 common_name="current", days_valid=3650)}],
            tls=[self._presenting("serves-lapsed", "lapsed"),
                 self._presenting("serves-current", "current")])
        self.assertEqual(set(self._findings("PAN-CRT-001")), {"lapsed"})
        self.assertTrue(Certificate.objects.get(name="lapsed").is_expired)
        self.assertFalse(Certificate.objects.get(name="current").is_expired)

    def test_the_expired_finding_does_not_claim_the_certificate_is_in_use(self):
        """The sentence is the whole point, and the column cannot support the stronger one.

        `not_relied_on` false means "something names it OR nobody could tell", and the map
        behind it is a floor - 65 of 69 known reference locations are covered by no collected
        model. So the finding may say that nothing establishes that nothing depends on this
        certificate, and may NOT say it is in use.
        """
        self._appliance(
            "fw-sentence",
            [{"@name": "lapsed", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(),
                common_name="lapsed", days_valid=30, days_ago=400)}],
            tls=[self._presenting("serves-lapsed", "lapsed")])
        finding = self._findings("PAN-CRT-001")["lapsed"]
        self.assertEqual(
            finding.matched_query_names,
            ["Expired, and nothing establishes that nothing depends on it"])
        self.assertNotIn("in use", finding.summary)
        self.assertIn("nothing establishes", finding.summary)

    def test_an_expired_certificate_no_collected_object_references_is_SILENT(self):
        """THE CONSEQUENCE OF THE REFERENCE MAP BEING A FLOOR, and it runs the wrong way.

        The walk runs on every normalization and reports what the COLLECTED models hold. It has
        three edges - a service profile's certificate, a validation profile's CA list, and the
        issuer-hash chain - against 69 known locations where this platform can reference a
        certificate, so 65 of them answer "nothing relies on it" by not being looked at.
        `not_relied_on` is then TRUE, and PAN-CRT-001 clauses on FALSE, so an expired
        certificate referenced only by GlobalProtect, SAML or syslog TLS produces NO finding.

        This is asserted rather than fixed because it is not this layer's to fix: the column is
        stage 7's and the clause is stage 5's. It is written down here so that the day a
        collector gains one of the other 66 edges, this test says what changes.
        """
        self._appliance("fw-unreferenced", [
            {"@name": "lapsed-and-unseen", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(),
                common_name="lapsed-and-unseen", days_valid=30, days_ago=400)},
        ])
        row = Certificate.objects.get(name="lapsed-and-unseen")
        self.assertTrue(row.is_expired)
        self.assertTrue(row.not_relied_on)
        self.assertEqual(row.relied_on_by, [])
        self.assertEqual(self._findings("PAN-CRT-001"), {})

    def test_an_undecodable_certificate_reports_as_expired(self):
        """`is_expired` defaults TRUE, so a blob nobody could read reports rather than passing.

        A certificate whose validity nobody has checked has not been shown to be current, and
        the stored default is what makes that the outcome instead of a null passing the clause.
        """
        self._appliance(
            "fw-unreadable",
            [{"@name": "garbage", "public-key": "-----BEGIN CERTIFICATE-----\nnope\n"}],
            tls=[self._presenting("serves-garbage", "garbage")])
        row = Certificate.objects.get(name="garbage")
        self.assertTrue(row.parse_error)
        self.assertIsNone(row.not_valid_after)
        self.assertTrue(row.is_expired)
        self.assertEqual(set(self._findings("PAN-CRT-001")), {"garbage"})

    # ---- PAN-CRT-008 -------------------------------------------------------------------

    def test_the_migration_default_is_the_quiet_side_of_this_control(self):
        """A row written before any walk holds FALSE, so the destructive finding stays silent.

        The finding says to review an authority for removal, the action is a DELETE, and an
        authority whose private key is held nowhere else cannot be recreated - so the window
        between a migration and the first normalization pass must not advise deleting anything.
        PAN-CRT-001 reads the same column in the other sense, so that window is still loud about
        expiry.
        """
        self.assertFalse(Certificate().not_relied_on)
        self.assertTrue(Certificate().is_expired)

    def test_an_authority_a_validation_profile_names_is_silent(self):
        self._appliance(
            "fw-named-ca",
            [{"@name": "used-ca", "ca": "yes", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(),
                common_name="used-ca", days_valid=3650, is_ca=True)}],
            profiles=[{"@name": "validates", "use-crl": "yes",
                       "block-unknown-cert": "yes", "block-timeout-cert": "yes",
                       "CA": {"entry": [{"@name": "used-ca"}]}}])
        row = Certificate.objects.get(name="used-ca")
        self.assertFalse(row.not_relied_on)
        self.assertEqual([r["kind"] for r in row.relied_on_by], ["certificate-profile"])
        self.assertEqual(self._findings("PAN-CRT-008"), {})

    def test_an_authority_nothing_names_but_that_signed_something_is_silent(self):
        """The central case, and the one a name-only scan gets wrong.

        Within one surface a certificate's issuer-hash equals its issuer's subject-hash, so an
        authority NO object names is found to be in use because of what it signed. A control
        written on name references alone would propose deleting an authority that is still
        issuing.
        """
        self._appliance("fw-chain", [
            {"@name": "issuing-ca", "ca": "yes", "subject-hash": "aaaa1111",
             "issuer-hash": "aaaa1111", "public-key": make_pem(
                 key=rsa_key(), signature_hash=hashes.SHA256(),
                 common_name="issuing-ca", days_valid=3650, is_ca=True)},
            {"@name": "its-leaf", "subject-hash": "bbbb2222", "issuer-hash": "aaaa1111",
             "public-key": make_pem(
                 key=rsa_key(), signature_hash=hashes.SHA256(),
                 common_name="its-leaf", days_valid=3650)},
        ])
        row = Certificate.objects.get(name="issuing-ca")
        self.assertEqual([r["name"] for r in row.relied_on_by], ["its-leaf"])
        self.assertFalse(row.not_relied_on)
        self.assertEqual(self._findings("PAN-CRT-008"), {})

    def test_an_authority_no_collected_object_references_fires_and_only_the_authority(self):
        """The applicability clause is the CA flag, so an unreferenced LEAF is not reported here.

        And this is the same floor as the PAN-CRT-001 case, pointing the other way: an authority
        referenced only by one of the 65 uncollected locations reads as unreferenced and IS
        reported. That direction was chosen deliberately - the finding asks for a review rather
        than performing a delete - but it is the louder half of the same incompleteness and a
        reader of the finding needs the referrer list beside it.
        """
        self._appliance("fw-orphan", [
            {"@name": "orphan-ca", "ca": "yes", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(),
                common_name="orphan-ca", days_valid=3650, is_ca=True)},
            {"@name": "orphan-leaf", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(),
                common_name="orphan-leaf", days_valid=3650)},
        ])
        self.assertTrue(Certificate.objects.get(name="orphan-ca").is_ca)
        self.assertFalse(Certificate.objects.get(name="orphan-leaf").is_ca)
        self.assertEqual(set(self._findings("PAN-CRT-008")), {"orphan-ca"})

    def test_the_two_senses_of_one_column_never_report_the_same_row(self):
        """One column, two clause senses, and they are exclusive by construction.

        An expired authority is reported by exactly one of the two controls and which one
        depends on the walk: referenced, and PAN-CRT-001 says reissue it; unreferenced, and
        PAN-CRT-008 says review it for removal. The point of asserting it is that the senses
        cannot collapse - a change making the column fire both ways would make one of these
        findings disappear rather than error.
        """
        self._appliance(
            "fw-both",
            [{"@name": "lapsed-ca", "ca": "yes", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(),
                common_name="lapsed-ca", days_valid=30, days_ago=400, is_ca=True)}],
            profiles=[{"@name": "validates", "use-crl": "yes",
                       "block-unknown-cert": "yes", "block-timeout-cert": "yes",
                       "CA": {"entry": [{"@name": "lapsed-ca"}]}}])
        self.assertEqual(set(self._findings("PAN-CRT-001")), {"lapsed-ca"})
        self.assertEqual(self._findings("PAN-CRT-008"), {})

        Certificate.objects.filter(name="lapsed-ca").update(
            not_relied_on=True, relied_on_by=[])
        self.assertEqual(set(self._findings("PAN-CRT-008")), {"lapsed-ca"})
        self.assertEqual(self._findings("PAN-CRT-001"), {})

    # ---- PAN-CRT-002, the calibration and the case the paired form passed ---------------

    def test_rsa_512_reports_critical_and_rsa_1024_reports_high(self):
        """The calibration, and the severity is the worst MATCHED query's.

        The far-below band matches both the baseline and the calibration query, so the
        calibration wins; the below band matches the baseline alone and keeps the control's own
        tier. Neither severity is written here - both come from the seeded catalog.

        THE 512-BIT ROW'S BAND IS SET RATHER THAN DECODED, and the rule is asserted against the
        Integrations helper rather than against the literal: `cryptography` 50 refuses to
        GENERATE an RSA key below 1024 bits, while the estate contains 512-bit certificates and
        stage 4 wrote one. Same asymmetry as the SHA-1 case, one layer down - the decoder reads
        what this library will not create, so the band is computed by the real function and
        written to the row.
        """
        self._appliance("fw-bands", [
            {"@name": "rsa-512", "public-key": make_pem(
                key=rsa_key(1024), signature_hash=hashes.SHA256(), common_name="rsa512")},
            {"@name": "rsa-1024", "public-key": make_pem(
                key=rsa_key(1024), signature_hash=hashes.SHA256(), common_name="rsa1024")},
            {"@name": "rsa-2048", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(), common_name="rsa2048")},
        ])
        self.assertEqual(key_strength_band("RSA", 512, ""), Certificate.BAND_FAR_BELOW)
        Certificate.objects.filter(name="rsa-512").update(
            key_size_bits=512, key_strength_band=key_strength_band("RSA", 512, ""))
        findings = self._findings("PAN-CRT-002")
        self.assertEqual(set(findings), {"rsa-512", "rsa-1024"})
        self.assertEqual(findings["rsa-512"].severity, Control.Severity.CRITICAL)
        self.assertEqual(findings["rsa-1024"].severity, Control.Severity.HIGH)
        self.assertEqual(
            findings["rsa-512"].matched_query_names,
            ["The key is below the strength floor carried for its own algorithm",
             "The key is far below the floor for its algorithm"])
        self.assertEqual(
            findings["rsa-1024"].matched_query_names,
            ["The key is below the strength floor carried for its own algorithm"])
        self.assertEqual(
            Certificate.objects.get(name="rsa-1024").key_strength_band,
            Certificate.BAND_BELOW)

    def test_an_algorithm_with_no_floor_reports_and_used_to_pass(self):
        """THE CASE THE PAIRED FORM GOT WRONG, and nothing about it errored.

        The query this replaced was an OR of RSA/EC/DSA algorithm-and-size groups plus a
        parse-error group. An Ed25519 certificate decodes perfectly, carries no parse error,
        matches none of the three algorithm literals, and has a NULL size that SQL drops from
        both sides of an inequality - so it passed every clause. The band has a member for it
        and that member is on the firing side.
        """
        self._appliance("fw-ed25519", [
            {"@name": "ed25519", "public-key": make_pem(
                key=ed25519.Ed25519PrivateKey.generate(),
                signature_hash=None, common_name="ed25519")},
        ])
        row = Certificate.objects.get(name="ed25519")
        self.assertEqual(row.parse_error, "", "it decodes - that is the whole problem")
        self.assertIsNone(row.key_size_bits)
        self.assertEqual(row.key_strength_band, Certificate.BAND_NO_FLOOR)
        self.assertEqual(set(self._findings("PAN-CRT-002")), {"ed25519"})
        self.assertEqual(
            self._findings("PAN-CRT-002")["ed25519"].severity, Control.Severity.HIGH,
            "stage 5 places this member unranked, so it reports at the control's own tier")

    # ---- PAN-CRT-003, the calibration and the identifier that names no hash -------------

    def test_sha1_reports_medium_and_a_decoded_sha1_certificate_is_a_real_one(self):
        """One graded rank below the baseline tier, on a certificate this library cannot create.

        The corpus allows SHA-1 "only for internal legacy with a documented expiry", which is an
        organizational exception this cannot see - so a SHA-1 finding may legitimately be closed
        as accepted and an MD5 one should not be, and the severity is where that difference is
        carried. The PEM is a captured artifact shared with `test_certificate_controls`:
        `cryptography` 50 refuses to SIGN with SHA-1 while still parsing it, which is exactly the
        asymmetry the control lives in.
        """
        self._appliance("fw-sha1", [
            {"@name": "signed-sha1", "public-key": SHA1_SIGNED_PEM},
            {"@name": "signed-sha256", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(), common_name="sha256")},
        ])
        row = Certificate.objects.get(name="signed-sha1")
        self.assertEqual(row.signature_hash, "sha1")
        self.assertTrue(row.weak_signature_hash)
        findings = self._findings("PAN-CRT-003")
        self.assertEqual(set(findings), {"signed-sha1"})
        self.assertEqual(findings["signed-sha1"].severity, Control.Severity.MEDIUM)
        self.assertEqual(
            findings["signed-sha1"].matched_query_names,
            ["The signing hash has a practical collision attack, or could not be resolved",
             "The signing hash is SHA-1"])

    def test_md5_reports_at_the_controls_own_tier_and_not_at_sha1s(self):
        """The two weak hashes are graded apart, and MD5 keeps the baseline tier.

        THE COLUMNS ARE SET RATHER THAN DECODED HERE and the reason is the same asymmetry as
        above, one release further on: `cryptography` 50 refuses to sign with MD5 as well, and no
        MD5-signed certificate has been captured off the lab to embed. What is asserted is the
        SEVERITY DERIVATION - that the SHA-1 calibration does not match an MD5 row, so the
        baseline tier survives - which is a property of the queries and not of the decoder. The
        decoder's own behavior on md5 is covered by `signature_hash_is_weak` in Integrations.
        """
        self._appliance("fw-md5", [
            {"@name": "pretend-md5", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(), common_name="md5")},
        ])
        Certificate.objects.filter(name="pretend-md5").update(
            signature_hash="md5", weak_signature_hash=True)
        findings = self._findings("PAN-CRT-003")
        self.assertEqual(set(findings), {"pretend-md5"})
        self.assertEqual(findings["pretend-md5"].severity, Control.Severity.HIGH)
        self.assertEqual(
            findings["pretend-md5"].matched_query_names,
            ["The signing hash has a practical collision attack, or could not be resolved"])

    def test_a_pss_certificate_signed_with_a_weak_hash_is_not_read_off_the_identifier(self):
        """The identifier is not the hash, and the substring query passed this certificate.

        An RSASSA-PSS certificate stores `rsassaPss` as its signature algorithm identifier,
        which names NO hash - for PSS the hash lives in the signature parameters. So
        `signature_algorithm contains sha1` matched nothing on a PSS certificate however it was
        signed. The hash is resolved from the parameters into its own column instead. SHA-256 is
        used here because this library refuses to SIGN with SHA-1 while still parsing it; what
        the test establishes is that the two columns disagree, which is the mechanism.
        """
        self._appliance("fw-pss", [
            {"@name": "pss", "public-key": make_pem(
                key=rsa_key(), signature_hash=hashes.SHA256(), common_name="pss", pss=True)},
        ])
        row = Certificate.objects.get(name="pss")
        self.assertEqual(row.signature_algorithm, "rsassaPss")
        self.assertNotIn("sha", row.signature_algorithm.lower(),
                         "the identifier carries no hash name at all")
        self.assertEqual(row.signature_hash, "sha256")
        self.assertFalse(row.weak_signature_hash)
        self.assertEqual(self._findings("PAN-CRT-003"), {})

    def test_a_certificate_whose_hash_cannot_be_resolved_reports(self):
        """And the row that carries it is the Ed25519 one, where there is no separate hash.

        It is the one placement in this domain where the firing side is also a false positive -
        an Ed25519 signature is sound - and it is recorded rather than quietly excluded, because
        the alternative is a blank hash reading as compliant on a certificate nobody decoded.
        """
        self._appliance("fw-nohash", [
            {"@name": "ed25519", "public-key": make_pem(
                key=ed25519.Ed25519PrivateKey.generate(),
                signature_hash=None, common_name="ed25519")},
        ])
        row = Certificate.objects.get(name="ed25519")
        self.assertEqual(row.signature_hash, "")
        self.assertTrue(row.weak_signature_hash)
        self.assertEqual(set(self._findings("PAN-CRT-003")), {"ed25519"})

    # ---- the scope axis, which every certificate control shares ------------------------

    def test_a_predefined_certificate_is_assessed_and_says_so(self):
        """It is read-only, so a finding against it cannot be remediated on the device.

        Held deliberately rather than filtered out: hiding it would mean the tool silently
        ignores the certificate the vendor's own hardened profile presents. The EC P-256 shape
        is the vendor's and passes, which is the case a single numeric threshold flagged.
        """
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-fw-predef", hostname="fw-predef")
        pem = make_pem(key=ec.generate_private_key(ec.SECP256R1()),
                       signature_hash=hashes.SHA256(), common_name="TLSv1.3_Default",
                       days_valid=3650)
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": {"deviceconfig": {"system": {}}}}}})
        # ITS OWN SNAPSHOT, and not a branch of the merged config: `show config merged` does not
        # carry /config/predefined at all, so the vendor namespace arrives from a separate
        # collector and an appliance collected before that collector existed has none.
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="config_predefined_certificates", collected_at=timezone.now(),
            payload={"certificate": {"entry": [
                {"@name": "TLSv1.3_Default", "public-key": pem}]}})
        normalize_appliance_certificate_objects(appliance)
        row = Certificate.objects.get(name="TLSv1.3_Default")
        self.assertEqual(row.scope, "predefined")
        self.assertEqual(row.key_strength_band, Certificate.BAND_AT_OR_ABOVE)
        self.assertEqual(self._findings("PAN-CRT-002"), {})
        self.assertEqual(self._findings("PAN-CRT-003"), {})
