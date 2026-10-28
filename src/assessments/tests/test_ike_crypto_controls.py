"""The nine IKE controls, against the configuration stage 6 of the `ike-crypto` domain built.

EVERY ROW HERE IS A READBACK AND NOT AN INVENTION. The fourteen crypto profiles and nine
gateways below are transcribed from `stage6-ike-crypto.json`'s `verified.read_back` blocks -
what `type=config&action=show` returned from pan-fw-111 after the commit that created each
entry, on 2026-10-27. Stage 6 wrote its expected verdict for each one BEFORE any query existed,
which is what makes this a test of the queries rather than a restatement of them.

WHAT A PER-RECORD EXPECTATION CANNOT ASSERT, and why two of these tests look lopsided. Stage 6
grades one stage 3 ASSERTION RECORD at a time; a finding exists per CONTROL. Where one control
carries two records, a subject the first record fires on and the second excludes produces ONE
finding, and the second record's `no_finding` is not reachable at the grain a finding has.
PAN-IKE-005 and PAN-IKE-008 are both in that shape, and the comments say which rows.

THE SECOND APPLIANCE IS NOT DECORATION. pan-fw-201 carries crypto profiles and NO gateway
container at all, which is this lab's commonest state and the one that makes every gateway
control silent by construction - an absent object SUPPRESSES five controls where an assertion
clause on the same object would have raised them. `test_an_appliance_with_no_gateways` holds
that suppression in place so nobody later reads it as a pass.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.ike_crypto_profile_findings import generate_ike_crypto_profile_findings
from assessments.ike_gateway_findings import generate_ike_gateway_findings
from assessments.models import (
    AssessmentRun, Control, IkeCryptoProfileFinding, IkeGatewayFinding)
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, IkeCryptoProfile, IkeGateway, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.ike import (
    normalize_ike_crypto_profiles, normalize_ike_gateways)

PROFILE_CONTROLS = ["PAN-IKE-002", "PAN-IKE-003", "PAN-IKE-004", "PAN-IKE-005"]
GATEWAY_CONTROLS = ["PAN-IKE-001", "PAN-IKE-006", "PAN-IKE-007", "PAN-IKE-008", "PAN-IKE-009"]

#: The pre-shared key as the device stores it. A 31-character plaintext reads back as this
#: 77-character ciphertext, and the SAME ciphertext came back from all eight gateways that were
#: given the same plaintext - so the stored value is a function of the plaintext alone.
PSK = "-AQ==CfUKZ5XQZQdRsWtG0WvD0XjcZ3s=XFRhADrjYb33/fnZc9j2j/785yQ0qi49TKr0ndnWgjI="


def members(*values):
    """A `<member>` list as xmltodict delivers it: a bare string for one, a list for several."""
    return {"member": list(values) if len(values) > 1 else values[0]}


#: The fourteen profiles, keyed by the stage 6 subject slug.
PROFILES = {
    "cp-01": {"@name": "oep-ike6-p01", "encryption": members("3des"),
              "hash": members("md5"), "dh-group": members("group1"),
              "lifetime": {"hours": "336"}},
    "cp-02": {"@name": "oep-ike6-p02", "encryption": members("aes-128-cbc"),
              "hash": members("sha1"), "dh-group": members("group2"),
              "lifetime": {"hours": "48"}},
    "cp-03": {"@name": "oep-ike6-p03", "encryption": members("aes-192-cbc"),
              "hash": members("sha256"), "dh-group": members("group5"),
              "lifetime": {"hours": "12"}},
    "cp-04": {"@name": "oep-ike6-p04", "encryption": members("aes-128-gcm"),
              "hash": members("non-auth"), "dh-group": members("group15"),
              "lifetime": {"hours": "8"}},
    "cp-05": {"@name": "oep-ike6-p05", "encryption": members("aes-256-cbc"),
              "hash": members("sha384"), "dh-group": members("group14"),
              "lifetime": {"hours": "8"}},
    "cp-06": {"@name": "oep-ike6-p06", "encryption": members("aes-256-gcm"),
              "hash": members("non-auth"), "dh-group": members("group16"),
              "lifetime": {"hours": "8"}},
    "cp-07": {"@name": "oep-ike6-p07", "encryption": members("aes-256-cbc"),
              "hash": members("sha512"), "dh-group": members("group19"),
              "lifetime": {"hours": "8"}},
    # NO LIFETIME CONTAINER. The object's only optional choice container, absent on a committed
    # entry - so `key_lifetime_known` is false and a threshold over the hours would pass it.
    "cp-08": {"@name": "oep-ike6-p08", "encryption": members("aes-256-cbc"),
              "hash": members("sha384"), "dh-group": members("group20")},
    # Written in SECONDS. 1800 of them coalesce to 1 hour by rounding UP, never to 0.
    "cp-09": {"@name": "oep-ike6-p09", "encryption": members("aes-256-cbc"),
              "hash": members("sha384"), "dh-group": members("group21"),
              "lifetime": {"seconds": "1800"}},
    "cp-10": {"@name": "oep-ike6-p10", "encryption": members("aes-256-cbc"),
              "hash": members("sha384"), "dh-group": members("none"),
              "lifetime": {"hours": "8"}},
    # sha256 AND non-auth with no AEAD cipher anywhere: committed by the device without comment.
    "cp-11": {"@name": "oep-ike6-p11", "encryption": members("aes-256-cbc"),
              "hash": members("sha256", "non-auth"), "dh-group": members("group19"),
              "lifetime": {"hours": "8"}},
    # The sentinel. 0 is accepted and stored although the device's stated range excludes it.
    "cp-12": {"@name": "oep-ike6-p12", "encryption": members("aes-256-cbc"),
              "hash": members("sha384"), "dh-group": members("group19"),
              "lifetime": {"hours": "8"}, "authentication-multiple": "0"},
    "cp-13": {"@name": "oep-ike6-p13", "encryption": members("aes-256-cbc"),
              "hash": members("sha384"), "dh-group": members("group19"),
              "lifetime": {"hours": "8"}, "authentication-multiple": "2"},
    # A post-quantum key-encapsulation name as the only member: no severity band ranks it.
    "cp-14": {"@name": "oep-ike6-p14", "encryption": members("aes-256-cbc"),
              "hash": members("sha384"), "dh-group": members("kyber-768"),
              "lifetime": {"hours": "8"}},
}

#: The nine gateways, keyed by the stage 6 subject slug.
GATEWAYS = {
    "gw-01": {"@name": "oep-ike6-g01", "peer-address": {"ip": "192.0.2.101"},
              "local-address": {"interface": "ethernet1/1"},
              "authentication": {"pre-shared-key": {"key": PSK}},
              "protocol": {"version": "ikev1", "ikev1": {
                  "exchange-mode": "main", "ike-crypto-profile": "oep-ike6-p05",
                  "dpd": {"enable": "yes", "interval": "5", "retry": "5"}}}},
    "gw-02": {"@name": "oep-ike6-g02", "peer-address": {"ip": "192.0.2.102"},
              "local-address": {"interface": "ethernet1/1"},
              "authentication": {"pre-shared-key": {"key": PSK}},
              "protocol": {"version": "ikev2-preferred",
                           "ikev1": {"exchange-mode": "aggressive",
                                     "ike-crypto-profile": "oep-ike6-p05"},
                           "ikev2": {"ike-crypto-profile": "oep-ike6-p12"}}},
    "gw-03": {"@name": "oep-ike6-g03", "peer-address": {"ip": "192.0.2.103"},
              "local-address": {"interface": "ethernet1/1"},
              "authentication": {"pre-shared-key": {"key": PSK}},
              "protocol": {"version": "ikev2", "ikev2": {
                  "ike-crypto-profile": "oep-ike6-p13", "dpd": {"enable": "no"}}}},
    "gw-04": {"@name": "oep-ike6-g04", "peer-address": {"ip": "192.0.2.104"},
              "local-address": {"interface": "ethernet1/1"},
              "authentication": {"pre-shared-key": {"key": PSK}},
              "protocol": {"version": "ikev1", "ikev1": {
                  "exchange-mode": "auto", "ike-crypto-profile": "oep-ike6-p05",
                  "dpd": {"enable": "no"}}}},
    # A version key and NO protocol branch beneath it: neither pointer set.
    "gw-05": {"@name": "oep-ike6-g05", "peer-address": {"ip": "192.0.2.105"},
              "local-address": {"interface": "ethernet1/1"},
              "authentication": {"pre-shared-key": {"key": PSK}},
              "protocol": {"version": "ikev2"}},
    # The vendor's own switch for taking a gateway out of force. `yes` means OFF.
    "gw-06": {"@name": "oep-ike6-g06", "peer-address": {"ip": "192.0.2.106"},
              "local-address": {"interface": "ethernet1/1"},
              "authentication": {"pre-shared-key": {"key": PSK}},
              "protocol": {"version": "ikev1", "ikev1": {
                  "exchange-mode": "aggressive", "ike-crypto-profile": "oep-ike6-p05"}},
              "disabled": "yes"},
    # NO protocol version key at all. The column holds "" and every negated equality matches.
    "gw-07": {"@name": "oep-ike6-g07", "peer-address": {"ip": "192.0.2.107"},
              "local-address": {"interface": "ethernet1/1"},
              "authentication": {"pre-shared-key": {"key": PSK}},
              "protocol": {"ikev1": {"ike-crypto-profile": "oep-ike6-p05"}}},
    # A profile named from BOTH branches, and they differ - which the vendor permits.
    "gw-08": {"@name": "oep-ike6-g08", "peer-address": {"ip": "192.0.2.108"},
              "local-address": {"interface": "ethernet1/1"},
              "authentication": {"pre-shared-key": {"key": PSK}},
              "protocol": {"version": "ikev2",
                           "ikev1": {"exchange-mode": "main",
                                     "ike-crypto-profile": "oep-ike6-p05"},
                           "ikev2": {"ike-crypto-profile": "oep-ike6-p13",
                                     "dpd": {"enable": "yes", "interval": "30"}}}},
    "gw-09": {"@name": "oep-ike6-g09", "peer-address": {"ip": "192.0.2.109"},
              "local-address": {"interface": "ethernet1/1"},
              "peer-id": {"type": "ipaddr", "id": "192.0.2.109"},
              "authentication": {"certificate": {
                  "local-certificate": {"name": "pan-fw-111"},
                  "certificate-profile": "quick-cert-profile",
                  "allow-id-payload-mismatch": "yes"}},
              "protocol": {"version": "ikev1", "ikev1": {
                  "exchange-mode": "main", "ike-crypto-profile": "oep-ike6-p05"}}},
}


def merged_payload(profiles, gateways):
    """A `show config merged` payload holding the two IKE collections.

    `gateways=None` leaves the gateway container ABSENT, which is not the same as empty: an
    absent container is an appliance that terminates no site-to-site key exchange, an empty one
    is an appliance that has had its gateways removed. Both shapes occur in the lab.
    """
    ike = {"crypto-profiles": {"ike-crypto-profiles": {"entry": list(profiles)}}}
    if gateways is not None:
        ike["gateway"] = {"entry": list(gateways)}
    return {"config": {"devices": {"entry": [
        {"@name": "localhost.localdomain", "network": {"ike": ike}}]}}}


class IkeControlTestCase(TestCase):
    """One appliance carrying the configuration stage 6 built, and the nine controls over it."""

    hostname = "pan-fw-111"
    serial = "6A9C0A9904E7D6E"

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.ike")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-ike",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=self.serial, hostname=self.hostname)
        self.run = AssessmentRun.objects.create(
            name="IKE", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        seed_controls(PROFILE_CONTROLS, control_type=Control.ControlType.IKE_CRYPTO_PROFILE)
        seed_controls(GATEWAY_CONTROLS, control_type=Control.ControlType.IKE_GATEWAY)

    def normalize(self, profiles=(), gateways=()):
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload=merged_payload(profiles, gateways))
        normalize_ike_crypto_profiles(self.appliance)
        normalize_ike_gateways(self.appliance)

    def whole_lab(self):
        self.normalize(PROFILES.values(), GATEWAYS.values())
        generate_ike_crypto_profile_findings(self.run)
        generate_ike_gateway_findings(self.run)

    def profile_findings(self):
        """{(control_id, entry_name): finding} over the crypto profiles."""
        return {(f.control.control_id, f.subject_name): f
                for f in IkeCryptoProfileFinding.objects.select_related("control")}

    def gateway_findings(self):
        return {(f.control.control_id, f.subject_name): f
                for f in IkeGatewayFinding.objects.select_related("control")}

    def verdicts(self, control_id):
        """{entry_name: (severity, [matched query names])} for one control over the whole lab."""
        model = (IkeCryptoProfileFinding if control_id in PROFILE_CONTROLS
                 else IkeGatewayFinding)
        return {f.subject_name: (f.severity, sorted(f.matched_query_names))
                for f in model.objects.filter(control__control_id=control_id)}


class IkeGatewayVersionTests(IkeControlTestCase):
    """PAN-IKE-001. Every gateway not pinned to IKE version 2, including one nobody read."""

    def test_the_version_control_over_the_whole_lab(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-IKE-001"), {
            # ikev1 only - stage 6's top band.
            "oep-ike6-g01": ("high", ["Baseline"]),
            # ikev2-preferred: the one calibrated band, because the gateway does negotiate
            # version 2 with a peer that supports it.
            "oep-ike6-g02": ("medium", ["Baseline", "IKEv2 preferred with IKEv1 fallback"]),
            "oep-ike6-g04": ("high", ["Baseline"]),
            # NO VERSION KEY AT ALL. The negated equality matches the empty string, so the row
            # is REPORTED rather than passed - which is the whole reason the clause is written
            # this way round and the column is non-nullable text.
            "oep-ike6-g07": ("high", ["Baseline"]),
            "oep-ike6-g09": ("high", ["Baseline"]),
        })

    def test_a_gateway_pinned_to_version_two_produces_nothing(self):
        self.whole_lab()
        self.assertNotIn("oep-ike6-g03", self.verdicts("PAN-IKE-001"))
        self.assertNotIn("oep-ike6-g05", self.verdicts("PAN-IKE-001"))
        self.assertNotIn("oep-ike6-g08", self.verdicts("PAN-IKE-001"))

    def test_the_absent_version_key_is_not_reported_as_a_version(self):
        """The finding must not name a version it did not read. What the device does with the
        key absent is unmeasured and the two available readings disagree."""
        self.whole_lab()
        summary = self.gateway_findings()[("PAN-IKE-001", "oep-ike6-g07")].summary
        self.assertIn("no protocol version key is configured", summary)
        self.assertIn("unmeasured", summary)
        self.assertNotIn("version 1 only", summary)


class DisabledGatewayTests(IkeControlTestCase):
    """`gateway_is_active` is applicability on EVERY gateway control, and this holds it there.

    oep-ike6-g06 carries the vendor's `disabled` key set to yes AND is the worst gateway in the
    lab on three separate controls - version 1, aggressive mode, a factory profile pointer. It
    produces nothing, and that is a SUPPRESSION rather than a pass: nothing looked at it.
    """

    def test_a_disabled_gateway_produces_no_finding_on_any_control(self):
        self.whole_lab()
        for control_id in GATEWAY_CONTROLS:
            with self.subTest(control_id):
                self.assertNotIn("oep-ike6-g06", self.verdicts(control_id))

    def test_the_same_gateway_enabled_fires_three_controls(self):
        """The proof that the exclusion above is the switch and not the configuration."""
        enabled = {k: dict(v) for k, v in GATEWAYS.items()}
        enabled["gw-06"].pop("disabled")
        self.normalize(PROFILES.values(), enabled.values())
        generate_ike_gateway_findings(self.run)
        fired = {cid for cid, name in self.gateway_findings() if name == "oep-ike6-g06"}
        self.assertEqual(fired, {"PAN-IKE-001", "PAN-IKE-006", "PAN-IKE-007", "PAN-IKE-008"})


class IkeCryptoProfileAlgorithmTests(IkeControlTestCase):
    """PAN-IKE-002, 003 and 004: three floors over three offer sets."""

    def test_the_dh_group_floor(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-IKE-002"), {
            "oep-ike6-p01": ("high", ["Baseline"]),
            "oep-ike6-p02": ("high", ["Baseline"]),
            "oep-ike6-p03": ("medium",
                             ["Baseline", "Weakest group is the 1536-bit finite field"]),
            # `none` is not a weak group: it can take the key agreement out of the proposal.
            "oep-ike6-p10": ("high", ["Baseline"]),
            # A post-quantum name is the only member. The floor column counts it as not meeting
            # the floor, and NO calibration query reaches it - so the finding carries the
            # control's own severity about a group nobody has ranked.
            "oep-ike6-p14": ("high", ["Baseline"]),
        })

    def test_the_medium_dh_band_above_the_floor_is_unreachable(self):
        """group14, group15 and group16 are ranked `medium` by stage 3 and MEET stage 5's floor,
        so the assertion clause excludes them and no query can produce that band. Measured, not
        assumed: three profiles in the lab sit there and none of them reports."""
        self.whole_lab()
        for entry in ("oep-ike6-p05", "oep-ike6-p04", "oep-ike6-p06"):
            with self.subTest(entry):
                self.assertNotIn(entry, self.verdicts("PAN-IKE-002"))

    def test_the_encryption_floor(self):
        """Only 3DES fails. The three `medium` cipher ranks are above the floor and unreachable
        for the same reason as the DH bands - aes-128-cbc is a lab profile and does not fire."""
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-IKE-003"),
                         {"oep-ike6-p01": ("high", ["Baseline"])})

    def test_the_hash_floor_and_the_aead_exception(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-IKE-004"), {
            "oep-ike6-p01": ("high", ["Baseline"]),
            "oep-ike6-p02": ("medium", ["Baseline", "Weakest integrity algorithm is SHA-1"]),
            # sha256 AND non-auth with NO AEAD cipher: the member is no integrity algorithm at
            # all here, and it ranks with md5 rather than below sha1.
            "oep-ike6-p11": ("high", ["Baseline"]),
        })

    def test_an_aead_profile_with_non_auth_is_the_configuration_the_vendor_mandates(self):
        """p04 and p06 offer an AEAD cipher and `non-auth` and NOTHING ELSE. A one-list test
        would fire on exactly the configuration the vendor tells a customer to make."""
        self.whole_lab()
        for entry in ("oep-ike6-p04", "oep-ike6-p06"):
            with self.subTest(entry):
                self.assertNotIn(entry, self.verdicts("PAN-IKE-004"))

    def test_the_non_auth_finding_says_which_meaning_it_has(self):
        self.whole_lab()
        summary = self.profile_findings()[("PAN-IKE-004", "oep-ike6-p11")].summary
        self.assertIn("no integrity algorithm at all", summary)
        self.assertIn("the device accepted this pairing without complaint", summary)


class IkeCryptoProfileLifetimeTests(IkeControlTestCase):
    """PAN-IKE-005: two quantities, four unit branches and one sentinel."""

    def test_the_lifetime_and_reauthentication_control(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-IKE-005"), {
            # 336 hours. Past the 168-hour band, so no calibration matches and the baseline
            # tier stands - which is what the BOUNDED middle band exists to protect: written as
            # a bare `greater than 24`, the `low` query would have matched this row too and the
            # worst matched calibration would have reported two weeks on one key BELOW 48 hours.
            "oep-ike6-p01": ("medium", ["Baseline"]),
            "oep-ike6-p02": ("low", ["Baseline", "Key lifetime between one day and one week"]),
            # NO LIFETIME READ. This row is here because of the second query and not the
            # baseline: a threshold over the null would have passed it in silence.
            "oep-ike6-p08": ("medium", ["Key lifetime not established"]),
            # The re-authentication half. p05 has no multiplier at all; p12 has the sentinel 0.
            "oep-ike6-p05": ("medium", ["IKEv2 re-authentication interval not bounded"]),
            "oep-ike6-p12": ("medium", ["IKEv2 re-authentication interval not bounded"]),
        })

    def test_a_sub_hour_lifetime_is_the_preferred_state_and_not_the_worst(self):
        """p09's lifetime is 1800 SECONDS. A comparison on the raw number without the unit would
        report it as the longest lifetime in the estate; coalesced and rounded UP it is 1 hour."""
        self.whole_lab()
        self.assertNotIn("oep-ike6-p09", self.verdicts("PAN-IKE-005"))
        self.assertEqual(
            IkeCryptoProfile.objects.get(entry_name="oep-ike6-p09").key_lifetime_hours, 1)

    def test_a_lifetime_between_the_baseline_and_the_target_produces_nothing(self):
        """p03 is 12 hours: past the 8-hour preferred state, inside the 24-hour bound. Stage 3
        ranks that band `low` and stage 5's assertion clause fires only above 24 hours, so the
        band is unreachable - the fourth floor-versus-target gap in this domain."""
        self.whole_lab()
        self.assertNotIn("oep-ike6-p03", self.verdicts("PAN-IKE-005"))

    def test_the_unread_lifetime_finding_does_not_say_the_lifetime_is_long(self):
        self.whole_lab()
        summary = self.profile_findings()[("PAN-IKE-005", "oep-ike6-p08")].summary
        self.assertIn("the key lifetime was not established", summary)
        self.assertIn("not a report that the lifetime is too long", summary)

    def test_the_zero_multiplier_is_reported_as_an_absence_of_a_bound(self):
        self.whole_lab()
        summary = self.profile_findings()[("PAN-IKE-005", "oep-ike6-p12")].summary
        self.assertIn("the authentication multiple is 0", summary)
        self.assertIn("disables re-authentication entirely", summary)

    def test_a_bounded_product_passes(self):
        """p13: multiplier 2 against an 8-hour lifetime is 16 hours, inside the bound."""
        self.whole_lab()
        self.assertNotIn("oep-ike6-p13", self.verdicts("PAN-IKE-005"))
        self.assertEqual(
            IkeCryptoProfile.objects.get(entry_name="oep-ike6-p13").reauth_interval_hours, 16)

    def test_a_profile_no_version_two_gateway_uses_is_out_of_the_reauth_population(self):
        """p01 has no multiplier either, and `used_by_ikev2_gateway` excludes it - so its only
        finding comes from the lifetime half. The exclusion is not a pass."""
        self.whole_lab()
        severity, queries = self.verdicts("PAN-IKE-005")["oep-ike6-p01"]
        self.assertNotIn("IKEv2 re-authentication interval not bounded", queries)


class IkeGatewayAuthenticationTests(IkeControlTestCase):
    """PAN-IKE-006: three states over two exclusive subtrees."""

    def test_the_authentication_control(self):
        self.whole_lab()
        verdicts = self.verdicts("PAN-IKE-006")
        # Every pre-shared-key gateway in force, at one severity: the grading's two firing
        # placements both sit at the control's own tier, so no calibration query exists.
        self.assertEqual(set(verdicts), {"oep-ike6-g01", "oep-ike6-g02", "oep-ike6-g03",
                                         "oep-ike6-g04", "oep-ike6-g05", "oep-ike6-g07",
                                         "oep-ike6-g08"})
        for name, (severity, queries) in verdicts.items():
            with self.subTest(name):
                self.assertEqual((severity, queries), ("medium", ["Baseline"]))

    def test_a_certificate_gateway_naming_a_validation_profile_passes(self):
        self.whole_lab()
        self.assertNotIn("oep-ike6-g09", self.verdicts("PAN-IKE-006"))

    def test_a_certificate_gateway_with_no_validation_profile_fires_at_the_same_tier(self):
        """Stage 3 added this state and ranked it WITH the shared-secret state rather than below
        it: the secret is gone and nothing constrains validation of what replaced it."""
        without = {k: dict(v) for k, v in GATEWAYS.items()}
        without["gw-09"]["authentication"] = {
            "certificate": {"local-certificate": {"name": "pan-fw-111"}}}
        self.normalize(PROFILES.values(), without.values())
        generate_ike_gateway_findings(self.run)
        self.assertEqual(self.verdicts("PAN-IKE-006")["oep-ike6-g09"], ("medium", ["Baseline"]))
        summary = self.gateway_findings()[("PAN-IKE-006", "oep-ike6-g09")].summary
        self.assertIn("no certificate profile named", summary)

    def test_the_finding_says_the_answer_is_the_staged_one(self):
        """The two branches are exclusive and the exclusion is enforced by SILENT REPLACEMENT at
        the write, so for the duration of a staging the candidate and running views disagree."""
        self.whole_lab()
        summary = self.gateway_findings()[("PAN-IKE-006", "oep-ike6-g01")].summary
        self.assertIn("staged configuration", summary)

    def test_the_finding_makes_no_claim_about_the_secret(self):
        """A 31-character plaintext reads back as 77 characters of ciphertext, so a length
        comparison would measure the encoding and pass a four-character key."""
        self.whole_lab()
        summary = self.gateway_findings()[("PAN-IKE-006", "oep-ike6-g01")].summary
        self.assertIn("no claim about its length", summary)


class IkeGatewayExchangeModeTests(IkeControlTestCase):
    """PAN-IKE-007, and the `auto` default that a two-state comparison passes."""

    def test_the_exchange_mode_control(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-IKE-007"), {
            "oep-ike6-g02": ("high", ["Baseline"]),
            # `auto` IS the schema default and it ranks WITH aggressive, not between it and
            # main: the device accepts both modes, so it completes the exposing exchange
            # whenever the peer initiates one.
            "oep-ike6-g04": ("high", ["Baseline"]),
            # No mode key at all, on a gateway with no version key either.
            "oep-ike6-g07": ("high", ["Baseline"]),
        })

    def test_main_mode_passes_and_a_version_two_gateway_is_out_of_scope(self):
        self.whole_lab()
        verdicts = self.verdicts("PAN-IKE-007")
        # Main mode on a version 1 gateway: compliant.
        self.assertNotIn("oep-ike6-g01", verdicts)
        self.assertNotIn("oep-ike6-g09", verdicts)
        # Pinned to version 2: the node is not in use. An EXCLUSION, not a pass - g08 holds an
        # ikev1 exchange-mode key of `main` under a version 2 pin and nothing reads it.
        self.assertNotIn("oep-ike6-g03", verdicts)
        self.assertNotIn("oep-ike6-g05", verdicts)
        self.assertNotIn("oep-ike6-g08", verdicts)

    def test_the_auto_finding_explains_why_auto_is_not_a_middle_setting(self):
        self.whole_lab()
        summary = self.gateway_findings()[("PAN-IKE-007", "oep-ike6-g04")].summary
        self.assertIn("not a middle setting", summary)
        self.assertIn("both main-mode and aggressive-mode", summary)


class IkeGatewayDeadPeerDetectionTests(IkeControlTestCase):
    """PAN-IKE-008: two nodes, two populations, and two switches a null would have passed."""

    def test_the_dead_peer_detection_control(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-IKE-008"), {
            # The version 1 switch read `no`.
            "oep-ike6-g04": ("low", ["Baseline"]),
            # The version 2 switch read `no`.
            "oep-ike6-g03": ("low", ["IKEv2 idle liveness probe switched off"]),
            # THE FOUR ROWS BELOW ARE THE COMPANION QUERIES, and stage 6 expected no finding on
            # the first two: it graded one assertion record at a time and neither record's own
            # clauses reach a row whose switch is null. Stage 5 requires exactly these rows to
            # be reported - `equals false` over a NULL matches nothing, so a gateway nobody read
            # would otherwise pass a test it was never subjected to.
            "oep-ike6-g02": ("low", ["IKEv1 dead-peer-detection switch not established",
                                     "IKEv2 liveness-check switch not established"]),
            "oep-ike6-g07": ("low", ["IKEv1 dead-peer-detection switch not established",
                                     "IKEv2 liveness-check switch not established"]),
            "oep-ike6-g05": ("low", ["IKEv2 liveness-check switch not established"]),
            "oep-ike6-g09": ("low", ["IKEv1 dead-peer-detection switch not established"]),
        })

    def test_a_branch_the_gateway_does_not_use_is_not_reported(self):
        """g01 is version 1 with the switch on, and its version 2 subtree is absent. An absent
        version 2 key on a version 1 gateway asserts NOTHING, so neither the query nor the
        sentence may treat it as a setting."""
        self.whole_lab()
        self.assertNotIn("oep-ike6-g01", self.verdicts("PAN-IKE-008"))
        # The phrase, not the words: "no version 2 exchange is possible" is the version prose
        # and belongs there. What must be absent is any statement about the OTHER branch's
        # dead-peer-detection subtree.
        self.assertNotIn("version 2 liveness", self.gateway_findings()[
            ("PAN-IKE-008", "oep-ike6-g04")].summary)
        self.assertNotIn("version 2 idle liveness", self.gateway_findings()[
            ("PAN-IKE-008", "oep-ike6-g04")].summary)
        self.assertNotIn("version 1 dead-peer", self.gateway_findings()[
            ("PAN-IKE-008", "oep-ike6-g03")].summary)

    def test_a_version_two_gateway_with_the_probe_on_passes(self):
        self.whole_lab()
        self.assertNotIn("oep-ike6-g08", self.verdicts("PAN-IKE-008"))

    def test_the_version_two_finding_does_not_claim_the_peer_goes_undetected(self):
        """Help p.652: "The IKEv2 Liveness Check is always on; all IKEv2 packets serve the
        purpose of a liveness check." So the claim is narrower than the version 1 branch's."""
        self.whole_lab()
        summary = self.gateway_findings()[("PAN-IKE-008", "oep-ike6-g03")].summary
        self.assertIn("IKEv2 packets still serve as a liveness check", summary)
        self.assertNotIn("black-hole", summary)

    def test_a_gateway_set_to_prefer_version_two_is_in_both_populations(self):
        self.whole_lab()
        _severity, queries = self.verdicts("PAN-IKE-008")["oep-ike6-g02"]
        self.assertEqual(len(queries), 2)


class IkeGatewayProposalProvenanceTests(IkeControlTestCase):
    """PAN-IKE-009's gateway half. Its PROFILE half is not implementable as a query here.

    The control's two stage 3 assertion records name DIFFERENT subjects - one the gateway, one
    the crypto profile - and a catalog control has ONE target model, derived from its
    control_type by `Control.save()`, with `ControlQuery.clean` refusing any query whose model
    differs. So the half asserting that no unreferenced proposal is kept cannot live on this
    control at all, and `test_the_profile_half_has_no_query_on_this_control` holds that absence
    visible rather than letting it read as a control that found nothing.
    """

    def test_the_proposal_provenance_control(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-IKE-009"), {
            # NEITHER pointer set. The gateway still consumes a proposal set and nothing stored
            # says which, so it is reported rather than passed.
            "oep-ike6-g05": ("low", ["Baseline"]),
        })

    def test_a_gateway_naming_a_reviewed_profile_passes(self):
        self.whole_lab()
        for entry in ("oep-ike6-g01", "oep-ike6-g08"):
            with self.subTest(entry):
                self.assertNotIn(entry, self.verdicts("PAN-IKE-009"))

    def test_either_pointer_naming_a_factory_profile_fires(self):
        """BOTH pointers, and all THREE factory names - not only `default` under IKEv1."""
        for key, branch, name in (("gw-01", "ikev1", "default"),
                                  ("gw-03", "ikev2", "Suite-B-GCM-128"),
                                  ("gw-08", "ikev2", "Suite-B-GCM-256")):
            with self.subTest(f"{key}/{branch}/{name}"):
                gateways = {k: dict(v) for k, v in GATEWAYS.items()}
                protocol = {k: dict(v) if isinstance(v, dict) else v
                            for k, v in gateways[key]["protocol"].items()}
                protocol[branch] = {**protocol[branch], "ike-crypto-profile": name}
                gateways[key] = {**gateways[key], "protocol": protocol}
                self.normalize(PROFILES.values(), gateways.values())
                generate_ike_gateway_findings(self.run)
                entry = GATEWAYS[key]["@name"]
                self.assertEqual(self.verdicts("PAN-IKE-009")[entry], ("low", ["Baseline"]))
                self.assertIn(name, self.gateway_findings()[("PAN-IKE-009", entry)].summary)

    def test_the_finding_tells_the_two_true_cases_apart(self):
        """The COLUMN cannot distinguish a factory-named pointer from no pointer at all; the ROW
        can, because both pointer names are on it, and the remediations differ."""
        self.whole_lab()
        summary = self.gateway_findings()[("PAN-IKE-009", "oep-ike6-g05")].summary
        self.assertIn("neither crypto-profile pointer is set", summary)
        self.assertNotIn("factory-shipped", summary)

    def test_the_profile_half_has_no_query_on_this_control(self):
        self.whole_lab()
        control = Control.objects.get(control_id="PAN-IKE-009")
        self.assertEqual(control.target_model, "integrations.IkeGateway")
        models = {q.canonical_query.get("model") for q in control.queries.all()}
        self.assertEqual(models, {"integrations.IkeGateway"})
        # Two lab profiles are referenced by no gateway on this appliance and neither is
        # reported anywhere: stage 6 expected both of them to fire.
        for entry in ("oep-ike6-p01", "oep-ike6-p14"):
            with self.subTest(entry):
                self.assertTrue(IkeCryptoProfile.objects.get(
                    entry_name=entry).referenced_by_gateway_on_this_appliance is False)
                self.assertNotIn(entry, self.verdicts("PAN-IKE-009"))


class AbsentIkeCollectionTests(IkeControlTestCase):
    """The commonest state in the lab, and the one that makes five controls silent."""

    def test_an_appliance_with_no_gateway_container_produces_no_gateway_finding(self):
        """Every assertion on the gateway carries `gateway_is_active` or a version clause as
        APPLICABILITY, so an absent object SUPPRESSES all five gateway controls where an
        assertion clause on the same object would have raised them. The suppression is right -
        an appliance that terminates no key exchange has no tunnel to be weak - and it is a
        suppression and not a pass."""
        self.normalize(PROFILES.values(), None)
        generate_ike_crypto_profile_findings(self.run)
        generate_ike_gateway_findings(self.run)
        self.assertEqual(IkeGateway.objects.count(), 0)
        self.assertEqual(IkeGatewayFinding.objects.count(), 0)
        # The profiles still report, and every one of them now reads as unreferenced - which on
        # an appliance with no gateway container is what the absence MEANS and not a failed read.
        self.assertTrue(IkeCryptoProfileFinding.objects.exists())
        self.assertEqual(IkeCryptoProfile.objects.filter(
            referenced_by_gateway_on_this_appliance=True).count(), 0)

    def test_an_appliance_with_no_profiles_produces_no_profile_finding(self):
        self.normalize((), GATEWAYS.values())
        generate_ike_crypto_profile_findings(self.run)
        self.assertEqual(IkeCryptoProfile.objects.count(), 0)
        self.assertEqual(IkeCryptoProfileFinding.objects.count(), 0)


class IkeFindingProseTests(IkeControlTestCase):
    """Sentences no finding in this domain is permitted to contain, over every finding at once.

    Each one is a claim the configuration cannot support, and each was refused on a measurement
    rather than on taste - see the two generators' module docstrings for which.
    """

    FORBIDDEN = (
        # The configured version is not the negotiated one and the read that would say which is
        # refused to this assessment.
        "negotiates IKEv1",
        "is negotiating",
        # The IKEv2 liveness check is always on.
        "cannot detect a dead peer",
        # A length comparison over the stored value measures the ciphertext.
        "weak pre-shared key",
        "short pre-shared key",
        # The factory names are not evidence of weak algorithms; the assertion is provenance.
        "the default profile is weak",
    )

    def test_no_finding_makes_a_claim_the_configuration_cannot_support(self):
        self.whole_lab()
        findings = {**self.profile_findings(), **self.gateway_findings()}
        self.assertTrue(findings)
        for (control_id, name), finding in findings.items():
            for phrase in self.FORBIDDEN:
                with self.subTest(f"{control_id}/{name}/{phrase}"):
                    self.assertNotIn(phrase, finding.summary)

    def test_every_finding_names_its_subject_and_its_appliance(self):
        self.whole_lab()
        for (control_id, name), finding in {**self.profile_findings(),
                                            **self.gateway_findings()}.items():
            with self.subTest(f"{control_id}/{name}"):
                self.assertIn(name, finding.summary)
                self.assertIn("pan-fw-111", finding.summary)
                self.assertEqual(finding.subject_name, name)

    def test_every_finding_carries_the_snapshot_it_was_computed_from(self):
        self.whole_lab()
        for finding in list(IkeCryptoProfileFinding.objects.all()) + \
                list(IkeGatewayFinding.objects.all()):
            with self.subTest(finding.subject_name):
                self.assertIsNotNone(finding.snapshot_id)
