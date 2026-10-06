"""PAN-MCR-001 to 005 over the management SSH server's effective offer.

Every one of these controls asserts the corpus PREFERRED value (2026-09-14), so the device's own
default offer now fires all five: its ciphers, KEX and MACs each carry algorithms outside the
preferred sets, its host key is RSA 2048, and it has no rekey interval.

The cases that earn their place are the ones where "preferred" does NOT mean strictest.
hmac-sha2-256 beside hmac-sha2-512 is compliant, because the corpus keeps 256 "for compatibility";
an ECDSA 384 host key passes, because it is stronger than the preferred 256 rather than weaker; and
aes256-ctr ALONE still fires, because its parenthetical adds it beside aes256-gcm rather than
substituting for it. Those three readings are the whole content of the rule.
"""

from django.test import TestCase
from django.utils import timezone

from assessments.management_ssh_findings import RESTART_CAVEAT, generate_management_ssh_findings
from assessments.models import AssessmentRun, Control, ManagementSshFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_ssh import (
    normalize_management_ssh)

#: Every list at its preferred value. A case testing ONE list overrides that key, so each
#: assertion can be an exact set of findings rather than a membership check.
PREFERRED = {
    "ciphers": {"member": ["aes256-gcm"]},
    "kex": {"member": ["ecdh-sha2-nistp384"]},
    "mac": {"member": ["hmac-sha2-512"]},
    "default-hostkey": {"key-type": {"ECDSA": "256"}},
    "session-rekey": {"interval": "3600"},
}


class ManagementSshControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.mssh")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-mssh", group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-MSSH", hostname="fw-mssh", software_version="11.1.13-h3")
        seed_controls(["PAN-MCR-001", "PAN-MCR-002", "PAN-MCR-003", "PAN-MCR-004", "PAN-MCR-005"],
                      control_type=Control.ControlType.MANAGEMENT_SSH)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _findings(self, profile=None):
        ssh = {}
        if profile is not None:
            ssh = {"mgmt": {"server-profile": "p"}, "profiles": {"mgmt-profiles": {
                "server-profiles": {"entry": [{"@name": "p", **profile}]}}}}
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": [{"@name": "localhost.localdomain",
                                                         "deviceconfig": {"system": {"ssh": ssh}}}]}}})
        normalize_management_ssh(self.appliance)
        generate_management_ssh_findings(self.run)
        return {f.control.control_id: f for f in ManagementSshFinding.objects.select_related("control")}

    def _preferred(self, **overrides):
        """The all-preferred profile with some lists replaced. A None value leaves the key in
        place holding nothing, which is what an explicitly empty `<kex/>` looks like."""
        return {**PREFERRED, **overrides}

    def test_the_device_default_fires_all_five(self):
        """No profile bound. Under the preferred-value rule the built-in offer fails every list -
        chacha20 and the 128-bit ciphers, the finite-field KEX groups, hmac-sha1 and umac."""
        found = self._findings()
        self.assertEqual(set(found), {"PAN-MCR-001", "PAN-MCR-002", "PAN-MCR-003",
                                      "PAN-MCR-004", "PAN-MCR-005"})
        self.assertEqual(found["PAN-MCR-001"].severity, "high")
        self.assertEqual(found["PAN-MCR-002"].severity, "high")
        self.assertEqual(found["PAN-MCR-003"].severity, "medium")
        self.assertEqual(found["PAN-MCR-004"].severity, "medium")
        self.assertEqual(found["PAN-MCR-005"].severity, "low")
        self.assertIn("chacha20-poly1305@openssh.com", found["PAN-MCR-001"].summary)
        self.assertIn("hmac-sha1", found["PAN-MCR-003"].summary)
        self.assertIn("the device default", found["PAN-MCR-003"].summary)
        # The TRAP, said once per finding rather than per list. Jason, 2026-10-06: the point is
        # "the fact that no explicit values are set, and the default values are known to be weak
        # on even modern versions of software" - so the sentence has to rule out upgrading as the
        # fix, which a reader shown only "offers hmac-sha1" would reasonably reach for.
        for control_id in ("PAN-MCR-001", "PAN-MCR-002", "PAN-MCR-003"):
            with self.subTest(control_id):
                summary = found[control_id].summary
                self.assertIn("weak on current PAN-OS", summary)
                self.assertIn("not by upgrading", summary)
        # No key type is configured, so the finding says that rather than naming RSA 2048 - a
        # value normalization inferred and 2026-09-14 measured unreliable on a device ever set
        # to `all`.
        self.assertIn("no host key type configured", found["PAN-MCR-004"].summary)
        self.assertNotIn("RSA 2048", found["PAN-MCR-004"].summary)

    def test_a_ciphers_only_profile_leaves_every_other_list_at_the_default(self):
        """tpa-a's shape: the unset MAC list is the default, not empty. Only 001 is answered."""
        found = self._findings({"ciphers": {"member": ["aes256-gcm"]}})
        self.assertEqual(set(found), {"PAN-MCR-002", "PAN-MCR-003",
                                      "PAN-MCR-004", "PAN-MCR-005"})
        self.assertIn(RESTART_CAVEAT, found["PAN-MCR-003"].summary)

    def test_a_cbc_cipher_fires_001_and_is_named_as_cbc(self):
        found = self._findings(self._preferred(ciphers={"member": ["aes128-cbc", "aes256-gcm"]}))
        self.assertEqual(set(found), {"PAN-MCR-001"})
        self.assertEqual(found["PAN-MCR-001"].severity, "high")
        self.assertIn("aes128-cbc", found["PAN-MCR-001"].summary)
        self.assertIn("CBC mode among them", found["PAN-MCR-001"].summary)

    def test_aes256_ctr_is_allowed_beside_the_preferred_cipher(self):
        """The corpus parenthetical "(add aes256-ctr for older clients)" is an allowance."""
        self.assertEqual(
            self._findings(self._preferred(ciphers={"member": ["aes256-gcm", "aes256-ctr"]})), {})

    def test_aes256_ctr_alone_fires_because_the_preferred_cipher_is_missing(self):
        """An allowance beside the preferred value is not a substitute for it."""
        found = self._findings(self._preferred(ciphers={"member": ["aes256-ctr"]}))
        self.assertEqual(set(found), {"PAN-MCR-001"})
        self.assertIn("no aes256-gcm cipher", found["PAN-MCR-001"].summary)

    def test_a_profile_selecting_hmac_sha1_fires_003(self):
        found = self._findings(self._preferred(mac={"member": ["hmac-sha1", "hmac-sha2-512"]}))
        self.assertEqual(set(found), {"PAN-MCR-003"})
        self.assertEqual(found["PAN-MCR-003"].severity, "medium")
        self.assertIn("hmac-sha1", found["PAN-MCR-003"].summary)

    def test_hmac_sha2_256_beside_512_is_the_preferred_state(self):
        """tpa-b's shape. The corpus keeps 256 "for compatibility", so this does NOT report - the
        low band that used to grade it as a preferred-state gap is gone rather than promoted."""
        self.assertEqual(
            self._findings(self._preferred(mac={"member": ["hmac-sha2-256", "hmac-sha2-512"]})), {})

    def test_sha2_256_without_512_fires_at_the_control_severity(self):
        """What the preferred value actually changed for 003, and there is no graded band."""
        found = self._findings(self._preferred(mac={"member": ["hmac-sha2-256"]}))
        self.assertEqual(set(found), {"PAN-MCR-003"})
        self.assertEqual(found["PAN-MCR-003"].severity, "medium")
        self.assertIn("no hmac-sha2-512 MAC", found["PAN-MCR-003"].summary)

    def test_a_fully_preferred_profile_fires_nothing(self):
        self.assertEqual(self._findings(dict(PREFERRED)), {})

    def test_rsa_3072_now_fires_004(self):
        """It passed under this control's earlier 128-bit-floor reading. The preferred value is
        ECDSA, so any RSA key reports and the consultant relaxes it where an estate needs RSA."""
        found = self._findings(self._preferred(**{"default-hostkey": {"key-type": {"RSA": "3072"}}}))
        self.assertEqual(set(found), {"PAN-MCR-004"})
        self.assertIn("RSA 3072 host key", found["PAN-MCR-004"].summary)

    def test_ecdsa_384_passes_because_it_is_stronger_than_preferred(self):
        """Replacing the minimum with the preferred must not make being better than the preferred
        value a finding."""
        self.assertEqual(
            self._findings(self._preferred(**{"default-hostkey": {"key-type": {"ECDSA": "384"}}})), {})

    def test_hostkey_all_fires_004(self):
        """Measured 2026-09-14: `all` takes no size and serves an RSA key alongside every ECDSA
        curve, so the RSA 2048 key this control is about is still presented."""
        found = self._findings(self._preferred(**{"default-hostkey": {"key-type": {"all": None}}}))
        self.assertEqual(set(found), {"PAN-MCR-004"})
        self.assertIn("host key type All", found["PAN-MCR-004"].summary)

    def test_no_rekey_interval_fires_only_005(self):
        found = self._findings(self._preferred(**{"session-rekey": None}))
        self.assertEqual(set(found), {"PAN-MCR-005"})
        self.assertIn("no time-based rekey interval", found["PAN-MCR-005"].summary)

    def test_a_shorter_rekey_interval_passes(self):
        """The preferred 3600 is a ceiling - the range is 10 to 3600 and rekeying more often is
        stronger - so every settable value satisfies the control."""
        self.assertEqual(self._findings(self._preferred(**{"session-rekey": {"interval": "600"}})), {})

    def test_an_explicitly_empty_kex_list_is_unrestricted(self):
        """Measured on tpa-a: `<kex/>` commits and offers the whole default set."""
        found = self._findings(self._preferred(kex=None))
        self.assertEqual(set(found), {"PAN-MCR-002"})
        self.assertIn("key exchange unrestricted", found["PAN-MCR-002"].summary)

    def test_a_restricted_list_keeping_group14_sha1_fires_at_the_control_severity(self):
        """It reported at low as a preferred-state gap until 2026-09-14; the band is gone."""
        found = self._findings(self._preferred(
            kex={"member": ["ecdh-sha2-nistp256", "diffie-hellman-group14-sha1"]}))
        self.assertEqual(set(found), {"PAN-MCR-002"})
        self.assertEqual(found["PAN-MCR-002"].severity, "high")
        self.assertIn("diffie-hellman-group14-sha1", found["PAN-MCR-002"].summary)
