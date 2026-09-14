"""PAN-MCR-001 and 003 over the management SSH server's effective offer.

001 can only fire on a profile that adds a CBC cipher - the measured default offers none. 003 fires
on the default itself, which offers hmac-sha1 and umac, and on a profile that selects hmac-sha1.
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

    def test_the_device_default_fires_everything_but_001(self):
        """RSA 2048 and no rekey interval are the defaults, so 004 and 005 report too."""
        found = self._findings()
        self.assertEqual(set(found), {"PAN-MCR-002", "PAN-MCR-003", "PAN-MCR-004", "PAN-MCR-005"})
        self.assertEqual(found["PAN-MCR-002"].severity, "high")
        self.assertEqual(found["PAN-MCR-004"].severity, "medium")
        self.assertEqual(found["PAN-MCR-005"].severity, "low")
        self.assertIn("RSA 2048 host key", found["PAN-MCR-004"].summary)
        self.assertEqual(found["PAN-MCR-003"].severity, "medium")
        self.assertIn("hmac-sha1", found["PAN-MCR-003"].summary)
        self.assertIn("the device default", found["PAN-MCR-003"].summary)

    def test_a_ciphers_only_profile_still_fires_003_on_the_default_macs(self):
        """tpa-a's shape: the unset MAC list is the default, not empty."""
        found = self._findings({"ciphers": {"member": ["aes256-gcm"]}})
        self.assertEqual(set(found), {"PAN-MCR-002", "PAN-MCR-003",
                                      "PAN-MCR-004", "PAN-MCR-005"})
        self.assertIn(RESTART_CAVEAT, found["PAN-MCR-003"].summary)

    def test_a_cbc_cipher_fires_001(self):
        found = self._findings({"ciphers": {"member": ["aes128-cbc", "aes256-gcm"]},
                                "kex": {"member": ["ecdh-sha2-nistp384"]},
                                "default-hostkey": {"key-type": {"ECDSA": "256"}},
                                "session-rekey": {"interval": "3600"},
                                "mac": {"member": ["hmac-sha2-512"]}})
        self.assertEqual(set(found), {"PAN-MCR-001"})
        self.assertEqual(found["PAN-MCR-001"].severity, "high")
        self.assertIn("aes128-cbc", found["PAN-MCR-001"].summary)

    def test_a_profile_selecting_hmac_sha1_fires_003(self):
        found = self._findings({"mac": {"member": ["hmac-sha1", "hmac-sha2-512"]}})
        self.assertIn("PAN-MCR-003", found)

    def test_sha2_256_as_the_weakest_mac_reports_low(self):
        """tpa-b's shape: the corpus band for a server that meets the floor and misses the
        preferred hmac-sha2-512."""
        found = self._findings({"ciphers": {"member": ["aes256-gcm"]},
                                "kex": {"member": ["ecdh-sha2-nistp256"]},
                                "default-hostkey": {"key-type": {"ECDSA": "256"}},
                                "session-rekey": {"interval": "3600"},
                                "mac": {"member": ["hmac-sha2-256", "hmac-sha2-512"]}})
        self.assertEqual(set(found), {"PAN-MCR-003"})
        self.assertEqual(found["PAN-MCR-003"].severity, "low")
        self.assertIn("hmac-sha2-256", found["PAN-MCR-003"].summary)

    def test_the_low_band_does_not_downgrade_a_weak_mac(self):
        """Worst wins: hmac-sha1 alongside hmac-sha2-256 stays medium."""
        found = self._findings({"kex": {"member": ["ecdh-sha2-nistp256"]},
                                "mac": {"member": ["hmac-sha1", "hmac-sha2-256"]}})
        self.assertEqual(found["PAN-MCR-003"].severity, "medium")

    def test_a_fully_restricted_profile_fires_nothing(self):
        self.assertEqual(self._findings({"ciphers": {"member": ["aes256-gcm"]},
                                         "kex": {"member": ["ecdh-sha2-nistp384"]},
                                         "default-hostkey": {"key-type": {"ECDSA": "256"}},
                                         "session-rekey": {"interval": "3600"},
                                         "mac": {"member": ["hmac-sha2-512"]}}), {})

    def test_rsa_3072_passes_004(self):
        found = self._findings({"kex": {"member": ["ecdh-sha2-nistp384"]},
                                "default-hostkey": {"key-type": {"RSA": "3072"}},
                                "session-rekey": {"interval": "600"},
                                "mac": {"member": ["hmac-sha2-512"]}})
        self.assertEqual(found, {})

    def test_an_ecdsa_key_without_a_rekey_interval_fires_only_005(self):
        found = self._findings({"kex": {"member": ["ecdh-sha2-nistp384"]},
                                "default-hostkey": {"key-type": {"ECDSA": "256"}},
                                "mac": {"member": ["hmac-sha2-512"]}})
        self.assertEqual(set(found), {"PAN-MCR-005"})
        self.assertIn("no time-based rekey interval", found["PAN-MCR-005"].summary)

    def test_an_explicitly_empty_kex_list_is_unrestricted(self):
        """Measured on tpa-a: `<kex/>` commits and offers the whole default set."""
        found = self._findings({"kex": None, "default-hostkey": {"key-type": {"ECDSA": "256"}},
                                "session-rekey": {"interval": "3600"},
                                "mac": {"member": ["hmac-sha2-512"]}})
        self.assertEqual(set(found), {"PAN-MCR-002"})

    def test_a_restricted_list_keeping_group14_sha1_reports_low(self):
        found = self._findings({"kex": {"member": ["ecdh-sha2-nistp256", "diffie-hellman-group14-sha1"]},
                                "default-hostkey": {"key-type": {"ECDSA": "256"}},
                                "session-rekey": {"interval": "3600"},
                                "mac": {"member": ["hmac-sha2-512"]}})
        self.assertEqual(set(found), {"PAN-MCR-002"})
        self.assertEqual(found["PAN-MCR-002"].severity, "low")
