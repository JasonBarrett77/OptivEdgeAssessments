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
        seed_controls(["PAN-MCR-001", "PAN-MCR-003"], control_type=Control.ControlType.MANAGEMENT_SSH)
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

    def test_the_device_default_fires_003_and_not_001(self):
        found = self._findings()
        self.assertEqual(set(found), {"PAN-MCR-003"})
        self.assertEqual(found["PAN-MCR-003"].severity, "medium")
        self.assertIn("hmac-sha1", found["PAN-MCR-003"].summary)
        self.assertIn("the device default", found["PAN-MCR-003"].summary)

    def test_a_ciphers_only_profile_still_fires_003_on_the_default_macs(self):
        """tpa-a's shape: the unset MAC list is the default, not empty."""
        found = self._findings({"ciphers": {"member": ["aes256-gcm"]}})
        self.assertEqual(set(found), {"PAN-MCR-003"})
        self.assertIn(RESTART_CAVEAT, found["PAN-MCR-003"].summary)

    def test_a_cbc_cipher_fires_001(self):
        found = self._findings({"ciphers": {"member": ["aes128-cbc", "aes256-gcm"]},
                                "mac": {"member": ["hmac-sha2-512"]}})
        self.assertEqual(set(found), {"PAN-MCR-001"})
        self.assertEqual(found["PAN-MCR-001"].severity, "high")
        self.assertIn("aes128-cbc", found["PAN-MCR-001"].summary)

    def test_a_profile_selecting_hmac_sha1_fires_003(self):
        found = self._findings({"mac": {"member": ["hmac-sha1", "hmac-sha2-512"]}})
        self.assertIn("PAN-MCR-003", found)

    def test_a_strict_profile_fires_neither(self):
        """tpa-b's shape."""
        self.assertEqual(self._findings({"ciphers": {"member": ["aes256-gcm"]},
                                         "mac": {"member": ["hmac-sha2-256", "hmac-sha2-512"]}}), {})
