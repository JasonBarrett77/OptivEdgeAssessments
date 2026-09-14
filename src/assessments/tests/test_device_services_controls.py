"""PAN-SVC-001, 002, 004, 005, 007 and 009 over deviceconfig/system.

Three models from one walk, so the fixtures build one `system` node and assert against all three.

The cases that earn their place are the measured ones, where the obvious reading is wrong:
an ABSENT `type` node is static rather than unknown, so a device with nothing written passes
PAN-SVC-007; an `access-setting` with no `version` child is v2c by the vendor's stated default,
so PAN-SVC-004 fires on it; and a device with no SNMP configuration at all is COMPLIANT rather
than unassessed, which is the one thing that would make these two controls noise on every estate.
"""

from django.test import TestCase
from django.utils import timezone

from assessments.models import (
    AssessmentRun, Control, NtpSettingsFinding, SnmpSettingsFinding, SystemIdentityFinding)
from assessments.ntp_settings_findings import generate_ntp_settings_findings
from assessments.snmp_settings_findings import generate_snmp_settings_findings
from assessments.system_identity_findings import generate_system_identity_findings
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_services import (
    normalize_device_services)

#: A device that passes all six, so a case testing one control overrides one key.
COMPLIANT = {
    "hostname": "fw-named",
    "timezone": "UTC",
    "type": {"static": None},
    "ntp-servers": {
        "primary-ntp-server": {
            "ntp-server-address": "ntp1.example.net",
            "authentication-type": {"symmetric-key": {"algorithm": "sha1", "key-id": "1"}}},
        "secondary-ntp-server": {
            "ntp-server-address": "ntp2.example.net",
            "authentication-type": {"symmetric-key": {"algorithm": "sha1", "key-id": "2"}}},
    },
}


class DeviceServicesControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.svc")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-svc",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-SVC", hostname="fw-svc", model="PA-5220",
            software_version="11.1.13-h3")
        seed_controls(["PAN-SVC-001", "PAN-SVC-002"], control_type=Control.ControlType.NTP_SETTINGS)
        seed_controls(["PAN-SVC-004", "PAN-SVC-005"],
                      control_type=Control.ControlType.SNMP_SETTINGS)
        seed_controls(["PAN-SVC-007", "PAN-SVC-009"],
                      control_type=Control.ControlType.SYSTEM_IDENTITY)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _findings(self, system):
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": [{"@name": "localhost.localdomain",
                                                       "deviceconfig": {"system": system}}]}}})
        normalize_device_services(self.appliance)
        generate_ntp_settings_findings(self.run)
        generate_snmp_settings_findings(self.run)
        generate_system_identity_findings(self.run)
        found = {}
        for model in (NtpSettingsFinding, SnmpSettingsFinding, SystemIdentityFinding):
            for finding in model.objects.select_related("control"):
                found[finding.control.control_id] = finding
        return found

    def _compliant(self, **overrides):
        return {**COMPLIANT, **overrides}

    def test_a_compliant_device_fires_nothing(self):
        self.assertEqual(self._findings(dict(COMPLIANT)), {})

    def test_an_empty_system_node_fires_ntp_and_the_hostname_half(self):
        """Nothing configured: no NTP at all, and no hostname - which PAN-OS renders as the
        model. The management address is NOT a finding, because absent `type` is static."""
        found = self._findings({})
        self.assertEqual(set(found), {"PAN-SVC-001", "PAN-SVC-002", "PAN-SVC-009"})
        self.assertEqual(found["PAN-SVC-001"].severity, "high")
        self.assertEqual(found["PAN-SVC-002"].severity, "medium")
        self.assertEqual(found["PAN-SVC-009"].severity, "low")
        self.assertIn("no NTP server", found["PAN-SVC-001"].summary)

    def test_one_ntp_server_fires_001_only(self):
        found = self._findings(self._compliant(**{"ntp-servers": {
            "primary-ntp-server": {
                "ntp-server-address": "ntp1.example.net",
                "authentication-type": {"symmetric-key": {"algorithm": "sha1"}}}}}))
        self.assertEqual(set(found), {"PAN-SVC-001"})
        self.assertIn("one NTP server", found["PAN-SVC-001"].summary)

    def test_unauthenticated_ntp_fires_002(self):
        found = self._findings(self._compliant(**{"ntp-servers": {
            "primary-ntp-server": {"ntp-server-address": "ntp1.example.net",
                                   "authentication-type": {"none": None}},
            "secondary-ntp-server": {"ntp-server-address": "ntp2.example.net",
                                     "authentication-type": {"none": None}}}}))
        self.assertEqual(set(found), {"PAN-SVC-002"})
        self.assertIn("no authentication", found["PAN-SVC-002"].summary)

    def test_autokey_fires_002_and_is_named_as_autokey(self):
        """Autokey IS authentication and still fails: the corpus preferred value is the
        symmetric-key literal, and the remediation differs from turning authentication on."""
        found = self._findings(self._compliant(**{"ntp-servers": {
            "primary-ntp-server": {"ntp-server-address": "ntp1.example.net",
                                   "authentication-type": {"autokey": None}},
            "secondary-ntp-server": {
                "ntp-server-address": "ntp2.example.net",
                "authentication-type": {"symmetric-key": {"algorithm": "sha1"}}}}}))
        self.assertEqual(set(found), {"PAN-SVC-002"})
        self.assertIn("autokey", found["PAN-SVC-002"].summary)

    def test_no_snmp_configuration_fires_neither_snmp_control(self):
        """controls.json: "If SNMP is unused, leave snmp-setting unconfigured entirely"."""
        self.assertEqual(self._findings(dict(COMPLIANT)), {})

    def test_v2c_with_a_default_community_fires_004_and_005(self):
        found = self._findings(self._compliant(**{"snmp-setting": {"access-setting": {
            "version": {"v2c": {"snmp-community-string": "public"}}}}}))
        self.assertEqual(set(found), {"PAN-SVC-004", "PAN-SVC-005"})
        self.assertEqual(found["PAN-SVC-004"].severity, "high")
        self.assertEqual(found["PAN-SVC-005"].severity, "high")
        self.assertIn("DEFAULT community string", found["PAN-SVC-005"].summary)

    def test_v2c_with_a_non_default_community_fires_only_004(self):
        found = self._findings(self._compliant(**{"snmp-setting": {"access-setting": {
            "version": {"v2c": {"snmp-community-string": "s3cret-poll-string"}}}}}))
        self.assertEqual(set(found), {"PAN-SVC-004"})
        self.assertIn("non-default community string", found["PAN-SVC-004"].summary)

    def test_a_community_string_is_matched_case_insensitively(self):
        found = self._findings(self._compliant(**{"snmp-setting": {"access-setting": {
            "version": {"v2c": {"snmp-community-string": "Public"}}}}}))
        self.assertIn("PAN-SVC-005", found)

    def test_an_access_setting_with_no_version_is_read_as_v2c(self):
        """Help p.740: "Version: V2c (default) or V3". The finding says the version was inferred
        rather than read, because it rests on a vendor sentence."""
        found = self._findings(self._compliant(**{"snmp-setting": {"access-setting": {}}}))
        self.assertEqual(set(found), {"PAN-SVC-004"})
        self.assertIn("defaults the dialog to V2c", found["PAN-SVC-004"].summary)

    def test_v3_fires_neither(self):
        snmp = {"access-setting": {"version": {"v3": {
            "users": {"entry": [{"@name": "monitor"}]},
            "views": {"entry": [{"@name": "all"}]}}}}}
        self.assertEqual(self._findings(self._compliant(**{"snmp-setting": snmp})), {})

    def test_an_unexposed_community_says_it_is_latent(self):
        """No management surface enables SNMP in this fixture, so the finding must not imply the
        community string is reachable today."""
        found = self._findings(self._compliant(**{"snmp-setting": {"access-setting": {
            "version": {"v2c": {"snmp-community-string": "public"}}}}}))
        self.assertIn("latent", found["PAN-SVC-004"].summary)

    def test_a_dhcp_management_address_fires_007(self):
        found = self._findings(self._compliant(**{"type": {"dhcp-client": {
            "accept-dhcp-hostname": "yes"}}}))
        self.assertEqual(set(found), {"PAN-SVC-007"})
        self.assertEqual(found["PAN-SVC-007"].severity, "medium")
        self.assertIn("accepts the hostname", found["PAN-SVC-007"].summary)

    def test_an_absent_type_node_passes_007(self):
        """Measured: a PA-5220 with no `type` node compiles to ip-type static and reports
        is-dhcp no. Absence is the safe state here, which is the opposite of the usual reading."""
        system = dict(COMPLIANT)
        del system["type"]
        found = self._findings(system)
        self.assertEqual(found, {})

    def test_a_non_utc_timezone_fires_009(self):
        found = self._findings(self._compliant(timezone="US/Eastern"))
        self.assertEqual(set(found), {"PAN-SVC-009"})
        self.assertIn("rather than UTC", found["PAN-SVC-009"].summary)

    def test_a_hostname_matching_the_model_fires_009(self):
        """Help p.700: with no hostname written PAN-OS uses the model, "for example, PA-5220_2"."""
        found = self._findings(self._compliant(hostname="PA-5220_2"))
        self.assertEqual(set(found), {"PAN-SVC-009"})
        self.assertIn("factory hostname", found["PAN-SVC-009"].summary)
