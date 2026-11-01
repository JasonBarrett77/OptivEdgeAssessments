"""PAN-SVC-001 to 010 over deviceconfig/system, less the one that ships nothing.

Three models from one walk, so the fixtures build one `system` node and assert against all three.

EVERY FIXTURE NOW WRITES A `show_ntp` SNAPSHOT, added 2026-11-01 with PAN-SVC-001's second
assertion record. That record asks whether the clock is anchored to a server this configuration
names, and the column it rests on defaults to the FIRING side on purpose - so before this, every
fixture in this module inherited "anchored to nothing" and PAN-SVC-001 fired on all fourteen of
them, including the one named `test_a_compliant_device_fires_nothing`. The default reading says
the clock is kept by COMPLIANT's own primary server, which is what makes a compliant device
compliant on both halves; `_findings(..., ntp=...)` overrides it and `ntp=None` means the
operational read was never taken.

The cases that earn their place are the measured ones, where the obvious reading is wrong:
an ABSENT `type` node is static rather than unknown, so a device with nothing written passes
PAN-SVC-007; an `access-setting` with no `version` child is v2c by the vendor's stated default,
so PAN-SVC-004 fires on it; and a device with no SNMP configuration at all is COMPLIANT rather
than unassessed, which is the one thing that would make these two controls noise on every estate.
"""

from django.test import TestCase
from django.utils import timezone

from assessments.models import (
    AssessmentRun, Control, DnsSettingsFinding, NtpSettingsFinding, ServiceRouteFinding,
    SnmpSettingsFinding, SystemIdentityFinding)
from assessments.dns_settings_findings import generate_dns_settings_findings
from assessments.ntp_settings_findings import generate_ntp_settings_findings
from assessments.service_route_findings import generate_service_route_findings
from assessments.snmp_settings_findings import generate_snmp_settings_findings
from assessments.system_identity_findings import generate_system_identity_findings
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ManagementStation, ServiceRoute, Snapshot, SnmpSettings)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_services import (
    normalize_device_services)

#: `show ntp` saying the clock is kept by COMPLIANT's own primary server. See the module
#: docstring: without this every fixture here reads as a clock anchored to nothing, which is the
#: firing side and is correct for a device nobody asked.
SYNCHED_TO_COMPLIANT_PRIMARY = {"synched": "ntp1.example.net"}

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
        seed_controls(["PAN-SVC-007", "PAN-SVC-009", "PAN-SVC-010"],
                      control_type=Control.ControlType.SYSTEM_IDENTITY)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _findings(self, system, ntp=SYNCHED_TO_COMPLIANT_PRIMARY):
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": [{"@name": "localhost.localdomain",
                                                       "deviceconfig": {"system": system}}]}}})
        if ntp is not None:
            Snapshot.objects.create(
                management_station=self.station, appliance=self.appliance,
                source_type="show_ntp", collected_at=timezone.now(), payload=ntp)
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

    def test_an_empty_system_node_fires_ntp_and_both_identity_controls(self):
        """Nothing configured: no NTP at all, no hostname - which PAN-OS renders as the model -
        and no time zone. The management address is NOT a finding, because absent `type` is
        static. 009 and 010 fire SEPARATELY; before the 2026-09-15 split this was one finding."""
        found = self._findings({})
        self.assertEqual(set(found), {"PAN-SVC-001", "PAN-SVC-002", "PAN-SVC-009", "PAN-SVC-010"})
        self.assertEqual(found["PAN-SVC-001"].severity, "high")
        self.assertEqual(found["PAN-SVC-002"].severity, "medium")
        self.assertEqual(found["PAN-SVC-009"].severity, "low")
        self.assertEqual(found["PAN-SVC-010"].severity, "low")
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
        """The sentence no longer says "rather than UTC", changed 2026-11-01 with the clause.

        It said "its time zone is US/Eastern rather than UTC" and branched on `timezone_is_utc`,
        which is one spelling of zero offset out of eighteen. The two cases below are the rows
        that made it wrong.
        """
        found = self._findings(self._compliant(timezone="US/Eastern"))
        self.assertEqual(set(found), {"PAN-SVC-009"})
        self.assertIn("does not declare zero offset", found["PAN-SVC-009"].summary)

    def test_a_hostname_matching_the_model_fires_010(self):
        """Help p.700: with no hostname written PAN-OS uses the model, "for example, PA-5220_2"."""
        found = self._findings(self._compliant(hostname="PA-5220_2"))
        self.assertEqual(set(found), {"PAN-SVC-010"})
        self.assertIn("factory hostname", found["PAN-SVC-010"].summary)

    def test_a_chosen_name_leading_with_the_model_does_not_fire_010(self):
        """The factory suffix is an INDEX. `PA-5220_EDGE-01` is a naming convention, not a
        default, and an earlier `startswith(model + "_")` reported every such device as unnamed."""
        self.assertEqual(self._findings(self._compliant(hostname="PA-5220_EDGE-01")), {})

    def test_the_two_identity_halves_fire_independently(self):
        """The reason for the split: one defect must not mask or carry the other."""
        found = self._findings(self._compliant(hostname="PA-5220_2", timezone="US/Eastern"))
        self.assertEqual(set(found), {"PAN-SVC-009", "PAN-SVC-010"})

    # ------------------------------------------------------------------ added by stage 8, 2026-11-01
    # Each of these is a row that the shipped clause or the shipped sentence got wrong, and the
    # measurement is in the name. They are regression guards for the two supersessions and for
    # the second assertion record, and nothing else in either repository holds them.

    def test_a_zero_offset_spelling_other_than_utc_does_not_fire_009(self):
        """THE ROW THE SHIPPED CLAUSE REPORTED AND SHOULD NOT HAVE. `timezone_is_utc` is
        `timezone.strip().upper() == "UTC"`; the device offers eighteen keys that declare zero
        offset in their own text, so seventeen compliant spellings fired the old clause. The
        supersession NARROWS this control, which is the opposite direction from the one the word
        suggests."""
        for zone in ("GMT", "Etc/UTC", "Zulu", "Universal"):
            with self.subTest(zone):
                SystemIdentityFinding.objects.all().delete()
                self.assertNotIn("PAN-SVC-009", self._findings(self._compliant(timezone=zone)))

    def test_a_zone_at_zero_offset_that_does_not_declare_it_fires_009_and_says_why(self):
        """`Atlantic/Reykjavik`: zero offset every month of the year, no daylight rule, and not a
        zero-offset SPELLING. The old sentence said its logs need offset arithmetic, which is
        false. It still reports, at this control's own severity, for the reason the new sentence
        gives - it reads correctly now and can move with a vendor time-zone update."""
        found = self._findings(self._compliant(timezone="Atlantic/Reykjavik"))
        self.assertEqual(set(found), {"PAN-SVC-009"})
        self.assertEqual(found["PAN-SVC-009"].severity, "low")
        self.assertIn("sits at zero offset today", found["PAN-SVC-009"].summary)
        self.assertNotIn("needs offset arithmetic", found["PAN-SVC-009"].summary)

    def test_two_servers_both_authenticated_and_a_clock_kept_locally_fires_001(self):
        """THE CONFIGURATION THAT PASSES THE COUNTABLE HALF AND IS KEEPING NO TIME AT ALL, and
        one lab appliance is in it. The shipped single-query control reported nothing here."""
        found = self._findings(dict(COMPLIANT), ntp={"synched": "LOCAL"})
        self.assertEqual(set(found), {"PAN-SVC-001"})
        self.assertEqual(found["PAN-SVC-001"].severity, "high")
        self.assertIn("nothing upstream is keeping its clock", found["PAN-SVC-001"].summary)

    def test_a_clock_kept_by_an_address_the_configuration_does_not_name_fires_001_at_medium(self):
        found = self._findings(dict(COMPLIANT), ntp={"synched": "time.elsewhere.example"})
        self.assertEqual(set(found), {"PAN-SVC-001"})
        self.assertEqual(found["PAN-SVC-001"].severity, "medium")
        self.assertIn("does not name", found["PAN-SVC-001"].summary)

    def test_an_unread_show_ntp_fires_001_rather_than_passing(self):
        """`rules.md`: an unknown fires. The two states share one rank deliberately - nothing
        downstream could act on the difference and the safe answer is the same either way."""
        found = self._findings(dict(COMPLIANT), ntp=None)
        self.assertEqual(set(found), {"PAN-SVC-001"})
        self.assertEqual(found["PAN-SVC-001"].severity, "high")

    def test_no_server_and_an_unnamed_source_still_reports_at_the_count_severity(self):
        """WHY THE WORST-CASE AT-TIER QUERY EXISTS, and it is not redundant. The severity is the
        worst MATCHED calibration; with no query for `server_count eq 0` this row would match the
        medium unnamed-source calibration alone and report one rank below what the count earns.
        The two assertion records grade different columns, so one row can match a query from
        each."""
        found = self._findings({}, ntp={"synched": "time.elsewhere.example"})
        self.assertEqual(found["PAN-SVC-001"].severity, "high")

    def test_the_snmp_supersession_selects_the_same_rows_as_the_clause_it_replaced(self):
        """MEASURED OVER EVERY REACHABLE STATE, because the new column's own docstring says it
        exists for a disjunction and the second member turns out to be inside the first:
        `implicit` materialises `v2c` as the effective version before `uses_v2c` is computed."""
        states = (
            ({}, False),
            ({"snmp-setting": {}}, False),
            ({"snmp-setting": {"access-setting": {}}}, True),
            ({"snmp-setting": {"access-setting": {"version": {"v2c": None}}}}, True),
            ({"snmp-setting": {"access-setting": {"version": {"v3": {}}}}}, False),
        )
        for node, fires in states:
            with self.subTest(node=node):
                SnmpSettingsFinding.objects.all().delete()
                found = self._findings(self._compliant(**node))
                self.assertEqual("PAN-SVC-004" in found, fires)
                row = SnmpSettings.objects.get(appliance=self.appliance)
                self.assertEqual(
                    row.answers_on_an_unauthenticated_version,
                    row.is_configured and row.uses_v2c,
                    "the superseding column and the clause it replaced must select one set")


class MintedDeviceServicesControlTests(TestCase):
    """PAN-SVC-003 and PAN-SVC-006, the two this domain minted on 2026-11-01.

    THEIR OWN CLASS AND NOT THE ONE ABOVE, deliberately. That class's `COMPLIANT` fixture is a
    device that passes the seven controls which already shipped, and it does NOT pass these two:
    it names no management resolver and sets no service path, so both fire on it correctly. Its
    tests assert on the exact SET of findings, which is a property worth keeping - so the new
    controls get their own fixtures rather than a shared one weakened to accommodate them.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.mint")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-mint",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-MINT", hostname="fw-mint", model="PA-5220",
            software_version="11.1.13-h3")
        seed_controls(["PAN-SVC-003"], control_type=Control.ControlType.DNS_SETTINGS)
        seed_controls(["PAN-SVC-006"], control_type=Control.ControlType.SERVICE_ROUTE)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _rows(self, system, vsys=()):
        entry = {"@name": "localhost.localdomain", "deviceconfig": {"system": system}}
        if vsys:
            entry["vsys"] = {"entry": list(vsys)}
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": [entry]}}})
        normalize_device_services(self.appliance)
        generate_dns_settings_findings(self.run)
        generate_service_route_findings(self.run)
        rows = []
        for model in (DnsSettingsFinding, ServiceRouteFinding):
            for finding in model.objects.select_related("control"):
                rows.append(finding)
        return rows

    def _by_control(self, system, vsys=()):
        out = {}
        for finding in self._rows(system, vsys=vsys):
            out.setdefault(finding.control.control_id, []).append(finding)
        return out
    def test_a_fixed_address_with_no_resolver_fires_003_and_names_the_mechanism(self):
        found = self._by_control({"type": {"static": None}})
        self.assertIn("PAN-SVC-003", found)
        self.assertEqual(found["PAN-SVC-003"][0].severity, "medium")
        self.assertIn("nothing is resolving management names at all",
                      found["PAN-SVC-003"][0].summary)

    def test_a_leased_address_with_no_resolver_says_it_is_resolving_through_the_lease(self):
        """THE RANK THE SHIPPED READING WOULD HAVE MISSED: an empty resolver pair on a leased
        management address is not "nothing is resolving". The vendor says of the resolvers what
        it says of the time servers - a lease's addresses are considered where none is
        configured - so such a firewall IS resolving, through an address nobody here chose."""
        found = self._by_control({"type": {"dhcp-client": {}}})
        self.assertIn("PAN-SVC-003", found)
        self.assertIn("its management address is leased", found["PAN-SVC-003"][0].summary)

    def test_two_resolvers_do_not_fire_003(self):
        found = self._by_control(
            {"type": {"static": None},
             "dns-setting": {"servers": {"primary": "10.0.0.53", "secondary": "10.0.0.54"}}})
        self.assertNotIn("PAN-SVC-003", found)

    def test_one_resolver_fires_003(self):
        found = self._by_control(
            {"type": {"static": None}, "dns-setting": {"servers": {"primary": "10.0.0.53"}}})
        self.assertIn("PAN-SVC-003", found)
        self.assertIn("losing that one resolver", found["PAN-SVC-003"][0].summary)

    def test_a_bound_proxy_object_counts_as_one_resolver_and_says_so(self):
        """It fires, and the sentence says the count is this assessment's and not the object's:
        the proxy object's own server list is a hop nothing in the measured estate exercises."""
        found = self._by_control(
            {"type": {"static": None}, "dns-setting": {"dns-proxy-object": "mgmt-proxy"}})
        self.assertIn("PAN-SVC-003", found)
        self.assertIn("counts as ONE chosen resolver", found["PAN-SVC-003"][0].summary)

    def test_the_firewall_wide_half_fires_on_an_undivided_firewall(self):
        """ONE CONTROL, TWO RECORDS, AND THE PARTITION IS `scope`. An appliance naming no vsys
        has exactly one row of this model, so only the firewall-wide query can match it - and
        the per-system columns hold their FIRING defaults on that row, so a query without
        `scope eq vsys` would report an appliance-wide point for failing to record a per-vsys
        choice. This is the test that would catch that."""
        found = self._by_control({"type": {"static": None}, "dns-setting": {
            "servers": {"primary": "10.0.0.53", "secondary": "10.0.0.54"}}})
        rows = found["PAN-SVC-006"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].severity, "medium")
        self.assertEqual(rows[0].subject_name, "fw-mint")
        self.assertIn("this assessment can attribute", rows[0].summary)

    def test_a_vsys_with_no_recorded_choice_fires_the_per_system_half_on_its_own_row(self):
        """TWO ROWS, TWO FINDINGS, ONE CONTROL - and `subject_scope` is what tells them apart,
        because `vsys1` is not a unique name in an estate."""
        found = self._by_control(
            {"type": {"static": None},
             "dns-setting": {"servers": {"primary": "10.0.0.53", "secondary": "10.0.0.54"}}},
            vsys=[{"@name": "vsys1"}])
        rows = sorted(found["PAN-SVC-006"], key=lambda f: f.subject_name)
        self.assertEqual([r.subject_name for r in rows], ["fw-mint", "vsys1"])
        self.assertEqual({r.subject_scope for r in rows}, {"fw-mint"})
        vsys_row = rows[1]
        self.assertEqual(vsys_row.severity, "medium")
        self.assertIn("records no service-path choice of its own", vsys_row.summary)
        self.assertNotIn("can attribute", vsys_row.summary)

    def test_the_two_records_partition_this_table_on_scope(self):
        """UNION IS THE WHOLE TABLE AND THE INTERSECTION IS EMPTY, measured over the rows rather
        than argued from the column's `choices`."""
        self._rows({"type": {"static": None}}, vsys=[{"@name": "vsys1"}, {"@name": "vsys2"}])
        local = set(ServiceRoute.objects.filter(scope="device-local").values_list("pk", flat=True))
        per_vsys = set(ServiceRoute.objects.filter(scope="vsys").values_list("pk", flat=True))
        every = set(ServiceRoute.objects.values_list("pk", flat=True))
        self.assertEqual(local | per_vsys, every)
        self.assertEqual(local & per_vsys, set())
        self.assertEqual((len(local), len(per_vsys)), (1, 2))
