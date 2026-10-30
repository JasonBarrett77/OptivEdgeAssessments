"""The five `ha-panorama` controls, against the configuration stage 6 of that domain built.

EVERY PAYLOAD HERE IS A READBACK AND NOT AN INVENTION. The keys and values are transcribed from
`stage6-ha-panorama.json`'s `verified.read_back` blocks and from the operational replies recorded
in its `verified.note` - what the four lab appliances returned on 2026-10-28 and 2026-10-29.
Stage 6 wrote its expected verdict for each subject BEFORE any query existed, which is what makes
this a test of the queries rather than a restatement of them.

SEVEN SUBJECTS, FOUR APPLIANCES, AND NOT ONE OF THEM IS ONE FINDING. Both PA-5220s are one HA
pair, so the HA subject yields TWO rows for one relationship and they are not expected to agree;
and two of stage 6's subjects sit on the SAME appliance under DIFFERENT assertion records of
PAN-HAP-005, so the finding that appliance gets is the union of two records' verdicts. The tests
that look lopsided are the ones holding that grain difference in place, and each says which.

WHAT THE ABSENCE OF A FINDING MEANS HERE, because three separate suppressions live on this
domain and all three read as compliance:

* `ha_enabled` is APPLICABILITY on PAN-HAP-002, 003 and 004, so a firewall in no pair produces
  nothing from them at all. `test_a_firewall_with_no_ha_node` holds that in place so nobody
  later reads it as a pass.
* AN APPLIANCE NOBODY COLLECTED HAS NO ROW, so no control over these two models can report it.
  `test_an_appliance_nobody_collected_has_no_row_to_report` is the measurement, and it is the
  reason the companion query stage 5 asked for cannot reach the case it was written for.
* PAN-HAP-006 and 007 have NO CATALOG ENTRY: they assert over Panorama's own configuration,
  which `rules.md` puts out of assessment scope. Their absence is a scope decision and not a
  gap, and `test_only_five_of_the_seven_controls_are_catalogued` says so.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.high_availability_findings import generate_high_availability_findings
from assessments.models import (
    AssessmentRun, Control, HighAvailabilityFinding, PanoramaRegistrationFinding)
from assessments.panorama_registration_findings import (
    generate_panorama_registration_findings)
from assessments.tests._seed import seed_controls, seed_specs
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, HighAvailabilityConfig, ManagementStation, PanoramaRegistration,
    Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.high_availability import (
    normalize_high_availability)
from optivedge_integrations.integrations.platforms.pan_os.normalization.panorama_registration \
    import normalize_panorama_registration

HA_CONTROLS = ["PAN-HAP-001", "PAN-HAP-002", "PAN-HAP-003", "PAN-HAP-004"]
PR_CONTROLS = ["PAN-HAP-005"]

#: `deviceconfig/high-availability` on fw-core-tpa-a - stage 6 subject hap6-01, and the same node
#: on its peer, which the pair's configuration synchronisation put there. `interface/ha1-backup`
#: is PRESENT AND EMPTY: the container answers as a key with a null value in all three config
#: views, which is the shape an existence test passes and the measured expression fails.
#: `interface/ha1/port`, `group/monitoring`, `group/election-option` and `cluster` are ABSENT.
HA_NODE_PAIR = {
    "enabled": "yes",
    "interface": {
        "ha1": {"ip-address": "172.30.19.101", "netmask": "255.255.255.0"},
        "ha1-backup": None, "ha2": None, "ha2-backup": None, "ha3": None,
    },
    "group": {
        "group-id": "44",
        "peer-ip": "172.30.19.102",
        "mode": {"active-passive": None},
        "configuration-synchronization": {"enabled": "yes"},
        "state-synchronization": {"enabled": "no"},
    },
}

#: `show high-availability all` on fw-core-tpa-a. THE MONITORING BLOCK IS THE MEASUREMENT THIS
#: DOMAIN TURNS ON: both enables report ON while no `group/monitoring` node exists in any config
#: view, so an absent key asserts that monitoring is enabled and monitoring nothing.
HA_RUNTIME_PAIR = {"response": {"result": {
    "enabled": "yes",
    "group": {
        "local-info": {"state": "active", "ha1-port": "ha1-a", "ha1-encrypt-enable": "no",
                       "ha1-encrypt-imported": "no", "state-sync": "User-disabled"},
        "peer-info": {"state": "passive", "conn-status": "up"},
        "running-sync": "synchronized", "running-sync-enabled": "yes",
        "link-monitoring": {"enabled": "yes", "failure-condition": "any", "groups": None},
        "path-monitoring": {"enabled": "yes", "failure-condition": "any",
                            "virtual-wire": None, "vlan": None, "virtual-router": None},
    },
}}}

#: The SHORT reply an appliance with no high-availability node answers - not nothing. `enabled:
#: no` is what the absence reads as, and the operational view is the only instrument that can
#: tell an absence from a read nobody took.
HA_RUNTIME_ABSENT = {"response": {"result": {
    "enabled": "no", "group": {"local-info": {"ha1-encrypt-imported": "no"}}}}}

#: hap6-03, written by stage 6 on fw-core-tpa-a (commit job 847) and carried to its peer; and
#: hap6-04, the state all four appliances were in before that write.
PANORAMA_TWO_SLOTS = {"panorama-server": "20.185.152.225", "panorama-server-2": "192.0.2.1"}
PANORAMA_ONE_SLOT = {"panorama-server": "20.185.152.225"}

#: hap6-05: a certificate BOUND and nothing switched on to use it. hap6-07: the explicit `none`
#: branch, present with no text - the same meaning as an absent key and a different stored state.
SECURE_CONN_BOUND_UNUSED = {"certificate-type": {"local": {"certificate": "pan-fw-111"}}}
SECURE_CONN_NONE_BRANCH = {"certificate-type": {"none": None}}

#: `show panorama-status` as the reply formats it: a plain string, not a parsed structure.
STATUS_TWO_SLOTS = {"response": {"result": (
    "Panorama Server 1 : 20.185.152.225\n    Connected     : yes\n    HA state      : Unknown\n"
    "Panorama Server 2 : 192.0.2.1\n    Connected     : no\n    HA state      : disconnected\n")}}
STATUS_ONE_SLOT = {"response": {"result": (
    "Panorama Server 1 : 20.185.152.225\n    Connected     : yes\n"
    "    HA state      : Unknown\n")}}


def merged(ha_node=None, local_panorama=None, secure_conn=None):
    """A `show config merged` payload. A key left out is ABSENT, which is not empty."""
    deviceconfig = {}
    if ha_node is not None:
        deviceconfig["high-availability"] = ha_node
    if local_panorama is not None:
        deviceconfig["system"] = {"panorama": {"local-panorama": local_panorama}}
    if secure_conn is not None:
        deviceconfig.setdefault("setting", {})["management"] = {"secure-conn-client": secure_conn}
    return {"config": {"devices": {"entry": [
        {"@name": "localhost.localdomain", "deviceconfig": deviceconfig}]}}}


#: hostname -> (serial, merged payload, HA runtime reply, panorama-status reply, in the pair).
#: The two PA-5220s are ONE HA pair in a real `ha_pair` group - which the probe's own census
#: cannot build - and the two PA-VMs are standalone, which is what they are.
ESTATE = {
    # hap6-01 + hap6-03 + hap6-06.
    "fw-core-tpa-a": ("013201001475", merged(HA_NODE_PAIR, PANORAMA_TWO_SLOTS, None),
                      HA_RUNTIME_PAIR, STATUS_TWO_SLOTS, True),
    # The passive member. NO SUBJECT OF STAGE 6 STANDS ON IT - stage 6 read it and wrote
    # nothing - so it is here to make the pair real and to show what the second row of one
    # relationship reports.
    "fw-core-tpa-b": ("013201001085", merged(HA_NODE_PAIR, PANORAMA_TWO_SLOTS, None),
                      HA_RUNTIME_PAIR, STATUS_TWO_SLOTS, True),
    # hap6-04 + hap6-05.
    "pan-fw-111": ("6A9C0A9904E7D6E", merged(None, PANORAMA_ONE_SLOT, SECURE_CONN_BOUND_UNUSED),
                   HA_RUNTIME_ABSENT, STATUS_ONE_SLOT, False),
    # hap6-02 + hap6-07.
    "pan-fw-201": ("691665AC334B458", merged(None, PANORAMA_ONE_SLOT, SECURE_CONN_NONE_BRANCH),
                   HA_RUNTIME_ABSENT, STATUS_ONE_SLOT, False),
}


class HaPanoramaControlTestCase(TestCase):
    """The lab's four appliances, two of them one HA pair, and the five controls over them."""

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="20.185.152.225")
        self.pair = ApplianceGroup.objects.create(
            management_station=self.station, name="g-fw-core-tpa",
            group_type=ApplianceGroup.TYPE_HA_PAIR)
        self.run = AssessmentRun.objects.create(
            name="HA/Panorama", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        seed_controls(HA_CONTROLS, control_type=Control.ControlType.HIGH_AVAILABILITY)
        seed_controls(PR_CONTROLS, control_type=Control.ControlType.PANORAMA_REGISTRATION)
        self.appliances = {}

    def appliance(self, hostname, *, group=None):
        serial = ESTATE[hostname][0]
        in_pair = ESTATE[hostname][4]
        if group is None:
            group = self.pair if in_pair else ApplianceGroup.objects.create(
                management_station=self.station, name=f"g-{hostname}",
                group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=group,
            serial_number=serial, hostname=hostname)
        self.appliances[hostname] = appliance
        return appliance

    def normalize(self, hostname, *, collect_runtime=True):
        _serial, payload, ha_runtime, status, _in_pair = ESTATE[hostname]
        appliance = self.appliances.get(hostname) or self.appliance(hostname)
        now = timezone.now()
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=now, payload=payload)
        if collect_runtime:
            Snapshot.objects.create(
                management_station=self.station, appliance=appliance,
                source_type="show_high_availability_all", collected_at=now, payload=ha_runtime)
            Snapshot.objects.create(
                management_station=self.station, appliance=appliance,
                source_type="show_panorama_status", collected_at=now, payload=status)
        normalize_high_availability(appliance)
        normalize_panorama_registration(appliance)
        return appliance

    def whole_lab(self, *, collect_runtime=True):
        for hostname in ESTATE:
            self.normalize(hostname, collect_runtime=collect_runtime)
        generate_high_availability_findings(self.run)
        generate_panorama_registration_findings(self.run)

    def verdicts(self, control_id):
        """{hostname: (severity, [matched query names])} for one control over the whole lab."""
        model = (HighAvailabilityFinding if control_id in HA_CONTROLS
                 else PanoramaRegistrationFinding)
        return {f.subject_name: (f.severity, sorted(f.matched_query_names))
                for f in model.objects.filter(control__control_id=control_id)}

    def summary(self, control_id, hostname):
        model = (HighAvailabilityFinding if control_id in HA_CONTROLS
                 else PanoramaRegistrationFinding)
        return model.objects.get(control__control_id=control_id, subject_name=hostname).summary


class CatalogueScopeTests(HaPanoramaControlTestCase):
    def test_only_five_of_the_seven_controls_are_catalogued(self):
        """PAN-HAP-006 and 007 assert over PANORAMA'S OWN configuration, which is out of
        assessment scope, so no catalog entry and no control type exists for them. Their absence
        is a scope decision rather than unfinished work, and this is where that is written down.
        """
        specs = seed_specs()
        present = sorted(cid for cid in specs if cid.startswith("PAN-HAP-"))
        self.assertEqual(present, ["PAN-HAP-001", "PAN-HAP-002", "PAN-HAP-003", "PAN-HAP-004",
                                   "PAN-HAP-005"])

    def test_each_control_targets_the_model_its_type_implies(self):
        for cid in HA_CONTROLS:
            with self.subTest(cid):
                self.assertEqual(Control.objects.get(control_id=cid).target_model,
                                 "integrations.HighAvailabilityConfig")
        self.assertEqual(Control.objects.get(control_id="PAN-HAP-005").target_model,
                         "integrations.PanoramaRegistration")


class RedundantPeerTests(HaPanoramaControlTestCase):
    """PAN-HAP-001. Every appliance in the lab, and that is the correct answer."""

    def test_the_control_fires_on_all_four_appliances(self):
        """Two reasons, independent of each other, and the finding has to say which.

        The two PA-VMs have no high-availability node: no peer, nothing fails over. The two
        PA-5220s ARE a configured pair and are not exchanging state - `state-sync: User-disabled`
        with `conn-ha2: down` - so the switch says redundant and the relationship is not.
        """
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-HAP-001"), {
            "fw-core-tpa-a": ("medium", ["Baseline"]),
            "fw-core-tpa-b": ("medium", ["Baseline"]),
            "pan-fw-111": ("medium", ["Baseline"]),
            "pan-fw-201": ("medium", ["Baseline"]),
        })

    def test_the_pair_member_is_not_reported_as_switched_off(self):
        """The sentence has to distinguish 'no peer configured' from 'configured and not formed'.
        Reporting the second as the first sends an engineer to enable a switch that is on."""
        self.whole_lab()
        pair = self.summary("PAN-HAP-001", "fw-core-tpa-a")
        self.assertIn("switched on and the relationship is not formed", pair)
        self.assertIn("state synchronisation is switched off", pair)
        standalone = self.summary("PAN-HAP-001", "pan-fw-201")
        self.assertIn("configured for no high-availability relationship at all", standalone)
        self.assertNotIn("switched on and the relationship is not formed", standalone)

    def test_a_pair_with_no_runtime_read_is_reported_as_not_established(self):
        """NO COLLECTOR ISSUES `show high-availability all` TODAY, so this is the state of every
        estate. The finding must say the relationship was not established, not that it failed -
        the reverse would send somebody to debug a pair nobody looked at."""
        self.whole_lab(collect_runtime=False)
        self.assertEqual(self.verdicts("PAN-HAP-001")["fw-core-tpa-a"], ("medium", ["Baseline"]))
        summary = self.summary("PAN-HAP-001", "fw-core-tpa-a")
        self.assertIn("NOT SHOWN to be", summary)
        self.assertIn("show high-availability all", summary)


class ControlLinkEncryptionTests(HaPanoramaControlTestCase):
    """PAN-HAP-002. The pair only - a standalone firewall has no peer link to encrypt."""

    def test_the_control_fires_on_the_pair_and_excludes_the_standalone_firewalls(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-HAP-002"), {
            # `unencrypted-dedicated-ha-port`, which stage 3 places AT this control's own
            # severity - so the baseline reports it and no calibration query is written.
            "fw-core-tpa-a": ("medium", ["Baseline"]),
            "fw-core-tpa-b": ("medium", ["Baseline"]),
        })

    def test_the_remediation_names_the_key_import_first(self):
        """The switch cannot be committed without an imported HA key - the device refuses it in
        those words. A finding that said only 'enable encryption' names a change that fails."""
        summary = self._summary_after_whole_lab()
        self.assertIn("no high-availability key is imported", summary)
        self.assertIn("Export and import the key between the peers first", summary)

    def test_the_finding_names_the_port_the_runtime_read_gave(self):
        """`interface/ha1/port` is ABSENT from the configuration on both members while the
        operational reply answers `ha1-a`. The band moves from port-unknown to dedicated port
        and the severity does not, which is why reading the runtime is accuracy and not risk."""
        summary = self._summary_after_whole_lab()
        self.assertIn("dedicated high-availability or auxiliary port", summary)

    def test_without_the_runtime_read_the_port_is_not_named(self):
        self.whole_lab(collect_runtime=False)
        summary = self.summary("PAN-HAP-002", "fw-core-tpa-a")
        self.assertIn("which port carries the control link was not established", summary)
        self.assertNotIn("dedicated high-availability or auxiliary port", summary)
        # Same severity either way, which is the whole point of the measurement.
        self.assertEqual(self.verdicts("PAN-HAP-002")["fw-core-tpa-a"][0], "medium")

    def test_a_link_on_the_management_port_is_graded_above_the_baseline(self):
        """The one calibration query this domain can exercise. The lab holds no appliance in
        this band, so the configuration is synthesised from the pair's own node with the port
        key present - which is the shape a real estate commonly has."""
        node = {**HA_NODE_PAIR, "interface": {**HA_NODE_PAIR["interface"],
                                              "ha1": {**HA_NODE_PAIR["interface"]["ha1"],
                                                      "port": "management"}}}
        appliance = self.appliance("fw-core-tpa-a")
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload=merged(node, PANORAMA_TWO_SLOTS, None))
        normalize_high_availability(appliance)
        generate_high_availability_findings(self.run)
        self.assertEqual(self.verdicts("PAN-HAP-002"), {
            "fw-core-tpa-a": ("high",
                              ["Baseline", "Unencrypted control link on the management port"]),
        })
        self.assertIn("shares the out-of-band management network",
                      self.summary("PAN-HAP-002", "fw-core-tpa-a"))

    def _summary_after_whole_lab(self):
        self.whole_lab()
        return self.summary("PAN-HAP-002", "fw-core-tpa-a")


class SecondKeepalivePathTests(HaPanoramaControlTestCase):
    """PAN-HAP-003. The subject that refutes the naive reading."""

    def test_an_empty_backup_container_is_a_finding_and_not_a_second_path(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-HAP-003"), {
            "fw-core-tpa-a": ("medium", ["Baseline"]),
            "fw-core-tpa-b": ("medium", ["Baseline"]),
        })
        summary = self.summary("PAN-HAP-003", "fw-core-tpa-a")
        self.assertIn("begun and not finished", summary)
        self.assertIn("A check for the container alone passes this appliance", summary)

    def test_one_complete_mechanism_satisfies_the_assertion_and_reports_nothing(self):
        """STAGE 3 GRADES THIS AT LOW AND NO QUERY CAN REACH IT. The normalizer sets the
        assertion column false the moment one mechanism is complete, and every query on this
        control carries that assertion clause - so the low band stage 3 assigned can never be
        reported, which is recorded in the stage 8 artifact's `unreachable_placements` rather
        than worked around here. This test holds the consequence in place: an appliance with one
        complete mechanism produces NOTHING, so the gap between the control's minimum and its
        preferred is not reported by this control at all."""
        node = {
            **HA_NODE_PAIR,
            "interface": {**HA_NODE_PAIR["interface"],
                          "ha1-backup": {"port": "ha1-b", "ip-address": "10.9.9.1",
                                         "netmask": "255.255.255.0"}},
            "group": {**HA_NODE_PAIR["group"], "peer-ip-backup": "10.9.9.2"},
        }
        appliance = self.appliance("fw-core-tpa-a")
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload=merged(node, PANORAMA_TWO_SLOTS, None))
        normalize_high_availability(appliance)
        row = HighAvailabilityConfig.objects.get(appliance=appliance)
        self.assertEqual(row.second_keepalive_path_state, "one-mechanism-complete")
        self.assertFalse(row.no_independent_second_keepalive_path)
        generate_high_availability_findings(self.run)
        self.assertEqual(self.verdicts("PAN-HAP-003"), {})


class MonitoringTests(HaPanoramaControlTestCase):
    """PAN-HAP-004. The sharpest measurement in the domain."""

    def test_monitoring_enabled_and_monitoring_nothing_is_the_finding(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-HAP-004"), {
            "fw-core-tpa-a": ("medium", ["Baseline"]),
            "fw-core-tpa-b": ("medium", ["Baseline"]),
        })
        row = HighAvailabilityConfig.objects.get(appliance__hostname="fw-core-tpa-a")
        # The device reports both enables as ON with no `group/monitoring` node anywhere, so a
        # query over either switch would have passed this appliance.
        self.assertTrue(row.link_monitoring_enabled)
        self.assertTrue(row.path_monitoring_enabled)
        self.assertEqual(row.ha_monitoring_state, "enabled-with-no-group")
        summary = self.summary("PAN-HAP-004", "fw-core-tpa-a")
        self.assertIn("reports itself as enabled and watches nothing", summary)
        self.assertIn("a link group carrying NO interface is valid configuration", summary)

    def test_a_populated_link_group_satisfies_the_assertion_and_reports_nothing(self):
        """The same unreachable-placement consequence as PAN-HAP-003's: stage 3 grades
        link-monitoring-only at low, the assertion column goes false as soon as a group holds an
        interface, and no query on this control can reach that band."""
        node = {
            **HA_NODE_PAIR,
            "group": {**HA_NODE_PAIR["group"], "monitoring": {"link-monitoring": {
                "enabled": "yes", "link-group": {"entry": [
                    {"@name": "lg1", "interface": {"member": "ethernet1/1"}}]}}}},
        }
        appliance = self.appliance("fw-core-tpa-a")
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload=merged(node, PANORAMA_TWO_SLOTS, None))
        normalize_high_availability(appliance)
        row = HighAvailabilityConfig.objects.get(appliance=appliance)
        self.assertEqual(row.ha_monitoring_state, "link-only-with-group")
        self.assertFalse(row.ha_monitors_nothing)
        generate_high_availability_findings(self.run)
        self.assertEqual(self.verdicts("PAN-HAP-004"), {})


class StandaloneFirewallTests(HaPanoramaControlTestCase):
    """`ha_enabled` is applicability on three of the four HA controls, and this holds it there."""

    def test_a_firewall_with_no_ha_node(self):
        """PAN-HAP-001 reports it and 002, 003 and 004 are SILENT - which is a suppression and
        not a pass. Nothing looked at the peer link, the keepalive paths or the monitoring on
        this appliance, because it has no peer for any of them to be about."""
        self.whole_lab()
        self.assertIn("pan-fw-201", self.verdicts("PAN-HAP-001"))
        for cid in ("PAN-HAP-002", "PAN-HAP-003", "PAN-HAP-004"):
            with self.subTest(cid):
                self.assertNotIn("pan-fw-201", self.verdicts(cid))

    def test_the_same_appliance_with_an_ha_node_fires_all_four(self):
        """The proof that the exclusion above is the switch and not the configuration."""
        appliance = self.appliance("pan-fw-201")
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload=merged(HA_NODE_PAIR, PANORAMA_ONE_SLOT, SECURE_CONN_NONE_BRANCH))
        normalize_high_availability(appliance)
        generate_high_availability_findings(self.run)
        fired = {f.control.control_id for f in HighAvailabilityFinding.objects
                 .select_related("control").filter(subject_name="pan-fw-201")}
        self.assertEqual(fired, set(HA_CONTROLS))


class CoverageTests(HaPanoramaControlTestCase):
    """What the companion query stage 5 asked for can and cannot reach.

    Stage 5 declares, for PAN-HAP-002, 003 and 004, a second query on
    `ha_config_collected equals false` firing on its own at the assertion's own severity, so that
    an appliance nobody read reports itself rather than failing the applicability clause in
    silence. These two tests measure what that query actually reaches, because the answer is not
    what the declaration assumes.
    """

    def test_an_appliance_nobody_collected_has_no_row_to_report(self):
        """THE CASE THE COMPANION QUERY WAS WRITTEN FOR PRODUCES NO ROW AT ALL, so no query on
        this model can reach it. `normalize_high_availability` returns early when there is no
        merged snapshot - deliberately, so that defaults never replace a real reading - and a
        control cannot report on a row that does not exist. The 'nobody looked' case for an
        uncollected APPLIANCE therefore belongs to a control over the appliance inventory, and
        not to this domain. Recorded in the stage 8 artifact rather than worked around here."""
        group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-never",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        never = Appliance.objects.create(
            management_station=self.station, appliance_group=group,
            serial_number="NEVER-READ", hostname="never-read")
        normalize_high_availability(never)
        normalize_panorama_registration(never)
        self.assertEqual(HighAvailabilityConfig.objects.filter(appliance=never).count(), 0)
        self.assertEqual(PanoramaRegistration.objects.filter(appliance=never).count(), 0)
        generate_high_availability_findings(self.run)
        self.assertEqual(HighAvailabilityFinding.objects.filter(
            subject_name="never-read").count(), 0)

    def test_a_row_carrying_the_migration_default_is_reported_by_the_companion_query(self):
        """The ONE state the companion query reaches: a row that exists and was not written by
        this normalizer - the `until_renormalised` case, which is what a future schema change
        leaves behind. The sentence must say the setting was NOT ESTABLISHED rather than that it
        is wrong, because the remediation for this one is ours and not the customer's."""
        group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-stale",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        stale = Appliance.objects.create(
            management_station=self.station, appliance_group=group,
            serial_number="STALE-ROW", hostname="stale-row")
        snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=stale,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload=merged(None, PANORAMA_ONE_SLOT, None))
        HighAvailabilityConfig.objects.create(
            appliance=stale, management_station=self.station, appliance_group=group,
            source_snapshot=snapshot)
        generate_high_availability_findings(self.run)
        for cid in ("PAN-HAP-002", "PAN-HAP-003", "PAN-HAP-004"):
            with self.subTest(cid):
                self.assertEqual(
                    self.verdicts(cid)["stale-row"],
                    ("medium", ["High-availability configuration not collected"]))
        summary = self.summary("PAN-HAP-002", "stale-row")
        self.assertIn("was not collected for this appliance", summary)
        self.assertIn("NOT ESTABLISHED", summary)
        self.assertIn("cleared by collecting the appliance", summary)
        # NOT the assertion's sentence. A coverage statement that read as a configuration defect
        # would send a customer to fix something nobody looked at.
        self.assertNotIn("crosses the link in clear", summary)


class ManagementChannelTests(HaPanoramaControlTestCase):
    """PAN-HAP-005. One control, two assertions, two severities, one row per appliance."""

    def test_the_control_over_the_whole_lab(self):
        """THE GRAIN DIFFERENCE IS VISIBLE HERE AND NOWHERE ELSE IN THIS DOMAIN. Stage 6 graded
        five subjects on this control across three appliances, two assertion records apart. Each
        appliance gets ONE finding, and its severity is the worse of the halves it fails:

        * the two PA-5220s name two management appliances and harden nothing, so only the
          hardening half fires and the row is low;
        * both PA-VMs fail both halves, so the redundancy calibration wins and the row is medium.
        """
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-HAP-005"), {
            "fw-core-tpa-a": ("low", ["Baseline"]),
            "fw-core-tpa-b": ("low", ["Baseline"]),
            "pan-fw-111": ("medium",
                           ["Baseline", "No secondary management appliance named"]),
            "pan-fw-201": ("medium",
                           ["Baseline", "No secondary management appliance named"]),
        })

    def test_a_row_failing_both_halves_reports_the_worse_severity(self):
        """The severity mechanism working as built: the baseline tier is discarded the moment a
        calibration matches. Reported the other way round - the redundancy half as the baseline
        and the hardening half as a low calibration - a firewall failing both would be reported
        at LOW, which is the gentler of the two and the wrong direction."""
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-HAP-005")["pan-fw-111"][0], "medium")
        summary = self.summary("PAN-HAP-005", "pan-fw-111")
        # Both halves' prose, one severity. Suppressing the gentler half's sentence would leave a
        # reader with a medium finding and no account of the certificate posture it also fails.
        self.assertIn("names ONE management appliance", summary)
        self.assertIn("predefined certificate pair", summary)

    def test_a_bound_certificate_nothing_uses_is_still_a_finding(self):
        """hap6-05. A device certificate IS bound and no surface is switched to use it, so the
        connection runs on the predefined pair and the binding configures nothing the device
        presents. The finding names the bound certificate so the remediation is actionable."""
        self.whole_lab()
        summary = self.summary("PAN-HAP-005", "pan-fw-111")
        self.assertIn("a device certificate is bound (pan-fw-111)", summary)
        self.assertIn("enable-secure-panorama-communication", summary)

    def test_the_explicit_none_branch_reads_the_same_as_an_absent_node(self):
        """hap6-07 against hap6-06. `certificate-type/none` present with no text and the whole
        `secure-conn-client` node absent are two different STORED STATES with one meaning, and
        the control has to treat them alike - a normalizer reading a text value here gets
        nothing, and one testing for the key's presence concludes a certificate type is
        configured."""
        self.whole_lab()
        none_branch = PanoramaRegistration.objects.get(appliance__hostname="pan-fw-201")
        absent_node = PanoramaRegistration.objects.get(appliance__hostname="fw-core-tpa-a")
        self.assertEqual(none_branch.client_certificate_type, "none")
        self.assertEqual(absent_node.client_certificate_type, "")
        self.assertTrue(none_branch.management_channel_not_hardened)
        self.assertTrue(absent_node.management_channel_not_hardened)
        self.assertIn("holds its `none` branch", self.summary("PAN-HAP-005", "pan-fw-201"))
        self.assertIn("node or its `certificate-type` key is absent",
                      self.summary("PAN-HAP-005", "fw-core-tpa-a"))

    def test_every_finding_says_the_pair_question_was_assumed(self):
        """`management_estate_is_a_pair` is TRUE BY DEFAULT and false by nothing: the answer is
        on the management appliance, which is out of assessment scope. On a single-appliance
        estate - which this lab IS, the station's HA node being absent in all three config views
        - the redundancy half fires everywhere and its remediation is wrong. The finding has to
        say so rather than leave a reader to find out."""
        self.whole_lab()
        summary = self.summary("PAN-HAP-005", "pan-fw-111")
        self.assertIn("ASSUMED to be a redundant pair", summary)
        self.assertIn("an appliance that does not exist", summary)

    def test_every_finding_says_the_station_half_is_unanswered(self):
        """Custom Certificate Only and Check Authorization List are on the station and on no
        firewall, so even all three firewall switches on does not authenticate the channel."""
        self.whole_lab()
        for hostname in ESTATE:
            with self.subTest(hostname):
                self.assertIn("UNANSWERED and no firewall can answer it",
                              self.summary("PAN-HAP-005", hostname))

    def test_a_fully_hardened_channel_with_two_slots_reports_nothing(self):
        """The only configuration in this domain that satisfies a control on every count, and the
        lab holds none of it - so it is synthesised. Without this the suite could not tell a
        control that always fires from one that fires correctly."""
        secure = {"certificate-type": {"local": {"certificate": "cust-fw"}},
                  "enable-secure-panorama-communication": "yes",
                  "check-server-identity": "yes"}
        appliance = self.appliance("pan-fw-111")
        Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload=merged(None, PANORAMA_TWO_SLOTS, secure))
        normalize_panorama_registration(appliance)
        row = PanoramaRegistration.objects.get(appliance=appliance)
        self.assertFalse(row.management_channel_not_hardened)
        generate_panorama_registration_findings(self.run)
        self.assertEqual(self.verdicts("PAN-HAP-005"), {})


class PairDuplicationTests(HaPanoramaControlTestCase):
    """ONE RELATIONSHIP, TWO ROWS, AND NOTHING DEDUPLICATES THEM - on purpose for one model and
    as a known duplication for the other."""

    def test_the_ha_pair_produces_two_findings_per_control(self):
        """Correct rather than a defect: HA state genuinely differs per node, and no column of a
        one-row-per-appliance model can hold a property of the pair. A pair with the encryption
        key imported on one member only reports as two independent findings."""
        self.whole_lab()
        for cid in ("PAN-HAP-002", "PAN-HAP-003", "PAN-HAP-004"):
            with self.subTest(cid):
                self.assertEqual(sorted(self.verdicts(cid)),
                                 ["fw-core-tpa-a", "fw-core-tpa-b"])

    def test_the_registration_rows_agree_and_still_produce_two_findings(self):
        """The opposite case, and the one a reader should know about: the management addresses
        and the secure-communication switches are not HA fields, so the pair's two rows hold the
        same values - measured, `panorama-server-2` written on one member and present on both -
        and the customer gets two identical findings for one gap."""
        self.whole_lab()
        rows = {r.appliance.hostname: (r.panorama_server_secondary,
                                       r.management_channel_not_hardened)
                for r in PanoramaRegistration.objects.select_related("appliance")
                .filter(appliance__appliance_group=self.pair)}
        self.assertEqual(rows, {"fw-core-tpa-a": ("192.0.2.1", True),
                                "fw-core-tpa-b": ("192.0.2.1", True)})
        verdicts = self.verdicts("PAN-HAP-005")
        self.assertEqual(verdicts["fw-core-tpa-a"], verdicts["fw-core-tpa-b"])


class TopologyTests(HaPanoramaControlTestCase):
    """THE CENSUS OFFSET THE STAGE 8 CONTRACT WARNS ABOUT DOES NOT APPLY TO THIS DOMAIN, and
    this is the measurement rather than the claim.

    The probe's own census builds STANDALONE appliance groups and its header says that makes
    `ha_required` false so the HA controls cannot fire. `ha_required` is a column of a DEPRECATED
    device-configuration-profile model, clauseed on by the deprecated HA-002/HA-003 controls in
    `seed-deprecated.json`. No column of `HighAvailabilityConfig` or `PanoramaRegistration` reads
    `ApplianceGroup.group_type` at all, and `ha_enabled` comes from the merged-config payload.
    """

    def test_the_group_type_changes_no_verdict(self):
        standalone_only = ApplianceGroup.objects.create(
            management_station=self.station, name="g-flat",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        for hostname in ESTATE:
            self.appliance(hostname, group=standalone_only)
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-HAP-001"), {
            "fw-core-tpa-a": ("medium", ["Baseline"]),
            "fw-core-tpa-b": ("medium", ["Baseline"]),
            "pan-fw-111": ("medium", ["Baseline"]),
            "pan-fw-201": ("medium", ["Baseline"]),
        })
        self.assertEqual(sorted(self.verdicts("PAN-HAP-002")),
                         ["fw-core-tpa-a", "fw-core-tpa-b"])
        self.assertEqual(self.verdicts("PAN-HAP-005")["pan-fw-111"][0], "medium")
