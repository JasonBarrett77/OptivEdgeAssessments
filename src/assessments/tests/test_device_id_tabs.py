"""The three Device-ID tabs as a customer reads them: what the columns are called, which cell is
marked, and the cells that say more than a field holds.

WHY THIS FILE EXISTS. The stage 9 run of the `device-id-iot` domain built all three tabs and read
all 13 rows, and the things it could not settle were report content - what the derived columns are
headed, and what a cell should say where the shared `display_value` has no word for the state.
Nothing in this repo held any of those, so each was a judgment the next change could undo in
silence. Three of them are not cosmetic:

  - AN EMPTY DEVICE-ID ADDRESS LIST IS THE VENDOR'S `any`, NOT A BLANK. Stage 4 measured the grid
    on two platforms: with no `device-acl` node INCLUDED NETWORKS renders `any` and EXCLUDED
    renders `none`, so an empty include list means identification applies to EVERY address in the
    zone - the most permissive state on the device AND the compliant one for PAN-IOT-002. A blank
    cell here is the first of this stage's three recorded presentation failures verbatim: "a blank
    cell where the honest value was *any source*".

  - THE VERDICT COLUMN'S HEADING CARRIES THE DIRECTION. `has_no_rule_matching_on_device` defaults
    True and True is the FIRING side, so a heading naming the healthy state would put "No" in the
    firing cell - and the failure this stage exists to catch is a row whose most REASSURING cell is
    the finding.

  - A NULL CONTENT AGE IS THE EM DASH AND NOT `(none)`. The appliance reported no release date at
    all, so PAN-IOT-003's applicability clause narrowed the row OUT of the graded comparison;
    `(none)` in a column of day counts reads as a value somebody failed to fill in.

AND ONE THING THAT IS NOT A JUDGMENT BUT A DEFECT, pinned so that fixing it shows up as a test
change rather than silently: `integrations.Zone` tracks no per-field provenance, so the Provenance
cell on the Security Zones tab cannot say whether a zone is local or pushed from a template. The
test below asserts the honest sentence it prints instead. If Zone ever becomes a `ProvenancedMixin`
this test should fail and be rewritten to assert the real answer.

THE FIXTURE IS A SUBSET AND SAYS SO. Six zones, two appliances and five enforcement points,
transcribed from `stage6-device-id-iot.json`'s `verified.read_back` and `verified.note` blocks -
which is what `type=config&action=show`, `request license info` and `show system info` returned
through Panorama's proxy on 2026-10-27. All 16 of the domain's verdicts are reconciled against
OptivEdgeProbe's stage 8 artifact and not here.
"""
from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as config_results
from assessments import device_id_presentation as device_id
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.layout import NONE
from assessments.artifacts.sheets.findings import build_findings_table
from assessments.device_identification_findings import generate_device_identification_findings
from assessments.models import AssessmentRun, Control
from assessments.rulebase_device_match_findings import generate_rulebase_device_match_findings
from assessments.tests._seed import seed_controls
from assessments.zone_findings import generate_zone_findings
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementPoint, ManagementStation, SecurityRule, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.device_identification import (
    normalize_device_identification_state, normalize_rulebase_device_match)
from optivedge_integrations.integrations.platforms.pan_os.normalization.zones import normalize_zones

TPA_A = "013201001475"
FW_111 = "6A9C0A9904E7D6E"

SLUGS = ("iot-security", "security-zones", "rulebase-device-match")

#: iot6-04 to iot6-07 and iot6-09, on fw-core-tpa-a. The bare entry is the absent-field subject for
#: the switch and the whole `device-acl` branch at once.
TPA_A_ZONES = {
    "vsys3": [
        {"@name": "oep-iot6-z1", "enable-device-identification": "yes",
         "network": {"layer3": None}},
        {"@name": "oep-iot6-z2"},
        {"@name": "oep-iot6-z3", "enable-device-identification": "yes",
         "device-acl": {"include-list": {"member": ["203.0.113.0/24"]}}},
        {"@name": "oep-iot6-z4", "enable-device-identification": "yes",
         "device-acl": {"exclude-list": {"member": ["203.0.113.128/25"]}}},
    ],
    "vsys6": [
        {"@name": "scratch_zone", "enable-device-identification": "yes",
         "device-acl": {"include-list": {"member": ["99.99.98.0/24", "99.99.99.99",
                                                    "ag-agent-desktop-services"]},
                        "exclude-list": {"member": ["88.88.88.0/24", "88.88.88.88",
                                                    "ag-b2b-integration-services-dg"]}},
         "network": {"layer3": None}},
    ],
    "vsys1": [],
}

#: iot6-16: a zone that exists ONLY in a Panorama template, every element decorated, and NO
#: `enable-device-identification` child in either view.
FW_111_ZONES = {"vsys1": [
    {"@name": "trust", "@ptpl": "ptpl-pan-fw-111", "@src": "tpl",
     "network": {"@ptpl": "ptpl-pan-fw-111", "@src": "tpl",
                 "layer3": {"member": ["ethernet1/2"]}, "log-setting": "default"}},
]}


def merged(zones_by_vsys, *, deviceconfig=None, shared_device_object=False,
           vsys_device_objects=()):
    entries = []
    for name, zones in zones_by_vsys.items():
        entry = {"@name": name, "zone": {"entry": list(zones)} if zones else {}}
        if name in vsys_device_objects:
            entry["device-object"] = {"entry": [{"@name": "oep-iot6-dev-v",
                                                 "category": {"member": ["Camera"]}}]}
        entries.append(entry)
    device = {"@name": "localhost.localdomain", "vsys": {"entry": entries}}
    if deviceconfig:
        device["deviceconfig"] = deviceconfig
    config = {"devices": {"entry": [device]}}
    if shared_device_object:
        config["shared"] = {"device-object": {"entry": [
            {"@name": "oep-iot6-dev-s", "profile": {"member": ["IP Camera"]}}]}}
    return {"config": config}


class DeviceIdTabTestCase(TestCase):
    def setUp(self):
        now = timezone.now()
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.iot")
        run = AssessmentRun.objects.create(
            name="Device-ID", status=AssessmentRun.Status.RUNNING, started_at=now)
        seed_controls(["PAN-IOT-001", "PAN-IOT-003"],
                      control_type=Control.ControlType.DEVICE_IDENTIFICATION)
        seed_controls(["PAN-IOT-002"], control_type=Control.ControlType.ZONE)
        seed_controls(["PAN-IOT-004"],
                      control_type=Control.ControlType.RULEBASE_DEVICE_MATCH)

        # fw-core-tpa-a: the edge node IS wired, the licence listing answers an EMPTY ENVELOPE -
        # a read that happened and reported nothing - and `show system info` carries a dictionary
        # version with NO release date, which is the state PAN-IOT-003's applicability clause
        # turns on.
        tpa_payload = merged(
            TPA_A_ZONES,
            deviceconfig={"setting": {"iot": {"edge": {
                "address": "edge-oep-iot6.invalid", "disable-device-cert": "no"}}}},
            shared_device_object=True, vsys_device_objects=("vsys3",))
        tpa = self._appliance(TPA_A, "fw-core-tpa-a", tpa_payload, now, licences={
            "licenses": None}, system={
            "system": {"device-dictionary-version": "82-406",
                       "time": "Tue Oct 27 16:46:00 2026"}},
            icd="Version: 13.pan_h1_r3\nTimeBuilt: 2026-02-06T13:34:53PST")

        # pan-fw-111: the edge node is ABSENT, three non-IoT licence rows, and a release date four
        # days before the reading - the one appliance in the lab whose content is current.
        fw_payload = merged(FW_111_ZONES)
        self._appliance(FW_111, "pan-fw-111", fw_payload, now, licences={"licenses": {"entry": [
            {"feature": "Adv Threat Prevention", "expires": "Never", "expired": "no"},
            {"feature": "PA-VM", "expires": "Never", "expired": "no"},
            {"feature": "Threat Prevention", "expires": "Never", "expired": "no"}]}},
            system={"system": {"device-dictionary-version": "249-772",
                               "device-dictionary-release-date": "2026/10/23 22:35:51 EDT",
                               "time": "Tue Oct 27 16:46:00 2026"}},
            icd="Version: 14_1275212e43\nTimeBuilt: 2024-07-22T16:20:06PDT")

        # iot6-08: the ONE rule set in the lab carrying the dimension - action allow, `source-hip`
        # naming a device object that RESOLVES. Its point must draw no PAN-IOT-004 row.
        point = EnforcementPoint.objects.get(appliance=tpa, vsys_name="vsys3")
        rule = SecurityRule.objects.create(
            management_station=self.station, enforcement_point=point,
            source_snapshot=Snapshot.objects.filter(enforcement_point=point).first(),
            name="oep-iot6-rule", rule_type="security", action="allow",
            effective_order=1, rule_position=1, config_source=SecurityRule.SOURCE_LOCAL)
        rule.securityrulesourcehips.create(value="oep-iot6-dev-v", position=0)

        for each in Appliance.objects.all():
            normalize_device_identification_state(each)
        for each in EnforcementPoint.objects.all():
            normalize_zones(each)
            normalize_rulebase_device_match(each)
        generate_device_identification_findings(run)
        generate_zone_findings(run)
        generate_rulebase_device_match_findings(run)

    def _appliance(self, serial, hostname, payload, now, *, licences, system, icd):
        # ONE GROUP PER APPLIANCE: `EnforcementPoint` is unique per (appliance_group, vsys_name)
        # and both appliances have a vsys1, so a shared group would make the two firewalls' vsys1
        # the SAME enforcement point.
        group = ApplianceGroup.objects.create(
            management_station=self.station, name=f"g-{hostname}",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=group,
            serial_number=serial, hostname=hostname)
        for source_type, body in (("show_merged_config", payload),
                                  ("request_license_info", licences),
                                  ("show_system_info", system),
                                  ("show_iot_icd_version", icd)):
            Snapshot.objects.create(management_station=self.station, appliance=appliance,
                                    source_type=source_type, collected_at=now, payload=body)
        for vsys in payload["config"]["devices"]["entry"][0]["vsys"]["entry"]:
            point = EnforcementPoint.objects.create(
                management_station=self.station, appliance_group=group, appliance=appliance,
                vsys_name=vsys["@name"], vsys_display_name=vsys["@name"])
            Snapshot.objects.create(management_station=self.station, enforcement_point=point,
                                    source_type="show_merged_config", collected_at=now,
                                    payload=payload)
        return appliance

    @staticmethod
    def table(slug):
        return build_findings_table(DOMAIN_BY_SLUG[slug].spec)

    #: WHAT IDENTIFIES A ROW DIFFERS PER TAB, because the three subjects have three grains: the
    #: appliance, the named zone within a virtual system, and the virtual system itself. A helper
    #: that assumed one of them would silently match the wrong row - or raise on a tab with no
    #: `Appliance` column, which two of these three are.
    KEY_COLUMNS = {
        "iot-security": ("Appliance",),
        "security-zones": ("Object",),
        "rulebase-device-match": ("Firewalls", "Vsys"),
    }

    def row(self, slug, control_id, subject):
        """`subject` is a string for a one-column key, or a tuple matching `KEY_COLUMNS`."""
        table = self.table(slug)
        columns = self.KEY_COLUMNS[slug]
        wanted = (subject,) if isinstance(subject, str) else tuple(subject)
        self.assertEqual(len(columns), len(wanted), f"{slug} is keyed on {columns}")
        indexes = [table.headers.index(c) for c in columns]
        found = [r for r in table.rows
                 if r[1] == control_id and tuple(r[i] for i in indexes) == wanted]
        self.assertEqual(1, len(found), f"{control_id} / {subject}: {len(found)} rows")
        return found[0]

    def cell(self, slug, control_id, subject, heading):
        table = self.table(slug)
        return self.row(slug, control_id, subject)[table.headers.index(heading)]

    def marked(self, slug, control_id, subject):
        table = self.table(slug)
        index = table.rows.index(self.row(slug, control_id, subject))
        return sorted(table.headers[c] for (r, c) in table.implicated if r == index)


class NoHeadingIsSilentlyBroken(DeviceIdTabTestCase):
    """A duplicate header is the silent one: Excel rejects a table that has one, xlsxwriter drops
    the table with a warning, and the sheet comes out as stray cells where the table should be."""

    def test_no_tab_repeats_a_heading(self):
        for slug in SLUGS:
            headers = self.table(slug).headers
            repeated = sorted({h for h in headers if headers.count(h) > 1})
            self.assertEqual([], repeated, f"{slug} repeats {repeated}")

    def test_no_tab_heads_a_column_with_a_raw_field_name(self):
        """`setting_columns` falls back to the raw Django field name where `setting_labels` has no
        entry, which is how most findings tabs still head their derived columns."""
        for slug in SLUGS:
            for heading in self.table(slug).headers:
                self.assertNotIn("_", heading, f"{slug} heads a column `{heading}`")

    def test_every_tab_carries_the_firing_condition_in_the_workbook(self):
        """`tested_columns` DEFAULTS to `('Provenance',)`, which keeps `Fires when` on the live
        page and drops it from the xlsx - so a row's defects split across the two media and the
        workbook shows a contradicting value under the control's name with no stated condition at
        all. All three specs declare `ALL_TESTED_COLUMNS` instead, deliberately."""
        for slug in SLUGS:
            self.assertIn("Fires when (failing condition)", self.table(slug).headers, slug)


class EveryRowPointsAtSomething(DeviceIdTabTestCase):
    """`hidden_fields` is empty on all three specs, which is the only known cause of a findings row
    with no value-at-fault mark anywhere in this repository. `check_every_tested_field_is_presented`
    would NOT catch it: it accepts a field's presence in `hidden_fields` as proof something shows
    it."""

    def test_every_row_on_every_tab_marks_at_least_one_cell(self):
        for slug in SLUGS:
            table = self.table(slug)
            marked_rows = {r for r, _c in table.implicated}
            unmarked = [i for i in range(len(table.rows)) if i not in marked_rows]
            self.assertEqual([], unmarked, f"{slug}: rows with no mark at all: {unmarked}")
            self.assertTrue(table.rows, f"{slug} drew no rows, so this proves nothing")

    def test_the_companion_column_is_what_an_unreported_release_date_marks(self):
        """PAN-IOT-003's graded group cannot fire on an appliance with no release date - its
        applicability clause narrows the row out, and a NULL age matches no threshold anyway - so
        the firing moves to the companion column and the mark has to move with it. The age cell
        reads an em dash on that row and must not be offered as the thing to change."""
        self.assertEqual(["Content release date reported"],
                         self.marked("iot-security", "PAN-IOT-003", "fw-core-tpa-a"))
        self.assertEqual(NONE, self.cell("iot-security", "PAN-IOT-003", "fw-core-tpa-a",
                                         "Content age (days)"))

    def test_the_narrowing_verdict_is_what_a_narrowed_zone_marks(self):
        """And NOT the switch, which reads Yes on these rows: the zone is correctly identified and
        what fires is the narrowing within it."""
        for zone in ("oep-iot6-z3", "oep-iot6-z4", "scratch_zone"):
            self.assertEqual(["Device identification narrowed"],
                             self.marked("security-zones", "PAN-IOT-002", zone), zone)
            self.assertEqual("Yes", self.cell("security-zones", "PAN-IOT-002", zone,
                                              "Enable Device Identification"), zone)


class TheVendorsOwnWordsForAnEmptyList(DeviceIdTabTestCase):
    """THE MOST CONSEQUENTIAL CELL ON THE ZONE TAB. An absent or empty `device-acl` renders
    INCLUDED NETWORKS as `any` and EXCLUDED as `none` in the vendor's own grid - measured by stage
    4 on two platforms - so identification applies to EVERY address in the zone, which is the most
    permissive reading AND the compliant state for this control. `display_value` would print
    `(empty)` for the JSON list and a bare join would print nothing at all."""

    def test_an_empty_include_list_reads_the_vendors_any(self):
        self.assertEqual("Any", self.cell("security-zones", "PAN-IOT-002", "oep-iot6-z2",
                                          "Device-ID address list (include)"))

    def test_an_empty_exclude_list_reads_the_vendors_none(self):
        self.assertEqual("None", self.cell("security-zones", "PAN-IOT-002", "oep-iot6-z3",
                                           "Device-ID address list (exclude)"))

    def test_a_populated_list_prints_its_members_one_per_line(self):
        """Members mixing literals, a CIDR block and an address GROUP name. The report names them
        and makes no claim that they cover the equipment: nothing on the firewall says what a
        group currently contains."""
        self.assertEqual("99.99.98.0/24\n99.99.99.99\nag-agent-desktop-services",
                         self.cell("security-zones", "PAN-IOT-002", "scratch_zone",
                                   "Device-ID address list (include)"))

    def test_the_exclude_only_zone_still_shows_any_on_the_include_side(self):
        """The row that makes the derived boolean worth having: no clause in this query language
        can say "either list has a member", so an exclude-only narrowing would be invisible to a
        clause over the include list - and the include cell still honestly reads `Any`."""
        self.assertEqual("Any", self.cell("security-zones", "PAN-IOT-002", "oep-iot6-z4",
                                          "Device-ID address list (include)"))
        self.assertEqual("203.0.113.128/25",
                         self.cell("security-zones", "PAN-IOT-002", "oep-iot6-z4",
                                   "Device-ID address list (exclude)"))


class TheVerdictHeadingCarriesTheDirection(DeviceIdTabTestCase):
    """`has_no_rule_matching_on_device` defaults True and True FIRES, so the heading is the only
    thing that stops a reader scanning the firing cell as a pass."""

    def test_the_firing_cell_reads_yes_to_a_question_whose_yes_is_the_problem(self):
        point = ("fw-core-tpa-a", "vsys1")
        self.assertEqual("Yes", self.cell("rulebase-device-match", "PAN-IOT-004", point,
                                          "Device dimension absent from the rule set"))
        self.assertEqual(["Device dimension absent from the rule set"],
                         self.marked("rulebase-device-match", "PAN-IOT-004", point))

    def test_the_point_whose_policy_carries_the_dimension_draws_no_row(self):
        """iot6-08: a rule with action allow whose `source-hip` names a device object that
        resolves. The verdict is false and the control correctly produces nothing - which is why
        vsys3 of fw-core-tpa-a is absent from this tab."""
        table = self.table("rulebase-device-match")
        vsys = table.headers.index("Vsys")
        self.assertNotIn("vsys3", [r[vsys] for r in table.rows])
        self.assertTrue(table.rows, "no rows at all, so this proves nothing")

    def test_zero_visible_device_objects_is_a_different_remediation_from_one(self):
        """ZERO means no rule COULD name a device even if somebody wrote one, so the work is to
        define the objects; non-zero means the objects exist and the policy does not use them. Both
        states are on this tab and the column is what separates them."""
        table = self.table("rulebase-device-match")
        vsys = table.headers.index("Vsys")
        firewalls = table.headers.index("Firewalls")
        objects = table.headers.index("Device objects visible here")
        by_point = {(r[firewalls], r[vsys]): r[objects] for r in table.rows}
        self.assertEqual("0", by_point[("pan-fw-111", "vsys1")])
        self.assertEqual("1", by_point[("fw-core-tpa-a", "vsys1")])


class WhatTheRowCannotSay(DeviceIdTabTestCase):
    """Two states this report has no vocabulary for, pinned so that giving it one shows up as a
    test change. Both are recorded in the stage 9 artifact's `unrenderable`."""

    def test_the_zone_provenance_cell_admits_it_cannot_tell_local_from_pushed(self):
        """`integrations.Zone` is a `SyncTrackedModel` and not a `ProvenancedMixin`: it declares no
        `DERIVED_FIELDS` and nothing writes a `FieldProvenance` row for a zone. So the one cell
        that could say whether a zone is configured locally or pushed from a Panorama template
        cannot, and `trust` here IS a template-only zone whose row is indistinguishable from a
        local one. If Zone ever becomes provenanced, this test should fail and be rewritten to
        assert the real answer."""
        cell = self.cell("security-zones", "PAN-IOT-002", "trust", "Provenance")
        self.assertEqual(device_id.ZONE_PROVENANCE, cell)
        self.assertIn("local", cell)
        self.assertIn("template", cell)

    def test_an_excluded_narrowing_question_is_indistinguishable_from_an_answered_one(self):
        """THE SHARPEST ROW ON THIS TAB. On `oep-iot6-z2` identification is OFF, so PAN-IOT-002's
        second record is EXCLUDED by its own applicability clause and the narrowing question was
        never asked of this zone. The row says nothing of the kind: `Device identification
        narrowed` reads No and `Device-ID lists read` reads Yes, which together read as "we checked
        the narrowing and found none" - a reassuring answer to a question that was not put.

        Not fixable in a cell: `build_rows` caches the subject and setting cells PER SUBJECT, so no
        cell can know which CONTROL's row it is being drawn on, and applicability is per record.
        """
        self.assertEqual("No", self.cell("security-zones", "PAN-IOT-002", "oep-iot6-z2",
                                         "Device identification narrowed"))
        self.assertEqual("Yes", self.cell("security-zones", "PAN-IOT-002", "oep-iot6-z2",
                                          "Device-ID lists read"))
        self.assertEqual(["Enable Device Identification"],
                         self.marked("security-zones", "PAN-IOT-002", "oep-iot6-z2"))


class BothContentInstrumentsAreOnTheRow(DeviceIdTabTestCase):
    """They rank this estate in OPPOSITE orders, and showing only one would invert the finding."""

    def test_the_graded_and_ungraded_instruments_disagree_on_the_row(self):
        """fw-core-tpa-a holds content 167 releases BEHIND pan-fw-111 and its classification-data
        build is nearly two years NEWER. A reader shown only the build date would call the stale
        appliance the fresher one."""
        stale_version = self.cell("iot-security", "PAN-IOT-003", "fw-core-tpa-a",
                                  "Device dictionary version")
        stale_build = self.cell("iot-security", "PAN-IOT-003", "fw-core-tpa-a",
                                "Classification data built")
        self.assertEqual("82-406", stale_version)
        self.assertEqual("2026-02-06T13:34:53PST", stale_build)
        current_build = self.cell("iot-security", "PAN-IOT-001", "pan-fw-111",
                                  "Classification data built")
        self.assertEqual("2024-07-22T16:20:06PDT", current_build)

    def test_the_licence_companion_separates_not_entitled_from_never_asked(self):
        """On an appliance holding no licenses the whole reply is `{'licenses': None}`, which is
        exactly what a collector that never issued the command produces. Both lab appliances
        ANSWERED, so the companion reads Yes on both and the subscription column carries the
        finding on its own."""
        for appliance in ("fw-core-tpa-a", "pan-fw-111"):
            self.assertEqual("Yes", self.cell("iot-security", "PAN-IOT-001", appliance,
                                              "License listing answered"), appliance)
            self.assertEqual("No", self.cell("iot-security", "PAN-IOT-001", appliance,
                                             "IoT Security subscription in force"), appliance)

    def test_the_wired_appliance_shows_its_address_and_the_unwired_one_does_not(self):
        """`edge_service_address` is the one PAYLOAD KEY on this tab and gets NO value reader: a
        reader would discard the field's own provenance row, and whether the key was absent,
        explicitly blank or template-supplied is half of what this control is about. So the cell
        keeps `display_value`'s own word for the empty string."""
        self.assertEqual("edge-oep-iot6.invalid",
                         self.cell("iot-security", "PAN-IOT-001", "fw-core-tpa-a",
                                   "Edge service address"))
        self.assertEqual("(empty)", self.cell("iot-security", "PAN-IOT-001", "pan-fw-111",
                                              "Edge service address"))
        self.assertIn("Edge service address",
                      self.marked("iot-security", "PAN-IOT-001", "pan-fw-111"))


class TheExplorerPagesRunOverRealRows(DeviceIdTabTestCase):
    """`test_configuration_queries`' squareness check has fixtures for one model, so a new page's
    `row` lambda would otherwise ship having never been called on a real object. Three new pages,
    three lambdas, and each must return exactly as many cells as its page has columns."""

    def test_every_new_results_spec_row_is_square_on_real_objects(self):
        for slug in ("iot-security", "zones", "rulebase-device-match"):
            spec = config_results.RESULTS[slug]
            objects = list(spec.base_queryset())
            self.assertTrue(objects, f"{slug}: no rows, so this proves nothing")
            for obj in objects:
                cells = spec.row(obj)
                self.assertEqual(len(spec.columns), len(cells),
                                 f"{slug}: {len(cells)} cells for {len(spec.columns)} columns")

    def test_every_query_field_on_the_new_pages_is_registered_in_the_compiler(self):
        """A heading mapped to an unregistered field points the "build a query from these rows"
        button at a lookup that refuses itself or silently matches nothing."""
        from assessments.search.registry import MODEL_REGISTRY
        for slug, model in (("iot-security", "integrations.DeviceIdentificationState"),
                            ("zones", "integrations.Zone"),
                            ("rulebase-device-match",
                             "integrations.RulebaseDeviceMatchVerdict")):
            spec = config_results.RESULTS[slug]
            registered = set(MODEL_REGISTRY[model]["field_operators"])
            for heading, field in spec.query_fields.items():
                self.assertIn(field, registered, f"{slug}: {heading} -> {field}")
                self.assertIn(heading, spec.columns, f"{slug}: {heading} is not a column")

    def test_the_zone_page_offers_the_columns_two_later_domains_need(self):
        """The `zones` rail item and page are SHARED: `user-id` (PAN-UID) and
        `zone-dos-protection` (PAN-ZON) both have controls over this model and both run after this
        domain. Their columns are here already so neither has to move the rail item."""
        spec = config_results.RESULTS["zones"]
        self.assertIn("User identification on", spec.query_fields)
        self.assertIn("Zone protection unresolved", spec.query_fields)
        # The naive reading is deliberately NOT queryable - a clause on the profile NAME passes
        # exactly the dangling-reference case the verdict column exists to catch.
        self.assertIn("Zone protection profile", spec.columns)
        self.assertNotIn("Zone protection profile", spec.query_fields)
