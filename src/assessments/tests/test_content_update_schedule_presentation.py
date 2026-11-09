"""The `Dynamic Update Schedule` tab, its rail item and its results page, pinned.
Stage 9, `updates`, 2026-11-03.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover a tab generically: every
assertion here is a JUDGMENT this run made that nothing else in the repository states, and a new
tab nothing asserts on is one the next refactor can break in silence.

  - THE COLUMN ORDER, read off the built table rather than derived from stage 5. Nothing gates it.
    `tested_fields` takes the baseline's clauses in clause order and then every OTHER active
    query's clauses in ALPHABETICAL ORDER OF THE QUERY'S NAME, and `setting_columns` walks the
    controls `order_by("control_id")` - so renaming a shipped calibration query silently reorders
    a customer-facing column and `auto_setting_columns` is all-or-nothing, so no sheet option can
    correct it. THIS TAB IS THE ONE THAT REALLY DEPENDS ON IT: three of its four controls clause
    on a RECURRENCE and an ACTION, the action arrives from a calibration query, and that
    calibration sorts among three or four others of the same control. It comes out matching stage
    5's clause order - but by a hair, because in each case the action-bearing calibration's name
    begins "downloads without installing" / "is downloaded without being installed" and sorts
    FIRST among its siblings. Rename it to "Downloads but never installs" and the two columns
    swap with nothing failing but this test.

  - NO `value_reader` ANYWHERE ON THIS TAB, AND THE ATTRIBUTE'S ABSENCE ASSERTED. All nine clause
    fields are `CharField`s with `choices=None`, so `get_<field>_display()` DOES NOT EXIST and the
    call would raise `AttributeError` at TEMPLATE RENDER - past `django check` and past all three
    cross-domain gates (P462). This is the half of the rule that ships a 500 rather than a wrong
    word, and the guard is against a later run copying the reader pattern across from a domain
    whose fields DO carry `choices`.

  - THE VALUE CELLS PRINT THE DEVICE'S OWN TOKENS, which is a decision and not an omission.
    `configuration_results._update_token` carries the reasoning; the short form is that the vendor
    documents no word for ANY recurrence value, and translating the two actions it DOES name would
    print one value two ways on one row - because `render_node`, which writes the `Fires when`
    cell, consults `setting_labels` nowhere. That mismatch is ASSERTED here rather than left
    implicit: the conditions really do read in raw Django field names while the headings beside
    them read in English, and a future run that adds a value map must confront this test.

  - THE PROVENANCE CELL (P451), AND WHICH FIX ACTUALLY DOES IT. Measured on built rows both ways.
    The normalizer hands `write_node_row` a provenance list naming only the two threshold fields,
    neither of which any control clauses on, and writes no `__entry__` row - so with no sheet-level
    `provenance_cell` every row printed "Not recorded" once per tested field, which means "nothing
    tracks that field" about a value this assessment derives on purpose. Declaring the fields in
    `DERIVED_FIELDS` does NOT fix it, though it looks as though it should: `provenance_of` does
    synthesise a DERIVED row, and `remediation_accessor` then discards it deliberately and falls
    back to an `__entry__` row that is never written. So this tab is the exact disproof condition a
    standing note in `reference/consumer-repo-notes.md` asks for, and it does not disprove it.

  - THE TWO ROWS WHOSE STATED CONDITION THEIR OWN SUBJECT DOES NOT MEET, pinned by appliance and
    control. `fires_when` renders the BASELINE alone and on PAN-UPD-001 and PAN-UPD-002 the
    baseline is the CADENCE half while the ACTION half is carried by calibration queries. These
    two rows are not a defect this stage may fix - `fires_when` is shared machinery - so they are
    pinned as KNOWN, with the property that identifies them: their `Matched queries` does not name
    the Baseline. If that stops being true, either the defect was fixed or a new row joined them,
    and both are worth a failing test.

  - PAN-UPD-005'S INVERTED SIGN, which is the one row shape in the domain that could have gone
    wrong here and did not. Both its stage 5 records are `finding_when_clauses_fail`, and stage 8
    compiled that INTO the baseline as an `or` group of the failing states - so its `Fires when`
    IS the firing condition. Asserted because a future recompilation that stated the PASSING
    condition instead would print the exact opposite of what the row reports, and nothing else
    would notice.

  - the explorer `row` lambda over real rows, which the shipped check cannot read, and every
    `query_fields` entry against the search registry.
"""
from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets import objects as _objects
from assessments.artifacts.sheets.findings import ALL_TESTED_COLUMNS, build_findings_table
from assessments.configuration_navigation import CONFIG_OBJECTS
from assessments.search.content_update_schedule import compiler as schedule_compiler
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ContentUpdateSchedule, EnforcementNode, EnforcementPoint,
    ManagementStation, Snapshot)

#: The four controls that HAVE a catalog entry. PAN-UPD-003 is discharged `engineer_answers` by
#: stage 5 and PAN-UPD-006 `not_in_configuration` plus `engineer_answers`; neither is in
#: `seed.json` at all, so `seed_controls` would raise on either.
#:
#: THESE ARE SEEDED FOR THE TAB TESTS and the reason is not incidental: a derived settings column
#: exists only because some control's query clauses on the field, so `build_findings_table` over
#: an unseeded catalog draws NO setting columns and an order assertion over that table passes
#: vacuously.
PAN_UPD = ("PAN-UPD-001", "PAN-UPD-002", "PAN-UPD-004", "PAN-UPD-005")

#: The nine derived settings columns IN THE ORDER THE BUILT TABLE EMITS THEM, which is also stage
#: 5's clause order and is NOT guaranteed by anything but this test. Read off
#: `FindingsTable.headers` on 2026-11-03, not derived from the artifact.
SETTING_COLUMNS = (
    "Antivirus recurrence",
    "Antivirus action",
    "Applications and Threats recurrence",
    "Applications and Threats action",
    "WildFire recurrence",
    "GlobalProtect data file recurrence",
    "GlobalProtect data file action",
    "Clientless VPN recurrence",
    "Clientless VPN action",
)

#: The clause field each of those columns presents, in the same order - so a heading that drifts
#: off its field fails rather than merely reading oddly.
SETTING_FIELDS = (
    "av_recurrence", "av_action", "threats_recurrence", "threats_action", "wildfire_recurrence",
    "gp_datafile_recurrence", "gp_datafile_action", "gp_clientless_vpn_recurrence",
    "gp_clientless_vpn_action",
)


class ContentUpdateScheduleRailTests(TestCase):
    """The rail item, and the ways one can be wrong without a test name saying so."""

    def item(self):
        (item,) = [o for o in CONFIG_OBJECTS if o.slug == "content-update-schedule"]
        return item

    def test_the_model_has_exactly_one_rail_item_and_it_claims_device(self):
        label = "integrations.ContentUpdateSchedule"
        items = [o for o in CONFIG_OBJECTS if o.search_model == label]
        self.assertEqual(1, len(items))
        self.assertEqual("content-update-schedule", items[0].slug)
        self.assertEqual("Device", items[0].category)

    def test_the_rail_item_names_the_vendor_path_established_in_the_corpus(self):
        """`Device > Dynamic Updates` is verbatim in Help 11.2 p.950 (`probe.corpus --id c84560`).
        Written down because several successive runs corrected a path taken from memory."""
        self.assertEqual("Device > Dynamic Updates", self.item().where)

    def test_it_shares_the_vendor_screen_with_installed_content_and_is_named_differently(self):
        """ONE SCREEN, TWO SUBJECTS, and the names must not collide. `content-streams` took
        "Installed Content" deliberately so that this item could take the schedule's own name -
        its entry in `configuration_navigation` says so. A later run renaming either to the
        screen's own `Dynamic Updates` would leave the other with no name to take."""
        (streams,) = [o for o in CONFIG_OBJECTS if o.slug == "content-streams"]
        self.assertEqual(streams.where, self.item().where)
        self.assertNotEqual(streams.label, self.item().label)
        self.assertEqual("Dynamic Update Schedule", self.item().label)
        self.assertEqual("Installed Content", streams.label)

    def test_the_icon_is_one_of_the_nineteen_vendored_files(self):
        """`ConfigObject.icon` IS NOT VALIDATED and a name that is not there raises
        `FileNotFoundError` at TEMPLATE RENDER - and because the rail renders on every explorer
        page it takes out every explorer test, with not one test name mentioning an icon.
        `globalprotect-portal` picked `lock`, which reads as obviously present and is not. The
        nineteen live in the OptivEdge HOST repo, not in this one."""
        vendored = {
            "book-marked", "chevron-right", "circle-question-mark", "clipboard-check",
            "download", "eye", "flag", "layout-dashboard", "list-checks", "monitor", "plus",
            "refresh-cw", "server", "settings", "shield", "trash-2", "triangle-alert",
            "wand-sparkles", "x"}
        self.assertIn(self.item().icon, vendored)

    def test_the_prefix_no_longer_waits_for_presentation(self):
        """Clearing it is part of this stage's job rather than a side effect: an exemption that
        survives the work it was waiting for is a permanent hole. And note what this does NOT
        claim - `test_configuration_links` was already green WITH the exemption, because it never
        consults `is_active`. The claim is that it is green WITHOUT it."""
        self.assertNotIn("PAN-UPD", cr.AWAITING_PRESENTATION)


class ContentUpdateScheduleDomainTests(TestCase):
    def test_the_domain_is_registered_and_derives_its_category_from_the_rail(self):
        """`category=''` is right for a subject an assessor opens a vendor screen to read:
        deriving it means the workbook cannot disagree with the app about where it lives."""
        domain = DOMAIN_BY_SLUG["content-update-schedule"]
        self.assertEqual("", domain.spec.category)
        self.assertEqual("Dynamic Update Schedule", domain.spec.sheet_title)

    def test_the_tab_title_fits_excels_sheet_name_cap(self):
        """31 characters, silently truncated past it - and `probe.surface_for` prints the
        UNtruncated title, so the tool and the workbook disagree and the tool looks right."""
        self.assertLessEqual(len(DOMAIN_BY_SLUG["content-update-schedule"].spec.sheet_title), 31)

    def test_one_tab_carries_all_four_controls(self):
        """The point of the shape: four controls, one model, one tab. A second tab for any of
        them would be a tab per control, which the presentation layer was refactored away from."""
        spec = _objects.SPEC_BY_TYPE["content_update_schedule"]
        self.assertEqual(("content_update_schedule",), spec.control_types)
        self.assertEqual((), spec.control_ids, "no control is singled out onto its own sheet")

    def test_hidden_fields_is_empty(self):
        """`check_every_tested_field_is_presented` counts a field as presented if `hidden_fields`
        carries it, so a non-empty tuple is a CLAIM accepted as proof - and the only known cause
        of a findings row that marks nothing as the thing to fix (P409)."""
        self.assertEqual((), _objects.SPEC_BY_TYPE["content_update_schedule"].hidden_fields)

    def test_the_sheet_carries_both_tested_columns(self):
        """The default is `("Provenance",)`, which drops `Fires when` from the WORKBOOK while the
        live page keeps it, so the two surfaces disagree about which cell a reader meets (P427)."""
        spec = _objects.SPEC_BY_TYPE["content_update_schedule"]
        self.assertEqual(ALL_TESTED_COLUMNS, spec.tested_columns)

    def test_no_clause_field_has_choices_so_no_reader_may_call_a_display_method(self):
        """P462's half that ships a 500 rather than a wrong word. `get_<field>_display()` exists
        ONLY on a field declaring `choices`; on these nine the call raises `AttributeError` at
        template render, past `django check` and past all three cross-domain gates."""
        spec = _objects.SPEC_BY_TYPE["content_update_schedule"]
        self.assertEqual({}, spec.value_readers, "a reader here would have to call getattr only")
        for field in SETTING_FIELDS:
            with self.subTest(field=field):
                self.assertIsNone(ContentUpdateSchedule._meta.get_field(field).choices)
                self.assertFalse(hasattr(ContentUpdateSchedule, f"get_{field}_display"))
                self.assertIn(field, ContentUpdateSchedule.DERIVED_FIELDS)

    def test_every_heading_is_english_and_none_is_a_raw_field_name(self):
        """A field with no `setting_labels` entry heads a customer-facing column with its raw
        Django name - `setting_labels` falls back to the field name - so declaring a column
        without a label IS choosing to show a database field name to a customer."""
        labels = _objects.SPEC_BY_TYPE["content_update_schedule"].setting_labels
        self.assertEqual(set(SETTING_FIELDS), set(labels))
        for field, heading in labels.items():
            with self.subTest(field=field):
                self.assertNotEqual(field, heading)
                self.assertNotIn("_", heading)


class ContentUpdateScheduleEstate(TestCase):
    """One appliance per content-schedule shape this domain reports on, transcribed from the
    `updates` stage 6 artifact's own `verified.read_back` - so the rows here are the measured
    estate's and not invented ones.

    The four are: tpa-a (antivirus daily and installing, no Applications-and-Threats node at all),
    tpa-b (no antivirus node, Applications and Threats weekly download-only), fw-201 (antivirus
    HOURLY and download-only, which is the row whose stated condition it does not meet) and
    fw-111 (antivirus weekly, WildFire every minute).
    """

    #: THE TPA PAIR IS A REAL HA PAIR HERE AND THE COMMITTED SEEDER'S ESTATE IS NOT, which is why
    #: this fixture is hand-built rather than taken from `print_findings_table`.
    #: `_estate.build_base_estate` gives every appliance its own standalone group and always sets
    #: `EnforcementPoint.appliance`, so `ha_role` reads "Standalone" on all four rows and
    #: `flows.get_in_scope_appliances` returns one appliance per point (P460). Stage 6 records
    #: 013201001475 and 013201001085 as an HA pair with the first ACTIVE, so that is what is built:
    #: ONE group of type `ha_pair`, ONE enforcement point with a NULL `appliance`, and TWO
    #: `EnforcementNode` rows - which is the arm that makes the flow walk the nodes and return both
    #: peers. The two standalone appliances keep the other arm, so both are exercised in one table.
    @classmethod
    def build_estate(cls):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_FIREWALL, hostname="fw.upd")
        appliances = {}
        snapshots = {}

        def snapshot_for(appliance):
            # `source_snapshot` is NOT NULL on this model, so no row can be built without one.
            return Snapshot.objects.create(
                management_station=station, appliance=appliance,
                source_type="show_merged_config", collected_at=timezone.now(), payload={})

        pair = ApplianceGroup.objects.create(
            management_station=station, name="g-upd-tpa",
            group_type=ApplianceGroup.TYPE_HA_PAIR)
        for serial, hostname in (("013201001475", "fw-core-tpa-a"),
                                 ("013201001085", "fw-core-tpa-b")):
            appliances[hostname] = Appliance.objects.create(
                management_station=station, appliance_group=pair,
                serial_number=serial, hostname=hostname)
            snapshots[hostname] = snapshot_for(appliances[hostname])
        pair.active_appliance = appliances["fw-core-tpa-a"]
        pair.save(update_fields=["active_appliance"])
        # ONE point for the pair's vsys, with NO appliance of its own: a vsys on an HA pair spans
        # both peers, and `EnforcementPoint` is unique on (group, vsys_name) so it could not be
        # modelled per peer even if that were right.
        pair_point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=pair, appliance=None,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True)
        for hostname in ("fw-core-tpa-a", "fw-core-tpa-b"):
            EnforcementNode.objects.create(management_station=station,
                                           enforcement_point=pair_point,
                                           appliance=appliances[hostname])

        for serial, hostname in (("691665AC334B458", "pan-fw-201"),
                                 ("6A9C0A9904E7D6E", "pan-fw-111")):
            group = ApplianceGroup.objects.create(
                management_station=station, name=f"g-{hostname}",
                group_type=ApplianceGroup.TYPE_STANDALONE)
            appliances[hostname] = Appliance.objects.create(
                management_station=station, appliance_group=group,
                serial_number=serial, hostname=hostname)
            point = EnforcementPoint.objects.create(
                management_station=station, appliance_group=group,
                appliance=appliances[hostname],
                vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True)
            EnforcementNode.objects.create(management_station=station, enforcement_point=point,
                                           appliance=appliances[hostname])
            snapshots[hostname] = snapshot_for(appliances[hostname])
        return station, appliances, snapshots

    #: Exactly what the committed normalisers produced from stage 6's `read_back`, checked column
    #: by column against the artifact before any row here was read. `none` is the token for a
    #: branch that is absent or explicitly none; the EMPTY STRING would mean nobody collected the
    #: management-plane node at all, and no appliance in the measured estate holds it.
    SCHEDULES = {
        "fw-core-tpa-a": dict(
            av_recurrence="daily", av_action="download-and-install",
            threats_recurrence="none", threats_action="none",
            wildfire_recurrence="real-time", wildfire_action="none",
            gp_datafile_recurrence="weekly", gp_datafile_action="download-and-install",
            gp_clientless_vpn_recurrence="daily",
            gp_clientless_vpn_action="download-and-install"),
        "fw-core-tpa-b": dict(
            av_recurrence="none", av_action="none",
            threats_recurrence="weekly", threats_action="download-only",
            wildfire_recurrence="none", wildfire_action="none",
            gp_datafile_recurrence="none", gp_datafile_action="none",
            gp_clientless_vpn_recurrence="none", gp_clientless_vpn_action="none"),
        "pan-fw-201": dict(
            av_recurrence="hourly", av_action="download-only",
            threats_recurrence="daily", threats_action="download-only",
            wildfire_recurrence="every-15-mins", wildfire_action="download-and-install",
            gp_datafile_recurrence="daily", gp_datafile_action="none",
            gp_clientless_vpn_recurrence="weekly", gp_clientless_vpn_action="none"),
        "pan-fw-111": dict(
            av_recurrence="weekly", av_action="download-and-install",
            threats_recurrence="hourly", threats_action="download-and-install",
            wildfire_recurrence="every-min", wildfire_action="download-and-install",
            gp_datafile_recurrence="hourly", gp_datafile_action="download-and-install",
            gp_clientless_vpn_recurrence="hourly",
            gp_clientless_vpn_action="download-and-install"),
    }

    @classmethod
    def build_rows(cls, station, appliances, snapshots):
        rows = {}
        for hostname, columns in cls.SCHEDULES.items():
            rows[hostname] = ContentUpdateSchedule.objects.create(
                management_station=station, appliance=appliances[hostname],
                appliance_group=appliances[hostname].appliance_group,
                source_snapshot=snapshots[hostname],
                update_schedule_collected=True, **columns)
        return rows

    def setUp(self):
        self.station, self.appliances, self.snapshots = self.build_estate()
        self.rows = self.build_rows(self.station, self.appliances, self.snapshots)


class ContentUpdateScheduleResultsTests(ContentUpdateScheduleEstate):
    """The explorer page: its `row` lambda over real rows, and its query fields against the
    registry. The shipped squareness check cannot call the lambda."""

    def row_for(self, obj):
        spec = cr.RESULTS["content-update-schedule"]
        return dict(zip(spec.columns, spec.row(obj)))

    def test_every_query_field_names_a_field_the_compiler_registers(self):
        """Stored, searchable and registered are three different things, and the repo's rule is
        that only a column a control asks for is registered. A heading mapped to an unregistered
        field aims the "build a query from these rows" button at a lookup that refuses itself."""
        registry = schedule_compiler.FIELD_OPERATOR_REGISTRY
        for heading, field in cr.RESULTS["content-update-schedule"].query_fields.items():
            with self.subTest(heading=heading):
                self.assertIn(field, registry)

    def test_wildfire_action_is_a_column_and_deliberately_not_queryable(self):
        """PAN-UPD-004 clauses on the WildFire RECURRENCE alone, so the compiler does not register
        the action and no findings column is derived for it. It is shown here because a reader
        comparing the five content types down one row would otherwise meet a hole."""
        spec = cr.RESULTS["content-update-schedule"]
        self.assertIn("WildFire action", spec.columns)
        self.assertNotIn("WildFire action", spec.query_fields)
        self.assertNotIn("wildfire_action", schedule_compiler.FIELD_OPERATOR_REGISTRY)

    def test_the_row_prints_the_devices_own_tokens(self):
        """THE DECISION NOT TO TRANSLATE, pinned. The vendor documents `Download Only` and
        `Download and Install` for the action and NO word for any recurrence value, and
        translating one and not the other would name a value two ways on one row - the condition
        cell beside it is written by `render_node`, which consults no label map."""
        cells = self.row_for(self.rows["pan-fw-201"])
        self.assertEqual("hourly", cells["Antivirus recurrence"])
        self.assertEqual("download-only", cells["Antivirus action"])
        self.assertEqual("every-15-mins", cells["WildFire recurrence"])
        self.assertEqual("none", cells["GlobalProtect data file action"])

    def test_an_uncollected_node_says_so_and_never_reads_as_none(self):
        """`none` is an absence the firewall REPORTED; the empty string is an absence NOBODY
        collected. Reporting them as the same thing would tell a customer their firewall is
        misconfigured on the strength of a reply nobody received. No appliance in the measured
        estate holds the empty string, so this is the branch the estate does not exercise."""
        row = self.rows["pan-fw-111"]
        row.av_recurrence = ""
        row.update_schedule_collected = False
        row.save(update_fields=["av_recurrence", "update_schedule_collected"])
        cells = self.row_for(row)
        self.assertEqual("not read", cells["Antivirus recurrence"])
        self.assertEqual("no", cells["Schedule read"])
        self.assertNotEqual("none", cells["Antivirus recurrence"])


class ContentUpdateScheduleTabTests(ContentUpdateScheduleEstate):
    """The findings tab over the measured estate.

    `build_findings_table` LOADS findings rather than computing them, so the generator has to have
    run or every row assertion here passes vacuously over an empty table - which is how the first
    draft of this file was green on four of its claims.
    """

    @classmethod
    def setUpTestData(cls):
        seed_controls(list(PAN_UPD))

    def setUp(self):
        super().setUp()
        from assessments.finding_run import regenerate_findings
        self.result = regenerate_findings()

    def table(self):
        return build_findings_table(_objects.SPEC_BY_TYPE["content_update_schedule"])

    def test_the_estate_produces_the_eleven_findings_stage_8_measured(self):
        """The reconciliation this tab rests on, at row grain: four appliances, four controls,
        eleven findings - and stage 8's own `actual.matched_query_names` agrees on every one.
        Asserted first because every other assertion in this class is vacuous without it."""
        table = self.table()
        self.assertEqual(11, len(table.rows))
        self.assertEqual(0, self.result.skipped_queries,
                         "a query that will not compile contributes no finding and reads exactly "
                         "like a clean control")

    def cell(self, table, row, heading):
        return row[table.headers.index(heading)]

    def test_the_setting_columns_come_out_in_stage_5s_clause_order(self):
        """THE ONE STRUCTURAL PROPERTY WITH NO GATE BEHIND IT. Across controls the order is
        `order_by("control_id")`; within a control it is the baseline's clauses in clause order
        and then every other active query's clauses ALPHABETICALLY BY THE QUERY'S NAME. Three of
        these four controls clause on a recurrence and an action, and the action arrives from a
        calibration - so this passing is a fact about those query names and not about stage 5."""
        table = self.table()
        start = table.headers.index("Provenance") + 1
        end = table.headers.index("Matched queries")
        self.assertEqual(list(SETTING_COLUMNS), list(table.headers[start:end]))

    def test_the_template_column_is_dropped_rather_than_shipped_blank(self):
        """`_default_template_cell` names the pushed template PER TESTED FIELD, and all nine here
        are computed from which branch element exists, so none can carry TEMPLATE provenance.
        Built with the default it was blank on every row, which reads as a gap in the collection
        rather than as a column that does not apply."""
        self.assertNotIn("Template", self.table().headers)
        self.assertEqual((), _objects.SPEC_BY_TYPE["content_update_schedule"].source_columns)

    def test_the_subject_block_leads_with_the_appliance_and_whether_anybody_looked(self):
        """Verdict grain: one row per appliance and NO object name, because the node is a
        singleton under `deviceconfig/system`. `Schedule read` is the column that lets every
        token cell on the row be read literally."""
        table = self.table()
        self.assertEqual(["Appliance", "HA role", "Schedule read"],
                         list(table.headers[table.headers.index("Appliance"):
                                            table.headers.index("Appliance") + 3]))

    def test_every_row_carries_a_marked_cell(self):
        """A findings row that marks nothing as the thing to fix is the failure `hidden_fields`
        causes, and this tab declares none. Asserted over every row rather than one."""
        table = self.table()
        self.assertTrue(table.rows)
        marked = {r for (r, _c) in table.implicated}
        self.assertEqual(set(range(len(table.rows))), marked)

    def test_every_marked_cell_is_a_setting_column_this_tab_heads(self):
        """A mark on `Severity` or `Appliance` would be the shape where "the most reassuring cell
        on the row was the finding"."""
        table = self.table()
        for row_index, col in table.implicated:
            with self.subTest(row=row_index, col=col):
                self.assertIn(table.headers[col], SETTING_COLUMNS)

    def test_the_provenance_cell_says_derived_and_never_not_recorded(self):
        """P451. "Not recorded" means "nothing tracks that field", and these nine are computed
        from WHICH BRANCH ELEMENT EXISTS - derived deliberately and by a documented rule. The
        sheet's `provenance_cell` is what answers it: declaring the fields in `DERIVED_FIELDS`
        does not, because `remediation_accessor` discards the synthesised DERIVED row and falls
        back to an `__entry__` row this normalizer never writes."""
        table = self.table()
        for row in table.rows:
            self.assertEqual("Derived", self.cell(table, row, "Provenance"))

    def test_pan_upd_005s_inverted_sign_states_the_FIRING_condition(self):
        """Both its stage 5 records are `finding_when_clauses_fail` - the only ones in the domain -
        and stage 8 compiled that into the baseline as an `or` group of the FAILING states. So the
        cell reads as the condition that fires. A recompilation stating the PASSING condition
        would print the exact opposite of what the row reports and nothing else would notice."""
        table = self.table()
        rows = [r for r in table.rows if self.cell(table, r, "Control ID") == "PAN-UPD-005"]
        self.assertTrue(rows)
        for row in rows:
            condition = self.cell(table, row, "Fires when (failing condition)")
            self.assertIn(" or ", condition)
            self.assertIn("gp_datafile_recurrence = none", condition)

    def test_the_two_rows_whose_condition_their_subject_does_not_meet_are_the_calibration_rows(self):
        """KNOWN AND NOT FIXABLE HERE: `fires_when` renders the BASELINE alone, and on PAN-UPD-001
        and PAN-UPD-002 the baseline is the CADENCE half while the ACTION half rides on
        calibration queries. pan-fw-201 runs its antivirus HOURLY and only downloads, so the row
        prints a condition requiring the recurrence not to be hourly beside a correctly marked
        action cell. `fires_when` is shared machinery and this stage may not change it.

        The invariant pinned is the one that IDENTIFIES such a row: its `Matched queries` does not
        name the Baseline. If this fails, either the defect was fixed or a new row joined them."""
        table = self.table()
        offenders = []
        for row in table.rows:
            if "Baseline" not in self.cell(table, row, "Matched queries").split("\n"):
                offenders.append((self.cell(table, row, "Control ID"),
                                  self.cell(table, row, "Appliance")))
        self.assertEqual([("PAN-UPD-001", "pan-fw-201"), ("PAN-UPD-002", "pan-fw-201")],
                         sorted(offenders))

    def test_a_basis_cell_can_name_two_queries_of_two_columns_at_one_severity(self):
        """P450's two-column shape, on a built row. PAN-UPD-002 on tpa-b matches a RECURRENCE
        calibration and an ACTION calibration at once - two different columns of one control - so
        `severity_basis` names both. Both carry the control's OWN default, so the grade is right
        and only the word "Adjusted" is false; the LOWER-grade variant of the defect is not
        reachable in this domain, because the only control with a severity spread grades on a
        single column whose five states are mutually exclusive."""
        table = self.table()
        (row,) = [r for r in table.rows
                  if self.cell(table, r, "Control ID") == "PAN-UPD-002"
                  and self.cell(table, r, "Appliance") == "fw-core-tpa-b"]
        basis = self.cell(table, row, "Severity basis").split("\n")
        self.assertEqual("Adjusted to High by:", basis[0])
        self.assertEqual(2, len(basis[1:]), "two calibrations, two columns, one row")
        self.assertEqual("High", self.cell(table, row, "Severity"))
        marked = sorted(table.headers[c] for (r, c) in table.implicated
                        if r == table.rows.index(row))
        self.assertEqual(["Applications and Threats action",
                          "Applications and Threats recurrence"], marked)

    def test_the_two_genuine_severity_moves_are_wildfires_and_they_are_the_only_ones(self):
        """17 of this domain's 19 calibrations announce an adjustment that moved nothing. Only
        PAN-UPD-004's fifteen-minute and one-minute cadences grade below the control's `high`."""
        table = self.table()
        graded = {(self.cell(table, r, "Control ID"), self.cell(table, r, "Appliance")):
                  self.cell(table, r, "Severity") for r in table.rows}
        self.assertEqual("Medium", graded[("PAN-UPD-004", "pan-fw-201")])
        self.assertEqual("Low", graded[("PAN-UPD-004", "pan-fw-111")])
        self.assertEqual("High", graded[("PAN-UPD-004", "fw-core-tpa-b")])

    def test_the_stated_condition_reads_in_raw_field_names_while_the_headings_do_not(self):
        """MEASURED, AND THE REASON THE VALUE CELLS ARE NOT TRANSLATED EITHER. `render_node`
        consults `setting_labels` nowhere, so the condition says `av_recurrence` under a heading
        reading "Antivirus recurrence". Labeling every heading does NOT make the tab clean, and
        a run reporting one off a heading grep would be reporting half the row."""
        table = self.table()
        conditions = {self.cell(table, r, "Fires when (failing condition)") for r in table.rows}
        self.assertTrue(conditions)
        for condition in conditions:
            self.assertTrue(any(field in condition for field in SETTING_FIELDS),
                            f"expected a raw field name in {condition!r}")
        for heading in SETTING_COLUMNS:
            self.assertNotIn(heading, " | ".join(conditions))

    def test_an_ha_pair_draws_two_rows_and_nothing_deduplicates_them(self):
        """Stage 5's `identity.one_row_per` says so and cites the vendor - Threat Prevention guide
        p.35 STEP 3 item 5, "the update schedule does not sync across peers; you must manually
        configure the schedule on both peers" - so two rows for one pair are two INDEPENDENT
        configurations and a pair showing one row is a pair half covered. That makes this subject
        the exception to the pipeline's standing "deduplicate a device-wide subject on the HA
        pair" remedy, which exists because `deviceconfig`'s non-HA fields DO synchronise. This one
        does not, and the two rows here hold genuinely different values."""
        table = self.table()
        pair = [r for r in table.rows
                if self.cell(table, r, "Appliance") in ("fw-core-tpa-a", "fw-core-tpa-b")
                and self.cell(table, r, "Control ID") == "PAN-UPD-002"]
        self.assertEqual(2, len(pair))
        self.assertNotEqual(self.cell(table, pair[0], "Applications and Threats recurrence"),
                            self.cell(table, pair[1], "Applications and Threats recurrence"))

    def test_the_pairs_rows_name_their_ha_role_and_the_standalones_do_not(self):
        """The HA role column is what stops two rows for one pair reading as a duplicate, and it
        is the cell the committed seeder's estate cannot produce: `build_base_estate` gives every
        appliance its own standalone group, so a run measuring HA through that estate alone sees
        "Standalone" on all four rows and could conclude stage 5 was wrong about the count. This
        fixture builds the pair the way stage 6 records it."""
        table = self.table()
        roles = {self.cell(table, r, "Appliance"): self.cell(table, r, "HA role")
                 for r in table.rows}
        self.assertEqual("Active", roles["fw-core-tpa-a"])
        self.assertEqual("Passive", roles["fw-core-tpa-b"])
        self.assertEqual("Standalone", roles["pan-fw-201"])
        self.assertEqual("Standalone", roles["pan-fw-111"])
