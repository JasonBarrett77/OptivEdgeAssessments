"""The three platform-lifecycle findings tabs, three rail items and three results pages, pinned.
Stage 9, `platform-lifecycle`, 2026-11-02.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover the tabs generically:
every assertion here is a JUDGMENT this run made that nothing else in the repository states,
and a new tab nothing asserts on is one the next refactor can break silently.

  - THE FOUR `choices` LABELS, EVERY MEMBER OF EVERY VOCABULARY. This is the first domain where
    P457 bites in full: all four clause fields are `CharField`s WITH `choices`, and the cell goes
    `read_value` -> `getattr` -> `display_value`, whose value branch ends in `str(value)` while
    `get_<field>_display()` is called NOWHERE in the sheets layer. Without the readers a customer
    reads `stream_never_installed`, `absent_from_inventory` and `on_with_thresholds_no_route`
    under headings written in English. Twenty-two labels are pinned here so the claim cannot
    drift back, which is what `globalprotect-portal` did for its three.

  - AND THE OTHER HALF OF THAT RULE, which ships a 500 rather than a wrong word: the three
    nullable alarm switches are `BooleanField`s with `choices=None`, so `get_<field>_display()`
    DOES NOT EXIST on them and the call would raise `AttributeError` at TEMPLATE RENDER - past
    `django check` and past all three cross-domain gates (P462). The test asserts the attribute's
    absence, which is the guard against a later run copying the reader pattern across.

  - THE PROVENANCE CELL ON ALL THREE TABS (P451), AND WHICH OF THE TWO FIXES ACTUALLY DOES IT.
    Measured on built rows three ways. With neither the readers nor the sheet's own
    `provenance_cell`, every tab prints "Not recorded" for every tested field - which means
    "nothing tracks this field" and reads to a customer as a gap in the collection, about a
    verdict this assessment computed. With the READERS alone it already reads "Derived", because
    a `value_reader` makes `tested_fields` return `stored=False` and `provenance_cells` answers
    with the DERIVED label before it looks at a row. So the standing "one line per sheet fixes
    it" remedy was not needed here; the line is kept because the per-field default prints
    `Derived\nDerived` on the Licenses tab, for a subject that answers once.

  - THE COLUMN ORDER, per tab, read off the built table rather than derived. Nothing gates it:
    `tested_fields` takes the baseline's clauses in clause order and then every other active
    query's in ALPHABETICAL ORDER OF THE QUERY'S NAME, so renaming a shipped calibration query
    silently reorders a customer-facing column. The Licenses tab is the one that depends on it -
    it has two clause fields and the second arrives from a calibration whose name happens to
    sort fourth of nine.

  - THE FOUR CELLS WHERE THIS RUN OVERRODE THE SHARED RENDERER, each wrong in the reassuring
    direction: `0` as a content version (it means NEVER INSTALLED, and the URL filtering stream
    spells the same state `0000.00.00.000`), a blank release date (it asserts the reply carried
    no date, never that the stream is absent), a NULL alarm switch (the key is not in the
    configuration; `(none)` in a Yes/No column reads as off), and a `0` threshold (whose meaning
    the model records as unmeasured, so a bare `0` invites a ranking that may be inverted).

  - the explorer `row` lambdas over real rows, which the shipped check cannot read, and every
    `query_fields` entry against the search registry.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments import platform_lifecycle_presentation as presentation
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets import objects as _objects
from assessments.artifacts.sheets.findings import ALL_TESTED_COLUMNS, build_findings_table
from assessments.configuration_navigation import CONFIG_OBJECTS
from assessments.search.firewall_content_streams import compiler as content_compiler
from assessments.search.licence_inventory import compiler as licence_compiler
from assessments.search.log_alarm_settings import compiler as alarm_compiler
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementNode, EnforcementPoint, FirewallContentStreams,
    LicenceInventory, LogAlarmSettings, ManagementStation, Snapshot)

#: The three controls that HAVE a catalog entry. PAN-PLT-001, -003 and -005 are discharged
#: `engineer_answers` by stage 5, compile no query and have none - `seed_controls` would raise.
#:
#: THE FINDINGS-TAB TESTS SEED THESE and the reason is not incidental: a derived settings column
#: exists only because some control's query clauses on the field, so `build_findings_table` over
#: an unseeded catalog draws NO setting columns at all and an order assertion over that table
#: passes vacuously.
PAN_PLT = ("PAN-PLT-002", "PAN-PLT-004", "PAN-PLT-006")

#: (rail slug, findings-domain slug, control type, model). The category is Device for all three
#: and is DERIVED from the rail, so the test asserts the agreement rather than the word.
TABS = (
    ("content-streams", "content-streams", "firewall_content_streams", FirewallContentStreams),
    ("licenses", "licenses", "licence_inventory", LicenceInventory),
    ("log-alarms", "log-alarms", "log_alarm_settings", LogAlarmSettings),
)


class PlatformLifecycleRailTests(TestCase):
    """The three rail items, and the ways one can be wrong without a test name saying so."""

    def test_each_model_has_exactly_one_rail_item_and_it_claims_device(self):
        for rail_slug, _domain_slug, _control_type, model in TABS:
            with self.subTest(model=model.__name__):
                label = f"integrations.{model.__name__}"
                items = [o for o in CONFIG_OBJECTS if o.search_model == label]
                self.assertEqual(1, len(items))
                self.assertEqual(rail_slug, items[0].slug)
                self.assertEqual("Device", items[0].category)

    def test_every_rail_item_names_a_vendor_path_established_in_the_corpus(self):
        """Three paths, each present verbatim in all three indexed Help editions. Written down
        because three successive runs corrected a path taken from memory."""
        paths = {"content-streams": "Device > Dynamic Updates",
                 "licenses": "Device > Licenses",
                 "log-alarms": "Device > Log Settings"}
        for slug, where in paths.items():
            with self.subTest(slug=slug):
                (item,) = [o for o in CONFIG_OBJECTS if o.slug == slug]
                self.assertEqual(where, item.where)

    def test_every_icon_is_one_of_the_nineteen_vendored_files(self):
        """`ConfigObject.icon` IS NOT VALIDATED and a name that is not there raises
        `FileNotFoundError` at TEMPLATE RENDER - and because the rail renders on every explorer
        page it takes out every explorer test, with not one test name mentioning an icon.
        `globalprotect-portal` picked `lock`, which reads as obviously present and is not."""
        vendored = {
            "book-marked", "chevron-right", "circle-question-mark", "clipboard-check",
            "download", "eye", "flag", "layout-dashboard", "list-checks", "monitor", "plus",
            "refresh-cw", "server", "settings", "shield", "trash-2", "triangle-alert",
            "wand-sparkles", "x"}
        for slug in ("content-streams", "licenses", "log-alarms"):
            with self.subTest(slug=slug):
                (item,) = [o for o in CONFIG_OBJECTS if o.slug == slug]
                self.assertIn(item.icon, vendored)

    def test_the_prefix_no_longer_waits_for_presentation(self):
        """Clearing it is part of this stage's job rather than a side effect: an exemption that
        survives the work it was waiting for is a permanent hole."""
        self.assertNotIn("PAN-PLT", cr.AWAITING_PRESENTATION)


class PlatformLifecycleDomainTests(TestCase):
    def test_three_domains_are_registered_in_generator_order(self):
        """Entitlement, then content, then alarm - `finding_run.GENERATORS`' own order and its
        stated reason: a reader meets "this appliance's license table could not be read" before
        "its antivirus stream was never installed", because the first explains the second."""
        slugs = [d.slug for d in __import__(
            "assessments.artifacts.domains", fromlist=["DOMAINS"]).DOMAINS]
        ours = [s for s in slugs if s in {"licenses", "content-streams", "log-alarms"}]
        self.assertEqual(["licenses", "content-streams", "log-alarms"], ours)

    def test_every_tab_title_fits_excels_sheet_name_cap(self):
        """A sheet title over 31 characters truncates in the workbook SILENTLY, and
        `probe.surface_for` prints the untruncated title, so the tool and the workbook disagree
        and the tool looks right."""
        for _rail, domain_slug, _control_type, _model in TABS:
            with self.subTest(domain=domain_slug):
                self.assertLessEqual(len(DOMAIN_BY_SLUG[domain_slug].title), 31)

    def test_no_sheet_declares_hidden_fields(self):
        """The gate counts a field as presented if a subject column, a settings column OR the
        sheet's own `hidden_fields` carries it - so a non-empty tuple is a CLAIM accepted as
        proof, and it is the only known cause in this repository of a findings row that marks
        nothing as the thing to fix (P409)."""
        for _rail, _domain_slug, control_type, _model in TABS:
            with self.subTest(control_type=control_type):
                self.assertEqual((), _objects.SPEC_BY_TYPE[control_type].hidden_fields)

    def test_every_sheet_carries_both_tested_columns(self):
        """The default `("Provenance",)` drops `Fires when` from the WORKBOOK while the live page
        keeps it, so the two surfaces would disagree about which cell a reader meets (P427)."""
        for _rail, _domain_slug, control_type, _model in TABS:
            with self.subTest(control_type=control_type):
                self.assertEqual(ALL_TESTED_COLUMNS,
                                 _objects.SPEC_BY_TYPE[control_type].tested_columns)

    def test_every_subject_column_names_its_field(self):
        """A subject column that declares no field does not suppress the derived column for the
        same attribute, so one value reaches the tab twice under two headings - and because the
        headings differ, the duplicate-header guard never fires. The two identity columns are
        the exception: Appliance and HA role present no setting."""
        for _rail, _domain_slug, control_type, _model in TABS:
            spec = _objects.SPEC_BY_TYPE[control_type]
            for column in spec.subject_columns[2:]:
                with self.subTest(control_type=control_type, header=column[0]):
                    self.assertEqual(5, len(column))
                    self.assertTrue(column[4])


class ChoicesLabelTests(TestCase):
    """Every member of every `choices` vocabulary this domain presents, in the English a
    customer reads. Twenty-two labels, because a reader has to be able to tell that the cell says
    a sentence rather than a database token."""

    def label(self, model, field, value, **extra):
        reader = {"content_currency_state": presentation.CONTENT_STREAMS_READERS,
                  "entitlement_state": presentation.LICENCE_INVENTORY_READERS,
                  "support_entitlement_state": presentation.LICENCE_INVENTORY_READERS,
                  "alarm_mechanism_state": presentation.LOG_ALARM_READERS}[field][field]
        return reader.read(model(**{field: value}, **extra))

    def test_content_currency_states(self):
        expected = {
            "applications_and_threats_behind": "Applications and threats behind",
            "malware_stream_behind": "Malware stream behind",
            "inside_minimum_outside_preferred": "Inside minimum, outside preferred",
            "current": "Current",
            "release_date_not_reported": "No release date reported",
            "stream_never_installed": "A stream was never installed",
        }
        for value, label in expected.items():
            with self.subTest(value=value):
                self.assertEqual(
                    label,
                    self.label(FirewallContentStreams, "content_currency_state", value))

    def test_entitlement_states(self):
        expected = {
            "expired_entitlement_present": "An entitlement has expired",
            "expiring_within_30_days": "An entitlement expires within 30 days",
            "active_inside_90_days": "All active, inside 90 days",
            "active_beyond_90_days": "All active, beyond 90 days",
            # The KEY stays as it is stored - it is a database value, not a word a client
            # reads - and only the label was swept. See the integrations migration 0123.
            "no_licence_rows_returned": "No license rows returned",
            "inventory_not_collected": "Inventory not collected",
        }
        for value, label in expected.items():
            with self.subTest(value=value):
                self.assertEqual(
                    label, self.label(LicenceInventory, "entitlement_state", value))

    def test_support_entitlement_states(self):
        expected = {
            "absent_from_inventory": "Absent from the inventory",
            "expired": "Expired",
            "expires_within_90_days": "Expires within 90 days",
            "active_beyond_90_days": "Active beyond 90 days",
            "inventory_not_collected": "Inventory not collected",
        }
        for value, label in expected.items():
            with self.subTest(value=value):
                self.assertEqual(
                    label, self.label(LicenceInventory, "support_entitlement_state", value))

    def test_alarm_mechanism_states(self):
        expected = {
            "node_absent": "No alarm node",
            "generation_off": "Alarm generation off",
            "on_without_thresholds": "On, no threshold",
            "on_with_thresholds_no_route": "On, thresholds, no notification route",
            "on_with_thresholds_and_route": "On, thresholds and a notification route",
        }
        for value, label in expected.items():
            with self.subTest(value=value):
                self.assertEqual(
                    label, self.label(LogAlarmSettings, "alarm_mechanism_state", value))

    def test_the_empty_string_is_a_sixth_state_on_every_one_of_them(self):
        """It is deliberately absent from all four `choices` lists - it is what an unrecomputed
        or uncollected row holds - and Django's own `get_FIELD_display` returns the stored value
        unchanged for a key it does not know, so without a branch the cell would be BLANK. Not an
        em dash: `layout.NONE` says "this branch does not exist on this subject", and an absent
        verdict is a different sentence."""
        self.assertEqual(
            "Not computed",
            self.label(FirewallContentStreams, "content_currency_state", ""))
        self.assertEqual("Not computed", self.label(LicenceInventory, "entitlement_state", ""))
        self.assertEqual(
            "Not computed", self.label(LicenceInventory, "support_entitlement_state", ""))
        self.assertEqual(
            "Not computed", self.label(LogAlarmSettings, "alarm_mechanism_state", ""))

    def test_the_licence_read_shape_is_a_fifth_choices_column_and_is_a_subject_cell(self):
        """It is not a clause field, so it reaches the row as a hand-declared subject column and
        does its own display call. Without it the cell prints `null_licenses_element`."""
        (column,) = [c for c in _objects.LICENCE_INVENTORY_SUBJECT
                     if len(c) > 4 and c[4] == "licence_inventory_read"]
        read = column[3]
        self.assertEqual("Rows returned",
                         read(LicenceInventory(licence_inventory_read="rows_returned"), None))
        self.assertEqual(
            "Null licenses element",
            read(LicenceInventory(licence_inventory_read="null_licenses_element"), None))
        self.assertEqual("Not collected",
                         read(LicenceInventory(licence_inventory_read="not_collected"), None))
        self.assertEqual("Not computed",
                         read(LicenceInventory(licence_inventory_read=""), None))

    def test_the_nullable_alarm_switches_have_no_display_method_at_all(self):
        """P462, the half that ships a 500 rather than a wrong word. `get_<field>_display()`
        exists ONLY on a field declaring `choices`; on these three the call raises
        `AttributeError` at TEMPLATE RENDER, past `django check` and past all three cross-domain
        gates. Measured on `GlobalProtectGateway.globalprotect_gateway_licensed` by the run that
        had copied the pattern from the four readers the domain before it wrote."""
        row = LogAlarmSettings()
        for field in ("alarm_generation_enabled", "cli_alarm_notification_enabled",
                      "web_alarm_notification_enabled", "alarm_settings_node_present",
                      "alarm_notification_route_present"):
            with self.subTest(field=field):
                self.assertIsNone(LogAlarmSettings._meta.get_field(field).choices)
                self.assertFalse(hasattr(row, f"get_{field}_display"))


class OverriddenCellTests(TestCase):
    """The four cells where this run overrode `display_value`, which has only a value, `(none)`
    and `(empty)` and is wrong in the reassuring direction on each."""

    def read(self, columns, field):
        # `len(c) > 4` because the two identity columns are 4-tuples: Appliance and HA role
        # present no setting, so they declare no `field` and indexing them raises.
        (column,) = [c for c in columns if len(c) > 4 and c[4] == field]
        return lambda row: column[3](row, None)

    def test_zero_is_a_stream_that_was_never_installed(self):
        """`0` is TRUTHY as a string, so a truthiness test reports an uninstalled stream as
        installed, and a numeric comparison treats it as the lowest version rather than as no
        version. Both literals come from the model's own `NEVER_INSTALLED_VERSIONS`."""
        read = self.read(_objects.CONTENT_STREAMS_SUBJECT, "av_version")
        self.assertEqual("Never installed",
                         read(FirewallContentStreams(av_version="0")))
        self.assertEqual("5709-6237", read(FirewallContentStreams(av_version="5709-6237")))
        self.assertEqual("Not read", read(FirewallContentStreams(av_version="")))

    def test_the_url_filtering_stream_spells_the_same_state_differently(self):
        """Measured on both PA-5220s: the four content streams answer `0` and the URL filtering
        stream answers `0000.00.00.000` for one state."""
        read = self.read(_objects.CONTENT_STREAMS_SUBJECT, "url_filtering_version")
        self.assertEqual(
            "Never installed",
            read(FirewallContentStreams(url_filtering_version="0000.00.00.000")))

    def test_a_blank_release_date_says_the_reply_carried_none(self):
        """It must NEVER be read as a proxy for installation: on both PA-5220s "no date
        reported" is true while "content installed" is also true."""
        read = self.read(_objects.CONTENT_STREAMS_SUBJECT, "app_release_date")
        self.assertEqual("No release date reported",
                         read(FirewallContentStreams(app_release_date="")))
        self.assertEqual("2026/10/20 01:27:15 GMT",
                         read(FirewallContentStreams(
                             app_release_date="2026/10/20 01:27:15 GMT")))

    def test_a_null_alarm_switch_is_not_off(self):
        """NULL means the key is not in the committed configuration and what the device does in
        that state is UNMEASURED - deliberately not stored as false, because false would mean an
        administrator switched alarms off."""
        read = self.read(_objects.LOG_ALARM_SUBJECT, "alarm_generation_enabled")
        self.assertEqual("Not in the configuration",
                         read(LogAlarmSettings(alarm_generation_enabled=None)))
        self.assertEqual("Yes", read(LogAlarmSettings(alarm_generation_enabled=True)))
        self.assertEqual("No", read(LogAlarmSettings(alarm_generation_enabled=False)))

    def test_a_zero_threshold_does_not_claim_to_be_the_strictest(self):
        """The model carries the sentinel: zero is inside the grammar's range, the device accepts
        it, and whether it means "alarm always" or "alarm never" is UNMEASURED - so a cell
        printing a bare `0` invites a ranking that may be exactly inverted. One lab appliance
        holds it."""
        read = self.read(_objects.LOG_ALARM_SUBJECT, "log_db_alarm_threshold_lowest")
        self.assertEqual("0 - what this value means is not established",
                         read(LogAlarmSettings(log_db_alarm_threshold_lowest=0)))
        self.assertEqual("80", read(LogAlarmSettings(log_db_alarm_threshold_lowest=80)))
        self.assertEqual("No threshold recorded",
                         read(LogAlarmSettings(log_db_alarm_threshold_lowest=None)))

    def test_a_threshold_map_names_its_log_types_and_claims_no_unit(self):
        """The vendor describes the same percentage as a share of "available disk space" on help
        11.2 p.912 and of "the maximum size" in that page's own field table on p.913, and the two
        denominators measure 11 GB and 0.341 GB on one lab appliance. Both sentences are in all
        three indexed Help editions, so no unit is claimed here."""
        read = self.read(_objects.LOG_ALARM_SUBJECT, "log_db_alarm_thresholds")
        # ONE PER LINE, not comma-joined - the repository's multi-value cell rule.
        self.assertEqual(
            "config 80\nsystem 85",
            read(LogAlarmSettings(log_db_alarm_thresholds={"system": 85, "config": 80})))
        self.assertEqual("None recorded",
                         read(LogAlarmSettings(log_db_alarm_thresholds={})))

    def test_a_count_of_zero_is_said_in_words(self):
        """The findings tabs' own rule: a bare zero in a reference column reads as "not counted"
        exactly where it means "counted, and the answer was none". On the license row count the
        zero is TWO device states - a present-and-empty element and a read that never ran - told
        apart by the cell before it and never by this one."""
        read = self.read(_objects.LICENCE_INVENTORY_SUBJECT, "licence_row_count")
        self.assertEqual("None returned", read(LicenceInventory(licence_row_count=0)))
        self.assertEqual("10", read(LicenceInventory(licence_row_count=10)))


class PlatformLifecycleEstateMixin:
    """One appliance, one vsys, and a row of each of the three models."""

    @classmethod
    def build_estate(cls):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_FIREWALL, hostname="fw.plt")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-plt",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="013201007777", hostname="fw-plt-a")
        point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, appliance=appliance,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True)
        EnforcementNode.objects.create(management_station=station, enforcement_point=point,
                                       appliance=appliance)
        # `source_snapshot` is NOT NULL on all three models, so no row can be built without one.
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        return station, appliance, point, snapshot

    @classmethod
    def build_rows(cls, station, appliance, snapshot):
        """One row of each model, in the state the measured estate's PA-VM is in."""
        streams = FirewallContentStreams.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            content_streams_collected=True, content_currency_state="stream_never_installed",
            app_version="9161-10297", app_release_date="2026/10/20 01:27:15 GMT",
            av_version="5709-6237", av_release_date="2026/10/11 11:00:30 GMT",
            threat_version="9161-10297", threat_release_date="2026/10/20 01:27:15 GMT",
            wildfire_version="0", url_filtering_version="20261028.20125",
            device_dictionary_version="82-406", release_date_reported=True)
        licenses = LicenceInventory.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            licence_inventory_read="rows_returned", licence_row_count=3,
            entitlement_state="active_beyond_90_days",
            support_entitlement_state="absent_from_inventory",
            entitlement_features_held=["Adv Threat Prevention", "PA-VM", "Threat Prevention"])
        alarms = LogAlarmSettings.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            alarm_settings_node_present=True, alarm_generation_enabled=True,
            alarm_generation_enabled_known=True,
            log_db_alarm_thresholds={"system": 85, "config": 80, "alarm": 0},
            log_db_alarm_threshold_count=3, log_db_alarm_threshold_lowest=0,
            cli_alarm_notification_enabled=False, web_alarm_notification_enabled=False,
            alarm_notification_route_present=False,
            alarm_mechanism_state="on_with_thresholds_no_route")
        return streams, licenses, alarms


class PlatformLifecycleResultsRowTests(PlatformLifecycleEstateMixin, TestCase):
    """The explorer `row` lambdas over real rows. The shipped check asserts a row is the same
    LENGTH as its columns and cannot see what a cell says."""

    def setUp(self):
        self.station, self.appliance, self.point, self.snapshot = self.build_estate()
        self.streams, self.licenses, self.alarms = self.build_rows(
            self.station, self.appliance, self.snapshot)

    def row_for(self, slug, obj):
        spec = cr.RESULTS[slug]
        row = spec.row(obj)
        self.assertEqual(len(spec.columns), len(row))
        return dict(zip(spec.columns, row))

    def test_the_content_page_pairs_each_version_with_its_date(self):
        cells = self.row_for("content-streams", self.streams)
        self.assertEqual("A stream was never installed", cells["Content currency"])
        self.assertEqual("yes", cells["Content read answered"])
        self.assertEqual("9161-10297 (2026/10/20 01:27:15 GMT)", cells["Applications"])
        # NO `wildfire_release_date` COLUMN ON THE MODEL, so the cell says nothing about a date
        # rather than saying there is none.
        self.assertEqual("never installed", cells["WildFire"])
        self.assertEqual("20261028.20125", cells["URL filtering"])

    def test_the_licence_page_prints_both_verdicts_as_english(self):
        cells = self.row_for("licenses", self.licenses)
        self.assertEqual("Rows returned", cells["License table read"])
        self.assertEqual("3 rows", cells["Rows returned"])
        self.assertEqual("All active, beyond 90 days", cells["Subscription entitlements"])
        self.assertEqual("Absent from the inventory", cells["Support entitlement"])
        self.assertEqual("Nothing", cells["Expired"])
        self.assertEqual("Adv Threat Prevention\nPA-VM\nThreat Prevention",
                         cells["Features held"])
        self.assertNotIn(", ", cells["Features held"])

    def test_the_alarm_page_keeps_the_three_way_switches_apart(self):
        cells = self.row_for("log-alarms", self.alarms)
        self.assertEqual("On, thresholds, no notification route", cells["Alarm mechanism"])
        self.assertEqual("yes", cells["Alarms enabled"])
        self.assertEqual("no", cells["CLI notification"])
        self.assertEqual("alarm 0\nconfig 80\nsystem 85", cells["Thresholds"])
        self.alarms.alarm_generation_enabled = None
        self.assertEqual("not in the configuration",
                         self.row_for("log-alarms", self.alarms)["Alarms enabled"])

    def test_every_query_field_names_a_registered_field(self):
        """A heading mapped to an UNREGISTERED field points the "build a query from these rows"
        button at a lookup that refuses itself or silently matches nothing. Stored, searchable
        and registered are three different things."""
        registries = {"content-streams": content_compiler.FIELD_OPERATOR_REGISTRY,
                      "licenses": licence_compiler.FIELD_OPERATOR_REGISTRY,
                      "log-alarms": alarm_compiler.FIELD_OPERATOR_REGISTRY}
        for slug, registry in registries.items():
            spec = cr.RESULTS[slug]
            for heading, field in spec.query_fields.items():
                with self.subTest(slug=slug, heading=heading):
                    self.assertIn(field, registry)
                    self.assertIn(heading, spec.columns)

    def test_the_shown_but_unqueryable_columns_are_deliberate(self):
        """Only a column a control asks for is registered, so the version strings, the release
        dates, the per-entitlement counts, the threshold map and the three nullable switches are
        SHOWN and not queryable. Pinned so a later run does not read the absence as an omission."""
        self.assertNotIn("Applications", cr.RESULTS["content-streams"].query_fields)
        self.assertIn("Applications", cr.RESULTS["content-streams"].columns)
        self.assertNotIn("Features held", cr.RESULTS["licenses"].query_fields)
        self.assertIn("Features held", cr.RESULTS["licenses"].columns)
        self.assertNotIn("Thresholds", cr.RESULTS["log-alarms"].query_fields)
        self.assertIn("Thresholds", cr.RESULTS["log-alarms"].columns)


class PlatformLifecycleTabTests(PlatformLifecycleEstateMixin, TestCase):
    """The built tables: the column order nothing gates, and the Provenance cell."""

    @classmethod
    def setUpTestData(cls):
        seed_controls(list(PAN_PLT))

    def setUp(self):
        self.station, self.appliance, self.point, self.snapshot = self.build_estate()
        self.build_rows(self.station, self.appliance, self.snapshot)

    def headers_of(self, control_type):
        spec = _objects.SPEC_BY_TYPE[control_type]
        return list(build_findings_table(spec, tested=ALL_TESTED_COLUMNS).headers)

    def test_the_content_tab_draws_one_derived_column_last(self):
        """PAN-PLT-002 clauses on ONE field and all five of its calibrations clause on the same
        one, so the tab has exactly one derived settings column however the queries are named -
        which is the one case where the alphabetical-by-query-name order cannot bite."""
        headers = self.headers_of("firewall_content_streams")
        self.assertEqual(1, headers.count("Content currency"))
        self.assertEqual("Content currency", headers[-3])
        self.assertLess(headers.index("Content read answered"),
                        headers.index("Content currency"))

    def test_the_licence_tab_orders_its_two_verdicts_the_way_the_query_names_sort(self):
        """THE ONE TAB HERE WHERE THE ORDER IS NOT FORCED. `tested_fields` takes the baseline's
        clauses first - `entitlement_state` - and then every other active query's in
        ALPHABETICAL ORDER OF THE QUERY'S NAME, so `support_entitlement_state` arrives from "No
        support entitlement appears in the license table", which sorts fourth of the nine
        calibrations. Renaming that query to sort before the three "An entitlement ..." ones
        would silently swap two customer-facing columns and nothing would fail."""
        headers = self.headers_of("licence_inventory")
        self.assertLess(headers.index("Subscription entitlements"),
                        headers.index("Support entitlement"))
        self.assertEqual(["Subscription entitlements", "Support entitlement"],
                         headers[-4:-2])

    def test_the_alarm_tab_draws_its_verdict_after_every_leaf(self):
        headers = self.headers_of("log_alarm_settings")
        self.assertEqual(1, headers.count("Alarm mechanism"))
        self.assertEqual("Alarm mechanism", headers[-3])
        for leaf in ("Alarm node in the configuration", "Alarms enabled",
                     "Log types with a threshold", "A notification route is on"):
            with self.subTest(leaf=leaf):
                self.assertLess(headers.index(leaf), headers.index("Alarm mechanism"))

    def test_no_heading_on_any_of_the_three_tabs_is_a_raw_django_field_name(self):
        """`setting_labels` falls back to the raw field name when it has no entry, so declaring a
        column without a label IS choosing to show a database field name to a customer."""
        for _rail, _domain_slug, control_type, _model in TABS:
            for header in self.headers_of(control_type):
                with self.subTest(control_type=control_type, header=header):
                    self.assertNotIn("_", header)

    def test_the_provenance_cell_says_derived_and_not_not_recorded(self):
        """P451 on all three tabs. The default cell answers per tested field through
        `remediation_accessor`, which skips a DERIVED row and walks to the object's `__entry__` -
        and `write_node_row` never writes an `__entry__` row, so the cell printed "Not recorded"
        about a verdict this assessment computed."""
        for _rail, _domain_slug, control_type, _model in TABS:
            spec = _objects.SPEC_BY_TYPE[control_type]
            with self.subTest(control_type=control_type):
                self.assertIsNotNone(spec.provenance_cell)
                self.assertEqual("Derived", spec.provenance_cell(None, None, ()))

    def test_the_readers_alone_already_fix_the_provenance_cell(self):
        """Which of the two fixes does the work, pinned, because the standing remedy is the other
        one. Removing the sheet's own `provenance_cell` and keeping the readers still reads
        "Derived"; removing BOTH reads "Not recorded".

        `regenerate_findings()` IS THE TEST. `build_findings_table` LOADS findings rather than
        computing them, and its only row-count guard compares what it built against what the
        database holds - so with no findings generated both sides are zero, nothing raises, the
        headings still come out right because they derive from the controls, and the two loops
        below iterate nothing and assert nothing. Measured 2026-11-03: without this call the three
        tabs build 0 rows each, and this test had been passing vacuously since it was written. The
        `assertTrue(table.rows)` lines are what stop it going hollow again. It is called here
        rather than in `setUp` because the other nine tests in this class read `headers` only, and
        a full finding run in `setUp` would be paid ten times on every gate run.
        """
        import dataclasses

        from assessments.finding_run import regenerate_findings

        regenerate_findings()

        for _rail, domain_slug, _control_type, _model in TABS:
            spec = DOMAIN_BY_SLUG[domain_slug].spec
            with self.subTest(domain=domain_slug):
                without_cell = dataclasses.replace(spec, provenance_cell=None)
                table = build_findings_table(without_cell, tested=ALL_TESTED_COLUMNS)
                index = list(table.headers).index("Provenance")
                self.assertTrue(table.rows, "no rows: this test would assert nothing")
                for row in table.rows:
                    self.assertEqual({"Derived"}, set(str(row[index]).split("\n")))

                without_either = dataclasses.replace(
                    spec, provenance_cell=None, value_readers={})
                table = build_findings_table(without_either, tested=ALL_TESTED_COLUMNS)
                index = list(table.headers).index("Provenance")
                self.assertTrue(table.rows, "no rows: this test would assert nothing")
                for row in table.rows:
                    self.assertEqual({"Not recorded"}, set(str(row[index]).split("\n")))

    def test_no_sheet_carries_a_template_column(self):
        """All four clause fields are in their model's `DERIVED_FIELDS` - computations over an
        operational reply or a configuration node, never a pushed value - so the default source
        column would be empty on every row of every tab."""
        for _rail, _domain_slug, control_type, _model in TABS:
            with self.subTest(control_type=control_type):
                self.assertEqual((), _objects.SPEC_BY_TYPE[control_type].source_columns)

    def test_each_model_is_unique_on_the_appliance_so_an_ha_pair_draws_two_rows(self):
        """Stage 5 says so for all three subjects and nothing deduplicates them. The Appliance
        and HA role columns are the only thing telling the two rows apart."""
        for _rail, _domain_slug, _control_type, model in TABS:
            with self.subTest(model=model.__name__):
                (constraint,) = model._meta.constraints
                self.assertEqual(("appliance",), tuple(constraint.fields))
