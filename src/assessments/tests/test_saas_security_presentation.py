"""The four SaaS findings tabs, four rail items and four results pages, pinned. Stage 9,
`saas-security`.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover the tabs generically:
every assertion here is a JUDGMENT this run made that nothing else in the repository states, and
a new tab nothing asserts on is one the next refactor can break silently.

  - THE THREE-WAY `ace_disabled` CELL. The column is nullable and NULL means the configuration
    node was never read; `display_value` has only a value, `(none)` and `(empty)`, and measured
    on a built row it printed `(none)` - which on a column headed "Engine disabled in
    configuration" reads as "nothing is configured there", and nothing configured is the engine
    being ON. This is the one cell on the four tabs where this run overrode the shared renderer.
  - THE PROVENANCE CELL ON ALL FOUR TABS. Measured with the default cell: every tab printed
    "Not recorded" for every tested field, which means "nothing tracks this field" and reads to
    a customer as a gap in the collection. The values are DERIVED. The fourth tab was the one
    nothing in either repository had settled, so its default answer is pinned too.
  - THE COLUMN ORDER, per tab, read off `FindingsTable.headers` rather than derived. Nothing
    gates it: `tested_fields` takes the baseline's clauses in clause order and then every other
    active query's in ALPHABETICAL ORDER OF THE QUERY'S NAME, so renaming a shipped calibration
    query silently reorders a customer-facing column.
  - THAT NO FIELD OF THE FOUR MODELS DECLARES `choices`, so no reader may call
    `get_<field>_display()`. That method exists only on a field with `choices`; on the booleans
    here the call raises `AttributeError` AT TEMPLATE RENDER, past `django check` and past all
    three cross-domain gates. This is the guard against a later run copying the pattern in.
  - THAT PAN-SAS-003's MARK LANDS ON THE VERDICT AND NOT ON THE GRADED COLUMN. Stage 8 recorded
    this disagreement and it is implemented as stage 8 wrote it; the test pins the consequence so
    that a later change is a decision rather than a surprise.
  - the explorer `row` lambdas over real rows, which the shipped check cannot read, and every
    `query_fields` entry against the search registry.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets import objects as _objects
from assessments.artifacts.sheets.findings import ALL_TESTED_COLUMNS, build_findings_table
from assessments.configuration_navigation import CATEGORIES, CONFIG_OBJECTS
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, CloudAppEngineSetting, EnforcementNode, EnforcementPoint,
    ManagementStation, SaasApplicationPolicyPosture, SaasUrlFilteringPosture,
    SanctionedApplicationMarking, Snapshot)

#: Every control of this domain. The findings-tab tests SEED THESE and the reason is not
#: incidental: a derived settings column exists only because some control's query clauses on the
#: field, so `build_findings_table` over an unseeded catalog draws NO setting columns at all and
#: an order assertion over that table passes vacuously.
PAN_SAS = tuple(f"PAN-SAS-{n:03d}" for n in range(1, 6))

#: (rail slug, findings-domain slug, sheet, the category both must agree on).
TABS = (
    ("saas-application-policy", "saas-application-policy",
     _objects.SPEC_BY_TYPE["saas_application_policy_posture"], "Policies"),
    ("sanctioned-applications", "sanctioned-application-marking",
     _objects.SPEC_BY_TYPE["sanctioned_application_marking"], "Objects"),
    ("saas-url-filtering", "saas-url-filtering-posture",
     _objects.SPEC_BY_TYPE["saas_url_filtering_posture"], "Objects"),
    ("ace", "cloud-app-engine", _objects.SPEC_BY_TYPE["cloud_app_engine_setting"], "Device"),
)

MODELS = (SanctionedApplicationMarking, SaasUrlFilteringPosture,
          SaasApplicationPolicyPosture, CloudAppEngineSetting)


class SaasRailItemTests(TestCase):
    """The four rail items, and the two ways one can be wrong without a test name saying so."""

    def test_each_of_the_four_models_has_exactly_one_rail_item(self):
        for model in MODELS:
            with self.subTest(model=model.__name__):
                label = f"integrations.{model.__name__}"
                items = [o for o in CONFIG_OBJECTS if o.search_model == label]
                self.assertEqual(1, len(items), f"{label} needs exactly one rail item")

    def test_every_icon_is_in_the_vendored_set(self):
        """NOT lucide's catalog. A name that is not in OptivEdge's own
        `templates/components/icons/` raises `FileNotFoundError` AT TEMPLATE RENDER, and because
        the rail draws on every explorer page it takes out every explorer test at once - with no
        test name mentioning an icon. Nineteen files, enumerated by the run that lost 56 errors
        to a plausible name that was not there."""
        vendored = {
            "book-marked", "chevron-right", "circle-question-mark", "clipboard-check",
            "download", "eye", "flag", "layout-dashboard", "list-checks", "monitor", "plus",
            "refresh-cw", "server", "settings", "shield", "trash-2", "triangle-alert",
            "wand-sparkles", "x"}
        for slug, _domain, _spec, _category in TABS:
            with self.subTest(slug=slug):
                (item,) = [o for o in CONFIG_OBJECTS if o.slug == slug]
                self.assertIn(item.icon, vendored)

    def test_the_rail_item_names_the_vendor_path(self):
        """Each `where` is a section path established in the corpus, not written from memory."""
        expected = {
            "sanctioned-applications": "Objects > Applications",
            "saas-url-filtering":
                "Objects > Security Profiles > URL Filtering > HTTP Header Insertion",
            "saas-application-policy": "Policies > Security",
            "ace": "Device > Setup > ACE"}
        for slug, where in expected.items():
            with self.subTest(slug=slug):
                (item,) = [o for o in CONFIG_OBJECTS if o.slug == slug]
                self.assertEqual(where, item.where)

    def test_the_prefix_left_awaiting_presentation(self):
        """The exemption that let all seven shipped queries resolve to nothing. An exemption
        surviving the work it was waiting for is a permanent hole."""
        self.assertNotIn("PAN-SAS-", cr.AWAITING_PRESENTATION)
        self.assertNotIn("PAN-SAS", cr.AWAITING_PRESENTATION)

    def test_no_page_declares_a_scope(self):
        """Each of the four models has exactly ONE page, so `object_for_canonical_query`
        short-circuits on the single candidate. A scope of {} is a subset of EVERY query over a
        model and would be dead weight a later second page has to reckon with."""
        for slug, _domain, _spec, _category in TABS:
            with self.subTest(slug=slug):
                self.assertIsNone(cr.RESULTS[slug].scope)


class SaasSheetShapeTests(TestCase):
    """The spec-level judgments, none of which needs a database."""

    def test_no_model_field_declares_choices_so_no_reader_may_call_a_display_method(self):
        """`get_<field>_display()` exists ONLY on a field with `choices`. On the booleans and
        char fields here the call raises `AttributeError` at TEMPLATE RENDER - past `django
        check` and past all three cross-domain gates. If this test ever fails, the field that
        gained `choices` NEEDS a reader, because `display_value` never calls the display method
        and the cell would print the stored key to a customer."""
        for model in MODELS:
            for field in model._meta.get_fields():
                if not hasattr(field, "attname"):
                    continue
                with self.subTest(model=model.__name__, field=field.name):
                    self.assertFalse(getattr(field, "choices", None))

    def test_no_sheet_declares_a_value_reader(self):
        """Nothing is owed one: no field has `choices`, every column is on the subject row, and
        `tested_fields` raises for a field the model neither stores nor computes - which none of
        these is. A reader here would be a `get_<field>_display()` call waiting to happen."""
        for _slug, _domain, spec, _category in TABS:
            with self.subTest(title=spec.sheet_title):
                self.assertEqual({}, spec.value_readers)

    def test_no_sheet_hides_a_field(self):
        """`check_every_tested_field_is_presented` accepts `hidden_fields` as PROOF that
        something shows the field, so a non-empty tuple is a claim taken on trust and is the only
        known cause in this repository of a findings row that marks nothing as the thing to
        fix."""
        for _slug, _domain, spec, _category in TABS:
            with self.subTest(title=spec.sheet_title):
                self.assertEqual((), spec.hidden_fields)

    def test_every_sheet_carries_the_firing_condition_as_well_as_provenance(self):
        """The default `("Provenance",)` drops `Fires when` from the WORKBOOK while the live page
        keeps it, so the two surfaces disagree about which cell a reader meets."""
        for _slug, _domain, spec, _category in TABS:
            with self.subTest(title=spec.sheet_title):
                self.assertEqual(ALL_TESTED_COLUMNS, spec.tested_columns)

    def test_every_tab_title_fits_a_worksheet_name(self):
        """Excel truncates a sheet name over 31 characters SILENTLY, and `probe.surface_for`
        prints the untruncated title - so the tool and the workbook disagree and the tool looks
        right."""
        for _slug, _domain, spec, _category in TABS:
            with self.subTest(title=spec.sheet_title):
                self.assertLessEqual(len(spec.sheet_title), 31)

    def test_each_tab_derives_its_category_from_the_rail(self):
        """`category=''` is right for a subject that IS a configuration object: deriving it means
        the workbook cannot disagree with the app about where the object lives."""
        for slug, domain_slug, spec, category in TABS:
            with self.subTest(slug=slug):
                self.assertEqual("", spec.category)
                (item,) = [o for o in CONFIG_OBJECTS if o.slug == slug]
                self.assertEqual(category, item.category)
                self.assertIn(category, CATEGORIES)
                self.assertIs(spec, DOMAIN_BY_SLUG[domain_slug].spec)

    def test_every_subject_column_presenting_a_model_field_names_it(self):
        """A subject column that declares no `field` does not suppress the derived column for the
        same attribute, so one value reaches the tab twice under two headings - and because the
        headings differ, the duplicate-header guard never fires. The two ADDRESS columns on the
        vsys-scoped tabs declare none deliberately: they are not model attributes, and declaring
        one would move the value-at-fault mark off the verdict and onto the row's address."""
        address = {"Firewalls", "Vsys", "Appliance", "HA role"}
        for _slug, _domain, spec, _category in TABS:
            for column in spec.subject_columns:
                header = column[0]
                with self.subTest(title=spec.sheet_title, header=header):
                    if header in address:
                        self.assertEqual(4, len(column), "an address column names no field")
                    else:
                        self.assertEqual(5, len(column))
                        self.assertTrue(column[4])


class SaasQueryFieldTests(TestCase):
    """Every `query_fields` entry against the search registry it points at."""

    def test_every_mapped_field_is_registered_by_the_compiler(self):
        """A heading mapped to an unregistered field points the "build a query from these rows"
        button at a lookup that refuses itself or silently matches nothing. Stored, searchable
        and registered are three different things."""
        import importlib
        registries = {
            "sanctioned-applications": "sanctioned_application_marking",
            "saas-url-filtering": "saas_url_filtering_posture",
            "saas-application-policy": "saas_application_policy_posture",
            "ace": "cloud_app_engine_setting"}
        for slug, module in registries.items():
            registry = importlib.import_module(
                f"assessments.search.{module}.compiler").FIELD_OPERATOR_REGISTRY
            spec = cr.RESULTS[slug]
            for heading, field in spec.query_fields.items():
                with self.subTest(slug=slug, heading=heading):
                    self.assertIn(field, registry)
            for heading in spec.query_fields:
                with self.subTest(slug=slug, heading=heading):
                    self.assertIn(heading, spec.columns)

    def test_the_two_unmappable_columns_carry_no_entry(self):
        """`marked_application_names` is a JSONField and nothing may clause on one;
        `cloudapp_server_address` is declared not searchable. Neither is in its registry, so
        neither may be a `query_fields` entry."""
        self.assertNotIn("Applications marked approved",
                         cr.RESULTS["sanctioned-applications"].query_fields)
        self.assertIn("Applications marked approved",
                      cr.RESULTS["sanctioned-applications"].columns)
        self.assertNotIn("Cloud endpoint override", cr.RESULTS["ace"].query_fields)
        self.assertIn("Cloud endpoint override", cr.RESULTS["ace"].columns)


class SaasEstateMixin:
    """One appliance, one vsys, and a row of each of the four models."""

    @classmethod
    def build_estate(cls):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_FIREWALL, hostname="fw.sas")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-sas",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="013201008888", hostname="fw-sas-a")
        point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, appliance=appliance,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True)
        EnforcementNode.objects.create(management_station=station, enforcement_point=point,
                                       appliance=appliance)
        # `source_snapshot` is NOT NULL on all four models, so no row can be built without one.
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        return station, appliance, point, snapshot


class SaasResultsRowTests(SaasEstateMixin, TestCase):
    """The explorer `row` lambdas over real rows. The shipped check asserts a row is the same
    LENGTH as its columns and cannot see what a cell says."""

    def setUp(self):
        self.station, self.appliance, self.point, self.snapshot = self.build_estate()

    def row_for(self, slug, obj):
        spec = cr.RESULTS[slug]
        row = spec.row(obj)
        self.assertEqual(len(spec.columns), len(row))
        return dict(zip(spec.columns, row))

    def test_an_unread_ace_node_says_so_rather_than_reading_as_not_disabled(self):
        """NULL means the `deviceconfig/setting` subtree was never read - neither present nor
        absent but unread. `_yes_no` would print "no", which IS the engine being on."""
        setting = CloudAppEngineSetting.objects.create(
            management_station=self.station, appliance=self.appliance, appliance_group=None,
            source_snapshot=self.snapshot, ace_disabled=None, cloudapp_node_read=False,
            ace_not_operational=True, ace_failure_reason="unread", cloudapp_server_address="")
        cells = self.row_for("ace", setting)
        self.assertEqual("-", cells["Engine disabled in configuration"])
        self.assertEqual("no", cells["Configuration node read"])
        self.assertEqual("unread", cells["Why the engine is not working"])
        self.assertEqual("the vendor's own endpoint", cells["Cloud endpoint override"])

    def test_a_read_ace_node_reports_the_vendor_key_in_the_vendor_polarity(self):
        setting = CloudAppEngineSetting.objects.create(
            management_station=self.station, appliance=self.appliance, appliance_group=None,
            source_snapshot=self.snapshot, ace_disabled=True, cloudapp_node_read=True,
            ace_not_operational=True, ace_failure_reason="configured_disable",
            cloudapp_server_address="")
        cells = self.row_for("ace", setting)
        self.assertEqual("yes", cells["Engine disabled in configuration"])
        self.assertEqual("yes", cells["Configuration node read"])

    def test_a_partition_marking_nothing_says_so_rather_than_leaving_a_blank(self):
        """An empty list beside a firing count of 0 is the honest pair; a blank cell would not
        say whether anyone looked."""
        marking = SanctionedApplicationMarking.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, sanctioned_application_count=0,
            marked_application_names=[], appliance_is_multi_vsys=False,
            marking_is_inconsistent_across_vsys=False)
        cells = self.row_for("sanctioned-applications", marking)
        self.assertEqual("Nothing marked", cells["Applications marked approved"])
        # The NUMBER, not a word: zero is the reportable end and the whole of the baseline
        # clause, and "Nothing" on a column named for a count reads as "not counted".
        self.assertEqual("0", cells["Applications marked approved (count)"])
        self.assertEqual("fw-sas-a", cells["Firewalls"])

    def test_the_marked_names_are_one_per_line(self):
        marking = SanctionedApplicationMarking.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, sanctioned_application_count=2,
            marked_application_names=["dropbox-base", "ms-office365"],
            appliance_is_multi_vsys=True, marking_is_inconsistent_across_vsys=True)
        cells = self.row_for("sanctioned-applications", marking)
        self.assertEqual("dropbox-base\nms-office365", cells["Applications marked approved"])

    def test_an_unreached_category_keeps_the_stored_token(self):
        """`in-no-restricting-list` means the category reaches no restricting surface at all,
        which is a different thing from being allowed by one - a word like "none" collapses
        them."""
        posture = SaasUrlFilteringPosture.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, url_filtering_profiles_read=False,
            header_insertion_type_entry_count=0, tenant_restriction_in_force=False,
            tenant_header_without_value_count=0, rule_bound_tenant_list_count=0,
            consumer_storage_category_treatment="in-no-restricting-list",
            consumer_storage_categories_are_restricted=False)
        cells = self.row_for("saas-url-filtering", posture)
        self.assertEqual("in-no-restricting-list", cells["Site Access (least restrictive)"])
        # THE PAIR THAT MAKES THE VERDICT HONEST: both verdicts read "no" here, and only this
        # cell says whether that is an answer or an absence of one.
        self.assertEqual("no", cells["Profiles read"])
        self.assertEqual("no", cells["Tenant restriction in force"])
        self.assertEqual("Nothing", cells["Header insertion entries"])

    def test_a_rulebase_naming_no_function_app_keeps_the_no_rule_token(self):
        """`no-rule` is a real value and not a blank: no rule names any function child
        application, so there is no action to read at all."""
        posture = SaasApplicationPolicyPosture.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, function_app_rule_count=0,
            function_apps_are_refused=False, effective_action_for_function_apps="no-rule",
            cloud_app_filter_count=0, cloud_app_selection_is_refused=False,
            cloud_app_selection_excludes_approved=False)
        cells = self.row_for("saas-application-policy", posture)
        self.assertEqual("no-rule", cells["Action on function apps"])
        self.assertEqual("Nothing", cells["Rules naming a function app"])
        self.assertEqual("no", cells["Upload and sharing functions refused"])


class SaasFindingsTabTests(SaasEstateMixin, TestCase):
    """The tabs as built, over a real row of each model with a finding on it."""

    @classmethod
    def setUpTestData(cls):
        seed_controls(list(PAN_SAS))

    def setUp(self):
        self.station, self.appliance, self.point, self.snapshot = self.build_estate()

    def headers_of(self, spec):
        return [header for header, _width, _wrap in
                build_findings_table(spec, tested=ALL_TESTED_COLUMNS).columns]

    def test_the_marking_tab_column_order_is_stage_5s_clause_order(self):
        """Read off `FindingsTable.headers`, not derived. The baseline's one clause, then the
        calibration query's applicability clause and its assertion, in clause order."""
        headers = self.headers_of(_objects.SPEC_BY_TYPE["sanctioned_application_marking"])
        settings = headers[headers.index("Provenance") + 1:headers.index("Matched queries")]
        self.assertEqual(
            ["Applications marked approved (count)",
             "Appliance has several virtual systems",
             "Approval differs between virtual systems"], settings)

    def test_the_url_filtering_tab_orders_by_control_then_baseline_then_query_name(self):
        """TWO controls share this tab. `setting_columns` walks the controls in `control_id`
        order and `tested_fields` puts each one's baseline clauses first, so PAN-SAS-002's
        verdict leads, then PAN-SAS-004's baseline, then the field only its calibration query
        names."""
        headers = self.headers_of(_objects.SPEC_BY_TYPE["saas_url_filtering_posture"])
        settings = headers[headers.index("Provenance") + 1:headers.index("Matched queries")]
        self.assertEqual(
            ["Tenant restriction in force",
             "Consumer storage categories restricted",
             "Site Access (least restrictive)"], settings)

    def test_the_ace_tab_puts_the_applicability_clause_before_the_assertion(self):
        """An applicability clause draws a column too - `tested_fields` registers them - and
        stage 5 writes it first in the record."""
        headers = self.headers_of(_objects.SPEC_BY_TYPE["cloud_app_engine_setting"])
        settings = headers[headers.index("Provenance") + 1:headers.index("Matched queries")]
        self.assertEqual(["Why the engine is not working", "Engine not working"], settings)

    def test_no_heading_on_any_of_the_four_tabs_reads_as_a_django_field_name(self):
        """A heading lives in `setting_labels`, which falls back to the RAW FIELD NAME when it
        has no entry - so declaring a column without a label IS choosing to show a database
        field name to a customer."""
        for _slug, _domain, spec, _category in TABS:
            for header in self.headers_of(spec):
                with self.subTest(title=spec.sheet_title, header=header):
                    self.assertNotRegex(header, r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$")

    def test_every_provenance_cell_says_derived_rather_than_not_recorded(self):
        """P451, and the fourth tab is the one nothing had settled. No provenance row exists for
        any tested column of any of the four models - the three postures write none at all, not
        even `__entry__`, and `write_node_row` writes one per NAMED field for two fields no
        control tests - so the default cell resolves through `remediation_accessor`, which
        discards a DERIVED row on purpose, finds no `__entry__` to fall back to and answers "Not
        recorded". That means "nothing tracks this field" and reads as a gap in the collection.
        """
        self.make_rows_with_findings()
        for _slug, _domain, spec, _category in TABS:
            table = build_findings_table(spec, tested=ALL_TESTED_COLUMNS)
            index = [h for h, _w, _wr in table.columns].index("Provenance")
            self.assertTrue(table.rows, f"{spec.sheet_title} drew no rows")
            for row in table.rows:
                with self.subTest(title=spec.sheet_title):
                    self.assertEqual(set(row[index].split("\n")), {"Derived"})

    def test_the_application_policy_mark_lands_on_the_verdict_not_the_graded_column(self):
        """STAGE 8 RECORDED THIS DISAGREEMENT and it is implemented as stage 8 wrote it: stage 6
        writes `fires_on` as the graded column `effective_action_for_function_apps` and the
        shipped query asserts on the boolean beside it. `implicated` marks a column only when its
        field is in the matched query's `asserted_fields`, so the graded column - the one that
        tells a customer what the rulebase ACTUALLY DOES - can never carry the fill. Writing a
        query that would change it is stage 8's work."""
        self.make_rows_with_findings()
        spec = _objects.SPEC_BY_TYPE["saas_application_policy_posture"]
        table = build_findings_table(spec, tested=ALL_TESTED_COLUMNS)
        headers = [h for h, _w, _wr in table.columns]
        marked = {headers[column] for _row, column in table.implicated}
        self.assertIn("Upload and sharing functions refused", marked)
        self.assertNotIn("Action on function apps", marked)

    def test_an_ha_pair_draws_one_posture_row_and_not_two(self):
        """STAGE 5 SAYS IT DRAWS TWO, on all four subjects, "and nothing downstream deduplicates
        them". It is wrong on the three enforcement-point models and there is nothing for a
        sheet to collapse: each declares `unique(enforcement_point)`, and an `EnforcementPoint`
        is itself unique per `(appliance_group, vsys_name)`, so an HA PAIR SHARES ONE POINT.
        Only `CloudAppEngineSetting` keys on the appliance and so draws a row per member."""
        self.group = self.point.appliance_group
        self.group.group_type = ApplianceGroup.TYPE_HA_PAIR
        self.group.active_appliance = self.appliance
        self.group.save(update_fields=["group_type", "active_appliance"])
        peer = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="013201008889", hostname="fw-sas-b")
        EnforcementNode.objects.create(management_station=self.station,
                                       enforcement_point=self.point, appliance=peer)
        for model in (SanctionedApplicationMarking, SaasUrlFilteringPosture,
                      SaasApplicationPolicyPosture):
            with self.subTest(model=model.__name__):
                (constraint,) = model._meta.constraints
                self.assertEqual(("enforcement_point",), tuple(constraint.fields))
        (constraint,) = CloudAppEngineSetting._meta.constraints
        self.assertEqual(("appliance",), tuple(constraint.fields))
        # The pair shares the one point, so one row is all the store can hold for it.
        self.assertEqual(2, self.point.nodes.count())
        self.assertEqual(1, EnforcementPoint.objects.filter(appliance_group=self.group).count())

    # ------------------------------------------------------------------ fixture

    def make_rows_with_findings(self):
        """One row of each model, each in a state that fires its control, plus the findings."""
        from assessments.finding_run import regenerate_findings

        SanctionedApplicationMarking.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, sanctioned_application_count=0,
            marked_application_names=[], appliance_is_multi_vsys=False,
            marking_is_inconsistent_across_vsys=False)
        SaasUrlFilteringPosture.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, url_filtering_profiles_read=True,
            header_insertion_type_entry_count=0, tenant_restriction_in_force=False,
            tenant_header_without_value_count=0, rule_bound_tenant_list_count=0,
            consumer_storage_category_treatment="alert",
            consumer_storage_categories_are_restricted=False)
        SaasApplicationPolicyPosture.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, function_app_rule_count=0,
            function_apps_are_refused=False, effective_action_for_function_apps="no-rule",
            cloud_app_filter_count=0, cloud_app_selection_is_refused=False,
            cloud_app_selection_excludes_approved=False)
        # `ace_failure_reason` is anything BUT `license_check_failed`, which the applicability
        # clause excludes: an unlicensed appliance is not misconfigured.
        CloudAppEngineSetting.objects.create(
            management_station=self.station, appliance=self.appliance, appliance_group=None,
            source_snapshot=self.snapshot, ace_disabled=None, cloudapp_node_read=False,
            ace_not_operational=True, ace_failure_reason="unread", cloudapp_server_address="")
        regenerate_findings()
