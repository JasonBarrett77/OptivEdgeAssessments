"""The Custom URL Category tab, the two new rail items, and the EIGHT pages over one model.

Stage 9, `url-filtering`, 2026-11-02. PAN-URL-001 to -006 - six controls and 32 shipped queries,
the largest query count in its batch.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover tabs and rows generically:
every assertion here is a JUDGEMENT this run made that nothing else in the repository states, and a
new tab nothing asserts on is one the next refactor can break silently.

  - `integrations.SecurityProfile` NOW HAS EIGHT PAGES. `object_for_canonical_query` keeps every
    candidate whose own scope clauses are a SUBSET of the query's and answers only when exactly one
    matched, so a scope that is too LOOSE matches alongside each sibling and pushes ALL EIGHT kinds
    to None. The seven pages that already worked are what a wrong scope here breaks, which is why
    `test_file_data_filtering_presentation.KINDS_AND_SLUGS` gained this domain's row in the
    vendor's position rather than being widened - see that fixture. This module asserts the things
    that are THIS domain's own.
  - FIVE CONTROLS SHARING ONE PAGE, which is the shape no earlier domain over this model had:
    PAN-URL-001 to -005 all carry `kind eq "url-filtering"` and nothing else, so one rail item and
    one `ResultsSpec` serve all five and all 31 of their queries. PAN-FIL-004 was the opposite case
    - one control spanning two pages - and both are worth pinning because the resolver is the same.
  - THE SIXTEEN HEADINGS THIS DOMAIN NAMED. 16 of the shared tab's 35 headings read as raw Django
    field names before this run and ALL SIXTEEN were this domain's, measured by building the table
    and reading `FindingsTable.headers`. A heading lives in `setting_labels`, which falls back to
    the raw field name, so an entry deleted there is a database field name on a customer's report
    and nothing else would say so. These columns appear on EVERY kind's row, so the regression
    would also hit domains that never touched this code.
  - THAT LABELLING THE HEADINGS DOES NOT MAKE THE TAB CLEAN. `Fires when (failing condition)`
    builds its text from the clause's own FIELD NAME and consults `setting_labels` nowhere, so a
    heading grep is blind to it. Pinned here as the measured state, NOT as an aspiration: shared
    machinery, recorded rather than fixed.
  - the explorer `row` lambdas over real rows. The shipped check asserts a row is the same LENGTH
    as its columns and cannot see what a cell says - and the cells here that are judgements are
    exactly the ones a length check cannot reach: a verdict column that is NULL FOR TWO UNRELATED
    REASONS, a three-state engine flag whose NULL is the firing side, a request-header column whose
    empty string is the PASSING state, and a pushed `type` leaf read as the wrong shape.
  - that `profile_kinds.KINDS` STAYS AT FOUR. The by-rule tabs are not where this kind goes: a
    url-filtering profile carries no severity-matching rule list at all, so a per-rule view of it
    would be empty by construction - the module's own stated reason for leaving PAN-AVW-006 out,
    and the call `zone-dos-protection` and `file-data-filtering` both made before this.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets import profile_kinds
from assessments.artifacts.sheets.findings import ALL_TESTED_COLUMNS, build_findings_table
from assessments.configuration_navigation import CATEGORIES, CONFIG_OBJECTS, objects_for_model
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, CustomUrlCategory, EnforcementNode, EnforcementPoint,
    ManagementStation, SecurityProfile, Snapshot)

#: Every control of this domain. The findings-tab tests SEED THESE and the reason is not
#: incidental: a derived settings column exists only because some control's query clauses on the
#: field, so `build_findings_table` over an unseeded catalog draws NO setting columns at all - and
#: a "no heading reads as a raw field name" assertion over that table passes vacuously.
PAN_URL = ("PAN-URL-001", "PAN-URL-002", "PAN-URL-003", "PAN-URL-004", "PAN-URL-005",
           "PAN-URL-006")

#: The SIXTEEN fields this domain's five profile controls draw columns for, with the heading each
#: was given. Read off `FindingsTable.headers` rather than derived from stage 5: `tested_fields`
#: sorts the non-baseline queries alphabetically BY QUERY NAME, so what a calibration query is
#: CALLED decides a customer-facing column's position.
OUR_HEADINGS = {
    "all_hostile_categories_blocked": "Malware, phishing and command-and-control blocked",
    "weakest_hostile_category_action": "Weakest Site Access on those categories",
    "all_reachable_categories_logged": "Every reachable category logged",
    "worst_reachable_unlogged_category": "Worst unlogged category",
    "category_catalogue_collected": "Category list read from the device?",
    "credential_detection_mode": "User Credential Detection",
    "all_reachable_categories_credential_restricted":
        "Every reachable category restricts credential submission",
    "credential_submission_blocked_for_every_category":
        "Credential submission blocked on every category",
    "worst_credential_permissive_category": "Worst category accepting credentials",
    "records_all_request_headers": "All three HTTP headers logged",
    "worst_unrecorded_request_header": "Worst HTTP header not logged",
    "inline_analysis_exemption_count": "URL exceptions",
    "broadest_inline_analysis_exemption_type": "Broadest URL exception",
    "cloud_inline_categorization": "Cloud Inline Categorization",
    "local_inline_categorization_on": "Local Inline Categorization",
    "inline_analysis_exemptions_computed": "Exception list read from the device?",
}

#: PAN-URL-006's two clause fields, on the other model.
OUR_CATEGORY_HEADINGS = {
    "is_used": "Named by anything this assessment read",
    "category_type": "Type",
}


def kind_query(kind):
    return {"model": "integrations.SecurityProfile", "operator": "and",
            "clauses": [{"field": "kind", "op": "eq", "value": kind, "negated": False}]}


class UrlFilteringRailTests(TestCase):
    """The eighth page over the shared model, and the first over the category model."""

    def test_the_url_filtering_kind_resolves_to_its_own_page(self):
        obj = cr.object_for_canonical_query(kind_query("url-filtering"))
        self.assertIsNotNone(obj, "url-filtering resolves to no page")
        self.assertEqual("url-filtering", obj.slug)

    def test_it_reaches_no_sibling_page(self):
        """The failure the resolver's own docstring names: a link that goes somewhere plausible
        and wrong is worse than no link."""
        self.assertEqual("/assessments/configuration/objects/url-filtering/",
                         cr.query_results_url(kind_query("url-filtering")))

    def test_its_scope_is_exactly_one_kind_clause(self):
        """Nothing looser. An empty scope is a subset of EVERY query over this model, so it would
        match beside each of the seven siblings, make `matched` two long, and push all eight kinds
        to None - breaking the seven pages that already worked rather than only the new one."""
        scope = cr.RESULTS["url-filtering"].scope
        self.assertIsNotNone(scope)
        self.assertEqual(1, len(scope["clauses"]))
        self.assertEqual("kind", scope["clauses"][0]["field"])
        self.assertEqual("url-filtering", scope["clauses"][0]["value"])

    def test_all_pages_over_the_shared_model_still_resolve(self):
        """Measured over the whole model and not only this domain's kind. The sibling list lives
        in `test_file_data_filtering_presentation.KINDS_AND_SLUGS`, which this domain's row was
        added to; this asserts the COUNT independently so that deleting a row there to make a
        failure go away cannot pass both files.

        EIGHT when this was written, and NINE from 2026-11-02, when stage 9 of
        `decryption-profiles` added the `decryption` kind's page. The literal is BUMPED rather
        than the assertion widened, which is the whole point of keeping it: it is a second
        independent guard on the same fact, so a run adding a page has to say so in both files.
        The method name lost its number at the same time, because a name carrying a count has to
        be renamed on every addition and a reader greps the number rather than the fact."""
        items = objects_for_model("integrations.SecurityProfile")
        self.assertEqual(9, len(items))
        self.assertIn("url-filtering", [o.slug for o in items])
        for obj in items:
            with self.subTest(slug=obj.slug):
                scope = cr.RESULTS[obj.slug].scope
                self.assertIsNotNone(scope, f"{obj.slug} has no kind scope")
                self.assertEqual(1, len(scope["clauses"]))
                kind = scope["clauses"][0]["value"]
                self.assertEqual(obj.slug, cr.object_for_canonical_query(kind_query(kind)).slug)

    def test_the_category_model_has_a_page_of_its_own(self):
        items = objects_for_model("integrations.CustomUrlCategory")
        self.assertEqual(["custom-url-categories"], [o.slug for o in items])
        self.assertEqual("Objects > Custom Objects > URL Category", items[0].where)

    def test_the_category_page_declares_no_kind_scope(self):
        """Its model has ONE page, so `object_for_canonical_query` short-circuits and a scope
        would be dead weight a later second page would have to reckon with."""
        self.assertIsNone(cr.RESULTS["custom-url-categories"].scope)

    def test_both_new_items_carry_a_vendor_path_and_a_results_spec(self):
        for slug, where in (("url-filtering", "Objects > Security Profiles > URL Filtering"),
                            ("custom-url-categories",
                             "Objects > Custom Objects > URL Category")):
            with self.subTest(slug=slug):
                item = next(o for o in CONFIG_OBJECTS if o.slug == slug)
                self.assertEqual(where, item.where)
                self.assertIn(slug, cr.RESULTS)
                self.assertIn(item.category, CATEGORIES)

    def test_the_custom_objects_group_sits_before_security_profiles(self):
        """PAN-OS lists Custom Objects above Security Profiles in the Objects tree, and `group`s
        render in the order their first object appears. Adding a group ahead of an existing one
        rearranges no existing item relative to any other, which is the line `dos-protection` and
        `file-blocking` drew when they declined to reorder the four older profile items."""
        groups = []
        for obj in CONFIG_OBJECTS:
            if obj.category == "Objects" and obj.group and obj.group not in groups:
                groups.append(obj.group)
        self.assertLess(groups.index("Custom Objects"), groups.index("Security Profiles"))

    def test_every_rail_slug_is_globally_unique(self):
        """`RESULTS` is keyed on the SLUG ALONE while `CONFIG_OBJECTS_BY_KEY` is keyed on
        (category, slug), so two items sharing a slug collapse onto one results spec. This domain
        gave a rail item the same slug as a profile KIND, which is where that would have bitten."""
        slugs = [o.slug for o in CONFIG_OBJECTS]
        self.assertEqual(sorted(set(slugs)), sorted(slugs))

    def test_this_domain_has_no_presentation_debt_left(self):
        """Clearing the prefix is part of this stage's job rather than a side effect of it: an
        exemption that survives the work it was waiting for is a permanent hole. Thirty-two
        queries rode on this one."""
        self.assertNotIn("PAN-URL", cr.AWAITING_PRESENTATION)

    def test_every_queryable_heading_on_the_two_new_pages_names_a_registered_field(self):
        """A heading mapped to an unregistered field points the "build a query from these rows"
        button at a lookup that refuses itself or silently matches nothing. Stored, searchable and
        registered are three different things."""
        from assessments.search import registry
        for slug, model in (("url-filtering", "integrations.SecurityProfile"),
                            ("custom-url-categories", "integrations.CustomUrlCategory")):
            registered = registry.MODEL_REGISTRY[model]["field_operators"]
            for heading, field in cr.RESULTS[slug].query_fields.items():
                with self.subTest(slug=slug, heading=heading):
                    self.assertIn(field, registered)

    def test_the_user_agent_header_is_not_offered_as_a_query(self):
        """MEASURED, not assumed: the compiler registers `log_http_header_referer` and
        `log_http_header_xff` and NOT `log_http_header_user_agent`. The three headers reach the
        page through `records_all_request_headers` and `worst_unrecorded_request_header`, both
        registered. A heading mapped to the user-agent key would refuse itself."""
        self.assertNotIn("log_http_header_user_agent",
                         cr.RESULTS["url-filtering"].query_fields.values())


class ProfileKindsStaysAtFourTests(TestCase):
    """The by-rule tabs are not where this kind goes."""

    def test_the_by_rule_tabs_are_still_four_and_name_no_pan_url_control(self):
        """`profile_kinds.KINDS` drives a findings domain per entry, so adding one would build a
        by-rule tab. A url-filtering profile carries no severity-matching rule list at all - its
        decisions are per CATEGORY, not per threat rule - so such a tab would be empty by
        construction, which is the module's own stated reason for leaving PAN-AVW-006 out."""
        self.assertEqual(4, len(profile_kinds.KINDS))
        self.assertEqual(
            ["antivirus", "anti-spyware", "vulnerability-protection", "wildfire-analysis"],
            [slug for slug, _t, _ids, _f in profile_kinds.KINDS])
        self.assertEqual((), tuple(c for c in profile_kinds.EVERY_PROFILE_CONTROL
                                   if c.startswith("PAN-URL")))


class UrlFilteringEstateTests(TestCase):
    """Both tabs and both explorer pages, over a real estate."""

    @classmethod
    def setUpTestData(cls):
        cls.controls = seed_controls(PAN_URL)
        station = ManagementStation.objects.create(
            station_type="panorama", name="t", hostname="t", username="u", password="p",
            ca_bundle_path="", notes="")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g", discovery_key="g", notes="")
        cls.appliance = Appliance.objects.create(
            management_station=station, appliance_group=group, hostname="fw-a",
            serial_number="S1", model="PA-VM", software_version="11.2.5",
            device_certificate_status="valid", notes="")
        group.active_appliance = cls.appliance
        group.save()
        # `EnforcementPoint.in_scope` DEFAULTS FALSE and the shared-scope normalisers filter on
        # it, so a hand-seeded estate normalises zero shared objects without this.
        cls.point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, appliance=cls.appliance,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True, discovery_key="k",
            notes="")
        # `EnforcementNode` rows are required or the whole workbook refuses to build.
        EnforcementNode.objects.create(management_station=station, enforcement_point=cls.point,
                                       appliance=cls.appliance, notes="")
        # `source_snapshot` is NOT NULL on both of this domain's models.
        cls.snapshot = Snapshot.objects.create(
            management_station=station, appliance=cls.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        cls.station = station
        cls.group = group

    def profile(self, name, **cols):
        return SecurityProfile.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, name=name, kind="url-filtering",
            namespace_type="local_vsys", namespace_value="vsys1", precedence_rank=10,
            config_source="local", description="", **cols)

    def category(self, name, **cols):
        return CustomUrlCategory.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, name=name, namespace_type="local_vsys",
            namespace_value="vsys1", precedence_rank=10, config_source="local", **cols)

    def cells(self, slug, obj):
        spec = cr.RESULTS[slug]
        return dict(zip(spec.columns, spec.row(obj)))

    # ---- the explorer pages, over real rows -------------------------------------------------

    def test_the_two_reasons_a_worst_category_cell_is_blank_are_different_cells(self):
        """THE JUDGEMENT THIS PAGE EXISTS TO PIN. `worst_reachable_unlogged_category` is NULL both
        when the category catalogue was never read and when every reachable category IS logged -
        one is "nobody looked" and the other is "nothing is wrong", and the stored value cannot
        tell them apart. The companion column is the only thing that can. On a real estate the
        first case is EVERY row, because stage 5 records that the operational catalogue read is
        issued by no collector, so printing one word for both would make the whole tab reassuring
        on the strength of nothing."""
        never_read = self.profile("p-unread", category_catalogue_collected=False,
                                  worst_reachable_unlogged_category=None)
        all_logged = self.profile("p-clean", category_catalogue_collected=True,
                                  worst_reachable_unlogged_category=None)

        self.assertEqual("category list not read",
                         self.cells("url-filtering", never_read)["Worst unlogged category"])
        self.assertEqual("None",
                         self.cells("url-filtering", all_logged)["Worst unlogged category"])

    def test_a_weakest_action_cell_does_not_read_as_an_action_when_nothing_was_read(self):
        """`weakest_hostile_category_action` is null EXACTLY when the catalogue was never read, so
        the set has no members to rank. `(none)`, which the shared findings renderer can say,
        would read as an action the profile holds."""
        profile = self.profile("p-null", category_catalogue_collected=False,
                               weakest_hostile_category_action=None)

        cell = self.cells("url-filtering", profile)["Weakest Site Access on those categories"]
        self.assertEqual("category list not read", cell)

    def test_the_on_box_engine_has_three_states_and_not_two(self):
        """`local_inline_categorization` is nullable and NULL is the FIRING side: on a PA-VM an
        absent key means the engine is ON, and elsewhere nobody established what it means - so
        `local_inline_categorization_on` is False both for "switched off" and for "never
        established". Printing a bare "no" for the second would report a configuration state this
        assessment never read."""
        off = self.profile("p-off", local_inline_categorization_on=False,
                           local_inline_categorization_undetermined=False)
        unknown = self.profile("p-unknown", local_inline_categorization_on=False,
                               local_inline_categorization_undetermined=True)

        self.assertEqual("no", self.cells("url-filtering", off)["Local Inline Categorization"])
        self.assertEqual("not read",
                         self.cells("url-filtering", unknown)["Local Inline Categorization"])

    def test_the_passing_state_of_the_header_column_is_named_rather_than_blank(self):
        """The store holds "" when every header IS logged, which is the PASSING state. An empty
        cell there would be the most reassuring thing on the row and would read as missing data -
        the exact failure Jason caught once already, where "the most reassuring cell on the row
        was the finding"."""
        clean = self.profile("p-hdr", records_all_request_headers=True,
                             worst_unrecorded_request_header="")

        self.assertEqual("None missing",
                         self.cells("url-filtering", clean)["Worst HTTP header not logged"])

    def test_an_exemption_naming_an_unread_category_is_not_reported_as_no_exemption(self):
        """`broadest_inline_analysis_exemption_type` is null both when there are NO exemptions and
        when an exemption's target category row is missing, which is the estate where the
        categories are in force through the pushed read and nobody issued it. The COUNT separates
        them."""
        none = self.profile("p-noex", inline_analysis_exemption_count=0,
                            broadest_inline_analysis_exemption_type=None)
        unread = self.profile("p-unread-ex", inline_analysis_exemption_count=1,
                              broadest_inline_analysis_exemption_type=None)

        self.assertEqual("Nothing exempted",
                         self.cells("url-filtering", none)["Broadest URL exception"])
        self.assertEqual("Exempted category not read",
                         self.cells("url-filtering", unread)["Broadest URL exception"])

    def test_the_credential_mode_cell_carries_the_vendors_sentence_on_this_page(self):
        """The field has no `choices`, so the findings tab prints the device's own key. That is a
        REFUSAL there and not an omission - see `CREDENTIAL_DETECTION_LABELS` - because a
        `value_readers` entry would discard the column's `FieldProvenance` row and hide whether
        the credential node was ABSENT or explicitly disabled. Here the cell is this module's own
        lambda and costs no provenance, so it carries the vendor's label."""
        profile = self.profile("p-cred", credential_detection_mode="ip-user")

        self.assertEqual("Use IP User Mapping",
                         self.cells("url-filtering", profile)["User Credential Detection"])

    def test_a_pushed_type_leaf_read_as_the_wrong_shape_says_so(self):
        """The `type` key is MANDATORY at commit validation, so a committed entry has no absent
        state - but on a PUSHED entry the value reads as a DICT, and blank therefore means the row
        came from somewhere that read that dict as a bare string. That is a collection fault worth
        naming, not a configuration state."""
        unread = self.category("c-pushed", category_type="")

        self.assertEqual("not read (pushed-value shape)",
                         self.cells("custom-url-categories", unread)["Type"])

    def test_a_member_count_nobody_read_is_not_a_count_of_zero(self):
        """`match_entry_count` is nullable for one reason: the list was never read. A category
        whose list is empty stores 0, and the two must not share a cell."""
        unread = self.category("c-unread", match_entry_count=None,
                               match_entry_count_computed=False)
        empty = self.category("c-empty", match_entry_count=0, match_entry_count_computed=True)

        self.assertEqual("not read", self.cells("custom-url-categories", unread)["Members"])
        self.assertEqual(0, self.cells("custom-url-categories", empty)["Members"])

    def test_the_reference_denominator_is_on_the_explorer_row(self):
        """Stage 5 requires it: this column must be "presented beside every finding so that
        `unreferenced` is never printed without its denominator". The walk reads TWELVE surfaces,
        while the vendor documents FOUR rulebases that can match on a URL category and this
        project's normalizer collects TWO - so an `unreferenced` verdict with no denominator beside
        it would read as a removal instruction, which this control's own docstring forbids."""
        row = self.category("c-unref", is_used=False, referrer_count=0,
                            reference_surfaces_searched=list(
                                CustomUrlCategory.REFERENCE_SURFACES))

        cells = self.cells("custom-url-categories", row)
        self.assertEqual("no", cells["Named by anything this assessment read"])
        self.assertEqual("Nothing", cells["Referring surfaces"])
        self.assertEqual("12 surface(s)", cells["Referring surfaces searched"])

    def test_the_companion_column_is_drawn_before_the_verdict_on_the_explorer_page(self):
        """This module controls its own column order, unlike the derived settings columns on the
        findings tab - where `tested_fields` sorts calibration queries alphabetically by query
        NAME and puts both companions AFTER the verdicts they qualify. Here a reader meets "was
        this established?" before "what did it establish?"."""
        columns = list(cr.RESULTS["url-filtering"].columns)
        self.assertLess(columns.index("Category list read from the device?"),
                        columns.index("Worst unlogged category"))
        self.assertLess(columns.index("Exception list read from the device?"),
                        columns.index("Broadest URL exception"))

    # ---- the findings tabs ------------------------------------------------------------------

    def test_the_category_tab_builds_and_reports_its_control(self):
        self.category("c-unref", is_used=False, category_type="URL List",
                      match_entry_count=1, match_entry_count_computed=True)
        from assessments.finding_run import regenerate_findings
        regenerate_findings()

        table = build_findings_table(DOMAIN_BY_SLUG["custom-url-categories"].spec)

        self.assertIn("PAN-URL-006",
                      {row[table.headers.index("Control ID")] for row in table.rows})
        self.assertEqual("Objects", table.category)
        self.assertEqual("Custom URL Category", table.title)

    def test_the_category_tab_hides_nothing(self):
        """The gate counts a field as presented if `hidden_fields` carries it, so a non-empty
        tuple is a CLAIM accepted as proof - and it is the only known cause in this repository of
        a findings row that marks nothing as the thing to fix (P409)."""
        self.assertEqual((), DOMAIN_BY_SLUG["custom-url-categories"].spec.hidden_fields)

    def test_the_category_tab_carries_the_firing_condition_in_the_workbook_too(self):
        """`tested_columns` defaults to `("Provenance",)`, which keeps `Fires when` on the live
        page and silently DROPS it from the xlsx, so the two surfaces disagree about which cell a
        reader meets (P427). Carrying it is safe here in a way it is not on most tabs: this
        control's baseline is the clause that fires on every row this tab draws."""
        table = build_findings_table(DOMAIN_BY_SLUG["custom-url-categories"].spec)

        self.assertIn("Fires when (failing condition)", table.headers)

    def test_the_shared_profile_tab_drops_the_firing_condition_from_the_workbook(self):
        """THE MEASURED STATE AND NOT AN ASPIRATION. The shared spec leaves `tested_columns` at
        its default, so the shared tab shows `Fires when` on the live page and NOT in the
        workbook. This domain did not change that: the spec serves five other domains' controls
        and altering it would add a column to their xlsx tabs too. Pinned so that the difference
        between the two surfaces is a recorded fact rather than a surprise."""
        workbook = build_findings_table(DOMAIN_BY_SLUG["security-profiles"].spec)
        live = build_findings_table(DOMAIN_BY_SLUG["security-profiles"].spec,
                                    tested=ALL_TESTED_COLUMNS)

        self.assertNotIn("Fires when (failing condition)", workbook.headers)
        self.assertIn("Fires when (failing condition)", live.headers)

    def test_no_field_this_domain_tests_heads_a_column_with_its_django_name(self):
        """SIXTEEN headings on the shared tab and TWO on this domain's own. A heading lives in
        `setting_labels`, which falls back to the raw field name, so an entry deleted there is a
        database field name on a customer's report and nothing else would say so.

        DELIBERATELY SCOPED TO THIS DOMAIN'S FIELDS. The shared tab still carries the `decryption`
        controls' raw headings; those are not this run's to name and this test passes while they
        stay raw.
        """
        profile_tab = build_findings_table(DOMAIN_BY_SLUG["security-profiles"].spec,
                                           tested=ALL_TESTED_COLUMNS)
        for field, heading in OUR_HEADINGS.items():
            with self.subTest(field=field):
                self.assertNotIn(field, profile_tab.headers)
                self.assertIn(heading, profile_tab.headers)

        category_tab = build_findings_table(DOMAIN_BY_SLUG["custom-url-categories"].spec)
        for field, heading in OUR_CATEGORY_HEADINGS.items():
            with self.subTest(field=field):
                self.assertNotIn(field, category_tab.headers)
                self.assertIn(heading, category_tab.headers)

    def test_the_stated_condition_still_speaks_in_field_names(self):
        """THE DEFECT LABELLING THE HEADINGS DOES NOT FIX, and the reason a heading grep is not
        evidence of a clean tab. `render_node` ends by returning
        `f"{node['field']} {op} {display_value(node['value'])}"` and consults `setting_labels`
        NOWHERE, so every `Fires when` cell on this domain's rows prints the raw Django field name
        even though all sixteen headings above it are now English.

        PINNED AS THE MEASURED STATE. Shared machinery - `fires_when` and `render_node` serve
        every findings tab in the repository - so this run recorded it rather than fixing it. If
        somebody teaches `render_node` the labels, this test is the one that should fail and be
        deleted.
        """
        self.category("c-unref", is_used=False, category_type="URL List")
        from assessments.finding_run import regenerate_findings
        regenerate_findings()

        table = build_findings_table(DOMAIN_BY_SLUG["custom-url-categories"].spec)
        conditions = {row[table.headers.index("Fires when (failing condition)")]
                      for row in table.rows}

        self.assertTrue(conditions, "no rows, so nothing was measured")
        self.assertTrue(all("is_used" in c for c in conditions),
                        f"expected the raw field name in every condition, got {conditions}")
        self.assertFalse(any(OUR_CATEGORY_HEADINGS["is_used"] in c for c in conditions),
                         "the stated condition now uses the heading - delete this test")

    # ---- the two value readers, and what they do to the other six kinds -----------------------

    def tab_cells(self, obj_name, control):
        """One row of the shared findings tab, as the LIVE page draws it."""
        table = build_findings_table(DOMAIN_BY_SLUG["security-profiles"].spec,
                                     tested=ALL_TESTED_COLUMNS)
        ci = table.headers.index("Control ID")
        oi = table.headers.index("Object")
        for row in table.rows:
            if row[oi] == obj_name and row[ci] == control:
                return dict(zip(table.headers, row))
        raise AssertionError(f"no {control} row for {obj_name}")

    def test_the_passing_header_state_is_named_on_the_findings_tab_too(self):
        """THE CELL THIS READER EXISTS FOR. The store holds "" when all three request headers ARE
        logged, and `display_value` has only `(empty)` for that - so before this reader the tab
        printed `(empty)` on exactly the rows where nothing was wrong, which reads as "nobody
        collected this". Measured on this domain's own rows before the fix: 2 of 21.

        The reader is free because `worst_unrecorded_request_header` is in
        `SecurityProfile.DERIVED_FIELDS` and carries no `FieldProvenance` row to discard."""
        self.profile("p-pass", records_all_request_headers=True,
                     worst_unrecorded_request_header="",
                     # fire ANOTHER control so the row exists at all
                     all_hostile_categories_blocked=False,
                     weakest_hostile_category_action="allow",
                     category_catalogue_collected=True)
        from assessments.finding_run import regenerate_findings
        regenerate_findings()

        cells = self.tab_cells("p-pass", "PAN-URL-001")

        self.assertEqual("None missing", cells["Worst HTTP header not logged"])
        self.assertNotIn("(empty)", cells["Worst HTTP header not logged"])

    def test_the_two_reasons_the_exemption_type_is_null_are_different_cells_on_the_tab(self):
        """`display_value` answers `(none)` for both "nothing is exempted" and "an exemption names
        a category this assessment never read". Measured before the fix: `(none)` on 15 of 21
        rows, 13 of which exempt nothing at all."""
        self.profile("p-noex", inline_analysis_exemption_count=0,
                     broadest_inline_analysis_exemption_type=None,
                     all_hostile_categories_blocked=False,
                     weakest_hostile_category_action="allow",
                     category_catalogue_collected=True)
        self.profile("p-unread-ex", inline_analysis_exemption_count=1,
                     broadest_inline_analysis_exemption_type=None,
                     all_hostile_categories_blocked=False,
                     weakest_hostile_category_action="allow",
                     category_catalogue_collected=True)
        from assessments.finding_run import regenerate_findings
        regenerate_findings()

        self.assertEqual("Nothing exempted",
                         self.tab_cells("p-noex", "PAN-URL-001")["Broadest URL exception"])
        self.assertEqual("Exempted category not read",
                         self.tab_cells("p-unread-ex", "PAN-URL-001")["Broadest URL exception"])

    def test_the_other_six_kinds_get_the_em_dash_and_not_a_sentence_about_http_headers(self):
        """THE COST OF PUTTING A READER ON A SHARED COLUMN, stated as a test. This spec serves
        seven profile kinds; these two columns are derived from THIS domain's clauses and so
        appear on every kind's row while meaning something on one. A reader that answered
        unconditionally would tell a customer that their antivirus profile logs all three HTTP
        request headers.

        So both readers branch on `kind` and return `layout.NONE` - the em dash, U+2014 - for
        every other kind, which is the sanctioned vocabulary for "this branch does not exist on
        this subject". That is strictly more honest than the `(empty)`/`(none)` those rows showed
        before, and it is the one thing this domain changed about another domain's cells.

        IT ALSO MAKES THE EM-DASH ESCAPE REACHABLE ON A MULTI-KIND MODEL, which the stage 9
        contract's finding 4 says it is not: `setting_columns` consults `value_readers` BEFORE
        `display_value`, so a reader branching on the row's own kind reaches the state per KIND
        rather than per MODEL."""
        from assessments.artifacts.layout import NONE
        self.assertEqual("—", NONE, "layout.NONE is not the em dash any more")

        # An ANTIVIRUS profile on the same shared tab, firing an antivirus control's own clause.
        SecurityProfile.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, name="av-1", kind="virus",
            namespace_type="local_vsys", namespace_value="vsys1", precedence_rank=10,
            config_source="local", description="", is_used=False)
        self.profile("p-url", all_hostile_categories_blocked=False,
                     weakest_hostile_category_action="allow", category_catalogue_collected=True,
                     worst_unrecorded_request_header="X-Forwarded-For")
        from assessments.finding_run import regenerate_findings
        regenerate_findings()

        table = build_findings_table(DOMAIN_BY_SLUG["security-profiles"].spec,
                                     tested=ALL_TESTED_COLUMNS)
        oi = table.headers.index("Object")
        hi = table.headers.index("Worst HTTP header not logged")
        ei = table.headers.index("Broadest URL exception")
        by_object = {row[oi]: row for row in table.rows}

        self.assertIn("p-url", by_object, "the url-filtering row did not draw")
        self.assertEqual("X-Forwarded-For", by_object["p-url"][hi])
        for name, row in by_object.items():
            if name == "p-url":
                continue
            with self.subTest(object=name):
                self.assertEqual(NONE, row[hi])
                self.assertEqual(NONE, row[ei])
