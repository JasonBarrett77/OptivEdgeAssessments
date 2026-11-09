"""The Data Filtering Posture tab, the three new rail items, and the SEVEN pages over one model.

Stage 9, `file-data-filtering`, 2026-11-02. PAN-FIL-001 to -004.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover tabs and rows generically:
every assertion here is a JUDGMENT this run made that nothing else in the repository states, and a
new tab nothing asserts on is one the next refactor can break silently.

  - `integrations.SecurityProfile` NOW HAS SEVEN PAGES and this domain added two of them on one
    day, which no earlier domain did. `object_for_canonical_query` keeps every candidate whose own
    scope clauses are a SUBSET of the query's and answers only when exactly one matched, so a scope
    that is too LOOSE matches alongside each sibling and pushes ALL SEVEN kinds to None. The five
    pages that already worked are what a wrong scope here breaks, which is why all seven are
    asserted and not just the two that are new.
  - ONE CONTROL WHOSE QUERIES SPAN TWO PAGES, which nothing in the catalog had before PAN-FIL-004.
    Its baseline is file-blocking and its second assertion is data-filtering, so the two queries
    resolve to two different pages while `control_results_url` - keyed on the baseline - lands on
    one of them. Both halves are asserted, because the useful statement is not "it resolves" but
    "it resolves to the page whose kind the query names, and the control's own link names only one".
  - that no heading on either tab this domain reports to reads as a raw Django field name FOR A
    FIELD THIS DOMAIN'S CONTROLS TEST. Nothing in either repository says which columns head raw; it
    is found by building the table and looking. The 37 raw headings belonging to the `decryption`
    and `url-filtering` controls on the shared tab are NOT asserted away here - they are not this
    run's to name - so this test is deliberately scoped to this domain's own fields and would pass
    while those stay raw.
  - the `reference_reach` CELL, which the inherited `setting_labels` comment claims carries the
    model's sentence and which printed the raw choice key until this run added a `ValueReader`.
  - the explorer `row` lambdas over real rows. The shipped check asserts a row is the same LENGTH
    as its columns and cannot see what a cell says - and the three cells here that are judgments
    are exactly the ones a length check cannot reach: a rule carrying no `action` key, a profile no
    rule sets a block threshold on, and a block threshold of 0 whose vendor meaning stage 4 could
    not settle.
  - that `profile_kinds.KINDS` STAYS AT FOUR. The by-rule tabs are not where these two kinds go,
    and the reason is the module's own: PAN-AVW-006 is "deliberately absent" because it is about a
    profile NO rule uses, "so there is no rule to report it on" and "a per-kind view for it would
    be empty by construction". PAN-FIL-004 is the same control shape over a different kind, so the
    same argument governs - which is what `zone-dos-protection` decided for both domains on
    2026-11-02, and this pins it rather than leaving it to a comment.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets import profile_kinds
from assessments.artifacts.sheets.findings import build_findings_table
from assessments.configuration_navigation import CATEGORIES, CONFIG_OBJECTS, objects_for_model
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, DataFilteringPosture, EnforcementNode, EnforcementPoint,
    ManagementStation, SecurityProfile, Snapshot)

#: Every control of this domain. The findings-tab tests SEED THESE and the reason is not
#: incidental: a derived settings column exists only because some control's query clauses on the
#: field, so `build_findings_table` over an unseeded catalog draws NO setting columns at all - and
#: a "no heading reads as a raw field name" assertion over that table passes vacuously.
PAN_FIL = ("PAN-FIL-001", "PAN-FIL-002", "PAN-FIL-003", "PAN-FIL-004")

#: Every kind this model is split by, with the rail slug each resolves to. SEVEN since 2026-11-02,
#: EIGHT later the same day (stage 9 of `url-filtering` added the `url-filtering` kind's page), and
#: NINE later still (stage 9 of `decryption-profiles` added the `decryption` kind's).
#: Each row is added HERE, in the vendor's own position, rather than this fixture being widened or
#: a second list kept beside it - the assertion below is on the exact list AND its order, so the
#: honest way to add a page is to put its row where the rail puts the item.
KINDS_AND_SLUGS = (
    ("spyware", "anti-spyware"),
    ("vulnerability", "vulnerability-protection"),
    ("virus", "antivirus"),
    # PAN-OS lists URL Filtering fourth, between Vulnerability Protection and File Blocking, and
    # the rail item was placed there - so it sorts here and not at the tail.
    ("url-filtering", "url-filtering"),
    ("file-blocking", "file-blocking"),
    ("wildfire-analysis", "wildfire-analysis"),
    ("data-filtering", "data-filtering"),
    ("dos-protection", "dos-protection"),
    # NINTH, 2026-11-02, by stage 9 of `decryption-profiles`. AT THE TAIL and not in the middle,
    # which is this fixture's own rule applied rather than an exception to it - the row goes where
    # the RAIL puts the item, and the rail puts it after the whole Security Profiles block because
    # PAN-OS does. Web Interface Help 11.1 p.213, 11.2 p.213 and 12.2 p.215 each enumerate the
    # Objects rail identically: "... Objects>Security Profiles ... Objects>Security Profile Groups
    # • Objects>Log Forwarding • Objects>Authentication • Objects>Decryption Profile • Objects >
    # SD-WAN Link Management • Objects>Schedules". So the decryption profile is not a Security
    # Profiles CHILD at all in any version we hold; it is a top-level Objects rail item that
    # follows them, which is why its `group` is "" and its row is last.
    ("decryption", "decryption-profile"),
)

#: The fields this domain's four controls test. The heading assertion below is scoped to these:
#: the other raw headings on the shared tab belong to other domains' controls.
OUR_FIELDS = (
    "is_predefined", "stops_floor_file_types", "floor_file_type_action",
    "confirm_rule_beyond_web_browsing", "stops_nested_encoding", "nested_encoding_action",
    "expresses_unopenable_file_decision", "reference_reach", "reference_reach_resolved",
    "outward_data_filtering_effective",
)


def kind_query(kind):
    return {"model": "integrations.SecurityProfile", "operator": "and",
            "clauses": [{"field": "kind", "op": "eq", "value": kind, "negated": False}]}


class SecurityProfileRailScopeTests(TestCase):
    """The seven pages over one model, and the subset rule that decides between them."""

    def test_every_kind_still_resolves_to_its_own_page(self):
        """ALL SEVEN, not just the two that are new: a too-loose scope breaks the other five."""
        for kind, slug in KINDS_AND_SLUGS:
            with self.subTest(kind=kind):
                obj = cr.object_for_canonical_query(kind_query(kind))
                self.assertIsNotNone(obj, f"{kind} resolves to no page")
                self.assertEqual(slug, obj.slug)

    def test_each_page_is_scoped_by_exactly_one_kind_clause(self):
        """Nothing looser. An empty scope is a subset of EVERY query over the model, so it would
        match beside each sibling, make `matched` two long and push all seven kinds to None."""
        for _kind, slug in KINDS_AND_SLUGS:
            with self.subTest(slug=slug):
                scope = cr.RESULTS[slug].scope
                self.assertIsNotNone(scope)
                clauses = scope["clauses"]
                self.assertEqual(1, len(clauses))
                self.assertEqual("kind", clauses[0]["field"])

    def test_the_seven_pages_are_the_only_ones_over_this_model(self):
        """And in this order, which is the rail's render order: the vendor lists File Blocking
        before WildFire Analysis and Data Filtering after it."""
        self.assertEqual(
            [slug for _kind, slug in KINDS_AND_SLUGS],
            [o.slug for o in objects_for_model("integrations.SecurityProfile")])

    def test_neither_new_kind_reaches_a_sibling_page(self):
        """The failure the resolver's own docstring names: a link that goes somewhere plausible
        and wrong is worse than no link."""
        for kind, slug in (("file-blocking", "file-blocking"),
                           ("data-filtering", "data-filtering")):
            with self.subTest(kind=kind):
                self.assertEqual(f"/assessments/configuration/objects/{slug}/",
                                 cr.query_results_url(kind_query(kind)))

    def test_the_posture_model_has_a_page_of_its_own(self):
        """A SECOND item at one vendor address over a DIFFERENT model - `rule-posture`'s pattern.
        It is not a second model on the `data-filtering` page: `RESULTS` is keyed on the slug
        alone, so one page cannot serve two models."""
        items = objects_for_model("integrations.DataFilteringPosture")
        self.assertEqual(["data-filtering-posture"], [o.slug for o in items])
        self.assertEqual("Objects > Security Profiles > Data Filtering", items[0].where)

    def test_the_posture_page_declares_no_kind_scope(self):
        """Its model has ONE page, so `object_for_canonical_query` short-circuits and a scope
        would be dead weight that a later second page would have to reckon with."""
        self.assertIsNone(cr.RESULTS["data-filtering-posture"].scope)

    def test_every_rail_slug_is_globally_unique(self):
        """`RESULTS` is keyed on the SLUG ALONE while `CONFIG_OBJECTS_BY_KEY` is keyed on
        (category, slug), so two items sharing a slug collapse onto one results spec. This domain
        put TWO items at one vendor address, which is where that would have happened."""
        slugs = [o.slug for o in CONFIG_OBJECTS]
        self.assertEqual(sorted(set(slugs)), sorted(slugs))

    def test_every_rail_item_claims_a_real_category(self):
        for obj in CONFIG_OBJECTS:
            with self.subTest(slug=obj.slug):
                self.assertIn(obj.category, CATEGORIES)

    def test_the_three_new_items_carry_a_vendor_path_and_a_results_spec(self):
        for slug, where in (("file-blocking", "Objects > Security Profiles > File Blocking"),
                            ("data-filtering", "Objects > Security Profiles > Data Filtering"),
                            ("data-filtering-posture",
                             "Objects > Security Profiles > Data Filtering")):
            with self.subTest(slug=slug):
                item = next(o for o in CONFIG_OBJECTS if o.slug == slug)
                self.assertEqual(where, item.where)
                self.assertIn(slug, cr.RESULTS)

    def test_this_domain_has_no_presentation_debt_left(self):
        """Clearing the prefix is part of this stage's job rather than a side effect of it: an
        exemption that survives the work it was waiting for is a permanent hole."""
        self.assertNotIn("PAN-FIL", cr.AWAITING_PRESENTATION)


class ControlQueriesSpanningTwoPagesTests(TestCase):
    """PAN-FIL-004, the first catalog control whose queries resolve to two different pages."""

    def setUp(self):
        (self.control,) = seed_controls(["PAN-FIL-004"])

    def test_its_two_assertion_queries_land_on_two_different_pages(self):
        pages = {}
        for query in self.control.queries.all():
            url = cr.query_results_url(query.canonical_query)
            if url:
                pages.setdefault(url, []).append(query.name)
        self.assertEqual(
            {"/assessments/configuration/objects/file-blocking/",
             "/assessments/configuration/objects/data-filtering/"},
            set(pages),
            f"expected both kinds' pages, got {pages}")

    def test_the_controls_own_link_lands_on_the_baselines_page_alone(self):
        """`control_results_url` is keyed on the declared target plus the BASELINE, and this
        control's baseline is the file-blocking half. So the control's "what would this report"
        link offers one of its two kinds and the other is reachable only from the query. That is
        correct - the baseline is what the control is keyed on - and it is worth asserting because
        a reader of the control page sees no sign that half of it is elsewhere."""
        baseline = self.control.queries.get(is_baseline=True)
        url = cr.control_results_url(self.control.target_model, baseline.canonical_query,
                                     control_pk=self.control.pk)
        # The `?control=` is how the page pre-loads the control's own query, so the assertion is
        # on the PATH: what this pins is which of the two kinds' pages the path names.
        self.assertEqual("/assessments/configuration/objects/file-blocking/", url.split("?")[0])
        self.assertNotIn("data-filtering", url)


class ProfileKindsStaysAtFourTests(TestCase):
    """The by-rule tabs are not where these two kinds go."""

    def test_the_by_rule_tabs_are_still_four_and_name_no_pan_fil_control(self):
        """`profile_kinds.KINDS` drives a findings domain per entry, so adding one would build a
        by-rule tab. A reference-reach control is about the PROFILE rather than a per-rule threat
        action, so such a tab is empty by construction - which is the module's own stated reason
        for leaving PAN-AVW-006 out, and PAN-FIL-004 is that control shape over another kind.
        Every by-rule tab also declares a 28-to-34 entry `hidden_fields`, the one known cause of a
        findings row that marks nothing (P409)."""
        self.assertEqual(4, len(profile_kinds.KINDS))
        self.assertEqual(
            ["antivirus", "anti-spyware", "vulnerability-protection", "wildfire-analysis"],
            [slug for slug, _t, _ids, _f in profile_kinds.KINDS])
        self.assertEqual((), tuple(c for c in profile_kinds.EVERY_PROFILE_CONTROL
                                   if c.startswith("PAN-FIL")))


class FileDataFilteringTabTests(TestCase):
    """The two tabs this domain reports to, built over a real estate."""

    @classmethod
    def setUpTestData(cls):
        cls.controls = seed_controls(PAN_FIL)
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

    def profile(self, name, kind, **cols):
        return SecurityProfile.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, name=name, kind=kind, namespace_type="local_vsys",
            namespace_value="vsys1", precedence_rank=10, config_source="local", description="",
            **cols)

    def posture(self, **cols):
        return DataFilteringPosture.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, enforcement_point=self.point,
            source_snapshot=self.snapshot, **cols)

    def row_for(self, slug, obj):
        return cr.RESULTS[slug].row(obj)

    def cells(self, slug, obj):
        spec = cr.RESULTS[slug]
        return dict(zip(spec.columns, spec.row(obj)))

    # ---- the explorer pages, over real rows -------------------------------------------------

    def test_a_rule_carrying_no_action_key_does_not_read_as_alert(self):
        """THE FOURTH CASE. Three actions exist - alert, continue, block - and an action key
        ABSENT from a committed rule is legal and was measured. Scoring the empty string as the
        schema default `alert` would tell an assessor the rule is known to deliver the file and
        log it, when what is known is nothing."""
        profile = self.profile("p-no-action", "file-blocking", rule_count=1, has_rules=True,
                               floor_file_type_action="", stops_floor_file_types=False)

        cells = self.cells("file-blocking", profile)

        self.assertEqual("no action set", cells["Weakest action on those file types"])
        self.assertNotIn("alert", cells["Weakest action on those file types"])

    def test_the_reference_reach_cell_is_the_models_sentence_and_not_the_choice_key(self):
        profile = self.profile("p-unref", "file-blocking", reference_reach="unreferenced")

        self.assertEqual("Nothing on this firewall names it",
                         self.cells("file-blocking", profile)["Reference reach"])

    def test_no_block_threshold_and_a_zero_one_are_different_cells(self):
        """Null means no rule of the profile sets a block count at all. ZERO is a count stage 4
        could not settle - the vendor's gloss makes it either "block every matching file" or
        "block nothing" - so it is printed with that said rather than as a bare 0, which a reader
        would take for the strictest setting there is."""
        none_set = self.profile("p-none", "data-filtering", lowest_block_threshold=None)
        zero = self.profile("p-zero", "data-filtering", lowest_block_threshold=0)

        self.assertEqual("no rule sets one",
                         self.cells("data-filtering", none_set)["Block Threshold"])
        self.assertEqual("0 (vendor meaning unsettled)",
                         self.cells("data-filtering", zero)["Block Threshold"])

    def test_a_point_nothing_watches_says_so_rather_than_showing_a_blank(self):
        """An empty evidence list beside a firing verdict is the honest pair the model's own
        docstring names. A blank cell would not say whether anyone looked."""
        row = self.posture(outward_data_filtering_effective=False, profiles_in_force=[])

        cells = self.cells("data-filtering-posture", row)

        # Lower case, because `_yes_no` is the EXPLORER's renderer and every page here answers
        # "yes"/"no". The findings tabs go through `display_value` instead and answer "Yes"/"No";
        # the two surfaces have always differed on this and it is not this run's to unify.
        self.assertEqual("no", cells["Outbound data watched"])
        self.assertEqual("Nothing reaches this traffic", cells["Profiles behind the verdict"])

    def test_every_queryable_heading_on_the_three_pages_names_a_registered_field(self):
        """A heading mapped to an unregistered field points the "build a query from these rows"
        button at a lookup that refuses itself or silently matches nothing. Stored, searchable and
        registered are three different things."""
        from assessments.search import registry
        for slug, model in (("file-blocking", "integrations.SecurityProfile"),
                            ("data-filtering", "integrations.SecurityProfile"),
                            ("data-filtering-posture", "integrations.DataFilteringPosture")):
            registered = registry.MODEL_REGISTRY[model]["field_operators"]
            for heading, field in cr.RESULTS[slug].query_fields.items():
                with self.subTest(slug=slug, heading=heading):
                    self.assertIn(field, registered)

    # ---- the findings tabs ------------------------------------------------------------------

    def test_the_posture_tab_builds_and_reports_its_control(self):
        self.posture(outward_data_filtering_effective=False)
        from assessments.finding_run import regenerate_findings
        regenerate_findings()

        table = build_findings_table(DOMAIN_BY_SLUG["data-filtering-posture"].spec)

        self.assertIn("PAN-FIL-003",
                      {row[table.headers.index("Control ID")] for row in table.rows})
        self.assertEqual("Objects", table.category)

    def test_the_posture_tab_says_its_verdict_is_derived_rather_than_unrecorded(self):
        """Every column of this model is in its `DERIVED_FIELDS` and no `FieldProvenance` row is
        ever written for it, so the DEFAULT provenance cell resolves through `remediation_accessor`
        - which discards a DERIVED row on purpose - falls back to an `__entry__` row nothing
        writes, and says "Not recorded". That means "nothing tracks this field" and reads to a
        customer as a gap in the collection. The value is not untracked; it is derived."""
        self.posture(outward_data_filtering_effective=False)
        from assessments.finding_run import regenerate_findings
        regenerate_findings()

        table = build_findings_table(DOMAIN_BY_SLUG["data-filtering-posture"].spec)

        self.assertEqual("Derived", table.rows[0][table.headers.index("Provenance")])

    def test_the_posture_tab_carries_the_firing_condition(self):
        """`tested_columns` defaults to `("Provenance",)`, which silently drops `Fires when` from
        the WORKBOOK while the live page keeps it, so the two surfaces disagree about which cell a
        reader meets (P427). Safe here in a way it is not on most tabs: this control ships ONE
        query, so the rendered condition is the clause that actually fired."""
        table = build_findings_table(DOMAIN_BY_SLUG["data-filtering-posture"].spec)

        self.assertIn("Fires when (failing condition)", table.headers)

    def test_no_field_this_domain_tests_heads_a_column_with_its_django_name(self):
        """DELIBERATELY SCOPED TO THIS DOMAIN'S FIELDS. The shared Security Profile tab carries 37
        other raw headings belonging to the `decryption` and `url-filtering` controls on the same
        model; those are not this run's to name and this test passes while they stay raw. What it
        pins is that none of OURS regressed - a heading lives in `setting_labels`, which falls back
        to the raw field name, so an entry deleted here is a database field name on a customer's
        report and nothing else would say so."""
        for slug in ("security-profiles", "data-filtering-posture"):
            table = build_findings_table(DOMAIN_BY_SLUG[slug].spec)
            for field in OUR_FIELDS:
                with self.subTest(slug=slug, field=field):
                    self.assertNotIn(field, table.headers)

    def test_the_posture_tab_hides_nothing(self):
        """The gate counts a field as presented if `hidden_fields` carries it, so a non-empty
        tuple is a CLAIM accepted as proof - and it is the only known cause in this repository of
        a findings row that marks nothing as the thing to fix (P409)."""
        self.assertEqual((), DOMAIN_BY_SLUG["data-filtering-posture"].spec.hidden_fields)
