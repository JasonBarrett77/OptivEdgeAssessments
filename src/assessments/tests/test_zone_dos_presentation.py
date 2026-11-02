"""The two zone/DoS findings tabs and the three rail items, pinned. Stage 9, `zone-dos-protection`.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover the tabs generically: every
assertion here is a JUDGEMENT this run made that nothing else in the repository states, and a new
tab nothing asserts on is one the next refactor can break silently.

  - the FIFTH rail item over `integrations.SecurityProfile`, and the thing that makes it safe:
    `object_for_canonical_query` keeps every candidate whose scope clauses are a SUBSET of the
    query's and answers only when exactly one matched, so a scope that is too LOOSE matches
    alongside each sibling and pushes ALL FIVE kinds to None. The four pages that already worked
    are what a wrong scope here breaks, which is why all five are asserted and not just the new one.
  - that no heading on any tab this domain reports to reads as a raw Django field name. Nothing in
    either repository says which columns head raw; it is found by building the table and looking.
  - the explorer `row` lambdas, over real rows. The shipped check asserts a row is the same LENGTH
    as its columns and cannot see what a cell says.
  - the em dash for a branch that does not exist on this subject, which `display_value` cannot say.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets.findings import build_findings_table
from assessments.configuration_navigation import CATEGORIES, CONFIG_OBJECTS, objects_for_model
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, DosPolicyRule, EnforcementNode, EnforcementPoint,
    ManagementStation, Snapshot, ZoneProtectionProfile)

#: Every control of this domain. The findings-tab tests SEED THESE and the reason is not
#: incidental: a derived settings column exists only because some control's query clauses on the
#: field, so `build_findings_table` over an unseeded catalog draws NO setting columns at all -
#: and a "no heading reads as a raw field name" assertion over that table passes vacuously. The
#: first version of this file did exactly that and proved nothing.
PAN_ZON = tuple(f"PAN-ZON-{n:03d}" for n in range(1, 9))

KINDS_AND_SLUGS = (
    ("spyware", "anti-spyware"),
    ("vulnerability", "vulnerability-protection"),
    ("virus", "antivirus"),
    ("wildfire-analysis", "wildfire-analysis"),
    ("dos-protection", "dos-protection"),
)


def kind_query(kind):
    return {"model": "integrations.SecurityProfile", "operator": "and",
            "clauses": [{"field": "kind", "op": "eq", "value": kind, "negated": False}]}


class SecurityProfileRailScopeTests(TestCase):
    """The five pages over one model, and the subset rule that decides between them."""

    def test_every_kind_still_resolves_to_its_own_page(self):
        """ALL FIVE, not just the new one: a too-loose scope breaks the other four."""
        for kind, slug in KINDS_AND_SLUGS:
            with self.subTest(kind=kind):
                obj = cr.object_for_canonical_query(kind_query(kind))
                self.assertIsNotNone(obj, f"{kind} resolves to no page")
                self.assertEqual(slug, obj.slug)

    def test_each_page_is_scoped_by_exactly_one_kind_clause(self):
        """Nothing looser. An empty scope is a subset of EVERY query over the model, so it would
        match beside each sibling, make `matched` two long and push all five kinds to None."""
        for _kind, slug in KINDS_AND_SLUGS:
            with self.subTest(slug=slug):
                scope = cr.RESULTS[slug].scope
                self.assertIsNotNone(scope)
                clauses = scope["clauses"]
                self.assertEqual(1, len(clauses))
                self.assertEqual("kind", clauses[0]["field"])

    def test_this_domains_page_is_among_the_pages_over_this_model(self):
        """IT WAS `test_the_five_pages_are_the_only_ones_over_this_model` and it held the whole
        list as a literal, so it failed the moment `file-data-filtering` added File Blocking and
        Data Filtering on 2026-11-02 - which is a page being ADDED correctly, not this domain's
        page breaking. Renamed and narrowed to what this file is actually about: that this
        domain's own kind still has exactly one page and it is the right one. The "these are ALL
        of them, in this order" assertion moved to
        `tests/test_file_data_filtering_presentation.py::test_the_seven_pages_are_the_only_ones_
        over_this_model`, which is where the next domain to add a kind will find it - one list in
        one place rather than a literal in every domain's test file."""
        slugs = [o.slug for o in objects_for_model("integrations.SecurityProfile")]
        self.assertEqual(["dos-protection"], [s for s in slugs if s == "dos-protection"])
        for _kind, slug in KINDS_AND_SLUGS:
            with self.subTest(slug=slug):
                self.assertIn(slug, slugs)

    def test_a_dos_protection_query_does_not_reach_a_sibling_page(self):
        """The failure the docstring of the resolver names: a link that goes somewhere plausible
        and wrong is worse than no link."""
        url = cr.query_results_url(kind_query("dos-protection"))
        self.assertEqual("/assessments/configuration/objects/dos-protection/", url)


class ZoneDosRailItemTests(TestCase):
    """The three rail items this domain needed, and the slug collision that nearly happened."""

    def test_each_new_model_has_exactly_one_page(self):
        for label, slug in (("integrations.ZoneProtectionProfile", "zone-protection"),
                            ("integrations.DosPolicyRule", "dos-protection-rules")):
            with self.subTest(model=label):
                items = objects_for_model(label)
                self.assertEqual(1, len(items))
                self.assertEqual(slug, items[0].slug)

    def test_the_zone_item_is_reused_and_not_duplicated(self):
        """`integrations.Zone` is shared with two earlier domains. This one reuses their item."""
        self.assertEqual(["zones"], [o.slug for o in objects_for_model("integrations.Zone")])

    def test_every_rail_slug_is_globally_unique(self):
        """`CONFIG_OBJECTS_BY_KEY` is keyed on (category, slug) and reads as a licence to reuse a
        slug across categories - but `RESULTS` is keyed on the SLUG ALONE, so two items sharing
        one would collapse onto a single results spec. The DoS profile and the DoS rulebase are
        the first pair the vendor gives the same label, which is why this is asserted."""
        slugs = [o.slug for o in CONFIG_OBJECTS]
        self.assertEqual(sorted(set(slugs)), sorted(slugs))

    def test_every_rail_item_claims_a_real_category(self):
        for obj in CONFIG_OBJECTS:
            with self.subTest(slug=obj.slug):
                self.assertIn(obj.category, CATEGORIES)

    def test_both_new_items_carry_a_vendor_path_and_a_results_spec(self):
        for slug, where in (("zone-protection", "Network > Network Profiles > Zone Protection"),
                            ("dos-protection-rules", "Policies > DoS Protection"),
                            ("dos-protection",
                             "Objects > Security Profiles > DoS Protection")):
            with self.subTest(slug=slug):
                obj = next(o for o in CONFIG_OBJECTS if o.slug == slug)
                self.assertEqual(where, obj.where)
                self.assertIn(slug, cr.RESULTS)


class ZoneDosResultsRowTests(TestCase):
    """The explorer rows, over real objects. The shipped squareness check cannot read a cell."""

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_FIREWALL, hostname="fw.zdp")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-zdp",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="013201007777", hostname="fw-zdp-a")
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group,
            appliance=self.appliance, vsys_name="vsys1", vsys_display_name="vsys1",
            in_scope=True)
        EnforcementNode.objects.create(management_station=self.station,
                                       enforcement_point=self.point, appliance=self.appliance)
        # `source_snapshot` is NOT NULL on both of this domain's models, so a row cannot be
        # built without one.
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

    def row_for(self, slug, obj):
        spec = cr.RESULTS[slug]
        row = spec.row(obj)
        self.assertEqual(len(spec.columns), len(row))
        return dict(zip(spec.columns, row))

    def test_a_profile_no_zone_names_says_nothing_rather_than_zero(self):
        """"Nothing" and not 0: a bare zero in a count column reads as "not counted" exactly
        where it means "counted, and no zone names this profile"."""
        profile = ZoneProtectionProfile.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_snapshot=self.snapshot, profile_name="p-unattached", attached_zone_count=0, is_in_force=False)

        cells = self.row_for("zone-protection", profile)

        self.assertEqual("Nothing", cells["Zones attached"])
        self.assertEqual("no", cells["In force"])

    def test_a_profile_with_no_scan_entry_reads_an_em_dash_not_empty(self):
        """`display_value` has three answers - a value, `(none)` and `(empty)` - and none of them
        says "this branch does not exist on this subject". A profile carrying no scan entry at
        all has no weakest action BY STRUCTURE rather than by choice. U+2014, which is
        `layout.NONE`."""
        profile = ZoneProtectionProfile.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_snapshot=self.snapshot, profile_name="p-noscan", scan_weakest_action="", attached_zone_count=1)

        cells = self.row_for("zone-protection", profile)

        self.assertEqual("—", cells["Weakest scan action"])
        self.assertEqual("Nothing", cells["Exempted sources"])

    def test_a_rule_with_no_action_branch_reads_an_em_dash(self):
        """The three actions are CHILD NODES rather than values, so an empty string is a rule
        with no action branch and not an action nobody read."""
        rule = DosPolicyRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source="local", rule_position=1, rule_name="r-noaction",
            rule_action="", names_a_profile=False)

        cells = self.row_for("dos-protection-rules", rule)

        self.assertEqual("—", cells["Action"])
        self.assertEqual("None", cells["Aggregate profile"])
        self.assertEqual("no", cells["Names a profile"])

    def test_a_rule_names_its_slots_and_its_position(self):
        rule = DosPolicyRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source="local", rule_position=4, rule_name="r-protect",
            rule_action="protect", aggregate_profile="agg-1", classified_profile="cls-1",
            names_a_profile=True, rule_disabled="yes")

        cells = self.row_for("dos-protection-rules", rule)

        self.assertEqual(4, cells["Position"])
        self.assertEqual("agg-1", cells["Aggregate profile"])
        self.assertEqual("cls-1", cells["Classified profile"])
        self.assertEqual("yes", cells["Disabled"])

    def test_every_query_field_is_registered_with_the_search_compiler(self):
        """A heading mapped to an unregistered field points the "build a query from these rows"
        button at a lookup that refuses itself or silently matches nothing. Stored, searchable
        and REGISTERED are three different things."""
        from assessments.search.dos_policy_rule.compiler import (
            FIELD_OPERATOR_REGISTRY as DOS_FIELDS)
        from assessments.search.zone_protection_profile.compiler import (
            FIELD_OPERATOR_REGISTRY as ZPP_FIELDS)

        for slug, registry in (("zone-protection", ZPP_FIELDS),
                               ("dos-protection-rules", DOS_FIELDS)):
            spec = cr.RESULTS[slug]
            for heading, field in spec.query_fields.items():
                with self.subTest(slug=slug, heading=heading):
                    self.assertIn(field, registry)
                    self.assertIn(heading, spec.columns)


class ZoneDosFindingsTabTests(TestCase):
    """The two new tabs, and the headings on all four this domain reports to."""

    #: Every tab a PAN-ZON control draws a row on. Two are this domain's own and two are
    #: inherited - PAN-ZON-001 reports on Security Zones and PAN-ZON-008 on Security Profile.
    TABS = ("zone-protection", "dos-protection-rules", "security-zones", "security-profiles")

    @classmethod
    def setUpTestData(cls):
        seed_controls(list(PAN_ZON))

    def test_the_two_new_tabs_claim_the_category_their_rail_item_does(self):
        """DERIVED from the rail (`category=''`), which is right for a subject that IS a
        configuration object: deriving it means the workbook cannot disagree with the app."""
        for slug, title, category in (("zone-protection", "Zone Protection", "Network"),
                                      ("dos-protection-rules", "DoS Protection Rules",
                                       "Policies")):
            with self.subTest(slug=slug):
                spec = DOMAIN_BY_SLUG[slug].spec
                self.assertEqual("", spec.category, "category should be derived from the rail")
                table = build_findings_table(spec)
                self.assertEqual(title, table.title)
                self.assertEqual(category, table.category)

    def test_no_heading_reads_as_a_raw_django_field_name(self):
        """Nothing in either repository says which columns head with a raw field name; it is
        found by building the table and looking. Two of these four tabs had one until this
        domain ran, and one of them had been customer-facing for months."""
        for slug in self.TABS:
            with self.subTest(slug=slug):
                headers = build_findings_table(DOMAIN_BY_SLUG[slug].spec).headers
                self.assertEqual([], [h for h in headers if "_" in h])

    def test_neither_new_sheet_declares_hidden_fields(self):
        """A non-empty `hidden_fields` is a CLAIM that `check_every_tested_field_is_presented`
        accepts as proof, and it is the only known cause of a findings row that marks nothing as
        the thing to fix. Both tabs pass that gate on real columns instead."""
        for slug in ("zone-protection", "dos-protection-rules"):
            with self.subTest(slug=slug):
                self.assertEqual((), DOMAIN_BY_SLUG[slug].spec.hidden_fields)

    def test_both_new_sheets_carry_the_stated_condition(self):
        """`tested_columns` defaults to `("Provenance",)`, which drops `Fires when` from the
        workbook while the live page keeps it, so the two surfaces disagree about which cell a
        reader meets. Taken knowing `fires_when` renders the BASELINE's condition alone."""
        for slug in ("zone-protection", "dos-protection-rules"):
            with self.subTest(slug=slug):
                spec = DOMAIN_BY_SLUG[slug].spec
                self.assertIn("Fires when (failing condition)", spec.tested_columns)
                self.assertIn("Provenance", spec.tested_columns)

    def test_every_subject_column_names_its_field(self):
        """A subject column that declares no field does not suppress the derived column for the
        same attribute, so one value reaches the tab twice under two headings - and because the
        headings differ, the duplicate-header guard never fires. The two VSYS_SCOPED address
        columns are the deliberate exception: they are the row's address, not a setting."""
        address_only = {"Firewalls", "Vsys", "Appliance", "HA role"}
        for slug in ("zone-protection", "dos-protection-rules"):
            with self.subTest(slug=slug):
                for column in DOMAIN_BY_SLUG[slug].spec.subject_columns:
                    heading = column[0]
                    if heading in address_only:
                        continue
                    self.assertEqual(5, len(column),
                                     f"{heading} declares no field")

    def test_the_reference_reach_headings_are_shared_with_one_later_domain(self):
        """`reference_reach` is asserted by exactly two controls in the catalogue - PAN-ZON-008
        and PAN-FIL-004, whose domain runs later - so these two headings are the shape that run
        inherits rather than chooses. The companion comes FIRST, which is stage 5's clause order:
        an applicability clause before the assertion it supports."""
        headers = build_findings_table(DOMAIN_BY_SLUG["security-profiles"].spec).headers

        self.assertIn("Reference walk completed", headers)
        self.assertIn("Reference reach", headers)
        self.assertLess(headers.index("Reference walk completed"),
                        headers.index("Reference reach"))
