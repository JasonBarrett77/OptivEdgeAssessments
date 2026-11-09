"""The three decryption-policy findings tabs and the three rail items, pinned. Stage 9.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover the tabs generically:
every assertion here is a JUDGMENT this run made that nothing else in the repository states, and
a new tab nothing asserts on is one the next refactor can break silently.

  - THE FIVE `value_readers`, which are not an optimization: `category`, `source`, `destination`,
    `source_user` and `service` are clause fields of shipped PAN-DEC queries and none of them is a
    field of `DecryptionPolicyRule`, so `tested_fields` RAISES and the tab cannot be built at all
    without them. A refactor that drops one does not degrade a cell; it takes the tab out.
  - THE VERDICT TAB'S `provenance_cell`, which is board record P451. Without it the default
    per-field walk prints "Not recorded" three times on every row - "nothing tracks that field",
    about three values this assessment computed - because every column of the model is derived and
    nothing writes it an `__entry__` row.
  - `Rules in force`, which is the only cell that tells the two failing states of
    `opens_outbound_web = No` apart: no decryption rulebase at all, and a rulebase whose every
    rule leaves traffic encrypted. The remediations are different pieces of work.
  - `Exclude` and `Source match is inverted`, each of which is the ONE cell that distinguishes two
    rows identical in every other column - and the second of those is the row that argues against
    its own finding.
  - THE THREE ROWS WHOSE `Fires when` CONTRADICTS THEIR OWN VALUE CELL, pinned as they are rather
    than fixed, because `fires_when` renders the BASELINE alone and is shared machinery. What is
    asserted is that the cells which RESOLVE the contradiction are all still on the row.
  - that no heading on any of the three tabs reads as a raw Django field name. All seventeen clause
    fields of this domain were headed by one before this stage ran, and nothing in either
    repository says which columns head raw: it is found by building the table and looking.
  - that no tab repeats a heading, which nothing in either repository checks and which ships a
    workbook Excel refuses to open.
  - the explorer `ResultsSpec.row` lambdas over real rows. The shipped check asserts a row is the
    same LENGTH as its columns and cannot see what a cell says.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets.findings import build_findings_table
from assessments.configuration_navigation import CONFIG_OBJECTS, objects_for_model
from assessments.decryption_policy_rule_findings import (
    generate_decryption_policy_rule_findings)
from assessments.decryption_rulebase_coverage_findings import (
    generate_decryption_rulebase_coverage_findings)
from assessments.models import AssessmentRun, Control
from assessments.ssl_decryption_exclusion_findings import (
    generate_ssl_decryption_exclusion_findings)
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementNode, EnforcementPoint, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.decryption import (
    normalize_decryption_policy, normalize_ssl_decryption_exclusions)

#: Every control of this domain, split by the type each one targets. THE FINDINGS-TAB TESTS SEED
#: ALL TEN and the reason is not incidental: a derived settings column exists only because some
#: control's query clauses on the field, so `build_findings_table` over an unseeded catalog draws
#: NO setting columns at all - and a "no heading reads as a raw field name" assertion over that
#: table passes vacuously.
RULE_CONTROLS = ("PAN-DEC-002", "PAN-DEC-003", "PAN-DEC-005", "PAN-DEC-006", "PAN-DEC-007",
                 "PAN-DEC-008", "PAN-DEC-010")
COVERAGE_CONTROLS = ("PAN-DEC-001", "PAN-DEC-009")
EXCLUSION_CONTROLS = ("PAN-DEC-004",)

TPA_A = "013201001475"
TPA_B = "013201001476"
FW201 = "691665AC334B458"
FW111 = "6A9C0A9904E7D6E"


def forward_proxy(name, **keys):
    """One decryption rule entry on the ssl-forward-proxy branch, in the device's own shape.

    `type` is a CHOICE NODE - the selection is which empty child exists - so the branch is a key
    with a None value and not a string.
    """
    entry = {"@name": name, "source": {"member": ["any"]},
             "destination": {"member": ["any"]},
             "action": keys.pop("action", "no-decrypt"),
             "type": {"ssl-forward-proxy": None}}
    entry.update(keys)
    return entry


def merged(vsys_name, rules=(), exclusions=(), shared_exclusions=()):
    vsys = {"@name": vsys_name}
    if rules:
        vsys["rulebase"] = {"decryption": {"rules": {"entry": list(rules)}}}
    if exclusions:
        vsys["ssl-decrypt"] = {"ssl-exclude-cert": {"entry": list(exclusions)}}
    shared = {}
    if shared_exclusions:
        shared["ssl-decrypt"] = {"ssl-exclude-cert": {"entry": list(shared_exclusions)}}
    return {"config": {
        "devices": {"entry": [{"@name": "localhost.localdomain",
                               "vsys": {"entry": [vsys]}}]},
        "shared": shared,
    }}

#: The pushed view, in the shape stage 4 measured on all four lab appliances: the pushed pre- and
#: post-rulebases hold `security` and `default-security-rules` and NO `decryption` child at all.
#: Required rather than decorative - `build_normalized_decryption_rules` raises without it on a
#: Panorama-managed point, which is the behaviour it should have.
PUSHED = {"policy": {"panorama": {
    "pre-rulebase": {"security": {"rules": {}}},
    "post-rulebase": {"security": {"rules": {}}, "default-security-rules": {"rules": {}}},
}}}


class DecryptionPolicyTabTestCase(TestCase):
    """Three subjects at three grains, over an estate with a real HA pair in it."""

    def setUp(self):
        now = timezone.now()
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.dec")
        run = AssessmentRun.objects.create(
            name="Decryption policy", status=AssessmentRun.Status.RUNNING, started_at=now)
        seed_controls(list(RULE_CONTROLS),
                      control_type=Control.ControlType.DECRYPTION_POLICY_RULE)
        seed_controls(list(COVERAGE_CONTROLS),
                      control_type=Control.ControlType.DECRYPTION_RULEBASE_COVERAGE)
        seed_controls(list(EXCLUSION_CONTROLS),
                      control_type=Control.ControlType.SSL_DECRYPTION_EXCLUSION)

        # THE HA PAIR. Both members hold the same vsys2, so vsys2 is ONE enforcement point across
        # the two - which is what makes the verdict row singular and its Firewalls cell plural.
        # Two rules, identical but for the negate switch, which is the pair of rows this file is
        # most about.
        tpa = merged("vsys2", rules=[
            forward_proxy("oep-dec6-r03", source={"member": ["ao-analytics-01"]}),
            forward_proxy("oep-dec6-r04", source={"member": ["ao-analytics-01"]},
                          **{"negate-source": "yes"}),
        ])
        self.tpa = self._group("g-tpa", ApplianceGroup.TYPE_HA_PAIR, tpa, now, [
            (TPA_A, "fw-core-tpa-a"), (TPA_B, "fw-core-tpa-b")], "vsys2")

        # pan-fw-201: the DECRYPTING rules, and the two exclusions - one per writable scope.
        # `oep-dec6-d01` keeps no record of a successful session and takes the measured
        # absent-means-YES default on the failed-handshake switch, which is the row whose stated
        # condition contradicts its own cell.
        fw201 = merged("vsys1", rules=[
            forward_proxy("oep-dec6-d01", action="decrypt"),
        ], exclusions=[{"@name": "oep-dec6-x01", "exclude": "yes"}],
            shared_exclusions=[{"@name": "oep-dec6-x02", "exclude": "no"}])
        self.fw201 = self._group("g-fw201", ApplianceGroup.TYPE_STANDALONE, fw201, now,
                                 [(FW201, "pan-fw-201")], "vsys1")

        # pan-fw-111: NO decryption rulebase at all, which is the commonest state in the measured
        # estate and the other failing value of `opens_outbound_web`.
        self.fw111 = self._group("g-fw111", ApplianceGroup.TYPE_STANDALONE,
                                 merged("vsys1"), now, [(FW111, "pan-fw-111")], "vsys1")

        for point in EnforcementPoint.objects.all():
            normalize_decryption_policy(point)
        for appliance in Appliance.objects.all():
            normalize_ssl_decryption_exclusions(appliance)
        generate_decryption_rulebase_coverage_findings(run)
        generate_decryption_policy_rule_findings(run)
        generate_ssl_decryption_exclusion_findings(run)

    def _group(self, name, group_type, payload, now, members, vsys_name):
        group = ApplianceGroup.objects.create(
            management_station=self.station, name=name, group_type=group_type)
        appliances = []
        for serial, hostname in members:
            appliance = Appliance.objects.create(
                management_station=self.station, appliance_group=group,
                serial_number=serial, hostname=hostname)
            appliances.append(appliance)
            Snapshot.objects.create(management_station=self.station, appliance=appliance,
                                    source_type="show_merged_config", collected_at=now,
                                    payload=payload)
        group.active_appliance = appliances[0]
        group.save(update_fields=["active_appliance"])
        point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=group, vsys_name=vsys_name,
            vsys_display_name=vsys_name,
            # DEFAULTS FALSE, and the shared-scope normalisers filter on it.
            in_scope=True)
        Snapshot.objects.create(management_station=self.station, enforcement_point=point,
                                source_type="show_merged_config", collected_at=now,
                                payload=payload)
        Snapshot.objects.create(management_station=self.station, enforcement_point=point,
                                source_type="show_pushed_shared_policy_vsys", collected_at=now,
                                payload=PUSHED)
        for appliance in appliances:
            EnforcementNode.objects.create(management_station=self.station,
                                           enforcement_point=point, appliance=appliance)
        return group

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def table(slug):
        return build_findings_table(DOMAIN_BY_SLUG[slug].spec)

    def rows_for(self, slug, control_id, name=None):
        table = self.table(slug)
        object_column = table.headers.index("Object")
        control_column = table.headers.index("Control ID")
        return [row for row in table.rows
                if row[control_column] == control_id
                and (name is None or row[object_column] == name)]

    def one_row(self, slug, control_id, name=None):
        rows = self.rows_for(slug, control_id, name)
        self.assertEqual(1, len(rows), f"{control_id} / {name}: {len(rows)} rows")
        return rows[0]

    def cell(self, slug, control_id, name, heading):
        table = self.table(slug)
        return self.one_row(slug, control_id, name)[table.headers.index(heading)]

    def marked(self, slug, control_id, name):
        """The HEADINGS of the cells marked as the value at fault on one row."""
        table = self.table(slug)
        object_column = table.headers.index("Object")
        control_column = table.headers.index("Control ID")
        index = next(n for n, row in enumerate(table.rows)
                     if row[control_column] == control_id and row[object_column] == name)
        return {table.headers[column] for row, column in table.implicated if row == index}


class DecryptionRailTests(TestCase):
    """The three rail items, their addresses, and the slug collision that nearly happened."""

    ITEMS = (
        ("integrations.DecryptionPolicyRule", "decryption-rules", "Policies",
         "Policies > Decryption"),
        ("integrations.DecryptionRulebaseVerdict", "decryption-coverage", "Policies",
         "Policies > Decryption"),
        ("integrations.SslDecryptionExclusion", "ssl-decryption-exclusion", "Device",
         "Device > Certificate Management > SSL Decryption Exclusion"),
    )

    def test_each_model_has_exactly_one_page_at_the_vendors_own_address(self):
        for model, slug, category, where in self.ITEMS:
            with self.subTest(model=model):
                items = objects_for_model(model)
                self.assertEqual(1, len(items))
                self.assertEqual(slug, items[0].slug)
                self.assertEqual(category, items[0].category)
                self.assertEqual(where, items[0].where)

    def test_the_exclusion_is_a_DEVICE_object_and_not_a_policy_one(self):
        """The address is the vendor's and it is NOT in Policies, where the rest of this domain
        lands. PAN-OS Web Interface Help 11.2 p.901, section path `Device > Certificate
        Management > SSL Decryption Exclusion`, and the same path in 11.1 p.889 and 12.2 p.940.
        A reader sent to Policies for this object would not find it."""
        (item,) = objects_for_model("integrations.SslDecryptionExclusion")
        self.assertEqual("Device", item.category)
        self.assertEqual("Certificate Management", item.group)

    def test_two_items_share_the_policies_decryption_address_over_two_models(self):
        """`rule-posture`'s shape: an engineer fixes one or the other. Everything on the rules
        page is fixed by EDITING a rule; everything on the coverage page by ADDING one."""
        at_address = [o for o in CONFIG_OBJECTS if o.where == "Policies > Decryption"]
        self.assertEqual(["decryption-rules", "decryption-coverage"],
                         [o.slug for o in at_address])
        self.assertEqual(2, len({o.search_model for o in at_address}))

    def test_the_policy_does_not_collide_with_the_profile_page(self):
        """`RESULTS` is keyed on the SLUG alone while `CONFIG_OBJECTS_BY_KEY` is keyed on
        (category, slug), so a bare `decryption` slug here and the Objects profile item could not
        both carry a results spec. The profile is a different screen in a different category."""
        (profile,) = [o for o in CONFIG_OBJECTS if o.slug == "decryption-profile"]
        self.assertEqual("Objects", profile.category)
        self.assertEqual("Objects > Decryption Profile", profile.where)
        self.assertNotIn("decryption", [o.slug for o in CONFIG_OBJECTS])

    def test_the_prefix_is_out_of_the_presentation_debt_register(self):
        """Clearing it is the work, not a side effect: an exemption that survives the work it was
        waiting for is a permanent hole. All 21 shipped PAN-DEC queries resolve on their own."""
        self.assertNotIn("PAN-DEC", cr.AWAITING_PRESENTATION)

    def test_the_vendor_optout_model_is_given_no_page_at_all(self):
        """PAN-DEC-004's SECOND assertion record names it and no catalog id can hold both
        halves, so NO shipped query names this model - which is why it is owed nothing here
        rather than why it was forgotten. Asserted so that adding a control for it fails this
        test and sends somebody to build the page."""
        self.assertEqual(
            [], list(objects_for_model("integrations.SslDecryptionVendorExclusionOptOut")))


class DecryptionResultsSpecTests(TestCase):
    """Every `query_fields` heading maps a field the search compiler REGISTERS, and the row
    lambdas are exercised over real rows elsewhere in this file."""

    REGISTRIES = (
        ("decryption-rules", "assessments.search.decryption_policy_rule.compiler"),
        ("decryption-coverage", "assessments.search.decryption_rulebase_coverage.compiler"),
        ("ssl-decryption-exclusion", "assessments.search.ssl_decryption_exclusion.compiler"),
    )

    def test_every_query_field_is_a_registered_field(self):
        """Stored, searchable and registered are three different things. A heading mapped to an
        unregistered field points the "build a query from these rows" button at a lookup that
        refuses itself or silently matches nothing."""
        for slug, module_name in self.REGISTRIES:
            module = __import__(module_name, fromlist=["FIELD_OPERATOR_REGISTRY"])
            with self.subTest(slug=slug):
                for heading, field in cr.RESULTS[slug].query_fields.items():
                    self.assertIn(field, module.FIELD_OPERATOR_REGISTRY,
                                  f"{slug}: {heading!r} -> {field!r} is not registered")

    def test_every_query_field_heading_is_a_column_of_its_page(self):
        for slug, _module in self.REGISTRIES:
            with self.subTest(slug=slug):
                spec = cr.RESULTS[slug]
                for heading in spec.query_fields:
                    self.assertIn(heading, spec.columns)

    def test_the_counted_and_switched_columns_offer_no_clause(self):
        """`rule_count` and `exclude` are COLUMNS and not query fields, measured: neither is in
        its model's registry, because no shipped control asks for it. They are evidence beside a
        verdict rather than something to clause on."""
        self.assertIn("Rules in force", cr.RESULTS["decryption-coverage"].columns)
        self.assertNotIn("Rules in force", cr.RESULTS["decryption-coverage"].query_fields)
        self.assertIn("Exclude", cr.RESULTS["ssl-decryption-exclusion"].columns)
        self.assertNotIn("Exclude", cr.RESULTS["ssl-decryption-exclusion"].query_fields)


class DecryptionHeadingTests(DecryptionPolicyTabTestCase):
    """Seventeen clause fields, none of which had a heading before this stage ran."""

    SLUGS = ("decryption-rules", "decryption-coverage", "ssl-decryption-exclusions")

    def test_no_heading_on_any_of_the_three_tabs_reads_as_a_django_field_name(self):
        """A column with no `setting_labels` entry keeps the raw field name, so declaring a column
        without a label IS choosing to show a database field name to a customer."""
        for slug in self.SLUGS:
            with self.subTest(slug=slug):
                raw = [h for h in self.table(slug).headers if "_" in h or h.islower()]
                self.assertEqual([], raw, f"{slug} heads these raw: {raw}")

    def test_no_tab_repeats_a_heading(self):
        """Nothing in either repository checks this and a duplicate header ships a table Excel
        rejects - xlsxwriter drops it with a warning, leaving a sheet of stray cells."""
        for slug in self.SLUGS:
            with self.subTest(slug=slug):
                headers = self.table(slug).headers
                self.assertEqual(sorted(set(headers)), sorted(headers))

    def test_the_two_user_columns_do_not_collide(self):
        """The near miss: the criterion and the verdict over its contents are different columns
        and the vendor has a word for only one of them."""
        headers = self.table("decryption-rules").headers
        self.assertIn("Source User", headers)
        self.assertIn("Exempt population is only platform keywords", headers)

    def test_the_setting_columns_arrive_in_stage_5s_clause_order(self):
        """THE ONE STRUCTURAL PROPERTY WITH NO GATE BEHIND IT. `tested_fields` returns the
        baseline's clauses in clause order and then every other active query's ALPHABETICALLY BY
        QUERY NAME, so what a calibration query is CALLED sets a customer-facing column's
        position. Pinned as the order read off the built table."""
        headers = self.table("decryption-rules").headers
        expected = ["Action", "Disabled", "URL Category", "Source Address",
                    "Destination Address", "Source User", "Service", "Description",
                    "Exempt population is only platform keywords", "Source match is inverted",
                    "Decryption Profile", "Log Unsuccessful SSL Handshake",
                    "Opens the session it matches", "Record of a successful session"]
        start = headers.index("Action")
        self.assertEqual(expected, headers[start:start + len(expected)])


class DecryptionCoverageRowTests(DecryptionPolicyTabTestCase):
    """The verdict tab: one row per enforcement point, and P451."""

    def test_the_ha_pair_draws_ONE_row_naming_BOTH_members(self):
        """`DecryptionRulebaseVerdict`'s unique constraint is on `enforcement_point` ALONE, and an
        enforcement point on an HA pair is one point spanning both members - so the store already
        deduplicates on the PAIR. Stage 5's `identity` declared (appliance, vsys_name) and said in
        prose that an HA pair yields TWO rows for one configuration; the shipped model does not do
        that, and a customer reading two defects where the estate has one gets a count they cannot
        reconcile against the device list."""
        table = self.table("decryption-coverage")
        firewalls = table.headers.index("Firewalls")
        vsys = table.headers.index("Vsys")
        pair_rows = [r for r in table.rows if r[vsys] == "vsys2"]
        self.assertEqual(2, len(pair_rows))        # PAN-DEC-001 and PAN-DEC-009, one each
        for row in pair_rows:
            self.assertEqual("fw-core-tpa-a\nfw-core-tpa-b", row[firewalls])

    def test_the_provenance_cell_says_Derived_and_not_Not_recorded(self):
        """BOARD RECORD P451. Every column of this model is in its `DERIVED_FIELDS` and the model
        writes NO provenance row for any of them, so the per-field walk finds none,
        `remediation_accessor` discards a synthesised DERIVED row on purpose, and nothing writes
        an `__entry__` row either - which lands `provenance_cells` on its `row is None` arm and
        prints "Not recorded" THREE TIMES. That means "nothing tracks that field" and reads to a
        customer as a gap in the collection, about three values we computed."""
        table = self.table("decryption-coverage")
        provenance = table.headers.index("Provenance")
        self.assertTrue(table.rows)
        for row in table.rows:
            self.assertEqual("Derived", row[provenance])
            self.assertNotIn("Not recorded", row[provenance])

    def test_rules_in_force_tells_the_two_failing_states_apart(self):
        """`opens_outbound_web = No` on BOTH, and the remediations are different pieces of work:
        pan-fw-111 has no decryption rulebase at all, so the answer is to write one; the pair has
        two rules in force that both leave traffic encrypted, so the answer is to change them.
        This cell is the only one that says which, and the disposition column beside it agrees."""
        table = self.table("decryption-coverage")
        count = table.headers.index("Rules in force")
        verdict = table.headers.index("Any rule opens an outbound web session")
        disposition = table.headers.index("What any outbound web session meets")
        vsys = table.headers.index("Vsys")
        firewalls = table.headers.index("Firewalls")
        by_point = {}
        for row in table.rows:
            by_point[(row[firewalls].split("\n")[0], row[vsys])] = row
        absent = by_point[("pan-fw-111", "vsys1")]
        populated = by_point[("fw-core-tpa-a", "vsys2")]
        self.assertEqual("No", absent[verdict])
        self.assertEqual("No", populated[verdict])
        self.assertEqual("0", absent[count])
        self.assertEqual("2", populated[count])
        self.assertEqual("no-rule-opens-outbound-web", absent[disposition])
        self.assertEqual("no-decrypt", populated[disposition])

    def test_the_decrypting_point_draws_no_coverage_row_at_all(self):
        """pan-fw-201 opens outbound web sessions and carries no inbound-inspection rule in this
        estate, so it passes PAN-DEC-001 and fires PAN-DEC-009 - which is what makes the two
        controls separable rather than one."""
        table = self.table("decryption-coverage")
        control = table.headers.index("Control ID")
        firewalls = table.headers.index("Firewalls")
        on_fw201 = {row[control] for row in table.rows if row[firewalls] == "pan-fw-201"}
        self.assertEqual({"PAN-DEC-009"}, on_fw201)


class DecryptionRuleRowTests(DecryptionPolicyTabTestCase):
    """The rule tab: the five readers, and the rows that argue against themselves."""

    def test_the_five_criteria_reach_their_cells_through_the_readers(self):
        """Not an optimization. None of the five is a field of the model, so `tested_fields`
        raises without a reader and this tab does not exist."""
        for heading, expected in (("URL Category", "any"),
                                  ("Destination Address", "any"),
                                  ("Source User", "any"),
                                  ("Service", "any"),
                                  ("Source Address", "ao-analytics-01")):
            with self.subTest(heading=heading):
                self.assertEqual(
                    expected,
                    self.cell("decryption-rules", "PAN-DEC-003", "oep-dec6-r03", heading))

    def test_a_criterion_cell_names_its_members_one_per_line(self):
        """The device's own order, a line each rather than a comma list: a criterion names objects
        whose own names contain hyphens and read as phrases."""
        cell = self.cell("decryption-rules", "PAN-DEC-003", "oep-dec6-r03", "Source Address")
        self.assertNotIn(",", cell)

    def test_the_inverted_rule_argues_against_its_own_PAN_DEC_005_finding(self):
        """THE ROW THIS STAGE EXISTS TO CATCH. PAN-DEC-005 reports that the exemption's content
        criterion is unbounded while its SOURCE is bounded to a named object - and on
        `oep-dec6-r04` the source match is NEGATED, so what the rule exempts is every address
        EXCEPT those in the object. The finding reports a bounded exemption and the row shows the
        broadest possible one.

        IT IS NOT FIXABLE HERE. The clause is a negated membership test on the member NAME and
        carries nothing about the negate switch; stage 5's clause list for that record has no
        `negate_source` clause to exclude it; and writing a query is stage 8's. Stage 8 recorded
        it as `all_belong: false` on that baseline and this stage implements it as written.

        WHAT MAKES THE ROW HONEST IS THE COLUMN. `Source match is inverted` is on this tab only
        because PAN-DEC-007 clauses on it and `setting_columns` derives the UNION across the
        tab's controls - so the cell that contradicts PAN-DEC-005's finding is there by way of a
        different control. Without it, r03 and r04 are identical in every visible cell."""
        bounded = self.one_row("decryption-rules", "PAN-DEC-005", "oep-dec6-r03")
        inverted = self.one_row("decryption-rules", "PAN-DEC-005", "oep-dec6-r04")
        table = self.table("decryption-rules")
        negate = table.headers.index("Source match is inverted")
        self.assertEqual("No", bounded[negate])
        self.assertEqual("Yes", inverted[negate])
        # ONE CELL, and it is the only difference between the two rows. Asserted so that dropping
        # the column - or moving PAN-DEC-007 to a tab of its own - fails here rather than quietly
        # making two opposite configurations read the same.
        differing = [n for n, (left, right) in enumerate(zip(bounded, inverted))
                     if left != right]
        self.assertEqual({"Finding #", "Object", "Source match is inverted"},
                         {table.headers[n] for n in differing})

    def test_the_same_rule_is_reported_twice_at_two_severities(self):
        """`oep-dec6-r04` is PAN-DEC-005's subject at medium and PAN-DEC-007's at high - one
        condition, two findings, which stage 3's own rank-1 ruling calls a defect the partition
        between the sibling controls is supposed to decide. Recorded rather than resolved: the
        remedy is a clause, and writing one is stage 8's."""
        self.assertEqual("Medium", self.cell(
            "decryption-rules", "PAN-DEC-005", "oep-dec6-r04", "Severity"))
        self.assertEqual("High", self.cell(
            "decryption-rules", "PAN-DEC-007", "oep-dec6-r04", "Severity"))

    def test_a_row_firing_on_a_calibration_prints_the_baselines_condition(self):
        """CONTRACT FINDING 1, reproduced. `fires_when` is
        `render_node(baseline_query(control).canonical_query)` with no per-spec hook, so
        `oep-dec6-d01` - which fired on PAN-DEC-010's SECOND record about the successful-session
        record - prints the FIRST record's condition `log_fail = No` beside a `Log Unsuccessful
        SSL Handshake` cell reading `Yes`. The subject does not meet the condition on the row.

        NOT FIXABLE AT THIS STAGE and not fixed: `fires_when` is shared machinery. What is
        asserted instead is that the three cells which RESOLVE it are all still on the row - the
        marked cell, `Matched queries` and `Severity basis` - which is the workaround the contract
        names. A refactor that drops any of the three takes the row's only explanation with it."""
        row = self.one_row("decryption-rules", "PAN-DEC-010", "oep-dec6-d01")
        table = self.table("decryption-rules")
        self.assertEqual("disabled = No and log_fail = No",
                         row[table.headers.index("Fires when (failing condition)")])
        self.assertEqual("Yes", row[table.headers.index("Log Unsuccessful SSL Handshake")])
        self.assertEqual({"Record of a successful session"},
                         self.marked("decryption-rules", "PAN-DEC-010", "oep-dec6-d01"))
        self.assertEqual("No record of a successful session",
                         row[table.headers.index("Matched queries")])
        self.assertIn("No record of a successful session",
                      row[table.headers.index("Severity basis")])

    def test_the_baseline_row_of_the_same_control_is_consistent(self):
        """The contrast, on one tab under one control: `oep-dec6-r03` takes the measured
        absent-means-yes default, so it does NOT fire the first record - which is what makes the
        row above an inconsistency rather than the normal case."""
        rows = self.rows_for("decryption-rules", "PAN-DEC-010", "oep-dec6-r03")
        self.assertEqual([], rows)

    def test_the_provenance_cell_resolves_a_reader_field_to_the_rules_own_origin(self):
        """A reader whose `provenance` is exactly the DERIVED label is a request to let the object
        answer, so the cell reads where the RULE came from rather than the word "Derived" - which
        is the useful answer for a criterion and matches the security rules sheet's reasoning that
        a rule is pushed as a unit.

        AND IT IS NOT THE LIST NODE'S OWN ROW, which is the cost. The normalizer writes a
        `FieldProvenance` row per criterion precisely so a reader can tell "the rule says any"
        from "nobody wrote one", and `stored=False` means `remediation_accessor` never asks for
        it. Measured side by side here: on `oep-dec6-r03` the `category` key was ABSENT and reads
        `Local`, while `description` - also absent, but a stored field with no reader - reads
        `Not configured`. Two absent keys, two different answers, on one tab."""
        table = self.table("decryption-rules")
        provenance = table.headers.index("Provenance")
        category_row = self.one_row("decryption-rules", "PAN-DEC-002", "oep-dec6-r03")
        description_row = self.one_row("decryption-rules", "PAN-DEC-003", "oep-dec6-r03")
        self.assertIn("Local", category_row[provenance])
        self.assertNotIn("Not recorded", category_row[provenance])
        self.assertIn("Not configured", description_row[provenance])

    def test_the_disabled_column_says_every_assessed_rule_is_in_force(self):
        """Jason, 2026-10-14: "keep disabled rules in scope". What the clause does is narrower
        than the ruling and the difference is visible here: `disabled = False` is an APPLICABILITY
        clause on nine of the ten controls, so a rule carrying `disabled: yes` is out of the
        population and draws no row - and this cell reading "No" on every row is the evidence that
        the rule assessed is one in force. The ruling is honoured by the model's DEFAULT, which is
        False, so a rule nobody read stays inside the population."""
        table = self.table("decryption-rules")
        disabled = table.headers.index("Disabled")
        self.assertTrue(table.rows)
        for row in table.rows:
            self.assertEqual("No", row[disabled])


class SslDecryptionExclusionRowTests(DecryptionPolicyTabTestCase):
    """The exclusion tab: two scopes, and the switch that changes what the finding means."""

    def test_both_writable_scopes_draw_a_row(self):
        """The vsys scope matters because PAN-OS puts the screen at the SHARED one: a vsys-scoped
        exclusion is real, committable configuration no operator can see or remove through the
        interface they use."""
        table = self.table("ssl-decryption-exclusions")
        scope = table.headers.index("Scope")
        self.assertEqual({"vsys1", "shared"}, {row[scope] for row in table.rows})

    def test_the_exclude_switch_is_what_the_finding_means_differently_about(self):
        """Both rows carry no reason and both fire at medium, and they are not the same problem:
        `oep-dec6-x01` is in force and keeps sessions to its server encrypted, while
        `oep-dec6-x02` is switched off and currently excludes nothing. Without this column the two
        rows are identical in every cell but the name."""
        self.assertEqual("Yes", self.cell(
            "ssl-decryption-exclusions", "PAN-DEC-004", "oep-dec6-x01", "Exclude"))
        self.assertEqual("No", self.cell(
            "ssl-decryption-exclusions", "PAN-DEC-004", "oep-dec6-x02", "Exclude"))

    def test_the_stated_condition_on_this_tab_reads_in_english(self):
        """THE ONE OF THE THREE TABS WHERE IT DOES, and it is luck rather than design: the clause
        field is `description`, whose proposed heading happens to BE "Description", and the
        operator renders as "is empty". `render_node` consults `setting_labels` nowhere, so the
        other two tabs print Django field names in this cell on every row."""
        self.assertEqual("description is empty", self.cell(
            "ssl-decryption-exclusions", "PAN-DEC-004", "oep-dec6-x01",
            "Fires when (failing condition)"))

    def test_the_provenance_cell_names_the_absent_key(self):
        """`description` is a stored column with a real `FieldProvenance` row behind it and an
        `__entry__` row behind that, so the default per-field walk answers honestly here and this
        tab needs no `provenance_cell`. "Not configured" is the recorded answer for a key the
        payload did not carry - which is the whole of this control."""
        self.assertEqual("Not configured", self.cell(
            "ssl-decryption-exclusions", "PAN-DEC-004", "oep-dec6-x01", "Provenance"))


class DecryptionExplorerRowTests(DecryptionPolicyTabTestCase):
    """The three `ResultsSpec.row` lambdas over real rows. The shipped squareness check asserts a
    row is the same LENGTH as its columns and cannot see what a cell says."""

    def rows(self, slug):
        spec = cr.RESULTS[slug]
        return spec, [spec.row(obj) for obj in spec.base_queryset()]

    def test_every_row_is_as_wide_as_its_columns_and_carries_real_cells(self):
        for slug in ("decryption-rules", "decryption-coverage", "ssl-decryption-exclusion"):
            with self.subTest(slug=slug):
                spec, rows = self.rows(slug)
                self.assertTrue(rows, f"{slug} produced no rows to exercise")
                for row in rows:
                    self.assertEqual(len(spec.columns), len(row))

    def test_the_rule_page_prints_the_five_criteria_and_the_rulebase(self):
        spec, rows = self.rows("decryption-rules")
        by_name = {row[spec.columns.index("Object")]: row for row in rows}
        rule = by_name["oep-dec6-r04"]
        self.assertEqual("Local", rule[spec.columns.index("Rulebase")])
        self.assertEqual("any", rule[spec.columns.index("URL Category")])
        self.assertEqual("ao-analytics-01", rule[spec.columns.index("Source Address")])
        self.assertEqual("yes", rule[spec.columns.index("Source match is inverted")])
        # "Nothing named" rather than a blank, and NOT "nothing applied": the device resolves an
        # absent profile key to the predefined `default` under some conditions and to nothing
        # under others, so this cell can only report what the rule SAYS.
        self.assertEqual("Nothing named", rule[spec.columns.index("Decryption Profile")])
        self.assertEqual("—", rule[spec.columns.index("Description")])

    def test_the_coverage_page_prints_the_count_as_a_number(self):
        """Zero is the reportable end here, so a word like "Nothing" would read as "not counted"
        rather than "none found"."""
        spec, rows = self.rows("decryption-coverage")
        counts = {row[spec.columns.index("Rules in force")] for row in rows}
        self.assertIn(0, counts)
        self.assertIn(2, counts)

    def test_the_exclusion_page_prints_the_scope_and_an_em_dash_for_no_reason(self):
        spec, rows = self.rows("ssl-decryption-exclusion")
        by_name = {row[spec.columns.index("Object")]: row for row in rows}
        self.assertEqual("—", by_name["oep-dec6-x01"][spec.columns.index("Description")])
        self.assertEqual("yes", by_name["oep-dec6-x01"][spec.columns.index("Exclude")])
        self.assertEqual("shared", by_name["oep-dec6-x02"][spec.columns.index("Where")])
