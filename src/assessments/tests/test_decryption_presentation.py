"""The Forward Proxy Signing tab, the two new rail items, and the NINE pages over one model.

Stage 9, `decryption-profiles`, 2026-11-02. PAN-DCP-001 to -007.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover tabs and rows generically:
every assertion here is a JUDGMENT this run made that nothing else in the repository states, and a
new tab nothing asserts on is one the next refactor can break silently.

  - `integrations.SecurityProfile` NOW HAS NINE PAGES. `object_for_canonical_query` keeps every
    candidate whose own scope clauses are a SUBSET of the query's and answers only when exactly one
    matched, so a scope that is too LOOSE matches alongside each sibling and pushes ALL NINE kinds
    to None. The eight pages that already worked are what a wrong scope here breaks, which is why
    all nine are asserted and not only the one that is new.
  - THE DECRYPTION PROFILE IS NOT A `Security Profiles` CHILD, which is the one thing about the
    rail entry that was measured rather than assumed - the commissioning brief said it was. All
    three Help versions in the corpus put it at a top level: 11.1 p.213, 11.2 p.213 and 12.2 p.215
    each enumerate the Objects rail with "Objects>Authentication • Objects>Decryption Profile •
    Objects > SD-WAN Link Management • Objects>Schedules", and a complete rung-1 count over every
    document for `Objects>Decryption` returns those three pages and nothing else. Asserted because
    a later tidy-up would otherwise "fix" it into the Security Profiles group.
  - THE SIX KIND-GATED VALUE READERS, which are the single largest thing this run changes about
    what a customer reads - and they change OTHER domains' rows. Before them an antivirus row on
    the shared tab told a customer its protocol floor was below TLS 1.2 and that RC4 was still
    negotiable, because those are the measured implicit values of keys an antivirus profile has no
    container for at all. Asserted on a real antivirus row, not by calling the readers.
  - THE REFUSAL ON `is_used`, which is the opposite call on the same tab and is the one a later run
    is most likely to "complete" by mistake. It is not a decryption column: PAN-AVW-006 is a
    shipped control over exactly it, and a kind gate would print an em dash over that control's
    own value-at-fault.
  - THE PROVENANCE CELL ON THE NEW TAB, which the default got WRONG - "Not recorded" on all three
    rows, meaning "nothing tracks this field" where the value is derived. Found by reading the
    rows and not by reasoning about them, so it is pinned by a row and not by a comment.
  - THE FOUR DESIGNATION SLOTS BEING PRESENT AT ALL. No shipped query clauses on them - their
    compiler declines to register them in terms - so `setting_columns` derives nothing and these
    subject columns are the only thing that puts them on the row. They are what tells a reader
    WHICH slot is empty, and each of the control's two verdicts covers two failing states.
  - the explorer `row` lambdas over real rows. The shipped check asserts a row is the same LENGTH
    as its columns and cannot see what a cell says - and the cells here that are judgments are
    exactly the ones a length check cannot reach: the compliant member of a graded column, an
    unresolvable protocol ceiling, and an empty designation slot.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.layout import NONE
from assessments.artifacts.sheets import objects as object_sheets
from assessments.artifacts.sheets.findings import build_findings_table
from assessments.configuration_navigation import CATEGORIES, CONFIG_OBJECTS, objects_for_model
from assessments.models import Control
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, Certificate, DecryptionSettings, EnforcementNode, EnforcementPoint,
    ManagementStation, SecurityProfile, Snapshot)

#: Every control of this domain. The findings-tab tests SEED THESE and the reason is not
#: incidental: a derived settings column exists only because some control's query clauses on the
#: field, so `build_findings_table` over an unseeded catalog draws NO setting columns at all - and
#: a "no heading reads as a raw field name" assertion over that table passes vacuously.
PAN_DCP = ("PAN-DCP-001", "PAN-DCP-002", "PAN-DCP-003", "PAN-DCP-004", "PAN-DCP-005",
           "PAN-DCP-006", "PAN-DCP-007")

#: The fields this domain's seven controls test. The heading assertion below is scoped to these:
#: the other headings on the shared tab belong to other domains' controls.
OUR_FIELDS = (
    "rule_destination_unrestricted", "ssl_min_version_below_tls12", "ssl_max_version_restrictive",
    "ssl_max_version", "ssl_min_version", "weakest_broken_primitive_permitted",
    "weakest_non_pfs_or_unauthenticated_permitted", "fwd_block_expired_certificate",
    "fwd_block_untrusted_issuer", "fwd_block_unsupported_version", "fwd_block_unsupported_cipher",
    "inb_block_unsupported_version", "inb_block_unsupported_cipher",
    "fwd_block_if_hsm_unavailable", "inb_block_if_hsm_unavailable", "fwd_block_if_no_resource",
    "fwd_block_tls13_downgrade_no_resource", "inb_block_if_no_resource",
    "inb_block_tls13_downgrade_no_resource", "decryption_rulebase_collected", "is_used",
)

#: The six columns a `value_readers` entry gates on `kind`, and the one deliberately left alone.
KIND_GATED = (
    "rule_destination_unrestricted", "ssl_min_version_below_tls12", "ssl_max_version_restrictive",
    "weakest_broken_primitive_permitted", "weakest_non_pfs_or_unauthenticated_permitted",
    "decryption_rulebase_collected",
)

#: The fourteen measured payload keys this run REFUSED a reader on, because a reader makes
#: `build_rows` hand the field `stored=False` to `remediation_accessor`, which then never reads the
#: column's `FieldProvenance` row - and that row is the only thing separating a key the device does
#: not carry from one typed to the failing value.
REFUSED_READER = (
    "ssl_max_version", "ssl_min_version", "fwd_block_expired_certificate",
    "fwd_block_untrusted_issuer", "fwd_block_unsupported_version", "fwd_block_unsupported_cipher",
    "inb_block_unsupported_version", "inb_block_unsupported_cipher",
    "fwd_block_if_hsm_unavailable", "inb_block_if_hsm_unavailable", "fwd_block_if_no_resource",
    "inb_block_if_no_resource", "fwd_block_tls13_downgrade_no_resource",
    "inb_block_tls13_downgrade_no_resource",
)


def kind_query(kind):
    return {"model": "integrations.SecurityProfile", "operator": "and",
            "clauses": [{"field": "kind", "op": "eq", "value": kind, "negated": False}]}


class DecryptionRailTests(TestCase):
    """The ninth page over the shared model, and the second page at one Device address."""

    def test_the_decryption_kind_resolves_to_its_own_page(self):
        obj = cr.object_for_canonical_query(kind_query("decryption"))
        self.assertIsNotNone(obj, "decryption resolves to no page")
        self.assertEqual("decryption-profile", obj.slug)

    def test_it_reaches_no_sibling_page(self):
        """The failure the resolver's own docstring names: a link that goes somewhere plausible
        and wrong is worse than no link."""
        self.assertEqual("/assessments/configuration/objects/decryption-profile/",
                         cr.query_results_url(kind_query("decryption")))

    def test_its_scope_is_exactly_one_kind_clause(self):
        """Nothing looser. An empty scope is a subset of EVERY query over this model, so it would
        match beside each of the eight siblings, make `matched` two long, and push all nine kinds
        to None - breaking the eight pages that already worked rather than only the new one."""
        scope = cr.RESULTS["decryption-profile"].scope
        self.assertIsNotNone(scope)
        self.assertEqual(1, len(scope["clauses"]))
        self.assertEqual("kind", scope["clauses"][0]["field"])
        self.assertEqual("decryption", scope["clauses"][0]["value"])

    def test_all_nine_pages_over_the_shared_model_still_resolve(self):
        """Measured over the whole model and not only this domain's kind, each to its OWN slug."""
        items = objects_for_model("integrations.SecurityProfile")
        self.assertEqual(9, len(items))
        self.assertIn("decryption-profile", [o.slug for o in items])
        for obj in items:
            with self.subTest(slug=obj.slug):
                scope = cr.RESULTS[obj.slug].scope
                self.assertIsNotNone(scope, f"{obj.slug} has no kind scope")
                self.assertEqual(1, len(scope["clauses"]))
                kind = scope["clauses"][0]["value"]
                self.assertEqual(obj.slug, cr.object_for_canonical_query(kind_query(kind)).slug)

    def test_the_decryption_profile_is_a_top_level_objects_item_and_not_a_profile_child(self):
        """MEASURED, because the brief that commissioned this said otherwise. Web Interface Help
        11.1 p.213, 11.2 p.213 and 12.2 p.215 all read "... Objects>Authentication •
        Objects>Decryption Profile • Objects > SD-WAN Link Management • Objects>Schedules", and
        nothing in any document in the corpus says `Objects > Decryption > Decryption Profile`."""
        item = next(o for o in CONFIG_OBJECTS if o.slug == "decryption-profile")
        self.assertEqual("", item.group, "the vendor gives it no rail heading")
        self.assertEqual("Objects", item.category)
        self.assertEqual("Objects > Decryption Profile", item.where)

    def test_it_follows_the_whole_security_profiles_block(self):
        """The vendor's own order: Security Profiles, Security Profile Groups, Log Forwarding,
        Authentication, Decryption Profile. So it is after every `Security Profiles` item, which
        is also what `test_file_data_filtering_presentation.KINDS_AND_SLUGS` asserts positionally
        for the model's pages."""
        slugs = [o.slug for o in CONFIG_OBJECTS if o.category == "Objects"]
        profiles = [i for i, slug in enumerate(slugs)
                    if next(o for o in CONFIG_OBJECTS if o.slug == slug).group
                    == "Security Profiles"]
        self.assertTrue(profiles)
        self.assertGreater(slugs.index("decryption-profile"), max(profiles))

    def test_the_signing_model_has_a_page_of_its_own_at_the_certificate_address(self):
        """A SECOND item at one vendor address over a DIFFERENT model - `data-filtering-posture`'s
        pattern. The address is the vendor's: help 11.2 p.170, "Create a certificate on the Device
        > Certificate Management > Certificates page and then click the name of the certificate and
        select Forward Trust Certificate"."""
        items = objects_for_model("integrations.DecryptionSettings")
        self.assertEqual(["forward-proxy-signing"], [o.slug for o in items])
        self.assertEqual("Device > Certificate Management > Certificates", items[0].where)
        self.assertEqual("Device", items[0].category)
        certificates = next(o for o in CONFIG_OBJECTS if o.slug == "certificates")
        self.assertEqual(certificates.where, items[0].where)

    def test_the_signing_page_declares_no_kind_scope(self):
        """Its model has ONE page, so `object_for_canonical_query` short-circuits and a scope
        would be dead weight that a later second page would have to reckon with."""
        self.assertIsNone(cr.RESULTS["forward-proxy-signing"].scope)

    def test_every_rail_slug_is_globally_unique(self):
        """`RESULTS` is keyed on the SLUG ALONE while `CONFIG_OBJECTS_BY_KEY` is keyed on
        (category, slug), so two items sharing a slug collapse onto one results spec. This domain
        put a second item at an address another item already held, which is where that would
        have happened."""
        slugs = [o.slug for o in CONFIG_OBJECTS]
        self.assertEqual(sorted(set(slugs)), sorted(slugs))

    def test_both_new_items_claim_a_real_category_and_carry_a_results_spec(self):
        for slug in ("decryption-profile", "forward-proxy-signing"):
            with self.subTest(slug=slug):
                item = next(o for o in CONFIG_OBJECTS if o.slug == slug)
                self.assertIn(item.category, CATEGORIES)
                self.assertIn(slug, cr.RESULTS)
                self.assertTrue(item.where)

    def test_this_domain_has_no_presentation_debt_left(self):
        """Clearing the prefix is part of this stage's job rather than a side effect of it: an
        exemption that survives the work it was waiting for is a permanent hole."""
        self.assertNotIn("PAN-DCP", cr.AWAITING_PRESENTATION)

    def test_every_control_of_this_domain_reaches_a_results_page(self):
        """All 25 shipped queries, which is what the cleared prefix stops exempting. Measured per
        QUERY and not per control, because `test_every_query_in_the_shipped_catalog_has_somewhere
        _to_go` fails once per query."""
        for control in seed_controls(PAN_DCP):
            for query in control.queries.all():
                with self.subTest(control=control.control_id, query=query.name):
                    self.assertTrue(cr.query_results_url(query.canonical_query),
                                    f"{control.control_id}/{query.name} goes nowhere")


class DecryptionExplorerPageTests(TestCase):
    """The two explorer pages' cells, over real rows."""

    @classmethod
    def setUpTestData(cls):
        cls.station = ManagementStation.objects.create(
            station_type="panorama", name="t", hostname="t", username="u", password="p",
            ca_bundle_path="", notes="")
        cls.group = ApplianceGroup.objects.create(
            management_station=cls.station, name="g", discovery_key="g", notes="")
        cls.appliance = Appliance.objects.create(
            management_station=cls.station, appliance_group=cls.group, hostname="fw-a",
            serial_number="S1", model="PA-VM", software_version="11.2.5",
            device_certificate_status="valid", notes="")
        cls.group.active_appliance = cls.appliance
        cls.group.save()
        # `EnforcementPoint.in_scope` DEFAULTS FALSE and the shared-scope normalisers filter on
        # it, so a hand-seeded estate normalises zero shared objects without this.
        cls.point = EnforcementPoint.objects.create(
            management_station=cls.station, appliance_group=cls.group, appliance=cls.appliance,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True, discovery_key="k",
            notes="")
        # `EnforcementNode` rows are required or the whole workbook refuses to build.
        EnforcementNode.objects.create(management_station=cls.station,
                                       enforcement_point=cls.point, appliance=cls.appliance,
                                       notes="")
        # `source_snapshot` is NOT NULL on both of this domain's models.
        cls.snapshot = Snapshot.objects.create(
            management_station=cls.station, appliance=cls.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

    def profile(self, name, kind="decryption", **cols):
        return SecurityProfile.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, name=name, kind=kind, namespace_type="local_vsys",
            namespace_value="vsys1", precedence_rank=10, config_source="local", description="",
            **cols)

    def settings(self, **cols):
        return DecryptionSettings.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot, **cols)

    def cells(self, slug, obj):
        spec = cr.RESULTS[slug]
        return dict(zip(spec.columns, spec.row(obj)))

    def test_each_page_builds_a_row_the_same_length_as_its_columns(self):
        """`cells()` below zips, which truncates silently, so the length is asserted on its own.
        The shipped squareness check needs rows in the database to reach these two specs."""
        profile = self.profile("p-square")
        settings = self.settings()
        for slug, obj in (("decryption-profile", profile),
                          ("forward-proxy-signing", settings)):
            with self.subTest(slug=slug):
                spec = cr.RESULTS[slug]
                self.assertEqual(len(spec.columns), len(spec.row(obj)))

    def test_the_seven_algorithm_switches_say_permitted_rather_than_yes(self):
        """STAGE 5 REQUIRES THESE SEVEN COLUMNS and `yes`/`no` is ambiguous on them in a way it is
        not elsewhere on the row: the twelve block switches beside them are BLOCK switches where
        false is the weak direction, and these seven are ALLOW switches where TRUE is. A column of
        `yes` and `no` under two opposite polarities, with nothing in the heading announcing the
        change, is the shape the model's own comment warns a query author about."""
        profile = self.profile("p-algos", enc_algo_rc4=True, auth_algo_md5=False)

        cells = self.cells("decryption-profile", profile)

        self.assertEqual("permitted", cells["Encryption Algorithms: RC4"])
        self.assertEqual("not permitted", cells["Authentication Algorithms: MD5"])

    def test_the_seven_algorithm_switches_are_shown_and_not_queryable(self):
        """Stage 5 marks all seven `presented` with its reason - collapsing to one token means a
        report naming RC4 is silent about SHA-1 on the same profile - and none of the seven is in
        the search registry, because only a column a control asks for is registered."""
        spec = cr.RESULTS["decryption-profile"]
        for heading in ("Key Exchange Algorithms: RSA", "Encryption Algorithms: 3DES",
                        "Encryption Algorithms: RC4", "Encryption Algorithms: AES-128-CBC",
                        "Encryption Algorithms: AES-256-CBC", "Authentication Algorithms: MD5",
                        "Authentication Algorithms: SHA1"):
            with self.subTest(heading=heading):
                self.assertIn(heading, spec.columns)
                self.assertNotIn(heading, spec.query_fields)

    def test_the_compliant_member_of_a_graded_column_is_spelled(self):
        """`none` is the PASSING member of both weakest-algorithm columns, and a cell reading
        `none` beside a passing row reads as "no value recorded" where it means "nothing weak is
        negotiable". This is the same shape as `url-filtering`'s empty request-header column."""
        profile = self.profile("p-clean", weakest_broken_primitive_permitted="none",
                               weakest_non_pfs_or_unauthenticated_permitted="none")

        cells = self.cells("decryption-profile", profile)

        self.assertEqual("None negotiable",
                         cells["Weakest broken algorithm still negotiable"])
        self.assertEqual(
            "None negotiable",
            cells["Weakest algorithm lacking forward secrecy or authenticated encryption"])

    def test_a_failing_graded_cell_carries_the_vendors_own_algorithm_spelling(self):
        profile = self.profile("p-rc4", weakest_broken_primitive_permitted="rc4",
                               weakest_non_pfs_or_unauthenticated_permitted="aes-128-cbc")

        cells = self.cells("decryption-profile", profile)

        self.assertEqual("RC4", cells["Weakest broken algorithm still negotiable"])
        self.assertEqual(
            "AES-128-CBC",
            cells["Weakest algorithm lacking forward secrecy or authenticated encryption"])

    def test_an_unresolvable_ceiling_says_so_rather_than_showing_a_blank(self):
        """BLANK in the store means the appliance's build is not one the ceiling resolver covers,
        and the verdict beside it then stays on the firing side - so the row is reported on the
        strength of a reading nobody established. An empty cell would not say that, and this is
        the one row where the resolution IS the finding."""
        unresolved = self.profile("p-max", ssl_max_version="max", ssl_max_version_resolved="")
        resolved = self.profile("p-max-ok", ssl_max_version="max",
                                ssl_max_version_resolved="tls1-3")

        self.assertEqual("Could not be resolved for this build",
                         self.cells("decryption-profile", unresolved)["Max Version in force"])
        self.assertEqual("TLSv1.3",
                         self.cells("decryption-profile", resolved)["Max Version in force"])

    def test_the_explorer_page_shows_the_vendors_version_spelling(self):
        """The store holds the DEVICE's spelling, which the model requires. Help 11.2 p.341 and
        p.345 give the vendor's six UI values verbatim, and this page prints those - while the
        FINDINGS tab keeps the raw token, because a reader there would cost the column's
        provenance row."""
        profile = self.profile("p-v", ssl_min_version="tls1-0", ssl_max_version="max")

        cells = self.cells("decryption-profile", profile)

        self.assertEqual("TLSv1.0", cells["Min Version"])
        self.assertEqual("Max", cells["Max Version"])

    def test_an_empty_designation_slot_says_nothing_designated(self):
        """An empty slot is the whole finding PAN-DCP-006 makes, and a blank cell reads as missing
        data. The store holds "" and not NULL - the search layer's `is_empty` compiles to
        `filter(field="")` - so `display_value` could only ever print `(empty)` here."""
        row = self.settings(forward_trust_cert_rsa="oep-p1-cert")

        cells = self.cells("forward-proxy-signing", row)

        self.assertEqual("oep-p1-cert", cells["Forward Trust Certificate (RSA)"])
        self.assertEqual("Nothing designated", cells["Forward Trust Certificate (ECDSA)"])
        self.assertEqual("Nothing designated", cells["Forward Untrust Certificate (RSA)"])

    def test_every_queryable_heading_on_both_pages_names_a_registered_field(self):
        """A heading mapped to an unregistered field points the "build a query from these rows"
        button at a lookup that refuses itself or silently matches nothing. Stored, searchable and
        registered are three different things, and `ssl_max_version_resolved` is the case in point:
        it is a COLUMN on this page and deliberately not a `query_fields` entry."""
        from assessments.search import registry
        for slug, model in (("decryption-profile", "integrations.SecurityProfile"),
                            ("forward-proxy-signing", "integrations.DecryptionSettings")):
            registered = registry.MODEL_REGISTRY[model]["field_operators"]
            for heading, field in cr.RESULTS[slug].query_fields.items():
                with self.subTest(slug=slug, heading=heading):
                    self.assertIn(field, registered)

    def test_the_resolved_ceiling_is_shown_and_not_queryable(self):
        """Both halves, because the useful statement is not "it is absent" but "it is presented
        and withheld from the builder", and a later run adding the registry entry should see this
        fail rather than silently gain a clause nobody asked for."""
        spec = cr.RESULTS["decryption-profile"]
        self.assertIn("Max Version in force", spec.columns)
        self.assertNotIn("Max Version in force", spec.query_fields)

    def test_the_four_designation_slots_are_shown_and_not_queryable(self):
        """Their compiler declines to register them in terms - "registering them would ship a
        search surface no control asks for" - and stage 9's half of that bargain is to SHOW them."""
        spec = cr.RESULTS["forward-proxy-signing"]
        for heading in ("Forward Trust Certificate (RSA)", "Forward Trust Certificate (ECDSA)",
                        "Forward Untrust Certificate (RSA)",
                        "Forward Untrust Certificate (ECDSA)"):
            with self.subTest(heading=heading):
                self.assertIn(heading, spec.columns)
                self.assertNotIn(heading, spec.query_fields)


class DecryptionFindingsTabTests(TestCase):
    """The two tabs this domain reports to, built over a real estate."""

    @classmethod
    def setUpTestData(cls):
        cls.controls = seed_controls(PAN_DCP)
        cls.station = ManagementStation.objects.create(
            station_type="panorama", name="t", hostname="t", username="u", password="p",
            ca_bundle_path="", notes="")
        cls.group = ApplianceGroup.objects.create(
            management_station=cls.station, name="g", discovery_key="g", notes="")
        cls.appliance = Appliance.objects.create(
            management_station=cls.station, appliance_group=cls.group, hostname="fw-a",
            serial_number="S1", model="PA-VM", software_version="11.2.5",
            device_certificate_status="valid", notes="")
        cls.group.active_appliance = cls.appliance
        cls.group.save()
        cls.point = EnforcementPoint.objects.create(
            management_station=cls.station, appliance_group=cls.group, appliance=cls.appliance,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True, discovery_key="k",
            notes="")
        EnforcementNode.objects.create(management_station=cls.station,
                                       enforcement_point=cls.point, appliance=cls.appliance,
                                       notes="")
        cls.snapshot = Snapshot.objects.create(
            management_station=cls.station, appliance=cls.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

    def profile(self, name, kind="decryption", **cols):
        return SecurityProfile.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, name=name, kind=kind, namespace_type="local_vsys",
            namespace_value="vsys1", precedence_rank=10, config_source="local", description="",
            **cols)

    def regenerate(self):
        from assessments.finding_run import regenerate_findings
        regenerate_findings()

    def table(self, slug):
        return build_findings_table(DOMAIN_BY_SLUG[slug].spec)

    # ---- the new tab -------------------------------------------------------------------------

    def test_the_signing_tab_builds_and_reports_its_control(self):
        DecryptionSettings.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot)
        self.regenerate()

        table = self.table("forward-proxy-signing")

        self.assertIn("PAN-DCP-006",
                      {row[table.headers.index("Control ID")] for row in table.rows})
        self.assertEqual("Device", table.category)
        self.assertEqual("Forward Proxy Signing", table.title)

    def test_the_signing_tab_says_its_verdicts_are_derived_and_where_the_slots_came_from(self):
        """THE DEFAULT PROVENANCE CELL WAS WRONG AND READING THE ROWS IS WHAT FOUND IT. It printed
        "Not recorded" twice, which means "nothing tracks this field" and reads to a customer as a
        gap in the collection: `remediation_accessor` treats a DERIVED row as no answer on purpose
        and walks to the object's `__entry__` row, which nothing writes for this model. The value
        is not untracked, it is derived - and the four designation slots it is derived FROM are the
        only thing on the row a device wrote, so the cell names their recorded provenance too."""
        DecryptionSettings.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot)
        self.regenerate()

        table = self.table("forward-proxy-signing")
        cell = table.rows[0][table.headers.index("Provenance")]

        self.assertTrue(cell.startswith("Derived"), cell)
        self.assertNotIn("Not recorded", cell)

    def test_the_signing_tab_carries_the_firing_condition_knowing_one_row_shape_is_wrong(self):
        """`tested_columns` defaults to `("Provenance",)`, which silently drops `Fires when` from
        the WORKBOOK while the live page keeps it, so the two surfaces disagree about which cell a
        reader meets (P427). Carried here KNOWING the cost: `fires_when` renders the BASELINE
        alone, so a row matched only by the calibration query prints a condition its own cell
        contradicts. That is asserted below rather than left as a comment, because it is the thing
        a reader of this tab will query."""
        self.assertIn("Fires when (failing condition)",
                      DOMAIN_BY_SLUG["forward-proxy-signing"].spec.tested_columns)

    def test_a_row_matched_only_by_the_calibration_query_prints_a_contradicting_condition(self):
        """MEASURED, not predicted. The baseline asserts the trust verdict and this row passes it;
        the finding comes from the untrust verdict alone. `fires_when` is
        `render_node(baseline_query(control))` with no per-spec hook, so the row states a condition
        it does not meet. Shared machinery - recorded, not worked around - and `Matched queries`
        plus the marked cell resolve it between them."""
        DecryptionSettings.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot,
            forward_trust_cert_rsa="ca", forward_trust_is_designated_local_ca=True)
        Certificate.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot, name="ca",
            scope="local_shared", is_ca=True, is_self_signed=True)
        self.regenerate()

        table = self.table("forward-proxy-signing")
        (row,) = table.rows
        fires = row[table.headers.index("Fires when (failing condition)")]
        trust = row[table.headers.index("Trust certificate is a local self-signed CA")]

        self.assertIn("forward_trust_is_designated_local_ca", fires)
        self.assertEqual("Yes", trust)
        self.assertEqual("No distinct forward-untrust authority",
                         row[table.headers.index("Matched queries")])

    def test_the_stated_condition_reads_in_django_field_names_after_labelling(self):
        """P437, measured AFTER the twenty-one labels landed rather than before. `render_node`
        builds its text from the clause's FIELD and consults `setting_labels` nowhere, so the same
        value is named two ways on one row: the heading says "Trust certificate is a local
        self-signed CA" and the condition above it says `forward_trust_is_designated_local_ca`.
        Shared machinery. Asserted so that a later fix to `render_node` shows up here as a failure
        to re-measure rather than as silence."""
        DecryptionSettings.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot)
        self.regenerate()

        table = self.table("forward-proxy-signing")
        fires = table.rows[0][table.headers.index("Fires when (failing condition)")]

        self.assertIn("forward_trust_is_designated_local_ca", fires)
        self.assertNotIn("Trust certificate is a local self-signed CA", fires)

    def test_the_signing_tab_hides_nothing(self):
        """The gate counts a field as presented if `hidden_fields` carries it, so a non-empty tuple
        is a CLAIM accepted as proof - and it is the only known cause in this repository of a
        findings row that marks nothing as the thing to fix (P409)."""
        self.assertEqual((), DOMAIN_BY_SLUG["forward-proxy-signing"].spec.hidden_fields)

    def test_the_signing_tab_shows_all_four_designation_slots(self):
        """No shipped query clauses on any of them, so `setting_columns` derives nothing and these
        subject columns are the only thing that puts them on the row. Each declares its `field`,
        which matters even though nothing would collide today: a subject column that declares no
        field does NOT suppress a derived column for the same attribute."""
        spec = DOMAIN_BY_SLUG["forward-proxy-signing"].spec
        declared = {column[4] for column in spec.subject_columns if len(column) > 4}
        for field in ("forward_trust_cert_rsa", "forward_trust_cert_ecdsa",
                      "forward_untrust_cert_rsa", "forward_untrust_cert_ecdsa"):
            with self.subTest(field=field):
                self.assertIn(field, declared)

    # ---- the shared tab ----------------------------------------------------------------------

    def test_no_field_this_domain_tests_heads_a_column_with_its_django_name(self):
        """DELIBERATELY SCOPED TO THIS DOMAIN'S FIELDS, as its two predecessors on this tab are.
        A heading lives in `setting_labels`, which falls back to the raw field name, so an entry
        deleted there is a database field name on a customer's report and nothing else would say
        so. Measured with THIS seed: 21 of the 41 headings read as Django names before the labels
        and 0 after - a figure that is a function of which controls are seeded and is not
        comparable with another domain's count on the same tab."""
        self.profile("p-raw")
        self.regenerate()

        for slug in ("security-profiles", "forward-proxy-signing"):
            table = self.table(slug)
            for field in OUR_FIELDS:
                with self.subTest(slug=slug, field=field):
                    self.assertNotIn(field, table.headers)

    def test_the_six_kind_gated_readers_give_another_kind_the_em_dash(self):
        """THE SINGLE LARGEST THING THIS RUN CHANGES ABOUT WHAT A CUSTOMER READS, and it changes
        ANOTHER DOMAIN'S ROWS. These six columns are derived from this domain's clauses, so they
        are drawn on every kind's row of the shared tab while meaning something on one: before
        this change an antivirus row told a customer `ssl_min_version_below_tls12 = Yes` and
        `weakest_broken_primitive_permitted = rc4`, which are the measured implicit values of keys
        an antivirus profile has no container for at all. Asserted on a REAL antivirus row, not by
        calling the readers."""
        antivirus = self.profile("p-av", kind=SecurityProfile.KIND_VIRUS)
        spec = DOMAIN_BY_SLUG["security-profiles"].spec

        for field in KIND_GATED:
            with self.subTest(field=field):
                self.assertIn(field, spec.value_readers)
                self.assertEqual(NONE, spec.value_readers[field].read(antivirus))

    def test_the_readers_answer_normally_on_a_decryption_row(self):
        profile = self.profile("p-dcp", ssl_min_version_below_tls12=True,
                               weakest_broken_primitive_permitted="none")
        spec = DOMAIN_BY_SLUG["security-profiles"].spec

        self.assertEqual("Yes", spec.value_readers["ssl_min_version_below_tls12"].read(profile))
        self.assertEqual(
            "None negotiable",
            spec.value_readers["weakest_broken_primitive_permitted"].read(profile))

    def test_is_used_is_deliberately_not_gated(self):
        """THE REFUSAL, and the one a later run is most likely to "complete" by mistake.
        `is_used` is not a decryption column - it sits beside `referrer_count` for every kind of
        this model and PAN-AVW-006 is a shipped control over exactly it - so a kind gate there
        would print an em dash over that control's own value-at-fault on five other kinds."""
        spec = DOMAIN_BY_SLUG["security-profiles"].spec
        self.assertNotIn("is_used", spec.value_readers)
        self.assertEqual("Named by a rule or profile group", spec.setting_labels["is_used"])

    def test_the_fourteen_measured_keys_keep_their_provenance_row(self):
        """THE LARGER HALF OF THE READER DECISION. A `value_readers` entry makes `tested_fields`
        report the field `stored=False`, `build_rows` hands that to `remediation_accessor`, which
        never reads the column's own `FieldProvenance` row, and `provenance_cells` answers
        "Derived" - so whether a block switch was ABSENT (the measured implicit) or TYPED to the
        failing value would stop being visible, and that distinction is most of what PAN-DCP-001
        and PAN-DCP-005 are about. Measured on the lab estate: 14 of 20 PAN-DCP-001 rows read
        `PAN-OS default` for the two version keys and 6 read `Local`, and a reader would have
        flattened all twenty to "Derived"."""
        spec = DOMAIN_BY_SLUG["security-profiles"].spec
        for field in REFUSED_READER:
            with self.subTest(field=field):
                self.assertNotIn(field, spec.value_readers)
                self.assertIn(field, spec.setting_labels)

    def test_the_absent_and_the_typed_floor_read_differently_in_the_provenance_cell(self):
        """The payoff of the refusal above, on real rows: two profiles with the SAME failing floor,
        one of which typed it and one of which has no key at all."""
        from optivedge_integrations.integrations.models import FieldProvenance
        typed = self.profile("p-typed", ssl_min_version="tls1-0")
        absent = self.profile("p-absent", ssl_min_version="tls1-0")
        FieldProvenance.objects.create(
            content_object=typed, field_name="ssl_min_version",
            provenance_type=FieldProvenance.ProvenanceType.LOCAL, raw_value="tls1-0")
        FieldProvenance.objects.create(
            content_object=absent, field_name="ssl_min_version",
            provenance_type=FieldProvenance.ProvenanceType.PAN_OS_DEFAULT, raw_value="")
        self.regenerate()

        table = self.table("security-profiles")
        prov = {row[table.headers.index("Object")]: row[table.headers.index("Provenance")]
                for row in table.rows
                if row[table.headers.index("Control ID")] == "PAN-DCP-001"}

        self.assertIn("Local", prov["p-typed"])
        self.assertIn("PAN-OS default", prov["p-absent"])

    def test_the_twelve_block_switch_headings_are_unique(self):
        """THE TAB-NAME PREFIX IS LOAD-BEARING AND NOT DECORATION. The vendor uses the SAME label
        on its two tabs for five of these switches, so five bare vendor labels would produce five
        DUPLICATE HEADINGS - and a table with a duplicate header is rejected by Excel, which
        xlsxwriter drops with a warning, leaving a sheet of stray cells where the table should be.
        This module's own `NAME` comment records that happening on this very tab on 2026-09-18."""
        spec = DOMAIN_BY_SLUG["security-profiles"].spec
        switches = [f for f in OUR_FIELDS if f.startswith(("fwd_block", "inb_block"))]
        self.assertEqual(12, len(switches))
        headings = [spec.setting_labels[f] for f in switches]
        self.assertEqual(sorted(set(headings)), sorted(headings))
        for heading in headings:
            with self.subTest(heading=heading):
                self.assertTrue(
                    heading.startswith(("Forward proxy: ", "Inbound inspection: ")), heading)

    def test_every_heading_on_the_shared_tab_is_unique(self):
        """The guard the prefix exists for, over the whole table rather than only this domain's
        block - because `setting_columns` draws every seeded domain's columns on one row."""
        self.profile("p-h")
        self.regenerate()

        headers = list(self.table("security-profiles").headers)
        self.assertEqual(sorted(set(headers)), sorted(headers))

    def test_the_shared_tab_still_drops_the_firing_condition_from_the_workbook(self):
        """NOT A REGRESSION AND NOT THIS RUN'S TO CHANGE: the shared sheet's `tested_columns` is
        the default, so the workbook omits `Fires when` while every live findings PAGE passes
        `ALL_TESTED_COLUMNS` and shows it. Measured here so the asymmetry is on the record rather
        than inferred - six of this domain's seven controls report onto this tab."""
        self.profile("p-f")
        self.regenerate()

        self.assertEqual(("Provenance",),
                         DOMAIN_BY_SLUG["security-profiles"].spec.tested_columns)
        self.assertNotIn("Fires when (failing condition)",
                         self.table("security-profiles").headers)

    def test_every_row_on_both_tabs_marks_something(self):
        """The property `hidden_fields` can fake and this run did not use: a findings row with no
        value-at-fault mark anywhere on it."""
        self.profile("p-m")
        DecryptionSettings.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot)
        self.regenerate()

        for slug in ("security-profiles", "forward-proxy-signing"):
            table = self.table(slug)
            marked = {row for row, _col in table.implicated}
            with self.subTest(slug=slug):
                self.assertTrue(table.rows, f"{slug} drew no rows")
                self.assertEqual(set(range(len(table.rows))), marked,
                                 f"{slug} has rows that mark nothing")


class DecryptionTabPlacementTests(TestCase):
    """Where the new tab sits, and that it did not take another domain's links."""

    def test_the_signing_tab_follows_the_certificates_tab(self):
        """`finding_run.GENERATORS` already placed this control type there with its own reasoning
        - the designation is a POINTER into the certificate store - and within a category the
        DOMAINS list takes that tuple's order."""
        from assessments.artifacts.domains import DOMAINS
        slugs = [d.slug for d in DOMAINS]
        self.assertEqual(slugs.index("certificates") + 1,
                         slugs.index("forward-proxy-signing"))

    def test_security_profile_links_still_land_on_the_shared_tab(self):
        """`_build_model_index` takes the FIRST domain claiming a MODEL. This domain claims
        `integrations.DecryptionSettings`, which no other domain claims, so nothing moved."""
        from assessments.artifacts.domains import domain_for_model
        self.assertEqual("security-profiles",
                         domain_for_model("integrations.SecurityProfile").slug)
        self.assertEqual("forward-proxy-signing",
                         domain_for_model("integrations.DecryptionSettings").slug)

    def test_both_tabs_derive_their_category_from_the_rail(self):
        """Right for a subject that IS a configuration object: deriving it means the workbook
        cannot disagree with the app about where the object lives."""
        for slug in ("security-profiles", "forward-proxy-signing"):
            with self.subTest(slug=slug):
                self.assertEqual("", DOMAIN_BY_SLUG[slug].spec.category)

    def test_the_profile_kinds_by_rule_tabs_stay_at_four(self):
        """`profile_kinds.KINDS` drives a findings domain per entry, so adding one would build a
        by-rule tab. Every control of this domain is about the PROFILE - its protocol range, its
        algorithm set, its block switches, whether anything names it - and not about a per-rule
        threat action, so such a tab is empty by construction. That is the module's own stated
        reason for leaving PAN-AVW-006 out, and `zone-dos-protection` and `file-data-filtering`
        each made the same call for their kinds."""
        from assessments.artifacts.sheets import profile_kinds
        self.assertEqual(4, len(profile_kinds.KINDS))
        self.assertEqual((), tuple(c for c in profile_kinds.EVERY_PROFILE_CONTROL
                                   if c.startswith("PAN-DCP")))

    def test_the_security_profile_sheet_declares_fourteen_readers_and_no_hidden_field(self):
        """A count, so that a reader added or removed on this shared sheet is a visible change
        rather than a silent one. Eight were here before this run and this run added six."""
        spec = DOMAIN_BY_SLUG["security-profiles"].spec
        self.assertEqual(14, len(spec.value_readers))
        self.assertEqual((), spec.hidden_fields)

    def test_the_sheet_is_reachable_through_the_control_type(self):
        self.assertIs(object_sheets.SPEC_BY_TYPE[Control.ControlType.DECRYPTION_SETTINGS],
                      DOMAIN_BY_SLUG["forward-proxy-signing"].spec)
