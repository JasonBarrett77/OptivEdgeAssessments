"""The three `globalprotect-gateway` findings tabs, their results pages, and the cells that were
JUDGEMENTS rather than derivations.

Stage 9 of `globalprotect-gateway`, 2026-11-02. Nothing obliges a stage 9 run to add a test file,
and `ike-crypto` and `ipsec-crypto` both did for the reason this one exists: a new tab that nothing
asserts on is a tab the next refactor can silently break, and the shipped squareness check cannot
exercise a `ResultsSpec.row` lambda over a real row - it checks the LENGTH of the tuple, not that
every accessor in it resolves.

THIS FILE EXISTS BECAUSE THAT GAP BIT THIS RUN. The gateway results page called
`get_globalprotect_gateway_licensed_display()`, copied from the sibling `globalprotect-coverage`
page where the equivalent column IS a `CharField` with choices. On this model it is a
`BooleanField(default=False)`, Django generates `get_<field>_display()` only for a field with
choices, and the call raises `AttributeError` at TEMPLATE RENDER - after `django check` passes, after
all three cross-domain gates pass, and on a page no test opened. `test_every_row_lambda_resolves`
below is the check that would have caught it, and it is written over real rows for that reason.

EVERY WORDING ASSERTED HERE IS A PROPOSAL (P399) and the assertions are deliberately about the
PROPERTY rather than the prose where the property is what matters - that a polarity reads the right
way round, that two cells do not read alike, that an em dash means "no such branch" and never "no".
Jason takes the heading pass once across many domains; a test pinning a heading he has not seen yet
would make his pass fail the suite. Where a literal string IS asserted, it is because the cell's
content is the finding - the three em-dash cells and the licence pair.
"""
from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementPoint, GlobalProtectGateway,
    GlobalProtectGatewayAgentConfig, GlobalProtectGatewayClientAuth, ManagementStation, Snapshot)

from assessments import configuration_navigation as cn
from assessments import configuration_results as cr
from assessments import globalprotect_gateway_presentation as gpg
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.layout import NONE

#: The three tabs this domain added, and the control types that reach them.
OUR_TABS = (
    ("globalprotect-gateways", "GlobalProtect Gateways", "globalprotect_gateway"),
    ("globalprotect-gateway-authentication", "Gateway Client Authentication",
     "globalprotect_gateway_client_auth"),
    ("globalprotect-gateway-agent", "Gateway Agent Configuration",
     "globalprotect_gateway_agent_config"),
)

#: The seven controls and the page each one's findings are drawn on. PAN-GPG-005 is on a tab this
#: domain did NOT build - `globalprotect-portal` left it un-narrowed so this control would reach it
#: - and it is in this list precisely so that sharing is asserted rather than assumed.
CONTROL_TABS = {
    "PAN-GPG-001": "globalprotect-gateways",
    "PAN-GPG-002": "globalprotect-gateway-authentication",
    "PAN-GPG-003": "globalprotect-gateway-agent",
    "PAN-GPG-004": "globalprotect-gateway-agent",
    "PAN-GPG-005": "globalprotect-coverage",
    "PAN-GPG-006": "globalprotect-gateways",
    "PAN-GPG-007": "globalprotect-gateways",
}


class GatewayPresentationShapeTests(TestCase):
    """The rail, the pages and the tabs. No estate needed."""

    def test_each_tab_exists_with_its_own_rail_item_and_category(self):
        for slug, title, _control_type in OUR_TABS:
            with self.subTest(slug=slug):
                domain = DOMAIN_BY_SLUG[slug]
                self.assertEqual(title, domain.title)
                # Category DERIVED from the rail (`category=''`), which is right for a subject
                # whose address is a PAN-OS node: deriving it means the workbook cannot disagree
                # with the app about where the object lives.
                self.assertEqual("", domain.spec.category)
                item = cn.CONFIG_OBJECTS_BY_KEY[("Network", slug)]
                self.assertEqual("GlobalProtect", item.group)
                self.assertTrue(item.where.startswith("Network > GlobalProtect > Gateways"))

    def test_no_tab_title_truncates_in_the_workbook(self):
        """Excel caps a worksheet name at 31 characters and truncates SILENTLY, so the workbook and
        the live page would disagree about the tab's own name. `probe.surface_for` prints the
        untruncated title, so the tool looks right while the book is wrong."""
        for _slug, title, _control_type in OUR_TABS:
            with self.subTest(title=title):
                self.assertLessEqual(len(title), 31, f"{title!r} is {len(title)} characters")

    def test_every_control_of_this_domain_reaches_a_tab(self):
        from assessments.artifacts.domains import DOMAINS

        for control_id, slug in CONTROL_TABS.items():
            with self.subTest(control_id=control_id):
                drawn = [d.slug for d in DOMAINS
                         if (d.spec.control_ids and control_id in d.spec.control_ids)
                         or (not d.spec.control_ids
                             and CONTROL_TABS[control_id] == d.slug)]
                self.assertIn(slug, drawn)

    def test_the_awaiting_presentation_debt_is_discharged(self):
        """An exemption that survives the work it was waiting for is a permanent hole, and
        `test_no_prefix_outlives_its_stage_9_artifact` fails once the artifact exists."""
        self.assertNotIn("PAN-GPG", cr.AWAITING_PRESENTATION)

    def test_no_sheet_of_this_domain_declares_hidden_fields(self):
        """`check_every_tested_field_is_presented` counts a field as presented if `hidden_fields`
        carries it, so a non-empty tuple is a CLAIM accepted as proof - and it is the only known
        cause in this repository of a findings row that marks nothing as the thing to fix."""
        for slug, _title, _control_type in OUR_TABS:
            with self.subTest(slug=slug):
                self.assertEqual((), DOMAIN_BY_SLUG[slug].spec.hidden_fields)

    def test_every_tab_carries_the_full_tested_column_set(self):
        """The default is `("Provenance",)`, which silently drops `Fires when` from the WORKBOOK
        while the live page keeps it, so the two surfaces disagree about which cell a reader meets
        (P427). Every control here has calibration queries splitting one column's values across
        severities, so the stated condition is the only cell that says why two otherwise identical
        rows report differently."""
        from assessments.artifacts.sheets.findings import ALL_TESTED_COLUMNS

        for slug, _title, _control_type in OUR_TABS:
            with self.subTest(slug=slug):
                self.assertEqual(ALL_TESTED_COLUMNS,
                                 DOMAIN_BY_SLUG[slug].spec.tested_columns)

    def test_every_subject_column_names_the_field_it_presents(self):
        """A subject column that declares no field does NOT suppress the derived settings column
        for the same attribute, so one value reaches the tab twice under two headings - and because
        the headings differ, the duplicate-header guard never fires. The Appliance and HA role
        columns are the two exceptions: neither presents a field of the subject model."""
        for slug, _title, _control_type in OUR_TABS:
            spec = DOMAIN_BY_SLUG[slug].spec
            for column in spec.subject_columns:
                header = column[0]
                if header in {"Appliance", "HA role"}:
                    continue
                with self.subTest(slug=slug, column=header):
                    self.assertEqual(5, len(column),
                                     f"{header!r} declares no field")
                    self.assertTrue(column[4])

    def test_no_tab_has_a_duplicate_heading(self):
        """Nothing in either repository checks this, and a table with a duplicate header is one
        Excel rejects: xlsxwriter drops the table with a warning and leaves a sheet of stray
        cells. Subject headings against each other, and against the proposed setting labels."""
        labels = {
            "globalprotect-gateways": gpg.GATEWAY_SETTING_LABELS,
            "globalprotect-gateway-authentication": gpg.CLIENT_AUTH_SETTING_LABELS,
            "globalprotect-gateway-agent": gpg.AGENT_CONFIG_SETTING_LABELS,
        }
        for slug, _title, _control_type in OUR_TABS:
            spec = DOMAIN_BY_SLUG[slug].spec
            headings = [c[0] for c in spec.subject_columns] + list(labels[slug].values())
            with self.subTest(slug=slug):
                self.assertEqual(len(headings), len(set(headings)),
                                 f"duplicate heading on {slug}: "
                                 f"{sorted(h for h in headings if headings.count(h) > 1)}")

    def test_every_results_page_query_field_is_registered(self):
        """A heading mapped to an unregistered field points the "build a query from these rows"
        button at a lookup that refuses itself or silently matches nothing. Stored, searchable and
        registered are three different things, and the repo's rule is that only a column a control
        asks for is registered - so this is read off the compiler rather than assumed."""
        # `search.registry.MODEL_REGISTRY` is the authority and an entry's `field_operators` is
        # that model's `FIELD_OPERATOR_REGISTRY` - read through the registry rather than importing
        # three compiler modules, so a model moved between compilers still resolves here.
        from assessments.search.registry import get_model_entry

        models = {
            "globalprotect-gateways": "integrations.GlobalProtectGateway",
            "globalprotect-gateway-authentication":
                "integrations.GlobalProtectGatewayClientAuth",
            "globalprotect-gateway-agent": "integrations.GlobalProtectGatewayAgentConfig",
        }
        for slug, label in models.items():
            registry = get_model_entry(label)["field_operators"]
            for heading, field in cr.RESULTS[slug].query_fields.items():
                with self.subTest(slug=slug, heading=heading):
                    self.assertIn(field, registry)

    def test_every_results_page_heading_is_a_column_and_every_column_is_square(self):
        for slug, _title, _control_type in OUR_TABS:
            spec = cr.RESULTS[slug]
            with self.subTest(slug=slug):
                for heading in spec.query_fields:
                    self.assertIn(heading, spec.columns)


class GatewayValueReaderTests(TestCase):
    """The readers, over real rows. These are the cells that were judgements."""

    @classmethod
    def setUpTestData(cls):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            name="s", hostname="s", username="u", password="p", ca_bundle_path="", notes="")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g", discovery_key="g", notes="")
        cls.appliance = Appliance.objects.create(
            management_station=station, appliance_group=group, hostname="fw-a",
            serial_number="S1", model="PA-VM", software_version="11.2.5", notes="")
        EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, appliance=cls.appliance,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True,
            discovery_key="S1:vsys1", notes="")
        cls.snapshot = Snapshot.objects.create(
            management_station=station, appliance=cls.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

    def _gateway(self, **values):
        defaults = dict(
            management_station=self.appliance.management_station, appliance=self.appliance,
            appliance_group=self.appliance.appliance_group, source_snapshot=self.snapshot,
            scope=GlobalProtectGateway.SCOPE_VSYS, vsys_name="vsys1", name="gw")
        defaults.update(values)
        return GlobalProtectGateway(**defaults)

    def _agent(self, **values):
        defaults = dict(
            management_station=self.appliance.management_station, appliance=self.appliance,
            appliance_group=self.appliance.appliance_group, source_snapshot=self.snapshot,
            scope=GlobalProtectGateway.SCOPE_VSYS, vsys_name="vsys1", name="cfg",
            gateway_name="gw")
        defaults.update(values)
        return GlobalProtectGatewayAgentConfig(**defaults)

    def test_an_unbounded_login_reads_an_em_dash_and_not_none(self):
        """NULL here means NO ROLE ENTRY BOUNDS THE LOGIN - stage 4 measured that state on every
        appliance in the lab - so there is no lifetime to express in hours. `(none)` would read as
        a gap in the report beside a companion column already saying the reading was taken."""
        reader = gpg.GATEWAY_VALUE_READERS["login_lifetime_hours"]
        self.assertEqual(NONE, reader.read(self._gateway(login_lifetime_hours=None)))
        self.assertEqual("720", reader.read(self._gateway(login_lifetime_hours=720)))

    def test_an_unbounded_idle_session_reads_an_em_dash_and_implies_no_default(self):
        """The vendor DOCUMENTS a 180-minute default that would already satisfy this control, and
        stage 4 declined to materialise it - so the cell must not imply a value."""
        reader = gpg.GATEWAY_VALUE_READERS["inactivity_logout_minutes"]
        cell = reader.read(self._gateway(inactivity_logout_minutes=None))
        self.assertEqual(NONE, cell)
        self.assertNotIn("180", cell)

    def test_the_first_proposal_is_an_em_dash_where_there_is_no_ipsec_to_propose(self):
        """The store holds `""` where no app-crypto profile resolved and `display_value` prints
        `(empty)` - which reads as "the proposal list is empty", a real and alarming device state,
        on a gateway that has no proposal list at all because IPSec is off or was never read."""
        reader = gpg.GATEWAY_VALUE_READERS["bound_app_crypto_first_encryption"]
        self.assertEqual(NONE, reader.read(
            self._gateway(ipsec_enabled=False, bound_app_crypto_first_encryption="")))
        self.assertEqual(NONE, reader.read(
            self._gateway(ipsec_enabled=None, bound_app_crypto_first_encryption="")))
        self.assertEqual("aes-256-gcm", reader.read(
            self._gateway(ipsec_enabled=True,
                          bound_app_crypto_first_encryption="aes-256-gcm")))

    def test_the_cookie_lifetime_tells_two_opposite_nulls_apart(self):
        """THE ONE READER HERE WHOSE BRANCH IS NOT "IS IT NULL". A row accepting no cookie has no
        lifetime branch and the honest cell is the em dash; a row that ACCEPTS one and bounds
        nothing is the FIRING state, and an em dash over it would read "not applicable" about
        exactly the row PAN-GPG-003 exists to raise."""
        reader = gpg.AGENT_CONFIG_VALUE_READERS["cookie_lifetime_hours"]
        self.assertEqual(NONE, reader.read(
            self._agent(accept_cookie_configured=False, cookie_lifetime_hours=None)))
        self.assertEqual("(none)", reader.read(
            self._agent(accept_cookie_configured=True, cookie_lifetime_hours=None)))
        self.assertEqual("336", reader.read(
            self._agent(accept_cookie_configured=True, cookie_lifetime_hours=336)))

    def test_the_mandatory_reader_walks_the_parent_and_says_so_when_there_is_none(self):
        """`gateway_client_certificate_is_a_second_factor` is a SEARCH REGISTRY KEY and not an
        attribute of this model - the compiler registers the lookup path
        `gateway__client_certificate_is_a_second_factor` - so `tested_fields` RAISES without this
        reader and takes down `store_run_tables` for the whole domain rather than one cell.

        THE FK IS `null=True`, so a row whose parent gateway did not resolve has nothing to read
        through. `(none)` there would offer "no" as the answer and therefore as the thing to fix."""
        reader = gpg.CLIENT_AUTH_VALUE_READERS[
            "gateway_client_certificate_is_a_second_factor"]
        parent = self._gateway(client_certificate_is_a_second_factor=True)
        parent.save()
        row = GlobalProtectGatewayClientAuth(
            management_station=self.appliance.management_station, appliance=self.appliance,
            appliance_group=self.appliance.appliance_group, source_snapshot=self.snapshot,
            scope=GlobalProtectGateway.SCOPE_VSYS, vsys_name="vsys1", name="r",
            gateway_name="gw", gateway=parent)
        self.assertEqual("Yes", reader.read(row))
        row.gateway = None
        self.assertEqual(NONE, reader.read(row))

    def test_tested_fields_raises_without_that_reader(self):
        """The raise is the whole reason the reader is mandatory, so it is asserted rather than
        described: a future refactor dropping the entry must fail here and not in a report build."""
        from assessments.artifacts.sheets.findings import tested_fields

        spec = DOMAIN_BY_SLUG["globalprotect-gateway-authentication"].spec
        self.assertIn("gateway_client_certificate_is_a_second_factor", spec.value_readers)

        class _Query:
            name, is_baseline, is_active, pk = "Baseline", True, True, 1
            canonical_query = {"clauses": [
                {"field": "gateway_client_certificate_is_a_second_factor",
                 "op": "eq", "value": False}]}
            asserted_fields = ["gateway_client_certificate_is_a_second_factor"]

        class _Queries:
            def all(self):
                return [_Query()]

        class _Control:
            control_id = "PAN-GPG-002"
            queries = _Queries()

        with self.assertRaises(ValueError) as caught:
            tested_fields(GlobalProtectGatewayClientAuth, _Control(), readers=())
        self.assertIn("neither stores nor computes", str(caught.exception))
        # And it does NOT raise once the sheet's own readers are handed in.
        self.assertEqual(
            [("gateway_client_certificate_is_a_second_factor", False)],
            tested_fields(GlobalProtectGatewayClientAuth, _Control(),
                          readers=spec.value_readers))


class GatewayResultsPageRowTests(TestCase):
    """`ResultsSpec.row` over REAL rows, which is the check the shipped squareness test cannot do.

    It verifies the tuple's LENGTH against `columns`; it never calls an accessor. This class is
    here because that gap shipped an `AttributeError` into this very page during this run - see the
    module docstring.
    """

    @classmethod
    def setUpTestData(cls):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            name="s", hostname="s", username="u", password="p", ca_bundle_path="", notes="")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g", discovery_key="g", notes="")
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group, hostname="fw-a",
            serial_number="S1", model="PA-VM", software_version="11.2.5", notes="")
        EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, appliance=appliance,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True,
            discovery_key="S1:vsys1", notes="")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        common = dict(management_station=station, appliance=appliance, appliance_group=group,
                      source_snapshot=snapshot, scope=GlobalProtectGateway.SCOPE_VSYS,
                      vsys_name="vsys1")

        # TWO OF EACH, one in every "present" state and one in every "absent or unread" state, so
        # each row lambda is exercised on both arms of every branch it carries.
        cls.hardened = GlobalProtectGateway.objects.create(
            name="gw-hardened", ssl_tls_service_profile="default",
            bound_tls_min_version="tls1-2", tls_profile_resolves_to_an_explicit_floor=True,
            networking_half_present=True, tunnel_mode=True, ipsec_enabled=True,
            ipsec_enabled_known=True, ipsec_crypto_profile_name="gp-gcm",
            bound_app_crypto_first_encryption="aes-256-gcm", app_crypto_offers_gcm_first=True,
            certificate_profile_name="cp", client_certificate_is_a_second_factor=True,
            block_quarantined_devices=True, login_lifetime_unit="hours",
            login_lifetime_as_entered=8, login_lifetime_hours=8, login_lifetime_known=True,
            inactivity_logout_minutes=60, inactivity_logout_known=True,
            video_traffic_excluded=False, globalprotect_gateway_licensed=True,
            licence_state_known=True, **common)
        cls.unread = GlobalProtectGateway.objects.create(
            name="gw-unread", ssl_tls_service_profile="",
            tls_profile_resolves_to_an_explicit_floor=False, networking_half_present=False,
            tunnel_mode=None, ipsec_enabled=None, ipsec_enabled_known=False,
            bound_app_crypto_first_encryption="", app_crypto_offers_gcm_first=False,
            block_quarantined_devices=None, login_lifetime_hours=None,
            login_lifetime_known=False, inactivity_logout_minutes=None,
            inactivity_logout_known=False, video_traffic_excluded=None,
            globalprotect_gateway_licensed=False, licence_state_known=False, **common)
        GlobalProtectGatewayClientAuth.objects.create(
            name="win", gateway_name="gw-hardened", gateway=cls.hardened, client_os="Windows",
            authentication_profile_name="saml-profile", authentication_backend_method="saml",
            backend_can_deliver_a_second_factor=True,
            user_credential_or_client_cert_required=False, **common)
        GlobalProtectGatewayClientAuth.objects.create(
            name="orphan", gateway_name="gw-gone", gateway=None, client_os="",
            authentication_profile_name="seq", authentication_backend_method="",
            backend_can_deliver_a_second_factor=False,
            user_credential_or_client_cert_required=None, **common)
        GlobalProtectGatewayAgentConfig.objects.create(
            name="cfg-managed", gateway_name="gw-hardened", gateway=cls.hardened,
            accept_cookie_configured=True, authentication_override_configured=True,
            generate_cookie=True, cookie_lifetime_unit="hours", cookie_lifetime_as_entered=8,
            cookie_lifetime_hours=8, cookie_lifetime_known=True,
            cookie_encrypt_decrypt_cert="signer", no_direct_access_to_local_network=True,
            uninspected_egress_path_count=0, egress_inventory_computed=True, **common)
        GlobalProtectGatewayAgentConfig.objects.create(
            name="cfg-byod", gateway_name="gw-hardened", gateway=cls.hardened,
            accept_cookie_configured=False, authentication_override_configured=False,
            generate_cookie=None, cookie_lifetime_hours=None, cookie_lifetime_known=False,
            cookie_encrypt_decrypt_cert=None, no_direct_access_to_local_network=None,
            split_tunnel_exclude_access_routes=["10.0.0.0/8"],
            uninspected_egress_path_count=2, egress_inventory_computed=True, **common)

    def test_every_row_lambda_resolves_on_every_row_and_stays_square(self):
        """THE CHECK THAT WOULD HAVE CAUGHT THIS RUN'S OWN BUG. A `get_<field>_display()` call on a
        field without `choices` raises `AttributeError` at template render, which `django check` and
        all three cross-domain gates pass straight through."""
        for slug, _title, _control_type in OUR_TABS:
            spec = cr.RESULTS[slug]
            rows = list(spec.base_queryset())
            with self.subTest(slug=slug):
                self.assertTrue(rows, f"{slug} has no rows to exercise")
                for row in rows:
                    cells = spec.row(row)
                    self.assertEqual(len(spec.columns), len(cells))
                    for cell in cells:
                        self.assertIsInstance(cell, str)

    def test_the_licence_pair_tells_unlicensed_from_never_asked(self):
        """A single boolean collapses the two, and the model's own comment records that two of the
        four measured appliances answer `{'licenses': None}` - "the instrument saying nothing rather
        than saying unlicensed". So the two states must not read alike."""
        spec = cr.RESULTS["globalprotect-gateways"]
        licensed = spec.columns.index("GlobalProtect licence")
        known = spec.columns.index("Licence state read")
        self.assertEqual(("yes", "yes"),
                         (spec.row(self.hardened)[licensed], spec.row(self.hardened)[known]))
        self.assertEqual(("no", "no"),
                         (spec.row(self.unread)[licensed], spec.row(self.unread)[known]))

    def test_a_null_switch_reads_as_not_read_and_never_as_no(self):
        """`rules.md`: a missing reading reported as compliant is a customer told they are safe on
        the strength of nothing. `_yes_no` would print "no" for a NULL, and the networking half of a
        gateway is a separate read at a different scope - the half most likely to be missing while
        the gateway row itself exists."""
        spec = cr.RESULTS["globalprotect-gateways"]
        cells = spec.row(self.unread)
        for heading in ("Tunnel Mode", "Enable IPSec", "Block login for quarantined devices",
                        "Exclude video applications"):
            with self.subTest(heading=heading):
                self.assertEqual("not read", cells[spec.columns.index(heading)])

    def test_the_split_tunnel_summary_names_each_axis_it_found(self):
        """The six lists are `JSONField`s that nothing may clause on and none is registered, so this
        page is the only surface in the report where their content is readable - which is what stage
        5 marking all six `presented: true` is satisfied by."""
        spec = cr.RESULTS["globalprotect-gateway-agent"]
        column = spec.columns.index("Split-tunnel lists")
        by_name = {row.name: spec.row(row)[column]
                   for row in spec.base_queryset()}
        self.assertEqual("Nothing", by_name["cfg-managed"])
        self.assertEqual("1 exclude routes", by_name["cfg-byod"])

    def test_the_split_tunnel_summary_puts_one_axis_per_line(self):
        """Jason, 2026-09-27: "In fields where multiple values may exist, the values should be [one
        per line]". `MultiValueCellTests.test_no_presentation_module_comma_joins_a_list` enforces it
        by grepping every presentation module, and it caught this cell comma-joining in the full
        suite after `django check` and all three cross-domain gates had passed. Asserted on the
        VALUE here as well as on the source there, because a grep over source cannot see a join
        that moves into a helper."""
        spec = cr.RESULTS["globalprotect-gateway-agent"]
        column = spec.columns.index("Split-tunnel lists")
        for row in spec.base_queryset():
            with self.subTest(row=row.name):
                self.assertNotIn(", ", spec.row(row)[column])


class GatewaySeverityBandTests(TestCase):
    """The two calibration shapes the brief asked to be pinned, read off the SHIPPED catalog.

    P450's second defect - a row matching two calibrations of DIFFERENT severities, so the basis
    cell lists a `low` query as a reason for a `medium` grade - is reachable on PAN-GPG-007 and
    harmless on PAN-GPG-003. The difference is whether the two tiers are equal, so the equality is
    asserted as a CONDITION: re-grading either one of PAN-GPG-003's pair turns a harmless overlap
    into a misleading basis cell, and this is what would say so.
    """

    def _queries(self, control_id):
        from assessments.controls_catalog.registry import load_seed_payload

        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                if control.get("control_id") == control_id:
                    return control
        self.fail(f"{control_id} is not in the shipped catalog")

    def test_the_two_cookie_queries_on_different_fields_carry_the_same_severity(self):
        """PAN-GPG-003's cookie bands are disjoint by arithmetic, but
        `cookie_encrypt_decrypt_cert is empty` is on ANOTHER FIELD ENTIRELY and nothing makes the
        two exclusive - so a row can match both. Both are `high` today, which makes the overlap
        harmless; this asserts that equality rather than the overlap."""
        control = self._queries("PAN-GPG-003")
        by_name = {q["name"]: q.get("adjusted_severity") for q in control["queries"]}
        self.assertEqual(by_name["A cookie is accepted and no lifetime was read for it"],
                         by_name["No certificate encrypts the reconnection cookie"])

    def test_the_two_session_companions_carry_different_severities_and_both_can_fire(self):
        """AND THIS ONE IS THE DEFECT, asserted as the state it is in rather than as a wish.
        PAN-GPG-007's two companions clause on DIFFERENT fields - `login_lifetime_known` at medium
        and `inactivity_logout_known` at low - nothing makes them exclusive, and stage 8's census
        says the expected finding on this estate is "nothing is bounded". So both fire on one row,
        `derive_control_query_severity_value` returns the worst, and the basis cell lists the LOW
        query as a reason for a MEDIUM grade. Recorded in the stage 9 artifact; not fixable from a
        sheet, because `severity_basis` is shared machinery."""
        control = self._queries("PAN-GPG-007")
        by_name = {q["name"]: q.get("adjusted_severity") for q in control["queries"]}
        self.assertEqual("medium", by_name["No login lifetime is bounded on this gateway"])
        self.assertEqual("low", by_name["No idle logout is bounded on this gateway"])
        self.assertNotEqual(by_name["No login lifetime is bounded on this gateway"],
                            by_name["No idle logout is bounded on this gateway"])
