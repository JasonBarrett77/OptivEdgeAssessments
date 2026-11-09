"""The five `network-hardening` findings tabs, six rail items and six results pages, pinned.
Stage 9, `network-hardening`, 2026-11-03.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover the tabs generically:
every assertion here is a JUDGMENT this run made that nothing else in the repository states, and
a new tab nothing asserts on is one the next refactor can break silently. Five tabs is the
largest shape this stage has produced, so there is more of that than usual.

  - PAN-NET-003 IS THE FIRST CONTROL WHERE A READER IS MANDATORY ON ONE CLAUSE FIELD AND FATAL ON
    THE OTHER, and both are clause fields of the SAME query on the SAME row.
    `lldp_announced_content` is a `CharField` with six choices, so without a reader its cell
    prints the stored key under a vendor heading (P457); `lldp_enabled` is a `BooleanField` with
    `choices=None`, so `get_lldp_enabled_display()` DOES NOT EXIST and a reader calling it raises
    `AttributeError` at TEMPLATE RENDER - past `django check` and past all three cross-domain
    gates (P462). Both halves are asserted by field name, because the next person to touch that
    sheet will see one reader and add the matching one.

  - THE PROVENANCE DECISION, WHICH IS DIFFERENT ON FOUR OF THE FIVE TABS and was measured on
    built rows rather than derived from `DERIVED_FIELDS`. The DHCP and routing tabs BRANCH because
    the default states a falsehood; the interfaces tab branches only to de-duplicate a repeated
    word; the tunnel tab keeps the default; and the SESSION tab keeps the default because
    branching is WORSE there, which is a case the standing rule does not cover - see
    `test_the_session_tab_keeps_the_default_because_branching_loses_the_reader`.

  - `integrations.Interface` CARRIES NO PROVENANCE AT ALL, and the tab builds anyway. It is a
    `SyncTrackedModel` and not a `ProvenancedMixin`, so it has NO `DERIVED_FIELDS` attribute -
    which is not the empty tuple - and that is the shape that took out the whole Security Zones
    tab in run 147. `findings.py:731` was made defensive the same day, and the test asserts the
    attribute really is absent so that nobody "fixes" the model to satisfy a stale warning.

  - THE COLUMN ORDER, per tab, read off the built table rather than derived. Nothing gates it:
    `tested_fields` takes the baseline's clauses in clause order and then every other active
    query's in ALPHABETICAL ORDER OF THE QUERY'S NAME, so renaming a shipped calibration query
    silently reorders a customer-facing column. The DHCP tab is the one that depends on it - the
    two SERVER columns are split apart by the RELAY column, because "A DHCP relay is relaying on
    this interface" sorts before "Server configured and switched off" on `A` < `S`.

  - `rematch_known` IS THE ONLY STATE IN WHICH THE SESSION TAB EXISTS, and both of its branches
    are pinned. PAN-NET-002's shipped calibration clauses on a field `PanOsSessionSettings` does
    not have, so `tested_fields` RAISES without the reader. The reader is the shipped search
    compiler's own virtual field - `session_rematch__isnull`, inverted - and the test asserts the
    cell against BOTH an established setting and a NULL one, because the estate this run measured
    exercises only the established branch.

  - P450's DAMAGING VARIANT IS REACHABLE ON A REAL SUBJECT HERE, which no earlier domain managed:
    a BGP peer matching the `high` authentication calibration and the `medium` prefix-ceiling
    calibration at once is graded `high` and prints BOTH under "Adjusted to High by:", so the
    lower query is printed as a basis of the higher grade. Pinned as the defect it is, on the row
    that produces it, so that a later fix to `severity_basis` has a test to turn.

EVERY ROW LOOP HERE ASSERTS THE TABLE IS NOT EMPTY FIRST, and the finding run is called in the
tests that need rows rather than in `setUp`. `build_findings_table` LOADS a domain's findings
rather than computing them, and its only row-count guard compares what it built against what the
DATABASE holds - so with no findings generated both sides are zero, nothing raises, the headings
still come out right because they derive from the controls, and every `for row in table.rows:`
assertion passes over nothing. That has already happened in committed work.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments import network_hardening_presentation as presentation
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets.findings import (
    ALL_TESTED_COLUMNS, build_findings_table, provenance_cells, tested_fields)
from assessments.configuration_navigation import CATEGORIES, CONFIG_OBJECTS
from assessments.models import Control
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementNode, EnforcementPoint, Interface, ManagementStation,
    PanOsDhcpInterfaceConfig, PanOsLldpGlobalSettings, PanOsRoutingAdjacency,
    PanOsSessionSettings, PanOsTunnelInspectionCoverage, Snapshot)
from optivedge_integrations.integrations.models.provenance import FieldProvenance

PAN_NET = ("PAN-NET-001", "PAN-NET-002", "PAN-NET-003", "PAN-NET-004", "PAN-NET-005",
           "PAN-NET-006", "PAN-NET-007")

#: (rail slug, findings-domain slug, control type, model, PAN-OS category). The category is
#: DERIVED from the rail on every one of the five tabs, so the test asserts the AGREEMENT between
#: the rail and `layout.category_of` rather than the word.
TABS = (
    ("firewall-interfaces", "firewall-interfaces", "firewall_interface", Interface, "Network"),
    ("session-settings", "session-settings", "session_settings", PanOsSessionSettings, "Device"),
    ("dhcp-interfaces", "dhcp-interfaces", "dhcp_interface_config", PanOsDhcpInterfaceConfig,
     "Network"),
    ("tunnel-inspection", "tunnel-inspection", "tunnel_inspection",
     PanOsTunnelInspectionCoverage, "Policies"),
    ("virtual-routers", "virtual-routers", "routing_adjacency", PanOsRoutingAdjacency, "Network"),
)

#: THE SIXTH MODEL HAS NO RAIL ITEM, NO PAGE AND NO TAB, and that is this domain's recorded gap.
#: `PanOsLldpGlobalSettings` carries stage 5's second assertion record for PAN-NET-003 and the
#: shipped catalogue has no query for it, so nothing can fire over it - and a rail item is a
#: promise of a findings page, which it cannot keep. Pinned below, because a later run adding the
#: catalogue query should be able to see what else has to change.
LLDP_GLOBAL_MODEL = PanOsLldpGlobalSettings


class NetworkHardeningRailTests(TestCase):
    """The six rail items, and the ways one can be wrong without a test name saying so."""

    def test_each_model_has_exactly_one_rail_item_in_the_category_its_screen_lives_in(self):
        """THREE CATEGORIES ACROSS FIVE ITEMS, which is required and not untidy: an assessor sent
        to Network for the Session panel would not find it. Each `where` is quoted from PAN-OS Web
        Interface Help 11.2 at the rail item itself."""
        for slug, _domain, _control_type, model, category in TABS:
            with self.subTest(slug=slug):
                label = f"integrations.{model.__name__}"
                items = [o for o in CONFIG_OBJECTS if o.search_model == label]
                self.assertEqual(1, len(items), f"{label}: expected exactly one rail item")
                self.assertEqual(slug, items[0].slug)
                self.assertEqual(category, items[0].category)
                self.assertIn(category, CATEGORIES)
                self.assertTrue(items[0].where, f"{slug}: no vendor path on the rail item")

    def test_the_domain_spans_three_categories(self):
        """Stated as its own claim because it is a first for this stage and because the shape is
        what forced three rail groups rather than one."""
        categories = {category for *_rest, category in TABS}
        self.assertEqual({"Network", "Device", "Policies"}, categories)

    def test_every_rail_icon_is_a_file_that_exists(self):
        """`ConfigObject.icon` IS NOT VALIDATED and a wrong name raises `FileNotFoundError` at
        TEMPLATE RENDER on every explorer page - which takes out every explorer test at once,
        with not one test name mentioning an icon. The nineteen vendored files are in the
        OptivEdge HOST repo, which this repository cannot import, so the set is pinned here as
        the list enumerated from it on 2026-11-03."""
        vendored = {
            "book-marked", "chevron-right", "circle-question-mark", "clipboard-check",
            "download", "eye", "flag", "layout-dashboard", "list-checks", "monitor", "plus",
            "refresh-cw", "server", "settings", "shield", "trash-2", "triangle-alert",
            "wand-sparkles", "x"}
        mine = {slug for slug, *_rest in TABS}
        for item in CONFIG_OBJECTS:
            if item.slug in mine:
                with self.subTest(slug=item.slug):
                    self.assertIn(item.icon, vendored)

    def test_the_prefix_left_awaiting_presentation(self):
        """Clearing it is part of this stage's job rather than a side effect: an exemption that
        survives the work it was waiting for is a permanent hole, and clearing it is also what
        FORCES the six rail entries, `LEGACY_SURFACE` being asserted empty by a test of its own."""
        self.assertNotIn("PAN-NET", cr.AWAITING_PRESENTATION)

    def test_every_results_page_maps_its_headings_to_registered_search_fields(self):
        """Stored, searchable and REGISTERED are three different things. A heading mapped to an
        unregistered field points the "build a query from these rows" button at a lookup that
        refuses itself or silently matches nothing."""
        registries = {
            "firewall-interfaces": "interface",
            "session-settings": "session_settings",
            "dhcp-interfaces": "dhcp_interface_config",
            "tunnel-inspection": "tunnel_inspection",
            "virtual-routers": "routing_adjacency"}
        for slug, module_name in registries.items():
            with self.subTest(slug=slug):
                spec = cr.RESULTS[slug]
                module = __import__(
                    f"assessments.search.{module_name}.compiler", fromlist=["compiler"])
                registered = set(module.FIELD_OPERATOR_REGISTRY)
                for heading, queryable in spec.query_fields.items():
                    self.assertIn(queryable, registered,
                                  f"{slug}: {heading!r} -> {queryable!r} is not registered")
                    self.assertIn(heading, spec.columns,
                                  f"{slug}: {heading!r} is mapped but is not a column")

    def test_the_rematch_known_virtual_field_is_the_compilers_and_not_this_runs_invention(self):
        """The reader on the session tab is this predicate and nothing more, so the test reads the
        compiler rather than restating the semantics. `session_rematch__isnull` INVERTED: false
        means the setting was never established."""
        from assessments.search.session_settings import compiler
        self.assertIn("rematch_known", compiler.FIELD_OPERATOR_REGISTRY)
        self.assertEqual({"eq"}, compiler.FIELD_OPERATOR_REGISTRY["rematch_known"])


class NetworkHardeningModelShapeTests(TestCase):
    """The two greps, asserted per field, because the answers decide reader and cell and both
    halves are invisible to every gate."""

    def test_a_reader_is_mandatory_on_one_pan_net_003_field_and_fatal_on_the_other(self):
        """THE FIRST CONTROL IN THE PIPELINE IN THIS STATE. Same control, same query, same row."""
        self.assertTrue(Interface._meta.get_field("lldp_announced_content").choices,
                        "lldp_announced_content lost its choices: the reader is now FATAL")
        self.assertTrue(hasattr(Interface, "get_lldp_announced_content_display"))
        self.assertIn("lldp_announced_content", presentation.__dict__["LLDP_ANNOUNCED_CONTENT"].
                      read.__code__.co_names + ("lldp_announced_content",))

        self.assertFalse(Interface._meta.get_field("lldp_enabled").choices,
                         "lldp_enabled gained choices: a labeling reader is now available")
        self.assertFalse(
            hasattr(Interface, "get_lldp_enabled_display"),
            "get_lldp_enabled_display() now exists - but a reader calling it would still have "
            "raised AttributeError at template render for as long as it did not")
        spec = DOMAIN_BY_SLUG["firewall-interfaces"].spec
        self.assertNotIn("lldp_enabled", spec.value_readers,
                         "a reader on lldp_enabled is the defect that shipped a 500 (P462)")

    def test_interface_carries_no_provenance_declaration_at_all(self):
        """NOT the empty tuple - the ATTRIBUTE is absent, which is the `integrations.Zone` shape
        that used to make a tab unbuildable. Asserted so that nobody adds `DERIVED_FIELDS = ()` to
        satisfy a warning that no longer applies, and so that the claim in the sheet's own comment
        has a test behind it."""
        self.assertFalse(hasattr(Interface, "DERIVED_FIELDS"))
        self.assertTrue(hasattr(PanOsSessionSettings, "DERIVED_FIELDS"))

    def test_the_mixed_tabs_really_are_mixed_and_the_uniform_ones_really_are_uniform(self):
        """The second grep, field by field. A tab whose clause fields are uniformly derived can
        take a constant cell honestly; a MIXED one cannot."""
        self.assertEqual(("is_missing", "dhcp_server_configured", "dhcp_relay_state"),
                         PanOsDhcpInterfaceConfig.DERIVED_FIELDS)
        self.assertNotIn("dhcp_server_mode", PanOsDhcpInterfaceConfig.DERIVED_FIELDS)
        self.assertNotIn("protocol", PanOsRoutingAdjacency.DERIVED_FIELDS)
        self.assertIn("authentication_strength", PanOsRoutingAdjacency.DERIVED_FIELDS)
        self.assertIn("prefix_limit_state", PanOsRoutingAdjacency.DERIVED_FIELDS)
        self.assertIn("tunnel_inspection_coverage_state",
                      PanOsTunnelInspectionCoverage.DERIVED_FIELDS)
        for field in ("session_rematch", "ipv6_firewalling"):
            self.assertNotIn(field, PanOsSessionSettings.DERIVED_FIELDS)

    def test_session_rematch_is_nullable_so_never_established_is_expressible(self):
        """THE WHOLE OF WHY `rematch_known` CAN BE FILLED HONESTLY. A non-nullable column with a
        default could not express "nobody ever wrote this", and the reader would then be inventing
        a distinction the data does not carry."""
        field = PanOsSessionSettings._meta.get_field("session_rematch")
        self.assertTrue(field.null)
        self.assertFalse(field.has_default())
        self.assertFalse(PanOsSessionSettings._meta.get_field("ipv6_firewalling").null,
                         "ipv6_firewalling became nullable: PAN-NET-005's undetermined state "
                         "would now be expressible and this domain's recorded gap would close")


class NetworkHardeningEstateMixin:
    """One standalone appliance and one HA PAIR, with a row of every subject model.

    THE PAIR IS BUILT BY HAND AND THAT IS THE POINT (P460). `tests/_estate.build_base_estate`
    always sets `EnforcementPoint.appliance` and gives every serial its own standalone group, so
    every row it builds reads `Standalone` and an HA measurement taken through it reports its own
    fixture. `flows.get_in_scope_appliances` (`flows.py:503-527`) takes
    `enforcement_point.appliance` when set and `continue`s without ever consulting the point's
    nodes, so ONE point with a NULL `appliance` and TWO `EnforcementNode`s is the only arm on
    which both members are in scope.
    """

    @classmethod
    def build_estate(cls):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="p.nhd")
        pair = ApplianceGroup.objects.create(
            management_station=station, name="ha-pair-nhd",
            group_type=ApplianceGroup.TYPE_HA_PAIR)
        active = Appliance.objects.create(
            management_station=station, appliance_group=pair,
            serial_number="013201001475", hostname="fw-core-tpa-a", model="PA-5220")
        passive = Appliance.objects.create(
            management_station=station, appliance_group=pair,
            serial_number="013201001476", hostname="fw-core-tpa-b", model="PA-5220")
        pair.active_appliance = active
        pair.save(update_fields=["active_appliance"])
        point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=pair, appliance=None,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True)
        for appliance in (active, passive):
            EnforcementNode.objects.create(
                management_station=station, enforcement_point=point, appliance=appliance)

        group = ApplianceGroup.objects.create(
            management_station=station, name="standalone-b458",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        standalone = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="691665AC334B458", hostname="pan-fw-b458", model="PA-VM")
        group.active_appliance = standalone
        group.save(update_fields=["active_appliance"])
        standalone_point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group, appliance=standalone,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True)
        EnforcementNode.objects.create(
            management_station=station, enforcement_point=standalone_point,
            appliance=standalone)
        # `source_snapshot` is NOT NULL on all five provenanced models, so no row can be built
        # without one.
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=active,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        return station, active, passive, standalone, snapshot

    @classmethod
    def build_rows(cls, station, active, passive, standalone, snapshot):
        """One row of each subject, in states that make every clause fire somewhere.

        The values are the measured lab shapes: an out-of-service port whose only residue is an
        unrestricted management binding (PAN-NET-001 at `high`), an LLDP profile announcing the
        management address (PAN-NET-003 at `high`), a session configuration with rematch written
        off, a DHCP server branch switched off, a vsys with no tunnel-inspect policy, and a BGP
        peer with a weak digest and no prefix ceiling.
        """
        rows = {}
        rows["interface"] = Interface.objects.create(
            management_station=station, appliance=active, source_snapshot=snapshot,
            name="ethernet1/20", container="", interface_type="layer3",
            management_profile_name="oep-nhd6-mp1", management_profile_restricts_sources=False,
            security_zone_name="", link_state=Interface.LINK_STATE_DOWN,
            out_of_service_residue=Interface.RESIDUE_UNRESTRICTED_MANAGEMENT,
            lldp_node_present=True, lldp_enabled=True, lldp_profile_name="oep-nhd6-lp1",
            lldp_announced_content=Interface.ANNOUNCED_MANAGEMENT_ADDRESS,
            aggregate_group="", comment="")
        # THE PAIR'S SECOND MEMBER, for the HA row count. A port synchronised between peers is
        # two rows for one real port and nothing deduplicates them.
        rows["interface_peer"] = Interface.objects.create(
            management_station=station, appliance=passive, source_snapshot=snapshot,
            name="ethernet1/20", container="", interface_type="layer3",
            management_profile_name="oep-nhd6-mp1", management_profile_restricts_sources=False,
            security_zone_name="", link_state=Interface.LINK_STATE_DOWN,
            out_of_service_residue=Interface.RESIDUE_UNRESTRICTED_MANAGEMENT,
            lldp_node_present=True, lldp_enabled=True, lldp_profile_name="oep-nhd6-lp1",
            lldp_announced_content=Interface.ANNOUNCED_MANAGEMENT_ADDRESS,
            aggregate_group="", comment="")
        # ESTABLISHED AND OFF: the key is present and reads false, so `rematch_known` is Yes and
        # the "never established" calibration must NOT match.
        rows["session"] = PanOsSessionSettings.objects.create(
            management_station=station, appliance=active, source_snapshot=snapshot,
            session_rematch=False, ipv6_firewalling=False, tcp_reject_non_syn=True)
        # NEVER ESTABLISHED: no key at all, which is the NULL. The other branch of the reader, and
        # the state the estate this run measured does not contain.
        rows["session_unestablished"] = PanOsSessionSettings.objects.create(
            management_station=station, appliance=standalone, source_snapshot=snapshot,
            session_rematch=None, ipv6_firewalling=True, tcp_reject_non_syn=True)
        rows["dhcp"] = PanOsDhcpInterfaceConfig.objects.create(
            management_station=station, appliance=active, source_snapshot=snapshot,
            interface_name="ethernet1/3", dhcp_server_configured=True,
            dhcp_server_mode=PanOsDhcpInterfaceConfig.MODE_DISABLED,
            dhcp_relay_ipv4_enabled=None,
            dhcp_relay_state=PanOsDhcpInterfaceConfig.RELAY_NOT_CONFIGURED)
        # THE SERVER BRANCH WITH NO `mode` KEY, which is the third provenance answer:
        # "Not configured" rather than Local or Derived.
        rows["dhcp_no_mode"] = PanOsDhcpInterfaceConfig.objects.create(
            management_station=station, appliance=standalone, source_snapshot=snapshot,
            interface_name="ethernet1/4", dhcp_server_configured=True,
            dhcp_server_mode=None, dhcp_relay_ipv4_enabled=None,
            dhcp_relay_state=PanOsDhcpInterfaceConfig.RELAY_NOT_CONFIGURED)
        rows["tunnel"] = PanOsTunnelInspectionCoverage.objects.create(
            management_station=station, appliance=active, source_snapshot=snapshot,
            scope=PanOsTunnelInspectionCoverage.SCOPE_VSYS, vsys_name="vsys2",
            tunnel_inspect_rule_count=0, tunnel_inspect_rules_collected=True,
            tunnel_acceleration=True,
            tunnel_inspection_coverage_state=PanOsTunnelInspectionCoverage.STATE_NO_POLICY)
        # THE P450 ROW: a BGP peer in one state of the AUTHENTICATION column and one state of the
        # PREFIX CEILING column at once, which matches two calibrations at different severities.
        rows["bgp"] = PanOsRoutingAdjacency.objects.create(
            management_station=station, appliance=active, source_snapshot=snapshot,
            router_name="oep-nhd6-vr1", protocol=PanOsRoutingAdjacency.PROTOCOL_BGP,
            adjacency_name="oep-nhd6-p1",
            routing_engine=PanOsRoutingAdjacency.ENGINE_LEGACY,
            bgp_authentication_profile="", ospf_authentication_profile="",
            authentication_profile="", max_prefixes=None,
            authentication_strength=PanOsRoutingAdjacency.STRENGTH_NONE,
            prefix_limit_state=PanOsRoutingAdjacency.LIMIT_NO_CEILING)
        return rows

    @classmethod
    def write_provenance(cls, rows):
        """A `FieldProvenance` row per field that HAS one, which is only the ones reading a
        payload key - `session_rematch`, `ipv6_firewalling`, `dhcp_server_mode` among this run's
        clause fields. Everything else is computed and declared in `DERIVED_FIELDS`, and NOTHING
        writes one for an `Interface` at all.

        P451's test is whether a TESTED field has a provenance row, not which write helper ran:
        `write_node_row` called WITH a provenance list still leaves the cell reading "Not
        recorded" when none of the fields in that list is one a control clauses on.
        """
        from django.contrib.contenttypes.models import ContentType

        def write(obj, field, provenance_type, raw_key, raw_value=""):
            FieldProvenance.objects.create(
                content_type=ContentType.objects.get_for_model(type(obj)), object_id=obj.pk,
                field_name=field, provenance_type=provenance_type, raw_key=raw_key,
                raw_value=raw_value)

        write(rows["session"], "session_rematch", FieldProvenance.ProvenanceType.LOCAL,
              "rematch", "no")
        write(rows["session"], "ipv6_firewalling", FieldProvenance.ProvenanceType.LOCAL,
              "ipv6-firewalling", "no")
        write(rows["session_unestablished"], "ipv6_firewalling",
              FieldProvenance.ProvenanceType.PAN_OS_DEFAULT, "ipv6-firewalling", "yes")
        write(rows["dhcp"], "dhcp_server_mode", FieldProvenance.ProvenanceType.LOCAL,
              "server/mode", "disabled")
        # NO ROW for `dhcp_no_mode`'s mode: the key was absent, and the normaliser skips a field
        # whose raw key is ABSENT. That is what makes the cell read "Not configured" rather than
        # "Local", and it is the third answer the branching cell has to be able to print.
        write(rows["dhcp_no_mode"], "dhcp_server_mode",
              FieldProvenance.ProvenanceType.NOT_CONFIGURED, "server/mode")


class NetworkHardeningTabTests(NetworkHardeningEstateMixin, TestCase):
    """The built tables. Every row loop here asserts the table is not empty first."""

    @classmethod
    def setUpTestData(cls):
        seed_controls(PAN_NET)

    def setUp(self):
        self.station, self.active, self.passive, self.standalone, self.snapshot = \
            self.build_estate()
        self.rows = self.build_rows(
            self.station, self.active, self.passive, self.standalone, self.snapshot)
        self.write_provenance(self.rows)

    def table(self, slug):
        """THE FINDING RUN IS THE TEST. Called here rather than in `setUp` so the rest of the
        suite does not pay a finding run on every gate run - with five tabs that is not a small
        cost."""
        from assessments.finding_run import regenerate_findings
        regenerate_findings()
        table = build_findings_table(DOMAIN_BY_SLUG[slug].spec, tested=ALL_TESTED_COLUMNS)
        self.assertTrue(table.rows, f"{slug}: ZERO ROWS - nothing asserted below is a measurement")
        return table

    def cell(self, table, row_index, heading):
        return table.rows[row_index][table.headers.index(heading)]

    # ------------------------------------------------------------------ column order

    def test_the_settings_column_order_on_every_tab(self):
        """READ OFF THE BUILT TABLE AND NOT DERIVED. Nothing gates it and `auto_setting_columns`
        is all-or-nothing, so no sheet option corrects it: the settings run baseline-clauses in
        clause order per control, controls by `control_id`, and within a control the non-baseline
        queries ALPHABETICALLY BY QUERY NAME."""
        expected = {
            "firewall-interfaces": ["Residue on an out-of-service port", "LLDP enabled",
                                    "LLDP announced content"],
            "session-settings": ["Rematch Sessions", "Rematch setting established",
                                 "IPv6 Firewalling"],
            "dhcp-interfaces": ["DHCP server branch present", "DHCP relay state",
                                "DHCP server mode"],
            "tunnel-inspection": ["Tunnel inspection coverage"],
            "virtual-routers": ["Adjacency authentication", "Protocol",
                                "Prefix ceiling enforced"]}
        for slug, settings in expected.items():
            with self.subTest(slug=slug):
                headers = self.table(slug).headers
                start = headers.index("Template") + 1
                self.assertEqual(settings, headers[start:headers.index("Matched queries")])

    def test_the_two_dhcp_server_columns_are_split_apart_by_the_relay_column(self):
        """THE ONE ORDER ON THIS DOMAIN THAT A QUERY RENAME WOULD SILENTLY CHANGE. "A DHCP relay
        is relaying on this interface" sorts before "Server configured and switched off" on
        `A` < `S`, so a customer reads server-configured, then relay-state, then server-mode -
        and the two columns about the SERVER are not adjacent."""
        headers = self.table("dhcp-interfaces").headers
        self.assertLess(headers.index("DHCP server branch present"),
                        headers.index("DHCP relay state"))
        self.assertLess(headers.index("DHCP relay state"), headers.index("DHCP server mode"))

    # ------------------------------------------------------------------ labels

    def test_every_graded_choices_column_prints_an_english_label_and_not_a_stored_key(self):
        """`display_value` NEVER calls `get_<field>_display()` - the cell goes `read_value` ->
        `getattr` -> `display_value`, whose value branch ends in `str(value)` - so without a
        reader a `choices` field prints its STORED KEY under a vendor heading. These are the
        labels, asserted so the claim cannot drift back."""
        checks = (
            ("firewall-interfaces", "Residue on an out-of-service port",
             "Management binding, no source restriction"),
            ("firewall-interfaces", "LLDP announced content", "Management address"),
            ("dhcp-interfaces", "DHCP relay state", "Not configured"),
            ("dhcp-interfaces", "DHCP server mode", "Disabled"),
            ("tunnel-inspection", "Tunnel inspection coverage",
             "No tunnel inspection policy"),
            ("virtual-routers", "Adjacency authentication", "None"),
            ("virtual-routers", "Protocol", "BGP"),
            ("virtual-routers", "Prefix ceiling enforced", "No ceiling"))
        for slug, heading, label in checks:
            with self.subTest(slug=slug, heading=heading):
                table = self.table(slug)
                values = {str(row[table.headers.index(heading)]) for row in table.rows}
                self.assertIn(label, values)
                for value in values:
                    self.assertNotRegex(
                        value, r"^[a-z0-9]+(_[a-z0-9]+)+$",
                        f"{slug}/{heading}: a stored key reached a customer-facing cell")

    def test_no_heading_on_any_of_the_five_tabs_is_a_raw_django_field_name(self):
        """A heading with no `setting_labels` entry falls back to the raw field name, so declaring
        a column without a label IS choosing to show a customer a database field name. NOTE that
        labeling every heading does not make a tab clean - the STATED CONDITION above it still
        reads in field names, because `render_node` consults `setting_labels` nowhere."""
        for slug, *_rest in TABS:
            with self.subTest(slug=slug):
                raw = [h for h in self.table(slug).headers
                       if h == h.lower() and "_" in h and " " not in h]
                self.assertEqual([], raw)

    # ------------------------------------------------------------------ the mark

    def test_every_row_of_every_tab_marks_at_least_one_real_cell(self):
        """`hidden_fields=()` on all five, so the mark falls on a real column rather than being
        claimed by a declaration. `check_every_tested_field_is_presented` accepts a non-empty
        `hidden_fields` as PROOF a field is presented, and it is the only known cause in the
        repository of a findings row that marks nothing as the thing to fix."""
        for slug, *_rest in TABS:
            with self.subTest(slug=slug):
                table = self.table(slug)
                marked = {row for row, _column in table.implicated}
                self.assertEqual(set(range(len(table.rows))), marked,
                                 f"{slug}: a row marks no cell at all")

    def test_the_scope_clause_column_is_drawn_and_is_not_marked(self):
        """`protocol` has `role: "scope"` in stage 5 and is a clause of the shipped BGP query, so
        `tested_fields` derives a column for it among the verdict columns - a column that merely
        SCOPES the control sitting where a reader expects a verdict. It is NOT in that query's
        `asserted_fields`, so the 2026-10-28 mark fix should leave it alone; this is the first
        confirmation of that behavior on a scope clause."""
        table = self.table("virtual-routers")
        protocol = table.headers.index("Protocol")
        self.assertNotIn(protocol, [column for _row, column in table.implicated])
        self.assertIn(table.headers.index("Adjacency authentication"),
                      [column for _row, column in table.implicated])

    # ------------------------------------------------------------------ provenance

    def test_the_interfaces_tab_provenance_says_nothing_tracks_the_field(self):
        """TRUE, and not the P451 defect. `integrations.Interface` carries no `FieldProvenance`
        rows at all - per field or `__entry__` - so "Not recorded" is the vocabulary's own words
        for the real state, where on the other tabs the same words were false about a column
        declared derived. The branching cell is on this sheet only to collapse the repeat on a
        two-clause-field row."""
        table = self.table("firewall-interfaces")
        for index in range(len(table.rows)):
            self.assertEqual("Not recorded", self.cell(table, index, "Provenance"))

    def test_the_dhcp_provenance_cell_branches_and_prints_three_different_answers(self):
        """A CONSTANT WOULD STATE A FALSEHOOD and the DEFAULT loses the measured key. The recorded
        answers are: `dhcp_server_configured` DERIVED, `dhcp_relay_state` DERIVED, and
        `dhcp_server_mode` either Local or - where the key was absent - "Not configured". The
        third answer is the one a two-way derived-or-Local branch would have printed over."""
        table = self.table("dhcp-interfaces")
        by_interface = {self.cell(table, i, "Interface"): self.cell(table, i, "Provenance")
                        for i in range(len(table.rows))}
        self.assertEqual("Derived\nLocal", by_interface["ethernet1/3"])
        self.assertEqual("Derived\nNot configured", by_interface["ethernet1/4"])

    def test_the_routing_provenance_cell_does_not_call_the_scope_clause_derived(self):
        """`protocol` is NEITHER declared derived NOR a payload key - it is part of the row's
        identity - so the DEFAULT cell, which prints the readers' own "Derived" prose for all
        three fields, states that it is computed. It is not. The branching cell prints what was
        recorded, which for that field is nothing."""
        table = self.table("virtual-routers")
        self.assertEqual("Derived\nNot recorded", self.cell(table, 0, "Provenance"))

    def test_the_session_tab_keeps_the_default_because_branching_loses_the_reader(self):
        """THE LIMIT OF THE `ha-panorama` REMEDY, and the reason the standing rule "MIXED -> the
        cell must branch" would have sent this tab the wrong way.

        `rematch_known` is not a model field, so `provenance_of` finds no stored row and no
        `DERIVED_FIELDS` entry and answers nothing - a branching cell prints "Not recorded" for
        it. The READER arm prints the reader's own "Derived", which is true: the value is read off
        the nullness of the key in the cell beside it. A `provenance_cell` cannot see a reader, so
        on a tab whose clause fields include a reader-only field the DEFAULT is the more honest of
        the two."""
        from dataclasses import replace
        spec = DOMAIN_BY_SLUG["session-settings"].spec
        self.assertIsNone(spec.provenance_cell, "the session tab took a sheet-level cell")
        table = self.table("session-settings")
        default = self.cell(table, 0, "Provenance")
        self.assertEqual("Local\nDerived", default)

        branched = build_findings_table(
            replace(spec, provenance_cell=presentation.provenance_cell),
            tested=ALL_TESTED_COLUMNS)
        self.assertTrue(branched.rows)
        self.assertEqual("Local\nNot recorded",
                         branched.rows[0][branched.headers.index("Provenance")])

    def test_a_readers_provenance_string_is_what_the_cell_prints(self):
        """Set it deliberately: a reader whose prose equals the DERIVED label triggers the
        `remediation_accessor` walk and anything else is printed verbatim. Both of this domain's
        spellings are asserted, because the outcome looked right on the two readers that existed
        before only because both happened to say "Derived"."""
        self.assertEqual(
            FieldProvenance.ProvenanceType.DERIVED.label, presentation.REMATCH_KNOWN.provenance)
        self.assertEqual("Not recorded", presentation.OUT_OF_SERVICE_RESIDUE.provenance)
        # And the vocabulary member the branching cell falls back on is the same word, so the two
        # routes cannot disagree about what an untracked field is called.
        self.assertEqual(("Not recorded", ""), provenance_cells(None, stored=True))

    # ------------------------------------------------------------------ rematch_known

    def test_the_session_tab_cannot_be_built_without_the_rematch_known_reader(self):
        """`tested_fields` RAISES `ValueError` on a tested field the model neither stores nor
        computes, so the reader is not a choice with a price - it is the only state in which this
        tab exists. Asserted by taking it away."""
        from dataclasses import replace
        spec = DOMAIN_BY_SLUG["session-settings"].spec
        self.assertIn("rematch_known", spec.value_readers)
        control = Control.objects.get(control_id="PAN-NET-002")
        with self.assertRaises(ValueError) as caught:
            tested_fields(PanOsSessionSettings, control, replace(spec, value_readers={}).
                          value_readers)
        self.assertIn("rematch_known", str(caught.exception))
        self.assertIn("neither stores nor computes", str(caught.exception))

    def test_rematch_known_reads_both_branches_and_the_calibration_agrees_with_it(self):
        """BOTH BRANCHES, because the estate this run measured exercises only the established one.
        The reader is the shipped compiler's `session_rematch__isnull` inverted, so the cell and
        the clause cannot disagree: the appliance whose key is absent reads No and is the one the
        "Setting never established" calibration matches."""
        table = self.table("session-settings")
        by_appliance = {
            self.cell(table, i, "Appliance"): (
                self.cell(table, i, "Rematch Sessions"),
                self.cell(table, i, "Rematch setting established"),
                self.cell(table, i, "Matched queries"))
            for i in range(len(table.rows))
            if self.cell(table, i, "Control ID") == "PAN-NET-002"}
        self.assertEqual(("No", "Yes"), by_appliance["fw-core-tpa-a"][:2])
        self.assertNotIn("Setting never established", by_appliance["fw-core-tpa-a"][2])
        self.assertEqual(("(none)", "No"), by_appliance["pan-fw-b458"][:2])
        self.assertIn("Setting never established", by_appliance["pan-fw-b458"][2])

    def test_the_unestablished_row_shows_none_in_the_setting_cell_and_that_is_recorded(self):
        """THE CELL THIS STAGE REFUSED TO IMPROVE, stated as a test so the refusal is visible.
        `session_rematch`'s NULL renders `(none)` because a reader on it would make
        `remediation_accessor` skip the field's own `FieldProvenance` row - the only thing
        separating an ABSENT key from one explicitly written - and that row matters most on the
        control whose second query is ABOUT the absence. The companion column carries the meaning
        instead."""
        spec = DOMAIN_BY_SLUG["session-settings"].spec
        self.assertNotIn("session_rematch", spec.value_readers)
        table = self.table("session-settings")
        unestablished = [i for i in range(len(table.rows))
                         if self.cell(table, i, "Appliance") == "pan-fw-b458"
                         and self.cell(table, i, "Control ID") == "PAN-NET-002"]
        self.assertTrue(unestablished)
        self.assertEqual("(none)", self.cell(table, unestablished[0], "Rematch Sessions"))

    # ------------------------------------------------------------------ P450

    def test_the_lower_calibration_is_printed_as_the_basis_of_the_higher_grade(self):
        """P450's DAMAGING VARIANT, REACHABLE ON A REAL SUBJECT - which no earlier domain managed.
        `findings.py:510-524` collects every matched non-baseline query carrying an adjusted
        severity, grades on the MAXIMUM, and prints them ALL under "Adjusted to <max> by:". A BGP
        peer with no authentication AND no prefix ceiling is in one state of each of two
        INDEPENDENT columns, so it matches the `high` authentication calibration and the `medium`
        prefix-ceiling one at once - and the medium query is then printed as a basis of the high
        grade.

        PINNED AS THE DEFECT IT IS. The grade is right; the basis is misleading. `severity_basis`
        is shared machinery and not this stage's to change, so this test is what a later fix
        turns."""
        table = self.table("virtual-routers")
        basis = str(self.cell(table, 0, "Severity basis"))
        self.assertEqual("High", str(self.cell(table, 0, "Severity")))
        self.assertIn("Authentication absent, disabled, cleartext or overridden", basis)
        self.assertIn("BGP peer with no enforced prefix ceiling", basis,
                      "the medium calibration is no longer printed under the high grade - if "
                      "severity_basis was fixed, this test is the one to retire")

    # ------------------------------------------------------------------ the HA pair

    def test_an_ha_pair_draws_two_rows_for_one_port_and_they_agree(self):
        """TWO ROWS FOR ONE REAL PORT, which is correct and not a duplicate: `Interface` is
        `unique(appliance, name)` and has no appliance-group bridge, so "this peer holds no
        interfaces" would be indistinguishable from "this peer was never normalized". The two
        rows AGREE here - an interface is synchronised between peers - so collapsing them would
        remove a duplicate rather than discard a reading, and that is the opposite of
        `ha-panorama`'s HA tab. It is still not collapsed, because both members must be collected.
        """
        table = self.table("firewall-interfaces")
        rows = [i for i in range(len(table.rows))
                if self.cell(table, i, "Interface") == "ethernet1/20"
                and self.cell(table, i, "Control ID") == "PAN-NET-001"]
        self.assertEqual(2, len(rows), "the pair did not draw two rows")
        appliances = {self.cell(table, i, "Appliance") for i in rows}
        self.assertEqual({"fw-core-tpa-a", "fw-core-tpa-b"}, appliances)
        self.assertEqual({"Active", "Passive"},
                         {str(self.cell(table, i, "HA role")) for i in rows})
        residues = {str(self.cell(table, i, "Residue on an out-of-service port")) for i in rows}
        self.assertEqual(1, len(residues), "the two peers' rows disagree about the port")

    def test_the_vsys_scoped_subject_names_its_vsys(self):
        """The one vsys-scoped subject in the domain. A verdict over a rulebase needs the vsys on
        the row, because the same appliance holds several and the remediation is per vsys."""
        table = self.table("tunnel-inspection")
        self.assertEqual("vsys2", self.cell(table, 0, "Virtual system"))
        self.assertEqual("Vsys", str(self.cell(table, 0, "Scope")))


class NetworkHardeningResultsPageTests(NetworkHardeningEstateMixin, TestCase):
    """The explorer `ResultsSpec.row` lambdas over real rows, which the shipped squareness check
    cannot do: it checks the WIDTH of a row and not what any cell says."""

    def setUp(self):
        self.station, self.active, self.passive, self.standalone, self.snapshot = \
            self.build_estate()
        self.rows = self.build_rows(
            self.station, self.active, self.passive, self.standalone, self.snapshot)

    def page(self, slug):
        spec = cr.RESULTS[slug]
        built = [spec.row(obj) for obj in spec.base_queryset()]
        self.assertTrue(built, f"{slug}: no rows, so nothing below is a measurement")
        for row in built:
            self.assertEqual(len(spec.columns), len(row))
        return spec, built

    def test_every_page_builds_a_square_row_over_real_objects(self):
        for slug in ("firewall-interfaces", "session-settings", "dhcp-interfaces",
                     "tunnel-inspection", "virtual-routers"):
            with self.subTest(slug=slug):
                self.page(slug)

    def test_the_lldp_global_switch_is_reachable_from_no_surface_at_all(self):
        """THIS DOMAIN'S RECORDED GAP, pinned so that a later run adding the catalog query can
        see everything that has to change with it.

        Stage 5 assessed `lldp_global_enable` as PAN-NET-003's SECOND assertion record and stage 8
        compiled a query for it; the shipped catalog does not carry that query. So the model has
        no findings domain - and a rail item is a promise of a findings page, which
        `views.findings_href_for` resolves through `domain_for_model` and both object templates
        require. A rail item was written for it and removed the same day, because it failed
        `test_every_rail_item_offers_the_link` and
        `test_every_object_crosses_to_the_page_that_reports_on_it`.

        WHEN THE CATALOG QUERY LANDS, this test should fail - and the things to add are a
        `FindingsDomain` over `T.LLDP_GLOBAL` (its finding kind is already registered), a rail
        item at `Network > LLDP`, and a `ResultsSpec` under its slug."""
        from assessments.artifacts import domains as artifact_domains

        label = f"integrations.{LLDP_GLOBAL_MODEL.__name__}"
        self.assertEqual([], [o for o in CONFIG_OBJECTS if o.search_model == label])
        self.assertIsNone(artifact_domains.domain_for_model(label))
        self.assertNotIn("lldp-global", cr.RESULTS)
        # The finding kind IS registered, which is what makes the gap a catalogue gap rather than
        # a modelling one - `test_finding_registry` requires every concrete FindingBase subclass
        # to be registered and this one is, with no control over it.
        from assessments import finding_registry
        kinds = [k for k in finding_registry.FINDING_KINDS
                 if k.control_type == "lldp_global"]
        self.assertEqual(1, len(kinds))
        self.assertEqual(
            0, Control.objects.filter(control_type="lldp_global").count(),
            "a control now targets the global LLDP switch: this domain's gap may be closed")

    def test_a_nullable_three_state_cell_never_reads_as_the_reassuring_answer(self):
        """NULL IS THE FIRING SIDE on every nullable column this domain presents, so printing it
        "no" would put the reassuring answer in the cell the control fired on. `_tri` exists for
        exactly this."""
        spec, built = self.page("session-settings")
        by_appliance = {row[0]: row for row in built}
        self.assertEqual(
            "not read",
            by_appliance["pan-fw-b458"][spec.columns.index("Rematch Sessions")])
        self.assertEqual(
            "no", by_appliance["pan-fw-b458"][spec.columns.index("Rematch setting established")])

    def test_an_absent_key_inside_a_branch_that_exists_is_named_and_not_blanked(self):
        """A server branch with no `mode` key is a real reading and a blank cell would read as
        missing data - the same argument the trust-certificate page's "Nothing designated" makes.
        It is NOT `layout.NONE`: the em dash is for a branch that does not exist on this subject,
        and here the branch does exist."""
        spec, built = self.page("dhcp-interfaces")
        by_interface = {row[spec.columns.index("Interface")]: row for row in built}
        self.assertEqual("No mode key",
                         by_interface["ethernet1/4"][spec.columns.index("Server mode")])
        self.assertEqual("Disabled",
                         by_interface["ethernet1/3"][spec.columns.index("Server mode")])

    def test_a_zero_rule_count_says_what_zero_means(self):
        """"Nothing" rather than 0, because a bare zero in a reference column reads as "not
        counted" exactly where it means "counted, and the answer was none" - and NO RULE EXISTING
        is the commonest failing state of this subject."""
        spec, built = self.page("tunnel-inspection")
        self.assertEqual("Nothing", built[0][spec.columns.index("Rules")])
        self.assertEqual("yes", built[0][spec.columns.index("Rulebase collected")])
