"""The network-hardening controls. PAN-NET-001 to 007, six subjects, five of them new.

WHAT THIS MODULE IS FOR. Most of it is the ordinary thing - seed the shipped control, build a
row, assert the finding and its severity. Four of its tests are not ordinary and are the reason
it is worth reading: each one pins a fact about the SEARCH LAYER that this domain's queries rest
on, that is not written down anywhere else, and that reads the opposite way if you reason about
it instead of measuring it.

1. `test_a_negated_clause_reaches_a_null_row`. Both consumer-repo notes and
   `models/network_hardening.py`'s own comments say a nullable column passes any clause written
   over it, because SQL answers every positive comparison over a NULL with no match. That is
   true of plain SQL and FALSE of these compilers: `compile_search_clause` negates at the pk-SET
   level, so a row absent from the positive subquery is present in the complement. PAN-NET-002's
   baseline therefore already reports the appliance whose rematch key nobody has set, and the
   second query stage 5 declared for exactly that population is a subset of it rather than the
   only thing reaching it.
2. `test_is_empty_reaches_a_null_on_a_nullable_boolean`. `is_empty` is the only operator of the
   twelve that is about absence and every shipped compiler makes it a TEXT operator compiling to
   `filter(field="")`. On a nullable boolean the empty string is not a value the column can
   hold, so this domain's compilers give the operator the IS NULL meaning there - which is what
   makes PAN-NET-002's declared second query expressible at all.
3. `test_is_empty_is_refused_on_a_non_nullable_boolean`. The same operator on
   `ipv6_firewalling` would raise `ValidationError` from `get_prep_value`, which is NOT a
   `SearchSyntaxError` and so is NOT caught by `evaluate_queryset_control_queries` - it would
   abort a whole findings run rather than skip one query. PAN-NET-005's declared second query is
   that query, and this test is what stops it being added back.
4. `test_an_unauthenticated_bgp_peer_with_no_ceiling_reports_high`.
   `derive_control_query_severity_value` DISCARDS the baseline tier the moment any non-baseline
   query with an adjusted severity matches, and takes the worst of those. PAN-NET-007 asserts
   two things at two severities over one model, so without an explicit high-tier calibration
   query a peer that is BOTH unauthenticated and unbounded would report at the prefix query's
   medium - below the severity its own authentication grading gives it.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.finding_run import regenerate_findings
from assessments.models import (
    Control, DhcpInterfaceConfigFinding, InterfaceFinding, RoutingAdjacencyFinding,
    SessionSettingsFinding, TunnelInspectionFinding,
)
from assessments.search.exceptions import SearchSyntaxError
from assessments.search.session_settings.compiler import (
    compile_session_settings_search_node,
)
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, Interface, ManagementStation, PanOsDhcpInterfaceConfig,
    PanOsLldpGlobalSettings, PanOsRoutingAdjacency, PanOsSessionSettings,
    PanOsTunnelInspectionCoverage, Snapshot,
)

SESSION_MODEL = "integrations.PanOsSessionSettings"


class NetworkHardeningBase(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.nhd")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-nhd",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = self._appliance("fw-nhd-a", "NHD0000001")
        self.other = self._appliance("fw-nhd-b", "NHD0000002")

    def _appliance(self, hostname, serial):
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=serial, hostname=hostname)
        appliance.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        return appliance

    def _anchors(self, appliance=None):
        appliance = appliance or self.appliance
        return {"management_station": self.station, "appliance": appliance,
                "appliance_group": self.group, "source_snapshot": appliance.snapshot}

    def _findings(self, model, control_id):
        return {(f.subject_name, f.severity): f
                for f in model.objects.filter(control__control_id=control_id)}


# ---------------------------------------------------------------------------
# The search-layer facts this domain's queries rest on
# ---------------------------------------------------------------------------

class SearchLayerFactsTests(NetworkHardeningBase):
    def _row(self, appliance, **fields):
        return PanOsSessionSettings.objects.create(**self._anchors(appliance), **fields)

    def _matches(self, node):
        predicate = compile_session_settings_search_node(node)
        return set(PanOsSessionSettings.objects.filter(predicate)
                   .values_list("appliance__serial_number", flat=True))

    def test_a_negated_clause_reaches_a_null_row(self):
        """`is not true` matches a row holding NULL, because the negation is over the pk SET.

        This is the fact the consumer-repo note and the integrations model comment both get
        backwards. If it ever stops being true, PAN-NET-002 silently stops reporting every
        appliance whose rematch key has never been set - which, in the estate this was measured
        on, is the population the control exists for.
        """
        self._row(self.appliance, session_rematch=None)
        self._row(self.other, session_rematch=True)
        self.assertEqual(
            self._matches({"model": SESSION_MODEL, "field": "session_rematch",
                           "op": "eq", "value": True, "negated": True}),
            {"NHD0000001"},
            "a negated clause must reach the NULL row; if it does not, PAN-NET-002's baseline "
            "reports an unmeasured appliance as compliant")

    def test_the_known_field_reaches_the_null_and_only_the_null(self):
        """`rematch_known` is a VIRTUAL field over `session_rematch__isnull`, inverted - the
        shipped convention that `address_object`'s `size_known` took first. It is how stage 5's
        declared `session_rematch is_empty` is expressed, because `is_empty` does not exist for
        a boolean field in any of the fourteen shipped compilers.
        """
        self._row(self.appliance, session_rematch=None)
        self._row(self.other, session_rematch=False)
        self.assertEqual(
            self._matches({"model": SESSION_MODEL, "field": "rematch_known",
                           "op": "eq", "value": False, "negated": False}),
            {"NHD0000001"},
            "rematch_known false must select exactly the rows whose session_rematch is NULL")
        self.assertEqual(
            self._matches({"model": SESSION_MODEL, "field": "rematch_known",
                           "op": "eq", "value": True, "negated": False}),
            {"NHD0000002"})

    def test_is_empty_does_not_exist_for_a_boolean_field(self):
        """Refused as a SearchSyntaxError, which is what the evaluator catches.

        Both booleans on this model refuse it, the nullable one included: this domain does NOT
        give `is_empty` a boolean meaning, because no shipped compiler does and the operator's
        whole definition is the empty string. On the NON-nullable column it matters more than
        tidiness - `BooleanField(null=False).get_prep_value("")` raises `ValidationError`, which
        is not a `SearchSyntaxError`, so `evaluate_queryset_control_queries` would not catch it
        and the whole findings run would abort rather than one query being skipped. That is why
        PAN-NET-005's declared second query could not be shipped.
        """
        self._row(self.appliance, ipv6_firewalling=True, session_rematch=None)
        for field in ("ipv6_firewalling", "session_rematch"):
            with self.subTest(field=field):
                with self.assertRaises(SearchSyntaxError):
                    self._matches({"model": SESSION_MODEL, "field": field,
                                   "op": "is_empty", "value": "", "negated": False})

    def test_there_is_no_known_field_for_the_non_nullable_boolean(self):
        """A virtual `*_known` field needs a null to detect, and `ipv6_firewalling` has none.
        So the gap PAN-NET-005 reports is not closeable from this stage: it needs a companion
        column or a changed default, and both are the normaliser's."""
        from assessments.search.session_settings.compiler import FIELD_OPERATOR_REGISTRY
        self.assertIn("rematch_known", FIELD_OPERATOR_REGISTRY)
        self.assertNotIn("ipv6_firewalling_known", FIELD_OPERATOR_REGISTRY)
        self.assertFalse(
            PanOsSessionSettings._meta.get_field("ipv6_firewalling").null,
            "if this column becomes nullable, PAN-NET-005 owes a `*_known` field and a second "
            "query - stage 5 already specifies both")

    def test_no_shipped_query_in_this_domain_names_an_unregistered_field(self):
        """Every clause of every PAN-NET query compiles. A query that does not compile is
        SKIPPED at evaluation time, silently, and the control reports a narrower population
        than its description claims."""
        from assessments.search.compiler import compile_predicate
        from assessments.search.registry import get_model_entry
        for control in seed_controls([f"PAN-NET-00{n}" for n in range(1, 8)]):
            for query in control.queries.all():
                canonical = query.canonical_query
                model_class = get_model_entry(canonical["model"])["model_class"]
                with self.subTest(control=control.control_id, query=query.name):
                    compile_predicate(model_class, canonical)


# ---------------------------------------------------------------------------
# PAN-NET-001 and PAN-NET-003 - the interface
# ---------------------------------------------------------------------------

class InterfaceControlTests(NetworkHardeningBase):
    def _interface(self, name, **fields):
        fields.setdefault("container", "ethernet")
        fields.setdefault("interface_type", Interface.TYPE_LAYER3)
        return Interface.objects.create(**self._anchors(), name=name, **fields)

    def test_the_residue_ranks_report_at_their_graded_severities(self):
        seed_controls(["PAN-NET-001"])
        self._interface("ethernet1/1", management_profile_name="p",
                        management_profile_restricts_sources=False,
                        out_of_service_residue=Interface.RESIDUE_UNRESTRICTED_MANAGEMENT)
        self._interface("ethernet1/2", management_profile_name="p",
                        management_profile_restricts_sources=True,
                        out_of_service_residue=Interface.RESIDUE_RESTRICTED_MANAGEMENT)
        self._interface("ethernet1/3", security_zone_name="z",
                        out_of_service_residue=Interface.RESIDUE_ZONE_MEMBERSHIP)
        self._interface("ethernet1/4", addressing=Interface.ADDRESSING_STATIC,
                        out_of_service_residue=Interface.RESIDUE_ADDRESS_ONLY)
        self._interface("ethernet1/5",
                        out_of_service_residue=Interface.RESIDUE_ADMIN_STATE_UNKNOWN)
        regenerate_findings()
        self.assertEqual(
            {name: sev for (name, sev) in self._findings(InterfaceFinding, "PAN-NET-001")},
            {"ethernet1/1": "high", "ethernet1/2": "medium", "ethernet1/3": "medium",
             "ethernet1/4": "low", "ethernet1/5": "medium"})

    def test_a_restricted_management_binding_reports_medium(self):
        """The census row for the lab's `ethernet1/21` grades `unrestricted` only because the
        profile it binds is another run's object and its permitted-source list is not in stage
        6's artifact. On a row whose column says the sources ARE restricted, the query reports
        the medium stage 6 expects - which is what separates an instrument gap from a defect.
        """
        seed_controls(["PAN-NET-001"])
        self._interface("ethernet1/21", management_profile_name="oep-p2-imp",
                        management_profile_restricts_sources=True,
                        out_of_service_residue=Interface.RESIDUE_RESTRICTED_MANAGEMENT)
        regenerate_findings()
        self.assertEqual(
            [sev for (_name, sev) in self._findings(InterfaceFinding, "PAN-NET-001")],
            ["medium"])

    def test_the_two_unranked_residues_and_the_acceptable_state_report_nothing(self):
        """Stage 5 places `comment_or_link_settings_only` and `routing_instance_without_address`
        as unranked, which it glosses as producing silence, and stage 6 expects no finding on
        both. Its own baseline clause - `is not stripped_and_shut_down` - fires on them, so the
        baseline carries the two exclusions explicitly."""
        seed_controls(["PAN-NET-001"])
        self._interface("ethernet1/6",
                        out_of_service_residue=Interface.RESIDUE_COMMENT_OR_LINK_SETTINGS)
        self._interface("ethernet1/7",
                        out_of_service_residue=Interface.RESIDUE_ROUTING_INSTANCE)
        self._interface("ethernet1/8",
                        out_of_service_residue=Interface.RESIDUE_STRIPPED_AND_SHUT_DOWN)
        regenerate_findings()
        self.assertEqual(InterfaceFinding.objects.count(), 0)

    def test_the_announced_content_ranks_report_at_their_graded_severities(self):
        seed_controls(["PAN-NET-003"])
        for name, content in (
                ("ethernet1/1", Interface.ANNOUNCED_MANAGEMENT_ADDRESS),
                ("ethernet1/2", Interface.ANNOUNCED_SYSTEM_DESCRIPTION),
                ("ethernet1/3", Interface.ANNOUNCED_HOSTNAME_OR_ROLE),
                ("ethernet1/4", Interface.ANNOUNCED_PORT_AND_CHASSIS_ONLY),
                ("ethernet1/5", Interface.ANNOUNCED_UNKNOWN_GLOBAL_DEFAULTS)):
            self._interface(name, lldp_node_present=True, lldp_enabled=True,
                            lldp_announced_content=content)
        regenerate_findings()
        self.assertEqual(
            {name: sev for (name, sev) in self._findings(InterfaceFinding, "PAN-NET-003")},
            {"ethernet1/1": "high", "ethernet1/2": "medium", "ethernet1/3": "low",
             "ethernet1/4": "low", "ethernet1/5": "low"})

    def test_a_transmitting_port_whose_profile_is_receive_only_reports_nothing(self):
        """`lldp_enabled` is the interface's own switch and the PROFILE decides what goes out.
        A port with the switch on and a receive-only profile puts nothing on the wire, which is
        stage 5's acceptable state and stage 6's expectation - and stage 5's one-clause baseline
        fires on it, so the baseline carries the exclusion."""
        seed_controls(["PAN-NET-003"])
        self._interface("ethernet1/14", lldp_node_present=True, lldp_enabled=True,
                        lldp_profile_name="receive-only-profile",
                        lldp_announced_content=Interface.ANNOUNCED_RECEIVE_ONLY_OR_OFF)
        self._interface("ethernet1/15", lldp_node_present=True, lldp_enabled=False,
                        lldp_announced_content=Interface.ANNOUNCED_RECEIVE_ONLY_OR_OFF)
        regenerate_findings()
        self.assertEqual(InterfaceFinding.objects.count(), 0)

    def test_the_two_interface_controls_do_not_calibrate_each_other(self):
        """Two controls share this model. `evaluate_queryset_control_queries` takes its union
        over ONE control's queries, so a port that violates both gets two findings at two
        severities rather than one at the worse - which is right, because they assert unrelated
        things and send a reader to different screens."""
        seed_controls(["PAN-NET-001", "PAN-NET-003"])
        self._interface("ethernet1/9", addressing=Interface.ADDRESSING_STATIC,
                        out_of_service_residue=Interface.RESIDUE_ADDRESS_ONLY,
                        lldp_node_present=True, lldp_enabled=True,
                        lldp_announced_content=Interface.ANNOUNCED_MANAGEMENT_ADDRESS)
        regenerate_findings()
        self.assertEqual(
            sorted((f.control.control_id, f.severity) for f in InterfaceFinding.objects.all()),
            [("PAN-NET-001", "low"), ("PAN-NET-003", "high")])


# ---------------------------------------------------------------------------
# PAN-NET-002 and PAN-NET-005 - the session settings
# ---------------------------------------------------------------------------

class SessionSettingsControlTests(NetworkHardeningBase):
    def test_rematch_off_and_rematch_unmeasured_both_report_high(self):
        seed_controls(["PAN-NET-002"])
        PanOsSessionSettings.objects.create(**self._anchors(), session_rematch=False)
        PanOsSessionSettings.objects.create(
            **self._anchors(self.other), session_rematch=None)
        regenerate_findings()
        found = {f.subject_name: (f.severity, tuple(f.matched_query_names))
                 for f in SessionSettingsFinding.objects.all()}
        self.assertEqual(found["fw-nhd-a"][0], "high")
        self.assertEqual(found["fw-nhd-b"][0], "high")
        # And the unmeasured appliance says SO on the row, which is the whole value of the
        # second query: the baseline alone would report both identically.
        self.assertIn("Setting never established", found["fw-nhd-b"][1])
        self.assertNotIn("Setting never established", found["fw-nhd-a"][1])

    def test_rematch_on_reports_nothing(self):
        seed_controls(["PAN-NET-002"])
        PanOsSessionSettings.objects.create(**self._anchors(), session_rematch=True)
        regenerate_findings()
        self.assertEqual(SessionSettingsFinding.objects.count(), 0)

    def test_ipv6_firewalling_fires_only_where_the_key_is_stored_off(self):
        """An absent key means the capability is ON, measured on the device's own dataplane, so
        the stored default of true is COMPLIANT. The naive reading of the same absence would
        have reported every appliance in the lab estate."""
        seed_controls(["PAN-NET-005"])
        PanOsSessionSettings.objects.create(**self._anchors(), ipv6_firewalling=False)
        PanOsSessionSettings.objects.create(
            **self._anchors(self.other), ipv6_firewalling=True)
        regenerate_findings()
        self.assertEqual(
            [(f.subject_name, f.severity) for f in SessionSettingsFinding.objects.all()],
            [("fw-nhd-a", "medium")])


# ---------------------------------------------------------------------------
# PAN-NET-004 - the DHCP configuration
# ---------------------------------------------------------------------------

class DhcpInterfaceConfigControlTests(NetworkHardeningBase):
    def _row(self, name, **fields):
        return PanOsDhcpInterfaceConfig.objects.create(
            **self._anchors(), interface_name=name, **fields)

    def test_the_server_modes_report_at_their_graded_severities(self):
        seed_controls(["PAN-NET-004"])
        self._row("ethernet1/3", dhcp_server_configured=True,
                  dhcp_server_mode=PanOsDhcpInterfaceConfig.MODE_ENABLED,
                  dhcp_relay_state=PanOsDhcpInterfaceConfig.RELAY_NOT_CONFIGURED)
        self._row("ethernet1/4", dhcp_server_configured=True,
                  dhcp_server_mode=PanOsDhcpInterfaceConfig.MODE_AUTO,
                  dhcp_relay_state=PanOsDhcpInterfaceConfig.RELAY_NOT_CONFIGURED)
        self._row("ethernet1/5", dhcp_server_configured=True,
                  dhcp_server_mode=PanOsDhcpInterfaceConfig.MODE_DISABLED,
                  dhcp_relay_state=PanOsDhcpInterfaceConfig.RELAY_NOT_CONFIGURED)
        regenerate_findings()
        self.assertEqual(
            {name: sev for (name, sev)
             in self._findings(DhcpInterfaceConfigFinding, "PAN-NET-004")},
            {"ethernet1/3": "medium", "ethernet1/4": "medium", "ethernet1/5": "low"})

    def test_a_server_branch_with_no_mode_key_still_reports(self):
        """Resting on the branch rather than the mode is what catches it: a null mode matches
        no value comparison, and two of the three modes enable the server."""
        seed_controls(["PAN-NET-004"])
        self._row("ethernet1/8", dhcp_server_configured=True, dhcp_server_mode=None,
                  dhcp_relay_state=PanOsDhcpInterfaceConfig.RELAY_NOT_CONFIGURED)
        regenerate_findings()
        self.assertEqual(
            [sev for (_n, sev) in self._findings(DhcpInterfaceConfigFinding, "PAN-NET-004")],
            ["medium"])

    def test_the_relay_states_report_at_their_graded_severities(self):
        seed_controls(["PAN-NET-004"])
        self._row("ethernet1/6", dhcp_server_configured=False,
                  dhcp_relay_state=PanOsDhcpInterfaceConfig.RELAY_RELAYING)
        self._row("ethernet1/7", dhcp_server_configured=False,
                  dhcp_relay_state=PanOsDhcpInterfaceConfig.RELAY_CONFIGURED_AND_OFF)
        regenerate_findings()
        self.assertEqual(
            {name: sev for (name, sev)
             in self._findings(DhcpInterfaceConfigFinding, "PAN-NET-004")},
            {"ethernet1/6": "medium", "ethernet1/7": "low"})

    def test_one_row_violating_both_halves_is_one_finding_at_the_worse_severity(self):
        """The two halves are one CONTROL, so a row that carries a switched-off server and a
        live relay is one finding - and it reports at the relay's medium rather than the
        server's low, which is the union behaving correctly rather than by luck."""
        seed_controls(["PAN-NET-004"])
        self._row("ethernet1/9", dhcp_server_configured=True,
                  dhcp_server_mode=PanOsDhcpInterfaceConfig.MODE_DISABLED,
                  dhcp_relay_state=PanOsDhcpInterfaceConfig.RELAY_RELAYING)
        regenerate_findings()
        findings = list(DhcpInterfaceConfigFinding.objects.all())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")

    def test_no_dhcp_configuration_means_no_row_and_so_no_finding(self):
        seed_controls(["PAN-NET-004"])
        regenerate_findings()
        self.assertEqual(DhcpInterfaceConfigFinding.objects.count(), 0)


# ---------------------------------------------------------------------------
# PAN-NET-006 - tunnel inspection coverage
# ---------------------------------------------------------------------------

class TunnelInspectionControlTests(NetworkHardeningBase):
    def _row(self, vsys, state, **fields):
        fields.setdefault("scope", PanOsTunnelInspectionCoverage.SCOPE_VSYS)
        fields.setdefault("tunnel_inspect_rules_collected", True)
        return PanOsTunnelInspectionCoverage.objects.create(
            **self._anchors(), vsys_name=vsys,
            tunnel_inspection_coverage_state=state, **fields)

    def test_the_coverage_states_report_at_their_graded_severities(self):
        seed_controls(["PAN-NET-006"])
        T = PanOsTunnelInspectionCoverage
        expected = {
            "vsys1": (T.STATE_NO_POLICY, "medium"),
            "vsys2": (T.STATE_ALL_RULES_DISABLED, "medium"),
            "vsys3": (T.STATE_PROTOCOL_SUBSET, "medium"),
            "vsys4": (T.STATE_ZONE_PAIR_GAP, "medium"),
            "vsys5": (T.STATE_SINGLE_LEVEL_ONLY, "low"),
            "vsys6": (T.STATE_OVERLAY_ID_SCOPED, "low"),
            "vsys7": (T.STATE_UNVERIFIED, "medium"),
        }
        for vsys, (state, _sev) in expected.items():
            self._row(vsys, state, tunnel_inspect_rule_count=1)
        regenerate_findings()
        self.assertEqual(
            {f.subject_name: f.severity for f in TunnelInspectionFinding.objects.all()},
            {vsys: sev for vsys, (_state, sev) in expected.items()})

    def test_fully_opened_reports_nothing(self):
        seed_controls(["PAN-NET-006"])
        self._row("vsys1", PanOsTunnelInspectionCoverage.STATE_FULLY_OPENED,
                  tunnel_inspect_rule_count=3)
        regenerate_findings()
        self.assertEqual(TunnelInspectionFinding.objects.count(), 0)

    def test_the_same_vsys_at_two_scopes_is_two_findings_and_the_row_says_which(self):
        """A vsys's coverage can come from its own rulebase or from a Panorama device group, and
        they are different answers about the same vsys. Without the scope on the finding a
        reader cannot tell which copy they are looking at."""
        seed_controls(["PAN-NET-006"])
        self._row("vsys1", PanOsTunnelInspectionCoverage.STATE_NO_POLICY)
        self._row("vsys1", PanOsTunnelInspectionCoverage.STATE_ALL_RULES_DISABLED,
                  scope=PanOsTunnelInspectionCoverage.SCOPE_DEVICE_GROUP,
                  tunnel_inspect_rule_count=1)
        regenerate_findings()
        self.assertEqual(
            sorted(f.subject_scope for f in TunnelInspectionFinding.objects.all()),
            ["device-group", "vsys"])


# ---------------------------------------------------------------------------
# PAN-NET-007 - routing adjacencies
# ---------------------------------------------------------------------------

class RoutingAdjacencyControlTests(NetworkHardeningBase):
    def _row(self, name, protocol, strength, limit, **fields):
        return PanOsRoutingAdjacency.objects.create(
            **self._anchors(), router_name="vr1", protocol=protocol, adjacency_name=name,
            authentication_strength=strength, prefix_limit_state=limit, **fields)

    def test_the_authentication_strengths_report_at_their_graded_severities(self):
        seed_controls(["PAN-NET-007"])
        R = PanOsRoutingAdjacency
        self._row("a-none", R.PROTOCOL_OSPF, R.STRENGTH_NONE, R.LIMIT_ENFORCING)
        self._row("a-disabled", R.PROTOCOL_OSPF, R.STRENGTH_EXPLICITLY_DISABLED,
                  R.LIMIT_ENFORCING, authentication_profile="p", bgp_authentication_profile="p")
        self._row("a-inner", R.PROTOCOL_OSPF, R.STRENGTH_WEAKER_INNER, R.LIMIT_ENFORCING,
                  authentication_profile="p", bgp_authentication_profile="p")
        self._row("a-clear", R.PROTOCOL_OSPF, R.STRENGTH_CLEARTEXT, R.LIMIT_ENFORCING,
                  authentication_profile="p", bgp_authentication_profile="p")
        self._row("a-weak", R.PROTOCOL_OSPF, R.STRENGTH_WEAK_DIGEST, R.LIMIT_ENFORCING,
                  authentication_profile="p", bgp_authentication_profile="p")
        regenerate_findings()
        self.assertEqual(
            {f.subject_name: f.severity for f in RoutingAdjacencyFinding.objects.all()},
            {"a-none": "high", "a-disabled": "high", "a-inner": "high",
             "a-clear": "high", "a-weak": "medium"})

    def test_the_two_acceptable_strengths_report_nothing(self):
        seed_controls(["PAN-NET-007"])
        R = PanOsRoutingAdjacency
        self._row("a-strong", R.PROTOCOL_OSPF, R.STRENGTH_STRONG_DIGEST, R.LIMIT_ENFORCING,
                  authentication_profile="p", bgp_authentication_profile="p")
        self._row("a-aead", R.PROTOCOL_OSPFV3, R.STRENGTH_AUTHENTICATED_ENCRYPTED,
                  R.LIMIT_ENFORCING, authentication_profile="p",
                  bgp_authentication_profile="p")
        regenerate_findings()
        self.assertEqual(RoutingAdjacencyFinding.objects.count(), 0)

    def test_the_prefix_limit_states_report_only_on_bgp(self):
        """The BGP clause is a SCOPE clause and it is repeated in the query that needs it. An
        OSPF attachment with a sound digest and no ceiling is not a finding - the ceiling half
        is about BGP peers, and the model holds four protocols' adjacencies."""
        seed_controls(["PAN-NET-007"])
        R = PanOsRoutingAdjacency
        self._row("p-none", R.PROTOCOL_BGP, R.STRENGTH_STRONG_DIGEST, R.LIMIT_NO_CEILING,
                  authentication_profile="p", bgp_authentication_profile="p")
        self._row("p-unlimited", R.PROTOCOL_BGP, R.STRENGTH_STRONG_DIGEST, R.LIMIT_UNLIMITED,
                  authentication_profile="p", bgp_authentication_profile="p",
                  max_prefixes=R.MAX_PREFIXES_UNLIMITED)
        self._row("p-warn", R.PROTOCOL_BGP, R.STRENGTH_STRONG_DIGEST, R.LIMIT_WARN_ONLY,
                  authentication_profile="p", bgp_authentication_profile="p")
        self._row("o-none", R.PROTOCOL_OSPF, R.STRENGTH_STRONG_DIGEST, R.LIMIT_NO_CEILING,
                  authentication_profile="p", bgp_authentication_profile="p")
        regenerate_findings()
        self.assertEqual(
            {f.subject_name: f.severity for f in RoutingAdjacencyFinding.objects.all()},
            {"p-none": "medium", "p-unlimited": "medium", "p-warn": "medium"})

    def test_an_unauthenticated_bgp_peer_with_no_ceiling_reports_high(self):
        """THE MOST CONSEQUENTIAL TEST IN THIS MODULE. One control asserts two things at two
        severities over one model. `derive_control_query_severity_value` discards the baseline
        tier the moment ANY non-baseline query with an adjusted severity matches and takes the
        WORST of those - so a peer matching both the high-tier authentication group and the
        medium prefix query must come out high, and would come out medium if the high-tier
        group had been left to the baseline on the grounds that its severity equals the
        control's default.
        """
        seed_controls(["PAN-NET-007"])
        R = PanOsRoutingAdjacency
        self._row("p-both", R.PROTOCOL_BGP, R.STRENGTH_NONE, R.LIMIT_NO_CEILING)
        regenerate_findings()
        findings = list(RoutingAdjacencyFinding.objects.all())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(sorted(findings[0].matched_query_names), [
            "Authentication absent, disabled, cleartext or overridden",
            "BGP peer with no enforced prefix ceiling",
            "Baseline - the adjacency is not authenticated with a strong digest",
        ])

    def test_a_weak_digest_bgp_peer_with_no_ceiling_reports_medium(self):
        """The other side of the same mechanism: both matched calibrations are medium, so the
        worst is medium and the baseline's high is correctly discarded."""
        seed_controls(["PAN-NET-007"])
        R = PanOsRoutingAdjacency
        self._row("p-weak", R.PROTOCOL_BGP, R.STRENGTH_WEAK_DIGEST, R.LIMIT_NO_CEILING,
                  authentication_profile="p", bgp_authentication_profile="p")
        regenerate_findings()
        self.assertEqual(
            [f.severity for f in RoutingAdjacencyFinding.objects.all()], ["medium"])

    def test_no_adjacency_means_no_finding_rather_than_a_passing_one(self):
        """The row's existence IS the applicability test, so a firewall routing only on static
        entries produces nothing. The absence of a finding here is not a statement that the
        firewall's routing is sound."""
        seed_controls(["PAN-NET-007"])
        regenerate_findings()
        self.assertEqual(RoutingAdjacencyFinding.objects.count(), 0)


# ---------------------------------------------------------------------------
# The registrations, and the one subject that has no control
# ---------------------------------------------------------------------------

class NetworkHardeningRegistrationTests(TestCase):
    CONTROL_IDS = [f"PAN-NET-00{n}" for n in range(1, 8)]

    EXPECTED_TARGETS = {
        "PAN-NET-001": "integrations.Interface",
        "PAN-NET-002": "integrations.PanOsSessionSettings",
        "PAN-NET-003": "integrations.Interface",
        "PAN-NET-004": "integrations.PanOsDhcpInterfaceConfig",
        "PAN-NET-005": "integrations.PanOsSessionSettings",
        "PAN-NET-006": "integrations.PanOsTunnelInspectionCoverage",
        "PAN-NET-007": "integrations.PanOsRoutingAdjacency",
    }

    def test_every_control_derives_the_target_model_its_queries_name(self):
        """`Control.save()` DERIVES `target_model` from `control_type`, and a type missing from
        `_CONTROL_TYPE_TARGET_MODEL` has its target silently emptied on every save - the control
        present, matching no model, and the catalog permanently reading as drifted. Two of the
        three registrations a new subject needs are silent when missed; this is the one that
        catches the silent pair for this domain."""
        for control in seed_controls(self.CONTROL_IDS):
            with self.subTest(control.control_id):
                self.assertEqual(control.target_model,
                                 self.EXPECTED_TARGETS[control.control_id])
                self.assertTrue(control.target_model, "target_model was silently emptied")
                for query in control.queries.all():
                    self.assertEqual(query.canonical_query["model"], control.target_model)

    def test_every_query_carries_the_fault_and_not_the_scope_in_asserted_fields(self):
        """Leave `asserted_fields` empty and `tested_fields()` falls back to EVERY clause,
        colouring the cells that SCOPED the object as well as the one that failed - silently, in
        the consumer repo, pointing a reader at the wrong setting. PAN-NET-007's BGP clause is
        the instance: it is a scope clause and must not appear."""
        for control in seed_controls(self.CONTROL_IDS):
            for query in control.queries.all():
                with self.subTest(control=control.control_id, query=query.name):
                    self.assertTrue(query.asserted_fields)
                    self.assertNotIn("protocol", query.asserted_fields)

    def test_the_global_lldp_subject_has_a_finding_model_and_no_control(self):
        """A recorded state, not an oversight. PAN-NET-003 asserts over `Interface` AND
        `PanOsLldpGlobalSettings`; `_CONTROL_TYPE_TARGET_MODEL` is one-to-one and
        `ControlQuery.clean()` refuses a query whose model differs from its control's target, so
        one catalogue control cannot hold both halves. Splitting the catalogue id changes what a
        customer's report contains and is not a run's decision.

        This test exists so that the half Jason may decide to build is found by someone looking
        for it, rather than by a reader wondering why the model has no rows.
        """
        seed_controls(self.CONTROL_IDS)
        self.assertEqual(
            Control.objects.filter(
                control_type=Control.ControlType.LLDP_GLOBAL).count(), 0)
        self.assertEqual(
            Control._CONTROL_TYPE_TARGET_MODEL[Control.ControlType.LLDP_GLOBAL],
            "integrations.PanOsLldpGlobalSettings")
        # The model and its search package exist and agree, so the query is writable today.
        from assessments.search.registry import get_model_entry
        self.assertIs(
            get_model_entry("integrations.PanOsLldpGlobalSettings")["model_class"],
            PanOsLldpGlobalSettings)
