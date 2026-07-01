import json
import ipaddress

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments.models import (
    Control,
    ControlQuery,
    SecurityRuleSearchState,
)
from assessments.search.compiler import apply_search
from assessments.search.exceptions import SearchSyntaxError
from optivedge.integrations.models import (
    AddressGroup,
    AddressGroupMember,
    AddressObject,
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    SecurityRule,
    SecurityRuleApplication,
    SecurityRuleDestinationAddressRef,
    SecurityRuleFromZone,
    SecurityRuleService,
    SecurityRuleSourceAddressRef,
    SecurityRuleToZone,
    Snapshot,
)


class SecurityRuleSearchTests(TestCase):
    model_name = "integrations.SecurityRule"

    def setUp(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        group = ApplianceGroup.objects.create(
            management_station=station,
            name="group-a",
        )
        enforcement_point = EnforcementPoint.objects.create(
            management_station=station,
            appliance_group=group,
            vsys_name="vsys1",
            vsys_display_name="edge",
        )
        snapshot = Snapshot.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_type="test",
            collected_at=timezone.now(),
        )
        self.rule_one = SecurityRule.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=1,
            rule_position=1,
            name="rule-one",
            action="allow",
            disabled=False,
            rule_type="universal",
            description="Primary trust to dmz rule",
            log_start=False,
            log_end=True,
            log_setting="default",
        )
        self.rule_two = SecurityRule.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=2,
            rule_position=2,
            name="rule-two",
            action="deny",
            disabled=True,
            rule_type="intrazone",
            description="Secondary dmz to untrust rule",
            log_start=True,
            log_end=False,
            log_setting="verbose",
        )
        any_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name="any",
            namespace_type="builtin",
            namespace_value="any",
            precedence_rank=90,
            address_type=AddressObject.TYPE_BUILTIN_ANY,
            value="any",
            normalized_value="any",
            ipv4_start_int=0,
            ipv4_end_int=4_294_967_295,
            num_hosts=4_294_967_296,
            is_any=True,
            is_builtin=True,
            description="Built-in any match",
            raw_object={"builtin": True},
        )
        web_prod_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name="web-prod",
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            address_type=AddressObject.TYPE_IP_NETMASK,
            value="10.10.10.10/32",
            normalized_value="10.10.10.10/32",
            ipv4_start_int=168430090,
            ipv4_end_int=168430090,
            num_hosts=1,
            description="",
            raw_object={},
        )
        corp_users_object = AddressObject.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name="corp-users",
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            address_type=AddressObject.TYPE_IP_NETMASK,
            value="10.20.20.20/32",
            normalized_value="10.20.20.20/32",
            ipv4_start_int=169088020,
            ipv4_end_int=169088020,
            num_hosts=1,
            description="",
            raw_object={},
        )
        corp_group = AddressGroup.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name="corp-group",
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            dynamic_filter="",
            raw_group={},
        )
        AddressGroupMember.objects.create(
            address_group=corp_group,
            value="corp-users",
            prov="local",
            position=1,
        )
        SecurityRuleFromZone.objects.create(
            security_rule=self.rule_one,
            value="trust",
            position=1,
        )
        SecurityRuleToZone.objects.create(
            security_rule=self.rule_one,
            value="dmz",
            position=1,
        )
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=self.rule_one,
            raw_value="any",
            ref_type=SecurityRuleSourceAddressRef.RefType.ANY,
            address_object=any_object,
            position=1,
        )
        SecurityRuleDestinationAddressRef.objects.create(
            security_rule=self.rule_one,
            raw_value="web-prod",
            ref_type=SecurityRuleDestinationAddressRef.RefType.ADDRESS_OBJECT,
            address_object=web_prod_object,
            position=1,
        )
        SecurityRuleApplication.objects.create(
            security_rule=self.rule_one,
            value="any",
            position=1,
        )
        SecurityRuleService.objects.create(
            security_rule=self.rule_one,
            value="application-default",
            position=1,
        )
        SecurityRuleFromZone.objects.create(
            security_rule=self.rule_two,
            value="dmz",
            position=1,
        )
        SecurityRuleToZone.objects.create(
            security_rule=self.rule_two,
            value="untrust",
            position=1,
        )
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=self.rule_two,
            raw_value="corp-group",
            ref_type=SecurityRuleSourceAddressRef.RefType.STATIC_ADDRESS_GROUP,
            address_object=corp_users_object,
            address_group=corp_group,
            position=1,
        )
        SecurityRuleDestinationAddressRef.objects.create(
            security_rule=self.rule_two,
            raw_value="any",
            ref_type=SecurityRuleDestinationAddressRef.RefType.ANY,
            address_object=any_object,
            position=1,
        )
        SecurityRuleApplication.objects.create(
            security_rule=self.rule_two,
            value="ssl",
            position=1,
        )
        SecurityRuleService.objects.create(
            security_rule=self.rule_two,
            value="any",
            position=1,
        )
        self.control = Control.objects.create(
            control_id="FW-RULE-PERMISSIVENESS-001",
            name="Ensure firewall rules are not overly permissive",
            control_type=Control.ControlType.SECURITY_RULE,
            description="Prototype control",
            default_severity=Control.Severity.MEDIUM,
        )
        self.station = station
        self.group = group
        self.enforcement_point = enforcement_point
        self.snapshot = snapshot
        self.any_object = any_object

    def create_interval_object(self, *, name, value):
        if "-" in value:
            start_text, end_text = value.split("-", 1)
            start = int(ipaddress.IPv4Address(start_text))
            end = int(ipaddress.IPv4Address(end_text))
            address_type = AddressObject.TYPE_IP_RANGE
            normalized_value = value
        else:
            network = ipaddress.IPv4Network(value, strict=False)
            start = int(network.network_address)
            end = int(network.broadcast_address)
            address_type = AddressObject.TYPE_IP_NETMASK
            normalized_value = str(network)

        return AddressObject.objects.create(
            management_station=self.station,
            enforcement_point=self.enforcement_point,
            source_snapshot=self.snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name=name,
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            address_type=address_type,
            value=value,
            normalized_value=normalized_value,
            ipv4_start_int=start,
            ipv4_end_int=end,
            num_hosts=(end - start) + 1,
            description="",
            raw_object={},
        )

    def create_rule(self, name):
        return SecurityRule.objects.create(
            management_station=self.station,
            enforcement_point=self.enforcement_point,
            source_snapshot=self.snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=SecurityRule.objects.count() + 1,
            rule_position=SecurityRule.objects.count() + 1,
            name=name,
            action="allow",
            disabled=False,
            rule_type="universal",
            description="",
            log_start=False,
            log_end=True,
            log_setting="default",
        )

    def test_from_zone_exact_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"from_zone","op":"eq","value":"trust"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_one], transform=lambda rule: rule)

    def test_from_zone_negated_match_excludes_matching_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"from_zone","op":"eq","value":"trust","negated":true}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_two], transform=lambda rule: rule)

    def test_nested_group_matches_either_branch(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"or","clauses":['
                '{"field":"from_zone","op":"eq","value":"trust"},'
                '{"field":"from_zone","op":"eq","value":"dmz"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(
            queryset,
            [self.rule_one, self.rule_two],
            transform=lambda rule: rule,
            ordered=True,
        )

    def test_missing_model_raises_search_syntax_error(self):
        with self.assertRaises(SearchSyntaxError):
            apply_search(
                SecurityRule.objects.all(),
                '{"operator":"and","clauses":[{"field":"from_zone","op":"eq","value":"trust"}]}',
            )

    def test_unsupported_operator_raises_search_syntax_error(self):
        with self.assertRaises(SearchSyntaxError):
            apply_search(
                SecurityRule.objects.all(),
                (
                    '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                    '{"field":"from_zone","op":"in","value":["trust"]}'
                    ']}'
                ),
            )

    def test_to_zone_exact_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"to_zone","op":"eq","value":"untrust"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_two], transform=lambda rule: rule)

    def test_source_address_name_any_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"source_address_name","op":"eq","value":"any"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_one], transform=lambda rule: rule)

    def test_destination_address_name_any_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"destination_address_name","op":"eq","value":"any"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_two], transform=lambda rule: rule)

    def test_source_address_name_effective_object_name_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"source_address_name","op":"eq","value":"corp-users"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_two], transform=lambda rule: rule)

    def test_source_address_name_group_name_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"source_address_name","op":"eq","value":"corp-group"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_two], transform=lambda rule: rule)

    def test_destination_address_exactly_matches_effective_member_equality(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"destination_address","op":"exactly","value":"10.10.10.10"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_one], transform=lambda rule: rule)

    def test_source_address_matches_requires_full_coverage(self):
        broad_object = self.create_interval_object(name="broad-net", value="10.0.0.0/8")
        rule = self.create_rule("rule-match-broad")
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=rule,
            raw_value="broad-net",
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=broad_object,
            position=1,
        )

        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"source_address","op":"matches","value":"10.64.0.0/10"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [rule], transform=lambda result: result)

    def test_source_address_includes_matches_effective_static_group_member(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"source_address","op":"includes","value":"10.20.20.20"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_two], transform=lambda rule: rule)

    def test_source_address_exactly_matches_effective_member_equality(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"source_address","op":"exactly","value":"10.20.20.20/32"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_two], transform=lambda rule: rule)

    def test_source_address_intersects_matches_overlap(self):
        broad_object = self.create_interval_object(name="overlap-net", value="10.0.0.0/9")
        rule = self.create_rule("rule-overlap")
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=rule,
            raw_value="overlap-net",
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=broad_object,
            position=1,
        )

        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"source_address","op":"intersects","value":"10.64.0.0/10"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [rule], transform=lambda result: result)

    def test_source_address_matches_include_any_allows_any_member(self):
        broad_object = self.create_interval_object(name="broad-net-exclude", value="10.0.0.0/8")
        rule = self.create_rule("rule-match-exclude-any")
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=rule,
            raw_value="broad-net-exclude",
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=broad_object,
            position=1,
        )

        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"source_address","op":"matches","value":"10.64.0.0/10","include_any":true}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(
            queryset,
            [self.rule_one, rule],
            transform=lambda result: result,
        )

    def test_source_address_equals_requires_contiguous_merged_effective_set(self):
        first_half = self.create_interval_object(name="half-a", value="10.0.0.0/9")
        second_half = self.create_interval_object(name="half-b", value="10.128.0.0/9")
        contiguous_rule = self.create_rule("rule-equals-contiguous")
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=contiguous_rule,
            raw_value="half-a",
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=first_half,
            position=1,
        )
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=contiguous_rule,
            raw_value="half-b",
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=second_half,
            position=2,
        )

        disjoint_object = self.create_interval_object(name="disjoint-net", value="11.0.0.0/9")
        disjoint_rule = self.create_rule("rule-equals-disjoint")
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=disjoint_rule,
            raw_value="half-a",
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=first_half,
            position=1,
        )
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=disjoint_rule,
            raw_value="disjoint-net",
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=disjoint_object,
            position=2,
        )

        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"source_address","op":"equals","value":"10.0.0.0/8"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [contiguous_rule], transform=lambda rule: rule)

    def test_source_address_skips_dynamic_group_refs_for_semantic_queries(self):
        dynamic_group = AddressGroup.objects.create(
            management_station=self.station,
            enforcement_point=self.enforcement_point,
            source_snapshot=self.snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            name="dynamic-group",
            namespace_type="local_vsys",
            namespace_value="vsys1",
            precedence_rank=10,
            dynamic_filter="'tag eq prod'",
            raw_group={},
        )
        rule = self.create_rule("rule-dynamic-group")
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=rule,
            raw_value="dynamic-group",
            ref_type=SecurityRuleSourceAddressRef.RefType.DYNAMIC_ADDRESS_GROUP,
            address_group=dynamic_group,
            position=1,
        )

        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"source_address","op":"intersects","value":"10.20.20.20"}'
                ']}'
            ),
        )

        self.assertNotIn(rule, list(queryset))

    def test_source_address_rejects_fqdn_query_value_for_semantic_queries(self):
        with self.assertRaises(SearchSyntaxError):
            apply_search(
                SecurityRule.objects.order_by("pk"),
                (
                    '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                    '{"field":"source_address","op":"matches","value":"example.com"}'
                    ']}'
                ),
            )

    def test_semantic_address_clause_rejects_non_boolean_include_any(self):
        with self.assertRaises(SearchSyntaxError):
            apply_search(
                SecurityRule.objects.order_by("pk"),
                (
                    '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                    '{"field":"source_address","op":"matches","value":"10.0.0.1","include_any":"yes"}'
                    ']}'
                ),
            )

    def test_application_any_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"application","op":"eq","value":"any"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_one], transform=lambda rule: rule)

    def test_service_any_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"service","op":"eq","value":"any"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_two], transform=lambda rule: rule)

    def test_config_source_display_label_exact_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"config_source","op":"eq","value":"Local"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(
            queryset,
            [self.rule_one, self.rule_two],
            transform=lambda rule: rule,
            ordered=True,
        )

    def test_management_station_hostname_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"management_station","op":"contains","value":"panorama"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(
            queryset,
            [self.rule_one, self.rule_two],
            transform=lambda rule: rule,
            ordered=True,
        )

    def test_vsys_display_name_exact_match_filters_rules(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"vsys_display_name","op":"eq","value":"edge"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(
            queryset,
            [self.rule_one, self.rule_two],
            transform=lambda rule: rule,
            ordered=True,
        )

    def test_description_contains_filters_single_rule(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"description","op":"contains","value":"trust to dmz"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_one], transform=lambda rule: rule)

    def test_disabled_true_match_filters_single_rule(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"disabled","op":"eq","value":"true"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_two], transform=lambda rule: rule)

    def test_log_start_yes_match_filters_single_rule(self):
        queryset, _search_query = apply_search(
            SecurityRule.objects.order_by("pk"),
            (
                '{"model":"integrations.SecurityRule","operator":"and","clauses":['
                '{"field":"log_start","op":"eq","value":"yes"}'
                ']}'
            ),
        )

        self.assertQuerySetEqual(queryset, [self.rule_two], transform=lambda rule: rule)

    def test_post_search_creates_server_side_search_state(self):
        payload = (
            '{"model":"integrations.SecurityRule","operator":"and","clauses":['
            '{"field":"from_zone","op":"eq","value":"trust"}'
            ']}'
        )
        response = self.client.post(
            reverse("assessment_security_rule_list"),
            {
                "q": payload,
                "search": payload,
            },
        )

        self.assertEqual(response.status_code, 302)
        search_state = SecurityRuleSearchState.objects.get()
        self.assertIn(f"search_state={search_state.token}", response["Location"])
        self.assertEqual(
            search_state.canonical_query,
            {
                "model": self.model_name,
                "operator": "and",
                "clauses": [
                    {
                        "field": "from_zone",
                        "op": "eq",
                        "value": "trust",
                        "negated": False,
                        "case_sensitive": False,
                        "include_any": False,
                    }
                ],
            },
        )

    def test_get_with_search_state_filters_results(self):
        search_state = SecurityRuleSearchState.objects.create(
            query_text='{"model":"integrations.SecurityRule","operator":"and","clauses":[{"field":"from_zone","op":"eq","value":"trust"}]}',
            canonical_query={
                "model": self.model_name,
                "operator": "and",
                "clauses": [
                    {
                        "field": "from_zone",
                        "op": "eq",
                        "value": "trust",
                        "negated": False,
                        "case_sensitive": False,
                    }
                ],
            },
        )

        response = self.client.get(
            reverse("assessment_security_rule_list"),
            {"search_state": str(search_state.token)},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["security_rule_rows"]), 1)
        self.assertEqual(response.context["security_rule_rows"][0]["security_rule"], self.rule_one)

    def test_edit_search_can_preload_saved_control_query(self):
        control_query = ControlQuery.objects.create(
            control=self.control,
            name="Any source baseline",
            short_description="Matches source any rules.",
            canonical_query={
                "model": self.model_name,
                "operator": "and",
                "clauses": [
                    {
                        "field": "source_address_name",
                        "op": "eq",
                        "value": "any",
                    }
                ],
            },
            is_baseline=True,
        )

        response = self.client.get(
            reverse("assessment_security_rule_list"),
            {
                "edit_search": "1",
                "control_query": control_query.pk,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(response.context["search_editor_query"]),
            control_query.canonical_query,
        )

    def test_get_with_control_query_applies_saved_query(self):
        control_query = ControlQuery.objects.create(
            control=self.control,
            name="Any source baseline",
            short_description="Matches source any rules.",
            canonical_query={
                "model": self.model_name,
                "operator": "and",
                "clauses": [
                    {
                        "field": "source_address_name",
                        "op": "eq",
                        "value": "any",
                        "negated": False,
                        "case_sensitive": False,
                    }
                ],
            },
            is_baseline=True,
        )

        response = self.client.get(
            reverse("assessment_security_rule_list"),
            {"control_query": control_query.pk},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["search_query"], control_query.canonical_query)
        self.assertEqual(len(response.context["security_rule_rows"]), 1)
        self.assertEqual(response.context["security_rule_rows"][0]["security_rule"], self.rule_one)

    def test_get_with_control_applies_active_queries(self):
        baseline_query = ControlQuery.objects.create(
            control=self.control,
            name="Any source baseline",
            short_description="Matches source any rules.",
            canonical_query={
                "model": self.model_name,
                "operator": "and",
                "clauses": [
                    {
                        "field": "source_address_name",
                        "op": "eq",
                        "value": "any",
                    }
                ],
            },
            is_baseline=True,
        )
        calibration_query = ControlQuery.objects.create(
            control=self.control,
            name="Any service calibration",
            short_description="Raise severity for any service rules.",
            canonical_query={
                "model": self.model_name,
                "operator": "and",
                "clauses": [
                    {
                        "field": "service",
                        "op": "eq",
                        "value": "any",
                    }
                ],
            },
            is_baseline=False,
            adjusted_severity=Control.Severity.HIGH,
        )

        response = self.client.get(
            reverse("assessment_security_rule_list"),
            {"control": self.control.pk},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["selected_control"], self.control)
        self.assertEqual(response.context["selected_control_query_count"], 2)
        self.assertEqual(response.context["selected_control_skipped_queries"], 0)
        self.assertTrue(response.context["show_control_severity"])
        self.assertEqual(
            response.context["search_summary"],
            f"Control candidates: {self.control.control_id} (2 queries)",
        )
        self.assertEqual(len(response.context["security_rule_rows"]), 2)
        self.assertEqual(response.context["security_rule_rows"][0]["security_rule"], self.rule_one)
        self.assertEqual(response.context["security_rule_rows"][1]["security_rule"], self.rule_two)
        self.assertEqual(response.context["security_rule_rows"][0]["control_severity"], "Medium")
        self.assertEqual(response.context["security_rule_rows"][1]["control_severity"], "High")
        self.assertContains(response, ">Severity<")
