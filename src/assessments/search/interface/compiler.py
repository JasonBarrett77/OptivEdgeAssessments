"""Canonical search compiler for one interface or subinterface. PAN-NET-001 and PAN-NET-003.

One row per interface per appliance, device-wide: the interface namespace is not vsys-scoped,
so there is no vsys axis and no shared-versus-vsys precedence. On an HA pair a port
synchronised between peers yields TWO rows for one real port, one per appliance, and nothing
downstream deduplicates them - `models/interfaces.py` says so in writing and explains why the
alternative (populating the active member only) was worse.

`ipv4_addresses` AND `ipv6_addresses` ARE DELIBERATELY NOT REACHABLE FROM HERE. They are
JSONFields, stage 5 marks `ipv4_addresses` `not_searchable`, and
`tests/test_findings_rest_on_columns.py` enforces the rule exhaustively by walking the compiled
query tree. What a control reads instead is `addressing` - the three-way alternative between a
static address, a DHCP client lease and PPPoE - and the `out_of_service_residue` verdict that
already folds "holds an address" into its ranking.

TWO COLUMNS HERE REASSURE AND NEITHER IS WHAT A CONTROL CLAUSES ON, which is the reason their
registration is not an invitation:

* `security_zone_name` is empty both for a port in no zone and for a row nobody has recomputed,
  so empty is not evidence. `out_of_service_residue` carries the firing.
* `lldp_enabled` is non-nullable with a materialised default of false, so an appliance whose
  interfaces were never read holds false on every port - which reads as compliant. That default
  is correct for a port that WAS read and carries no key, which is the ordinary case and the one
  stage 4 measured; it is wrong for a port nobody read, and no column on this model separates
  the two. PAN-NET-003's baseline rests on it anyway because stage 5 declared the collection gap
  as a reported decision rather than as a clause - see the stage 8 artifact.

`link_state` IS NULLABLE AND `is_empty` CANNOT REACH A NULL ON A TEXT COLUMN - measured here,
not assumed: `filter(link_state="")` returns no row for a row holding NULL. Nothing clauses on
it; it is a display-and-input column read by the verdict beside it, which is exactly the use
`models/interfaces.py` reserves a nullable column for.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import Interface

INTERFACE_MODEL = "integrations.Interface"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return Interface.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return Interface.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return Interface.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # The row's address. One stage 5 column, `appliance`, registered as two fields because an
    # engineer searches by whichever one they are holding and a serial is the only stable one.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "name": build_text_compiler("name", "name"),
    # Readings. `addressing` stands in for the two JSON address lists, which may not be
    # registered; it is also the better reading, since a DHCP client legitimately holds no
    # address in configuration.
    "addressing": build_text_compiler("addressing", "addressing"),
    "management_profile_name": build_text_compiler(
        "management_profile_name", "management_profile_name"),
    "security_zone_name": build_text_compiler("security_zone_name", "security_zone_name"),
    "link_state": build_text_compiler("link_state", "link_state"),
    "lldp_profile_name": build_text_compiler("lldp_profile_name", "lldp_profile_name"),
    # Booleans whose FALSE is the firing side and also the migration default, so a port nobody
    # recomputed is reported rather than passing.
    "management_profile_restricts_sources": build_boolean_compiler(
        "management_profile_restricts_sources", "management_profile_restricts_sources"),
    "lldp_node_present": build_boolean_compiler("lldp_node_present", "lldp_node_present"),
    "lldp_enabled": build_boolean_compiler("lldp_enabled", "lldp_enabled"),
    # The two verdict columns. PAN-NET-001 asserts and grades on the first, PAN-NET-003 grades
    # on the second; every member of both vocabularies is placed by stage 5.
    "out_of_service_residue": build_text_compiler(
        "out_of_service_residue", "out_of_service_residue"),
    "lldp_announced_content": build_text_compiler(
        "lldp_announced_content", "lldp_announced_content"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_interface_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_interface_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def compile_search_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause["negated"] else predicate
