"""Canonical search compiler for interface management profiles.

The searchable unit is the profile ON ONE APPLIANCE. A profile pushed from a Panorama
template exists separately in each firewall's merged config, and bound on one device but
not another it is genuinely two different facts - so the row, and the finding, are per
appliance rather than per template.

`binding_count` is the field that matters and it is an ordinary column: normalization
counts the bindings from the same payload in the same pass, so asking "is this unused" here
is a scalar comparison rather than a join against the surfaces the profile did not create.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import InterfaceManagementProfile

INTERFACE_MANAGEMENT_PROFILE_MODEL = "integrations.InterfaceManagementProfile"

INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains",
                  "starts_with": "istartswith", "ends_with": "iendswith"}.get(op, "iexact")
        return InterfaceManagementProfile.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def compile_binding_count_clause(clause):
    op, value = clause["op"], clause["value"]
    if op not in INTEGER_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for binding_count: {op}.")
    if isinstance(value, bool) or not isinstance(value, int):
        raise SearchSyntaxError("binding_count search value must be an integer.")
    suffix = {"eq": "exact"}.get(op, op)
    return InterfaceManagementProfile.objects.filter(
        **{f"bound_interface_count__{suffix}": value}).values("pk")


compile_binding_count_clause.SUPPORTED_OPERATORS = INTEGER_OPERATORS

FIELD_COMPILERS = {
    "binding_count": compile_binding_count_clause,
    "name": build_text_compiler("name", "name"),
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
}

FIELD_OPERATOR_REGISTRY = {
    name: getattr(compiler, "SUPPORTED_OPERATORS", TEXT_OPERATORS)
    for name, compiler in FIELD_COMPILERS.items()
}


def compile_interface_management_profile_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_interface_management_profile_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    field = clause["field"]
    compiler = FIELD_COMPILERS.get(field)
    if compiler is None:
        raise SearchSyntaxError(
            f"Unsupported search field for {INTERFACE_MANAGEMENT_PROFILE_MODEL}: {field}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause.get("negated") else predicate
