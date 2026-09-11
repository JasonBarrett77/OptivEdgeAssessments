"""Canonical search compiler for authentication sequences. PAN-AAA-012.

The searchable unit is the sequence ON ONE APPLIANCE IN ONE SCOPE, as for authentication
profiles: a shared and a vsys definition can share a name. The members themselves are not
searchable fields - a finding rests on a column - so what a query can ask is what the
normalizer resolved from them: whether any member is local, whether all are external, how many
failed to resolve.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import AuthenticationSequence

AUTHENTICATION_SEQUENCE_MODEL = "integrations.AuthenticationSequence"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return AuthenticationSequence.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return AuthenticationSequence.objects.filter(
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
        return AuthenticationSequence.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in INTEGER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return AuthenticationSequence.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "name": build_text_compiler("name", "name"),
    "scope": build_text_compiler("scope", "scope"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "is_administrative": build_boolean_compiler("is_administrative", "is_administrative"),
    "has_local_member": build_boolean_compiler("has_local_member", "has_local_member"),
    "all_members_external": build_boolean_compiler("all_members_external", "all_members_external"),
    "exit_sequence_on_failure": build_boolean_compiler(
        "exit_sequence_on_failure", "exit_sequence_on_failure"),
    "use_domain_find_profile": build_boolean_compiler(
        "use_domain_find_profile", "use_domain_find_profile"),
    "use_userid_domain": build_boolean_compiler("use_userid_domain", "use_userid_domain"),
    "member_count": build_integer_compiler("member_count", "member_count"),
    "referrer_count": build_integer_compiler("referrer_count", "referrer_count"),
    "unresolved_member_count": build_integer_compiler(
        "unresolved_member_count", "unresolved_member_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_authentication_sequence_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_authentication_sequence_search_node(c) for c in group["clauses"]]
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
