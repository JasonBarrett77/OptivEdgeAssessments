"""Canonical search compiler for anti-spyware and vulnerability profiles.

The verdict fields - `critical_blocked`, `high_blocked`, `medium_blocked` - are stored
CONCLUSIONS, computed in normalization from the profile's whole rule list, because the question
"is every critical threat blocked" spans rules and the search layer compares one field to a
literal. The reason sits beside each verdict (`critical_detail`) so a row can be checked rather
than taken.

A profile belongs to an enforcement point (vsys and predefined scope) or to an appliance group
(shared scope), so `appliance_group` matches either path.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import SecurityProfile

SECURITY_PROFILE_MODEL = "integrations.SecurityProfile"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        # EVERY path empty or missing. A profile has one owner, so the other owner's path is
        # always NULL - OR-ing the null branches would call every row empty.
        q = Q()
        for lookup in lookups:
            q &= Q(**{lookup: ""}) | Q(**{f"{lookup}__isnull": True})
        return q
    if not isinstance(value, str) or not value.strip():
        raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
    suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
    q = Q()
    for lookup in lookups:
        q |= Q(**{f"{lookup}__{suffix}": value.strip()})
    return q


def build_text_compiler(field_name, *lookups):
    """One field over one or more lookup paths - several when the owner can be either model."""
    def compiler(clause):
        return SecurityProfile.objects.filter(_text_filter(field_name, lookups, clause)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return SecurityProfile.objects.filter(**{lookup_field: value}).values("pk")
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
        return SecurityProfile.objects.filter(**{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "name": build_text_compiler("name", "name"),
    "kind": build_text_compiler("kind", "kind"),
    "namespace_type": build_text_compiler("namespace_type", "namespace_type"),
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    "appliance_group": build_text_compiler(
        "appliance_group", "appliance_group__name", "enforcement_point__appliance_group__name"),
    # The firewalls holding the definition: every appliance of the owning group, or the vsys's.
    "hostname": build_text_compiler(
        "hostname", "appliance_group__appliances__hostname",
        "enforcement_point__appliance_group__appliances__hostname", "enforcement_point__appliance__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "appliance_group__appliances__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number",
        "enforcement_point__appliance__serial_number"),
    "description": build_text_compiler("description", "description"),
    "is_predefined": build_boolean_compiler("is_predefined", "is_predefined"),
    "is_used": build_boolean_compiler("is_used", "is_used"),
    "critical_blocked": build_boolean_compiler("critical_blocked", "critical_blocked"),
    "critical_detail": build_text_compiler("critical_detail", "critical_detail"),
    "high_blocked": build_boolean_compiler("high_blocked", "high_blocked"),
    "high_detail": build_text_compiler("high_detail", "high_detail"),
    "medium_blocked": build_boolean_compiler("medium_blocked", "medium_blocked"),
    "medium_detail": build_text_compiler("medium_detail", "medium_detail"),
    "rule_count": build_integer_compiler("rule_count", "rule_count"),
    "referrer_count": build_integer_compiler("referrer_count", "referrer_count"),
    "threat_exception_count": build_integer_compiler("threat_exception_count", "threat_exception_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_security_profile_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_security_profile_search_node(c) for c in group["clauses"]]
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
