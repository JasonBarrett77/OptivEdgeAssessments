"""Canonical search compiler for the management resolvers. PAN-SVC-003.

One row per appliance: how the MANAGEMENT PLANE resolves names, which is a different question
from how the data plane does. Minted by stage 8 of `device-services` on 2026-11-01.

TWO COLUMNS AND NO MORE, plus the appliance identity. Stage 5 marks seven of this subject's ten
columns `needs_compiler_field`, and only two of them are NAMED by this domain - `chosen_resolver_
count` as PAN-SVC-003's assertion clause and `management_resolver_posture` as its grading axis.
The other five (`primary_resolver_address`, `secondary_resolver_address`, `dns_proxy_object_name`,
`resolver_mechanism`, `resolution_follows_the_management_lease`) are deliberately NOT registered:
the compiler's rule in this repository is that a field earns its place by a control needing it,
and registering the rest would ship a search surface no control asks for. They are report columns
and a later control is what earns them a field.

`hostname` AND `serial_number` BOTH SERVE STAGE 5's ONE `appliance` COLUMN, which is what the
three shipped compilers of this domain's other subjects do - measured before copying it rather
than assumed, because three of the 66 shipped compilers register neither.

`management_resolver_posture` TAKES THE TEXT COMPILER rather than `build_choice_compiler`, for
the reason the NTP compiler records: the closed form accepts none of the shared
`PROBE_VALUES` and this model carries a JSONField (`management_resolvers_in_force`), so the
closed form would put this domain's vocabulary into a shared test of every other model.
`is_empty` comes with the text operator set and can never match - the column is non-null with a
non-empty default.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import DnsSettings

DNS_SETTINGS_MODEL = "integrations.DnsSettings"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return DnsSettings.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return DnsSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in INTEGER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return DnsSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "chosen_resolver_count": build_integer_compiler(
        "chosen_resolver_count", "chosen_resolver_count"),
    "management_resolver_posture": build_text_compiler(
        "management_resolver_posture", "management_resolver_posture"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_dns_settings_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_dns_settings_search_node(c) for c in group["clauses"]]
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
