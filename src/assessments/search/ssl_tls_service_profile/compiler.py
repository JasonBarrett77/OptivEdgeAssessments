"""Canonical search compiler for SSL/TLS service profiles as objects.

The searchable unit is the profile ON ONE APPLIANCE IN ONE SCOPE. Both halves matter: the
same profile pushed from a template exists separately in each firewall's merged config, and
a name can occur twice on one device in different scopes - a shared entry and a predefined
one, measured 2026-09-02, where the predefined definition is the one in force.

Every searchable field here is an ordinary COLUMN. `protocol_algorithms` holds the other
fifteen algorithm settings and is deliberately NOT searchable: a finding must rest on a column,
not on a key inside a JSON blob, which is unindexed, silently matches nothing when a key is
renamed, and writes the shape of a vendor payload into a control definition where no schema
protects it. `allows_sha1` was promoted to a column when PAN-CRT-009 needed to assert it; the
rest stay readable for display until a control asks.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import SslTlsServiceProfile

SSL_TLS_SERVICE_PROFILE_MODEL = "integrations.SslTlsServiceProfile"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return SslTlsServiceProfile.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return SslTlsServiceProfile.objects.filter(
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
        return SslTlsServiceProfile.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "name": build_text_compiler("name", "name"),
    "scope": build_text_compiler("scope", "scope"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "certificate_name": build_text_compiler("certificate_name", "certificate_name"),
    "min_version": build_text_compiler("min_version", "min_version"),
    "max_version": build_text_compiler("max_version", "max_version"),
    # A COLUMN, not a JSON lookup. See the model: a finding must rest on a column, and the
    # CBC and key-exchange settings are deliberately not searchable because no control asserts
    # them - they are readable in protocol_algorithms for display.
    "allows_sha1": build_boolean_compiler("allows_sha1", "allows_sha1"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_ssl_tls_service_profile_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_ssl_tls_service_profile_search_node(c) for c in group["clauses"]]
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
