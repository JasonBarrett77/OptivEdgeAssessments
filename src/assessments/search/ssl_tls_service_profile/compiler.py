"""Canonical search compiler for SSL/TLS service profiles as objects.

The searchable unit is the profile ON ONE APPLIANCE IN ONE SCOPE. Both halves matter: the
same profile pushed from a template exists separately in each firewall's merged config, and
a name can occur twice on one device in different scopes - a shared entry and a predefined
one, measured 2026-09-02, where the predefined definition is the one in force.

`min_version` is an ordinary column and is what PAN-CRT-005 tests. The ALGORITHM settings are
searchable too, and deliberately not part of that control: the corpus asserts a protocol
floor and nothing about ciphers. They are exposed because a profile can hold a TLS 1.2 floor
while permitting SHA-1 and CBC - measured, and true of every profile in the lab - so an
engineer reading the tab needs to see it even though no control fires on it yet.
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


def build_algorithm_compiler(field_name, algorithm_key):
    """Match on an EFFECTIVE algorithm setting, absent already expanded to enabled.

    Queried through the JSON column rather than a per-algorithm boolean, because there are
    sixteen of them and no control reads any yet - a column each would be sixteen migrations
    ahead of a requirement.
    """
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return SslTlsServiceProfile.objects.filter(
            **{f"protocol_algorithms__{algorithm_key}": value}).values("pk")
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
    "allows_sha1": build_algorithm_compiler("allows_sha1", "auth-algo-sha1"),
    "allows_aes_128_cbc": build_algorithm_compiler("allows_aes_128_cbc", "enc-algo-aes-128-cbc"),
    "allows_aes_256_cbc": build_algorithm_compiler("allows_aes_256_cbc", "enc-algo-aes-256-cbc"),
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
