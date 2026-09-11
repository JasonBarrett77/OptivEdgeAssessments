"""Canonical search compiler for the management interface's SSL/TLS binding.

PAN-MGT-010 and PAN-CRT-006. One row per appliance.

THREE FIELDS ARE READ THROUGH A JOIN - `min_version`, `max_version`, `certificate_name` live on
the `SslTlsServiceProfile` row the binding points at, not on the binding. That is the fix for the
drift the aggregate suffered, and it puts one trap in this file: `is_empty` over a joined field.

An UNRESOLVED binding - a name that matches no row - has a null key, and a plain
`ssl_tls_service_profile__min_version=""` does not match a null join. PAN-MGT-010's fourth clause
is exactly "a profile is bound and its floor is empty", and it exists to catch dangling bindings,
so a naive lookup would silently stop reporting the case it was written for. `is_empty` on a
joined field therefore means "no row, or a row whose value is empty".
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import ManagementTlsBinding

MANAGEMENT_TLS_MODEL = "integrations.ManagementTlsBinding"

#: The key a joined field is read through. Empty for a field stored on the binding itself.
_JOIN = "ssl_tls_service_profile"


def build_text_compiler(field_name, lookup_field, *, joined=False):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            predicate = Q(**{lookup_field: ""})
            if joined:
                # No row at all is empty too - see the module docstring.
                predicate |= Q(**{f"{_JOIN}__isnull": True})
            return ManagementTlsBinding.objects.filter(predicate).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return ManagementTlsBinding.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "profile_name": build_text_compiler("profile_name", "profile_name"),
    "profile_scope": build_text_compiler("profile_scope", "profile_scope"),
    "certificate_trust": build_text_compiler("certificate_trust", "certificate_trust"),
    "certificate_scope": build_text_compiler("certificate_scope", "certificate_scope"),
    "certificate_issuer": build_text_compiler("certificate_issuer", "certificate_issuer"),
    "min_version": build_text_compiler(
        "min_version", f"{_JOIN}__min_version", joined=True),
    "max_version": build_text_compiler(
        "max_version", f"{_JOIN}__max_version", joined=True),
    "certificate_name": build_text_compiler(
        "certificate_name", f"{_JOIN}__certificate_name", joined=True),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_management_tls_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_management_tls_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause.get("negated") else predicate
