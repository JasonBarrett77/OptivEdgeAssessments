"""Canonical search compiler for certificates.

The searchable unit is the certificate ON ONE APPLIANCE IN ONE SCOPE. Predefined certificates
are included deliberately: they are read-only, so a finding against one cannot be remediated on
the device - but hiding them would mean the tool silently ignores the certificate the vendor's
own hardened profile presents.

`key_size_bits` is exposed but must never be the whole story. The corpus asks for "RSA 2048 or
ECDSA P-256 minimum", which is two thresholds, and the estate proves why: the predefined
TLSv1.3_Default is EC 256-bit, so `key_size_bits < 2048` would flag the strongest certificate
in the lab. Pair it with `key_algorithm` in an AND group.

`key_algorithm` carries the curve name for EC - "EC (secp256r1)" - so `contains` is the
operator to use rather than `eq`.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import Certificate

CERTIFICATE_MODEL = "integrations.Certificate"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return Certificate.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return Certificate.objects.filter(
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
        return Certificate.objects.filter(**{lookup_field: value}).values("pk")
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
        # A NULL key size means the certificate could not be decoded. It must not satisfy a
        # `lt` comparison by accident - SQL drops NULLs from both sides of an inequality, so
        # excluding them here is explicit rather than incidental.
        return Certificate.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).exclude(
            **{f"{lookup_field}__isnull": True}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "name": build_text_compiler("name", "name"),
    "scope": build_text_compiler("scope", "scope"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "common_name": build_text_compiler("common_name", "common_name"),
    "issuer": build_text_compiler("issuer", "issuer"),
    "key_algorithm": build_text_compiler("key_algorithm", "key_algorithm"),
    "key_size_bits": build_integer_compiler("key_size_bits", "key_size_bits"),
    "signature_algorithm": build_text_compiler("signature_algorithm", "signature_algorithm"),
    "parse_error": build_text_compiler("parse_error", "parse_error"),
    "is_ca": build_boolean_compiler("is_ca", "is_ca"),
    "is_self_signed": build_boolean_compiler("is_self_signed", "is_self_signed"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_certificate_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_certificate_search_node(c) for c in group["clauses"]]
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
