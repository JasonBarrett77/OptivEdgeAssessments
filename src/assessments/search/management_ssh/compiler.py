"""Canonical search compiler for the management SSH server. PAN-MCR-001 to 005.

One row per appliance: what its management SSH server OFFERS - the bound profile's lists where
it sets them, the device's measured default offer where it does not. The algorithm lists are
display; a control reads the flags the normalizer derived from them, because a finding rests on
a column.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import ManagementSshSettings

MANAGEMENT_SSH_MODEL = "integrations.ManagementSshSettings"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return ManagementSshSettings.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return ManagementSshSettings.objects.filter(
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
        return ManagementSshSettings.objects.filter(**{lookup_field: value}).values("pk")
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
        return ManagementSshSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "profile_name": build_text_compiler("profile_name", "profile_name"),
    "host_key_type": build_text_compiler("host_key_type", "host_key_type"),
    "profile_found": build_boolean_compiler("profile_found", "profile_found"),
    "offers_cbc_cipher": build_boolean_compiler("offers_cbc_cipher", "offers_cbc_cipher"),
    "offers_weak_mac": build_boolean_compiler("offers_weak_mac", "offers_weak_mac"),
    "offers_sha1_kex": build_boolean_compiler("offers_sha1_kex", "offers_sha1_kex"),
    "offers_weak_kex": build_boolean_compiler("offers_weak_kex", "offers_weak_kex"),
    "offers_sha2_256_mac": build_boolean_compiler("offers_sha2_256_mac", "offers_sha2_256_mac"),
    "ciphers_below_preferred": build_boolean_compiler(
        "ciphers_below_preferred", "ciphers_below_preferred"),
    "kex_below_preferred": build_boolean_compiler("kex_below_preferred", "kex_below_preferred"),
    "macs_below_preferred": build_boolean_compiler("macs_below_preferred", "macs_below_preferred"),
    "ciphers_default": build_boolean_compiler("ciphers_default", "ciphers_default"),
    "kex_default": build_boolean_compiler("kex_default", "kex_default"),
    "macs_default": build_boolean_compiler("macs_default", "macs_default"),
    "defaults_measured": build_boolean_compiler("defaults_measured", "defaults_measured"),
    "host_key_bits": build_integer_compiler("host_key_bits", "host_key_bits"),
    "rekey_interval_seconds": build_integer_compiler(
        "rekey_interval_seconds", "rekey_interval_seconds"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_management_ssh_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_management_ssh_search_node(c) for c in group["clauses"]]
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
