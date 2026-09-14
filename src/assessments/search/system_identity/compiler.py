"""Canonical search compiler for system identity. PAN-SVC-007 and 009.

One row per appliance: how the device names itself, keeps time, and gets its management address.

`hostname` means the APPLIANCE's hostname here, exactly as it does on every other search
surface, and the device's own configured value is `configured_hostname`. They are usually the
same string and the case where they differ is the one that matters - a device whose
`deviceconfig/system/hostname` is still the factory default is discovered by whichever name the
collector recorded, so overloading the field would make the interesting rows unfindable.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import SystemIdentity

SYSTEM_IDENTITY_MODEL = "integrations.SystemIdentity"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return SystemIdentity.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return SystemIdentity.objects.filter(
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
        return SystemIdentity.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "configured_hostname": build_text_compiler("configured_hostname", "hostname"),
    "timezone": build_text_compiler("timezone", "timezone"),
    "addressing_mode": build_text_compiler("addressing_mode", "addressing_mode"),
    "hostname_is_factory_default": build_boolean_compiler(
        "hostname_is_factory_default", "hostname_is_factory_default"),
    "timezone_is_utc": build_boolean_compiler("timezone_is_utc", "timezone_is_utc"),
    "addressing_mode_explicit": build_boolean_compiler(
        "addressing_mode_explicit", "addressing_mode_explicit"),
    "accept_dhcp_hostname": build_boolean_compiler(
        "accept_dhcp_hostname", "accept_dhcp_hostname"),
    "accept_dhcp_domain": build_boolean_compiler("accept_dhcp_domain", "accept_dhcp_domain"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_system_identity_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_system_identity_search_node(c) for c in group["clauses"]]
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
