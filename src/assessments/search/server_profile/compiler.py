"""Canonical search compiler for AAA server profiles.

EVERY CONTROL ON THIS MODEL MUST CLAUSE ON `kind`. Six kinds share one table, so a column that
only means something for one of them still holds its default on the other five - and the
defaults were measured, not chosen. `ldap_verify_server_certificate` is implicit FALSE, so a
control querying it without `kind eq ldap` fires on every RADIUS, TACACS+, Kerberos, SAML and
MFA profile in the estate.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import ServerProfile

SERVER_PROFILE_MODEL = "integrations.ServerProfile"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return ServerProfile.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return ServerProfile.objects.filter(
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
        return ServerProfile.objects.filter(**{lookup_field: value}).values("pk")
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
        return ServerProfile.objects.filter(**{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "name": build_text_compiler("name", "name"),
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "scope": build_text_compiler("scope", "scope"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    "kind": build_text_compiler("kind", "kind"),
    "protocol": build_text_compiler("protocol", "protocol"),
    "ldap_bind_dn": build_text_compiler("ldap_bind_dn", "ldap_bind_dn"),
    "ldap_type": build_text_compiler("ldap_type", "ldap_type"),
    "mfa_vendor_type": build_text_compiler("mfa_vendor_type", "mfa_vendor_type"),
    "certificate_reference": build_text_compiler(
        "certificate_reference", "certificate_reference"),
    "admin_use_only": build_boolean_compiler("admin_use_only", "admin_use_only"),
    "ldap_ssl": build_boolean_compiler("ldap_ssl", "ldap_ssl"),
    "ldap_verify_server_certificate": build_boolean_compiler(
        "ldap_verify_server_certificate", "ldap_verify_server_certificate"),
    "saml_validate_idp_certificate": build_boolean_compiler(
        "saml_validate_idp_certificate", "saml_validate_idp_certificate"),
    "saml_want_auth_requests_signed": build_boolean_compiler(
        "saml_want_auth_requests_signed", "saml_want_auth_requests_signed"),
    "server_count": build_integer_compiler("server_count", "server_count"),
    "referrer_count": build_integer_compiler("referrer_count", "referrer_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_server_profile_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_server_profile_search_node(c) for c in group["clauses"]]
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
