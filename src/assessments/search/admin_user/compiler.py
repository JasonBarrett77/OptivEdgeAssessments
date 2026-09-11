"""Canonical search compiler for administrator accounts.

`superuser_cohort_size` is an appliance TOTAL stored on every row, the same trick
`PasswordProfile.global_expiration_period` uses and for the same reason: the search layer
compares a field to a LITERAL, and PAN-AUTH-022 asserts something about a count. It is 0 on any
account that is not a superuser, so every query on the control - the baseline and the two
severity queries beside it - reads this one field and a threshold is the only number in play.
A second clause narrowing to superusers would put a second number in every one of them.

`admin_mfa_enabled` is resolved in the normalizer too, THROUGH the binding rather than stored on
the profile: PAN-AUTH-020's finding is about a person, and two administrators on one appliance
can sit behind different profiles. A query over AuthenticationProfile cannot say which people
are exposed, which is the whole reason the control moved off that model.

`centrally_authenticated` is likewise computed in the normalizer. It reads three payload keys -
`phash`, `public-key`, `authentication-profile` - AND the METHOD of the profile that reference
resolves to, which lives on another model entirely. The search layer compares a field to a
literal and cannot follow that edge, and no clause combination over separate columns could
express it either.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import AdminUser

ADMIN_USER_MODEL = "integrations.AdminUser"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return AdminUser.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return AdminUser.objects.filter(
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
        return AdminUser.objects.filter(**{lookup_field: value}).values("pk")
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
        return AdminUser.objects.filter(**{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "name": build_text_compiler("name", "name"),
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "role_type": build_text_compiler("role_type", "role_type"),
    "custom_role_profile": build_text_compiler("custom_role_profile", "custom_role_profile"),
    "authentication_profile_name": build_text_compiler(
        "authentication_profile_name", "authentication_profile_name"),
    "effective_authentication_profile": build_text_compiler(
        "effective_authentication_profile", "effective_authentication_profile"),
    "authentication_binding": build_text_compiler(
        "authentication_binding", "authentication_binding"),
    "password_profile_name": build_text_compiler(
        "password_profile_name", "password_profile_name"),
    "is_superuser": build_boolean_compiler("is_superuser", "is_superuser"),
    "client_certificate_only": build_boolean_compiler(
        "client_certificate_only", "client_certificate_only"),
    "has_password": build_boolean_compiler("has_password", "has_password"),
    "has_public_key": build_boolean_compiler("has_public_key", "has_public_key"),
    "authentication_is_external": build_boolean_compiler(
        "authentication_is_external", "authentication_is_external"),
    "centrally_authenticated": build_boolean_compiler(
        "centrally_authenticated", "centrally_authenticated"),
    "admin_mfa_enabled": build_boolean_compiler("admin_mfa_enabled", "admin_mfa_enabled"),
    "authentication_profile_unresolved": build_boolean_compiler(
        "authentication_profile_unresolved", "authentication_profile_unresolved"),
    "superuser_cohort_size": build_integer_compiler(
        "superuser_cohort_size", "superuser_cohort_size"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_admin_user_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_admin_user_search_node(c) for c in group["clauses"]]
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
