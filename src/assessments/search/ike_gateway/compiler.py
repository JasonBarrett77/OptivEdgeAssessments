"""Canonical search compiler for one named IKE gateway. PAN-IKE-001, 006 to 009.

One row per named entry per appliance, device-wide like the sibling object.

THE NEGATION IS A CLAUSE FLAG AND NOT AN OPERATOR, and three of this domain's assertions need
it. `ike_version`, `ikev1_exchange_mode` and `peer_authentication` are all columns where TWO of
the members fire and one passes, so the clause is written as a negated equality against the
passing member rather than as a disjunction - the query language has no `in` operator and a
clause has one field slot. `compile_search_clause` applies `negated` by inverting the predicate.

THAT POLARITY IS WHY ALL THREE COLUMNS ARE NON-NULLABLE TEXT DEFAULTING TO THE EMPTY STRING,
which the model declares and this module depends on. An unread or absent key holds "", so
NOT(column = 'ikev2') is TRUE and the gateway is REPORTED. A nullable spelling would make SQL
answer NOT(NULL = x) with NULL and silently drop every gateway nobody read, inverting every
clause written here.

THE TWO DEAD-PEER-DETECTION SWITCHES ARE THE OPPOSITE CASE: they are nullable booleans, and
`= false` over a NULL matches nothing, so a gateway nobody read would PASS a test it was never
subjected to. `ikev1_dpd_enabled_known` and `ikev2_dpd_enabled_known` are the companions a
control clauses on, and they are registered here for that reason.

`disabled` IS REGISTERED AND NOTHING SHOULD CLAUSE ON IT. It is the device's own key in the
device's own polarity - `yes` means the gateway is OFF - and it is nullable, so an applicability
clause over it drops the unread rows and suppresses the control. `gateway_is_active` is the
column every assertion in this domain uses instead. The raw key is reachable so an operator can
search for it; the asymmetry is deliberate and is the reason this paragraph exists.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import IkeGateway

IKE_GATEWAY_MODEL = "integrations.IkeGateway"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return IkeGateway.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return IkeGateway.objects.filter(
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
        return IkeGateway.objects.filter(**{lookup_field: value}).values("pk")
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
        return IkeGateway.objects.filter(**{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "entry_name": build_text_compiler("entry_name", "entry_name"),
    "scope": build_text_compiler("scope", "scope"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    "ike_version": build_text_compiler("ike_version", "ike_version"),
    "ikev1_exchange_mode": build_text_compiler(
        "ikev1_exchange_mode", "ikev1_exchange_mode"),
    "peer_authentication": build_text_compiler(
        "peer_authentication", "peer_authentication"),
    "certificate_profile_name": build_text_compiler(
        "certificate_profile_name", "certificate_profile_name"),
    "ikev1_crypto_profile_name": build_text_compiler(
        "ikev1_crypto_profile_name", "ikev1_crypto_profile_name"),
    "ikev2_crypto_profile_name": build_text_compiler(
        "ikev2_crypto_profile_name", "ikev2_crypto_profile_name"),
    # See the module docstring: reachable, and not what an assertion clauses on.
    "disabled": build_boolean_compiler("disabled", "disabled"),
    "gateway_is_active": build_boolean_compiler("gateway_is_active", "gateway_is_active"),
    "local_certificate_named": build_boolean_compiler(
        "local_certificate_named", "local_certificate_named"),
    "uses_pre_shared_key": build_boolean_compiler(
        "uses_pre_shared_key", "uses_pre_shared_key"),
    "ikev1_dpd_enabled": build_boolean_compiler("ikev1_dpd_enabled", "ikev1_dpd_enabled"),
    "ikev1_dpd_enabled_known": build_boolean_compiler(
        "ikev1_dpd_enabled_known", "ikev1_dpd_enabled_known"),
    "ikev2_dpd_enabled": build_boolean_compiler("ikev2_dpd_enabled", "ikev2_dpd_enabled"),
    "ikev2_dpd_enabled_known": build_boolean_compiler(
        "ikev2_dpd_enabled_known", "ikev2_dpd_enabled_known"),
    "relies_on_factory_named_proposal": build_boolean_compiler(
        "relies_on_factory_named_proposal", "relies_on_factory_named_proposal"),
    "ikev2_dpd_interval": build_integer_compiler(
        "ikev2_dpd_interval", "ikev2_dpd_interval"),
    "ikev1_dpd_retry": build_integer_compiler("ikev1_dpd_retry", "ikev1_dpd_retry"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_ike_gateway_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_ike_gateway_search_node(c) for c in group["clauses"]]
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
