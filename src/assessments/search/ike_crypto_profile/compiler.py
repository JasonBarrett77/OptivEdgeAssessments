"""Canonical search compiler for one named IKE crypto profile. PAN-IKE-002 to 005.

One row per named entry per appliance, device-wide: stage 4 of the `ike-crypto` pipeline domain
asked ten candidate paths on two platforms and two vsys postures and found exactly one
firewall-local scope, so there is no vsys axis and no shared-versus-vsys precedence.

THE THREE ALGORITHM LISTS ARE DELIBERATELY NOT REACHABLE FROM HERE. `dh_groups`,
`encryption_ciphers` and `hash_algorithms` are JSONFields, stage 5 marks them `not_searchable`,
and `test_findings_rest_on_columns` enforces the rule exhaustively. What a control reads is the
`weakest_*` member beside each list and the `*_floor_met` verdict over the whole set - which is
also the right reading rather than a workaround: the profile OFFERS every member and takes the
first a peer accepts, so what matters is the weakest member an exchange can be driven down to.

TWO INTEGER COLUMNS ARE NULLABLE AND NO OPERATOR HERE REACHES A NULL. `key_lifetime_hours` and
`authentication_multiple` are null where nothing was read, and SQL answers every positive
comparison over a null with no match - so a profile nobody collected PASSES any threshold
written over it. That is why `key_lifetime_known` and `authentication_multiple_known` exist and
are registered: a control over the value clauses on the companion, never on the value alone.
There is no is-null operator in this query language and this module does not invent one.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import IkeCryptoProfile

IKE_CRYPTO_PROFILE_MODEL = "integrations.IkeCryptoProfile"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return IkeCryptoProfile.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return IkeCryptoProfile.objects.filter(
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
        return IkeCryptoProfile.objects.filter(**{lookup_field: value}).values("pk")
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
        return IkeCryptoProfile.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "entry_name": build_text_compiler("entry_name", "entry_name"),
    "scope": build_text_compiler("scope", "scope"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    # The graded columns. A severity query compares on these; an assertion never does.
    "weakest_dh_group": build_text_compiler("weakest_dh_group", "weakest_dh_group"),
    "weakest_encryption_cipher": build_text_compiler(
        "weakest_encryption_cipher", "weakest_encryption_cipher"),
    "weakest_hash_algorithm": build_text_compiler(
        "weakest_hash_algorithm", "weakest_hash_algorithm"),
    "key_lifetime_unit": build_text_compiler("key_lifetime_unit", "key_lifetime_unit"),
    # The verdict columns. Each one's false is the finding side AND the migration default, so a
    # profile nobody has recomputed is reported rather than passing.
    "dh_group_floor_met": build_boolean_compiler("dh_group_floor_met", "dh_group_floor_met"),
    "encryption_floor_met": build_boolean_compiler(
        "encryption_floor_met", "encryption_floor_met"),
    "offers_aead_cipher": build_boolean_compiler("offers_aead_cipher", "offers_aead_cipher"),
    "hash_floor_met": build_boolean_compiler("hash_floor_met", "hash_floor_met"),
    "key_lifetime_known": build_boolean_compiler("key_lifetime_known", "key_lifetime_known"),
    "authentication_multiple_known": build_boolean_compiler(
        "authentication_multiple_known", "authentication_multiple_known"),
    "reauth_interval_bounded": build_boolean_compiler(
        "reauth_interval_bounded", "reauth_interval_bounded"),
    "used_by_ikev2_gateway": build_boolean_compiler(
        "used_by_ikev2_gateway", "used_by_ikev2_gateway"),
    "referenced_by_gateway_on_this_appliance": build_boolean_compiler(
        "referenced_by_gateway_on_this_appliance",
        "referenced_by_gateway_on_this_appliance"),
    # Nullable integers. Clause on the `*_known` companion beside any threshold written here.
    "key_lifetime_hours": build_integer_compiler("key_lifetime_hours", "key_lifetime_hours"),
    "authentication_multiple": build_integer_compiler(
        "authentication_multiple", "authentication_multiple"),
    "reauth_interval_hours": build_integer_compiler(
        "reauth_interval_hours", "reauth_interval_hours"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_ike_crypto_profile_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_ike_crypto_profile_search_node(c) for c in group["clauses"]]
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
