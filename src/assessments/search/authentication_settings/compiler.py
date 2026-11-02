"""Canonical search compiler for the device-wide administrator authentication settings.

One row per appliance. PAN-AUTH-014 to 017's subject.

FOUR INTEGER FIELDS AND NO TWO ZEROS MEAN THE SAME THING, which is why there are no derived
booleans here and no "is strict" convenience field: 0 is unlimited attempts on
`lockout_failed_attempts`, locked-until-released on `lockout_time_minutes`, a key that never
expires on `api_key_lifetime_minutes`, and no timeout on `idle_timeout_minutes`. A query says
which field it means, and the direction lives in the control rather than in a column name.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import AuthenticationSettings

AUTHENTICATION_SETTINGS_MODEL = "integrations.AuthenticationSettings"

INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return AuthenticationSettings.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return AuthenticationSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    """Added 2026-11-01 for PAN-AUTH-015's companion. This package had NO boolean builder.

    `search/management_interface/compiler.py` was in the same state until 2026-11-01, so a
    boolean column needs this added beside the text one rather than reused - there was nothing
    here to reuse. The body is the four lines every other package's boolean builder carries.

    `lockout_time_minutes_unknown` is `null=False, default=True`, so `filter(field=value)`
    reaches every row and no `__isnull`-OR branch is wanted: the shape two compilers carry for a
    NULLABLE column has no null to find here. The NULLABLE column is
    `lockout_time_minutes` BESIDE it, which is exactly why the companion exists.
    """
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return AuthenticationSettings.objects.filter(**{lookup_field: value}).values("pk")
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
        return AuthenticationSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


_INTEGER_FIELDS = (
    "idle_timeout_minutes", "lockout_failed_attempts", "lockout_time_minutes",
    "api_key_lifetime_minutes",
)

#: `lockout_time_minutes_unknown` is PAN-AUTH-015's companion. Its sibling columns need none:
#: `lockout_failed_attempts`, `idle_timeout_minutes` and `api_key_lifetime_minutes` are all
#: `null=False` with a materialised default, so their own clause reaches the unread appliance.
#: `lockout_time_minutes` is the one `null=True` column of the four, and the vendor contradicts
#: itself about which end of its scale 0 sits at - so no stored sentinel can both fire on the
#: unknown and leave a real 0 alone, and the companion is the only honest answer.
_BOOLEAN_FIELDS = ("lockout_time_minutes_unknown",)

FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    **{name: build_boolean_compiler(name, name) for name in _BOOLEAN_FIELDS},
    **{name: build_integer_compiler(name, name) for name in _INTEGER_FIELDS},
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_authentication_settings_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_authentication_settings_search_node(c) for c in group["clauses"]]
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
