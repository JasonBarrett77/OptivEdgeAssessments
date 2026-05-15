"""Shared compiler helpers for scalar boolean management-plane fields."""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from optivedge.integrations.models import ManagementPlaneProfile


SUPPORTED_OPERATORS = {"eq"}
TRUE_VALUES = {"true", "yes", "on", "1"}
FALSE_VALUES = {"false", "no", "off", "0"}


def parse_boolean_value(value, *, field_name):
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        raise SearchSyntaxError(f"{field_name} search value must be a boolean or boolean-like string.")

    normalized = value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise SearchSyntaxError(f"{field_name} search value must be true/false, yes/no, on/off, or 1/0.")


def compile_scalar_boolean_clause(clause, *, field_name, lookup_field):
    op = clause["op"]
    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if clause["case_sensitive"]:
        raise SearchSyntaxError(f"{field_name} does not support case-sensitive matching.")

    parsed_value = parse_boolean_value(clause["value"], field_name=field_name)
    return ManagementPlaneProfile.objects.filter(**{lookup_field: parsed_value}).values("pk")
