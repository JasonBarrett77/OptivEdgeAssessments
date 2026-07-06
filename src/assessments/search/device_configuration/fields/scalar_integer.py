"""Shared compiler helpers for scalar integer device configuration fields."""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import DeviceConfigurationProfile


SUPPORTED_OPERATORS = {"eq", "lt", "lte", "gt", "gte"}


def parse_integer_value(value, *, field_name):
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        raise SearchSyntaxError(f"{field_name} search value must be an integer or integer-like string.")
    trimmed = value.strip()
    if not trimmed:
        raise SearchSyntaxError(f"{field_name} search value must not be empty.")
    try:
        return int(trimmed)
    except ValueError as exc:
        raise SearchSyntaxError(f"{field_name} search value must be an integer.") from exc


def compile_scalar_integer_clause(clause, *, field_name, lookup_field):
    op = clause["op"]
    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if clause["case_sensitive"]:
        raise SearchSyntaxError(f"{field_name} does not support case-sensitive matching.")

    parsed_value = parse_integer_value(clause["value"], field_name=field_name)
    lookup_suffix = {
        "eq": "",
        "lt": "__lt",
        "lte": "__lte",
        "gt": "__gt",
        "gte": "__gte",
    }[op]
    lookup = f"{lookup_field}{lookup_suffix}"
    return DeviceConfigurationProfile.objects.filter(**{lookup: parsed_value}).values("pk")
