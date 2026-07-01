"""Shared compiler helpers for scalar text security-rule fields."""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from optivedge.integrations.models import SecurityRule


SUPPORTED_OPERATORS = {"eq", "contains"}


def compile_scalar_text_clause(clause, *, field_name, lookup_field):
    op = clause["op"]
    value = clause["value"]
    case_sensitive = clause["case_sensitive"]

    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if not isinstance(value, str):
        raise SearchSyntaxError(f"{field_name} search value must be a string.")

    trimmed_value = value.strip()
    if not trimmed_value:
        raise SearchSyntaxError(f"{field_name} search value must not be empty.")

    base_query = SecurityRule.objects.all()
    if op == "eq":
        lookup = f"{lookup_field}__exact" if case_sensitive else f"{lookup_field}__iexact"
        return base_query.filter(**{lookup: trimmed_value}).values("pk")

    lookup = f"{lookup_field}__contains" if case_sensitive else f"{lookup_field}__icontains"
    return base_query.filter(**{lookup: trimmed_value}).values("pk")
