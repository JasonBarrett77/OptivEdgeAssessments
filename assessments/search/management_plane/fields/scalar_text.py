"""Shared compiler helpers for scalar text management-plane fields."""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from optivedge.integrations.models import ManagementPlaneProfile


SUPPORTED_OPERATORS = {"eq", "contains", "is_empty"}


def compile_scalar_text_clause(clause, *, field_name, lookup_field):
    op = clause["op"]
    value = clause["value"]
    case_sensitive = clause["case_sensitive"]

    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")

    if op == "is_empty":
        if not isinstance(value, str):
            raise SearchSyntaxError(f"{field_name} search value must be an empty string for is_empty.")
        if value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string value.")
        if case_sensitive:
            raise SearchSyntaxError(f"{field_name} does not support case-sensitive matching for is_empty.")
        return ManagementPlaneProfile.objects.filter(**{lookup_field: ""}).values("pk")

    if not isinstance(value, str):
        raise SearchSyntaxError(f"{field_name} search value must be a string.")

    trimmed_value = value.strip()
    if not trimmed_value:
        raise SearchSyntaxError(f"{field_name} search value must not be empty.")

    base_query = ManagementPlaneProfile.objects.all()
    if op == "eq":
        lookup = f"{lookup_field}__exact" if case_sensitive else f"{lookup_field}__iexact"
        return base_query.filter(**{lookup: trimmed_value}).values("pk")

    lookup = f"{lookup_field}__contains" if case_sensitive else f"{lookup_field}__icontains"
    return base_query.filter(**{lookup: trimmed_value}).values("pk")
