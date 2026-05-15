"""Shared compiler helpers for repeated security-rule value fields."""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError


SUPPORTED_OPERATORS = {"eq", "contains"}


def compile_repeated_value_clause(
    clause,
    *,
    model_class,
    field_name,
    value_field_name="value",
    security_rule_field_name="security_rule_id",
):
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

    base_query = model_class.objects.all()
    if op == "eq":
        lookup = f"{value_field_name}__exact" if case_sensitive else f"{value_field_name}__iexact"
        return base_query.filter(**{lookup: trimmed_value}).values(security_rule_field_name)

    lookup = f"{value_field_name}__contains" if case_sensitive else f"{value_field_name}__icontains"
    return base_query.filter(**{lookup: trimmed_value}).values(security_rule_field_name)
