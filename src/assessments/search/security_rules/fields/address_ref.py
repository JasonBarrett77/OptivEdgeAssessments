"""Compiler helpers for security-rule address-ref fields."""

from __future__ import annotations

from django.db.models import Q

from assessments.search.exceptions import SearchSyntaxError


SUPPORTED_OPERATORS = {"eq", "contains"}


def compile_address_ref_clause(
    clause,
    *,
    model_class,
    field_name,
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

    if op == "eq":
        suffix = "exact" if case_sensitive else "iexact"
    else:
        suffix = "contains" if case_sensitive else "icontains"

    predicate = (
        Q(**{f"raw_value__{suffix}": trimmed_value})
        | Q(**{f"address_object__name__{suffix}": trimmed_value})
        | Q(**{f"address_group__name__{suffix}": trimmed_value})
    )
    return model_class.objects.filter(predicate).values(security_rule_field_name)
