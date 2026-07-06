"""Compiler for the `provenance` security-rule search field."""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import SecurityRule


SUPPORTED_OPERATORS = {"eq", "contains"}


def compile_provenance_clause(clause):
    op = clause["op"]
    value = clause["value"]
    case_sensitive = clause["case_sensitive"]

    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for provenance: {op}.")
    if not isinstance(value, str):
        raise SearchSyntaxError("provenance search value must be a string.")

    trimmed_value = value.strip()
    if not trimmed_value:
        raise SearchSyntaxError("provenance search value must not be empty.")

    base_query = SecurityRule.objects.filter(
        field_provenance__field_name="__entry__",
    )
    if op == "eq":
        lookup = "field_provenance__raw_value__exact" if case_sensitive else "field_provenance__raw_value__iexact"
    else:
        lookup = "field_provenance__raw_value__contains" if case_sensitive else "field_provenance__raw_value__icontains"

    return base_query.filter(**{lookup: trimmed_value}).values("pk")


compile_provenance_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
