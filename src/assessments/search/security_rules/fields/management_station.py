"""Compiler for the `management_station` security-rule search field."""

from __future__ import annotations

from django.db.models import Q

from assessments.search.exceptions import SearchSyntaxError
from optivedge.integrations.models import SecurityRule


SUPPORTED_OPERATORS = {"eq", "contains"}


def compile_management_station_clause(clause):
    op = clause["op"]
    value = clause["value"]
    case_sensitive = clause["case_sensitive"]

    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for management_station: {op}.")
    if not isinstance(value, str):
        raise SearchSyntaxError("management_station search value must be a string.")

    trimmed_value = value.strip()
    if not trimmed_value:
        raise SearchSyntaxError("management_station search value must not be empty.")

    if op == "eq":
        if case_sensitive:
            predicate = Q(management_station__name__exact=trimmed_value) | Q(
                management_station__hostname__exact=trimmed_value
            )
        else:
            predicate = Q(management_station__name__iexact=trimmed_value) | Q(
                management_station__hostname__iexact=trimmed_value
            )
        return SecurityRule.objects.filter(predicate).values("pk")

    if case_sensitive:
        predicate = Q(management_station__name__contains=trimmed_value) | Q(
            management_station__hostname__contains=trimmed_value
        )
    else:
        predicate = Q(management_station__name__icontains=trimmed_value) | Q(
            management_station__hostname__icontains=trimmed_value
        )
    return SecurityRule.objects.filter(predicate).values("pk")


compile_management_station_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
