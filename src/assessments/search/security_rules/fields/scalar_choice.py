"""Shared compiler helpers for scalar choice security-rule fields."""

from __future__ import annotations

from django.db.models import Q

from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import SecurityRule


SUPPORTED_OPERATORS = {"eq", "contains"}


def _normalized_choice_pairs(choice_map):
    return [
        (stored_value, str(label))
        for stored_value, label in choice_map
    ]


def compile_scalar_choice_clause(clause, *, field_name, lookup_field, choice_map):
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

    normalized_choices = _normalized_choice_pairs(choice_map)

    if op == "eq":
        matches = []
        for stored_value, label in normalized_choices:
            if case_sensitive:
                if trimmed_value == stored_value or trimmed_value == label:
                    matches.append(stored_value)
            else:
                normalized_value = trimmed_value.lower()
                if normalized_value == stored_value.lower() or normalized_value == label.lower():
                    matches.append(stored_value)
        if not matches:
            return SecurityRule.objects.none().values("pk")
        return SecurityRule.objects.filter(**{f"{lookup_field}__in": matches}).values("pk")

    predicate = Q()
    for stored_value, label in normalized_choices:
        haystacks = [stored_value, label]
        if case_sensitive:
            if any(trimmed_value in haystack for haystack in haystacks):
                predicate |= Q(**{lookup_field: stored_value})
        else:
            normalized_value = trimmed_value.lower()
            if any(normalized_value in haystack.lower() for haystack in haystacks):
                predicate |= Q(**{lookup_field: stored_value})
    if not predicate:
        return SecurityRule.objects.none().values("pk")
    return SecurityRule.objects.filter(predicate).values("pk")
