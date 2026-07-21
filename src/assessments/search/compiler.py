"""Top-level canonical search compiler and model dispatch."""

from __future__ import annotations

import json

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.registry import get_model_entry, get_model_label
from assessments.search.syntax import validate_search_payload


def parse_search_payload(search_payload):
    if not search_payload:
        return None
    try:
        raw_node = json.loads(search_payload)
    except json.JSONDecodeError as exc:
        raise SearchSyntaxError("Search payload must be valid JSON.") from exc
    return validate_search_payload(raw_node)


def apply_search(queryset, search_payload):
    search_node = parse_search_payload(search_payload)
    if search_node is None:
        return queryset, None
    return apply_search_node(queryset, search_node), search_node


def compile_predicate(queryset_model, search_node):
    """Compile a canonical search node into a Q-like predicate for queryset_model,
    without applying it. Shared by apply_search_node (single filter) and
    evaluate_queryset_control_queries (union query + narrowed per-query attribution)."""
    validated_node = validate_search_payload(search_node)
    model_entry = get_model_entry(validated_node["model"])
    queryset_model_label = get_model_label(queryset_model)
    if queryset_model_label != validated_node["model"]:
        raise SearchSyntaxError(
            f"Search model '{validated_node['model']}' does not match queryset model '{queryset_model_label}'."
        )
    return model_entry["compiler"](validated_node)


def apply_search_node(queryset, search_node):
    if search_node is None:
        return queryset
    predicate = compile_predicate(queryset.model, search_node)
    return queryset.filter(predicate)
