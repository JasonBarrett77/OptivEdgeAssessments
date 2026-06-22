"""Shared control-query evaluation helpers."""

from __future__ import annotations

from assessments.models import Control
from assessments.search.compiler import apply_search_node
from assessments.search.exceptions import SearchSyntaxError


SECURITY_RULE_QUERY_MODEL = "integrations.SecurityRule"
MANAGEMENT_PLANE_MODEL = "integrations.ManagementPlaneProfile"


SEVERITY_LABELS = dict(Control.Severity.choices)
SEVERITY_RANK = {
    Control.Severity.INFORMATIONAL: 0,
    Control.Severity.LOW: 1,
    Control.Severity.MEDIUM: 2,
    Control.Severity.HIGH: 3,
    Control.Severity.CRITICAL: 4,
}


def default_security_rule_search_query():
    return {"model": SECURITY_RULE_QUERY_MODEL, "operator": "and", "clauses": []}


def default_management_plane_search_query():
    return {"model": MANAGEMENT_PLANE_MODEL, "operator": "and", "clauses": []}


def severity_label(severity_value: str) -> str:
    return SEVERITY_LABELS.get(severity_value, severity_value)


def derive_control_query_severity_value(control, matched_queries):
    calibration_queries = [
        query
        for query in matched_queries
        if not query.is_baseline and query.adjusted_severity
    ]
    if not calibration_queries:
        return control.default_severity
    winning_query = max(
        calibration_queries,
        key=lambda query: SEVERITY_RANK[query.adjusted_severity],
    )
    return winning_query.adjusted_severity


def evaluate_queryset_control_queries(queryset, control, *, model_name):
    active_queries = list(control.queries.filter(is_active=True).order_by("-is_baseline", "name", "pk"))
    matched_by_object = {}
    skipped_queries = 0

    for control_query in active_queries:
        canonical_query = control_query.canonical_query
        if not isinstance(canonical_query, dict):
            skipped_queries += 1
            continue
        if canonical_query.get("model") != model_name:
            skipped_queries += 1
            continue
        try:
            matched_object_ids = apply_search_node(queryset, canonical_query).values_list("pk", flat=True)
            for object_id in matched_object_ids:
                matched_by_object.setdefault(object_id, []).append(control_query)
        except SearchSyntaxError:
            skipped_queries += 1

    if not matched_by_object:
        return queryset.none(), active_queries, skipped_queries, {}, {}

    severity_by_object_id = {
        object_id: derive_control_query_severity_value(control, matched_queries)
        for object_id, matched_queries in matched_by_object.items()
    }
    return (
        queryset.filter(pk__in=matched_by_object.keys()),
        active_queries,
        skipped_queries,
        matched_by_object,
        severity_by_object_id,
    )


def evaluate_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SECURITY_RULE_QUERY_MODEL,
    )


def evaluate_management_plane_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or MANAGEMENT_PLANE_MODEL,
    )
