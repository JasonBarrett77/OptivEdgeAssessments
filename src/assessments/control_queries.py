"""Shared control-query evaluation helpers."""

from __future__ import annotations

from assessments.models import Control
from assessments.search.compiler import compile_predicate
from assessments.search.exceptions import SearchSyntaxError


SECURITY_RULE_QUERY_MODEL = "integrations.SecurityRule"
DEVICE_CONFIGURATION_MODEL = "integrations.DeviceConfigurationProfile"
MANAGEMENT_INTERFACE_MODEL = "integrations.ManagementInterface"


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


def default_device_configuration_search_query():
    return {"model": DEVICE_CONFIGURATION_MODEL, "operator": "and", "clauses": []}


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
    """Match `queryset` against every active ControlQuery on `control`.

    Runs one broad union query to find every matching object, then attributes matches
    to individual queries (needed for severity ranking) only against that narrowed
    subset - instead of running each active query as its own full-table query.
    """
    active_queries = list(control.queries.filter(is_active=True).order_by("-is_baseline", "name", "pk"))
    predicates_by_query = []
    combined_predicate = None
    skipped_queries = 0

    for control_query in active_queries:
        canonical_query = control_query.canonical_query
        if not isinstance(canonical_query, dict) or canonical_query.get("model") != model_name:
            skipped_queries += 1
            continue
        try:
            predicate = compile_predicate(queryset.model, canonical_query)
        except SearchSyntaxError:
            skipped_queries += 1
            continue
        predicates_by_query.append((control_query, predicate))
        combined_predicate = predicate if combined_predicate is None else combined_predicate | predicate

    if combined_predicate is None:
        return queryset.none(), active_queries, skipped_queries, {}, {}

    matched_ids = set(queryset.filter(combined_predicate).values_list("pk", flat=True))
    if not matched_ids:
        return queryset.none(), active_queries, skipped_queries, {}, {}

    narrowed_queryset = queryset.filter(pk__in=matched_ids)
    matched_by_object = {}
    for control_query, predicate in predicates_by_query:
        for object_id in narrowed_queryset.filter(predicate).values_list("pk", flat=True):
            matched_by_object.setdefault(object_id, []).append(control_query)

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


def evaluate_device_configuration_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or DEVICE_CONFIGURATION_MODEL,
    )


def evaluate_management_interface_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or MANAGEMENT_INTERFACE_MODEL,
    )
