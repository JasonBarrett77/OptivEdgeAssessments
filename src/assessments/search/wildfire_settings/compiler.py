"""Canonical search compiler for the device-wide WildFire settings. PAN-AVW-004 and PAN-AVW-005.

TWO CONTROLS over one model, and their polarities are opposite - which is exactly the trap
the services-settings pair was split to avoid, so it is spelled out here:

  PAN-AVW-004  `size_limits_untuned eq true` fires. A TUNING check (Jason, 2026-10-09): a
               value still at its PAN-OS default means nobody sized it for this estate, and
               a value moved off it - up OR down - is taken as evidence that somebody did.
  PAN-AVW-005  `shares_full_session_info eq false` OR either report flag false. Session
               information is stored as EXCLUSIONS, so EMPTY IS THE GOOD STATE and the field
               below is derived rather than read straight off a column.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import WildfireSettings

WILDFIRE_SETTINGS_MODEL = "integrations.WildfireSettings"

def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return WildfireSettings.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return WildfireSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return WildfireSettings.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # PAN-AVW-004
    "size_limits_untuned": build_boolean_compiler(
        "size_limits_untuned", "size_limits_untuned"),
    # PAN-AVW-005
    # A stored COLUMN, not a lookup into `session_info_excluded`: a control may not rest on
    # a JSON field, because a JSON lookup is unindexed and matches nothing when the vendor
    # renames a key - failing silently rather than loudly.
    "shares_full_session_info": build_boolean_compiler(
        "shares_full_session_info", "shares_full_session_info"),
    "report_benign_file": build_boolean_compiler("report_benign_file", "report_benign_file"),
    "report_grayware_file": build_boolean_compiler(
        "report_grayware_file", "report_grayware_file"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_wildfire_settings_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_wildfire_settings_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause.get("negated") else predicate
