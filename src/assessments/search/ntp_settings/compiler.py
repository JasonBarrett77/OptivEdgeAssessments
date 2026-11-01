"""Canonical search compiler for NTP settings. PAN-SVC-001 and 002.

One row per appliance. `server_count` is what PAN-SVC-001 grades on rather than the two address
fields, because the assertion is about redundancy and a count is what a threshold compares;
`all_servers_symmetric_key` is PAN-SVC-002's whole assertion, resolved across both slots in
normalization because the search layer cannot ask "every configured server".
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import NtpSettings

NTP_SETTINGS_MODEL = "integrations.NtpSettings"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return NtpSettings.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return NtpSettings.objects.filter(
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
        return NtpSettings.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in INTEGER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return NtpSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "primary_server": build_text_compiler("primary_server", "primary_server"),
    "secondary_server": build_text_compiler("secondary_server", "secondary_server"),
    "primary_auth_type": build_text_compiler("primary_auth_type", "primary_auth_type"),
    "secondary_auth_type": build_text_compiler("secondary_auth_type", "secondary_auth_type"),
    "all_servers_symmetric_key": build_boolean_compiler(
        "all_servers_symmetric_key", "all_servers_symmetric_key"),
    "server_count": build_integer_compiler("server_count", "server_count"),
    # PAN-SVC-001's SECOND assertion record and the two gradings, registered by stage 8 of
    # `device-services` on 2026-11-01. Stage 5 marks all three `needs_compiler_field`; the five
    # columns of this subject it marks `already` are the eight above.
    #
    # THE TWO VERDICT COLUMNS TAKE THE TEXT COMPILER AND NOT `build_choice_compiler`, which is
    # the majority convention here and is a choice rather than an oversight. A choice compiler
    # refuses a value the column cannot hold, which is better; it also accepts none of
    # `tests/test_findings_rest_on_columns.py::PROBE_VALUES`, and this model carries a JSONField
    # (`unauthenticated_servers`) so that test probes it rather than skipping it - so the
    # closed form would make this domain's vocabulary a literal in a shared test of every other
    # model. The values these columns are clauseed with are generated from stage 5's
    # `grading.placements` and checked against a census, not typed by hand.
    #
    # `is_empty` COMES WITH THE TEXT COMPILER AND CAN NEVER MATCH EITHER OF THEM: both columns
    # are non-null with a non-empty default, so no row holds "". Recorded rather than removed,
    # because the operator set is the shared one.
    "synched_to_a_configured_server": build_boolean_compiler(
        "synched_to_a_configured_server", "synched_to_a_configured_server"),
    "time_source_in_force": build_text_compiler(
        "time_source_in_force", "time_source_in_force"),
    "server_authentication_mechanism": build_text_compiler(
        "server_authentication_mechanism", "server_authentication_mechanism"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_ntp_settings_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_ntp_settings_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def compile_search_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause["negated"] else predicate
