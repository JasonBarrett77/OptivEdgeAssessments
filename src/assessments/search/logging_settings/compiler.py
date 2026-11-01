"""Canonical search compiler for the logging and reporting settings.

PAN-MGT-011, and since 2026-11-01 PAN-LOG-001, 003, 004, 006, 007, 008, 009 and 010.

PAN-MGT-011's implicit value is the OPPOSITE of its neighbour on the update server: absent means
DISABLED, so an untouched device matches `log_on_high_dp_load eq false`.

TEN COLUMNS ADDED FOR THE `logging` DOMAIN, AND FOUR DELIBERATELY LEFT. Stage 5 marks all
fifteen of this subject's columns `needs_compiler_field` and ten of them are NAMED by this
domain - as an assertion clause, an applicability clause or a grading axis. The other four are
not registered: `config_log_offbox_destination` and `config_log_filter_narrows` are the two
halves stored beside `config_log_fully_offbox` so a FINDING can say which one failed, which is
prose rather than a predicate; `central_store_status_collected` is PAN-LOG-010's declared
companion and stage 5's own grading note says in terms that it is neither a placement nor a
clause; and `log_settings_match_lists` is a JSONField stage 5 marks `not_searchable`. The
compiler's rule in this repository is that a field earns its place by a control needing it, and
registering the rest would ship a search surface no control asks for.

`hostname` AND `serial_number` WERE ALREADY HERE and both serve stage 5's one `appliance`
column, so the logging domain added neither - measured rather than assumed, because three of the
66 shipped compilers register neither.

`is_empty` IS THE BARE `filter(field="")` SHAPE HERE AND THAT IS CORRECT FOR THESE COLUMNS,
which is the half of the nullable-column trap worth writing down. Measured on the integrations
model: `system_log_severity_gaps` is `CharField(max_length=64, blank=True,
default=ALL_SYSTEM_SEVERITIES_MISSING)` and `panorama_log_type_gaps` is the same shape at 255 -
NEITHER carries `null=True`. So the only absent value either column can hold is `""`, which the
bare shape reaches, and an `__isnull=True` branch beside it would match nothing extra. The trap
is a `null=True` text column, where the bare shape compiles, passes every gate and matches
nothing on the exact population the clause was written for; it does not arise on this model.

AND THE GAP COLUMNS ARE QUERIED WITH `contains`, NOT `eq`. Both hold a comma-joined set of what
is MISSING, so a severity band or a log type is tested for MEMBERSHIP of that set. Stage 5 says
its own `placements[].value` cannot express this and that downstream it is `contains`. The five
System severities and the sixteen Panorama log types were each checked for substring collisions
before the queries were written - no token of either set is a substring of another - because
`icontains` over a joined string would otherwise match a band nobody is missing.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import LoggingSettings

LOGGING_SETTINGS_MODEL = "integrations.LoggingSettings"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}

def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return LoggingSettings.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return LoggingSettings.objects.filter(
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
        return LoggingSettings.objects.filter(**{lookup_field: value}).values("pk")
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
        return LoggingSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "log_on_high_dp_load": build_boolean_compiler(
        "log_on_high_dp_load", "log_on_high_dp_load"),
    # --- the `logging` domain, 2026-11-01 -------------------------------------------------
    # PAN-LOG-001's assertion axis AND its grading axis. It needs TWO shapes over one integer:
    # `lt 2` for the assertion, because the floor is one path and the vendor asks for two, and
    # an EQUALITY on 1 for the medium rung - a threshold-shaped calibration would also match a
    # row holding 0 and report the worst case at the lower severity. Stage 7's `spec_gaps[4]`
    # names exactly that pair and the integrations model carries an index for it.
    "offbox_destination_count": build_integer_compiler(
        "offbox_destination_count", "offbox_destination_count"),
    # PAN-LOG-001's second assertion record.
    "syslog_destination_in_use": build_boolean_compiler(
        "syslog_destination_in_use", "syslog_destination_in_use"),
    # PAN-LOG-003's assertion axis and its grading axis. Queried as a NEGATED `is_empty` for the
    # assertion - the registry has no `is not empty` operator, so the negation is taken at the
    # clause, which `_compile_clause` below applies - and as `contains` per severity band.
    "system_log_severity_gaps": build_text_compiler(
        "system_log_severity_gaps", "system_log_severity_gaps"),
    # PAN-LOG-004's only assertion. The two halves beside it are not registered: see the module
    # docstring.
    "config_log_fully_offbox": build_boolean_compiler(
        "config_log_fully_offbox", "config_log_fully_offbox"),
    # PAN-LOG-006's and PAN-LOG-010's applicability clause. Defaulted TRUE on the model, so an
    # unrecomputed row is judged rather than silently excluded.
    "panorama_managed": build_boolean_compiler("panorama_managed", "panorama_managed"),
    # PAN-LOG-006's assertion. Negated `is_empty`, as PAN-LOG-003's.
    "panorama_log_type_gaps": build_text_compiler(
        "panorama_log_type_gaps", "panorama_log_type_gaps"),
    # PAN-LOG-007's only assertion.
    "require_audit_comment": build_boolean_compiler(
        "require_audit_comment", "require_audit_comment"),
    # PAN-LOG-009's assertion axis and its grading axis, which are the same column: the baseline
    # IS the only graded placement that fires, so this control ships one query.
    "log_retention_configured": build_boolean_compiler(
        "log_retention_configured", "log_retention_configured"),
    # PAN-LOG-008's first group. Its SECOND group is a clause on `LogServerTarget` that stage 5
    # left in `undetermined` rather than in `clauses`, so nothing here serves it.
    "email_alerting_for_critical_system_events": build_boolean_compiler(
        "email_alerting_for_critical_system_events",
        "email_alerting_for_critical_system_events"),
    # PAN-LOG-010's assertion axis and its grading axis, the same shape as PAN-LOG-009's.
    "central_store_delivery_healthy": build_boolean_compiler(
        "central_store_delivery_healthy", "central_store_delivery_healthy"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_logging_settings_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_logging_settings_search_node(c) for c in group["clauses"]]
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
