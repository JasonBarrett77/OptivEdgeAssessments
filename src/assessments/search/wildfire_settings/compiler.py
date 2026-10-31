"""Canonical search compiler for the device-wide WildFire settings. PAN-AVW-004 and PAN-AVW-005.

TWO CONTROLS over one model, and their polarities are opposite - which is exactly the trap
the services-settings pair was split to avoid, so it is spelled out here:

  PAN-AVW-004  `size_limits_wholly_untuned eq true` fires. A TUNING check (Jason,
               2026-10-09): a value still at its PAN-OS default means nobody sized it for
               this estate, and a value moved off it - up OR down - is taken as evidence that
               somebody did. The ALL quantifier, not the ANY one: see the two columns below.
  PAN-AVW-005  `shares_full_session_info eq false`, plus one calibration query per member of
               `verdict_reporting_gap`. Session information is stored as EXCLUSIONS, so EMPTY
               IS THE GOOD STATE and the field below is derived rather than read straight off
               a column.

Both control's clauses were re-read against their columns by the stage 8 av-wildfire run,
2026-10-31, which is where the two quantifier columns and the graded token came in. The
previously claused `size_limits_untuned`, `report_benign_file` and `report_grayware_file`
remain registered: nothing else names them today, and they are the measured columns the three
derived ones are computed from, so a reader comparing a finding to the store needs them.
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
    # PAN-AVW-004's ACTUAL assertion, and the ALL quantifier beside the ANY one above. The two
    # columns disagree deliberately and the model's own comments say which is which:
    # `size_limits_untuned` fires when ANY asserted type is still at its PAN-OS default,
    # `size_limits_wholly_untuned` only when EVERY one is. Stage 3 asserts the second - the
    # control's description is about a platform nobody sized at all - and the lab separates
    # them: fw-core-tpa-a has moved `pe` off its default and nothing else, so the ANY column
    # reports it and the ALL column does not.
    "size_limits_wholly_untuned": build_boolean_compiler(
        "size_limits_wholly_untuned", "size_limits_wholly_untuned"),
    # PAN-AVW-005
    # A stored COLUMN, not a lookup into `session_info_excluded`: a control may not rest on
    # a JSON field, because a JSON lookup is unindexed and matches nothing when the vendor
    # renames a key - failing silently rather than loudly.
    "shares_full_session_info": build_boolean_compiler(
        "shares_full_session_info", "shares_full_session_info"),
    "report_benign_file": build_boolean_compiler("report_benign_file", "report_benign_file"),
    "report_grayware_file": build_boolean_compiler(
        "report_grayware_file", "report_grayware_file"),
    # PAN-AVW-005's SECOND half as one graded token, which is how its OR was dissolved. The
    # two report flags above are a disjunction, and a clause tree can express that - but a
    # SEVERITY GRADING cannot, because the two halves rank differently (`grayware` low,
    # `benign` informational) and a disjunction has one severity. The normalizer derives this
    # column from the same two booleans, so it can never disagree with them.
    #
    # TEXT, not boolean: the members are `none`, `benign`, `grayware` and `both`, mutually
    # exclusive on a single-valued column, which is what makes a calibration query per member
    # safe - no row can match two of them.
    "verdict_reporting_gap": build_text_compiler(
        "verdict_reporting_gap", "verdict_reporting_gap"),
    # WHETHER ANYBODY LOOKED, and the companion `shares_full_session_info` needs. That column
    # is `BooleanField(default=True)` and `true` is PAN-AVW-005's COMPLIANT side, so a row the
    # normalizer never wrote - one from before the column existed, or an appliance nothing has
    # collected - passes the assertion in silence. There is no is-null operator to ask with.
    # Registered so a coverage clause CAN be written; stage 5 declared the decision not to
    # report it, and this run carries that forward rather than reversing it - see the stage 8
    # artifact's `coverage_placements`.
    "session_info_read": build_boolean_compiler("session_info_read", "session_info_read"),
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
