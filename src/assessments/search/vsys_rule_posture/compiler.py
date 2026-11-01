"""Canonical search compiler for one enforcement point's whole-policy verdicts.

PAN-POL-007, -010, -017, -018 and -019. Minted by stage 8 of `security-policy`, 2026-11-01.

EVERY COLUMN ON THIS MODEL IS A STATEMENT ABOUT THE ABSENCE OF A RULE SOMEBODY SHOULD HAVE
WRITTEN, taken over the point's stored `SecurityRule` rows rather than over any one rule - which
is why the subject is the vsys and not a rule, and why `_CONTROL_TYPE_TARGET_MODEL` needed a new
member rather than these being columns of `SecurityRule`. A rule-keyed row cannot report a rule
that does not exist.

SEVEN FIELDS AND NOT TEN. Stage 5 marks seven of this subject's ten columns
`needs_compiler_field` and names SIX of those seven in a clause, plus `rules_collected`, which it
marks `already` and which is not searchable on this model at all - there was no compiler for it
before this file. So:

  * `rules_collected` is registered and is the APPLICABILITY clause of all five controls. It is
    the load-bearing column of the model: without it a vsys nobody collected would answer false
    to every existence verdict below and report as missing every rule it was supposed to have.
  * `has_logged_catch_all_deny`, `default_rules_log_session_end`,
    `has_application_block_rule_above_permits`, `vendor_hostile_list_block_directions_missing`,
    `expresses_geographic_boundary` and `has_port_matched_block_rule` are the five controls'
    assertions.
  * `has_prestaged_blocklist_rule` is NOT registered. Stage 5 marks it
    `needs_compiler_field` and no assertion of this domain names it - it is the column the
    incident-response half of the corpus would want and no control claims it yet. A field for a
    clause nobody writes is a search surface with no owner.
  * `management_station` and `vsys_name` are stage 5's identity columns for this subject and both
    carry `searchable: already`, which is false on this model: neither was queryable here before
    today. `hostname` and `serial_number` are registered in their place, which is what MOST
    shipped compilers do for stage 5's appliance-or-point column - measured rather than copied,
    because three of the 66 shipped compilers register neither and `security_rules`, the closest
    precedent this domain has, is one of the three. `vsys_name` IS registered, because this
    model's grain is the vsys and a reader filtering its own findings has nothing else to name
    one by; it reaches `EnforcementPoint.vsys_name` through the FK, which is where the column
    lives - `VsysRulePosture` itself has no such column, and stage 5's `already` mark on it is
    premature about the model rather than wrong about the fact.

EVERY BOOLEAN HERE IS NON-NULLABLE WITH A `False` DEFAULT AND FALSE IS THE FIRING SIDE, which
is the opposite of the usual hazard and worth stating: an unrecomputed row reads as the WORST
answer rather than the most reassuring one, so a migration that creates the row before the
renormalize that fills it over-reports rather than under-reports. The one count,
`vendor_hostile_list_block_directions_missing`, defaults to 2 - both directions missing - for the
same reason.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import VsysRulePosture

VSYS_RULE_POSTURE_MODEL = "integrations.VsysRulePosture"
BOOLEAN_OPERATORS = {"eq"}
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}
TRUE_VALUES = {"true", "yes", "on", "1"}
FALSE_VALUES = {"false", "no", "off", "0"}


def _parse_boolean(value, *, field_name):
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        raise SearchSyntaxError(
            f"{field_name} search value must be a boolean or boolean-like string.")
    normalized = value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise SearchSyntaxError(
        f"{field_name} search value must be true/false, yes/no, on/off, or 1/0.")


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            # Every lookup this compiler offers is a non-nullable CharField on
            # `Appliance` or `EnforcementPoint`, so `""` is the only absent value and no
            # `__isnull` branch beside it would match anything extra.
            return VsysRulePosture.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return VsysRulePosture.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op = clause["op"]
        if op not in BOOLEAN_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        parsed = _parse_boolean(clause["value"], field_name=field_name)
        return VsysRulePosture.objects.filter(**{lookup_field: parsed}).values("pk")
    compiler.SUPPORTED_OPERATORS = BOOLEAN_OPERATORS
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in INTEGER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return VsysRulePosture.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    #: The appliance identity, serving stage 5's `management_station` column. Two fields for one
    #: column because a hostname is what a reader recognises and a serial is what identifies.
    "hostname": build_text_compiler("hostname", "enforcement_point__appliance__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number"),
    #: The virtual system this row is the posture OF. Reached through the FK because the column
    #: lives on `EnforcementPoint` - this model carries no `vsys_name` of its own.
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    #: THE APPLICABILITY CLAUSE OF ALL FIVE CONTROLS. False means no rulebase read has answered
    #: for this vsys, and every verdict below it would then be an absence nobody measured.
    "rules_collected": build_boolean_compiler("rules_collected", "rules_collected"),
    #: PAN-POL-010's two assertions. The second is about the two rules PAN-OS ships, and it is
    #: FALSE where no override row exists at all - the measured shipped value is session-end
    #: logging OFF, so the absence of rows is false rather than unknown.
    "has_logged_catch_all_deny": build_boolean_compiler(
        "has_logged_catch_all_deny", "has_logged_catch_all_deny"),
    "default_rules_log_session_end": build_boolean_compiler(
        "default_rules_log_session_end", "default_rules_log_session_end"),
    #: PAN-POL-007's assertion.
    "has_application_block_rule_above_permits": build_boolean_compiler(
        "has_application_block_rule_above_permits",
        "has_application_block_rule_above_permits"),
    #: PAN-POL-017's assertion. A COUNT of the two directions - traffic to those addresses and
    #: traffic from them - with no standing block rule, so the severity can turn on how many are
    #: missing rather than on a pair of booleans.
    "vendor_hostile_list_block_directions_missing": build_integer_compiler(
        "vendor_hostile_list_block_directions_missing",
        "vendor_hostile_list_block_directions_missing"),
    #: PAN-POL-018's assertion.
    "expresses_geographic_boundary": build_boolean_compiler(
        "expresses_geographic_boundary", "expresses_geographic_boundary"),
    #: PAN-POL-019's assertion.
    "has_port_matched_block_rule": build_boolean_compiler(
        "has_port_matched_block_rule", "has_port_matched_block_rule"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_vsys_rule_posture_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_vsys_rule_posture_search_node(c) for c in group["clauses"]]
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
