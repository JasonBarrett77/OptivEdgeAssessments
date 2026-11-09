"""Canonical search compiler for one vsys's User-ID discovery include/exclude list. PAN-UID-002.

ONE ROW PER VSYS AND THE ROW IS A VERDICT OVER THE WHOLE LIST, not over one entry. The commonest
failing state is that the list holds NOTHING: help p.981 says a collector with no in-force entry
performs discovery in ALL subnetworks, so every address reachable through a monitored server is
eligible to become a named user in policy and in the log. A per-entry grain would have no row to
report on in exactly that case, which is why stage 5 declared the conclusion as a column.

`list_shape` IS REGISTERED THROUGH THE TEXT BUILDER AND NOT THROUGH A CHOICE BUILDER, and the
reason decides whether this control can report an uncollected row at all. The column is
`CharField(choices=..., blank=True)`: stage 7's classifier returns the EMPTY STRING for a vsys
whose collection never reached this node, so `""` is a REACHABLE value of the column and is
absent from its own `choices`. A `build_choice_compiler` registration - the raising form this
package otherwise prefers, because it refuses a value outside the set - can express no query for
that state at all. Measured and recorded by the `platform-lifecycle` run, 2026-11-01, in
`reference/consumer-repo-notes.md`.

The cost of the text builder has to be stated rather than discovered: a MISSPELLED value in a
catalog payload compiles against a text field and matches nothing, where the raising form would
have refused it. What limits the damage here is the shape of this control - see below.

THE ASSERTION OVER THIS SUBJECT IS INVERTED, AND THAT IS WHAT MAKES THE UNKNOWN FIRE. Stage 5
states PAN-UID-002 as `list_shape equals include_present` with `sign:
finding_when_clauses_fail`, so the baseline fires on the NEGATION: every shape that is not an
in-force include list. A NEGATED equality reaches `""` without needing an `is_empty` member,
because a row holding the empty string is not equal to `include_present` - so an uncollected row
FIRES rather than passing, which is the direction `rules.md` requires. It is also why a
misspelled CALIBRATION value loses a RANK and never a finding: the baseline still fires on every
value that is not the passing one.

THE FOUR VALUES ARE MUTUALLY EXCLUSIVE BY CONSTRUCTION, which is what licenses this control's
calibration queries to be equalities on a single-valued column. No row matches two of them, so
the worst matched calibration is the only matched calibration - the condition
`derive_control_query_severity_value` makes load-bearing.

`exclude_entry_count` AND `include_entry_count` ARE REGISTERED AND NO SHIPPED CLAUSE RESTS ON
THEM. They are what tells a reader "the list has entries and none of them is an include" from
"the list is empty", which `list_shape` already decides but does not quantify. Registered because
a finding reads them; not claused, because the conclusion is the column above.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import UserIdDiscoveryBound

USER_ID_DISCOVERY_BOUND_MODEL = "integrations.UserIdDiscoveryBound"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        predicate = Q()
        for lookup in lookups:
            predicate &= Q(**{lookup: ""}) | Q(**{f"{lookup}__isnull": True})
        return predicate
    if not isinstance(value, str) or not value.strip():
        raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
    suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
    predicate = Q()
    for lookup in lookups:
        predicate |= Q(**{f"{lookup}__{suffix}": value.strip()})
    return predicate


def build_text_compiler(field_name, *lookups):
    def compiler(clause):
        return UserIdDiscoveryBound.objects.filter(
            _text_filter(field_name, lookups, clause)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in INTEGER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return UserIdDiscoveryBound.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column: one column, two fields, and each field two lookup paths
    # because exactly one of the enforcement point's two owners is set.
    "hostname": build_text_compiler(
        "hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    # Stage 5's `enforcement_point` column. The row's identity IS the vsys.
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # PAN-UID-002's assertion AND its graded column - the baseline negates it and three
    # calibrations compare on it. Text rather than choice, and the empty string is a reachable
    # value that the baseline's negation reaches: see the module docstring for both.
    "list_shape": build_text_compiler("list_shape", "list_shape"),
    # REGISTERED AND UNCLAUSED. What a finding reads to say how big the list is; the conclusion
    # is `list_shape` above and no shipped clause rests on either count.
    "include_entry_count": build_integer_compiler(
        "include_entry_count", "include_entry_count"),
    "exclude_entry_count": build_integer_compiler(
        "exclude_entry_count", "exclude_entry_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_user_id_discovery_bound_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_user_id_discovery_bound_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause["negated"] else predicate
