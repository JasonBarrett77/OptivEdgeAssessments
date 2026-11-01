"""Canonical search compiler for one enforcement point's decryption rulebase. PAN-DEC-001, -009.

ONE ROW PER ENFORCEMENT POINT - one virtual system of one appliance or of one HA pair - carrying a
VERDICT over all of that point's decryption rules together. The owner is reached through the point
and the appliance lookups branch on either owner, the same two-path shape
`search/decryption_policy_rule` beside it uses.

WHY THERE ARE TWO COMPILERS OVER ONE PAN-OS OBJECT, which is the fact to read before the field list.
Stage 4 measured the commonest state of this domain as NO DECRYPTION RULEBASE AT ALL - all four lab
appliances, all twenty virtual systems, both Panorama Shared rulebases and all ten device groups,
twice. A predicate cannot compare against a row that is not there, so the two controls whose finding
is that NO rule does something have nothing to match at the per-entry grain. Every column below
holds its FIRING value as its migration default for exactly that reason: an enforcement point
nobody collected, and a row nobody recomputed, both report themselves.

`rule_count` IS STORED AND IS DELIBERATELY NOT REGISTERED. Stage 5 marks it
`needs_compiler_field`, and no clause, grading or `undetermined` of this domain names it - so by
this repository's own rule (a field earns its place by a control needing it) registering it would
ship a search surface no control asks for. What a reader needs from it is a NUMBER in the finding's
own sentence, which is stage 9's business, and the generator beside this file states it. Stage 5
also declared its `stored_type` as `string` while its own default value is the integer 0; stage 7
built `PositiveIntegerField` and recorded the contradiction, and the stage 8 artifact carries it in
`disagreed_with_input`.

AND `opens_outbound_web` IS A BOOLEAN WHERE STAGE 5 SAYS `string`, which is the same contradiction
on the column a clause DOES rest on and is why it matters. Stage 5's assertion for PAN-DEC-001 is
`opens_outbound_web equals false`; a text column compared with `is greater than 0` - the comparison
stage 5's own sibling column writes - would compare strings. Stage 7 built `BooleanField`, and the
clause below is `eq true/false` rather than a string comparison.

THE TWO GRADED TEXT COLUMNS ARE SINGLE-VALUED AND THEIR PLACEMENTS ARE MUTUALLY EXCLUSIVE
EQUALITIES, which is what makes PAN-DEC-001's two baseline-tier calibration queries safe to build:
no row can match two of them, so the worst matched calibration is the only matched calibration and
its severity equals the baseline tier. The only thing those queries change is that the graded value
behind a finding is recorded rather than inferred from the absence of a calibration.

`is_empty` IS ADVERTISED ON THE TEXT FIELDS BY `scalar_text` AND IS REACHABLE. Both
`outbound_web_disposition` and `inbound_inspection_posture` are non-nullable with an explicit
non-empty migration default, so the bare `filter(field="")` shape matches nothing on them and
cannot be wrong in the silent direction - no clause of this domain uses it, and no value of either
column is the empty string. The two-path identity fields take the `__isnull`-OR shape instead,
because exactly one of the point's two owners is set and the other path is always NULL.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import DecryptionRulebaseVerdict

DECRYPTION_RULEBASE_COVERAGE_MODEL = "integrations.DecryptionRulebaseVerdict"


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        # EVERY path empty or missing. An enforcement point has one owner, so the other owner's
        # path is always NULL and OR-ing the null branches would call every row empty.
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
        return DecryptionRulebaseVerdict.objects.filter(
            _text_filter(field_name, lookups, clause)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return DecryptionRulebaseVerdict.objects.filter(
            **{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column: one column, two fields, each with two lookup paths.
    "hostname": build_text_compiler(
        "hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    # Stage 5's `vsys_name`, which with the appliance is the whole of this row's identity.
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # PAN-DEC-001'S ASSERTION, and it is kept separate from the disposition beside it on purpose:
    # the baseline must fire on BOTH failing states - no forward-proxy rule at all, and rules that
    # all leave the session encrypted - in one conjunction, while the disposition carries the
    # severity. Splitting them is what lets `decrypt-and-forward` sit OUTSIDE the baseline: the
    # session IS opened, so that value meets the assertion and must not be reported as a coverage
    # failure. False is the migration default and the firing side.
    "opens_outbound_web": build_boolean_compiler(
        "opens_outbound_web", "opens_outbound_web"),
    # PAN-DEC-001'S GRADING AXIS, and a clause nowhere: one of the four OUTBOUND_* values, as the
    # strongest thing any in-force forward-proxy rule on this point does. Registered on grading
    # grounds alone, which is one of the legitimate kinds of `asserted_fields` member - a
    # calibration query asserts on it and a reader of that finding needs the cell.
    "outbound_web_disposition": build_text_compiler(
        "outbound_web_disposition", "outbound_web_disposition"),
    # PAN-DEC-009'S ASSERTION AND ITS GRADING AXIS, both: whether anything inspects inbound TLS on
    # the organisation's own published servers. The assertion is an equality on
    # `no-inbound-inspection-rule`, which IS the grading's baseline-tier placement - so that
    # placement is carried by the baseline itself and needs no calibration query of its own. The
    # grading's `inbound-inspection-present` placement is `no_finding` and compiles to nothing,
    # which is right twice over: it is the acceptable value AND the assertion clause excludes it.
    "inbound_inspection_posture": build_text_compiler(
        "inbound_inspection_posture", "inbound_inspection_posture"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_decryption_rulebase_coverage_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_decryption_rulebase_coverage_search_node(c) for c in group["clauses"]]
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
