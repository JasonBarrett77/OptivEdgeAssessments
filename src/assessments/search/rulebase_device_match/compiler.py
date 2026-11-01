"""Canonical search compiler for one enforcement point's device-match verdict. PAN-IOT-004.

ONE ROW PER ENFORCEMENT POINT, and the row is a CONCLUSION ABOUT THE RULE SET rather than about
any rule. "No rule names what a device IS" cannot be said of a particular rule, and 182 of the
188 rules measured in the lab carry neither device element - so keying the row on the rule would
multiply one failure across the whole rulebase instead of locating it. The owner is reached
through the enforcement point, with the usual two paths for its two possible owners.

THE ASSERTION IS INVERTED TWICE OVER AND BOTH INVERSIONS COST A PREVIOUS STAGE A ROUND.

The first is the element itself. Stage 1 put this control on a node called `source-device`; stage
2 refuted it offline three ways and stage 4 confirmed it on the device, where `action=complete`
at a security rule returns 32 children on the PA-VMs and 30 on the PA-5220s and NEITHER
`source-device` NOR `destination-device` is among them on any appliance. The real elements are
`source-hip` and `destination-hip` - one element pair behind three UI labels, with three keywords
on the source side (any, no-hip, quarantine) against two on the destination side, and `no-hip`
REFUSED at the write on the destination side. A clause on the naive element would have compiled
to a query that can never fire, so every rule set in every estate would have passed.

The second matters more: THE ELEMENT BEING POPULATED IS NOT THE TEST. The 6 rules in the lab that
carry either element carry only the keyword `any`, which constrains nothing - so a clause on "the
element is not empty" would pass a rule set with no device dimension at all. The verdict is
therefore computed at normalization by resolving each member against the device-object namespace,
and this compiler reaches the boolean rather than the elements.

`has_no_rule_matching_on_device` DEFAULTS TO TRUE AND TRUE IS THE FIRING SIDE. That is deliberate
and it is what makes the migration window announce itself: an enforcement point nobody has
recomputed reports rather than reading as a clean estate. Absence of a RULE is not a finding, but
absence of the DIMENSION across the whole rule set is exactly what this control asserts.

`rules_matching_on_device_count` AND `device_object_count` ARE NOT REACHABLE FROM HERE. No clause
and no grading in `device-id-iot` names either: both are `presented: true` so a finding can print
a number a reviewer checks the verdict against, and so that a reader can tell "no rule names a
device" from "there is no device to name" - two different remediations. Registering them would
ship a search surface no control asks for. One thing a reader will not expect, recorded by stage
7: the count's action filter DIFFERS from the verdict's, because the count includes a `deny` rule
naming a device and the verdict deliberately does not, so the two can be printed side by side and
not reconcile.

THE COMPANION THIS SUBJECT DOES NOT HAVE. Every other uncertain reading in this domain carries a
"was this read" flag and the verdict - the most expensive reading of the four - has none, so a
verdict taken over six rules of 109 is indistinguishable in the row from one over all 109. Stage
7 filed that gap; the only existing signal is that `NormalizationIssue` rows are written per
enforcement point by the rule pass, which a consumer can ask as an EXISTS.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import RulebaseDeviceMatchVerdict

RULEBASE_DEVICE_MATCH_MODEL = "integrations.RulebaseDeviceMatchVerdict"


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
        return RulebaseDeviceMatchVerdict.objects.filter(
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
        return RulebaseDeviceMatchVerdict.objects.filter(
            **{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column: one column, two fields, two lookup paths each.
    "hostname": build_text_compiler(
        "hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    # Stage 5's `vsys_name` - the enforcement point this verdict is about.
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # PAN-IOT-004's only assertion. TRUE fires, and true is the stored default.
    "has_no_rule_matching_on_device": build_boolean_compiler(
        "has_no_rule_matching_on_device", "has_no_rule_matching_on_device"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_rulebase_device_match_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_rulebase_device_match_search_node(c) for c in group["clauses"]]
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
