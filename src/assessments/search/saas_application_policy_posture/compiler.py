"""Canonical search compiler for one enforcement point's SaaS application-policy verdict.

PAN-SAS-003, and the half of PAN-SAS-004 that this model cannot carry - see below. Two questions
off two objects: whether the upload, sharing and delete FUNCTIONS of permitted applications are
refused, and whether the partition selects cloud applications by ATTRIBUTE rather than one name
at a time.

WHY NOT THE RULE GRAIN, WHICH WAS AVAILABLE AND CHEAPER. `SecurityRule` ships, its `application`
members ship, and `application` is reachable from a query already - so "a rule names a function
child app and its action is allow" is one unit of work on existing columns. It was not taken for
two measured reasons: the commonest failing state is that NO rule names the functions, which a
rule row cannot report; and the assertion is a RELATION BETWEEN TWO RULES - a deny on the
function child evaluated BEFORE an allow on the base application - and rule order is positional
rather than a column.

`effective_action_for_function_apps` IS THE GRADED COLUMN AND `no-rule` IS ITS SENTINEL. The
sentinel sorts as benign on any equality against `allow` while being the state the control is
most often failed by - every appliance in this lab held it before stage 6 wrote six rules. Both
of stage 5's finding placements, `allow` and `no-rule`, sit at the control's OWN severity, so
the baseline reports both and no calibration query is owed. That property rests on the shape of
the column rather than on luck: the baseline asserts on `function_apps_are_refused`, which is
false in BOTH states, so the sentinel is reached without a query of its own. A later stage that
converts either placement into a threshold-shaped query breaks it.

`deny` IS NOT THE ONLY REFUSAL, which is why the baseline reads the verdict and not the action.
The `action` leaf's value set is six, measured identically on all four lab appliances with
`@default='yes'` on `allow`, and `drop`, `reset-client`, `reset-server` and `reset-both` are all
denials in this control's sense while none of them is the string `deny` that the catalog's own
set command writes. A query matching the literal would report a compliant partition as failing.

PAN-SAS-004's SECOND RECORD ASSERTS ON THIS MODEL AND PAN-SAS-004 CANNOT TARGET IT.
`Control.save()` derives one `target_model` from `control_type` through a one-to-one map and
`ControlQuery.clean()` refuses a query on another model, so that control carries queries for its
first record's subject only. The two fields its second record would have rested on -
`cloud_app_selection_is_refused` and `cloud_app_selection_excludes_approved` - are registered
here so the clause exists the moment a control can hold it, and `subjects_in_two_models` in the
stage 8 artifact for `saas-security` records which half is silent. Nothing in this repository
queries them today.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import SaasApplicationPolicyPosture

SAAS_APPLICATION_POLICY_POSTURE_MODEL = "integrations.SaasApplicationPolicyPosture"
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
        return SaasApplicationPolicyPosture.objects.filter(
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
        return SaasApplicationPolicyPosture.objects.filter(
            **{lookup_field: value}).values("pk")
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
        return SaasApplicationPolicyPosture.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler(
        "hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # PAN-SAS-003's assertion. FALSE is the finding, and false is also what a rulebase naming
    # none of the function applications holds - the count beside it tells the two apart.
    "function_apps_are_refused": build_boolean_compiler(
        "function_apps_are_refused", "function_apps_are_refused"),
    # The GRADED column, with the sentinel at the weak end. A calibration query compares on
    # this; the assertion never does.
    "effective_action_for_function_apps": build_text_compiler(
        "effective_action_for_function_apps", "effective_action_for_function_apps"),
    # What tells "no rule names them" from "a rule names them and permits them". Nothing fires
    # on it alone and a finding reads it.
    "function_app_rule_count": build_integer_compiler(
        "function_app_rule_count", "function_app_rule_count"),
    # The attribute surface. REGISTERED AND UNQUERIED - see the module docstring: PAN-SAS-004's
    # second record asserts on these two and cannot target this model.
    "cloud_app_selection_is_refused": build_boolean_compiler(
        "cloud_app_selection_is_refused", "cloud_app_selection_is_refused"),
    "cloud_app_selection_excludes_approved": build_boolean_compiler(
        "cloud_app_selection_excludes_approved", "cloud_app_selection_excludes_approved"),
    "cloud_app_filter_count": build_integer_compiler(
        "cloud_app_filter_count", "cloud_app_filter_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_saas_application_policy_posture_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_saas_application_policy_posture_search_node(c)
                for c in group["clauses"]]
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
