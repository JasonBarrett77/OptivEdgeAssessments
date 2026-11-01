"""Canonical search compiler for the management service paths. PAN-SVC-006.

ONE ROW PER ENFORCEMENT POINT, not per appliance: the firewall-wide paths are one row with
`scope='device-local'` and an empty `vsys_name`, and every virtual system the appliance names
gets its own row with `scope='vsys'`. Minted by stage 8 of `device-services` on 2026-11-01.

`scope` IS REGISTERED BECAUSE IT IS LOAD-BEARING AND NOT BECAUSE IT IS AN IDENTITY COLUMN. The
control's two assertion records partition this table on it: the firewall-wide half asks whether
every originated service has a chosen path, and the per-system half asks whether a virtual
system recorded a choice at all - and the two per-system columns hold their FIRING defaults on
the device-local row, where the question has no answer. A query grading the per-system half
without `scope eq vsys` reports an appliance-wide enforcement point for failing to record a
per-vsys choice. Stage 7's `spec_gaps[5]` is about exactly this and says the discriminator is
what stage 8 must clause on.

`vsys_name` IS REGISTERED AS THE OTHER HALF OF THE ROW'S KEY. `scope eq vsys` reaches twenty
rows on a twenty-vsys firewall and cannot address one of them; the finding's `subject_scope`
carries the same value, so a reader who sees a finding about `vsys3` needs a field to find it by.
No control clauses on it.

`services_originated` IS A JSONField AND IS NOT REGISTERED, and may not be: the shared gate
`tests/test_findings_rest_on_columns.py` walks every registered field's SQL for a JSON column
and fails. `services_with_a_chosen_path` and `path_covers_both_address_families` are not
registered either - no clause, no grading axis and no `undetermined` of this domain names them.

The two verdict columns take the text compiler rather than `build_choice_compiler`; the NTP
compiler records the reasoning, and it applies here with more force because this model does
carry a JSONField and is therefore probed by that shared test.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import ServiceRoute

SERVICE_ROUTE_MODEL = "integrations.ServiceRoute"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return ServiceRoute.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return ServiceRoute.objects.filter(
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
        return ServiceRoute.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # `is_empty` IS THE ONLY OPERATOR THAT REACHES THE DEVICE-LOCAL ROW on this one, because a
    # firewall-wide row's `vsys_name` is legitimately the empty string. The column is
    # non-nullable, so the bare `filter(field="")` shape this compiler gives `is_empty` reaches
    # it correctly - the `__isnull` trap that shape carries elsewhere does not apply.
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    "scope": build_text_compiler("scope", "scope"),
    "every_originated_service_has_a_chosen_path": build_boolean_compiler(
        "every_originated_service_has_a_chosen_path",
        "every_originated_service_has_a_chosen_path"),
    "service_path_posture": build_text_compiler(
        "service_path_posture", "service_path_posture"),
    "per_system_path_choice_recorded": build_boolean_compiler(
        "per_system_path_choice_recorded", "per_system_path_choice_recorded"),
    "per_system_path_posture": build_text_compiler(
        "per_system_path_posture", "per_system_path_posture"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_service_route_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_service_route_search_node(c) for c in group["clauses"]]
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
