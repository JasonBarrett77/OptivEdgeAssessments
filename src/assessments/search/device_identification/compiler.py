"""Canonical search compiler for one appliance's device-identification state. PAN-IOT-001, -003.

ONE ROW PER APPLIANCE, because all three instruments behind this model are device-wide: the
license table and `show system info` are operational commands with no xpath at any scope, and
`deviceconfig/setting/iot/edge` is a device-wide singleton. So the owner is the appliance
directly, there is no enforcement point in the lookup path, and there is one lookup per field
with no either-owner branch. On an HA pair this yields two rows for what an operator thinks of
as one firewall and the two can legitimately differ, because a license is per serial.

TWO CONTROLS SHARE THIS MODEL AND ASSERT ON DISJOINT COLUMNS. PAN-IOT-001 asserts on the
entitlement (`device_id_licensed`) and the wiring (`edge_service_address`); PAN-IOT-003 on the
currency of the installed classification data (`device_dictionary_age_days`). A type maps to one
model and many controls may share a type.

`edge_service_address` IS `blank=True` AND NOT NULLABLE, AND THAT IS WHAT MAKES THE SHIPPED
`is_empty` CLAUSE WORK. `is_empty` compiles to `filter(field="")` in every per-model compiler in
this package and tests the empty string and nothing else - there is no is-null operator in this
query language. A `null=True` column would therefore be unreachable by the one operator written
for absence, and PAN-IOT-001's second half - whose finding is that the firewall is pointed at
nothing - would have matched no row on the exact population it was written for. Stage 7 chose
blank deliberately and said so in the model's own comment.

`device_dictionary_age_days` IS NULLABLE AND NO OPERATOR HERE REACHES A NULL. It is null on every
appliance that reports no release date - measured on two of the four lab appliances, and they are
the two holding content 167 releases behind their siblings - and SQL answers no for a null on
every positive comparison, so those appliances PASS every staleness threshold. That is why
`device_dictionary_release_date_known` is registered beside it and why PAN-IOT-003's graded group
carries it as an applicability clause: the companion keeps the unmeasurable rows OUT of the
graded comparison, and a second query fires on the companion at false so they report rather than
passing. This module does not invent an is-null operator.

`licence_read_taken` IS THE SAME SHAPE FOR A DIFFERENT REASON. An appliance holding no
entitlement answers `{"licenses": None}`, which is exactly what an appliance nobody asked
produces - the two are INDISTINGUISHABLE in the payload, so `device_id_licensed eq false` cannot
say which false it is. The companion is the only thing that separates them and PAN-IOT-001
carries a second query on it.

`device_dictionary_version`, `device_dictionary_release_date`, `icd_build_version` and
`icd_built_at` ARE DELIBERATELY NOT REACHABLE FROM HERE. No clause and no grading in
`device-id-iot` names any of them: they are `presented: true` so a reader of a staleness finding
can see the instrument that DISAGREES with the one being graded, which is stage 9's business and
not a clause's. Registering them would ship a search surface no control asks for. The
disagreement is worth knowing about: `icd_built_at` ranks the two appliances 167 content releases
behind as the FRESHEST in the estate, which is why stage 5 grades on the age column instead.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import DeviceIdentificationState

DEVICE_IDENTIFICATION_MODEL = "integrations.DeviceIdentificationState"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return DeviceIdentificationState.objects.filter(
                **{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return DeviceIdentificationState.objects.filter(
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
        return DeviceIdentificationState.objects.filter(
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
        return DeviceIdentificationState.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column, which is ONE COLUMN AND TWO FIELDS - the convention every
    # shipped compiler in this package follows. The hostname is what a reader recognises; the
    # serial number is what identifies the appliance when two carry the same hostname, which on
    # an HA pair is the normal case rather than the edge one.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # PAN-IOT-001's first half. FALSE fires, and false is the stored default: the vendor returns
    # NO ROW for an entitlement an appliance does not hold, so the question is about the ABSENCE
    # of a row, which no predicate can express - hence a derived per-appliance boolean.
    "device_id_licensed": build_boolean_compiler(
        "device_id_licensed", "device_id_licensed"),
    # The companion that tells "not entitled" from "never asked". See the module docstring.
    "licence_read_taken": build_boolean_compiler(
        "licence_read_taken", "licence_read_taken"),
    # PAN-IOT-001's second half, asserted with `is_empty`. Reachable only because the column is
    # blank-not-null; read the module docstring before changing either.
    "edge_service_address": build_text_compiler(
        "edge_service_address", "edge_service_address"),
    # PAN-IOT-003's graded column. NULLABLE - clause on the companion below beside any
    # comparison written here, which is what the control's applicability clause does.
    "device_dictionary_age_days": build_integer_compiler(
        "device_dictionary_age_days", "device_dictionary_age_days"),
    # The companion that answers "is this unknown" for the column above, and the applicability
    # clause on PAN-IOT-003's graded group.
    "device_dictionary_release_date_known": build_boolean_compiler(
        "device_dictionary_release_date_known", "device_dictionary_release_date_known"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_device_identification_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_device_identification_search_node(c) for c in group["clauses"]]
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
