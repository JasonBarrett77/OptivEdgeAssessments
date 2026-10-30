"""Canonical search compiler for one enforcement point's approval-marking verdict. PAN-SAS-001.

THE ROW IS A VERDICT AND NOT AN ENTRY, which is what makes every field here a derived column.
The firewall holds no list of what the business approved - the approval MARKING is the firewall's
only record of it - so no column compares the marked set against an approved set, and the control
reduces to whether the mechanism is used at all and whether the appliance's partitions agree.

THE ROW IS KEYED ON `enforcement_point`, NOT ON `appliance` + `vsys_name`. Stage 5's identity
declared the pair; the shipped model keys on the point and reaches both through the foreign key,
which is the same correction `DecryptionRulebaseVerdict` records. So `hostname`, `serial_number`
and `vsys_name` are REGISTERED FIELD NAMES OVER FOREIGN-KEY PATHS rather than columns, and
`hostname` has to match either owner path because an `EnforcementPoint` carries exactly one of
`appliance`/`appliance_group` (`models/collected.py::EnforcementPoint.clean`).

`marked_application_names` IS DELIBERATELY NOT REACHABLE FROM HERE. It is a JSONField, stage 5
marks it `not_searchable`, and `test_findings_rest_on_columns` enforces the rule exhaustively.
What a control reads is `sanctioned_application_count` beside it; the list is read off the row by
the generator, for the prose and for the remediation.

ZERO IS THE FIRING VALUE OF THE COUNT AND IT IS ALSO THE MIGRATION DEFAULT, so a partition
nobody has recomputed reports itself rather than passing a threshold written over a NULL. The
same holds for both booleans: `appliance_is_multi_vsys` defaults TRUE so an applicability clause
cannot silently remove the control from a row nobody looked at, and
`marking_is_inconsistent_across_vsys` defaults TRUE because an appliance whose partitions nobody
compared has no established agreement.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import SanctionedApplicationMarking

SANCTIONED_APPLICATION_MARKING_MODEL = "integrations.SanctionedApplicationMarking"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        # EVERY path empty or missing. A point has one owner, so the other owner's path is
        # always NULL - OR-ing the null branches would call every row empty.
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
    """One field over one or more lookup paths - several when the owner can be either model."""
    def compiler(clause):
        return SanctionedApplicationMarking.objects.filter(
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
        return SanctionedApplicationMarking.objects.filter(
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
        return SanctionedApplicationMarking.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column, which the shipped model reaches through the point. TWO fields
    # for one column, which is what every shipped compiler does: a reader searches by name and an
    # inventory joins on the serial.
    "hostname": build_text_compiler(
        "hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    # Stage 5's `vsys_name`. The enforcement point IS the partition, so this is its own field.
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # The assertion of PAN-SAS-001's first record. A COUNT and not a presence test: stage 4 found
    # the container absent on two appliances and the lab holds a POPULATED container whose one
    # entry carries no `tag` child, so a truthiness test splits those the wrong way.
    "sanctioned_application_count": build_integer_compiler(
        "sanctioned_application_count", "sanctioned_application_count"),
    # Applicability on the second record, and the DIRECTION of its default is the point: it is
    # TRUE until a pass computes it, so an unrecomputed single-vsys appliance raises a finding
    # that is checkable in a minute rather than vanishing from the report.
    "appliance_is_multi_vsys": build_boolean_compiler(
        "appliance_is_multi_vsys", "appliance_is_multi_vsys"),
    # The assertion of the second record. TRUE fires, and true is the stored default.
    "marking_is_inconsistent_across_vsys": build_boolean_compiler(
        "marking_is_inconsistent_across_vsys", "marking_is_inconsistent_across_vsys"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_sanctioned_application_marking_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_sanctioned_application_marking_search_node(c)
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
