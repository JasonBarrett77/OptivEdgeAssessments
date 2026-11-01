"""Canonical search compiler for one enforcement point's outward data-filtering posture.
PAN-FIL-003.

ONE ROW PER ENFORCEMENT POINT, and the row is a CONCLUSION rather than a profile. The commonest
failing state of this domain is NO DATA-FILTERING PROFILE AT ALL - three of the four lab
appliances - and `/config/predefined/profiles/data-filtering` is absent on every one of them, so
unlike file blocking there is nothing the vendor ships to fall back on. A profile-keyed row
reports nothing on exactly the devices that fail, which is why the subject is the point. Same
shape as the three SaaS postures and `rulebase_device_match`.

THE VERDICT IS ONE COLUMN AND NOT THREE CLAUSES, which is a stage 5 decision this compiler only
has to respect. The assertion has three parts that fail INDEPENDENTLY - no profile in force; one
in force that names no pattern; one naming a pattern object that defines nothing - and a control
query's clause list is one conjunction with no OR, so three clauses would fire only where all
three failed. `outward_data_filtering_effective` is the conjunction, computed at normalization,
and the three parts stay beside it as their own columns so the finding can say WHICH one failed.

TWO OF THOSE THREE PARTS ARE REGISTERED HERE AND ONE IS NOT. `data_filtering_in_force` and
`named_patterns_defined` are registered because a reader of a PAN-FIL-003 finding needs the cell
that failed, and because the verdict alone cannot tell "nobody configured data filtering" from
"somebody referenced a profile whose pattern object matches nothing" - two different remediations.
`profiles_in_force` is NOT registered and must not be: it is a JSONField, the evidence list a
human reads beside the verdict, and `test_findings_rest_on_columns` fails any registered field
that resolves to one.

WHAT IS DELIBERATELY NOT REACHABLE FROM HERE. The second half of PAN-FIL-003 - every rule of a
watching profile carries both the alert and the block count - clauses on
`integrations.SecurityProfile`. `ControlQuery.clean()` refuses a query whose model differs from
its control's target, and standing ruling 6's remedy is to reach the other half by a relation.
That relation does not work in this direction and the reason is measured, not stylistic:
`SecurityProfile.enforcement_point` IS NULLABLE, because a shared-scope profile hangs off the
appliance group instead - so `enforcement_point__security_profiles__*` misses the shared-scope and
pushed subjects entirely, and widening to the group would fire this point's row for a profile in
another vsys. A to-many walk DOWNWARD also changes what the row means: ruling 6's own examples
walk to-ONE upward (an interface to the firewall-wide switch above it), where the row's grain
survives. At this grain one point's row cannot name which profile failed. The stage 8 artifact
records that half as silent in `subjects_in_two_models`; what would close it is a column on THIS
model carrying the quantifier at this grain, which stage 8 may not add.

NO is-null OPERATOR EXISTS IN THIS LANGUAGE and none is invented here. Every column this compiler
registers is a non-nullable boolean whose default is the FIRING side - false - so an enforcement
point nobody has normalised reports rather than reading as a clean estate, which is the same
property `rulebase_device_match` relies on in the other direction.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import DataFilteringPosture

DATA_FILTERING_POSTURE_MODEL = "integrations.DataFilteringPosture"


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
        return DataFilteringPosture.objects.filter(
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
        return DataFilteringPosture.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column: ONE COLUMN, TWO FIELDS, which is the convention every shipped
    # compiler in this package follows. This model carries its own `appliance` FK as well as the
    # point's, and the direct one is authoritative - the posture row is written per point of a
    # named appliance - so it is the first lookup and the point's is the fallback for a row whose
    # appliance is reached through the group.
    "hostname": build_text_compiler(
        "hostname", "appliance__hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "appliance__serial_number",
        "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    # Stage 5's `enforcement_point` column - the point this verdict is about. A multi-vsys
    # appliance can have one vsys watched and another not, which is why the row is per point.
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # PAN-FIL-003's assertion clause. FALSE fires, and false is the stored default.
    "outward_data_filtering_effective": build_boolean_compiler(
        "outward_data_filtering_effective", "outward_data_filtering_effective"),
    # The two parts of that conjunction, registered so the finding can colour the cell that
    # actually failed rather than the verdict alone. Stage 5 marks both `needs_compiler_field`
    # and the domain names both in PAN-FIL-003's clause note.
    "data_filtering_in_force": build_boolean_compiler(
        "data_filtering_in_force", "data_filtering_in_force"),
    "named_patterns_defined": build_boolean_compiler(
        "named_patterns_defined", "named_patterns_defined"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_data_filtering_posture_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_data_filtering_posture_search_node(c) for c in group["clauses"]]
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
