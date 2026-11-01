"""Canonical search compiler for interface management profiles.

The searchable unit is the profile ON ONE APPLIANCE. A profile pushed from a Panorama
template exists separately in each firewall's merged config, and bound on one device but
not another it is genuinely two different facts - so the row, and the finding, are per
appliance rather than per template.

`binding_count` is the field that matters and it is an ordinary column: normalization
counts the bindings from the same payload in the same pass, so asking "is this unused" here
is a scalar comparison rather than a join against the surfaces the profile did not create.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import InterfaceManagementProfile

INTERFACE_MANAGEMENT_PROFILE_MODEL = "integrations.InterfaceManagementProfile"

INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return InterfaceManagementProfile.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains",
                  "starts_with": "istartswith", "ends_with": "iendswith"}.get(op, "iexact")
        return InterfaceManagementProfile.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def compile_binding_count_clause(clause):
    op, value = clause["op"], clause["value"]
    if op not in INTEGER_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for binding_count: {op}.")
    if isinstance(value, bool) or not isinstance(value, int):
        raise SearchSyntaxError("binding_count search value must be an integer.")
    suffix = {"eq": "exact"}.get(op, op)
    return InterfaceManagementProfile.objects.filter(
        **{f"bound_interface_count__{suffix}": value}).values("pk")


compile_binding_count_clause.SUPPORTED_OPERATORS = INTEGER_OPERATORS

FIELD_COMPILERS = {
    "binding_count": compile_binding_count_clause,
    "name": build_text_compiler("name", "name"),
    # PAN-MGT-013's GRADING AXIS - what this profile WOULD expose if somebody attached it, as
    # one of three classes. The baseline fires on `binding_count eq 0` regardless; this column
    # decides at which of stage 3's three ranks an unused definition is reported.
    #
    # A COUNTERFACTUAL AND NOT A READING OF A SURFACE, which is the whole reason it is stored on
    # this model: `ManagementService` holds a profile's services keyed to the SURFACE where they
    # matter, and an unattached profile creates no surface, so nothing anywhere else says what
    # an unused profile would have enabled.
    #
    # `CharField(choices=..., default=EXPOSURE_UNENCRYPTED)` - not nullable, no empty state - so
    # `eq` over the three tokens reaches every value the column can hold and the text compiler's
    # `is_empty` arm is registered and unreachable rather than absent. The default is the WORST
    # class: a profile nobody has classified has not been shown to be harmless.
    #
    # WHERE `snmp` FALLS IS A DECLARED JUDGEMENT AND NOT A MEASUREMENT, which the integrations
    # classifier's own docstring argues and stage 7 filed as a spec gap: nothing in stage 5 says
    # which services belong to which class, four of the five administrative services place
    # themselves, and SNMP was classified `monitoring_or_nothing` on the grounds that the
    # mildest class means "answerable but not administrable" and SNMP is a community-string read
    # rather than a login. A clause here inherits that judgement; it does not re-make it.
    "unbound_exposure_class": build_text_compiler(
        "unbound_exposure_class", "unbound_exposure_class"),
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
}

FIELD_OPERATOR_REGISTRY = {
    name: getattr(compiler, "SUPPORTED_OPERATORS", TEXT_OPERATORS)
    for name, compiler in FIELD_COMPILERS.items()
}


def compile_interface_management_profile_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_interface_management_profile_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    field = clause["field"]
    compiler = FIELD_COMPILERS.get(field)
    if compiler is None:
        raise SearchSyntaxError(
            f"Unsupported search field for {INTERFACE_MANAGEMENT_PROFILE_MODEL}: {field}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause.get("negated") else predicate
