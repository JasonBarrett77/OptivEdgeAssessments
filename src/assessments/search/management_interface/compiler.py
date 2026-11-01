"""Canonical search compiler for management surfaces.

The searchable unit is the SURFACE - MGT, Aux-1, or a named data-plane interface - because
that is what a finding names. "10.0.0.0/8 is allowed" is not reportable; "allowed to
ethernet1/1" is.

`exposure` is the field that matters and it is semantic rather than a column. It is computed
in Python and returned as a pk queryset, which is what the field-compiler contract already
expects. That is affordable here in a way it would not be for security rules: a surface is
one row per management plane per appliance, so tens of rows, not thousands.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.management_interface.fields.exposure import (
    EXPOSURE_STATES,
    SUPPORTED_OPERATORS as EXPOSURE_OPERATORS,
    compile_exposure_clause,
)
from assessments.search.management_interface.fields.services import (
    SUPPORTED_OPERATORS as SERVICE_OPERATORS,
    compile_service_enabled_clause,
)
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import ManagementInterface

MANAGEMENT_INTERFACE_MODEL = "integrations.ManagementInterface"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        return ManagementInterface.objects.filter(
            **_text_lookup(clause, field_name, lookup_field)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    """A stored verdict column on the surface itself, as against a child service row.

    THE FIRST BOOLEAN FIELD ON THIS SURFACE, added for PAN-UID-005's companion column. Every
    field registered here before it was either text on the surface or a membership test over the
    `services` child rows, so there was no boolean builder to reuse. `eq` is the only operator a
    boolean can carry, and the value is type-checked rather than coerced: `eq "false"` on a
    boolean column is a catalogue payload bug, and Python would read the non-empty string as
    TRUE and match the opposite rows in silence.
    """

    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return ManagementInterface.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def _text_lookup(clause, field_name, lookup_field):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        # Advertised by TEXT_OPERATORS and never implemented here. Nothing offered these
        # operators to a person until the configuration query builder rendered the compiler's
        # own registry, and then the dropdown carried an operator that could only ever error.
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        return {lookup_field: ""}
    if not isinstance(value, str) or not value.strip():
        raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
    suffix = {"eq": "iexact", "contains": "icontains",
              "starts_with": "istartswith", "ends_with": "iendswith"}.get(op, "iexact")
    return {f"{lookup_field}__{suffix}": value.strip()}


FIELD_COMPILERS = {
    "exposure": compile_exposure_clause,
    "service_enabled": compile_service_enabled_clause,
    "plane": build_text_compiler("plane", "plane"),
    "interface_name": build_text_compiler("interface_name", "interface_name"),
    "profile_name": build_text_compiler("profile_name", "profile_name"),
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # PAN-UID-005's COMPANION COLUMN, and the only honest answer to "did anybody look".
    # `service_enabled` above reads as COMPLIANT when nobody looked - an absent child service
    # row matches no membership test and SQL drops it - so a surface nobody collected passes
    # the listener clause silently. Stage 5 declares this column as that clause's companion and
    # declares its own `when_unknown.reads_as` as `fires`, which is stage 5 saying it is THE
    # COLUMN THAT ANSWERS THE QUESTION: FALSE fires.
    #
    # THE MEASURED INSTANCE IT EXISTS FOR IS THE AUXILIARY PLANES. Stage 4 for `user-id`
    # measured the AUX-1 and AUX-2 service nodes existing on a PA-5220 with the User-ID
    # listener keys ABSENT, while the payload contract's `applies_to` names only
    # /deviceconfig/system/service - so on an auxiliary plane with no service node nothing in
    # this project establishes anything, and `rules.md` holds that an unknown fires.
    "userid_listener_state_established": build_boolean_compiler(
        "userid_listener_state_established", "userid_listener_state_established"),
}

FIELD_OPERATOR_REGISTRY = {
    name: getattr(compiler, "SUPPORTED_OPERATORS", TEXT_OPERATORS)
    for name, compiler in FIELD_COMPILERS.items()
}


def compile_management_interface_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_management_interface_search_node(c) for c in group["clauses"]]
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
