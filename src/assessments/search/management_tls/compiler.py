"""Canonical search compiler for the management interface's SSL/TLS binding.

PAN-MGT-010 and PAN-CRT-006. One row per appliance.

THREE FIELDS ARE READ THROUGH A JOIN - `min_version`, `max_version`, `certificate_name` live on
the `SslTlsServiceProfile` row the binding points at, not on the binding. That is the fix for the
drift the aggregate suffered, and it puts one trap in this file: `is_empty` over a joined field.

An UNRESOLVED binding - a name that matches no row - has a null key, and a plain
`ssl_tls_service_profile__min_version=""` does not match a null join. PAN-MGT-010's fourth clause
is exactly "a profile is bound and its floor is empty", and it exists to catch dangling bindings,
so a naive lookup would silently stop reporting the case it was written for. `is_empty` on a
joined field therefore means "no row, or a row whose value is empty".
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import ManagementTlsBinding

MANAGEMENT_TLS_MODEL = "integrations.ManagementTlsBinding"

#: The key a joined field is read through. Empty for a field stored on the binding itself.
_JOIN = "ssl_tls_service_profile"


def build_text_compiler(field_name, lookup_field, *, joined=False):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            predicate = Q(**{lookup_field: ""})
            if joined:
                # No row at all is empty too - see the module docstring.
                predicate |= Q(**{f"{_JOIN}__isnull": True})
            return ManagementTlsBinding.objects.filter(predicate).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return ManagementTlsBinding.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    """THE FIRST BOOLEAN FIELD ON THIS MODEL, added for PAN-MGT-010's derived verdict.

    Every field registered here before it was text, two of them read through the join. `eq` is
    the only operator a boolean can carry, and the value is type-checked rather than coerced:
    `eq "false"` on a boolean column is a catalogue payload bug, and Python reads the non-empty
    string as TRUE and matches the opposite rows in silence.
    """

    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return ManagementTlsBinding.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "profile_name": build_text_compiler("profile_name", "profile_name"),
    "profile_scope": build_text_compiler("profile_scope", "profile_scope"),
    "certificate_trust": build_text_compiler("certificate_trust", "certificate_trust"),
    "certificate_scope": build_text_compiler("certificate_scope", "certificate_scope"),
    "certificate_issuer": build_text_compiler("certificate_issuer", "certificate_issuer"),
    "min_version": build_text_compiler(
        "min_version", f"{_JOIN}__min_version", joined=True),
    "max_version": build_text_compiler(
        "max_version", f"{_JOIN}__max_version", joined=True),
    "certificate_name": build_text_compiler(
        "certificate_name", f"{_JOIN}__certificate_name", joined=True),
    # PAN-MGT-010's ASSERTION, AND IT REPLACES AN ENUMERATION THAT UNDER-REPORTED. The shipped
    # baseline was four OR branches - `profile_name is_empty`, `min_version eq tls1-0`,
    # `min_version eq tls1-1`, and a bound-but-empty-floor branch - and stage 8 of
    # `management-services` moved the assertion onto this column on 2026-11-01.
    #
    # WHAT THE ENUMERATION MISSED, which is one reachable state and not a style preference: a
    # bound profile whose stored floor is a token that is none of the four the device offers.
    # The enumeration's value branches do not match it, its empty branch does not match it
    # because the value is not empty, and so it read as COMPLIANT. This column asks
    # `SslTlsServiceProfile.min_version_rank`, whose `RANK_UNRECOGNISED = -1` sorts BELOW
    # `tls1-0` so every "the floor is too low" comparison FIRES on it - and that column's own
    # comment names the enumerated query as the defect it exists to prevent. So the two
    # populations differ on exactly that state and this one is the superset.
    #
    # IT ALSO FOLDS IN THE NULL JOIN no comparison on `min_version` reaches: `min_version` is a
    # PROPERTY read through `ssl_tls_service_profile`, so with no profile row there is nothing
    # for a comparison to compare. True where the floor is withdrawn AND true where no floor
    # could be resolved at all - nothing bound, a name resolving nowhere, or a resolved profile
    # carrying no protocol-settings.
    #
    # DEFAULT TRUE ON THE MODEL, deliberately: a binding nobody has recomputed is reported as
    # serving a withdrawn generation, on the column an administrator's own session is negotiated
    # against. The opposite default would pass every appliance in the estate during the window
    # between the migration and the normalization pass with nothing erroring.
    "floor_below_minimum": build_boolean_compiler(
        "floor_below_minimum", "floor_below_minimum"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_management_tls_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_management_tls_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause.get("negated") else predicate
