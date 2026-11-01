"""Canonical search compiler for SNMP settings. PAN-SVC-004 and 005.

One row per appliance. `is_configured` is the gate both controls sit behind - controls.json says
"If SNMP is unused, leave snmp-setting unconfigured entirely", so an unconfigured device is the
compliant state and every query here has to exclude it explicitly.

`is_exposed` is resolved across the ManagementService rows rather than from this subtree: the
`snmp-setting` node says how SNMP would answer, and `disable-snmp` on each surface says whether
anything is listening. The search layer cannot traverse that edge, so normalization resolves it.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import SnmpSettings

SNMP_SETTINGS_MODEL = "integrations.SnmpSettings"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return SnmpSettings.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return SnmpSettings.objects.filter(
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
        return SnmpSettings.objects.filter(**{lookup_field: value}).values("pk")
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
        return SnmpSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "version": build_text_compiler("version", "version"),
    "is_configured": build_boolean_compiler("is_configured", "is_configured"),
    "uses_v2c": build_boolean_compiler("uses_v2c", "uses_v2c"),
    "version_implicit": build_boolean_compiler("version_implicit", "version_implicit"),
    "community_set": build_boolean_compiler("community_set", "community_set"),
    "community_is_default": build_boolean_compiler(
        "community_is_default", "community_is_default"),
    "is_exposed": build_boolean_compiler("is_exposed", "is_exposed"),
    "v3_user_count": build_integer_compiler("v3_user_count", "v3_user_count"),
    "v3_view_count": build_integer_compiler("v3_view_count", "v3_view_count"),
    # PAN-SVC-004's superseding assertion column and the two gradings, registered by stage 8 of
    # `device-services` on 2026-11-01. See the NTP compiler for why the two verdict columns take
    # the text compiler rather than the closed-choice one.
    #
    # `answers_on_an_unauthenticated_version` SELECTS EXACTLY THE ROWS `is_configured AND
    # uses_v2c` DOES, measured over all five reachable states of the normalizer
    # (`normalization/device_services.py::_snmp`): `uses_v2c` is `effective == "v2c"`,
    # `effective` is `version_name or ("v2c" if implicit else "")`, and `implicit` requires an
    # access-setting - so `implicit` implies `uses_v2c`, the stored disjunction has one reachable
    # member, and `uses_v2c` implies `is_configured`. `uses_v2c` STAYS REGISTERED: it is a
    # report column and a saved search may rest on it.
    "answers_on_an_unauthenticated_version": build_boolean_compiler(
        "answers_on_an_unauthenticated_version", "answers_on_an_unauthenticated_version"),
    "default_community_exposure": build_text_compiler(
        "default_community_exposure", "default_community_exposure"),
    # READS `v2c` ON A ROW WHOSE `version` IS EMPTY, which a reader of the name would not expect:
    # `snmp_version_in_force(configured=True, implicit=False, effective="")` falls through to
    # `V2C`, the state of an `snmp-setting` node carrying no `access-setting` at all. Every query
    # shipped over this column also carries PAN-SVC-004's assertion clause, which excludes that
    # row, so the control cannot report it - but an ad-hoc search on this field alone will.
    "snmp_version_in_force": build_text_compiler(
        "snmp_version_in_force", "snmp_version_in_force"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_snmp_settings_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_snmp_settings_search_node(c) for c in group["clauses"]]
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
