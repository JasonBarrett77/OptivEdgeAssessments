"""Canonical search compiler for one appliance's device-wide LLDP enable.

One leaf, one row per appliance. `network/lldp` is device-wide, so no vsys axis and no scope
column; on an HA pair this is two rows for one real configuration.

NO SHIPPED CONTROL QUERIES THIS MODEL TODAY, and that is a recorded state rather than an
oversight. PAN-NET-003's assertions name TWO subjects - the per-interface announcement and this
device-wide enable - and `Control._CONTROL_TYPE_TARGET_MODEL` is one-to-one while
`ControlQuery.clean()` refuses a query whose model differs from its control's target, so one
catalogue control cannot hold both. The per-interface half took the control id, because seven of
the ten expectations stage 6 wrote for PAN-NET-003 are on it and all of its graded severities
are. Splitting PAN-NET-003 into two catalogue ids changes what a customer's report contains and
is Jason's decision, not a run's; this package exists so that the query is writable the moment
he makes it. See `pipeline/artifacts/stage8-network-hardening.json`,
`diff.subjects_in_two_models`.

`lldp_global_enable` IS NULLABLE AND THE NULL IS THE WHOLE ESTATE. The node is absent on every
lab appliance and what the absence MEANS is unmeasured in both directions - globally enabled by
default, in which case the preferred value is unmet everywhere, or globally disabled, in which
case the per-interface keys are moot. The one piece of evidence, zero frames transmitted on
three interfaces, is consistent with either reading because those interfaces also store
`enable: no` individually. So nothing is stored, and the null is reached through the virtual
field `lldp_global_enable_known` over `lldp_global_enable__isnull` - the shipped convention,
which `search/session_settings/compiler.py` sets out and which `address_object`'s `size_known`
took first. `is_empty` is NOT given a boolean meaning here or anywhere: it does not exist for a
boolean field in any of the fourteen shipped compilers.

AND THE BASELINE ALREADY REACHES IT, which the model's own comment denies. `models/
network_hardening.py` says "An appliance that has never touched the setting is therefore not
selectable by any single clause over this column." Measured here: `compile_search_clause`
negates at the pk-SET level, so `lldp_global_enable is not false` matches the NULL row - it is
absent from the positive subquery and therefore present in the complement. The comment is true
of plain SQL and false of this compiler.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import PanOsLldpGlobalSettings

LLDP_GLOBAL_MODEL = "integrations.PanOsLldpGlobalSettings"

def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return PanOsLldpGlobalSettings.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return PanOsLldpGlobalSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field, *, invert=False):
    """`invert` is for a field that answers whether something is KNOWN, over a column that stores
    the absence. The shipped convention - see `search/session_settings/compiler.py`."""
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return PanOsLldpGlobalSettings.objects.filter(
            **{lookup_field: (not value) if invert else value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "lldp_global_enable": build_boolean_compiler(
        "lldp_global_enable", "lldp_global_enable"),
    # FALSE means the firewall-wide state was never established, which is every appliance
    # measured so far. The group stage 5 declared as the second query of PAN-NET-003's record 1.
    "lldp_global_enable_known": build_boolean_compiler(
        "lldp_global_enable_known", "lldp_global_enable__isnull", invert=True),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_lldp_global_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_lldp_global_search_node(c) for c in group["clauses"]]
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
