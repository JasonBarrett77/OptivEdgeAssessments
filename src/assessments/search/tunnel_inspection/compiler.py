"""Canonical search compiler for one enforcement point's tunnel inspection coverage. PAN-NET-006.

One row per appliance per scope per vsys, and the row is a VERDICT over a rulebase rather than
one row per rule. The grain is the decision: an absent tunnel-inspect rulebase is this control's
FAILING state - the one object in this domain whose absence fires rather than passes - and a
per-rule row cannot report it, because there is no rule. An engineer fixing it does not open a
rule either; the rule they need does not exist.

THREE IDENTITY FIELDS AND ONE OF THEM IS A SCOPE, because a vsys's coverage can come from its own
rulebase or from a Panorama device group and the two are different answers about the same vsys.
`scope` says which config subtree the rules came from and NOT who owns it: a pushed rulebase is
device-group scope with a Panorama owner, and the two axes are separate.

`tunnel_inspect_rules_collected` IS REGISTERED AND MUST NOT BE CLAUSED ON AS APPLICABILITY. It is
the did-we-collect-it signal, and an applicability clause on a column like this one SUPPRESSES
the control when the answer is no - which reads as careful and is the exact inversion of what the
pipeline requires. Stage 5 says so in terms and the OptivEdgeIntegrations model repeats it. It is
registered so the page can REPORT it, and the count's firing default is what already covers the
case.

AND IT CANNOT BE FALSE ON ANY ROW THIS NORMALIZER WRITES, which stage 7's own validator flagged
as a gap: a row exists only where the merged snapshot was found and the vsys walked, so the flag
is True by construction and False is the migration default and nothing else. The failure it was
asked to separate - a collector that skipped the subtree - is not representable, because the
merged read is all-or-nothing per device. A clause written over it would therefore be a clause
over a constant.

FOUR OF THE EIGHT COVERAGE-STATE MEMBERS CANNOT BE COMPUTED FROM CONFIGURATION. `protocol_subset`,
`zone_pair_gap`, `single_level_only` and `overlay_id_scoped` each need to know what actually
transited, and so does `fully_opened`, which is the claim that everything transiting IS opened. A
configuration-only normalizer writes only the three it can establish, so the queries over the
other five match no row until a customer's traffic answer arrives. The counters that LOOK like an
answer are not one - `num-gtpu-active` and `num-active` read zero on all four lab appliances,
which is a lab with no traffic rather than an estate with no tunnels.

`tunnel_acceleration` MATTERS IN THE OPPOSITE DIRECTION FROM MOST SETTINGS: where acceleration is
on, the vendor says a GTP-U inspection rule is NOT required, so true is the state that NARROWS
the assertion. It is stored and presented and clauses on nothing - written as an applicability
clause it would suppress the whole control on every protocol wherever acceleration is on, which,
because an absent node asserts ENABLED, is every appliance that has never touched the setting.
The exemption is per PROTOCOL and is applied when the protocol list arrives.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import PanOsTunnelInspectionCoverage

TUNNEL_INSPECTION_MODEL = "integrations.PanOsTunnelInspectionCoverage"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return PanOsTunnelInspectionCoverage.objects.filter(
                **{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return PanOsTunnelInspectionCoverage.objects.filter(
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
        return PanOsTunnelInspectionCoverage.objects.filter(
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
        return PanOsTunnelInspectionCoverage.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "scope": build_text_compiler("scope", "scope"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    # ZERO is this control's worst rank and is also what an uncollected rulebase reads as, which
    # is why the flag below exists - and why it cannot do the job it was declared for.
    "tunnel_inspect_rule_count": build_integer_compiler(
        "tunnel_inspect_rule_count", "tunnel_inspect_rule_count"),
    "tunnel_inspect_rules_collected": build_boolean_compiler(
        "tunnel_inspect_rules_collected", "tunnel_inspect_rules_collected"),
    "tunnel_acceleration": build_boolean_compiler(
        "tunnel_acceleration", "tunnel_acceleration"),
    # The verdict. PAN-NET-006 asserts and grades on this one column.
    "tunnel_inspection_coverage_state": build_text_compiler(
        "tunnel_inspection_coverage_state", "tunnel_inspection_coverage_state"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_tunnel_inspection_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_tunnel_inspection_search_node(c) for c in group["clauses"]]
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
