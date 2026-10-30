"""Canonical search compiler for one dynamic routing adjacency. PAN-NET-007.

One row per adjacency within one router within one appliance. The router namespace is device-wide
on both routing engines, so there is no vsys axis. `protocol` is part of the identity because a
BGP peer and an OSPF attachment can carry the same name and are different things, and an
authentication reference resolves WITHIN one virtual router - measured - so the same profile name
on another router is a different object.

THE ROW'S EXISTENCE IS THE APPLICABILITY TEST, and that is why PAN-NET-007 carries no
applicability clause. A firewall routing only on static entries forms no adjacency and so
produces no row; there is nothing for a finding to attach to. Stage 4 measured the shape that
makes this safe: an absent peer-group means no adjacency exists, which makes the control
inapplicable, while an absent auth-profile collection means no authentication material exists,
which is the FAILING state - so a query that tested only for the auth-profile would have reported
seven routers unauthenticated on an estate where the control does not apply.

WHAT NO READ RETURNS, and it is the thing the control is really about: the key. The
authentication secret and the OSPF password are encrypted-text and cannot be read back from the
firewall at all, so whether a key is unique to an adjacency or shared across sites is
unanswerable from any read and no column here pretends to it. No field registered below reaches
a secret's value in any form, which is the database requirement rather than an environment one.

`max_prefixes` IS TEXT BECAUSE `unlimited` SHARES THE LEAF WITH A NUMBER, and it is a SENTINEL
rather than a magnitude: a present literal that is the negation of the field's purpose. It sorts
as a string, so every numeric comparison a query author reaches for skips it - which is the
inversion stage 5 named, and it is why `prefix_limit_state` is what a clause tests and this
column is registered for the page rather than for a control. It is also NULLABLE, and `is_empty`
cannot reach a NULL on a text column - measured, `filter(max_prefixes="")` returns no row for a
row holding NULL - so "no ceiling key at all" is not selectable here either. The verdict column
collapses absence and the keyword, which the firewall already treats the same.

`routing_engine` IS REGISTERED AND NO CLAUSE NAMES IT, which stage 7's validator recorded as
surplus. It stays because `unknown` is a real outcome a reader must be able to filter on: the
`advance-routing` leaf is absent on every lab appliance and `show advanced-routing` is refused on
all four, which is consistent with an implicit `no` but is a reading of the ENGINE's state rather
than of the leaf. A later stage using it to pick a tree must read `unknown` as "read both and say
so".
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import PanOsRoutingAdjacency

ROUTING_ADJACENCY_MODEL = "integrations.PanOsRoutingAdjacency"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return PanOsRoutingAdjacency.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return PanOsRoutingAdjacency.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # Identity. `protocol` is also PAN-NET-007's second half's SCOPE clause - it narrows which of
    # this model's rows that assertion is about without deciding whether the control applies.
    "router_name": build_text_compiler("router_name", "router_name"),
    "protocol": build_text_compiler("protocol", "protocol"),
    "adjacency_name": build_text_compiler("adjacency_name", "adjacency_name"),
    "routing_engine": build_text_compiler("routing_engine", "routing_engine"),
    # The two per-protocol references and the coalesced one. Blank and NOT nullable, so
    # `is_empty` - the one operator about absence - can reach them, which is what makes
    # "nothing is attached here" a selectable state. Empty means UNAUTHENTICATED: there is no
    # implied profile and no device-wide default to fall back to, measured as an absence in
    # three config views on four appliances.
    "bgp_authentication_profile": build_text_compiler(
        "bgp_authentication_profile", "bgp_authentication_profile"),
    "ospf_authentication_profile": build_text_compiler(
        "ospf_authentication_profile", "ospf_authentication_profile"),
    "authentication_profile": build_text_compiler(
        "authentication_profile", "authentication_profile"),
    "max_prefixes": build_text_compiler("max_prefixes", "max_prefixes"),
    # The two verdicts, one per half of PAN-NET-007. The REFERENCE BEING PRESENT IS NOT
    # AUTHENTICATION, which is why the first half rests on a strength grading and not on the
    # binding.
    "authentication_strength": build_text_compiler(
        "authentication_strength", "authentication_strength"),
    "prefix_limit_state": build_text_compiler("prefix_limit_state", "prefix_limit_state"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_routing_adjacency_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_routing_adjacency_search_node(c) for c in group["clauses"]]
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
