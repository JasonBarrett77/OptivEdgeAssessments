"""Canonical search compiler for one interface's DHCP configuration. PAN-NET-004.

One row per interface per appliance, and A ROW EXISTS ONLY WHERE DHCP IS CONFIGURED on that
port. That is the shape the control turns on: PAN-NET-004's passing state for its server half is
the absence of the row, not a value in it, so a firewall with no DHCP produces nothing for any
query here to match. No row, no finding - which is right, and which is also why this page can
never answer "is DHCP correctly absent from this port".

THE ABSENCE OF THE CONTAINER IS NOT DISTINGUISHABLE FROM A PATH NOBODY READ, measured in
OptivEdgeIntegrations: an appliance with no DHCP and a collector that skipped `network/dhcp`
both produce nothing. For this control that is the direction that produces SILENCE rather than a
firing default, and no column on this model can carry it, because a reading about whether the
container was fetched has no row to live on when no row exists. It is the one gap in this domain
that fails quiet, and it is recorded in the stage 8 artifact rather than papered over here.

TWO VALUE COLUMNS ARE NULLABLE AND NEITHER IS WHAT THE ASSERTIONS CLAUSE ON.

* `dhcp_server_mode` is null where `server/mode` is absent - nobody has established whether the
  key is mandatory on a bare server branch, and two of its three values ENABLE the server, so a
  guess would be a guess about whether an unconfigured branch hands out addresses. The assertion
  rests on `dhcp_server_configured`, whose answer does not depend on the mode; this column grades
  the severity. A branch whose mode key is absent therefore falls into NONE of stage 5's three
  placements and is reported by the baseline alone - recorded, not fixed here.
* `dhcp_relay_ipv4_enabled` is null for the same reason and answers for ONE address family. The
  verdict beside it reads both.

`dhcp_relay_ipv4_enabled_known` IS A VIRTUAL FIELD OVER THAT COLUMN'S NULLNESS - the shipped
convention argued in `search/session_settings/compiler.py`, because `is_empty` does not exist for
a boolean field in any of the fourteen shipped compilers. Nothing shipped clauses on it; it is
registered because stage 5 marks the column searchable and because "the switch was never read"
is a question a reader of this page will want to ask, and the verdict beside it is what the
assertion rests on.

`dhcp_relay_state`'s DEFAULT IS ITS WORST MEMBER, deliberately: a row written before the
recompute pass reads `relaying` and over-reports, where the alternative would pass every
pre-existing row in silence.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import PanOsDhcpInterfaceConfig

DHCP_INTERFACE_CONFIG_MODEL = "integrations.PanOsDhcpInterfaceConfig"

def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return PanOsDhcpInterfaceConfig.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return PanOsDhcpInterfaceConfig.objects.filter(
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
        return PanOsDhcpInterfaceConfig.objects.filter(
            **{lookup_field: (not value) if invert else value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # The entry's own name, which is an INTERFACE name rather than an operator-chosen label -
    # measured as the shape of the node - so the namespace is the platform's port list.
    "interface_name": build_text_compiler("interface_name", "interface_name"),
    # The branch's EXISTENCE, which is not a value any key holds. PAN-NET-004's first half
    # asserts on this and not on the mode.
    "dhcp_server_configured": build_boolean_compiler(
        "dhcp_server_configured", "dhcp_server_configured"),
    "dhcp_server_mode": build_text_compiler("dhcp_server_mode", "dhcp_server_mode"),
    "dhcp_relay_ipv4_enabled": build_boolean_compiler(
        "dhcp_relay_ipv4_enabled", "dhcp_relay_ipv4_enabled"),
    "dhcp_relay_ipv4_enabled_known": build_boolean_compiler(
        "dhcp_relay_ipv4_enabled_known", "dhcp_relay_ipv4_enabled__isnull", invert=True),
    # The verdict across BOTH address families, which is what the second half asserts on: the
    # two families are independent switches, so a reading that tests one has answered for
    # neither.
    "dhcp_relay_state": build_text_compiler("dhcp_relay_state", "dhcp_relay_state"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_dhcp_interface_config_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_dhcp_interface_config_search_node(c) for c in group["clauses"]]
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
