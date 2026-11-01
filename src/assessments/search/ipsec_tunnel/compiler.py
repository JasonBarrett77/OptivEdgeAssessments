"""Canonical search compiler for one named IPSec tunnel. PAN-IPS-006, 007 and 008.

One row per named entry per appliance, device-wide like the crypto profile at the sibling path,
so there is no vsys axis and no `scope` or `vsys_name` field to register.

THE TWO `*_determined` COLUMNS ARE THE POINT OF THIS MODULE AND ARE REGISTERED FOR THAT REASON.
`anti_replay` and `tunnel_monitor_enable` are both `null=True`, and a NULL matches no positive
comparison - so `anti_replay eq false` cannot reach a tunnel whose `anti-replay` key is simply
ABSENT, and that row would pass the control in silence. There is no is-null operator anywhere in
this query language and this module does not invent one. Instead each nullable boolean has a
NON-NULLABLE companion that fires on its own: `anti_replay_determined` and
`tunnel_monitor_enable_determined`, both `default=False`, both carrying their own query at their
record's own severity. The two queries on a pair cannot both match one row - a key is either
present or absent - so nothing is reported twice and no unread tunnel is silent.

AND THE FINDING TEXT FOR THE COMPANION SAYS "NOT DETERMINED" RATHER THAN "OFF", which stage 5
names as the whole distinction: materialising `false` would raise a finding on behalf of a
measurement nobody took, and materialising `true` would clear every tunnel that never mentions
the field. Stage 4 measured no implicit for either key.

`is_empty` OVER A BOOLEAN IS REFUSED RATHER THAN MERELY INEFFECTIVE, and that is why the pair
above exists rather than a clever operator. Every boolean compiler here sets its supported
operators to equality alone, so `is_empty` raises `SearchSyntaxError` - which
`evaluate_queryset_control_queries` CATCHES and counts as a SKIPPED query. A clause reaching for
it would not fail loudly, it would vanish, and the control would ship narrower than its artifact
says.

ONLY THE COLUMNS A CONTROL ASKS FOR ARE HERE. `tunnel_monitor_destination_ip`,
`tunnel_monitor_profile_name`, `monitor_action_effective` and `crypto_profile_name` are stored
and searchable and NO clause or grading of this domain names one, so none is registered - and
the first two are `null=True` text columns, where the bare `is_empty` shape this repo's majority
compiles would have matched nothing on exactly the population a clause over them would be
written for. Not registering them is the narrow reading the compiler's own rule asks for and it
avoids that trap rather than documenting it.

`ike_gateway_names` IS A JSONField AND IS DELIBERATELY UNREACHABLE. `test_findings_rest_on_
columns` refuses a registered JSONField outright, and nothing in this domain names it:
PAN-IPS-008's orphaned-gateway half does not exist, because the IKE gateway object was never
measured by this domain's stage 4.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import IpsecTunnel

IPSEC_TUNNEL_MODEL = "integrations.IpsecTunnel"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return IpsecTunnel.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return IpsecTunnel.objects.filter(
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
        return IpsecTunnel.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # The identity surface, as on every shipped compiler: `hostname` for a reader and
    # `serial_number` for uniqueness, both serving stage 5's single `appliance` column.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "tunnel_name": build_text_compiler("tunnel_name", "tunnel_name"),
    # PAN-IPS-008 ASSERTS ON THE TRUE SIDE OF THIS, which is the opposite direction from every
    # other verdict column in this domain: a tunnel left switched off IS the finding. So no
    # applicability clause suppresses a disabled tunnel here, and the three controls over this
    # model all fire on tunnels nothing is routed through.
    "is_disabled": build_boolean_compiler("is_disabled", "is_disabled"),
    # The two nullable booleans and their non-nullable companions. See the module docstring:
    # the companion is the only thing that reaches the absent key, and it is a separate query
    # rather than a disjunct because the query layer ships no OR in this contract.
    "anti_replay": build_boolean_compiler("anti_replay", "anti_replay"),
    "anti_replay_determined": build_boolean_compiler(
        "anti_replay_determined", "anti_replay_determined"),
    "tunnel_monitor_enable": build_boolean_compiler(
        "tunnel_monitor_enable", "tunnel_monitor_enable"),
    "tunnel_monitor_enable_determined": build_boolean_compiler(
        "tunnel_monitor_enable_determined", "tunnel_monitor_enable_determined"),
    # PAN-IPS-009's TUNNEL HALF, REGISTERED AND NOT CARRIED BY A SHIPPED CONTROL. The control
    # ships as the PROFILE half - one `target_model`, one half reachable - so this field has no
    # query on it today. It is registered because it is the column that answers the tunnel-side
    # question and the day the other half gets its own control id, the surface is already here.
    # The stage 8 artifact for `ipsec-crypto` records the choice and names the silent half.
    "effective_crypto_profile_chosen": build_boolean_compiler(
        "effective_crypto_profile_chosen", "effective_crypto_profile_chosen"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_ipsec_tunnel_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_ipsec_tunnel_search_node(c) for c in group["clauses"]]
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
