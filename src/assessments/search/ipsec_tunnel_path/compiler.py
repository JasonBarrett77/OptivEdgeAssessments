"""Canonical search compiler for one IPSec tunnel path. PAN-IKE-002 to -005, PAN-IPS-001 to -005.

ONE ROW PER TUNNEL-AND-GATEWAY PAIR, plus one per IKE gateway no tunnel on the appliance names.
Device-wide like the four collections it joins, so there is no vsys axis and no `scope` or
`vsys_name` field to register.

WHY THESE NINE CONTROLS MOVED HERE FROM THE TWO PROFILE MODELS. A crypto profile is a named
algorithm set and not an enforcement point: a finding raised on the profile reads the same whether
one tunnel uses it or a thousand do. Jason, 2026-11-04: *"A weak profile use on one IPSec tunnel
should not receive the same treatment as a weak profile used on 1000 IPSec tunnels. The best way
to accomplish this is to raise a finding per effected tunnel."* The clause field names are
UNCHANGED from the two profile compilers - `weakest_dh_group`, `dh_group_floor_met`,
`weakest_encryption_offered`, `lifetime_hours` and the rest - because the composite carries each
column under the name the shipped clause already used. Only each control's `control_type` moved.

`path_origin` IS REGISTERED BECAUSE THE FIVE IPSEC PAYLOAD CONTROLS NEED IT. An orphan-gateway
row has no tunnel on it, so it names no IPSec crypto profile, so every IPSec payload column on it
is blank or false - which is indistinguishable, to a clause, from a tunnel running on a profile
that offers nothing. Those five controls therefore carry `path_origin eq tunnel` as a conjunct
and the four IKE-side controls do not: a weak IKE proposal on a gateway nothing routes through is
still a weak proposal, and its row says so by holding a blank tunnel name.

AN UNRESOLVED PATH NEEDS NO CLAUSE OF ITS OWN, AND THAT WAS CHECKED RATHER THAN ASSUMED. Jason's
ruling makes an unresolvable binding fail, and the nine controls as shipped already fire on
exactly that state: each one's baseline is a NEGATED equality or a false verdict boolean -
`protocol_branch is not esp`, `weakest_encryption_offered is not aes-256-gcm`,
`dh_group_floor_met eq false` - and an unresolved path stores a blank in every value column and
leaves every verdict at its false default. So no query was added to any of the nine, and the
unresolved path reports at the control's DEFAULT severity: the per-value calibration queries
compare against value lists, a blank matches no member of one, and "we cannot tell what this
tunnel proposes" is not a reading that earns a calibrated grade.

`ike_crypto_unresolved` AND `ipsec_crypto_unresolved` ARE REGISTERED AND CLAUSED ON BY NOTHING
TODAY, along with the three `*_resolution` columns behind them. They are registered because the
three invalid configurations Jason named - a tunnel with no IKE gateway, a gateway naming no IKE
crypto profile, a tunnel left at `default` - are three distinct remedies that the nine controls
report as one undifferentiated baseline hit, and a control written for any one of them needs the
column to exist rather than to be added with it.

THE TWO APPLICABILITY COLUMNS ARE REGISTERED BECAUSE TWO SHIPPED CLAUSES NAME THEM.
`used_by_ikev2_gateway` carries PAN-IKE-005's fourth query and `all_offered_ciphers_authenticate`
carries PAN-IPS-003's whole clause set. Both keep the names their source columns have, so those
clauses ported unchanged - and `used_by_ikev2_gateway` is MEASURED here where the profile model
could only default it to True, because a path holds the gateway whose version answers it.

`is_disabled` AND `gateway_is_active` ARE DELIBERATELY ABSENT FROM THIS REGISTRY. Jason, 2026-11-04:
*"ignore the disabled flag for now. Do not differentiate between disabled=yes/no when generating
findings."* Both columns are stored and both are shown on the page; registering them would let a
clause reach a distinction the ruling says not to draw. PAN-IPS-008 keeps `is_disabled` on its own
subject, the tunnel object, where the disabled state IS the assertion.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import IpsecTunnelPath

IPSEC_TUNNEL_PATH_MODEL = "integrations.IpsecTunnelPath"

INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return IpsecTunnelPath.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return IpsecTunnelPath.objects.filter(
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
        return IpsecTunnelPath.objects.filter(**{lookup_field: value}).values("pk")
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
        return IpsecTunnelPath.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # The identity surface, as on every shipped compiler: `hostname` for a reader and
    # `serial_number` for uniqueness, both serving stage 5's single `appliance` column.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # The two names that identify a path. `tunnel_name` is EMPTY on an orphan-gateway row, which
    # is what `is_empty` is for here.
    "tunnel_name": build_text_compiler("tunnel_name", "tunnel_name"),
    "gateway_name": build_text_compiler("gateway_name", "gateway_name"),
    # The conjunct the five IPSec payload controls carry. See the module docstring.
    "path_origin": build_text_compiler("path_origin", "path_origin"),
    # The three-state resolutions, registered ahead of the controls that will name them.
    "gateway_resolution": build_text_compiler("gateway_resolution", "gateway_resolution"),
    "ike_crypto_resolution": build_text_compiler(
        "ike_crypto_resolution", "ike_crypto_resolution"),
    "ipsec_crypto_resolution": build_text_compiler(
        "ipsec_crypto_resolution", "ipsec_crypto_resolution"),
    "ike_crypto_unresolved": build_boolean_compiler(
        "ike_crypto_unresolved", "ike_crypto_unresolved"),
    "ipsec_crypto_unresolved": build_boolean_compiler(
        "ipsec_crypto_unresolved", "ipsec_crypto_unresolved"),
    # ---- the gateway's own settings: PAN-IKE-001, -006 and -007 keep their own subject, so
    # these three are registered for the page and for the clause a path-grained version of those
    # controls would need.
    "ike_version": build_text_compiler("ike_version", "ike_version"),
    "ikev1_exchange_mode": build_text_compiler("ikev1_exchange_mode", "ikev1_exchange_mode"),
    "peer_authentication": build_text_compiler("peer_authentication", "peer_authentication"),
    "uses_pre_shared_key": build_boolean_compiler(
        "uses_pre_shared_key", "uses_pre_shared_key"),
    # ---- PAN-IKE-002 to -005, under the names those controls' shipped clauses already use ----
    "ike_crypto_profile_name": build_text_compiler(
        "ike_crypto_profile_name", "ike_crypto_profile_name"),
    "weakest_dh_group": build_text_compiler("weakest_dh_group", "weakest_dh_group"),
    "dh_group_floor_met": build_boolean_compiler("dh_group_floor_met", "dh_group_floor_met"),
    "weakest_encryption_cipher": build_text_compiler(
        "weakest_encryption_cipher", "weakest_encryption_cipher"),
    "encryption_floor_met": build_boolean_compiler(
        "encryption_floor_met", "encryption_floor_met"),
    "weakest_hash_algorithm": build_text_compiler(
        "weakest_hash_algorithm", "weakest_hash_algorithm"),
    "hash_floor_met": build_boolean_compiler("hash_floor_met", "hash_floor_met"),
    "key_lifetime_hours": build_integer_compiler("key_lifetime_hours", "key_lifetime_hours"),
    "key_lifetime_known": build_boolean_compiler("key_lifetime_known", "key_lifetime_known"),
    "reauth_interval_bounded": build_boolean_compiler(
        "reauth_interval_bounded", "reauth_interval_bounded"),
    "used_by_ikev2_gateway": build_boolean_compiler(
        "used_by_ikev2_gateway", "used_by_ikev2_gateway"),
    # ---- PAN-IPS-001 to -005, likewise ----
    "ipsec_crypto_profile_name": build_text_compiler(
        "ipsec_crypto_profile_name", "ipsec_crypto_profile_name"),
    "protocol_branch": build_text_compiler("protocol_branch", "protocol_branch"),
    "weakest_encryption_offered": build_text_compiler(
        "weakest_encryption_offered", "weakest_encryption_offered"),
    "weakest_integrity_offered": build_text_compiler(
        "weakest_integrity_offered", "weakest_integrity_offered"),
    "all_offered_ciphers_authenticate": build_boolean_compiler(
        "all_offered_ciphers_authenticate", "all_offered_ciphers_authenticate"),
    "integrity_meets_sha2_floor": build_boolean_compiler(
        "integrity_meets_sha2_floor", "integrity_meets_sha2_floor"),
    "dh_group": build_text_compiler("dh_group", "dh_group"),
    "dh_group_meets_target": build_boolean_compiler(
        "dh_group_meets_target", "dh_group_meets_target"),
    "lifetime_hours": build_integer_compiler("lifetime_hours", "lifetime_hours"),
    "lifetime_within_target": build_boolean_compiler(
        "lifetime_within_target", "lifetime_within_target"),
    # ---- the tunnel's own monitoring columns, carried so one page answers the whole path.
    # PAN-IPS-006 and -007 keep their own subject and their own `*_determined` companions there.
    "anti_replay": build_boolean_compiler("anti_replay", "anti_replay"),
    "anti_replay_determined": build_boolean_compiler(
        "anti_replay_determined", "anti_replay_determined"),
    "tunnel_monitor_enable": build_boolean_compiler(
        "tunnel_monitor_enable", "tunnel_monitor_enable"),
    "tunnel_monitor_enable_determined": build_boolean_compiler(
        "tunnel_monitor_enable_determined", "tunnel_monitor_enable_determined"),
    "monitor_action_effective": build_text_compiler(
        "monitor_action_effective", "monitor_action_effective"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_ipsec_tunnel_path_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_ipsec_tunnel_path_search_node(c) for c in group["clauses"]]
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
