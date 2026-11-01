"""Canonical search compiler for one vsys's PAN-OS integrated User-ID agent settings.

PAN-UID-003 (client probing), PAN-UID-004 (the service account and session reading) and
PAN-UID-006 (mapping expiry) all query this surface. ONE ROW PER VSYS, so the owner is reached
through the enforcement point and the appliance lookups branch on either owner - `appliance` set
means locally managed, `appliance_group` set means Panorama-managed. That is the same two-path
shape every enforcement-point-owned compiler in this package uses.

THE NODE EXISTS NOWHERE IN THE ESTATE THIS WAS BUILT AGAINST. Stage 4 for `user-id` measured
`vsys/entry/user-id-collector/setting` absent on all four appliances and all twenty vsys, so
every clause here is today a clause about a vendor IMPLICIT rather than a stored value. Stage 7
writes the implicit into the row, which is what makes the clauses answerable at all - but it also
means an ABSENT ROW and a COMPLIANT ROW are different states and only the second is a pass. No
column of this model can tell them apart; a vsys whose merged read was missed has no row here and
is reported by nothing.

`wmi_account` IS TEXT AND ITS CLAUSE IS A NEGATED `is_empty`, WHICH IS NOT A STYLISTIC CHOICE.
PAN-UID-004 asserts that no directory principal is configured for server monitoring, so the
firing state is "this column holds something". There is no is-not-empty operator in this
language, so the clause is `is_empty` carrying the clause's own `negated` flag - and `is_empty`
is also the ONLY operator here that reaches the empty string positively, because every text
compiler in this package raises `SearchSyntaxError` on an empty `eq` value and
`evaluate_queryset_control_queries` CATCHES that and counts the query SKIPPED. A query written
as `eq ""` would therefore not fail loudly; it would vanish, and the control would ship narrower
than its catalog entry says. Measured by the `updates` run, 2026-11-01, and recorded in
`reference/consumer-repo-notes.md`.

`ip_user_mapping_timeout` IS AN INTEGER WITH NO NULL AND NO REACHABLE SENTINEL. Stage 5 measured
the absent key resolving to the vendor implicit 45, so there is no null for `gt 60` to miss -
which matters, because a `>` comparison drops a null row silently and the compliant direction
would have been the wrong one to guess. The value 0 is PLACED in stage 3's grading and is
unstorable: the device's write gate refuses it (`value=0 should be equal to or between 1 and
1440`), so no row can hold it and no query here reaches it. The never-expire state is the sibling
boolean `enable_mapping_timeout` being false, which is PAN-UID-006's other half - not 0.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import UserIdCollectorSettings

USER_ID_COLLECTOR_MODEL = "integrations.UserIdCollectorSettings"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        predicate = Q()
        for lookup in lookups:
            predicate &= Q(**{lookup: ""}) | Q(**{f"{lookup}__isnull": True})
        return predicate
    if not isinstance(value, str) or not value.strip():
        raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
    suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
    predicate = Q()
    for lookup in lookups:
        predicate |= Q(**{f"{lookup}__{suffix}": value.strip()})
    return predicate


def build_text_compiler(field_name, *lookups):
    def compiler(clause):
        return UserIdCollectorSettings.objects.filter(
            _text_filter(field_name, lookups, clause)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return UserIdCollectorSettings.objects.filter(**{lookup_field: value}).values("pk")
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
        return UserIdCollectorSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column: one column, two fields, and each field two lookup paths
    # because exactly one of the enforcement point's two owners is set.
    "hostname": build_text_compiler(
        "hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    # Stage 5's `enforcement_point` column. The row's identity IS the vsys, so this is part of
    # the subject rather than a convenience.
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # PAN-UID-003's assertion. TRUE fires: client probing sends the agent's credentials to
    # endpoints over WMI/NetBIOS, where anyone on a probed segment can capture and relay them.
    "enable_probing": build_boolean_compiler("enable_probing", "enable_probing"),
    # PAN-UID-004's SECOND record. TRUE fires - the firewall reads user sessions from the
    # monitored servers, which is the privilege the service account needs and the reason the
    # account's rights matter.
    "enable_session": build_boolean_compiler("enable_session", "enable_session"),
    # PAN-UID-004's FIRST record, and the one that cannot be written as an equality. See the
    # module docstring: the firing state is a NON-empty value, the clause is a negated
    # `is_empty`, and an `eq ""` here would be skipped rather than refused.
    "wmi_account": build_text_compiler("wmi_account", "wmi_account"),
    # PAN-UID-006's FIRST record. FALSE fires, which is the inverted-looking direction and is
    # right: expiry switched OFF means an IP-to-user mapping never expires, so identity outlives
    # the DHCP lease that justified it. Stage 5 measured the absent key's implicit as TRUE, so a
    # vsys that configures nothing passes this clause.
    "enable_mapping_timeout": build_boolean_compiler(
        "enable_mapping_timeout", "enable_mapping_timeout"),
    # PAN-UID-006's SECOND record and its GRADED column. The assertion is `gt 60` - stage 3's
    # acceptable rank is "60 or less", so 60 passes and 61 does not. No null to miss and no
    # reachable sentinel; see the module docstring.
    "ip_user_mapping_timeout": build_integer_compiler(
        "ip_user_mapping_timeout", "ip_user_mapping_timeout"),
    # REGISTERED AND UNQUERIED BY ANY SHIPPED CONTROL. Stage 5 names this column in the
    # `undetermined` of PAN-UID-005's monitored-server record - the half this domain leaves
    # silent - as the vsys collector's SSL/TLS service profile for the encrypted syslog
    # listener. It is registered so the clause exists the moment a control can hold it, and
    # `subjects_in_two_models` in the stage 8 artifact for `user-id` records which half is
    # silent and why.
    "syslog_service_profile": build_text_compiler(
        "syslog_service_profile", "syslog_service_profile"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_user_id_collector_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_user_id_collector_search_node(c) for c in group["clauses"]]
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
