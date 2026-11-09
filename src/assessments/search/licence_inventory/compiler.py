"""Canonical search compiler for one appliance's entitlement set. PAN-PLT-004, both halves.

THE ROW IS A CONCLUSION ABOUT THE LICENSE TABLE AND NOT ONE LICENSE, which is what lets one
control report an entitlement that is MISSING. `integrations.LicenceEntitlement` carries the
per-license rows and has no compiler and no control type: no assertion record of this domain names
that subject, and an absent subscription has no row of its own to be queried.

TWO STATE COLUMNS AND NOT ONE, because PAN-PLT-004 is stated as two assertion records over this
one model. `entitlement_state` grades the protection subscriptions and `support_entitlement_state`
grades the support entitlement; the two lapse independently and carry different consequences - one
stops a content stream, the other stops software updates and the vendor's help during an incident.
Both are registered because each is the assertion of its own record and the grading axis of its
own calibrations. This is one type for one model carrying a control stated twice over, which is
why the stage 8 artifact declares NO silent half for it.

`entitlement_features_held` IS A JSONField AND IS DELIBERATELY NOT REGISTERED - the ban
`test_findings_rest_on_columns` enforces, and the right ban: a JSON lookup is unindexed and
matches NOTHING the day the vendor renames a key, so a control resting on one stops finding
anything instead of failing. WHAT CARRIES THE READING INSTEAD: `licence_row_count` is the scalar
beside it and is registered below, `licence_inventory_read` says whether the table answered at
all, and the FEATURE NAMES reach a reader through the finding's own sentence rather than through a
query. Stage 5 marks that column `not_searchable` for the same reason.

WHAT IS DELIBERATELY NOT REGISTERED BEYOND THAT: `expired_entitlement_count` and
`expiring_within_30_days_count`. Both are inputs the normalizer already resolved into
`entitlement_state`, no clause or grading axis of this domain names either, and a clause on a
count would re-derive a verdict this model publishes.

WHY THE STATE COLUMNS ARE REGISTERED AS TEXT AND NOT THROUGH `build_choice_compiler`, which
raises on a value outside the column's own `choices` and is the form this repository otherwise
prefers. THE EMPTY STRING IS A REACHABLE STATE OF `content_currency_state` AND IS NOT IN ITS
CHOICE LIST: the normalizer returns it for an appliance whose `show system info` never answered
while its merged configuration did, and it is deliberate - a token there would be a verdict over
a reply nobody received. A choice compiler reading its members off `choices` could not express a
query for that state at all, and the text compiler's `is_empty` arm, which ORs an `__isnull`
term, is the only operator in this language that reaches it. The cost is named rather than
hidden: a MISSPELLED token in a catalog payload compiles here and matches nothing, where the
raising form would refuse it. The baseline's negated equality is what limits the damage - it
fires on every value that is not the passing token, misspelled calibrations included - so a
typo loses a RANK and never a finding.
"""
from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import LicenceInventory

LICENCE_INVENTORY_MODEL = "integrations.LicenceInventory"

#: Every integer field here offers the same five. `is_empty` is a TEXT operator and has no
#: integer equivalent, which is safe on this model: every comparison below is one a NULL fails,
#: so an unread column cannot pass an integer clause.
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
        return LicenceInventory.objects.filter(
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
        return LicenceInventory.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in INTEGER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        # `bool` IS REJECTED EXPLICITLY AND THE REASON IS A TEST, not tidiness:
        # `isinstance(True, int)` is true, and `test_findings_rest_on_columns` probes `True`
        # BEFORE `1`, so without this an integer field would compile `field=True` as `field=1`
        # and be vouched for on a value no clause would ever carry.
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return LicenceInventory.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler

FIELD_COMPILERS = {
    # Stage 5's `appliance` column as TWO fields. Entitlements are device-wide and not
    # vsys-scoped, and a licence is per SERIAL - so on an HA pair the two peers' rows may
    # legitimately differ and the serial is the field that distinguishes them.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # PAN-PLT-004 record 0's assertion AND its grading column: the protection subscriptions.
    "entitlement_state": build_text_compiler("entitlement_state", "entitlement_state"),
    # PAN-PLT-004 record 1's assertion AND its grading column: the support entitlement. NO
    # APPLIANCE IN THIS ESTATE CARRIES ONE, so `absent_from_inventory` is the only value measured
    # - and it is a finding rather than a pass, because an absent row cannot be told from a
    # subscription nobody bought.
    "support_entitlement_state": build_text_compiler(
        "support_entitlement_state", "support_entitlement_state"),
    # THE COLUMN THAT SAYS WHETHER ANYBODY LOOKED, declared by stage 5 as reading `fires` when
    # unknown and named IN BOTH RECORDS' `undetermined` prose as the second clause group's column:
    # "`licence-inventory.licence_inventory_read` is not `rows_returned`, role assertion". It is
    # registered so that group is buildable, and it is the field that tells the estate's trap
    # apart from an answer - `{"licenses": null}` is the PRESENT-and-EMPTY shape both PA-5220s
    # return, which is `null_licenses_element` and not `not_collected`.
    "licence_inventory_read": build_text_compiler(
        "licence_inventory_read", "licence_inventory_read"),
    # The scalar that carries the JSON feature list's reading, per the module docstring. No clause
    # of this domain uses it; it is registered because a surface that bans the JSONField owes a
    # column that can answer "how many rows did the table return".
    "licence_row_count": build_integer_compiler("licence_row_count", "licence_row_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_licence_inventory_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_licence_inventory_search_node(c) for c in group["clauses"]]
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
