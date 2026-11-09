"""Canonical search compiler for one appliance's log-database alarm mechanism. PAN-PLT-006.

THE SUBJECT IS A SINGLETON NODE under `deviceconfig/setting/management/
common-criteria-alarm-generation` - no entry name, no vsys axis, one row per appliance.

`alarm_mechanism_state` IS ONE ORDERED VERDICT AND NOT A CONJUNCTION OF THE LEAVES, and that is
stage 3's ordering rather than a convenience: "on but with no threshold recorded" is WORSE than
"on with thresholds and no notification route", and a clause list - one conjunction, no OR - says
nothing about which of two failures is worse. The normalizer resolves the master switch, the
threshold count and the two notification routes into one token and the control asserts a negated
equality against the single passing one.

AN ABSENT NODE AND AN EMPTIED CONTAINER ARE DIFFERENT VERDICTS, measured. Deleting the leaves
alone leaves a container that reads as PRESENT, which is `generation_off`, not `node_absent` - so
a truthiness test on the container reports an alarm mechanism where there is none.

`log_db_alarm_thresholds` IS A JSONField AND IS DELIBERATELY NOT REGISTERED, per the ban
`test_findings_rest_on_columns` enforces. WHAT CARRIES THE READING INSTEAD:
`log_db_alarm_threshold_count` is the scalar beside it and is registered below, and the verdict
column's `on_without_thresholds` token is what a control actually asserts on. Stage 5 marks the
JSON column `not_searchable` for the same reason.

A SEVERITY DIRECTION NO CLAUSE ON THIS SURFACE MAY ASSUME, recorded here because the hazard
outlives this control. A log-type threshold of `0` IS STORABLE - written, validated and committed
on one lab appliance, read back as `0` from the running view - and what it MEANS is unmeasured.
"Alarm always" and "alarm never" are both readings and nothing on the device says which, so a
clause ranking lower-is-stricter on the MAGNITUDE would be exactly inverted at the one value an
unconfigured-looking appliance would hold. `log_db_alarm_threshold_count` counts the log types
that carry a threshold and never reads their magnitude, which is why it is the safe scalar to
register; `log_db_alarm_threshold_lowest` is NOT registered, and that is the reason.

WHAT IS DELIBERATELY NOT REGISTERED BEYOND THAT: `alarm_settings_node_present`,
`alarm_generation_enabled`, `cli_alarm_notification_enabled`, `web_alarm_notification_enabled`
and `alarm_notification_route_present`. All five are inputs the normalizer already resolved into
the verdict, no clause or grading axis of this domain names any of them, and a clause on one would
re-derive an ordering the verdict already carries.

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
from optivedge_integrations.integrations.models import LogAlarmSettings

LOG_ALARM_SETTINGS_MODEL = "integrations.LogAlarmSettings"

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
        return LogAlarmSettings.objects.filter(
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
        return LogAlarmSettings.objects.filter(**{lookup_field: value}).values("pk")
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
        return LogAlarmSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler

FIELD_COMPILERS = {
    # Stage 5's `appliance` column as TWO fields. THE HA PAIR IS ONE ADDRESS FOR THIS NODE AND NOT
    # TWO, measured: `deviceconfig/setting` SYNCHRONISES on that pair - `setting/config/rematch`
    # reads the same value in RUNNING on both serials although only one was ever written - so the
    # two members cannot hold different values here. The serial is still registered, because the
    # two rows exist and a reader needs to know which appliance a row came from.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # PAN-PLT-006's assertion AND its grading column. Five placements; `on_with_thresholds_and_route`
    # is the only one producing no finding, and the node is ABSENT on every appliance this estate
    # shipped with.
    "alarm_mechanism_state": build_text_compiler(
        "alarm_mechanism_state", "alarm_mechanism_state"),
    # THE COLUMN THAT SAYS WHETHER ANYBODY LOOKED, declared by stage 5 as reading `fires` when
    # unknown, and ONE companion for all three measured booleans on this model rather than one
    # each - they come from the same node by the same read. It means the read answered AND the
    # node carried the master switch, which is NOT the same as the read answering: the first
    # version of the normaliser conflated them and stored "known" beside a null on both PA-5220s,
    # the exact circularity a companion exists to prevent.
    "alarm_generation_enabled_known": build_boolean_compiler(
        "alarm_generation_enabled_known", "alarm_generation_enabled_known"),
    # The scalar that carries the JSON threshold map's reading, per the module docstring: HOW MANY
    # log types carry a threshold, never how large one is.
    "log_db_alarm_threshold_count": build_integer_compiler(
        "log_db_alarm_threshold_count", "log_db_alarm_threshold_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_log_alarm_settings_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_log_alarm_settings_search_node(c) for c in group["clauses"]]
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
