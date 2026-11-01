"""Canonical search compiler for one appliance's dynamic content update schedule.

PAN-UPD-001, -002, -004 and -005. One row per appliance carrying all five content types as their
own columns, so FOUR controls query this one model and each reads its own content type's pair.

TEN COLUMNS IN FIVE PAIRS, AND NINE OF THEM ARE REGISTERED. Each content type has a recurrence
and an action; a control asserts on the recurrence, and on the action where stage 5 states that
half as its own assertion record. `wildfire_action` IS DELIBERATELY NOT REGISTERED and it is the
only omission in this family: PAN-UPD-004 clauses on the recurrence alone, because `real-time`
and `none` carry no `action` child at all, so `wildfire_action` holds `none` on exactly the one
compliant configuration and a second conjunct over it would fire on the rows the control means to
pass. Stage 5 records that as subsumed rather than claused, and registering the column anyway
would ship a search surface no control asks for.

`threats_threshold_hours` AND `threats_new_app_threshold_hours` ARE ALSO NOT REGISTERED, for a
different reason. They are PAN-UPD-003's columns and stage 5 discharges both of that control's
records `engineer_answers`: a long value and an absent one can each be correct depending on an
answer only the engineer who set it holds, so no clause can fire correctly and none is written.
The columns are stored and presented; they are not queried.

THE EMPTY STRING IS A REACHABLE STATE OF ALL TEN TEXT COLUMNS, AND `is_empty` IS THE ONLY
OPERATOR IN THIS LANGUAGE THAT REACHES IT POSITIVELY. An appliance whose `deviceconfig/system`
node arrived empty holds `""` on every recurrence and action column - the normaliser writes it
rather than `none`, because `none` would say "we read it and nothing is scheduled" about a reply
nobody received. The text filter's `eq` arm REFUSES an empty value outright (`not
value.strip()`), so a query that must name that state positively has to use `is_empty`, whose arm
ORs an `__isnull` term. A NEGATED equality reaches `""` without it, because the subquery it
negates selects only rows holding the named token.

THIS IS WHY THE COLUMNS ARE REGISTERED AS TEXT AND NOT THROUGH A CHOICE COMPILER. A compiler
reading its members off a `choices` list could not express the empty state at all, and these
columns carry no `choices`: the normaliser writes the device's own branch name, and a cadence a
later PAN-OS build adds should REPORT rather than be refused here. The cost is named rather than
hidden - a misspelled token in a catalogue payload compiles and matches nothing - and what limits
it is that every baseline in this domain is a negated equality, so a typo in a calibration loses
a RANK and never a finding.

AND ONE ASYMMETRY BETWEEN THE TWO COLUMN FAMILIES, because it decides what a partition over them
can claim. The RECURRENCE columns are closed: the normaliser collapses any branch name outside
the measured set to `none`, so a recurrence column holds a measured member, `none`, or `""` and
nothing else. The ACTION columns are NOT closed in the same way: the leaf's value is passed
through verbatim with only a falsy fallback to `none`, so a third action token the grammar might
one day offer would be stored as itself. The device's action set is measured as exactly
{download-only, download-and-install} by `config_complete` with a body at the leaf on both lab
platforms and corroborated as an inline CLI enum, so the four tokens an action column can hold
today are those two plus `none` plus `""` - but that is a measurement of the grammar rather than
a constraint the store enforces.
"""
from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import ContentUpdateSchedule

CONTENT_UPDATE_SCHEDULE_MODEL = "integrations.ContentUpdateSchedule"


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
        return ContentUpdateSchedule.objects.filter(
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
        return ContentUpdateSchedule.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column as TWO fields, which is this repository's convention and what
    # every shipped compiler does. The schedule is per APPLIANCE with no vsys axis, and on an HA
    # pair the two peers legitimately hold DIFFERENT schedules - the node does not sync across
    # peers - so the serial is the field that tells the two rows apart when the hostnames are
    # similar, and the hostname is the one a reader recognises.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # THE COLUMN THAT SAYS WHETHER ANYBODY LOOKED. Stage 5 declares it reading `fires` when
    # unknown and names it in the `undetermined` prose of PAN-UPD-001[0], -004[0] and both
    # PAN-UPD-005 records as the column that distinguishes an unread appliance from a configured
    # absence. No clause of this domain carries it - every record reaches the unread state
    # through the empty string instead - and it is registered because those four records name it
    # as the answer to "is this unknown" and a reader of any finding here needs to be able to ask.
    "update_schedule_collected": build_boolean_compiler(
        "update_schedule_collected", "update_schedule_collected"),
    # ANTIVIRUS. PAN-UPD-001: record 0's assertion AND its grading axis is the recurrence,
    # record 1's assertion is the action. `hourly` is this content type's measured ceiling.
    "av_recurrence": build_text_compiler("av_recurrence", "av_recurrence"),
    "av_action": build_text_compiler("av_action", "av_action"),
    # APPLICATIONS AND THREATS. PAN-UPD-002, the same two-record shape. The only content type
    # offering `every-30-mins`, which is stage 2's recorded preferred posture for it.
    "threats_recurrence": build_text_compiler("threats_recurrence", "threats_recurrence"),
    "threats_action": build_text_compiler("threats_action", "threats_action"),
    # WILDFIRE. PAN-UPD-004, ONE record and the recurrence alone - see the module docstring for
    # why `wildfire_action` is absent rather than forgotten. This is the only grading in the
    # domain whose placements are NOT all at the baseline tier: `every-15-mins` and `every-min`
    # are graded BELOW `high`, so two calibration queries here actually move a severity.
    "wildfire_recurrence": build_text_compiler("wildfire_recurrence", "wildfire_recurrence"),
    # GLOBALPROTECT DATA FILE and GLOBALPROTECT CLIENTLESS VPN. PAN-UPD-005's two records, one
    # content type each, and the only records in the domain whose sign is inverted: stage 5
    # states the PASSING condition, so each record fires on the DISJUNCTION of its two clauses
    # failing. Both columns of both pairs are registered because each record asserts on both.
    "gp_datafile_recurrence": build_text_compiler(
        "gp_datafile_recurrence", "gp_datafile_recurrence"),
    "gp_datafile_action": build_text_compiler("gp_datafile_action", "gp_datafile_action"),
    "gp_clientless_vpn_recurrence": build_text_compiler(
        "gp_clientless_vpn_recurrence", "gp_clientless_vpn_recurrence"),
    "gp_clientless_vpn_action": build_text_compiler(
        "gp_clientless_vpn_action", "gp_clientless_vpn_action"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_content_update_schedule_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_content_update_schedule_search_node(c) for c in group["clauses"]]
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
