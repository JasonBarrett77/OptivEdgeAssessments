"""Canonical search compiler for one appliance's content streams, as a set. PAN-PLT-002.

ONE ROW PER APPLIANCE CARRYING EVERY STREAM AS ITS OWN COLUMN, which is stage 5's
`identity.one_row_per` and is what makes this grain queryable at all: a stream-keyed row would
have nothing to report on exactly the streams that are ABSENT, and the never-installed sentinel
is the commonest reading in this estate - WildFire on three of four lab appliances, antivirus on
three of four.

`content_currency_state` IS ONE DERIVED COLUMN AND NOT A PREDICATE OVER TEN, and that is a stage 5
decision this compiler only has to respect. Stage 3's ranks are WINDOWS IN TIME - days since
publication, per stream, against two thresholds each - and `placements[].value` is a value-set
member, so the windows were computed into tokens at normalisation rather than left as numbers for
a query to compare. A clause list is also one conjunction with no OR, and "any one of three
streams is behind" is a disjunction.

NO JSONField IS LEFT OUT HERE BECAUSE THIS MODEL CARRIES NONE: every reading is a CharField or a
BooleanField, so the JSON ban `test_findings_rest_on_columns` enforces has nothing to catch on
this surface.

WHAT IS DELIBERATELY NOT REGISTERED, because fields earn their place by a control needing them.
The ten per-stream version and release-date columns, and `release_date_reported`: no clause, no
grading axis and no `undetermined` of this domain names any of them, and registering them would
ship a search surface no control asks for. They are not lost to a reader - the finding's own
sentence names which stream is behind and by how far, and that is where stage 5 put them.

AND THE TWO SPELLINGS OF "NEVER INSTALLED", because a reviewer writing a clause by hand will get
this wrong. The four content streams answer `0` and the URL filtering stream answers
`0000.00.00.000`; BOTH ARE TRUTHY STRINGS. A `contains 0` clause matches a real version too, and
a numeric comparison would rank `0` as the lowest version rather than as no version. The
normaliser compares against the literals and publishes the answer as a token; nothing here should
re-derive it.

WHY THE STATE COLUMNS ARE REGISTERED AS TEXT AND NOT THROUGH `build_choice_compiler`, which
raises on a value outside the column's own `choices` and is the form this repository otherwise
prefers. THE EMPTY STRING IS A REACHABLE STATE OF `content_currency_state` AND IS NOT IN ITS
CHOICE LIST: the normaliser returns it for an appliance whose `show system info` never answered
while its merged configuration did, and it is deliberate - a token there would be a verdict over
a reply nobody received. A choice compiler reading its members off `choices` could not express a
query for that state at all, and the text compiler's `is_empty` arm, which ORs an `__isnull`
term, is the only operator in this language that reaches it. The cost is named rather than
hidden: a MISSPELLED token in a catalogue payload compiles here and matches nothing, where the
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
from optivedge_integrations.integrations.models import FirewallContentStreams

FIREWALL_CONTENT_STREAMS_MODEL = "integrations.FirewallContentStreams"

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
        return FirewallContentStreams.objects.filter(
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
        return FirewallContentStreams.objects.filter(**{lookup_field: value}).values("pk")
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
        return FirewallContentStreams.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler

FIELD_COMPILERS = {
    # Stage 5's `appliance` column as TWO fields, which is what every shipped compiler does.
    # `appliance` is non-nullable on this model, so there is no appliance-group fallback. ON AN HA
    # PAIR THE SAME CONTENT STATE ARRIVES ON BOTH PEERS - stage 4 measured fw-core-tpa-b's content
    # as identical to its peer on every stream - so this subject yields two rows for one real
    # configuration, nothing deduplicates them, and the SERIAL is what tells the two apart where
    # the hostname does not.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # PAN-PLT-002's assertion AND its grading column. Six placements; `current` is the only one
    # that produces no finding, and no appliance in this estate holds it.
    "content_currency_state": build_text_compiler(
        "content_currency_state", "content_currency_state"),
    # THE COLUMN THAT SAYS WHETHER ANYBODY LOOKED, which stage 5 declares as reading `fires` when
    # unknown - its way of naming the column that answers the question. It is what separates the
    # empty verdict above from a token, and it is registered so the clause that asserts "this
    # appliance's content was never read" is buildable at all. No query of PAN-PLT-002 carries it
    # today: the baseline's negated equality already fires on the empty string.
    "content_streams_collected": build_boolean_compiler(
        "content_streams_collected", "content_streams_collected"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_firewall_content_streams_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_firewall_content_streams_search_node(c) for c in group["clauses"]]
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
