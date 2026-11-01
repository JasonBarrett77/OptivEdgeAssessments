"""Canonical search compiler for one server entry of one log-settings server profile.

PAN-LOG-002. Minted by stage 8 of `logging` on 2026-11-01.

THREE COLUMNS AND NO MORE, plus the appliance identity. Stage 5 marks all ten columns of the
`syslog-server-target` subject `needs_compiler_field` and names three of them: `kind` as
PAN-LOG-002's scope clause, `profile_referrer_count` as its applicability clause and `transport`
as both its assertion clause and its grading axis. `server_address`, `port`, `profile_name`,
`server_name`, `scope` and `vsys_name` are deliberately NOT registered - the compiler's rule in
this repository is that a field earns its place by a control needing it, and registering the rest
would ship a search surface no control asks for. They are report columns and a later control is
what earns them a field. `port` in particular: stage 5's own note says no control in this domain
clauses on it, because a secure session on another agreed port still satisfies the assertion.

AND THE WHOLE `email-server-target` SUBJECT IS LEFT, WHICH IS FOURTEEN MORE MARKED COLUMNS. It is
the same table under a different `kind`, and NO ASSERTION IN THIS DOMAIN NAMES IT: PAN-LOG-008's
second group would have - `meets_authenticated_tls eq false` - and stage 5 put that group in its
record's free-prose `undetermined` rather than in `clauses`, because the clause list is one
conjunction with no OR. So `protocol`, `tls_version`, `auth_method`, `meets_authenticated_tls`
and `transport_grade` have no query to serve. The day something asserts the e-mail kind, it
reuses this type and this package and adds its own fields; it mints nothing.

`kind` IS AN IDENTITY COLUMN AND IT IS STILL OWED A FIELD, which is the thing to read before
assuming identity columns are decoration. `transport` holds its UDP default on the e-mail kind
of this same table, so PAN-LOG-002 without `kind eq syslog` reports every mail relay in the
estate as sending syslog in the clear. The model's own docstring says every control on it must
clause on the kind, and nothing enforces that - not the catalog schema, not this compiler, not a
lint, not a generic test. Measured: the shape is the same as device-services' `service-paths.scope`.

`kind` TAKES THE TEXT COMPILER rather than a closed-choice form, for the reason the NTP and DNS
compilers record: the closed form accepts none of the shared `PROBE_VALUES`, so it would put this
domain's vocabulary into a shared test of every other model. `is_empty` comes with the text
operator set and can never match on `kind` - it is non-null with `choices` and every stored row
carries one of the two members - and on `transport` it can never match either, because that
column is non-null with a `UDP` default.

`hostname` AND `serial_number` BOTH SERVE STAGE 5's ONE `appliance` COLUMN, which is what the
shipped compiler for this domain's third subject does. Measured before copying it rather than
assumed, because three of the 66 shipped compilers register neither.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import LogServerTarget

LOG_SERVER_TARGET_MODEL = "integrations.LogServerTarget"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return LogServerTarget.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return LogServerTarget.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in INTEGER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return LogServerTarget.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    #: PAN-LOG-002's SCOPE clause, and the one clause this control cannot ship without.
    "kind": build_text_compiler("kind", "kind"),
    #: PAN-LOG-002's applicability clause: a profile nothing forwards to is an address book and
    #: not a collector this firewall sends to. ZERO SILENCES THE CONTROL rather than firing it,
    #: which is the opposite direction from the shipped control on the same shape, PAN-AAA-013.
    "profile_referrer_count": build_integer_compiler(
        "profile_referrer_count", "profile_referrer_count"),
    #: PAN-LOG-002's assertion clause AND its grading axis. The assertion is a NEGATED equality
    #: on the one encrypting member, so the baseline needs no `is_empty` member to reach an
    #: absent value: the column is non-null with a materialised `UDP` default.
    "transport": build_text_compiler("transport", "transport"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_log_server_target_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_log_server_target_search_node(c) for c in group["clauses"]]
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
