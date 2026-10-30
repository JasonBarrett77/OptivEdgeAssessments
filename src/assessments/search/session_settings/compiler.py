"""Canonical search compiler for one appliance's Session settings. PAN-NET-002 and PAN-NET-005.

One row per appliance. Both config nodes - `deviceconfig/setting/config/rematch` and
`deviceconfig/setting/session/ipv6-firewalling` - are device-wide, so there is no vsys axis and
no scope column. On an HA pair this is TWO rows for one real configuration, one per peer, with
the values synchronised; nothing downstream deduplicates them.

TWO BOOLEANS, OPPOSITE NULLABILITY, AND THAT IS THE WHOLE DIFFICULTY OF THIS MODULE.

`rematch_known` IS A VIRTUAL FIELD OVER `session_rematch__isnull` AND IT IS THE SHIPPED ANSWER,
not an invention here. `is_empty` is the only operator of the twelve that is about absence and it
does not exist for a boolean field at all - `build_boolean_compiler` advertises `{"eq"}` in every
one of the fourteen shipped compilers, so `<boolean column> is_empty` is refused as an
unsupported operator before any lookup is built. What three shipped compilers do instead is
register a boolean field over another column's NULLNESS and invert it: `address_object`'s
`size_known` over `num_hosts__isnull` took it first, `collection_attempted` followed, and
`management_ssh`'s `rekey_interval_known` copied it. So a `null=True` column of any type is
reachable by a clause through a registered name the model does not have to carry, and no
migration is owed.

That is what makes PAN-NET-002's second failing group expressible. Stage 5 declares it as
`session_rematch is_empty` firing at HIGH, because an appliance whose rematch setting nobody has
established may be leaving revoked access in force on exactly the long-lived flows the control is
about; `rematch_known eq false` is the same predicate through the repo's own convention. The
clause reaches the nullness and the finding still asserts on `session_rematch`, which is the
column a reader must be sent to and the only one of the two the model actually has - a finding
asserting on the virtual name would raise in `tested_fields()`, which resolves every asserted
field against the model.

`ipv6_firewalling` GETS NO SUCH FIELD AND CANNOT. It is NON-nullable - the vendor default is
measured, so an absent key stores true - and a virtual `*_known` field needs a null to detect.
Only a companion column or a changed default would close it, and both are the normaliser's to
decide rather than this stage's. PAN-NET-005's declared second query is therefore recorded in the
stage 8 artifact as one that could not be compiled, and the consequence stands and is reported:
that control cannot separate "we asked and the device says it is on" from "we never asked".

WHAT `is not true` ALREADY REACHES, measured, because the obvious reading is wrong in the
reassuring direction. `compile_search_clause` negates at the pk-SET level - `~Q(pk__in=...)` -
and not at the column level, so a row absent from the positive subquery IS in the complement. A
row holding NULL is therefore matched by `session_rematch is not true`. `models/
network_hardening.py`'s own comment says the opposite ("a clause testing `session_rematch is not
true` matches no NULL row"), and that comment is about plain SQL rather than about this compiler.
The consequence: PAN-NET-002's second query is a strict SUBSET of its baseline rather than the
only thing catching the unmeasured appliance. It is shipped because it names WHICH group fired on
the finding, not because the baseline misses the row.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import PanOsSessionSettings

SESSION_SETTINGS_MODEL = "integrations.PanOsSessionSettings"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return PanOsSessionSettings.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return PanOsSessionSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field, *, invert=False):
    """`invert` is for a field that answers whether something is KNOWN, over a column that stores
    the absence - `session_rematch__isnull` answers the opposite of `rematch_known`. Copied from
    `management_ssh`'s builder of the same name, which copied it from `address_object`; the three
    differ only in the model they filter."""
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return PanOsSessionSettings.objects.filter(
            **{lookup_field: (not value) if invert else value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # Nullable: nothing was measured for an absent key, so nothing is stored. The provenance row
    # beside it is what tells a reader a stored value came from an absent key.
    "session_rematch": build_boolean_compiler("session_rematch", "session_rematch"),
    # The virtual field over that column's nullness - see this module's docstring. FALSE means
    # the setting was never established, which is the group stage 5 declared as PAN-NET-002's
    # second query.
    "rematch_known": build_boolean_compiler(
        "rematch_known", "session_rematch__isnull", invert=True),
    # Non-nullable with a MEASURED vendor default of true - the device's own dataplane says an
    # absent key means IPv6 firewalling is ON, paid in both directions on a committed state. So
    # no `*_known` companion is possible here, and the reassuring value is also the ordinary one.
    "ipv6_firewalling": build_boolean_compiler("ipv6_firewalling", "ipv6_firewalling"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_session_settings_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_session_settings_search_node(c) for c in group["clauses"]]
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
