"""Canonical search compiler for the cryptographic operational mode an appliance reports.

PAN-MGT-012. Minted by stage 8 of `management-services` on 2026-11-01. One row per appliance;
on an HA pair two rows, because the mode is set per appliance from maintenance mode and is
synchronised by nothing.

THERE IS NO CONFIGURATION NODE FOR THIS AT ANY SCOPE, which is why both columns here are
verdicts over a RUNTIME reading rather than over a stored leaf. The mode is reported at
`/response/result/system/operational-mode` in the `show system info` reply; `show fips-mode`
answers code=17 on all four lab appliances and the CLI grammar carries no node for it.

BOTH OF STAGE 5's REGISTERABLE COLUMNS ARE HERE, and the split between them is the point:

    approved_cryptography_mode   PAN-MGT-012's assertion clause   BooleanField(default=False)
    operational_mode             PAN-MGT-012's grading axis       CharField(blank=True)

`approved_cryptography_mode` FALSE IS THE FIRING SIDE AND IS THE DEFAULT - an appliance nobody
has read has not been shown to be in the approved mode - so `eq false` matches an unread row as
well as a read one, which is the direction `rules.md` requires.

`operational_mode` IS `blank=True` AND NOT `null=True`, so its only absent value is `""` and the
bare `filter(field="")` shape is CORRECT here. That is measured rather than assumed: the
null trap - where `is_empty` compiles, passes every gate and matches nothing on the exact
population the clause was written for - needs `null=True`, and this column does not have it. An
empty value means THE READ WAS NOT TAKEN, which is a different state from any mode the device
can report, and the verdict column beside it fires on that row anyway.

AND THE COMPARISON IS CASE-INSENSITIVE, WHICH MATTERS IN ONE DIRECTION ONLY. `eq` renders as
`iexact`. The device answered lowercase `normal` on all four lab appliances through both
operational reads, and stage 5's grading places the token as `normal`, so the two agree. The
OTHER mode's spelling is UNMEASURED - `ApplianceOperationalMode.APPROVED_MODE` is the
catalog's `FIPS-CC`, no appliance in this estate runs it, and neither available instrument can
enumerate it because `action=complete` needs an xpath and there is none. No query rests on that
spelling today: stage 5 grades `FIPS-CC` as `no_finding`, which compiles to no query at all. The
day a control asserts the approved mode positively, that spelling is the first thing to measure.

WHAT A FINDING ON THIS MODEL MUST NOT BE USED FOR. OptivEdgeAssessments records, and Jason
decided 2026-09-04, that reinterpreting another domain's implicit defaults from this value
"would lie". The stored mode must not reinterpret another domain's defaults until that question
is answered estate-wide, and this compiler gives no one a way to do so: it answers which
appliances report which mode and nothing else.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import ApplianceOperationalMode

APPLIANCE_OPERATIONAL_MODE_MODEL = "integrations.ApplianceOperationalMode"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return ApplianceOperationalMode.objects.filter(
                **{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains",
                  "starts_with": "istartswith", "ends_with": "iendswith"}.get(op, "iexact")
        return ApplianceOperationalMode.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    """`eq` is the only operator a boolean can carry, and the value is type-checked.

    Not coerced: `eq "false"` on a boolean column is a catalog payload bug, and Python reads
    the non-empty string as TRUE and matches the opposite rows in silence.
    """

    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return ApplianceOperationalMode.objects.filter(
            **{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    #: PAN-MGT-012's assertion. FALSE fires and is the default.
    "approved_cryptography_mode": build_boolean_compiler(
        "approved_cryptography_mode", "approved_cryptography_mode"),
    #: PAN-MGT-012's grading axis: the mode VERBATIM as the appliance answers it.
    "operational_mode": build_text_compiler("operational_mode", "operational_mode"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_appliance_operational_mode_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_appliance_operational_mode_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(
            f"Unsupported search field for {APPLIANCE_OPERATIONAL_MODE_MODEL}: "
            f"{clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause.get("negated") else predicate
