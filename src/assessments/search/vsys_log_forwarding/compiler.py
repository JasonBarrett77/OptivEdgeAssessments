"""Canonical search compiler for one virtual system's Log Forwarding availability.

PAN-LOG-005. Minted by stage 8 of `logging` on 2026-11-01.

TWO COLUMNS AND NO MORE, plus the appliance identity. Stage 5 marks four of this subject's five
columns `needs_compiler_field` and names two of them: `pushed_profile_sources_collected` as
PAN-LOG-005's applicability clause and `offbox_log_type_gaps` as both its assertion clause and
its grading axis. `vsys_name` is marked and is NOT named by any clause, grading or undetermined,
so it is not registered - it is what the finding PRINTS as its subject name, which is the finding
model's business and not a predicate's. `profile_names` is a JSONField stage 5 marks
`not_searchable`, and the integrations model's own docstring says why: a finding must not rest on
a stored display structure, because an unindexed lookup and a renamed vendor key that matches
nothing both fail silently.

THE APPLICABILITY CLAUSE IS A DID-WE-COLLECT-IT COLUMN AND IT EXCLUDES RATHER THAN FIRES, which
is the shape `rules.md` warns about and which stage 5 argued for deliberately. `false` takes the
row out of PAN-LOG-005 instead of raising it, because over-reporting here means telling an
engineer that a correctly configured vsys has no log forwarding at all: the gap column would have
been computed from the vsys's LOCAL profiles alone, with the Panorama-pushed and vendor-predefined
namespaces missing, and on this lab's own measurement those two namespaces are where most of the
coverage lives. The direction is stage 5's and the artifact records that this run implemented it
as written rather than agreeing with it.

`is_empty` IS THE BARE `filter(field="")` SHAPE AND IT IS CORRECT HERE. Measured on the
integrations model: `offbox_log_type_gaps` is `CharField(max_length=255, blank=True,
default=ALL_FORWARDING_LOG_TYPES_MISSING)` with NO `null=True`, so the only absent value it can
hold is `""` and an `__isnull=True` branch beside it would match nothing extra. The trap is a
`null=True` text column, where the bare shape compiles, passes every gate and matches nothing on
the exact population the clause was written for; it does not arise on this model.

AND THE GAP COLUMN IS QUERIED WITH `contains`, NOT `eq`. It holds a comma-joined set of the log
types that are MISSING, so a log type is tested for MEMBERSHIP. The ten members of
`FORWARDING_PROFILE_LOG_TYPES` were checked for substring collisions before the queries were
written - no token is a substring of another - because `icontains` over a joined string would
otherwise match a type nobody is missing.

`hostname` AND `serial_number` BOTH SERVE STAGE 5's ONE `appliance` COLUMN. Measured against the
shipped precedent rather than assumed, because three of the 66 shipped compilers register neither.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import VsysLogForwarding

VSYS_LOG_FORWARDING_MODEL = "integrations.VsysLogForwarding"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return VsysLogForwarding.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return VsysLogForwarding.objects.filter(
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
        return VsysLogForwarding.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    #: PAN-LOG-005's assertion clause - as a NEGATED `is_empty`, the registry having no
    #: `is not empty` operator - and its grading axis, as `contains` per log type.
    "offbox_log_type_gaps": build_text_compiler(
        "offbox_log_type_gaps", "offbox_log_type_gaps"),
    #: PAN-LOG-005's applicability clause. See the module docstring for its direction.
    "pushed_profile_sources_collected": build_boolean_compiler(
        "pushed_profile_sources_collected", "pushed_profile_sources_collected"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_vsys_log_forwarding_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_vsys_log_forwarding_search_node(c) for c in group["clauses"]]
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
