"""Canonical search compiler for one appliance's departures from the vendor's SSL exclusion list.

ONE ROW PER APPLIANCE. `/config/shared/ssl-decrypt/disabled-ssl-exclude-cert-from-predefined` is a
bare MEMBER LIST and not a collection, so there is no entry to be one row per and the row is a
conclusion about the VENDOR's entries: which of them are switched off here. SHARED SCOPE ONLY -
stage 4 completed both scopes and this node is the one the vsys scope is missing - so on a
multi-vsys firewall the decision cannot be taken per vsys and the appliance FK is direct.

NO SHIPPED CONTROL COMPILES THROUGH THIS REGISTRY ENTRY, which is a recorded state rather than dead
code and is the same position `search/lldp_global`'s own model is in. PAN-DEC-004's two assertion
records name two models, a control has exactly one `target_model`, and
`probe.relation_between SslDecryptionExclusion SslDecryptionVendorExclusionOptOut` finds NO RELATION
IN EITHER DIRECTION - six paths through shared ancestors, every one to-many and every one leaving a
scope field unconstrained, which is a WRONG ROW rather than an understated severity. So one half
ships and this one is silent until somebody splits the catalog id. It is registered now because
`test_every_control_type_targets_a_registered_model` requires it of the type, and because the half
reports the moment a control exists.

AND NO ESTATE CAN MAKE IT FIRE TODAY, which is the sharper fact. The one clean assertion is that no
switched-off entry is left on the list after the vendor stopped shipping it, and that is a SET
DIFFERENCE whose right-hand side - the vendor's own catalog - is invisible to `action=get` and to
the merged configuration. Measured on all four lab appliances: the config read a collector naturally
reaches for answers a well-formed, TRUTHY, EMPTY count envelope
(`{"@total-count": "0", "@count": "0"}`) for a populated vendor list, while `action=show` at the same
xpath denies the node exists and the `show predefined` OPERATIONAL read returns all 330 or 385
entries. Nothing issues that operational read on a collection run, so
`stale_disabled_vendor_exclusion_count` is zero on every row in every estate - and stage 5 declared
that column's unknown as reading COMPLIANT, with the concession written out, rather than have it
report "the vendor has stopped shipping an exclusion you switched off" on every appliance including
the four measured to have switched none off.

TWO STORED COLUMNS ARE DELIBERATELY ABSENT and they are absent for DIFFERENT reasons, which is the
distinction worth keeping:

  `disabled_vendor_exclusions`       A JSONField, and `test_findings_rest_on_columns` refuses a
                                     registered JSONField OUTRIGHT in two separate checks - one
                                     walking every compiled query for a JSON column reference and
                                     one refusing the NAME in the registry at all. Stage 5 marks it
                                     `not_searchable` for the same reason and calls it what
                                     PAN-DEC-004's second half is DELIVERED as: the list a reader
                                     needs beside the reachable count.
  `disabled_vendor_exclusion_count`  Searchable, and named by no clause, grading or `undetermined`
                                     of this domain - so by this repository's rule it earns no
                                     field. A non-empty list is a REVIEW ITEM and not a gap: the
                                     vendor's own screen says switching one off removes support for
                                     applications that break decryption, which is a hardening act,
                                     so a control firing on a non-zero count would report the
                                     opposite of what it meant.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import SslDecryptionVendorExclusionOptOut

SSL_DECRYPTION_VENDOR_EXCLUSION_OPTOUT_MODEL = (
    "integrations.SslDecryptionVendorExclusionOptOut")
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return SslDecryptionVendorExclusionOptOut.objects.filter(
                **{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return SslDecryptionVendorExclusionOptOut.objects.filter(
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
        return SslDecryptionVendorExclusionOptOut.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column, which is this row's whole identity: one column, two fields,
    # and the FK is direct. ON AN HA PAIR THIS MODEL YIELDS TWO ROWS FOR ONE REAL CONFIGURATION
    # and nothing deduplicates them, so the hostname is what tells the two apart.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # PAN-DEC-004's SECOND ASSERTION, which is the one half of it that is a clean predicate: how
    # many switched-off entries the vendor NO LONGER SHIPS. `gt 0` is the reachable form of a set
    # difference the predicate cannot express itself. `PositiveIntegerField(default=0)` and never
    # nullable, so `gt 0` matches no unrecomputed row - which is the whole of the concession stage
    # 5 took and the module docstring states.
    "stale_disabled_vendor_exclusion_count": build_integer_compiler(
        "stale_disabled_vendor_exclusion_count", "stale_disabled_vendor_exclusion_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_ssl_decryption_vendor_exclusion_optout_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_ssl_decryption_vendor_exclusion_optout_search_node(c)
                for c in group["clauses"]]
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
