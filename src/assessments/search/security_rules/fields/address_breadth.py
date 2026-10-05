"""Compilers for the address-breadth security-rule fields. PAN-POL-002.

How many IPv4 addresses each side of a rule permits, after negation, and whether that was
establishable at all. The count is a column on the rule, written by normalization, because
following a reference to read a property of the target belongs there - the search layer
compares a field to a literal and cannot walk a rule's address refs, merge their intervals
and apply a negation.

`*_breadth_known` is a boolean rather than an `is_null` operator on the count. The question
the control asks is "did we establish this side's breadth", and asking it that way keeps the
two states apart: NULL means INDETERMINATE, never zero. A side is unknowable when it names a
dynamic address group or a region, when an EDL or FQDN on it has no resolved content, or when
that content was truncated and is a known under-count. Scoring that as 0 would make a rule
nobody could measure the narrowest rule on the device - the failure direction this control
exists to catch - so the control queries the flag and reports it instead.
"""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.security_rules.fields.scalar_boolean import (
    parse_boolean_value,
)
from optivedge_integrations.integrations.models import SecurityRule

NUMBER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}
BOOLEAN_OPERATORS = {"eq"}


def _build_count_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in NUMBER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        # A NULL count never matches a comparison, which is correct and is why the control
        # needs the companion flag: an indeterminate side is not a small one.
        return SecurityRule.objects.filter(**{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = NUMBER_OPERATORS
    return compiler


def _build_known_compiler(field_name, lookup_field):
    def compiler(clause):
        op = clause["op"]
        if op not in BOOLEAN_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        known = parse_boolean_value(clause["value"], field_name=field_name)
        # Inverted: the column stores the absence of an answer, not the presence of one.
        return SecurityRule.objects.filter(**{f"{lookup_field}__isnull": not known}).values("pk")
    compiler.SUPPORTED_OPERATORS = BOOLEAN_OPERATORS
    return compiler


compile_source_num_hosts_clause = _build_count_compiler("source_num_hosts", "source_num_hosts")
compile_destination_num_hosts_clause = _build_count_compiler(
    "destination_num_hosts", "destination_num_hosts")
compile_source_breadth_known_clause = _build_known_compiler(
    "source_breadth_known", "source_num_hosts")
compile_destination_breadth_known_clause = _build_known_compiler(
    "destination_breadth_known", "destination_num_hosts")
