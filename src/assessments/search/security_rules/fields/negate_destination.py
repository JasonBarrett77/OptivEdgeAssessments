"""Compiler for the `negate_destination` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_boolean import (
    SUPPORTED_OPERATORS,
    compile_scalar_boolean_clause,
)


def compile_negate_destination_clause(clause):
    return compile_scalar_boolean_clause(
        clause,
        field_name="negate_destination",
        lookup_field="negate_destination",
    )


compile_negate_destination_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
