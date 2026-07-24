"""Compiler for the `negate_source` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_boolean import (
    SUPPORTED_OPERATORS,
    compile_scalar_boolean_clause,
)


def compile_negate_source_clause(clause):
    return compile_scalar_boolean_clause(
        clause,
        field_name="negate_source",
        lookup_field="negate_source",
    )


compile_negate_source_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
