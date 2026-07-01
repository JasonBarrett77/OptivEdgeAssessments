"""Compiler for the `log_start` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_boolean import (
    SUPPORTED_OPERATORS,
    compile_scalar_boolean_clause,
)


def compile_log_start_clause(clause):
    return compile_scalar_boolean_clause(
        clause,
        field_name="log_start",
        lookup_field="log_start",
    )


compile_log_start_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
