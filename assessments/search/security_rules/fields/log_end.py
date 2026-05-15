"""Compiler for the `log_end` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_boolean import (
    SUPPORTED_OPERATORS,
    compile_scalar_boolean_clause,
)


def compile_log_end_clause(clause):
    return compile_scalar_boolean_clause(
        clause,
        field_name="log_end",
        lookup_field="log_end",
    )


compile_log_end_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
