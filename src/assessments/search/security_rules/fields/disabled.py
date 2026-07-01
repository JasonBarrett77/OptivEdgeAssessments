"""Compiler for the `disabled` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_boolean import (
    SUPPORTED_OPERATORS,
    compile_scalar_boolean_clause,
)


def compile_disabled_clause(clause):
    return compile_scalar_boolean_clause(
        clause,
        field_name="disabled",
        lookup_field="disabled",
    )


compile_disabled_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
