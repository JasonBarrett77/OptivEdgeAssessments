"""Compiler for the `action` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_text import (
    SUPPORTED_OPERATORS,
    compile_scalar_text_clause,
)


def compile_action_clause(clause):
    return compile_scalar_text_clause(
        clause,
        field_name="action",
        lookup_field="action",
    )


compile_action_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
