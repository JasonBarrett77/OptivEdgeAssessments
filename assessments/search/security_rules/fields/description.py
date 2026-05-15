"""Compiler for the `description` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_text import (
    SUPPORTED_OPERATORS,
    compile_scalar_text_clause,
)


def compile_description_clause(clause):
    return compile_scalar_text_clause(
        clause,
        field_name="description",
        lookup_field="description",
    )


compile_description_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
