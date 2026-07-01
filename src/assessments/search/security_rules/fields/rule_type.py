"""Compiler for the `rule_type` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_text import (
    SUPPORTED_OPERATORS,
    compile_scalar_text_clause,
)


def compile_rule_type_clause(clause):
    return compile_scalar_text_clause(
        clause,
        field_name="rule_type",
        lookup_field="rule_type",
    )


compile_rule_type_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
