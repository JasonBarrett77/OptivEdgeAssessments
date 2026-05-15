"""Compiler for the `log_setting` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_text import (
    SUPPORTED_OPERATORS,
    compile_scalar_text_clause,
)


def compile_log_setting_clause(clause):
    return compile_scalar_text_clause(
        clause,
        field_name="log_setting",
        lookup_field="log_setting",
    )


compile_log_setting_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
