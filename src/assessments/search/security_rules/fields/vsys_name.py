"""Compiler for the `vsys_name` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_text import (
    SUPPORTED_OPERATORS,
    compile_scalar_text_clause,
)


def compile_vsys_name_clause(clause):
    return compile_scalar_text_clause(
        clause,
        field_name="vsys_name",
        lookup_field="enforcement_point__vsys_name",
    )


compile_vsys_name_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
