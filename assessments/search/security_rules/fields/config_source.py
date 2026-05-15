"""Compiler for the `config_source` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.scalar_choice import (
    SUPPORTED_OPERATORS,
    compile_scalar_choice_clause,
)
from optivedge.integrations.models import SecurityRule


def compile_config_source_clause(clause):
    return compile_scalar_choice_clause(
        clause,
        field_name="config_source",
        lookup_field="config_source",
        choice_map=SecurityRule.CONFIG_SOURCE_CHOICES,
    )


compile_config_source_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
