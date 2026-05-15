"""Compiler for the `from_zone` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.repeated_value import (
    SUPPORTED_OPERATORS,
    compile_repeated_value_clause,
)
from optivedge.integrations.models import SecurityRuleFromZone


def compile_from_zone_clause(clause):
    return compile_repeated_value_clause(
        clause,
        model_class=SecurityRuleFromZone,
        field_name="from_zone",
    )


compile_from_zone_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
