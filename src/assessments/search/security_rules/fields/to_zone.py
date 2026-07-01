"""Compiler for the `to_zone` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.repeated_value import (
    SUPPORTED_OPERATORS,
    compile_repeated_value_clause,
)
from optivedge.integrations.models import SecurityRuleToZone


def compile_to_zone_clause(clause):
    return compile_repeated_value_clause(
        clause,
        model_class=SecurityRuleToZone,
        field_name="to_zone",
    )


compile_to_zone_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
