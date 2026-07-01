"""Compiler for the `application` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.repeated_value import (
    SUPPORTED_OPERATORS,
    compile_repeated_value_clause,
)
from optivedge.integrations.models import SecurityRuleApplication


def compile_application_clause(clause):
    return compile_repeated_value_clause(
        clause,
        model_class=SecurityRuleApplication,
        field_name="application",
    )


compile_application_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
