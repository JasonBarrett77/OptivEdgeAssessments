"""Compiler for the `service` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.repeated_value import (
    SUPPORTED_OPERATORS,
    compile_repeated_value_clause,
)
from optivedge_integrations.integrations.models import SecurityRuleService


def compile_service_clause(clause):
    return compile_repeated_value_clause(
        clause,
        model_class=SecurityRuleService,
        field_name="service",
    )


compile_service_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
