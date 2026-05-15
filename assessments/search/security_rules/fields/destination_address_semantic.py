"""Compiler for the `destination_address` semantic security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.address_semantic import (
    SUPPORTED_OPERATORS,
    compile_semantic_address_clause,
)
from optivedge.integrations.models import SecurityRuleDestinationAddressRef


def compile_destination_address_semantic_clause(clause):
    return compile_semantic_address_clause(
        clause,
        model_class=SecurityRuleDestinationAddressRef,
        field_name="destination_address",
    )


compile_destination_address_semantic_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
