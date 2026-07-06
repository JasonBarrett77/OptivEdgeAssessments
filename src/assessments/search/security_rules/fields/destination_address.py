"""Compiler for the `destination_address_name` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.address_ref import (
    SUPPORTED_OPERATORS,
    compile_address_ref_clause,
)
from optivedge_integrations.integrations.models import SecurityRuleDestinationAddressRef


def compile_destination_address_clause(clause):
    return compile_address_ref_clause(
        clause,
        model_class=SecurityRuleDestinationAddressRef,
        field_name="destination_address_name",
    )


compile_destination_address_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
