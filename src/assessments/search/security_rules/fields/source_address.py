"""Compiler for the `source_address_name` security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.address_ref import (
    SUPPORTED_OPERATORS,
    compile_address_ref_clause,
)
from optivedge.integrations.models import SecurityRuleSourceAddressRef


def compile_source_address_clause(clause):
    return compile_address_ref_clause(
        clause,
        model_class=SecurityRuleSourceAddressRef,
        field_name="source_address_name",
    )


compile_source_address_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
