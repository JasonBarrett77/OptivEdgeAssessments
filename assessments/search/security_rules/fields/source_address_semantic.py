"""Compiler for the `source_address` semantic security-rule search field."""

from __future__ import annotations

from assessments.search.security_rules.fields.address_semantic import (
    SUPPORTED_OPERATORS,
    compile_semantic_address_clause,
)
from optivedge.integrations.models import SecurityRuleSourceAddressRef


def compile_source_address_semantic_clause(clause):
    return compile_semantic_address_clause(
        clause,
        model_class=SecurityRuleSourceAddressRef,
        field_name="source_address",
    )


compile_source_address_semantic_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
