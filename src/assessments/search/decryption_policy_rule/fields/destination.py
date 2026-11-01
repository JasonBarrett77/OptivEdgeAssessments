"""Compiler for the `destination` decryption-rule search field.

Mandatory at commit validation in the same reply as `source`, in the same four member kinds.

REGISTERED FOR PAN-DEC-002'S STRUCTURAL HALF AND FOR NOTHING ELSE: 'keyed on nothing at all' is a
conjunction over EVERY criterion, and a criterion left out of that conjunction is a rule bounded by
a destination that reads as bounded by nothing. The DESTINATION-keyed form of PAN-DEC-005's
carve-out is a second clause group stage 5 declined to write - `clauses` is one conjunction with no
OR - and it stands on the lab as `oep-dec6-r12`, ungraded. This field is what a later stage would
need to write it; no shipped query of this domain compares on it alone.
"""

from __future__ import annotations

from assessments.search.decryption_policy_rule.fields.member_criterion import (
    SUPPORTED_OPERATORS,
    compile_member_criterion_clause,
)
from optivedge_integrations.integrations.models import DecryptionPolicyRuleDestination


def compile_destination_clause(clause):
    return compile_member_criterion_clause(
        clause,
        model_class=DecryptionPolicyRuleDestination,
        field_name="destination",
    )


compile_destination_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
