"""Compiler for the `service` decryption-rule search field.

An absent key means every port, materialised as `any`.

NO CONTROL ASSERTS A SERVICE CRITERION ON ITS OWN and this field exists for one conjunction:
PAN-DEC-002's structural half needs 'keyed on nothing at all' to range over EVERY criterion, and a
criterion left out of it is a rule bounded by a port that reads as bounded by nothing. `oep-dec6-r13`
is that configuration on the lab - `service: application-default` and every other criterion
unbounded - and it is the subject that proves the conjunction is not vacuous.
"""

from __future__ import annotations

from assessments.search.decryption_policy_rule.fields.member_criterion import (
    SUPPORTED_OPERATORS,
    compile_member_criterion_clause,
)
from optivedge_integrations.integrations.models import DecryptionPolicyRuleService


def compile_service_clause(clause):
    return compile_member_criterion_clause(
        clause,
        model_class=DecryptionPolicyRuleService,
        field_name="service",
    )


compile_service_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
