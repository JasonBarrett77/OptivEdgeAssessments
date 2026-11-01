"""Compiler for the `source` decryption-rule search field.

MANDATORY AT COMMIT VALIDATION, measured as job 217, so the literal `any` is a WRITTEN value here
and not a default - the opposite of `category` on the same object. The consequence stage 4 drew is
the one a clause has to respect: neither PAN-DEC-005 nor PAN-DEC-007 can be expressed as 'the key is
absent', because on a running device the absent state does not exist and the value to compare
against is the literal.

A MEMBER MAY BE AN ADDRESS OBJECT, AN ADDRESS GROUP, A REGION OR AN EXTERNAL DYNAMIC LIST and the
device offers no `@type` to tell them apart, so this field compares the NAME it was given. How large
the named object is is a question nothing in this domain can answer - stage 2 recorded that nothing
on either screen or in the grammar measures a prefix size, and the arithmetic belongs to
PAN-POL-002. That is why four of stage 5's graded placements over this column are `unranked`.
"""

from __future__ import annotations

from assessments.search.decryption_policy_rule.fields.member_criterion import (
    SUPPORTED_OPERATORS,
    compile_member_criterion_clause,
)
from optivedge_integrations.integrations.models import DecryptionPolicyRuleSource


def compile_source_clause(clause):
    return compile_member_criterion_clause(
        clause,
        model_class=DecryptionPolicyRuleSource,
        field_name="source",
    )


compile_source_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
