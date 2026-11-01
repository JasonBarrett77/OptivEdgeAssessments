"""Compiler for the `source_user` decryption-rule search field.

An absent key means EVERY user, materialised as `any` - measured, with the positive control moving
the grid's USER column both ways.

THE GRADING AXIS FOR PAN-DEC-006, AND IT IS A MEMBER LIST, which is the whole reason that control
needs a query at its own baseline tier as well as above and below it. One rule can name several of
the four device keywords at once, so a rule naming both `unknown` and `pre-logon` matches the
`pre-logon` calibration - which carries LOW - and would match no calibration for `unknown` if that
placement contributed none. The worst MATCHED calibration wins and the baseline tier is discarded as
soon as one matches, so the rule would report at LOW where its grading gives it MEDIUM, in silence.

WHAT THIS FIELD CANNOT DO is tell a directory GROUP from one individual. A member outside
`DecryptionPolicyRule.USER_KEYWORDS` is a free principal string of unknown kind, which is what
`source_user_is_keyword_population` reports as false and what stage 5 leaves `unranked`: the read
that would separate them is PAN-UID-001's `show user group list`, and the device's own reference for
this field points at the LOCAL user database rather than the directory.

THE LEAF NAME IS ONE OF THE MOST REUSED IN THE PRODUCT - 85 objects in the grammar carry it - and
the SECURITY rulebase's copy decides whether traffic is ALLOWED rather than whether it is INSPECTED.
"""

from __future__ import annotations

from assessments.search.decryption_policy_rule.fields.member_criterion import (
    SUPPORTED_OPERATORS,
    compile_member_criterion_clause,
)
from optivedge_integrations.integrations.models import DecryptionPolicyRuleSourceUser


def compile_source_user_clause(clause):
    return compile_member_criterion_clause(
        clause,
        model_class=DecryptionPolicyRuleSourceUser,
        field_name="source_user",
    )


compile_source_user_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
