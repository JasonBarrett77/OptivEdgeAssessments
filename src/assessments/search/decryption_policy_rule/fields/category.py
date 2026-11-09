"""Compiler for the `category` decryption-rule search field.

AN ABSENT KEY MEANS EVERY URL CATEGORY, so the empty state is the most permissive one and the
normalizer materialises `any` for it - which is what makes `includes 'any'` reach the rule nobody
bounded as well as the rule somebody set to `any` on purpose. Measured by stage 4 on a committed
rule carrying only its six mandatory keys: `show running decryption-policy` printed `category any`,
and the positive control moved and moved back.

A MEMBER MAY BE A CUSTOM URL CATEGORY OBJECT WHOSE OWN MEMBERS ARE OTHER CATEGORIES, and that
object is an INTERSECTION rather than a union - the vendor's own worked procedure blocks the
combined object while leaving each constituent class at a permitting action, which is coherent only
under an intersection. So coverage read off the member NAMES OVERSTATES what a rule opens. Nothing
here resolves the object; PAN-URL-006 owns its hygiene.
"""

from __future__ import annotations

from assessments.search.decryption_policy_rule.fields.member_criterion import (
    SUPPORTED_OPERATORS,
    compile_member_criterion_clause,
)
from optivedge_integrations.integrations.models import DecryptionPolicyRuleCategory


def compile_category_clause(clause):
    return compile_member_criterion_clause(
        clause,
        model_class=DecryptionPolicyRuleCategory,
        field_name="category",
    )


compile_category_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
