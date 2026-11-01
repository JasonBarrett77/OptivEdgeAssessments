"""The shared compiler for a decryption rule's five MEMBER-LIST criteria.

FIVE REF MODELS AND NOT FIVE JSON COLUMNS, and that is the shape this module exists for.
`category`, `source`, `destination`, `source-user` and `service` are each stored as rows of their
own child model - `DecryptionPolicyRuleCategory`, `...Source`, `...Destination`, `...SourceUser`
and `...Service`, all four columns the same: `(decryption_rule, value, prov, position)`. That is
`SecurityRuleValue`'s shipped shape, and the reason OEI chose it over a blob is read in this
repository rather than assumed: `test_findings_rest_on_columns` refuses a registered JSONField
outright, in two separate checks, so a JSON criterion would have put PAN-DEC-002's structural half
out of reach entirely.

THE PRECEDENT IS `search/security_rules/fields/address_ref.py`, which is why this is a package with
a `fields/` subdirectory rather than the single-file compiler every other model in this map uses.
What is taken from it is the SHAPE and not the semantics: that file filters the ref model and
returns `.values("security_rule_id")`, leaving `compile_search_clause` to wrap the result in
`Q(pk__in=Subquery(...))` at the parent's grain. Everything below does the same with
`decryption_rule_id`.

WHAT IS DELIBERATELY NOT TAKEN is `address_semantic.py`'s `includes`. That operator shares this
one's NAME and means something else: it resolves each member into `AddressObject` and compares IPv4
INTERVALS, so `source includes "10.0.0.0/8"` asks whether some member COVERS that network. Stage 5
cites that file for the operator vocabulary and writes `includes 'any'` meaning membership of the
literal token - the device keyword - which is a string comparison against the member's own stored
value and needs no address resolution. Registering the semantic compiler here would have answered a
different question under stage 5's own word.

THERE IS NO `in` OPERATOR IN ANY REGISTRY, which is the other half of why these are rows: the
membership question is answered by QUERYING THE CHILD MODEL, not by an operator on the parent. And
`does not include` is the grammar's clause-level NEGATION of `includes` rather than a thirteenth
operator - `compile_search_clause` inverts the whole `pk__in` SET, so a rule with no member rows at
all is correctly inside the negation. Measured, and it matters: a rule whose criterion nobody
collected has no child rows, and `~Q(pk__in=...)` reaches it while a positive comparison cannot.

ONE OPERATOR AND NOT TWO. `contains` is not offered, because a substring test over a member list
answers a question no control in this domain asks and would read as a safe way to spell `includes`:
`category contains "any"` would match a custom category object named `company-any-approved`. The
values these criteria hold are device keywords and object names, both of which a control compares
whole.
"""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError

#: The only operator a member criterion offers. See the module docstring for why `contains` is not
#: here and why this name is not `address_semantic.py`'s `includes`.
SUPPORTED_OPERATORS = {"includes"}


def compile_member_criterion_clause(clause, *, model_class, field_name):
    """Every decryption rule holding `value` as a member of this criterion.

    Case-insensitive, matching every other text comparison in this package: PAN-OS accepts
    `ANY` and `any` at the same keyword and the grid renders what was typed.
    """
    op = clause["op"]
    value = clause["value"]

    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if not isinstance(value, str):
        raise SearchSyntaxError(f"{field_name} search value must be a string.")
    trimmed = value.strip()
    if not trimmed:
        # An empty member is not expressible in PAN-OS and `is_empty` is not offered here: the
        # question "does this rule name nothing at all" is answered by NEGATING a membership test,
        # which reaches a rule with no member rows. See the module docstring.
        raise SearchSyntaxError(f"{field_name} search value must not be empty.")

    suffix = "exact" if clause["case_sensitive"] else "iexact"
    return (model_class.objects
            .filter(**{f"value__{suffix}": trimmed})
            .values("decryption_rule_id"))
