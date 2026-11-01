"""Canonical search compiler for one decryption policy rule. PAN-DEC-002, -003, -005 to -008, -010.

ONE ROW PER NAMED RULE PER RULEBASE PER VSYS, so the owner is reached through the enforcement point
and the appliance lookups branch on either owner - `appliance` set means locally managed,
`appliance_group` set means Panorama-managed. That is the same two-path shape every
enforcement-point-owned compiler in this package uses, and `search/dos_policy_rule` is the closest
sibling.

A PACKAGE WITH A `fields/` SUBDIRECTORY RATHER THAN THE SINGLE FILE EVERY OTHER MODEL HERE USES,
and `search/security_rules/` is the only precedent. The reason is five of this model's columns:
`category`, `source`, `destination`, `source_user` and `service` are MEMBER LISTS stored as rows of
five separate child models, so each one's compiler filters a different table and returns parent ids
rather than filtering this model at all. `fields/member_criterion.py` carries the shared shape and
says what was taken from `security_rules/fields/address_ref.py` and what was deliberately not taken
from `address_semantic.py` - whose `includes` has the same NAME and compares IPv4 intervals.

THE TWO GRAINS ARE TWO COMPILERS AND NOT ONE. `search/decryption_rulebase_coverage` serves
PAN-DEC-001 and PAN-DEC-009 over `integrations.DecryptionRulebaseVerdict`, because the state those
two controls report is that NO rule does something - and stage 4 measured the commonest state of
this domain as no decryption rulebase at all, where this model has no row to compare against.

ONLY THE COLUMNS A CONTROL ASKS FOR ARE HERE, which is the repo's rule, and three stored columns are
deliberately absent:

  `rule_uuid`     stage 5 marks it `needs_compiler_field` and NO clause, grading or `undetermined`
                  of this domain names it. It is the firewall's own identifier, it survives a
                  rename and two moves, and a reader is told it by the finding rather than by a
                  query - which is stage 9's business.
  `rule_position` the CONFIGURATION rank, stored because no configuration key holds the evaluation
                  order and a shadowing question could not otherwise be asked later. No control
                  asserts rule order; stage 5's own `not_stored` records the shadowing verdict as
                  absent. AND IT IS ONE COLUMN FOR TWO NUMBERS: `show running decryption-policy`
                  OMITS a disabled rule, so its `index:` runs one lower than the array position for
                  every rule below the first disabled one, and `SecurityRule` carries both under
                  `rule_position` and `effective_order` while stage 5 declared one. Registering this
                  would put a search surface over the half that is not the evaluation order.
  `type_branch`   which of the three `type` children is present. Named by no clause; what PAN-DEC-001
                  and PAN-DEC-009 need from it is already rolled into the verdict model's
                  `outbound_web_disposition` and `inbound_inspection_posture`, computed over the
                  branch. `log_success` and `log_setting` are absent for the same reason:
                  `success_record_disposition` is the one column PAN-DEC-010's second half compares,
                  because a grading holds exactly ONE column and those two states differ by two
                  columns at once.

`config_source` IS NOT REGISTERED EITHER, and it is the one a reader may expect. It is part of this
row's IDENTITY - the same rule NAME may exist in a device-group pre-rulebase and a post-rulebase at
the same scope - and the finding carries it in `subject_scope` for exactly that reason. No clause
names it, and `search/dos_policy_rule`, the sibling at this grain, registers the same four identity
fields and not this one.

`is_empty` IS THE BARE `field=""` SHAPE ON THE TWO COLUMNS THAT NEED IT AND THAT IS CORRECT HERE.
Measured across all 58 shipped compilers, 35 compile `is_empty` to `filter(field="")` alone and 22
OR an `__isnull=True` branch beside it; the bare shape silently matches nothing wherever the absent
case is stored as NULL. Both columns a clause asserts emptiness on - `description` (PAN-DEC-003) and
`profile_name` (PAN-DEC-008) - are `blank=True, default=""` and NEVER `null=True`, which OEI's own
model docstring says it chose for this reason in terms: "the search layer has no is-null operator,
so a positive comparison over NULL matches nothing and the control silently stops firing". So there
is no NULL for the bare filter to miss. The TWO-PATH identity fields are the exception and do take
the `__isnull`-OR shape, because exactly one of the enforcement point's two owners is set and the
other path is always NULL - the same argument `security_profile` and `dos_policy_rule` both make.

AND `is_empty` OVER A BOOLEAN IS REFUSED RATHER THAN INEFFECTIVE, with the refusal swallowed as a
skipped query, so the five booleans below advertise `eq` alone.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.decryption_policy_rule.fields.category import compile_category_clause
from assessments.search.decryption_policy_rule.fields.destination import (
    compile_destination_clause,
)
from assessments.search.decryption_policy_rule.fields.service import compile_service_clause
from assessments.search.decryption_policy_rule.fields.source import compile_source_clause
from assessments.search.decryption_policy_rule.fields.source_user import (
    compile_source_user_clause,
)
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import DecryptionPolicyRule

DECRYPTION_POLICY_RULE_MODEL = "integrations.DecryptionPolicyRule"


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        # EVERY path empty or missing. A rule's enforcement point has one owner, so the other
        # owner's path is always NULL - OR-ing the null branches would call every row empty. The
        # same shape the shipped `security_profile` and `dos_policy_rule` compilers argue for, and
        # for the same reason.
        predicate = Q()
        for lookup in lookups:
            predicate &= Q(**{lookup: ""}) | Q(**{f"{lookup}__isnull": True})
        return predicate
    if not isinstance(value, str) or not value.strip():
        raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
    suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
    predicate = Q()
    for lookup in lookups:
        predicate |= Q(**{f"{lookup}__{suffix}": value.strip()})
    return predicate


def build_text_compiler(field_name, *lookups):
    def compiler(clause):
        return DecryptionPolicyRule.objects.filter(
            _text_filter(field_name, lookups, clause)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return DecryptionPolicyRule.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column: ONE COLUMN, TWO FIELDS, and each field two lookup paths
    # because exactly one of the enforcement point's two owners is set. A reader recognises the
    # hostname and only the serial is guaranteed unique across an estate, which is why both exist
    # and why `serves` says so in the stage 8 artifact.
    "hostname": build_text_compiler(
        "hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    # Stage 5's `vsys_name`. The content is vsys-scoped, so the row is scoped to the enforcement
    # point and not to the appliance - stage 4 measured NINE independent decryption rulebases on
    # one multi-vsys PA-5220, which an appliance-grained row would collapse to one.
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # Stage 5's `rule_name` - the entry name an engineer reads in the grid.
    "rule_name": build_text_compiler("rule_name", "rule_name"),
    # THE APPLICABILITY PAIR SEVEN CONTROLS SHARE, and both defaults are load-bearing in the
    # INCLUSIVE direction. `action eq no-decrypt` is how stage 3's phrase "every rule that leaves
    # traffic encrypted" becomes one literal comparison, which it can only be because the grain is
    # one row per rule. `disabled eq false` keeps the population to rules actually IN FORCE, and
    # the materialised default is false - so an absent key keeps the rule inside the population
    # rather than excluding it, which is the suppressing shape rules.md names. A DISABLED exempting
    # rule is therefore asserted by nothing, and this domain's stage 3 recorded that in its
    # uncovered list.
    "action": build_text_compiler("action", "action"),
    "disabled": build_boolean_compiler("disabled", "disabled"),
    # PAN-DEC-003's assertion, written on the FIRING side because `is_empty` exists and its
    # negation does not. `TextField(blank=True, default="")` and never nullable - see the module
    # docstring on why the bare `is_empty` shape is right here.
    "description": build_text_compiler("description", "description"),
    # PAN-DEC-008's assertion, the same shape and the same reason. EMPTY DOES NOT MEAN NOTHING IS
    # APPLIED in general: stage 4 measured the device resolving an absent profile to the predefined
    # profile named `default` once `action` moved to `decrypt` on the inbound branch. PAN-DEC-008
    # confines itself with `action eq no-decrypt`, which is one of the conditions under which the
    # absent profile was measured resolving to nothing.
    "profile_name": build_text_compiler("profile_name", "profile_name"),
    # PAN-DEC-007's assertion, stored with THE VENDOR'S OWN POLARITY: true means the device's key
    # is `yes`, which means the match is INVERTED. The column name reads negative and the value
    # negates nothing. ASSUMED and not measured by stage 4 on this object, though stage 7 later
    # measured the oracle DOES render it as a `(negate)` suffix on the source member - recorded as
    # a gap rather than promoted here.
    "negate_source": build_boolean_compiler("negate_source", "negate_source"),
    # PAN-DEC-010's first assertion AND its grading axis. True is the failed-handshake record being
    # kept; ABSENT MEANS YES, measured in both directions and confirmed by the vendor twice, so the
    # materialised default is true and an unedited rule does not fire. That is where this domain
    # disagrees with stage 3, which graded an absent key as a finding at medium.
    "log_fail": build_boolean_compiler("log_fail", "log_fail"),
    # PAN-DEC-010's second applicability: whether the rule OPENS the session it matches, true for
    # either of `decrypt` and `decrypt-and-forward`. A DISJUNCTION the grammar cannot write - there
    # is no `or` inside a clause and no `in` operator - so it is a derived boolean, and TRUE is the
    # migration default deliberately: a boolean migrated false would exclude every rule in the
    # estate from that half and the control would report nothing.
    "opens_session": build_boolean_compiler("opens_session", "opens_session"),
    # PAN-DEC-010's second assertion AND its grading axis, over `log_success` and `log_setting`
    # together. ONE COLUMN AND NOT A COMPARISON BETWEEN TWO, for a mechanical reason: a grading
    # holds exactly one column and that half is graded at two severities whose states differ by two
    # columns at once. `no-record` is the worst of the three AND the migration default, so an
    # unrecomputed row reports itself.
    "success_record_disposition": build_text_compiler(
        "success_record_disposition", "success_record_disposition"),
    # PAN-DEC-006's assertion: whether EVERY member of the user criterion is one of the four device
    # keywords. A quantifier over a related row set, which the predicate has neither a quantifier
    # nor an `in` operator for. TRUE is the firing side and the migration default deliberately -
    # the framework's boolean default of false is the REASSURING side here and would pass every
    # people-keyed exemption in the estate until the recompute ran, with nothing erroring.
    "source_user_is_keyword_population": build_boolean_compiler(
        "source_user_is_keyword_population", "source_user_is_keyword_population"),
    # THE FIVE MEMBER CRITERIA, each one a row set in its own child model. See
    # `fields/member_criterion.py` for the shape, the one operator and why it is not
    # `address_semantic.py`'s `includes`.
    "category": compile_category_clause,
    "source": compile_source_clause,
    "destination": compile_destination_clause,
    "source_user": compile_source_user_clause,
    "service": compile_service_clause,
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_decryption_policy_rule_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_decryption_policy_rule_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def compile_search_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    # THE NEGATION INVERTS THE pk SET AND NOT THE COLUMN, which is what makes `does not include`
    # expressible at all: a rule with NO member rows for a criterion is outside the positive set
    # and therefore inside the negation, which is the correct reading of "this rule does not name
    # `any`". A column-level negation could not reach it.
    return ~predicate if clause["negated"] else predicate
