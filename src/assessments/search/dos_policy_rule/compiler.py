"""Canonical search compiler for one DoS Protection policy rule. PAN-ZON-007.

ONE ROW PER NAMED RULE PER RULEBASE PER VSYS, so the owner is reached through the enforcement
point and the appliance lookups branch on either owner - `appliance` set means locally managed,
`appliance_group` set means Panorama-managed. That is the same two-path shape every
enforcement-point-owned compiler in this package uses.

THE RULE AND NOT THE PROFILE IS THE SUBJECT, and stage 5 records that as a choice between two
defensible answers. The finding PAN-ZON-007 wants names a SERVICE, and a service is no model's
subject anywhere in this estate; what an engineer edits to close the finding is the rule, and the
profile is read rather than named. Naming the profile would have been wrong because a profile is
not what is missing.

HALF OF THIS CONTROL OWES NO QUERY AND THAT IS NOT A GAP HERE. Stage 5 discharges PAN-ZON-007's
first record onto a question for a person - which services behind this firewall are published or
business-critical, and on which addresses they answer - because nothing in a firewall says which
destination is a crown-jewel service. So the five match criteria (`from`, `to`, `source`,
`destination`, `service`) have no column on the model at all, let alone a field here: storing five
member lists to support a question nobody can ask from the configuration is cost with no control
behind it. What remains, and what this compiler serves, is the half a configuration settles - that
the rules which DO exist enforce the profile they name.

`rule_action` IS BOTH THE ASSERTION AND THE GRADING AXIS, which is why it is the only text field
here that three queries use. The assertion is a NEGATED equality against `protect` - a clause flag
in this language rather than an operator, so "any value except this one" over a three-member enum
needs no OR group - and the grading places the other two members apart because they are NOT
equally bad: `allow` matches and passes everything while the configuration reads as protected, and
`deny` drops the traffic, which protects the service by refusal rather than by metering and is
something the vendor permits deliberately to carve an exception out of a group.

THE THREE ARMS ARE CHILD ELEMENTS AND NOT VALUES OF A LEAF, measured on three builds, with the
stored shape `action: {'protect': None}`. That changes how the column is FILLED and not what it is
compared to - it is a normalisation fact and it is recorded here because a later reader of this
module expecting a string leaf would be reading a different node. The key is also MANDATORY at
commit validation, so the column is always present on a committed rule: its unknown case is an
unreadable rule rather than an absent key.

`rule_disabled` IS DECLARED ON THE MODEL AND IS DELIBERATELY NOT REGISTERED. Stage 4 measured NO
implicit for it on this object and a wrong guess reads catastrophically: if an absent key were
taken to mean "disabled" the control would suppress every rule in the estate, silently. Firing
regardless means a finding may name a rule that is switched off, which is a false finding
checkable in seconds, and that is the direction rules.md asks for. Registering the column would
make the narrowing one clause away.

`rule_position` IS NOT REGISTERED EITHER, for a different reason. Stage 7 stores it as plumbing
because a rulebase resolves by order and stage 5 declared no such column; nothing in this domain
names it, and a field earns its place by a control needing it.

`classified_profile`, `classification_address` AND `aggregate_profile` ARE NOT REGISTERED. They
are what PAN-ZON-007's engineer-answered half would need - the adjective its preferred state turns
on lives on the PROFILE (`SecurityProfile.profile_type`) and the slot it is set in is the rule's -
and stage 5 clauses on none of them. `names_a_profile` below is the one fact about those slots
that a clause does need.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import DosPolicyRule

DOS_POLICY_RULE_MODEL = "integrations.DosPolicyRule"


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        # EVERY path empty or missing. A rule has one owner, so the other owner's path is
        # always NULL - OR-ing the null branches would call every row empty. The same shape the
        # shipped `security_profile` compiler argues for, and for the same reason.
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
        return DosPolicyRule.objects.filter(
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
        return DosPolicyRule.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column: one column, two fields, and each field two lookup paths
    # because exactly one of the enforcement point's two owners is set.
    "hostname": build_text_compiler(
        "hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    # Stage 5's `enforcement_point` column. A rule name is unique only per point and rulebase,
    # so the vsys is part of the rule's identity and not a convenience.
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # Stage 5's `rule_name` - the rule's own entry name.
    "rule_name": build_text_compiler("rule_name", "rule_name"),
    # PAN-ZON-007's APPLICABILITY, and it is load-bearing rather than tidy. TRUE is in the
    # population: the rule names a profile in at least one of its two protection slots. The
    # vendor permits `deny` DELIBERATELY to carve an exception out of a group, so a rule carrying
    # no profile and set to deny is a legitimate configuration and firing on it would be a false
    # finding. This clause is repeated in every query the grading produces.
    "names_a_profile": build_boolean_compiler("names_a_profile", "names_a_profile"),
    # PAN-ZON-007's ASSERTION and its GRADING AXIS, both. The assertion is `is not protect`,
    # written as a negated equality; the two calibrations are equalities on the other two
    # members. Mutually exclusive on a single-valued column, which is what makes the
    # baseline-tier calibration safe to build: no row can match two of them.
    "rule_action": build_text_compiler("rule_action", "rule_action"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_dos_policy_rule_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_dos_policy_rule_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def compile_search_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause["negated"] else predicate
