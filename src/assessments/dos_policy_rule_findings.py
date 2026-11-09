"""Finding generation for one DoS Protection policy rule. PAN-ZON-007.

ONE CONTROL AND ONE OF ITS TWO HALVES. Stage 5 discharges PAN-ZON-007's first record onto a
question for a person - which services behind this firewall are published to the internet or
business-critical, and on which addresses and ports each answers - because the firewall holds the
rules, the profiles and the destination addresses and NOTHING IN IT SAYS WHICH DESTINATION IS A
CROWN-JEWEL SERVICE. That half owes no query and has no finding. What this module reports is the
half a configuration settles: the rules that DO exist enforce the profile they name.

THE RULE IS THE SUBJECT AND THE PROFILE IS NOT, which stage 5 records as a choice between two
defensible answers. What an engineer edits to close this finding is the rule; naming the profile
would have been wrong because a profile is not what is missing, and naming nothing is not
available.

WHAT THIS GENERATOR CANNOT SAY, AND IT IS THE MORE IMPORTANT HALF OF THE CONTROL. That no DoS rule
covers a particular service is not derivable from any configuration - stage 3's own words are that
"a finding naming a service without the inventory behind it is a guess dressed as a gap". That no
rule of this kind exists ANYWHERE on the appliance IS deliverable, and it is a different assertion
at a different grain: a verdict per appliance rather than per rule. No model holds that verdict and
writing it here would be taking stage 3's decision about what this control asserts, so it is a gap
recorded in the stage 8 artifact rather than a sentence invented here. The consequence is concrete:
on an appliance with NO DoS rules at all this control produces nothing, and nothing produces
nothing, which from the outside is indistinguishable from an appliance whose rules are all correct.

THE DISPATCH DEFAULTS TO `()`, for the reason `zone_protection_profile_findings` gives at length:
a default that is another control's arms is how a control reusing a type gets described with
someone else's claims, and this domain repaired exactly that in `zone_findings`.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_dos_policy_rule_control_queries
from assessments.models import (
    Control,
    DosPolicyRuleFinding,
    DosPolicyRuleFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import DosPolicyRule


def _action_does_not_protect(obj) -> list[str]:
    """PAN-ZON-007's configurational half: does the rule's action consult the profile it names."""
    if obj.rule_action == "protect":
        return []
    named = ", ".join(
        f"{slot} `{value}`" for slot, value in (
            ("aggregate", obj.aggregate_profile), ("classified", obj.classified_profile))
        if value) or "a profile slot that could not be read"
    if obj.rule_action == "allow":
        found = (
            f"THIS RULE NAMES {named} AND ITS ACTION IS `allow`, so the rule matches, passes "
            "everything and consults the profile it names for nothing. Only `protect` applies a "
            "DoS Protection profile - the vendor says so without hedging in two documents - so "
            "this configuration reads as protected and meters nothing")
    elif obj.rule_action == "deny":
        found = (
            f"THIS RULE NAMES {named} AND ITS ACTION IS `deny`, so the traffic it matches is "
            "dropped outright and the profile it names is never consulted. The service is "
            "protected by refusal rather than by metering, which is a misconfiguration rather "
            "than an exposure - and the vendor permits `deny` DELIBERATELY to carve an exception "
            "out of a group, so read the rule above this one before changing anything")
    else:
        found = (
            f"THIS RULE NAMES {named} AND ITS ACTION READS "
            f"`{obj.rule_action or 'as nothing this reader could resolve'}`, which is not "
            "`protect` - the only action that applies the profile")
    return [
        found,
        f"it is rule {obj.rule_position} of the {obj.get_config_source_display().lower()} DoS "
        "rulebase of this vsys, and POSITION IS PART OF WHAT THIS ROW IS: a DoS rulebase resolves "
        "by order, so a rule above this one may already have matched the traffic you are looking "
        "at. The position is not part of the row's identity, because a rule keeps its name across "
        "a move",
        "WHETHER THIS RULE'S PROFILE COUNTS PER DEVICE OR PER MATCHED GROUP IS NOT ASSERTED HERE. "
        "That property is a field of the PROFILE and not of this rule, and the catalog row "
        "points at the rule's own aggregate slot instead - so a reading taken from the row reports "
        "the preferred state as absent on a rule that satisfies it",
        "AND A RULE MAY BE SWITCHED OFF WITHOUT THIS FINDING KNOWING. No implicit was measured for "
        "the disable key on this object, and a wrong guess would suppress every rule in the estate "
        "silently - so this fires regardless, and a finding naming a disabled rule is a false "
        "finding checkable in seconds rather than a missed exposure",
    ]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. One control today, and the default is `()`.
PARTS_BY_CONTROL = {
    "PAN-ZON-007": (_action_does_not_protect,),
}


def _owner(obj) -> str:
    point = obj.enforcement_point
    appliance = point.appliance
    owner = str(appliance.hostname if appliance is not None else point.appliance_group)
    return f"{owner} / {point.vsys_name}"


def _subject(obj, control_id: str) -> str:
    parts = [f"DoS Protection rule {obj.rule_name} in {_owner(obj)}"]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_dos_policy_rule_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="DoS policy rule",
    control_type=Control.ControlType.DOS_POLICY_RULE,
    finding_model=DosPolicyRuleFinding,
    link_model=DosPolicyRuleFindingControlQuery,
    subject_fk="dos_policy_rule",
    link_fk="dos_policy_rule_finding",
    queryset=lambda: DosPolicyRule.objects.select_related(
        "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group"),
    evaluate=evaluate_dos_policy_rule_control_queries,
    summary=build_dos_policy_rule_finding_summary,
    # The rule's own entry name. NOT `obj.name`, which this model does not have.
    subject_name=lambda obj: obj.rule_name,
    # The appliance, the vsys AND the rulebase. A rule name is unique only per point and
    # rulebase - the shipped constraint is `(enforcement_point, config_source, rule_name)` - so a
    # local rule and a Panorama pre-rule of the same name are different objects a reader must
    # tell apart.
    subject_scope=lambda obj: f"{_owner(obj)} / {obj.config_source}"[:128],
)


def generate_dos_policy_rule_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_dos_policy_rule_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
