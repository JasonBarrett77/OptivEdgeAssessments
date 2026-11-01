"""Finding generation for an enforcement point's device-match verdict. PAN-IOT-004.

THE FINDING REPORTS THE ABSENCE OF A DIMENSION, NOT A LIST OF GAPS, and that is stage 3's own
settlement of what it can say without an engineer's answer. Which classes of unadministered
equipment exist and what each should reach is a question only a person can answer; absent it, the
finding says the policy has no device dimension at all.

WHY THE SUBJECT IS THE ENFORCEMENT POINT AND NOT THE RULE. 182 of the 188 rules measured carry
neither device element, so keying the finding on the rule would report one condition 182 times
and locate nothing. The row is a conclusion about the rule SET, taken over all three reads that
make it up - the firewall-local vsys rulebase, the Panorama pre- and post-rulebases pushed to it,
and the vendor's two predefined defaults.

THE TEST IS NOT WHETHER THE ELEMENT IS POPULATED, and a sentence that said so would be wrong
twice over. The elements are `source-hip` and `destination-hip` - there is no `source-device` on
any appliance measured, which is where stage 1 had put this control - and the 6 rules in the lab
that carry either element carry only the keyword `any`, which constrains nothing. So a rule set
with the elements filled in can still have no device dimension whatever, and the verdict resolves
each member against the device-object namespace instead.

TWO COUNTS ARE PRINTED AND THEY ANSWER DIFFERENT QUESTIONS:

* `device_object_count` at zero means NO RULE COULD NAME A DEVICE even if somebody wrote one,
  which is a different remediation from "no rule names one" - build the device objects first.
* `rules_matching_on_device_count` is the reachable form of the verdict, and ITS ACTION FILTER
  DIFFERS FROM THE VERDICT'S: it counts a `deny` rule that names a device and the verdict
  deliberately does not. So the two can be printed side by side and not reconcile, which a
  reader will not expect and which this sentence therefore says out loud.

TWO THINGS THE SENTENCE IS NOT ALLOWED TO CLAIM:

* WHICH RULEBASE THE ABSENCE SPANS. The verdict carries no scope column, so on an estate whose
  policy is pushed from Panorama a remediation read literally would have an engineer adding rules
  to a vsys rulebase the firewall will not accept them into. The distinction IS stored, on each
  rule's own `config_source`, and the sentence sends a reader there rather than guessing.
* THAT THE WHOLE RULE SET WAS READ. This subject has no "was this read" companion - the only one
  of the four in this domain without one - and the rule normalizer DROPS a rule whose address
  references it cannot resolve. A verdict over six rules of 109 is indistinguishable in this row
  from a verdict over all 109, so the sentence names the per-point normalization records as the
  thing to read beside it.

AND A DEVICE OBJECT IS NOT YET TOLD APART FROM A GLOBALPROTECT HIP PROFILE. One member list
holds device objects, HIP profiles and bare keywords all as plain strings; the only discriminator
is resolving the member against the device-object namespace, so a HIP profile sharing a name with
a device object would be counted as a device match. No HIP profile exists anywhere in the lab, so
the gap is inert here and wrong on the first estate that uses host posture.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_rulebase_device_match_control_queries
from assessments.models import (
    Control,
    RulebaseDeviceMatchFinding,
    RulebaseDeviceMatchFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import RulebaseDeviceMatchVerdict


def _no_device_dimension(obj) -> list[str]:
    """PAN-IOT-004's only expressible half: does the policy match on what a device IS."""
    if not obj.has_no_rule_matching_on_device:
        return []
    parts = [
        "no rule this enforcement point evaluates permits traffic on the basis of what the "
        "device IS - the policy has no device dimension at all, so a rule written for "
        "unadministered equipment cannot be distinguished from one written for anything else "
        "sharing its addresses",
    ]
    if not obj.device_object_count:
        parts.append(
            "AND THERE IS NOTHING FOR A RULE TO NAME: this enforcement point resolves no device "
            "objects in any scope - vsys, firewall-local shared or pushed - so the remediation "
            "starts with defining them and not with editing the policy. That is a different fix "
            "from a policy that ignores objects which exist")
    else:
        parts.append(
            f"this enforcement point could resolve {obj.device_object_count} device object(s), "
            f"so the objects exist and the policy does not use them")
    if obj.rules_matching_on_device_count:
        parts.append(
            f"a separate count of rules naming a device object in either element, taken WITHOUT "
            f"an action filter, is {obj.rules_matching_on_device_count} - it includes a rule "
            f"that DENIES on a device, which the verdict above deliberately does not, so the two "
            f"numbers are not expected to reconcile")
    parts.append(
        "THE REMEDIATION DEPENDS ON WHERE THIS POLICY IS WRITTEN and this row cannot say: the "
        "verdict spans the firewall's own rulebase, anything pushed to it and the vendor's "
        "default rules together, so check each rule's own source before adding anything locally "
        "- a firewall whose policy is pushed will refuse it")
    parts.append(
        "AND READ THIS BESIDE THIS POINT'S NORMALIZATION RECORDS. Nothing in this row says how "
        "much of the rule set was actually read, and a rule whose address references could not "
        "be resolved is dropped before the verdict is taken - so a verdict over part of a "
        "rulebase looks exactly like a verdict over all of it")
    return parts


#: WHICH FACTS THIS CONTROL'S FINDING MAY STATE. One control and one half of it: the other half -
#: whether the service's own rule recommendations are ever looked at - is an engineer's answer on
#: a cycle no device records, so no part here speaks to it. The firewall records when a
#: recommendation was imported and never records whether anybody read the ones that were not.
PARTS_BY_CONTROL = {
    "PAN-IOT-004": (_no_device_dimension,),
}


def _subject(obj, control_id: str) -> str:
    appliance = obj.enforcement_point.appliance or obj.enforcement_point.appliance_group
    parts = [f"device matching in the policy of {obj.enforcement_point.vsys_name} "
             f"on {appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, (_no_device_dimension,)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_rulebase_device_match_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


def _appliance_scope(obj) -> str:
    appliance = obj.enforcement_point.appliance
    return str(appliance.hostname if appliance is not None
               else obj.enforcement_point.appliance_group)


SPEC = ObjectFindingSpec(
    label="rulebase device match",
    control_type=Control.ControlType.RULEBASE_DEVICE_MATCH,
    finding_model=RulebaseDeviceMatchFinding,
    link_model=RulebaseDeviceMatchFindingControlQuery,
    subject_fk="rulebase_device_match_verdict",
    link_fk="rulebase_device_match_finding",
    queryset=lambda: RulebaseDeviceMatchVerdict.objects.select_related(
        "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group"),
    evaluate=evaluate_rulebase_device_match_control_queries,
    summary=build_rulebase_device_match_finding_summary,
    # The vsys, because the row has no entry name - a rule's own name would be the wrong thing to
    # print on a verdict about all of them.
    subject_name=lambda obj: obj.enforcement_point.vsys_name,
    subject_scope=_appliance_scope,
)


def generate_rulebase_device_match_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_rulebase_device_match_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
