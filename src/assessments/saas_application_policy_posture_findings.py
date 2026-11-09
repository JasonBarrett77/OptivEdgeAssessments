"""Finding generation for the SaaS application-policy control. PAN-SAS-003.

THE TWO FAILING STATES ARE THE SAME `false` AND A READER HAS TO BE TOLD WHICH ONE IT IS.
`function_apps_are_refused` is false both where a rule names an upload or sharing function and
PERMITS it, and where NO rule names any of them - and the second is the state every appliance in
this lab was in before stage 6 wrote six rules. `function_app_rule_count` is what tells them
apart, and the sentence reads it rather than reporting a bare verdict. The direction matters:
naming the functions and then permitting them is worse than not naming them, because it reads as
control.

THREE THINGS THE SENTENCE IS NOT ALLOWED TO SAY:

* THAT THE ACTION IS `deny` OR IS NOT. The `action` leaf's value set is six and `drop`,
  `reset-client`, `reset-server` and `reset-both` are all denials in this control's sense while
  none of them is the string `deny`. So the sentence reports the token it read and calls it a
  refusal or a permission, never the literal the catalog's set command happens to write.
* THAT THE FUNCTION APPLICATIONS WERE ENUMERATED. The population comes from the predefined
  application catalog, which is delivered by content updates and which this pipeline has not
  enumerated - 5,164 entries on one lab build and 5,166 on another. So any count of rules naming
  a function child application is a LOWER BOUND, and where the catalog was never collected both
  columns hold their firing defaults and the sentence says nobody enumerated them.
* THAT A REFUSAL IS IN FORCE. A DISABLED RULE COUNTS toward this verdict - the normalizer that
  writes it records that decision and records that it is probably wrong - so where the verdict
  passes, no finding is written and nothing here claims a session would meet the deny. Where it
  fails, the sentence stands either way.

AND THE HALF OF PAN-SAS-004 THAT LANDS ON THIS SUBJECT AND HAS NO CONTROL. The attribute-driven
selection columns - `cloud_app_selection_is_refused`, `cloud_app_selection_excludes_approved`,
`cloud_app_filter_count` - are read here by `_attribute_selection`, which is reachable only
through an UNMAPPED control. PAN-SAS-004's `control_type` resolves to the URL-filtering posture
and `ControlQuery.clean()` refuses a query on another model, so nothing invokes it today. It is
written rather than omitted because the alternative is a finding with no detail, which is
indistinguishable from a finding about a sound partition.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_saas_application_policy_posture_control_queries,
)
from assessments.models import (
    Control,
    SaasApplicationPolicyPostureFinding,
    SaasApplicationPolicyPostureFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import SaasApplicationPolicyPosture

#: What the finding calls each first-match action. The five refusals are named as refusals
#: because `deny` is not the only one, which is the measured point of the six-value set.
ACTION_PROSE = {
    SaasApplicationPolicyPosture.ACTION_ALLOW: "permits them",
    SaasApplicationPolicyPosture.ACTION_DENY: "refuses them with a deny",
    SaasApplicationPolicyPosture.ACTION_DROP: "refuses them by dropping the session silently",
    SaasApplicationPolicyPosture.ACTION_RESET_CLIENT: "refuses them with a reset to the client",
    SaasApplicationPolicyPosture.ACTION_RESET_SERVER: "refuses them with a reset to the server",
    SaasApplicationPolicyPosture.ACTION_RESET_BOTH: "refuses them with a reset to both ends",
}


def _function_apps(obj) -> list[str]:
    if obj.function_apps_are_refused:
        return []
    if obj.effective_action_for_function_apps == SaasApplicationPolicyPosture.ACTION_NO_RULE:
        # THE SENTINEL, and the state this control is most often failed by. It sorts as benign on
        # any equality against `allow` and means the opposite of benign.
        return ["NO RULE OF THIS PARTITION NAMES ANY UPLOAD, SHARING OR DELETE FUNCTION of a "
                "cloud application, so there is no action to read and nothing distinguishes "
                "browsing an application from moving data into it. That is an absence rather "
                "than a value, and it is the state the control is most often failed by. The "
                "population comes from the predefined application catalog, which content "
                "updates deliver and which this assessment has not enumerated - so if that "
                "catalog was never collected, this reads the same as a rulebase nobody walked"]
    prose = ACTION_PROSE.get(
        obj.effective_action_for_function_apps,
        f"carries the action `{obj.effective_action_for_function_apps}`, which no ordering in "
        f"this control ranks")
    detail = (f"{obj.function_app_rule_count} rule(s) of this partition's merged rulebase - "
              f"local, pushed pre and pushed post together - name at least one function child "
              f"application, and the first rule that matches the weakest of them {prose}")
    if obj.effective_action_for_function_apps == SaasApplicationPolicyPosture.ACTION_ALLOW:
        detail += (" - so the rulebase shows the granularity somebody intended and enforces the "
                   "opposite of it, which is worse than not naming the functions at all")
    detail += (". The count is a LOWER BOUND over a catalog delivered by content updates and "
               "not enumerated here")
    return [detail]


def _attribute_selection(obj) -> list[str]:
    """PAN-SAS-004's second half. NOT REACHABLE FROM ANY CONTROL TODAY - see the module docstring."""
    parts = []
    if not obj.cloud_app_selection_is_refused:
        if obj.cloud_app_filter_count:
            parts.append(
                f"{obj.cloud_app_filter_count} application filter(s) reachable from this "
                f"partition select cloud applications by attribute and no rule that names one "
                f"refuses what it selects - so the selection exists as a definition and catches "
                f"nothing")
        else:
            parts.append(
                "no application filter reachable from this partition selects cloud applications "
                "by attribute, so the policy names them one at a time and nothing catches a "
                "cloud service that appears after the policy was written")
    if obj.cloud_app_filter_count and not obj.cloud_app_selection_excludes_approved:
        parts.append(
            "no such selection carves the organization's own approved applications out of "
            "itself - neither by naming them in the filter's exclusion list nor by selecting on "
            "the approval marking - so it catches the approved applications too")
    return parts


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. `_attribute_selection` is deliberately absent
#: from PAN-SAS-003's tuple: a finding about an upload function sent to Objects > Application
#: Filters is a reader at the wrong screen.
PARTS_BY_CONTROL = {
    "PAN-SAS-003": (_function_apps,),
}


def _subject(obj, control_id: str) -> str:
    appliance = obj.enforcement_point.appliance or obj.enforcement_point.appliance_group
    parts = [f"SaaS application policy posture of {obj.enforcement_point.vsys_name} "
             f"on {appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, (_function_apps, _attribute_selection)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_saas_application_policy_posture_finding_summary(obj, matched_queries) -> str:
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
    label="SaaS application policy posture",
    control_type=Control.ControlType.SAAS_APPLICATION_POLICY_POSTURE,
    finding_model=SaasApplicationPolicyPostureFinding,
    link_model=SaasApplicationPolicyPostureFindingControlQuery,
    subject_fk="saas_application_policy_posture",
    link_fk="saas_application_policy_posture_finding",
    queryset=lambda: SaasApplicationPolicyPosture.objects.select_related(
        "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group"),
    evaluate=evaluate_saas_application_policy_posture_control_queries,
    summary=build_saas_application_policy_posture_finding_summary,
    subject_name=lambda obj: obj.enforcement_point.vsys_name,
    subject_scope=_appliance_scope,
)


def generate_saas_application_policy_posture_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_saas_application_policy_posture_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
