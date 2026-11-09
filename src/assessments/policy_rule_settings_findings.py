"""Finding generation for one appliance's device-wide policy-rule switches.

PAN-POL-011, which SHIPS INACTIVE. Minted by stage 8 of `security-policy`, 2026-11-01.

WHY THIS MODULE EXISTS FOR A CONTROL THAT DOES NOT FIRE. Jason, 2026-10-31, recorded in stage 5's
own record for the control: "Let's just leave PAN-POL-011 as disabled or not in use." The
catalog entry carries `is_active: false`, which this project's own convention establishes as
the way a question stays in the catalog with its reason and generates no findings by design.
The generator ships with it so that switching the control on is one field and not a build - and
so that `finding_run.GENERATORS` has the line a test fails without.

THE REASON IS IN THE COLUMN AND NOT IN THE CONTROL. `disable_shadow_rule_check` is a nullable
boolean whose implicit value stage 4 left UNMEASURED, deliberately: the leaf is a NEGATIVE whose
being set suppresses the very evidence the control's other half rests on, so inferring `no` from
its name would hand the reassuring answer to the configuration the control exists to catch. The
restatement therefore clauses it `is not false`, NULL matches, and the key is absent on every
appliance in the lab - so the control as written would report every appliance in an estate on the
strength of a reading nobody took.

WHAT WOULD SETTLE IT IS NOT A SCREEN. There is no UI control for the key - the vendor's Policy
Rulebase Settings panel enumerates its controls and this is not among them, and `shadow` appears
in the 11.1 and 11.2 Help only under Validate Commit and in the commit-warnings list. The feature
surfaces as a `Rule Shadow` commit warning, so the experiment is two rules where one shadows the
other in a vsys of an appliance where the key is absent, then one `validate full`. That is a
commit gate, which no collector may issue.

A COVERAGE CONTROL WAS CONSIDERED AND DROPPED on the same day, and the reason belongs here
because the next reader will think of it: the gap is not a failed normalization, so it does not
fit the shipped `NORMALIZATION` type over `integrations.NormalizationIssue`, and reporting it
over this model would have cost a companion column in integrations, a migration, a control type,
a target-model entry, a finding model, a registry entry and a compiler. Holding the control is
cheaper and more honest until the implicit is measured.

THE OTHER COLUMN OF THIS MODEL HAS NO CONTROL HERE AT ALL. `rule_hit_count_enabled` is
PAN-POL-013's first assertion record, and PAN-POL-013 is built at the per-RULE grain instead -
`probe.relation_between` finds NO relation between `PolicyRuleSettings` and `SecurityRule` in
either direction, so a control reaches one of the two and is silent about the other. That half's
implicit HAS since been measured, in the direction that an absent key asserts counting is ON, so
the clause `is not true` correctly passes an appliance whose key is absent - which is why the
half going silent costs less than PAN-POL-011's would have.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_policy_rule_settings_control_queries
from assessments.models import (
    Control, PolicyRuleSettingsFinding, PolicyRuleSettingsFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import PolicyRuleSettings


def _shadow_check(obj) -> list[str]:
    """PAN-POL-011's first half. THREE STATES AND THEY READ DIFFERENTLY TO A CUSTOMER.

    `True` is the device's own key set, which SUPPRESSES the shadow check. `None` is the key
    absent, where nobody has established what the device does - and the control reports it,
    because a device with the check off produces zero shadow warnings for exactly the same
    reason a clean rulebase does. The sentence has to say which of the two it found, or an
    engineer sent to turn the check on will not find it turned off.
    """
    if obj.disable_shadow_rule_check is True:
        return [f"THE FIREWALL'S OWN SHADOW-RULE CHECK IS SUPPRESSED ON {obj.appliance}: "
                f"`disable-shadow-rule-check` is set, so this appliance reports no unreachable "
                f"rules for the same reason a clean rulebase does, and a rulebase nobody has "
                f"checked is signed off as one that has been"]
    if obj.disable_shadow_rule_check is None:
        return [f"WHETHER THE SHADOW-RULE CHECK RUNS ON {obj.appliance} COULD NOT BE "
                f"ESTABLISHED: the `disable-shadow-rule-check` key is absent and what an absent "
                f"key means has not been measured - the vendor publishes no default for it and "
                f"there is no screen that reads it back. This is reported rather than passed "
                f"because the key is a negative: if it is in force, every shadow warning this "
                f"appliance would have raised is already missing"]
    return []


def _hit_count(obj) -> list[str]:
    """`rule_hit_count_enabled`, which NO CONTROL ON THIS MODEL ASSERTS TODAY.

    Written so the arm exists for the day PAN-POL-013's first record gets an id of its own, and
    reachable from no shipped query - see the module docstring on the silent half.
    """
    if obj.rule_hit_count_enabled is True:
        return []
    state = ("is switched off" if obj.rule_hit_count_enabled is False
             else "could not be read")
    return [f"RULE USAGE COUNTING ON {obj.appliance} {state}, so every rule on this appliance "
            f"reads as never matched whether or not it is carrying traffic - and a rule reading "
            f"as unused is then no evidence at all"]


#: Keyed by control id, defaulting to `()`. A default that is PAN-POL-011's arms is how the next
#: control on this type gets described with PAN-POL-011's claim, which this repository has
#: repaired elsewhere twice.
PARTS_BY_CONTROL = {
    "PAN-POL-011": (_shadow_check,),
}


def _subject(obj, control_id: str = "") -> str:
    parts: list[str] = []
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    if not parts:
        return f"the device-wide policy rule settings of {obj.appliance}"
    return "; ".join(parts)


def build_policy_rule_settings_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="policy rule settings",
    control_type=Control.ControlType.POLICY_RULE_SETTINGS,
    finding_model=PolicyRuleSettingsFinding,
    link_model=PolicyRuleSettingsFindingControlQuery,
    subject_fk="policy_rule_settings",
    link_fk="policy_rule_settings_finding",
    queryset=lambda: PolicyRuleSettings.objects.select_related("appliance"),
    evaluate=evaluate_policy_rule_settings_control_queries,
    summary=build_policy_rule_settings_finding_summary,
    # The appliance's own name. The subject is APPLIANCE-grained, so no `subject_scope` is
    # needed: a hostname is the scope.
    subject_name=lambda obj: str(obj.appliance)[:64],
)

PolicyRuleSettingsFindingRunResult = ObjectFindingRunResult


def generate_policy_rule_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_policy_rule_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
