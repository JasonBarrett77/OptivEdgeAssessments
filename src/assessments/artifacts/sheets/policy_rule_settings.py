"""Engineer-detail xlsx: the two device-wide switches the rulebase controls depend on.

`security-policy`, stage 9, 2026-11-01. PAN-POL-011, WHICH SHIPS INACTIVE.

THIS TAB IS EMPTY TODAY AND THAT IS NOT THE SAME AS BROKEN. Its one control is switched off by
Jason's decision of 2026-10-31 - "Let's just leave PAN-POL-011 as disabled or not in use" -
because `PolicyRuleSettings.disable_shadow_rule_check` is a nullable boolean whose implicit value
has never been measured, the control's clause reads `is not false` so that NULL reports, and the
key is absent on every appliance in the lab: as written it would report every appliance on the
strength of a reading nobody took. So the tab draws its header, its column set and "No findings",
and `selected_controls` returns nothing for it. The alternative was no tab, and the contract this
run works to says a tab with no rows is indistinguishable from a tab that is broken - which cuts
both ways: a MISSING tab for a shipped control type is indistinguishable from a control nobody
built. The tab exists, with the reason in the sheet's own description.

ONE ROW PER APPLIANCE, which on an HA pair is TWO ROWS FOR ONE NODE. The node sits at
`deviceconfig/setting/management` and has no vsys axis, so stage 5 declared this subject
device-wide and recorded that it yields two rows for one real configuration. THIS TAB DOES NOT
FOLD THEM, and the reason is in the integrations model rather than in this file: the two peers'
management containers have been measured DIFFERING while config sync reported synchronized, so a
difference between peers is data and not a normalization fault. Folding on the pair would hide
exactly the reading that matters. The HA role column is what makes the pair legible instead. This
run's artifact records the question as unsettled and says what would settle it.

THE APPLIANCE COLUMNS ARE THE DEFAULT ONES, deliberately: this is an appliance-scoped settings
row, the shape `DEFAULT_SUBJECT_COLUMNS` exists for, and inventing columns for it would be the
copying `findings.py` was written to stop.
"""
from __future__ import annotations

from assessments.models import Control

from . import findings as findings_sheet
from ..layout import SheetInfo

#: PROPOSED HEADINGS for the derived setting columns, and both are proposals rather than
#: decisions. Neither renders today - no active control tests either field, so no column is
#: derived - and they are written now so that switching PAN-POL-011 on is a one-line change
#: rather than a presentation decision taken in a hurry.
#:
#: THE POLARITY IS THE WHOLE CARE HERE. `disable_shadow_rule_check` is the device's own key and
#: the device's own polarity is kept on the column: TRUE means the check has been SUPPRESSED. A
#: heading reading "Shadow rule check" beside a cell reading "Yes" would say the opposite of the
#: truth, which is the failure mode this run's contract calls "a wrong presentation sends someone
#: to the wrong device". So the heading names the SUPPRESSION.
SETTING_LABELS = {
    "disable_shadow_rule_check": "Shadow-rule check suppressed",
    # PAN-POL-013's first record, which this domain does not build as a control. The column is
    # here because the rule-age finding on the Security Rules tab is worth nothing without it:
    # an appliance that is not counting answers `hit-count: 0` for every rule, which is
    # byte-identical to a rule that has never matched.
    "rule_hit_count_enabled": "Rule hit count enabled",
}

SPEC = findings_sheet.DeviceSettingSheet(
    title="Policy Rule Settings",
    control_types=(Control.ControlType.POLICY_RULE_SETTINGS,),
    #: The appliance and its HA role - `DEFAULT_SUBJECT_COLUMNS`. The HA role is load-bearing on
    #: this tab: see the module docstring on why the two peers are not folded.
    auto_setting_columns=True,
    setting_labels=SETTING_LABELS,
    tested_columns=("Fires when (failing condition)", "Provenance"),
    description=("Two device-wide switches at Device > Setup > Management that decide what the "
                 "firewall's own rule analysis is worth: whether it counts how often each rule "
                 "is matched, and whether its shadow-rule check has been suppressed. NO "
                 "FINDINGS ARE REPORTED HERE TODAY: the one control over them is switched off, "
                 "because the key it reads is absent on every appliance measured and nobody has "
                 "established what an absent key means - so as written it would report every "
                 "appliance on the strength of a reading nobody took."),
)


def write_sheet(build) -> SheetInfo:
    return findings_sheet.write_sheet(build, SPEC)
