"""One view per security-profile kind, over RULES.

Jason, 2026-10-12: "We need to present each security profile finding on its own. Separate views
for antivirus, antispyware, etc. Still rule based."

Eleven controls about security profiles report per rule since that day, and they all carry the
`security_rule` control type - the same type as the twenty-odd PAN-POL controls. On one sheet
they read as a pile: an antivirus decoder gap, a DNS sinkhole gap and a brute-force gap are
three unrelated jobs for three different people, and the thing to fix is a different profile in
each case.

So four sheets, one per profile kind, each the rules sheet filtered to that kind's controls:

    Antivirus (by rule)              PAN-AVW-001, PAN-AVW-002
    Anti-Spyware (by rule)           PAN-SPY-001 .. PAN-SPY-005
    Vulnerability Protection (by rule)  PAN-VLN-001 .. PAN-VLN-004
    WildFire Analysis (by rule)      PAN-AVW-003

**The columns are the rules sheet's, deliberately.** The subject is a rule, so what an engineer
scans for is unchanged - which rule, where, what it matches - and a different column set per
kind would break the agreement the rules sheet keeps with the rules page. What differs is the
Profiles cell: on each sheet it names only THAT kind's verdicts, because on the anti-spyware
sheet a vulnerability gap is another sheet's subject.

**PAN-AVW-006 is not here and cannot be.** "Unused AV / WildFire Profiles" is about a profile
NO rule uses; there is no rule to report it on, so it stays profile-based on the
security-profiles sheet. A fifth per-kind view would be empty by construction.

**The generic rules sheet excludes all eleven** - see `EVERY_PROFILE_CONTROL`, which it names in
`exclude_control_ids` - so nothing is reported twice. The PAN-POL controls stay there, which is
what that sheet has always been about: the rule itself rather than what inspects it.
"""

from __future__ import annotations

from assessments.models import Control

from . import findings as findings_sheet
from . import profile_kinds
from . import security_rules

KINDS = profile_kinds.KINDS
EVERY_PROFILE_CONTROL = profile_kinds.EVERY_PROFILE_CONTROL
_DESCRIPTIONS = profile_kinds.DESCRIPTIONS

def _subject_columns(verdict_fields):
    """The rules sheet's columns, with a Profiles cell narrowed to one kind's verdicts."""
    narrowed = []
    for column in security_rules.SUBJECT_COLUMNS:
        if column[0] != "Profiles":
            narrowed.append(column)
            continue
        header, width, wrap, _read, *rest = column
        narrowed.append((header, width, wrap,
                         lambda rule, _p, _f=verdict_fields:
                         security_rules.profiles_in_force(rule, _f),
                         *rest))
    return tuple(narrowed)


#: Fields a kind's controls assert on that are NOT one of the satellite's assertion names, with
#: the column that already says each one. `hidden_fields` is a statement that something else on
#: the sheet carries the fact, so each entry here has to name what.
_EXTRA_HIDDEN = {
    "vulnerability-protection": (
        # PAN-VLN-004's grading axis, which its two calibration queries clause on. The Profiles
        # cell prints that control's own verdict detail - "<n> exception(s): <surfaces>" - so the
        # WIDEST surface is the same fact as that line, the way `*_breadth_known` on the generic
        # rules sheet is the same fact as a host count reading Unknown. Whether it deserves a
        # column of its own is a presentation decision and is not made here.
        "vulnerability_widest_exemption_surface",
        # The coverage companion all four PAN-VLN controls carry. `threat_profile_lines` prints
        # one line for a rule with no verdict row for any assertion, which is the only state
        # this column is False in - so the cell says "assessment has not run" rather than
        # leaving a row whose cells all look fine, which is what that check exists to stop.
        "vulnerability_verdict_written",
    ),
    "anti-spyware": (
        # THE THREE GRADING AXES PAN-SPY-001, -002 and -004 CALIBRATE THEIR SEVERITY WITH, each
        # claused on by that control's calibration queries. All three are carried by the
        # Profiles cell, which prints `(graded <value>)` beside the failing assertion's detail -
        # see `security_rules.threat_profile_lines`, where that suffix was added for exactly
        # this declaration. It is the same fact and not a second one: the grading axis IS the
        # value the row's severity was derived from, and the cell now names it.
        #
        # None of the three is a candidate for a column of its own here, because this sheet sets
        # `auto_setting_columns=False` and `tested_columns=()` - it has no Setting / Observed
        # value block at all - so a column would be a hand-written one, which is stage 9's
        # decision and not this one's.
        "spyware_worst_unstopped_severity",
        "spyware_dns_content_list_action",
        "spyware_worst_engine_action",
    ),
}


def _spec(slug, title, control_ids, verdict_fields):
    return findings_sheet.DeviceSettingSheet(
        title=title,
        description=_DESCRIPTIONS[slug],
        auto_setting_columns=False,
        control_types=(Control.ControlType.SECURITY_RULE,),
        control_ids=control_ids,
        subject_columns=_subject_columns(verdict_fields),
        source_columns=security_rules.SOURCE_COLUMNS,
        value_readers=security_rules.SPEC.value_readers,
        tested_columns=(),
        # The rules sheet's own list, plus this kind's verdict fields. The Profiles column
        # carries them, which is what `hidden_fields` is a statement about.
        hidden_fields=(security_rules.SPEC.hidden_fields + tuple(verdict_fields)
                       + _EXTRA_HIDDEN.get(slug, ())),
        subject_select_related=security_rules.SPEC.subject_select_related,
        subject_prefetch=security_rules.SPEC.subject_prefetch,
        appliance_of=security_rules.SPEC.appliance_of,
        provenance_cell=security_rules.SPEC.provenance_cell,
    )


SPEC_BY_KIND = {slug: _spec(slug, title, control_ids, fields)
                for slug, title, control_ids, fields in KINDS}
