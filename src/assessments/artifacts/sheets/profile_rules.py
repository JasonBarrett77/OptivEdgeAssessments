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
        hidden_fields=security_rules.SPEC.hidden_fields + tuple(verdict_fields),
        subject_select_related=security_rules.SPEC.subject_select_related,
        subject_prefetch=security_rules.SPEC.subject_prefetch,
        appliance_of=security_rules.SPEC.appliance_of,
        provenance_cell=security_rules.SPEC.provenance_cell,
    )


SPEC_BY_KIND = {slug: _spec(slug, title, control_ids, fields)
                for slug, title, control_ids, fields in KINDS}
