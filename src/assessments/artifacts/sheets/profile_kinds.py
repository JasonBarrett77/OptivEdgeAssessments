"""Which controls belong to which security-profile kind, and what each one tests.

A module of its own, with no dependency on either sheet, because BOTH need it and importing
one from the other is a cycle: `profile_rules` builds its four specs from the rules sheet's
columns, and the rules sheet needs the same list to exclude those controls from itself.

The three satellite-backed groups take their field lists from the model's own assertion tuples
rather than restating them, so a tenth assertion cannot be added to the model and forgotten
here. PAN-AVW-003 is named explicitly because it is the one per-rule profile verdict still
stored in COLUMNS on SecurityRule rather than on the satellite - see the open question about
unifying the two mechanisms.

PAN-AVW-006 is deliberately absent. "Unused AV / WildFire Profiles" is about a profile NO rule
uses, so there is no rule to report it on and it stays profile-based; a per-kind view for it
would be empty by construction.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import SecurityRuleProfileVerdict

_V = SecurityRuleProfileVerdict

#: (slug, sheet title, control ids, verdict fields the sheet's Profiles cell may print)
KINDS = (
    ("antivirus", "Antivirus (by rule)",
     ("PAN-AVW-001", "PAN-AVW-002"), _V.ANTIVIRUS_ASSERTIONS),
    ("anti-spyware", "Anti-Spyware (by rule)",
     ("PAN-SPY-001", "PAN-SPY-002", "PAN-SPY-003", "PAN-SPY-004", "PAN-SPY-005"),
     _V.SPYWARE_ASSERTIONS),
    ("vulnerability-protection", "Vulnerability Protection (by rule)",
     ("PAN-VLN-001", "PAN-VLN-002", "PAN-VLN-003", "PAN-VLN-004"),
     _V.VULNERABILITY_ASSERTIONS),
    ("wildfire-analysis", "WildFire Analysis (by rule)",
     ("PAN-AVW-003",), ("wildfire_analysis_submits_all", "wildfire_analysis_detail")),
)

#: Every control the four per-kind sheets claim, for the generic rules sheet to exclude so
#: nothing is reported twice.
EVERY_PROFILE_CONTROL = tuple(
    control_id for _slug, _title, control_ids, _fields in KINDS for control_id in control_ids)

DESCRIPTIONS = {
    "antivirus": "Rules whose antivirus profile lets malware through",
    "anti-spyware": "Rules whose anti-spyware profile leaves a threat unblocked",
    "vulnerability-protection":
        "Rules whose vulnerability protection profile leaves an exploit unblocked",
    "wildfire-analysis": "Rules whose WildFire analysis profile does not submit every file type",
}
