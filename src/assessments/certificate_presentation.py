"""Headings for the certificate, master key and WildFire tabs.

2026-11-04. Four tabs whose specs declared no `setting_labels`, so every derived settings
column headed a customer-facing table with a raw Django field name - 13 of them. The headings
are proposals (P399), sourced to the vendor's word where there is one and saying so where the
column is a verdict of ours.
"""

from __future__ import annotations

#: `Device > Certificate Management > Certificates`. PAN-CRT-001, -002 and -003.
CERTIFICATE_SETTING_LABELS = {
    "is_expired": "Expired",
    # NO VENDOR WORD: a FLOOR rather than a census - 65 of 69 known reference locations are
    # covered by no model, so this says only that nothing we read relies on it. The heading
    # must not promise "unused", because the remediation it suggests is irreversible.
    "not_relied_on": "Nothing we read relies on it",
    # NO VENDOR WORD. The key length as a BAND, which is what the control compares; a
    # certificate nobody could decode reads as undecodable rather than as passing.
    "key_strength_band": "Key strength",
    "weak_signature_hash": "Weak signature algorithm",
    # THE VENDOR'S OWN COLUMN on the certificate list.
    "signature_hash": "Algorithm",
}

#: `Device > Certificate Management > Certificate Profile`. PAN-CRT-004.
CERTIFICATE_PROFILE_SETTING_LABELS = {
    # THE VENDOR'S OWN CHECKBOXES: "Use CRL", "Use OCSP".
    "use_crl": "Use CRL",
    "use_ocsp": "Use OCSP",
    # NO VENDOR WORD: the verdict over both, which is what the control asserts.
    "checks_revocation": "Checks revocation",
    # THE VENDOR'S OWN SETTING is "Block session if certificate status cannot be retrieved
    # within timeout"; this column holds what the profile does when it cannot tell.
    "fail_open_mode": "When revocation cannot be checked",
}

#: `Device > Master Key and Diagnostics`. PAN-CRT-007.
MASTER_KEY_SETTING_LABELS = {
    # NO VENDOR WORD: the vendor shows a key and a lifetime, not a state. Ours is the verdict
    # over whether the factory key is still in force, and it carries an undetermined member.
    "state": "Master key state",
}

#: `Device > Setup > WildFire`. PAN-AVW-004 and -005.
WILDFIRE_SETTING_LABELS = {
    # NO VENDOR WORD: the vendor lists a size limit per file type; this is the verdict that
    # every one of the ten a template can set is still at its default.
    "size_limits_wholly_untuned": "Every size limit untuned",
    # THE VENDOR'S OWN SETTING: "Report Grayware Files" sits beside it, and the session
    # information sharing checkboxes are what this reads.
    "shares_full_session_info": "Shares full session information",
    # NO VENDOR WORD: which half of the verdict report is missing.
    "verdict_reporting_gap": "Verdict reporting gap",
}
