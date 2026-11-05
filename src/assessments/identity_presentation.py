"""Headings for the identity tabs - who may log in, and what authenticates them.

2026-11-04. Three shipped tabs over three models, every one of them a bare stub: a description,
a subject, and no `setting_labels` at all, so **every** derived settings column on them headed a
customer-facing table with a raw Django field name.

    server_profile           integrations.ServerProfile           tab `AAA Server Profile`
    authentication_profile   integrations.AuthenticationProfile   tab `Authentication Profile`
    admin_user               integrations.AdminUser               tab `Administrator`

Measured before this module existed: **17 raw headings** - six on AAA Server Profile, six on
Authentication Profile, five on Administrator. `setting_columns` falls back to the field name
when a spec declares no label, so declaring a column without a label IS a decision to print
code, and the three tabs made it by omission.

THE HEADINGS BELOW ARE PROPOSALS (P399). Jason takes the heading pass across domains. Each is
sourced to the vendor's own word where the vendor has one, and SAYS SO where it does not -
several of these columns are verdicts of ours spanning more than one vendor field, and borrowing
the vendor's word for them would promise the vendor's field and deliver something wider.

WHAT THIS FIXES AND WHERE. `setting_labels` is read by `build_findings_table`, which draws the
web findings tab, the remediation page's value columns and the workbook tab from one definition.
So these land on `/assessments/findings/<slug>/` and on
`/assessments/remediation/group/<slug>/` at once - and on the workbook only when one is next
built. Nothing about the existing findings artifact changes; this adds the words that were
missing from both surfaces.
"""

from __future__ import annotations

#: `Device > Server Profiles > LDAP / RADIUS / TACACS+ / SAML`. PAN-AAA-001, -002, -004, -006,
#: -008, -009 and -013.
SERVER_PROFILE_SETTING_LABELS = {
    # THE VENDOR'S OWN WORD, Help 11.2: the LDAP profile's "Require SSL/TLS secured connection".
    # Shortened because the column holds Yes/No and the row already says which profile.
    "ldap_ssl": "SSL/TLS required",
    # THE VENDOR'S OWN WORD: "Verify Server Certificate for SSL sessions", cleared by default.
    "ldap_verify_server_certificate": "Server certificate verified",
    # THE VENDOR'S OWN WORD on both kinds that have it - RADIUS's "Authentication Protocol" and
    # TACACS+'s "Protocol". One column, because the two store the same answer differently and
    # the question asked of them is the same.
    "protocol": "Authentication protocol",
    # THE VENDOR'S OWN WORD: "Validate Identity Provider Certificate".
    "saml_validate_idp_certificate": "IdP certificate validated",
    # NO VENDOR WORD. The vendor has a checkbox, "Sign SAML Message to IdP"; this column is the
    # verdict over three facts - the flag, a certificate to sign with, and an authentication
    # profile that actually reaches this IdP - and reads False where nothing sends a message at
    # all. Headed as the effect rather than as the checkbox.
    "message_signing_effective": "Messages signed in practice",
    # NO VENDOR WORD: the count is ours, from a walk of the whole payload rather than a list of
    # known paths, and it is what PAN-AAA-013 grades. "Places" rather than "references" because
    # what is counted is where in the configuration the name appears.
    "referrer_count": "Places that name this profile",
}

#: `Device > Authentication Profile`. PAN-AAA-010, PAN-AUTH-018 and PAN-AUTH-025.
AUTHENTICATION_PROFILE_SETTING_LABELS = {
    # NO VENDOR WORD. Derived: a profile is administrative when something under
    # `mgt-config/users` or `deviceconfig/system` names it, which is a fact about the estate
    # rather than a field on the profile.
    "is_administrative": "Admits administrators",
    # THE VENDOR'S FIELD IS "Allow List" and this is the `all` member of it, said plainly:
    # everyone the method can reach may authenticate through the profile.
    "allow_list_is_all": "Allow list admits everyone",
    # NO VENDOR WORD. Three states the vendor's own screen cannot distinguish at a glance -
    # everyone, a named group, and EMPTY, which admits nobody. The column exists to keep the
    # first and the last apart; every clause comparison collapses them.
    "allow_list_width": "Who the allow list admits",
    # THE VENDOR'S WORD IS "Type" on the profile's Authentication tab. Headed less tersely
    # because `Type` beside a column headed `Kind` on a neighbouring tab reads as a synonym.
    "method": "Authentication type",
    # THE VENDOR'S OWN WORD: "Failed Attempts", under the profile's Advanced > Lockout.
    "lockout_failed_attempts": "Failed attempts before lockout",
    # NO VENDOR WORD - as on the server profile tab, and the same walk.
    "referrer_count": "Places that name this profile",
}

#: `Device > Administrators`. PAN-AUTH-019, -021 and -022.
ADMIN_USER_SETTING_LABELS = {
    # NO VENDOR WORD: a verdict over the account's authentication profile binding AND its
    # stored credential, because a profile pushed at an account that also holds a local password
    # is never consulted - measured against a dead RADIUS server, two attempts two seconds
    # apart. Headed as what is true of the account, not as a field.
    "authentication_is_external": "Authenticated externally",
    # NO VENDOR WORD, and the heading is about the ASSESSMENT rather than the device: it says
    # this count came from `mgt-config/users` alone, with no operational roster read to
    # reconcile against, so the cohort may be larger than it looks. True on every appliance
    # today, because no collector issues `show admins all`.
    "roster_is_configuration_only": "Counted from configuration only",
    # NO VENDOR WORD. The configuration stores a hash whose value says nothing; only its
    # presence is usable, and the remedy for it - delete the credential - differs from the
    # remedy for a missing binding, which is why the two are separate columns.
    "has_local_credential": "Local password stored",
    # THE VENDOR'S OWN ROLE NAME, "Superuser".
    "is_superuser": "Superuser",
    # NO VENDOR WORD: a total over the appliance, carried on every row because PAN-AUTH-022
    # grades on the count and a count is not a property of any one account. Reads 0 for an
    # account outside the cohort.
    "superuser_cohort_size": "Superusers on this appliance",
}


#: `Device > Setup > Management > Minimum Password Complexity`. PAN-AUTH-002 to -013. Every
#: heading here is THE VENDOR'S OWN, read off the panel itself.
PASSWORD_COMPLEXITY_SETTING_LABELS = {
    "minimum_length": "Minimum Length",
    "minimum_uppercase": "Minimum Uppercase Letters",
    "minimum_lowercase": "Minimum Lowercase Letters",
    "minimum_numeric": "Minimum Numeric Letters",
    "minimum_special": "Minimum Special Characters",
    "block_username_inclusion": "Block Username Inclusion (including reversed)",
    "new_differs_by_characters": "New Password Differs By Characters",
    "history_count": "Prevent Password Reuse Limit",
    "expiration_period": "Required Password Change Period (days)",
    "expiration_warning_period": "Expiration Warning Period (days)",
    "post_expiration_admin_login_count": "Post Expiration Admin Login Count",
    "post_expiration_grace_period": "Post Expiration Grace Period (days)",
    # NO VENDOR WORD: the two companions say the assessment never read the value, which is a
    # different state from a zero and the one the control fires on. Headed as the reading
    # rather than as the setting.
    "post_expiration_admin_login_count_unknown": "Post expiration admin login count not read",
    "post_expiration_grace_period_unknown": "Post expiration grace period not read",
}

#: `Device > Setup > Management > Authentication Settings`. PAN-AUTH-014 to -017.
AUTHENTICATION_SETTINGS_SETTING_LABELS = {
    # THE VENDOR'S OWN WORDS on the panel: "Failed Attempts", "Lockout Time (min)", "Idle
    # Timeout (min)", "API Key Lifetime (min)".
    "lockout_failed_attempts": "Failed Attempts",
    "lockout_time_minutes": "Lockout Time (min)",
    "idle_timeout_minutes": "Idle Timeout (min)",
    "api_key_lifetime_minutes": "API Key Lifetime (min)",
    # NO VENDOR WORD - see the password complexity companions above.
    "lockout_time_minutes_unknown": "Lockout time not read",
}

#: `Device > Certificate Management > SSL/TLS Service Profile`. PAN-CRT-005 and -009.
SSL_TLS_SERVICE_PROFILE_SETTING_LABELS = {
    # NO VENDOR WORD. The vendor's field is "Min Version" and holds a protocol name; this
    # column is that floor as an ORDERED number, which is the only shape an assertion can
    # compare, and it carries a sentinel for a profile nobody has ranked. Headed as the rank so
    # it is not mistaken for the protocol itself, which the sheet shows beside it.
    "min_version_rank": "Protocol floor (rank)",
    # NO VENDOR WORD: the vendor lists algorithms to allow, and this is the verdict over one of
    # them. Absent means enabled, so the column reads Yes on a profile that names nothing.
    "allows_sha1": "Still negotiates SHA-1",
}


#: `Device > Password Profiles`. PAN-AUTH-026.
PASSWORD_PROFILE_SETTING_LABELS = {
    # NO VENDOR WORD for either: the profile holds its own expiry and the comparison against
    # the firewall-wide policy is ours. The global period is carried on the row because a
    # clause compares a field to a literal and cannot reach across objects.
    "expiration_period": "Required Password Change Period (days)",
    "global_expiration_period": "Firewall-wide change period (days)",
    "weakens_global_expiration": "Weakens the firewall-wide policy",
}

#: `Device > Authentication Sequence`. PAN-AAA-012.
AUTHENTICATION_SEQUENCE_SETTING_LABELS = {
    # NO VENDOR WORD - the same derivation as the authentication profile's.
    "is_administrative": "Admits administrators",
    "has_local_member": "Falls back to local authentication",
    "member_count": "Profiles in the sequence",
    # NO VENDOR WORD: a member naming a profile this assessment did not find.
    "unresolved_member_count": "Members that resolve to nothing",
    "weakest_member_method": "Weakest method in the sequence",
}
