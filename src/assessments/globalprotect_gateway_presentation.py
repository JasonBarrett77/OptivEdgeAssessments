"""Readers, evidence cells and proposed headings for the three globalprotect-gateway findings tabs.

`globalprotect-gateway`, 2026-11-02. Three subjects, three grains, three tabs - and a fourth
subject that already has one:

- `integrations.GlobalProtectGateway` - one named gateway entry in one virtual system of one
  appliance. Three controls: PAN-GPG-001, -006, -007.
- `integrations.GlobalProtectGatewayClientAuth` - one row of one gateway's client-authentication
  table, keyed by the endpoint CLASS it serves. PAN-GPG-002 alone.
- `integrations.GlobalProtectGatewayAgentConfig` - one `remote-user-tunnel-configs` entry of one
  gateway. PAN-GPG-003 and -004.
- `integrations.GlobalProtectEnforcementPoint` - PAN-GPG-005, which needs nothing built here: the
  `globalprotect-portal` domain built the `GlobalProtect Coverage` tab on 2026-11-02 and
  deliberately did not narrow it with `control_ids`, so this control reached it before this run
  started (`probe.surface_for PAN-GPG-005`, measured). What it DID need is the one heading at the
  foot of this module.

EVERY ROW THIS MODULE DRAWS ON THE FIRST THREE TABS IS RECONSTRUCTED, AND THAT IS THE ONE THING
TO READ BEFORE TRUSTING A CELL HERE. There is no GlobalProtect gateway anywhere in the measured
estate: every `global-protect-gateway` subject in `stage6-globalprotect-gateway.json` carries
`standing_as: "absent"` with zero `read_back` keys, stage 6 spent eleven lease windows failing to
commit one, and stage 8 records in a blocking `needs_human` that six of the seven controls ship
unexercised. Measured here on 2026-11-02 with the committed seeder
(`print_findings_table --stage6 ... --stage8 ...`): the real estate builds three
`GlobalProtectEnforcementPoint` rows and ZERO rows of each of this module's first three models,
and it reconciles against stage 8's diff at 0 mismatches. So the emptiness is the lab's and the
artifact's honesty, NOT a defect in the normalizers - both gateway normalizers are wired into
`flows.py` and run - and the rows these three tabs were designed against were built by hand from
the vendor's own payload grammar. The wordings below are therefore judgments about shapes, not
reports about a customer's firewall.

EVERY HEADING IN THIS MODULE IS A PROPOSAL (P399). Jason takes the heading pass once across many
domains; what is decided here is the column SET, which comes from the controls' own clauses.
TWENTY-ONE clause fields over four models, and not one of the first three models' twenty had a
heading before today - there was no sheet for any of those three control types to inherit a
`setting_labels` entry from, so without this module twenty customer-facing columns would be headed
with a Django field name. `setting_labels` falls back to the raw field name, so declaring a column
without a label IS choosing to show a database field name to a customer.

THE VENDOR'S WORDS BELOW ARE FROM PAN-OS WEB INTERFACE HELP 11.2, quoted verbatim per heading with
the page. The three screens are
`Network > GlobalProtect > Gateways` (p.1044), `... > <gateway-config> > Authentication` (p.1046)
and `... > <gateway-config> > Agent > <agent-config> > ...` (p.1048-1061, six child tabs). Where
the vendor has no word for a column - every one of this domain's verdict columns is ours - the
heading says so in the comment rather than implying a vendor label.
"""
from __future__ import annotations

from .artifacts.sheets import findings as findings_sheet
from .artifacts.layout import NONE

DERIVED = findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label


# --------------------------------------------------------------------------------------------
# THE VALUE READERS - ONE MANDATORY, FOUR CHOSEN, TWO REFUSED
#
# THE MANDATORY ONE FIRST, because without it this domain has no tabs at all rather than one bad
# cell. PAN-GPG-002's calibration query clauses on `gateway_client_certificate_is_a_second_factor`,
# which is a SEARCH REGISTRY KEY and not a model attribute: the compiler registers it at
# `search/globalprotect_gateway_client_auth/compiler.py:193-195` with the lookup path
# `gateway__client_certificate_is_a_second_factor`. `tested_fields` resolves every clause field
# against the SUBJECT model, finds neither a field nor a property of that name, and RAISES
# `ValueError` - which takes down `store_run_tables` for the whole domain and not one cell. The
# compiler's own comment at :186-192 predicted it and stage 8 filed it in `needs_human` as owed to
# this stage. A `value_readers` entry is the only state in which this tab exists.
#
# NOT FIXED BY RENAMING THE FIELD, which stage 8 also says: naming stage 5's own column
# (`client_certificate_is_a_second_factor`) would pass the artifact check and raise in the consumer,
# because that column is on the GATEWAY and this subject is the client-auth ROW.
#
# AND THE PRICE IS GENUINELY NOTHING, measured rather than taken on trust - an orchestrator's brief
# said it "looks FREE" and told the `decryption-policy` run the same thing about a reader that cost
# five provenance rows the normaliser writes on purpose. Checked both halves in the committed
# normaliser: `_gateway_client_auth_rows` (`normalization/globalprotect.py:1186-1190`) writes
# exactly three provenance keys - `client_os`, `authentication_profile_name`,
# `user_credential_or_client_cert_required` - and nothing by this reader's name, because no such
# column exists on the row to carry one. The value it walks to,
# `GlobalProtectGateway.client_certificate_is_a_second_factor`, is in that model's `DERIVED_FIELDS`
# and gets no provenance row either. So there is no `FieldProvenance` row for
# `remediation_accessor` to skip, and the row's own `__entry__` row - written by
# `write_scoped_objects` on every pass - still answers where to go and change it. FREE, and this
# time the brief was right.
#
# WHAT IT CANNOT DO, which is a real limit and not a quibble: `GlobalProtectGatewayClientAuth.gateway`
# is `null=True`, so a row whose parent gateway did not resolve reads through nothing. That is the
# em dash below, and it is the honest answer - the question "is the certificate a second factor on
# the gateway" has no answer at all for a row with no gateway, and `(none)` would offer "no" as the
# finding's remedy.
GATEWAY_CERT_SECOND_FACTOR_READER = findings_sheet.ValueReader(
    read=lambda row: (
        findings_sheet.display_value(row.gateway.client_certificate_is_a_second_factor)
        if row.gateway is not None else NONE),
    provenance=DERIVED,
)

# --------------------------------------------------------------------------------------------
# THE FOUR CHOSEN READERS, each one an instance of contract finding 4's FIRST case: a key that is
# absent BY STRUCTURE rather than unset by choice, which `display_value` has no way to say.
#
# `display_value` HAS EXACTLY THREE ANSWERS - a value, `(none)` for NULL and `(empty)` for the
# empty string - and a branch the subject does not have gets one of those three anyway. On the
# `ike-crypto` tabs that put `(empty)` in five cells for a branch the gateway did not have and
# offered `(none)` as the thing to fix on a sixth. `read_value` consults the sheet's `value_readers`
# FIRST and hands the reader the SUBJECT, so a reader branching on the subject's own state reaches
# a distinction the model cannot express. `layout.NONE` is `"—"`, U+2014 EM DASH.
#
# ALL FOUR ARE FREE AND THAT IS WHY THEY ARE HERE. The price rule is that a reader makes
# `tested_fields` report the field `stored=False`, `remediation_accessor` then skips its own
# `FieldProvenance` row and walks to `__entry__`, and `provenance_cells` answers "Derived" without
# reading one - so a reader costs the field's provenance row wherever the normaliser writes one.
# Every one of these four is in its model's `DERIVED_FIELDS` and appears in NO provenance list in
# `normalization/globalprotect.py`:
#   gateway rows write provenance for `ssl_tls_service_profile`, `tunnel_mode`,
#   `certificate_profile_name`, `block_quarantined_devices` always, plus `ipsec_enabled`,
#   `ipsec_crypto_profile_name` and `video_traffic_excluded` when the networking half joined (:1455-1472);
#   agent rows write it for `generate_cookie`, `cookie_encrypt_decrypt_cert` and
#   `no_direct_access_to_local_network` and nothing else (:1302-1306).
# None of the four below is in either list. The two fields that ARE in them and would have wanted a
# reader are refused at the foot of this section.

#: PAN-GPG-007's graded column. NULL means NO ROLE ENTRY BOUNDS THE LOGIN AT ALL - stage 4 measured
#: that state on every appliance in the lab - so there is no lifetime to express in hours rather
#: than a lifetime nobody read. `(none)` would read as a gap in the report beside a companion column
#: already saying the reading was taken, and the pair would contradict each other on one row.
#:
#: THE COMPANION IS WHAT MAKES THE EM DASH SAFE and it is drawn two columns away: `login_lifetime_known`
#: is False on exactly these rows and fires on its own at the control's own severity, so "there is no
#: bound" is stated by a cell that is marked as the thing to fix. Without that column this em dash
#: would be the whole report of an unbounded session, which is the shape stage 5 wrote the companion
#: for: "THE COMPARISON IS `is greater than 24` AND A NULL MATCHES NO POSITIVE COMPARISON, so a
#: gateway whose login lifetime nobody could read passes the threshold in silence".
LOGIN_LIFETIME_HOURS_READER = findings_sheet.ValueReader(
    read=lambda gw: (findings_sheet.display_value(gw.login_lifetime_hours)
                     if gw.login_lifetime_hours is not None else NONE),
    provenance=DERIVED,
)
#: PAN-GPG-007's second graded column, for the same reason and with the same companion
#: (`inactivity_logout_known`). The vendor DOCUMENTS a 180-minute default that would already satisfy
#: this control, and stage 4 explicitly declined to materialise it - so this cell must not imply a
#: value. An em dash says there is no configured bound; it does not say what the product does.
INACTIVITY_LOGOUT_READER = findings_sheet.ValueReader(
    read=lambda gw: (findings_sheet.display_value(gw.inactivity_logout_minutes)
                     if gw.inactivity_logout_minutes is not None else NONE),
    provenance=DERIVED,
)
#: PAN-GPG-006's third rank. The store holds `""` where no app-crypto profile resolved, and
#: `display_value` prints `(empty)` - which reads as "the proposal list is empty", a real and
#: alarming device state, on a gateway that HAS NO PROPOSAL LIST BECAUSE IPSEC IS OFF OR WAS NEVER
#: READ. Those are three different rows printing one cell.
#:
#: SO THE BRANCH IS ON `ipsec_enabled`, not on the string: only a gateway with IPSec enabled has a
#: first proposal to name. Where IPSec is off the transport is SSL-VPN and the question does not
#: arise; where `ipsec_enabled` is NULL the networking half was never read and `ipsec_enabled_known`
#: is the column that says so. Both get the em dash and the two are told apart by that companion.
APP_CRYPTO_FIRST_ENCRYPTION_READER = findings_sheet.ValueReader(
    read=lambda gw: (findings_sheet.display_value(gw.bound_app_crypto_first_encryption)
                     if gw.ipsec_enabled is True else NONE),
    provenance=DERIVED,
)
#: PAN-GPG-003's graded column, and the one reader here whose branch is NOT simply "is it null".
#:
#: TWO NULLS WITH OPPOSITE MEANINGS SHARE THIS COLUMN and the control's own applicability clause is
#: the thing that tells them apart, so the cell has to as well:
#:   * a row that accepts NO reconnection cookie has no lifetime branch at all. PAN-GPG-003's
#:     applicability clause (`accept_cookie_configured eq true`) excludes it, no finding is drawn,
#:     and the honest cell is the em dash.
#:   * a row that DOES accept one and bounds nothing is the firing state - stage 3 says it out loud,
#:     "An absent value in ALL THREE branches is not a rank at all: it reads as nobody having looked
#:     and fires, and it must not be graded as acceptable" - and `(none)` is right there, beside a
#:     marked `cookie_lifetime_known` of No and a shipped query named "A cookie is accepted and no
#:     lifetime was read for it".
#: An em dash on the second would read as "not applicable" over exactly the row this control exists
#: to raise, which is the reassuring-cell failure this stage exists to catch.
COOKIE_LIFETIME_HOURS_READER = findings_sheet.ValueReader(
    read=lambda cfg: (findings_sheet.display_value(cfg.cookie_lifetime_hours)
                      if cfg.accept_cookie_configured else NONE),
    provenance=DERIVED,
)

# TWO READERS REFUSED, both on the same rule and both deliberately leaving a weaker cell standing.
#
# `ipsec_enabled` and `cookie_encrypt_decrypt_cert` are the two columns on these tabs whose cell a
# reader would most obviously improve, and both are MEASURED PAYLOAD KEYS with a `FieldProvenance`
# row of their own that the normaliser writes on purpose. A reader on either makes
# `remediation_accessor` skip that row and walk to `__entry__`, so the Provenance cell would answer
# "Derived" or "Local" about a key whose history is the whole question - and on both of them whether
# the key was ABSENT, explicitly off, or template-pushed is what the control is about:
#   * `ipsec_enabled` NULL means the networking half of the gateway - a separate read at a different
#     scope - was never collected. That is stage 3's named failure mode for PAN-GPG-006 and the
#     reason `ipsec_enabled_known` exists. The provenance row is what separates a gateway whose
#     half is pushed by a template from one whose half nobody read.
#   * `cookie_encrypt_decrypt_cert` NULL means no certificate encrypts the reconnection cookie, and
#     PAN-GPG-003's fifth shipped query raises exactly that. Whoever can forge the cookie reconnects
#     as any user of the gateway; the provenance row says where the binding would be changed.
# So both cells read `(none)` where a reader could have said something better, both have a marked
# companion or a query of their own saying what the null means, and the loss is recorded rather than
# reported as free. What would remove the trade: a `stored` argument on `ValueReader`, or an arm in
# `remediation_accessor` consulting `provenance_of` for a reader field whose name is a provenance
# key on the same row.

GATEWAY_VALUE_READERS = {
    "login_lifetime_hours": LOGIN_LIFETIME_HOURS_READER,
    "inactivity_logout_minutes": INACTIVITY_LOGOUT_READER,
    "bound_app_crypto_first_encryption": APP_CRYPTO_FIRST_ENCRYPTION_READER,
}
CLIENT_AUTH_VALUE_READERS = {
    "gateway_client_certificate_is_a_second_factor": GATEWAY_CERT_SECOND_FACTOR_READER,
}
AGENT_CONFIG_VALUE_READERS = {
    "cookie_lifetime_hours": COOKIE_LIFETIME_HOURS_READER,
}

#: NO `members=` ON ANY READER HERE. A reader with `members` sends `member_provenance_index` to
#: build an index over CHILD rows, and every value above is computed on the subject row itself or
#: read through one nullable FK to its parent. The client-auth row and the agent config ARE children
#: of the gateway, but each is a subject with a tab of its own, not a member another row reads
#: through.


# --------------------------------------------------------------------------------------------
# EVIDENCE CELLS - the values a verdict column cannot carry, as subject columns.
#
# EVERY ONE NAMES ITS `field`, which is not tidiness: a subject column that declares no field does
# NOT suppress the derived settings column for the same attribute, so the value reaches the tab
# twice under two headings - and because the headings differ, the duplicate-header guard never
# fires. (`ike-crypto` and `ipsec-crypto` both recorded this.)
#
# AND NONE OF THEM NAMES A CLAUSE FIELD, with one deliberate exception. Naming a clause field in a
# subject column suppresses its derived column, which would be fine for the gate -
# `check_every_tested_field_is_presented` counts a subject column as presenting the field - but it
# moves the cell OUT of the settings block, and the value-at-fault fill marks settings cells. The
# exception is `client_os` below, and the reason is given there.

def _switch(value) -> str:
    """A vendor yes/no switch in a SUBJECT column, where NULL means the key was not carried.

    `display_value` prints `(none)` for a null boolean, which reads as "no value" - and on all
    three of the switches this is used for, the normalizer has ALREADY ACTED on the absence, so
    "no value" is the one thing the cell does not mean:

      * `no-direct-access-to-local-network` null is COUNTED AS AN OPEN PATH by
        `_gateway_agent_configs` ("THE COUNT COUNTS A NULL LOCAL-NETWORK SWITCH AS OPEN ... the
        key's name is the negation of what it permits, so an absence most likely leaves direct
        access allowed"). So the egress count beside it has already included this row, and a
        reader seeing `(none)` would take the axis for unknown rather than for counted-against.
      * `generate_cookie` and `block_quarantined_devices` null is an unmeasured switch, and stage 5
        reads both as FIRING for that reason.
      * `user_credential_or_client_cert_required` null is the key absent on a committed row OR a
        row the collector did not carry, and stage 5 says neither is safe to report as a value.
        This one matters most of the four, because the VENDOR'S POLARITY IS INVERTED here - "No"
        is the HARDENED answer - so `(none)` rendering next to a column of Yes/No invites a reader
        to take the blank for the safe end of a switch whose safe end is spelled "No".

    "Not set" rather than `(none)`, and it is a SUBJECT column so this is the sheet's own choice to
    make - no reader, no provenance row discarded, nothing shared. The word is deliberately not
    "No": the vendor's own No is a configured answer and this is the absence of one.
    """
    if value is None:
        return "Not set"
    return findings_sheet.display_value(value)


def _gateway_of(row) -> str:
    """The parent gateway's name, for a child row's identity.

    `gateway_name` is a STRING on both child models and is in both their `DERIVED_FIELDS`, so this
    reads the denormalised name rather than the nullable FK - a row whose parent did not resolve
    still knows what it was called, and that name is what an assessor types into the Gateways
    screen. The FK is consulted only by the one reader that needs a value off the parent.
    """
    return row.gateway_name or NONE


def _login_lifetime_as_entered(gw) -> str:
    """What was typed on the screen, in the unit it was typed in.

    THE WHOLE HAZARD ON THIS FIELD IS A LIMIT SET IN ONE UNIT AND READ THROUGH ANOTHER UNIT'S LEAF,
    which is stage 5's own words for it, and the graded column beside this one is normalized to
    hours. So a gateway whose login lifetime reads 720 hours under `Login Lifetime` is a gateway
    somebody set to 30 days, and an assessor sent to the screen will not find "720" anywhere on it.
    This cell is what they will find.

    `login_lifetime_unit` gets no column of its own: no control clauses on it, and a bare unit in a
    column of its own says nothing without the number.
    """
    if gw.login_lifetime_as_entered is None:
        return NONE
    return f"{gw.login_lifetime_as_entered} {gw.login_lifetime_unit}".strip()


def _cookie_lifetime_as_entered(cfg) -> str:
    """As above, for the reconnection cookie. The vendor's own ranges are "1-72 hours, 1-52 weeks,
    or 1-365 days" (Help 11.2 p.1051), so three unit branches reach one normalized column and the
    entered pair is the only cell that says which branch held the value."""
    if cfg.cookie_lifetime_as_entered is None:
        return NONE
    return f"{cfg.cookie_lifetime_as_entered} {cfg.cookie_lifetime_unit}".strip()


#: The five pieces of evidence a gateway's verdict columns cannot carry. `objects.py` composes this
#: onto `APPLIANCE + SCOPE + NAME`, which is where those three shared constants and `scope_of` live;
#: importing them here would be circular, because `objects.py` imports this module.
#:
#: FIVE IS WIDE AND EACH ONE EARNS IT. Three controls report here over ten derived columns, and
#: every one of the ten is a BOOLEAN VERDICT or a NORMALISED NUMBER - there is not one cell among
#: them naming the object an assessor has to go and change. `tls_profile_resolves_to_an_explicit_floor`
#: says a floor is missing and cannot say which profile is bound; `app_crypto_offers_gcm_first` says
#: the first proposal is wrong and cannot say which profile proposed it. Without these the tab
#: reports faults at addresses it does not print.
#:
#: `APPLIANCE + SCOPE` AND NOT `VSYS_SCOPED`, which is the HA answer and is measured. `VSYS_SCOPED`
#: reads `s.enforcement_point.vsys_name`, and this model has no `enforcement_point` at all - it
#: carries `appliance`, `scope` and `vsys_name` directly, and its shipped constraint is
#: `unique(appliance, scope, vsys_name, name)`. So an HA PAIR WRITES TWO ROWS FOR ONE CONFIGURATION
#: and the Appliance and HA role columns are what tell them apart. `scope_of` already prints the
#: vsys name for a `scope=vsys` row, so the Scope column IS stage 5's `vsys_name` column.
GATEWAY_EVIDENCE = (
    # VENDOR'S OWN WORD, Help 11.2 p.1046 verbatim, the Authentication tab's first setting:
    # "SSL/TLS Service Profile Select an SSL/TLS service profile for securing this GlobalProtect
    # gateway." THE NAME PAN-GPG-001's VERDICT CANNOT SAY - and on this control the name is the
    # finding: stage 5 records that the commonest state for a CORRECTLY hardened gateway is a name
    # resolving into `/config/predefined`, which no merge view carries, so the profile is unreadable
    # rather than absent. A reader following the verdict with no name beside it has nothing to open.
    ("SSL/TLS Service Profile", 22, False,
     lambda s, _p: s.ssl_tls_service_profile or NONE, "ssl_tls_service_profile"),
    # OURS. The vendor's word on the SSL/TLS profile screen is "Min Version", but this cell is not
    # that leaf - it is the floor RESOLVED THROUGH the binding above, which is why it can be empty
    # while a profile is named. Headed so the two read as a pair.
    ("TLS floor on that profile", 18, False,
     lambda s, _p: s.bound_tls_min_version or NONE, "bound_tls_min_version"),
    # VENDOR'S OWN WORD, Help 11.2 p.1049 verbatim, Tunnel Settings: "GlobalProtect IPSec Crypto-
    # Select a GlobalProtect IPSec Crypto profile that specifies authentication and encryption
    # algorithms for the VPN tunnels. The default profile uses AES-128-CBC encryption and SHA1
    # authentication." The address PAN-GPG-006's two proposal ranks send a reader to.
    ("GlobalProtect IPSec Crypto", 24, False,
     lambda s, _p: s.ipsec_crypto_profile_name or NONE, "ipsec_crypto_profile_name"),
    # VENDOR'S OWN WORD, Help 11.2 p.1058, Connection Settings: "Login Lifetime Specify the number
    # of days, hours, or minutes allowed for a single gateway login session." See
    # `_login_lifetime_as_entered` for why the entered pair is on the row at all.
    ("Login Lifetime as entered", 20, False,
     lambda s, _p: _login_lifetime_as_entered(s), "login_lifetime_as_entered"),
    # VENDOR'S OWN WORD, Help 11.2 p.1048, the Authentication tab's last setting: "Block login for
    # quarantined devices Specify whether to block gateway login for GlobalProtect client devices
    # that are in the quarantine list (Device > Device Quarantine)."
    #
    # HERE BECAUSE NO CONTROL ON THIS TAB REPORTS IT AND THE STATE IS WORTH READING, which is a gap
    # this run records rather than fills. Stage 5's PAN-GPG-005 record [2] names
    # `globalprotect-gateway` and clauses on this field and on `automatic_quarantine_path_exists`;
    # stage 8 compiled NO query for that record - PAN-GPG-005 ships one baseline, over the
    # enforcement point - so the quarantine half of that control is unbuilt and these two columns
    # would be on no surface at all. The vendor states the consequence of the switch being off in as
    # many words: "the app notifies the user and the user is able to log in from the quarantined
    # device". A subject column is where that reaches a reader without this stage writing a query,
    # which is stage 8's to write and not this stage's.
    ("Block login for quarantined devices", 14, True,
     lambda s, _p: _switch(s.block_quarantined_devices),
     "block_quarantined_devices"),
)

#: The parent-gateway column both child tabs carry, composed in `objects.py` between `SCOPE` and
#: `NAME`: the gateway comes BEFORE the row's own name because it is the outer half of the identity
#: and the row name means nothing on its own.
GATEWAY_OF_ROW = (
    ("Gateway", None, False, lambda s, _p: _gateway_of(s), "gateway_name"),
)

#: The four evidence columns of one client-authentication row.
#:
#: `client_os` IS THE ONE CLAUSE FIELD PRESENTED AS A SUBJECT COLUMN, and the reason is that it is
#: IDENTITY here rather than a setting. The vendor's own screen says so - "The OS is the main
#: differentiator between multiple configurations" (Help 11.2 p.1046) - and PAN-GPG-002's clause on
#: it is an APPLICABILITY clause, not an assertion: it narrows the control away from `X-Auth` rows
#: and is not in the baseline's `asserted_fields`, so it would never carry the value-at-fault mark
#: even as a settings column. Naming the field here suppresses the duplicate derived column and the
#: gate still counts the field as presented.
CLIENT_AUTH_EVIDENCE = (
    # VENDOR'S OWN WORD, and the vendor's own one-letter label. Help 11.2 p.1046: "OS By default,
    # the configuration applies to all endpoints. You can refine the list of endpoints by OS
    # (Android, Chrome, iOS, IoT, Linux, Mac, Windows, or WindowsUWP), by Satellite devices, or by
    # third-party IPSec VPN clients (X-Auth)."
    #
    # "Endpoint class (OS)" AND NOT A BARE "OS", which is the `globalprotect-portal` run's heading
    # for the same column on its sibling tab and is kept for the same reason: a two-letter heading
    # in a table of sentences reads as an abbreviation of the column beside it. The vendor's word is
    # in the parenthesis so an assessor searching the screen for "OS" still finds it.
    ("Endpoint class (OS)", 16, False,
     lambda s, _p: s.client_os or NONE, "client_os"),
    # VENDOR'S OWN WORD, Help 11.2 p.1047: "Authentication Profile Choose an authentication profile
    # or sequence from the drop-down to authenticate access to the gateway."
    #
    # THE CELL CANNOT SAY WHETHER THIS IS A PROFILE OR A SEQUENCE, which is a real limit of the row
    # and the reason the column beside it can be empty: the leaf accepts either and the stored
    # string does not say which, so a row naming a SEQUENCE resolves to nothing and the back-end
    # column reads empty. That is the state PAN-GPG-002's baseline fires on, and these two cells
    # together are the only place a reader can see why.
    ("Authentication Profile", 22, False,
     lambda s, _p: s.authentication_profile_name or NONE, "authentication_profile_name"),
    # OURS, and the heading is a safety decision. The vendor's label is the whole sentence "Allow
    # Authentication with User Credentials OR Client Certificate" (Help 11.2 p.1047) and its
    # polarity is INVERTED relative to hardening: "If you select No, users must authenticate to the
    # gateway using both user credentials and client certificates. If you select Yes, users can
    # authenticate to the gateway using either."
    #
    # SO "Yes" IS THE PERMISSIVE ANSWER AND THE HEADING HAS TO MAKE THAT READABLE. Headed with the
    # vendor's bare sentence, a cell reading "Yes" under a column about requiring a second factor
    # looks like the hardened answer, and the most reassuring cell on the row would be the finding -
    # which is the failure Jason caught once already and the one this stage exists to catch. Phrased
    # as "accepted", Yes plainly means either one alone gets in.
    ("Credentials OR certificate accepted", 14, True,
     lambda s, _p: _switch(s.user_credential_or_client_cert_required),
     "user_credential_or_client_cert_required"),
    # OURS. The vendor has no word for this: it is the element NAME under the resolved profile's
    # `method`, which is how the DEVICE models the choice, and it is empty on a row whose named
    # object is a sequence rather than a profile. Two of its values mean no second factor is
    # possible at all, which is what the verdict column beside it reads.
    ("Authentication back end", 18, False,
     lambda s, _p: s.authentication_backend_method or NONE, "authentication_backend_method"),
)

#: The three evidence columns of one `remote-user-tunnel-configs` entry - the vendor's Agent
#: configuration.
#:
#: THREE AND NO MORE, because this tab's seven derived columns already include the two applicability
#: gates (`accept_cookie_configured`, `authentication_override_configured`) that explain most of its
#: empty cells. What they do not carry is the entered lifetime, the generation switch on the other
#: side of the cookie exchange, and the one exclusion axis that is a SIBLING of split tunnelling
#: rather than a child of it.
AGENT_CONFIG_EVIDENCE = (
    # VENDOR'S OWN WORD, Help 11.2 p.1051: "Cookie Lifetime-Specify the hours, days, or weeks that
    # the cookie is valid. The typical lifetime is 24 hours. The ranges are 1-72 hours, 1-52 weeks,
    # or 1-365 days."
    ("Cookie Lifetime as entered", 20, False,
     lambda s, _p: _cookie_lifetime_as_entered(s), "cookie_lifetime_as_entered"),
    # VENDOR'S OWN WORD, Help 11.2 p.1051: "Generate cookie for authentication override-During the
    # lifetime of the cookie, the agent presents this cookie each time the user authenticates with
    # the gateway."
    #
    # THE OTHER HALF OF THE EXCHANGE, and no control clauses on it. PAN-GPG-003 is about ACCEPTING a
    # cookie, because accepting one is what lets a stolen cookie in; generating one is what makes a
    # cookie exist to steal. A row that generates and does not accept is a real and readable state,
    # and this is the only cell that shows it.
    ("Generate cookie for authentication override", 14, True,
     lambda s, _p: _switch(s.generate_cookie), "generate_cookie"),
    # VENDOR'S OWN WORD, Help 11.2 p.1053: "No direct access to local network Use this option to
    # enable or disable local network access on Windows, macOS and Linux endpoints ... When this
    # option is enabled users cannot send traffic directly to proxies or local resources such as
    # printers while connected to GlobalProtect."
    #
    # ONE OF PAN-GPG-004's EIGHT EGRESS AXES, and the one the count's own container cannot see: it
    # is a SIBLING of `split-tunneling` rather than a child. The count beside it is a number with no
    # breakdown, so the axes that are single switches are worth printing. The polarity is the
    # vendor's: "Yes" here is the HARDENED answer, which is the opposite of the credentials switch on
    # the sibling tab, and is why the heading keeps the vendor's negative phrasing rather than being
    # "normalised" to a positive one that would read the same as a verdict column.
    ("No direct access to local network", 14, True,
     lambda s, _p: _switch(s.no_direct_access_to_local_network),
     "no_direct_access_to_local_network"),
    # THE SIX SPLIT-TUNNEL LISTS GET NO COLUMN, which is a decision and not an omission. They are
    # `JSONField`s, the model's own docstring says "NOTHING MAY CLAUSE ON THEM", none of the six is
    # registered in the search compiler, and a findings table is not where a reader reads a list of
    # 200 domains. The count is what this tab reports and the explorer page is where the lists are
    # read. Stage 5 marks all six `presented: true`, which this run read as "reaches a surface"
    # rather than "reaches this tab" - see the results page.
)


# --------------------------------------------------------------------------------------------
# PROPOSED HEADINGS, TAB 1 - the ten derived setting columns of the GlobalProtect Gateways tab.
#
# IN `tested_fields` ORDER, WHICH IS NOT STAGE 5's CLAUSE ORDER AND WAS READ OFF THE BUILT TABLE
# rather than reasoned about. The baseline's clauses come first per control, in clause order, and
# then every other ACTIVE query's clauses in ALPHABETICAL ORDER OF THE QUERY'S NAME
# (`findings.py:380`, `order_by("-is_baseline", "name", "pk")`). The visible consequence on this tab
# is at the end of the list: `login_lifetime_known` is the companion that says whether the bound
# above it could be read at all, and it is drawn LAST - after both idle-logout columns - because
# "No login lifetime is bounded on this gateway" sorts after "No idle logout is bounded on this
# gateway". So the companion is separated from the column it supports by two unrelated cells, and
# renaming either shipped query would silently move it again. `auto_setting_columns` is all or
# nothing, so a sheet cannot fix this; it is recorded instead.
GATEWAY_SETTING_LABELS = {
    # OURS, AND A SAFETY DECISION. The vendor's noun for the object is "SSL/TLS Service Profile" and
    # that noun is already a subject column two cells to the left. This column is a BOOLEAN whose
    # FALSE is the firing side, and it collapses two states on purpose - the bound name resolving to
    # nothing the collection carries, and the resolved profile stating no floor of its own.
    #
    # PHRASED SO THE PROBLEM READS AS THE PROBLEM. Headed "TLS floor is explicit", a cell reading
    # "No" would be correct and would look like a missing feature rather than a finding; headed with
    # the vendor's bare noun it would look like the answer to "is a profile bound?", which is a
    # question this column does not answer and which stage 4 measured as ALWAYS YES - the device
    # refuses to commit a gateway without one.
    "tls_profile_resolves_to_an_explicit_floor": "Bound profile states a TLS floor",
    # VENDOR'S OWN WORD, Help 11.2 p.1048, Tunnel Settings: "Tunnel Mode Select Tunnel Mode to
    # enable tunnel mode and then specify the following settings". PAN-GPG-006's baseline fires when
    # this is false - a gateway that builds no tunnel inspects nothing.
    "tunnel_mode": "Tunnel Mode",
    # VENDOR'S OWN WORD, Help 11.2 p.1049: "Enable IPSec-Select this option to enable IPSec mode for
    # endpoint traffic, making IPSec the primary method and SSL-VPN the fallback method."
    #
    # NULL IS A THIRD STATE HERE AND IT PRINTS `(none)`, deliberately un-read: see the refused
    # reader above. The companion two columns down is what says the networking half was never
    # collected.
    "ipsec_enabled": "Enable IPSec",
    # OURS. The vendor's screen names no "preferred algorithm" - it names the profile and says what
    # the default profile contains ("The default profile uses AES-128-CBC encryption and SHA1
    # authentication", p.1049). This column is our verdict over the FIRST member of that profile's
    # proposal list, because the first proposal is the one a negotiation actually lands on.
    "app_crypto_offers_gcm_first": "First proposal is AES-256-GCM",
    # OURS, naming the value rather than a verdict: this is the algorithm itself, so the heading is
    # the question and the cell is the answer. Two shipped queries split its values at two
    # severities - `aes-128-cbc` at medium and `aes-128-gcm` at low - so the cell is what
    # distinguishes two rows whose verdict columns are identical.
    "bound_app_crypto_first_encryption": "First proposal",
    # OURS, AND ONE OF THE FIVE COLUMNS THIS DOMAIN HAS THAT EXIST ONLY TO TELL "we could not see
    # it" FROM "it is wrong". The networking half of a gateway is a SEPARATE READ at a different
    # scope, so it is the half most likely to be missing while the gateway row itself exists - and
    # `ipsec_enabled eq false` does not match a NULL, so without this column a gateway whose
    # transport nobody read would pass PAN-GPG-006 in silence. Its own shipped query, "The
    # networking half of this gateway was never read", fires on it.
    #
    # HEADED AS A READING AND NOT AS A SETTING. "Transport read" would look like a device feature;
    # "Was the transport half read?" is a question about this assessment, which is what it is.
    "ipsec_enabled_known": "Transport half of the gateway was read",
    # VENDOR'S OWN WORD, Help 11.2 p.1058, Connection Settings: "Login Lifetime Specify the number
    # of days, hours, or minutes allowed for a single gateway login session." NORMALISED TO HOURS
    # here, which the entered pair in the subject block is the antidote to - see
    # `_login_lifetime_as_entered`.
    "login_lifetime_hours": "Login Lifetime (hours)",
    # VENDOR'S OWN WORD, Help 11.2 p.1058-1059: "Inactivity Logout Specify the amount of time (in
    # minutes) after which an inactive session is automatically logged out (range for tunnel mode is
    # 5 to 43200 and for non-tunnel mode 120 to 43200 minutes; default is 180 minutes)." The
    # vendor's own unit is minutes, so this column needs no unit conversion and no entered pair.
    "inactivity_logout_minutes": "Inactivity Logout (minutes)",
    # OURS, the companion to the column above, and the two must not read alike: an em dash in
    # `Inactivity Logout (minutes)` with "No" here says nobody bounded the idle session, which is a
    # finding; a number there with "Yes" here says it was bounded and the number is the rank.
    "inactivity_logout_known": "An idle-logout bound was read",
    # OURS, the companion to `Login Lifetime (hours)` - and the column the ordering note above is
    # about, because it is drawn here rather than beside the column it supports.
    "login_lifetime_known": "A login-lifetime bound was read",
}

# --------------------------------------------------------------------------------------------
# PROPOSED HEADINGS, TAB 2 - the two derived setting columns of the Gateway Client Authentication
# tab. `client_os` is the third clause field and is a subject column; see `CLIENT_AUTH_SUBJECT`.
CLIENT_AUTH_SETTING_LABELS = {
    # OURS. The vendor's screen says what a second factor requires - "ensure that the Authentication
    # Profile uses RADIUS or SAML with two-factor authentication. If you don't use RADIUS or SAML,
    # then you need to configure a Certificate profile in addition to an Authentication Profile"
    # (Help 11.2 p.1047) - but it has no label for the conclusion, which is this column.
    #
    # "can deliver" AND NOT "delivers". The column says the back end is CAPABLE of a second factor,
    # not that one is enforced: whether the profile actually has two-factor switched on is not on
    # the firewall, and stage 5 discharged that half onto the engineer. A heading promising the
    # stronger claim would overstate what the row knows.
    "backend_can_deliver_a_second_factor": "Back end can deliver a second factor",
    # OURS, and the heading has to carry the word "gateway" because the value is READ OFF THE
    # PARENT. This is the mandatory reader's column: the field is a search-registry key whose lookup
    # walks `gateway__client_certificate_is_a_second_factor`, so the cell is the GATEWAY's verdict
    # shown on a CLIENT-AUTH row. Without "on the gateway" in the heading a reader would take it for
    # a property of this row and look for it on the Authentication tab's client-authentication
    # table, where there is no such setting.
    #
    # AN EM DASH HERE MEANS THE ROW'S PARENT GATEWAY DID NOT RESOLVE, not that the answer is no.
    "gateway_client_certificate_is_a_second_factor":
        "Client certificate is a second factor on the gateway",
}

# --------------------------------------------------------------------------------------------
# PROPOSED HEADINGS, TAB 3 - the seven derived setting columns of the Gateway Agent Configuration
# tab, in `tested_fields` order across PAN-GPG-003 then PAN-GPG-004.
AGENT_CONFIG_SETTING_LABELS = {
    # VENDOR'S OWN WORD, Help 11.2 p.1051: "Accept cookie for authentication override-Select this
    # option to configure the gateway to accept authentication using the encrypted cookie. When the
    # agent presents the cookie, the gateway validates that the cookie was encrypted by the gateway
    # before authenticating the user."
    #
    # AN APPLICABILITY GATE AND NOT A FAULT, which is why the heading is the vendor's plain label
    # and carries no judgement: "No" here SUPPRESSES PAN-GPG-003 rather than raising it, and that is
    # correct - a gateway that accepts no reconnection cookie has no cookie to steal. Stage 5
    # records the cost in the same breath: an unrecomputed row also reads false and goes quiet.
    "accept_cookie_configured": "Accept cookie for authentication override",
    # VENDOR'S OWN WORD, p.1051, quoted in `_cookie_lifetime_as_entered`. NORMALISED TO HOURS, with
    # the entered pair in the subject block, because the vendor offers three unit branches.
    "cookie_lifetime_hours": "Cookie Lifetime (hours)",
    # OURS, the companion, and on this tab it is the one that matters most: the graded column above
    # it passes a NULL in silence, so this is the only cell separating "accepted for an unbounded
    # time" from "bounded, and within a day". Its own shipped query is "A cookie is accepted and no
    # lifetime was read for it".
    "cookie_lifetime_known": "A cookie lifetime was read",
    # VENDOR'S OWN WORD, Help 11.2 p.1051: "Authentication Override Enable the gateway to use
    # secure, device-specific, encrypted cookies to authenticate the user after the user first
    # authenticates using the authentication scheme specified by the authentication or certificate
    # profile." The second applicability gate on this tab, for the certificate column below it.
    "authentication_override_configured": "Authentication Override",
    # VENDOR'S OWN WORD, Help 11.2 p.1051: "Certificate to Encrypt/Decrypt Cookie-Select the
    # certificate the gateway uses to use when encrypting and decrypting the cookie. Ensure that the
    # gateway and portal both use the same certificate to encrypt and decrypt cookies."
    #
    # THE CELL PRINTS `(none)` WHERE NOTHING IS BOUND and that is the un-improved cell this run
    # recorded rather than fixed - see the refused readers above. The shipped query "No certificate
    # encrypts the reconnection cookie" is what says what the `(none)` means.
    "cookie_encrypt_decrypt_cert": "Certificate to Encrypt/Decrypt Cookie",
    # OURS. The vendor has no word for this - it is a COUNT over eight exclusion axes, six of them
    # inside `split-tunneling` and two of them siblings of it, and no PAN-OS screen presents them
    # together. "Uninspected" is the point: a path excluded from the tunnel is a path the firewall
    # never sees, whatever else is true of it.
    #
    # ZERO IS THE PASSING VALUE AND THE DEFAULT, which is why the companion below exists.
    "uninspected_egress_path_count": "Egress paths excluded from the tunnel",
    # OURS, the companion, and stage 5 calls it "the one default in this artifact that sits on the
    # reassuring side": the count's honest empty value is zero, which is also a perfectly configured
    # full tunnel, so a row nobody recomputed is indistinguishable from the most compliant row on
    # the tab. This column is false on exactly those rows and fires on its own.
    "egress_inventory_computed": "The exclusion inventory was computed",
}


# --------------------------------------------------------------------------------------------
# THE ONE HEADING THIS DOMAIN OWES ON SOMEBODY ELSE'S TAB.
#
# PAN-GPG-005 reports on `integrations.GlobalProtectEnforcementPoint`, whose `GlobalProtect Coverage`
# tab the `globalprotect-portal` domain built on 2026-11-02 and deliberately left un-narrowed so
# this control would reach it. `setting_columns` derives a column per clause field of the controls
# PRESENT in the build, so this control's arrival ADDS a column to that tab - which that run
# predicted in as many words ("`setting_columns` will derive new columns on it for whatever that
# control clauses on") and could not name, because the column does not exist until this domain
# ships.
#
# MEASURED BEFORE WRITING IT, with the seeder against the real artifacts: the tab drew 17 headings
# over 3 rows and reported "RAW HEADINGS: 1 of 17" - `posture_referenced_in_policy`, this column,
# heading a customer-facing cell on a tab that was otherwise fully labelled. That is the defect the
# strict reading of "do not choose a heading" produces, and it is why this entry exists.
POSTURE_SETTING_LABELS = {
    # OURS, and the vendor has no word for it because the vendor has no such screen: this is a
    # verdict over THREE PLACES AT ONCE - the HIP objects at `Objects > GlobalProtect > HIP
    # Objects`, the HIP profiles at `Objects > GlobalProtect > HIP Profiles`, and the security
    # rulebase that may or may not reference one. Help 11.2 p.997 enumerates the eight GlobalProtect
    # screens and there is no roll-up over them.
    #
    # "referenced by a Security policy rule" IS THE LOAD-BEARING HALF. Posture that is collected and
    # never referenced gives a non-compliant endpoint exactly the access a compliant one gets, which
    # is the whole of PAN-GPG-005: the apparatus costs licence, agent and administrative effort and
    # changes no outcome until a rule asks. A heading reading "Host posture enforced" would claim
    # more than the column knows - it knows a rule REFERENCES a profile, not that the rule matches
    # anything.
    "posture_referenced_in_policy": "Host posture referenced by a Security policy rule",
}
