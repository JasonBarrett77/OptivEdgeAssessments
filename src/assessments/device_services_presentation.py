"""Presentation for the `device-services` pipeline domain - five tabs over five models.

Stage 9, 2026-11-03. Nine shipped controls, PAN-SVC-001 to -010 less -008, over five control
types and five models, all five of them appliance-scoped singletons under
`deviceconfig/system`:

    ntp_settings      integrations.NtpSettings      PAN-SVC-001, -002      tab `NTP`
    snmp_settings     integrations.SnmpSettings     PAN-SVC-004, -005      tab `SNMP`
    system_identity   integrations.SystemIdentity   PAN-SVC-007, -009, -010 tab `System Identity`
    dns_settings      integrations.DnsSettings      PAN-SVC-003           tab `DNS Settings`  NEW
    service_route     integrations.ServiceRoute     PAN-SVC-006           tab `Service Routes` NEW

THREE OF THE FIVE TABS ALREADY EXISTED AS BARE STUBS - a description and a title and nothing
else - so every settings column on them was a raw Django field name in front of a customer.
Measured with `print_findings_table`'s raw-heading census before this module existed:
**16 raw headings of 55** across the three tabs (5 of 18 on NTP, 5 of 18 on SNMP, 6 of 19 on
System Identity). This module's `setting_labels` are what close that, and the census is re-run
after in `tests/test_device_services_presentation.py`.

EVERY HEADING AND BOTH NEW TAB TITLES BELOW ARE PROPOSALS (P399). Jason takes the heading pass
once across many domains. Each is sourced to the vendor's own word where the vendor has one, with
the Help version and page, and SAYS SO where the vendor has no word - because a verdict column
spanning several vendor fields is ours and implying otherwise would be worse than admitting it.

---------------------------------------------------------------------------------------------
WHY EVERY ONE OF THE FIVE TABS NEEDS A SHEET-LEVEL `provenance_cell`, measured on built rows

The contract's two greps, answered PER FIELD over the 23 clause fields (not once per tab):

  (i)  `choices`: TWELVE of the 23 carry it and ELEVEN do not, and they sit side by side on the
       same row of the same tab on all five tabs. A reader is MANDATORY on the twelve - without
       one the cell prints the stored enum key - and FATAL on the eleven, where
       `get_<field>_display()` does not exist and the `AttributeError` lands at TEMPLATE RENDER,
       past `django check` and past all three cross-domain gates (P462). The twelve are named in
       the five `*_READERS` maps below and nowhere else.

  (ii) `DERIVED_FIELDS` against the clause-field list, field by field. THREE of the five models
       are MIXED, not two:

         NtpSettings      5 clause fields, all 5 derived
         DnsSettings      2 clause fields, both derived
         SnmpSettings     5 clause fields, 4 derived - `community_is_default` IS NOT
         SystemIdentity   6 clause fields, 5 derived - `addressing_mode` IS NOT
         ServiceRoute     5 clause fields, 4 derived - `scope` IS NOT

       `community_is_default` is the one the orchestrator's brief had wrong: it was briefed as
       "all five derived, a constant cell is honest", and it is a real stored column carrying a
       real `FieldProvenance` row - measured `Local` on pan-fw-1085 and `Not configured` on the
       other three appliances. A constant "Derived" cell would print a FALSEHOOD about it on
       every PAN-SVC-005 row.

AND THE DEFAULT CELL IS WRONG ON ALL FIVE TABS, which the greps alone do not predict and which
is the `saas-security` shape (P451) rather than the `updates` one. Measured on built rows:
NOT ONE of the 23 clause fields has a `FieldProvenance` row except `community_is_default` and
`addressing_mode`. The rows these normalizers DO write belong to the stored keys the columns are
computed FROM - `primary_server`, `secondary_server`, `primary_auth_type`, `secondary_auth_type`,
`hostname`, `timezone`, `primary_resolver_address` - and no control clauses on any of them. So
`write_node_row` was called WITH a provenance list and none of its fields is one a control tests,
which leaves the default cell reading "Not recorded". And NO model here carries an `__entry__`
row either, so `remediation_accessor`'s walk has nothing to reach: the `logging` remedy of
calling `provenance_of("__entry__")` buys nothing on this domain and is measured, not assumed -
see `provenance_cell`'s own docstring.

---------------------------------------------------------------------------------------------
WHAT A READER COSTS HERE, AND THE ONE PLACE THE SHEET-LEVEL CELL BUYS IT BACK

The contract's price rule: a reader marks its field `stored=False`, `remediation_accessor` then
sets `row=None` (`findings.py:570`) and walks to the object's `__entry__` row, so a reader on a
measured payload key costs that key's own provenance row. ELEVEN of the twelve readers below are
free by that rule - their fields are in `DERIVED_FIELDS` and have no row to lose.

`addressing_mode` IS THE EXCEPTION AND IS NOT FREE BY THAT RULE: it is a stored key with a real
row, measured `PAN-OS default` on pan-fw-1085 and `Local` on the other three. It needs a reader
anyway, because it carries `choices` and would otherwise print `dhcp-client` to a customer under
a heading taken from the vendor's own screen.

THE SHEET-LEVEL CELL RECOVERS IT, which is already on the record and is CONFIRMED here on built
rows rather than discovered: `reference/consumer-repo-notes.md`, "`build_rows` computes the whole
per-field provenance `cells` list and then DISCARDS it when the spec sets `provenance_cell`, so a
`value_reader`'s recorded provenance cost is ZERO on such a sheet". That entry also states the
narrower form this domain pays - a reader on such a sheet still costs the TEMPLATE column's answer
for its field, because `tested_fields` marks it `stored=False` and that reaches
`remediation_accessor` through `dict(fields)`. `build_rows` computes the Provenance cell as
`spec.provenance_cell(policy, provenance_of, shown)` when a sheet declares
one, and hands it `provenance_of` - the raw index lookup - rather than `remediation_of`. So the
cell still finds `addressing_mode`'s real row even though the per-field cell behind it cannot.
MEASURED on the built PAN-SVC-007 rows, 2026-11-03: the default cell reads "Derived | Derived" -
the reader's own prose string twice, because `remediation_accessor` returned `row=None` and then
found no `__entry__` row, so the fallback at `findings.py:752` printed `reader.provenance` - and
this cell reads "Local | Derived". The word the reader loses is recovered by the cell, and on
pan-fw-1085 the recovered word would be "PAN-OS default", which is a state neither "Local" nor
"Derived" can express.

SO THE PRICE RULE'S EXEMPTION IS LOAD-BEARING HERE, and this is the first domain where refusing
the reader was not an option: a reader on a measured payload key costs that key's provenance row
IN THE PER-FIELD CELLS, and a sheet-level `provenance_cell` buys it back. It is NOT a general
license - the per-field `Template` column and the `source_columns` still go through
`remediation_of` and still lose it, so what is recovered is the Provenance cell and not every
surface. `addressing_mode`'s Template cell is the price this domain pays and it is paid knowingly:
the field is a local key on three of the four appliances and a vendor implicit on the fourth, and
neither is a template, so the Template column had nothing to lose on this estate. On a
Panorama-pushed estate it would.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import FieldProvenance

from assessments.artifacts.layout import NONE, ha_role
from assessments.artifacts.sheets import findings as findings_sheet

DERIVED = FieldProvenance.ProvenanceType.DERIVED.label


# ---------------------------------------------------------------------------------------------
# The Provenance cell
# ---------------------------------------------------------------------------------------------

def _recorded(provenance_of, fields, skip=()) -> str:
    """The distinct answers `provenance_of` RECORDED about the row's own clause fields.

    Distinct and in the order encountered, which is `member_provenance`'s own rule and
    `logging_presentation.provenance_cell`'s: a row whose five derived fields all answer the same
    way prints one line, not five.
    """
    labels = []
    for field, _stored in fields:
        if field in skip:
            continue
        label, _template = findings_sheet.provenance_cells(provenance_of(field), stored=True)
        if label not in labels:
            labels.append(label)
    return "\n".join(labels) or "Not recorded"


def provenance_cell(subject, provenance_of, fields) -> str:
    """What is recorded about each clause field, with derived and measured told apart.

    For `NTP`, `SNMP`, `System Identity` and `DNS Settings`. Signature is `build_rows`' own -
    (subject, provenance_of, [(field, stored), ...]) - with `fields` already narrowed to what the
    row shows and in the order the per-field cells are written, so this reads across with the
    settings columns.

    `provenance_of` is read DIRECTLY rather than through `remediation_accessor`, because the
    distinction this cell prints is the one that accessor deliberately discards: it treats DERIVED
    as "no answer" (`findings.py:563-564`) and walks to the object's `__entry__` row, which none
    of these four models carries. MEASURED on built rows, 2026-11-03, per tab AND PER CONTROL -
    `build_rows` hands this the clause fields of the ROW'S OWN control, not the tab's:

        NTP, PAN-SVC-001 row       default "Not recorded | Not recorded | Derived"  this "Derived"
        NTP, PAN-SVC-002 row       default "Not recorded | Derived"                 this "Derived"
        SNMP, PAN-SVC-004 row      default "Not recorded | Not recorded | Derived"  this "Derived"
        SNMP, PAN-SVC-005 row      default "Not recorded | Local | Derived"
                                                                      this "Derived | Local"
        System Identity, -007 row  default "Derived | Derived"        this "Local | Derived"
        System Identity, -009 row  default "Not recorded | Derived"   this "Derived"
        System Identity, -010 row  default "Not recorded | Derived"   this "Derived"
        DNS Settings, PAN-SVC-003  default "Not recorded | Derived"   this "Derived"

    (`Service Routes` has its own cell - see `SERVICE_ROUTE_SCOPE_NOTE`. Default on a PAN-SVC-006
    row is "Not recorded | Not recorded | Not recorded | Derived | Derived"; that cell reads
    "Derived".)

    TWO THINGS THE GREPS DO NOT PREDICT, both measured above. First, the default prints
    "Not recorded" somewhere on EVERY ONE of these rows, about columns the model declares derived
    - the `saas-security` shape (P451): these normalizers call `write_node_row` WITH a provenance
    list, and every field in it is a stored key the columns are computed FROM rather than a field
    a control clauses on, so the cell never reads one. Second, on the PAN-SVC-005 row the default
    is not merely noisy but reaches `Local` and then prints "Not recorded" beside it, so the one
    row in the domain whose tested value an administrator actually wrote is the row whose cell
    reads worst.

    THE DISTINCT ANSWERS APPEAR ACROSS ROWS AND NEVER MEET IN ONE CELL, which is the thing that
    has to be measured per control rather than over the tab's union: `Local` is true of
    PAN-SVC-005's and PAN-SVC-007's rows and of no other's, and a constant "Derived" would be
    false on both. The two-way derived-or-`Local` branch is not enough either -
    `community_is_default` reads `Not configured` on the three appliances whose community is
    unset, and `addressing_mode` reads `PAN-OS default` on pan-fw-1085, which is a VENDOR IMPLICIT
    and is neither written by an administrator nor derived by us. Neither of those two appliances
    draws a row for the control that tests the field in question on this estate, so they do not
    appear in the table above - which is exactly why the cell prints what was RECORDED and
    decides nothing, rather than branching on the two answers this lab happens to produce.

    `NtpSettings` and `DnsSettings` have every clause field derived, so this is measured to return
    exactly the constant "Derived" on them. It is written as the branch rather than as a literal
    so that a stored clause field added to either model later cannot silently make the cell lie -
    which is precisely how `SnmpSettings` came to be briefed as uniform when it is not.
    """
    return _recorded(provenance_of, fields)


#: `scope` IS IDENTITY AND NOT A TESTED VALUE, which is why the `Service Routes` tab gets its own
#: cell. Measured on built rows, 2026-11-03:
#:
#:     default                  "Not recorded | Not recorded | Not recorded | Derived | Derived"
#:     `provenance_cell` above  "Not recorded | Derived"
#:     this                     "Derived"
#:
#: `ServiceRoute` carries ZERO `FieldProvenance` rows of any kind - not one per field and no
#: `__entry__` row - so the fourth branch's remedy does not apply here and that was measured
#: rather than taken on trust. The orchestrator's brief predicted `scope` would be the fourth
#: case and that the remedy would be `logging`'s walk to `provenance_of("__entry__")`. The first
#: half holds exactly: `scope` is stored, is not in `DERIVED_FIELDS`, is not reader-only, and
#: `provenance_of("scope")` answers None, because the normaliser takes the value from the config
#: SUBTREE the row was read at rather than from any key of the entry - stage 5 says so in those
#: words ("with SCOPE FOLLOWING THE CONFIG SUBTREE the value came from rather than which read
#: returned it"). The second half does NOT: there is no entry row to walk to, so the walk returns
#: the same "Not recorded" and buys nothing.
#:
#: SO THE REMEDY HERE IS THE SUBJECT COLUMN, NOT THE WALK. Stage 5 calls `scope` "half the row's
#: key" and declares its unknown state `cannot_be_unknown` for that reason, so it is presented by
#: a subject column of its own - `Scope`, with `field="scope"` so the cell can still be marked -
#: and this cell does not answer about it. The Provenance column says where the values a control
#: TESTED came from; printing "Not recorded" about the row's own identity would be noise that
#: reads as a gap. The remaining four clause fields are all derived and this returns "Derived".
#:
#: `scope` is in NO query's `asserted_fields` - it is PAN-SVC-006's scope clause only - so moving
#: it into the subject block forfeits no value-at-fault mark, which was checked in the catalogue
#: before the column was moved rather than assumed from the clause list.
SERVICE_ROUTE_SCOPE_NOTE = "scope is identity: presented by a subject column, not by this cell"


def service_route_provenance_cell(subject, provenance_of, fields) -> str:
    """As `provenance_cell`, less the row's own identity. See `SERVICE_ROUTE_SCOPE_NOTE`."""
    return _recorded(provenance_of, fields, skip=("scope",))


# ---------------------------------------------------------------------------------------------
# NTP - Device > Setup > Services > NTP
# ---------------------------------------------------------------------------------------------

#: REWRITTEN 2026-11-03 (PROPOSAL, P399), because the shipped sentence told a customer this
#: assessment does not do a thing the catalogue ships two graded queries about. The sentence
#: removed, verbatim:
#:
#:     "Whether a configured server is reachable or synchronized is not assessed - that is live
#:      device state, not configuration."
#:
#: PAN-SVC-001's third and fourth calibrations clause on `synched_to_a_configured_server` and
#: `time_source_in_force`, one of them graded `high`, and both are drawn columns on this tab.
#:
#: THE SENTENCE IS THE HALF THAT WAS WRONG, not the clause, and the catalogue says so in its own
#: words rather than leaving it to be judged: PAN-SVC-001's description carries "AND
#: SYNCHRONIZATION IS NOW ASSESSED, which this paragraph said it was not until 2026-11-01". So
#: the control was widened on 2026-11-01 and this tab's description was simply not updated with
#: it. Nothing about the clause is in doubt and nothing here is a disagreement with stage 8.
NTP_DESCRIPTION = (
    "Where each firewall gets its time, whether those exchanges are authenticated, and whether "
    "the clock is actually anchored to a server this configuration names. An appliance whose "
    "`show ntp` reading was never taken reports as NOT anchored rather than as compliant, and "
    "the Time source in force column says which of the two it is. DEVICE-WIDE: "
    "`deviceconfig/system/ntp-servers` is outside configuration sync, so an HA pair holds two "
    "independent settings and both are reported.")

#: PROPOSALS (P399). Vendor words from PAN-OS Web Interface Help 11.2 p.751, the `NTP` block of
#: Global Services Settings at Device > Setup > Services, read out of the corpus rather than from
#: memory: "NTP Server Address", "Authentication Type", "Symmetric Key", "Autokey".
NTP_SETTING_LABELS = {
    # The vendor names the two slots "NTP Server Address"; the COUNT over them is ours. PAN-OS
    # has exactly two slots, so this is 0, 1 or 2 and never a list length.
    "server_count": "NTP servers configured",
    # NO VENDOR WORD - this is a comparison between an operational reply and the configured slots
    # and the vendor's screen has nothing to say about it. Said rather than implied.
    "synched_to_a_configured_server": "Clock anchored to a configured server",
    # NO VENDOR WORD, and the heading deliberately does not promise synchronisation either way:
    # the column's own vocabulary separates "Not synchronised, or never read" from
    # "Synchronised to a source the configuration does not name" from "Synchronised to a
    # configured server", and the first of those three is one state and not two.
    "time_source_in_force": "Time source in force",
    # Vendor "Symmetric Key", one of the three Authentication Type options.
    "all_servers_symmetric_key": "Every server on a symmetric key",
    # THE VENDOR'S OWN WORDS, Help 11.2 p.751.
    "server_authentication_mechanism": "Authentication Type",
}


def _time_source(ntp) -> str:
    """`time_source_in_force`'s LABEL, not its stored key.

    MANDATORY, not a nicety: the field carries `choices` and nothing in the sheets layer calls
    `get_<field>_display()`, so the cell would print `not_synchronised_or_never_read` to a
    customer under the heading above (P457). FREE: the field is in `NtpSettings.DERIVED_FIELDS`,
    so there is no `FieldProvenance` row for `stored=False` to discard.

    AND THE LABEL IS THE WHOLE ANSWER TO THE OPERATIONAL-READ PROBLEM ON THIS TAB, which is why
    this reader is load-bearing rather than cosmetic. `logging` drew a finding on every appliance
    reading "logs are not reaching the central store" where the truth was "no reading was taken",
    because its column was a BOOLEAN and False was the firing side: the column had no way to say
    which. This column is a three-member classification whose firing member is spelled
    `not_synchronised_or_never_read` and whose label reads "Not synchronised, or never read" - so
    the model already tells a customer that the two states are not distinguished, in the cell
    itself. Measured on all four appliances of the built estate, where the operational reply is
    absent because stage 6 records it in prose and the seeder has no `op://` placement: every row
    reads "Not synchronised, or never read". A hand-declared `*_known` companion column would add
    nothing this label does not already say, and no such column exists on the model to declare.
    """
    return ntp.get_time_source_in_force_display()


def _ntp_authentication(ntp) -> str:
    return ntp.get_server_authentication_mechanism_display()


NTP_READERS = {
    "time_source_in_force": findings_sheet.ValueReader(read=_time_source, provenance=DERIVED),
    "server_authentication_mechanism": findings_sheet.ValueReader(
        read=_ntp_authentication, provenance=DERIVED),
}


# ---------------------------------------------------------------------------------------------
# SNMP - Device > Setup > Operations > SNMP Setup
# ---------------------------------------------------------------------------------------------

#: PROPOSALS (P399). Vendor words from PAN-OS Web Interface Help 11.2 p.740, "Enable SNMP
#: Monitoring" at Device > Setup > Operations: "Version - Select the SNMP version: V2c (default)
#: or V3", "SNMP Community String ... Don't use the default community string public."
SNMP_SETTING_LABELS = {
    # NO VENDOR WORD for the verdict - the vendor's screen either has an agent configured or does
    # not and says nothing about the distinction.
    "is_configured": "SNMP agent configured",
    "answers_on_an_unauthenticated_version": "Answers on an unauthenticated version",
    # THE VENDOR'S WORD IS "Version" AND THIS COLUMN IS WIDER THAN IT, said rather than quietly
    # borrowed: the field's four members include "Configured with no version recorded" and "No
    # agent configured", which are states of the assessment and not values of the vendor's
    # drop-down. Heading the column "Version" would promise the vendor's field and deliver a
    # verdict over it.
    "snmp_version_in_force": "SNMP version in force",
    # Vendor "SNMP Community String", and the vendor's own warning names the default: "Don't use
    # the default community string public."
    "community_is_default": "Community string is a default",
    "default_community_exposure": "Default community exposure",
}


def _snmp_version(snmp) -> str:
    """`snmp_version_in_force`'s label. MANDATORY (`choices`), FREE (`DERIVED_FIELDS`)."""
    return snmp.get_snmp_version_in_force_display()


def _community_exposure(snmp) -> str:
    """`default_community_exposure`'s label. MANDATORY (`choices`), FREE (`DERIVED_FIELDS`)."""
    return snmp.get_default_community_exposure_display()


SNMP_READERS = {
    "snmp_version_in_force": findings_sheet.ValueReader(read=_snmp_version, provenance=DERIVED),
    "default_community_exposure": findings_sheet.ValueReader(
        read=_community_exposure, provenance=DERIVED),
}


# ---------------------------------------------------------------------------------------------
# System Identity - Device > Setup > Management > General Settings, and Setup > Interfaces
# ---------------------------------------------------------------------------------------------

#: PROPOSALS (P399). Vendor words from PAN-OS Web Interface Help 11.2 p.700, General Settings at
#: Device > Setup > Management: "Hostname - Enter a hostname (up to 31 characters) ... If you
#: don't enter a value, PAN-OS uses the firewall model (for example, PA-5220_2) as the default";
#: "Time Zone - Select the time zone of the firewall"; and "Management Interface IP Type is DHCP
#: Client", which is the vendor's name for `addressing_mode`.
#:
#: THE VENDOR CONFIRMS ONE OF THIS DOMAIN'S COLUMNS IN ITS OWN DOCUMENTATION, which is worth
#: recording because stage 8 flagged the same state as the project's first standing subject for
#: the clause: `hostname_posture`'s member "The stored name is the model, with or without a
#: numeric suffix" is exactly the vendor's documented default behaviour above.
SYSTEM_IDENTITY_SETTING_LABELS = {
    # THE VENDOR'S OWN WORDS, Help 11.2 p.700.
    "addressing_mode": "Management Interface IP Type",
    # NO VENDOR WORD: a verdict over the IP Type crossed with whether any input classifies the
    # appliance as cloud-hosted, which is not on the vendor's screen at all.
    "addressing_mode_posture": "Management addressing posture",
    "timezone_declares_zero_offset": "Time Zone declares a zero offset",
    "timezone_offset_class": "Time Zone offset",
    "hostname_is_factory_default": "Hostname is the factory default",
    # NO VENDOR WORD. This is the column carrying the distinction PAN-SVC-010's clause drops -
    # see `HOSTNAME_POSTURE_NOTE`.
    "hostname_posture": "Name in force",
}

#: WHAT THIS TAB SHOWS THAT PAN-SVC-010's VERDICT CANNOT, recorded because stage 8 raised it as a
#: `needs_human` and it lands on presentation. Stage 3 grades "a chosen name on a device that may
#: take its name from the lease"; stage 6 expects PAN-SVC-010 to fire on `dsv6-host-02`; and
#: stage 5's clause `hostname_is_factory_default eq true` excludes it by the rank's own premise,
#: because a CHOSEN name is by definition not the factory default. Stage 8 implemented the clause
#: as written and its diff row is the one red row in the domain.
#:
#: MEASURED ON BUILT ROWS, 2026-11-03, and the answer is that the distinction IS on the tab and is
#: NOT attached to a verdict. `dsv6-host-02` is pan-fw-111, serial 6A9C0A9904E7D6E, which nine of
#: this domain's 34 stage 6 subjects share - so the appliance has a `SystemIdentity` row, and
#: PAN-SVC-007 and PAN-SVC-009 both fire on it. `setting_columns` fills every settings column for
#: every row of the matching model, not only the columns of the row's own control, so the
#: `Name in force` cell on those two rows reads
#:
#:     "A chosen name on a device that may take its name from the lease"
#:
#: which is the rank stage 3 graded, in the vendor-independent words the model already carries,
#: beside a PAN-SVC-007 verdict of `medium` and a PAN-SVC-009 verdict of `low`. PAN-SVC-010 draws
#: NO row for that appliance, so there is no cell of its own to read: the honest answer to "what
#: does the posture cell say beside the verdict" is that it says the right thing beside somebody
#: else's verdict, and nothing beside its own. A reader who filters this tab to PAN-SVC-010 does
#: not see it. Nothing presentation can declare fixes that - it needs the second assertion record
#: stage 8 proposed, which is stage 5's artifact to change.
HOSTNAME_POSTURE_NOTE = (
    "hostname_posture carries PAN-SVC-010's dropped rank, but only on rows another control drew")


def _addressing_mode(identity) -> str:
    """`addressing_mode`'s label.

    MANDATORY: `choices` of ("static", "dhcp-client"), so the cell would print `dhcp-client`
    under a heading taken from the vendor's own screen.

    NOT FREE BY THE PRICE RULE, AND BOUGHT BACK BY THE SHEET-LEVEL CELL - the one instance of
    this in the domain. See this module's docstring: `addressing_mode` is a stored key with a
    real `FieldProvenance` row, measured `PAN-OS default` on pan-fw-1085 and `Local` on the other
    three appliances, and marking it `stored=False` makes `remediation_accessor` walk past that
    row to an `__entry__` row `SystemIdentity` does not carry - so the per-field cell falls back
    to this reader's own `provenance` string and prints "Derived" about a key an administrator
    wrote. `provenance_cell` reads `provenance_of` directly and still finds the row, so the
    Provenance column reads "Local | Derived" where the default reads "Derived | Derived".
    Measured on both built PAN-SVC-007 rows, 2026-11-03.
    """
    return identity.get_addressing_mode_display()


def _addressing_posture(identity) -> str:
    return identity.get_addressing_mode_posture_display()


def _timezone_offset(identity) -> str:
    return identity.get_timezone_offset_class_display()


def _hostname_posture(identity) -> str:
    """`hostname_posture`'s label. See `HOSTNAME_POSTURE_NOTE` for why this cell matters most."""
    return identity.get_hostname_posture_display()


SYSTEM_IDENTITY_READERS = {
    "addressing_mode": findings_sheet.ValueReader(read=_addressing_mode, provenance=DERIVED),
    "addressing_mode_posture": findings_sheet.ValueReader(
        read=_addressing_posture, provenance=DERIVED),
    "timezone_offset_class": findings_sheet.ValueReader(
        read=_timezone_offset, provenance=DERIVED),
    "hostname_posture": findings_sheet.ValueReader(read=_hostname_posture, provenance=DERIVED),
}


# ---------------------------------------------------------------------------------------------
# DNS Settings - Device > Setup > Services > DNS Settings            NEW TAB
# ---------------------------------------------------------------------------------------------

#: TAB TITLE, A PROPOSAL (P399): "DNS Settings", 12 characters, well under the 31 Excel allows a
#: sheet name (`DeviceSettingSheet.title`, which truncates SILENTLY past it).
#:
#: THE VENDOR'S OWN HEADING, read out of the corpus: PAN-OS Web Interface Help 11.2 p.749 heads
#: the block "DNS Settings" inside "Global Services Settings - Device > Setup > Services". The
#: control type's own label is "Management Resolvers", which is OURS and is what the sheet would
#: fall back to with no title - so the title is passed deliberately to put the vendor's word on
#: the tab an assessor reads, matching its two siblings `NTP` and `SNMP` on the same screen.
DNS_SETTINGS_TITLE = "DNS Settings"

DNS_SETTINGS_DESCRIPTION = (
    "Which resolvers each firewall uses for the lookups it originates itself - reaching the "
    "update server, resolving FQDN address objects and resolving names in logs - and whether "
    "that choice is the firewall's own or follows whatever its management lease hands it. "
    "DEVICE-WIDE: `deviceconfig/system/dns-setting` is outside configuration sync, so an HA pair "
    "holds two independent settings and both are reported.")

#: PROPOSALS (P399). Vendor words from PAN-OS Web Interface Help 11.2 p.749: "DNS Settings",
#: "Primary DNS Server", "Secondary DNS Server".
DNS_SETTINGS_SETTING_LABELS = {
    # The vendor names the two slots; the COUNT of resolvers actually in force is ours, and it is
    # not simply "how many of the two slots are filled" - a DNS proxy object and a management
    # lease are both ways to have a resolver without either slot being set.
    "chosen_resolver_count": "Resolvers chosen",
    # NO VENDOR WORD: a verdict crossing the resolver count with whether the management address
    # is leased, which is two vendor screens rather than one field.
    "management_resolver_posture": "Management resolver posture",
}


def _resolver_posture(dns) -> str:
    """`management_resolver_posture`'s label. MANDATORY (`choices`), FREE (`DERIVED_FIELDS`)."""
    return dns.get_management_resolver_posture_display()


DNS_SETTINGS_READERS = {
    "management_resolver_posture": findings_sheet.ValueReader(
        read=_resolver_posture, provenance=DERIVED),
}


# ---------------------------------------------------------------------------------------------
# Service Routes - Device > Setup > Services > Service Route Configuration        NEW TAB
# ---------------------------------------------------------------------------------------------

#: TAB TITLE, A PROPOSAL (P399): "Service Routes", 14 characters, under the 31-character cap.
#:
#: THE VENDOR'S LITERAL CONTROL IS "Service Route Configuration" - PAN-OS Web Interface Help 11.2
#: p.748, "In Service Features, click Service Route Configuration" - which is 27 characters and
#: would also fit. The shorter noun is proposed instead because a tab is not a button and the
#: three siblings on the same screen are `NTP`, `SNMP` and `DNS Settings`; "Service Routes" is
#: the vendor's own noun for the thing without the word for the dialogue that sets it. The
#: control type's own label, "Management Service Paths", is ours.
SERVICE_ROUTE_TITLE = "Service Routes"

#: THE TWO SCOPES ARE ONE TAB AND NOT TWO, which is the vendor's own organisation: Help 11.2
#: p.748 puts both behind the same Service Route Configuration control, on a Global tab and a
#: Virtual Systems tab ("Use the Virtual Systems tab to specify service routes for a single
#: virtual system. Select a Location (virtual system) and click Service Route Configuration").
#: One model, one control, one set of columns, and the Scope column says which a row is - so
#: splitting them would print `layout.NONE` in half the columns of every row for nothing.
SERVICE_ROUTE_DESCRIPTION = (
    "Which source interface and address each firewall uses to reach the services it originates "
    "itself - DNS, syslog, LDAP, RADIUS, updates and the rest - firewall-wide and per virtual "
    "system. The firewall-wide row is DEVICE-WIDE, so an HA pair holds two independent settings "
    "and both are reported; a virtual system's own set belongs to the virtual system. The Scope "
    "column says which of the two a row is.")

#: PROPOSALS (P399). Vendor words from PAN-OS Web Interface Help 11.2 p.748: "Service Route
#: Configuration", "Use Management Interface for all", "Customize", "Inherit Global Service Route
#: Configuration", and Table 13's list of the services that can be customised.
SERVICE_ROUTE_SETTING_LABELS = {
    # NO VENDOR WORD for the verdict. "Originated" is the distinction the control rests on and the
    # vendor's Table 13 is the list it is taken over: a service the firewall does not originate
    # cannot have a path and is not counted against this.
    "every_originated_service_has_a_chosen_path": "Every originated service has a chosen path",
    # Vendor "Inherit Global Service Route Configuration" versus "Customize" - the two things a
    # virtual system's own tab offers. This column says whether EITHER was recorded.
    "per_system_path_choice_recorded": "Virtual system records its own choice",
    "per_system_path_posture": "Virtual system path posture",
    "service_path_posture": "Firewall-wide path posture",
}

#: THE SUBJECT COLUMNS. `Scope` names `field="scope"` so that a control testing it marks THIS cell
#: rather than drawing a second column of the same name - which is not merely untidy: a table with
#: a duplicate header is rejected by Excel and xlsxwriter drops it, leaving a sheet of stray cells
#: (`NAME`'s own comment in `objects.py` records two sheets this happened to).
#:
#: `Virtual system` is the vendor's own noun and the em dash is `layout.NONE`, U+2014, for the
#: firewall-wide row - which does not have a virtual system rather than having an empty one. That
#: is the one state `display_value` cannot express: it would print `(empty)` and offer it as the
#: thing to fix.
#:
#: `get_scope_display()` is called here and is the reason `scope` sits in this block rather than
#: in the derived settings columns: the field carries `choices` of ("device-local", "vsys") and a
#: settings column would print `device-local` to a customer. A subject lambda can call the display
#: method without a `value_reader`, so the identity column pays none of the reader's price.
SERVICE_ROUTE_SUBJECT_NOTE = "Scope declares field='scope'; see SERVICE_ROUTE_SCOPE_NOTE"

SERVICE_ROUTE_SUBJECT = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
    ("Scope", 24, False, lambda s, _p: s.get_scope_display(), "scope"),
    ("Virtual system", 14, False, lambda s, _p: s.vsys_name or NONE, "vsys_name"),
)


def _path_posture(route) -> str:
    """`service_path_posture`'s label. MANDATORY (`choices`), FREE (`DERIVED_FIELDS`)."""
    return route.get_service_path_posture_display()


def _per_system_posture(route) -> str:
    """`per_system_path_posture`'s label. MANDATORY (`choices`), FREE (`DERIVED_FIELDS`)."""
    return route.get_per_system_path_posture_display()


SERVICE_ROUTE_READERS = {
    "service_path_posture": findings_sheet.ValueReader(read=_path_posture, provenance=DERIVED),
    "per_system_path_posture": findings_sheet.ValueReader(
        read=_per_system_posture, provenance=DERIVED),
}
