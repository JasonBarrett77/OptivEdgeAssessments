"""What the `logging` domain's three findings tabs show, and why each cell reads as it does.

Stage 9 of the OptivEdgeProbe pipeline, domain `logging`, 2026-11-03. Ten controls, PAN-LOG-001
to -010, over three subject models and three control types:

    logging_settings      PAN-LOG-001, -003, -004, -006, -007, -008, -009, -010
                          integrations.LoggingSettings      - an EXISTING tab, PAN-MGT-011's
    log_server_target     PAN-LOG-002   integrations.LogServerTarget      - a new tab
    vsys_log_forwarding   PAN-LOG-005   integrations.VsysLogForwarding    - a new tab

EIGHT OF THE TEN LAND ON A TAB THIS DOMAIN DOES NOT OWN, which no stage 9 run before this one
has had. `Logging and Reporting Settings` existed for PAN-MGT-011 alone - one settings column,
`log_on_high_dp_load`, with NO `setting_labels` at all, so that heading was a raw Django field
name on a shipped tab. Adding eight controls to it adds ten more columns, and every one of them
would have been raw too. So the label map here covers ELEVEN clause fields and not ten: the
eleventh is PAN-MGT-011's own, labeled here deliberately rather than left bare for the
`management-services` run to find. The column is not this domain's; the tab a customer reads is.

EVERY HEADING BELOW IS A PROPOSAL (P399) and each is sourced to the vendor's own words where the
vendor has words, or says so where it does not. The three Help editions the corpus carries agree
on every citation used here; `PAN-OS Web Interface Help 11.2` page numbers are given.
"""
from __future__ import annotations

from .artifacts.layout import NONE, ha_role
from .artifacts.sheets import findings as findings_sheet


# ------------------------------------------------------------------------------------------
# The provenance cell, shared by two of the three tabs
# ------------------------------------------------------------------------------------------

def provenance_cell(subject, provenance_of, fields) -> str:
    """What is RECORDED about each clause field, with derived and measured told apart.

    Signature is `build_rows`' own - (subject, provenance_of, [(field, stored), ...]) - with
    `fields` already narrowed to what the row shows and in the order the per-field cells are
    written, so this reads across with the settings columns.

    `provenance_of` is read DIRECTLY rather than through `remediation_accessor`, because the
    distinction this cell prints is the one that accessor deliberately discards: it treats
    DERIVED as "no answer" (`findings.py:563-564`) and walks to the object's `__entry__` row,
    which `write_node_row` never writes for these models - so the default cell prints
    "Not recorded" for a computed column. MEASURED on built rows, 2026-11-03:

        LoggingSettings, PAN-LOG-001's row   default  "Not recorded | Not recorded"
                                             this     "Derived"
        LoggingSettings, PAN-LOG-007's row   default  "Local"          this  "Local"
        LoggingSettings, PAN-MGT-011's row   default  "PAN-OS default" this  "PAN-OS default"
        VsysLogForwarding                    default  "Not recorded | Not recorded"
                                             this     "Derived"

    THREE ANSWERS ACROSS THE ROWS OF ONE TAB, AND NOT THREE ON ONE ROW - which this run measured
    wrongly first and its own test caught. `build_rows` hands this cell the fields of the ROW's
    OWN control (`fields_by_control[finding.control_id]`), so the big tab's eleven clause fields
    never meet in one cell: PAN-LOG-001's row covers two derived columns and reads "Derived",
    PAN-LOG-007's covers `require_audit_comment` - a key an administrator wrote - and reads
    "Local", and PAN-MGT-011's covers `log_on_high_dp_load`, ABSENT on all three measured
    appliances and recorded by the normalizer as a VENDOR IMPLICIT, which reads "PAN-OS default":
    neither written by anyone nor derived by us. A constant string would be false on two of those
    three rows, and a two-way derived-or-local branch would have printed one of those two words
    over a state that is neither.

    ON `VsysLogForwarding` BOTH clause fields are declared derived, so this is measured to return
    exactly the constant "Derived" - which is the honest answer the contract's "all derived ->
    constant" rule asks for. It is written as this branch rather than as a literal so that a
    clause field added to that model later cannot silently make the cell lie.

    IT IS NOT USED ON THE `LogServerTarget` TAB, and that is measured rather than assumed - see
    `LOG_SERVER_TARGET_PROVENANCE_NOTE`.

    Distinct answers, in the order encountered, matching `member_provenance`'s own rule: a row
    whose nine derived fields all answer the same way prints one line, not nine.
    """
    labels = []
    for field, _stored in fields:
        label, _template = findings_sheet.provenance_cells(provenance_of(field), stored=True)
        if label not in labels:
            labels.append(label)
    return "\n".join(labels) or "Not recorded"


def provenance_cell_through_the_object(subject, provenance_of, fields) -> str:
    """The DEFAULT cell's own walk, de-duplicated. For the `LogServerTarget` tab only.

    THE DEFAULT CELL IS RIGHT HERE AND THE BRANCHING ONE IS WRONG - see
    `LOG_SERVER_TARGET_PROVENANCE_NOTE` - so this reproduces the default's answer rather than
    replacing it, and changes exactly one thing: it prints each distinct answer once. Measured on
    built rows, 2026-11-03:

        default                      "Local | Local | Local"      (three lines, one word)
                                     "Template | Template | Local" on the template row
        branching on provenance_of   "Not recorded | Derived | Local"
        this                         "Local"
                                     "Template | Local" on the template row

    `network-hardening`'s interfaces tab is the precedent for a sheet-level cell written ONLY to
    de-duplicate a repeated word, with no truth value changing. Three clause fields answering
    "Local" print "Local" three times under the default, and a reader cannot tell that from three
    separate findings about one row.

    HOW IT REACHES THE OBJECT WITHOUT `remediation_accessor`, which `provenance_cell` is not
    handed: `provenance_of` is a plain lookup into the row index `build_rows` bulk-loaded, and
    `__entry__` is a key in that index like any other - so asking it for `"__entry__"` gets the
    object's own entry row, which is the thing `remediation_accessor` walks to. `__entry__` is not
    in any `DERIVED_FIELDS`, so the synthesised-DERIVED arm of that closure cannot fire for it.

    The rule it implements is `remediation_accessor`'s, in that function's own words: the field's
    own provenance, else the object's entry, else nothing - with DERIVED counting as no answer,
    because a computed column has no location and the object does.
    """
    entry_row = provenance_of("__entry__")
    labels = []
    for field, _stored in fields:
        row = provenance_of(field)
        if row is None or row.provenance_type == row.ProvenanceType.DERIVED:
            row = entry_row
        label, _template = findings_sheet.provenance_cells(
            row, stored=True if row is not None else False)
        if label not in labels:
            labels.append(label)
    return "\n".join(labels) or "Not recorded"


#: WHY THE `LogServerTarget` TAB KEEPS THE DEFAULT PROVENANCE CELL'S ANSWER, although its clause
#: fields are
#: MIXED and the two-grep rule therefore says to branch. Measured on built rows, 2026-11-03:
#:
#:     default    "Local"                            (and "Template | Local" on the row a
#:                                                     template contributed)
#:     branching  "Not recorded | Derived | Local"
#:
#: The branch is WRONG, twice over, and the cause is a shape the contract's three branches do not
#: name. `kind` is a clause field of PAN-LOG-002 (its scope clause), it is a real stored column,
#: it is NOT in `DERIVED_FIELDS` - and it carries NO `FieldProvenance` row, because the normaliser
#: takes it from the config SUBTREE the profile was read at rather than from any key of the entry,
#: which `LogServerTarget.DERIVED_FIELDS`' own comment says in terms about the positional columns.
#: So `provenance_of("kind")` answers None, and a cell that prints what `provenance_of` recorded
#: prints "Not recorded" about a column whose location is simply the object's.
#:
#: And the default is the ONLY one of the two that surfaces a TEMPLATE. `remediation_accessor`
#: walks an unanswered field to the object's `__entry__` row, which this model DOES carry, so the
#: template-contributed server entry reads "Template" - the state PAN-LOG-002's remediation turns
#: on. The branch replaces that with "Local" and states something false about where to go and
#: change the value.
#:
#: So the rule needs a fourth branch: MIXED is not sufficient, because a clause field can be
#: unprovenanced WITHOUT being derived and WITHOUT being reader-only. The test that holds is the
#: one the contract already asks for and which the greps cannot answer - measure both cells on a
#: built row per tab.
LOG_SERVER_TARGET_PROVENANCE_NOTE = (
    "default cell kept: `kind` is a stored clause field with no FieldProvenance row, so a "
    "branching cell prints 'Not recorded' about it, and only the default reaches the __entry__ "
    "row that names a template")


# ------------------------------------------------------------------------------------------
# Tab 1 - Logging and Reporting Settings (integrations.LoggingSettings)
# ------------------------------------------------------------------------------------------

def _config_log_half(obj, which) -> str:
    """One half of PAN-LOG-004's verdict, as Yes/No.

    `config_log_fully_offbox` is an AND of two readings and the row shows only the AND, so a
    customer reads "Every configuration-change log leaves the firewall = No" with nothing saying
    WHICH half failed - and the two halves need opposite remediations: add a destination, or
    widen the filter that is holding logs back. Stage 8's own note on the firing row says the
    two half-columns "are stored beside the verdict so the finding can say WHICH half failed",
    and no clause reads either, so `tested_fields` derives no column for them.
    """
    return findings_sheet.display_value(getattr(obj, which))


#: The appliance, its HA role, and THREE readings that say which state a verdict names. None of
#: the three is a clause field, so `setting_columns` derives no column for any of them and the
#: rows would otherwise carry a verdict with no way to tell two opposite causes apart.
#:
#: HAND-DECLARED, which is the documented way to settle this: `presented` on a stage 5 column is a
#: record of what the column is FOR and not an instruction, and the machinery derives clause
#: fields only. All three ARE `presented: true` in stage 5, and all three would have reached no
#: cell. `COVERAGE_SUBJECT`'s "Device's own count" and `ha_panorama`'s three evidence columns are
#: the precedent for a subject-block column that is EVIDENCE rather than identity.
#:
#: EACH DECLARES ITS `field`, so a control later clausing on one marks THIS cell rather than
#: drawing a second column under a different heading - which the duplicate-header guard cannot
#: catch, because the two headings would differ.
#:
#: THE POSITIONAL COST, stated because it is real: the subject block sits BEFORE `Fires when`, so
#: these three evidence cells are read before the verdicts they explain. There is nowhere else to
#: put them - `auto_setting_columns` is all or nothing and `source_columns` cells can never be
#: marked - and a reader who meets the evidence early is better served than one who never meets
#: it.
#:
#: `central_store_status_collected` IS THE MOST IMPORTANT OF THE THREE and the reason is measured.
#: `central_store_delivery_healthy` is computed from an OPERATIONAL reply, and over any estate
#: where that reply was not collected it reads False - which is the firing side - so PAN-LOG-010
#: reports "logs are not reaching the central store" on an appliance nobody asked. This column is
#: the difference between that and a measured unhealthy collector, and rules.md's own rule covers
#: it: a reading that cannot tell ZERO from UNKNOWN is an unknown, per field.
LOGGING_POSTURE_EVIDENCE = (
    # Help 11.2 p.334 names the destinations a configuration match list can hold: "Panorama", a
    # "Syslog" server profile, an "HTTP" server profile. The vendor has no word for "any of
    # these exists", so this heading is ours.
    ("Configuration logs have a destination", 22, True,
     lambda s, _p: _config_log_half(s, "config_log_offbox_destination"),
     "config_log_offbox_destination"),
    # TRUE IS THE FIRING SIDE on this one, which the heading has to say or the cell reads
    # backwards beside its neighbour. Help 11.2 p.333 on a match list: "By default, the firewall
    # forwards All Logs of the selected Log Type. To forward a subset of the logs, select an
    # existing filter" - so a filter is the vendor's own mechanism for holding logs back.
    ("A filter holds configuration logs back", 22, True,
     lambda s, _p: _config_log_half(s, "config_log_filter_narrows"),
     "config_log_filter_narrows"),
    # The vendor has no word for this: it is our record of whether an operational read answered,
    # not a setting on any screen. Said plainly rather than implied.
    ("Delivery status was collected", 20, True,
     lambda s, _p: _config_log_half(s, "central_store_status_collected"),
     "central_store_status_collected"),
)


#: ELEVEN CLAUSE FIELDS AND ELEVEN HEADINGS, the eleventh being PAN-MGT-011's.
#:
#: `setting_labels` falls back to the raw field name, so declaring a column without a label IS
#: choosing to show a customer a database field name. The tab had ONE settings column and ZERO
#: entries here before this run.
LOGGING_SETTING_LABELS = {
    # PAN-LOG-001. No vendor word for a count of destinations; Help 11.2 p.332 calls them
    # "forwarding destinations" and p.918 "a syslog server". The count is ours.
    "offbox_destination_count": "Off-box log destinations (count)",
    # PAN-LOG-001's calibration column. Help 11.2 p.918: "To select the Syslog Server profile for
    # System, Config, User-ID, HIP Match, and Correlation logs, see Device > Log Settings" - a
    # profile is only an address book until a match list names it, which is what this reads.
    "syslog_destination_in_use": "A forwarding rule names a syslog profile",
    # PAN-LOG-003. The five severities are the log viewer's own grades, not a measured device
    # enum - `log_settings.SYSTEM_LOG_SEVERITIES` says so. "Missing" is the column's own sense:
    # it lists what is NOT covered.
    "system_log_severity_gaps": "System-log severities with no off-box destination",
    # PAN-LOG-004, the AND of the two evidence columns in the subject block above.
    "config_log_fully_offbox": "Every configuration-change log leaves the firewall",
    # PAN-LOG-006 and PAN-LOG-010's applicability clause, drawn ONCE. Help 11.2 p.334 names the
    # pair as the vendor does: "Panorama/Logging Service ... Select Panorama if you want to
    # forward logs to Log Collectors or the Panorama management server or to forward logs to the
    # Logging Service."
    "panorama_managed": "Has a Panorama or Logging Service to send to",
    # PAN-LOG-006. The forwardable set spans the Device > Log Settings kinds and the Log
    # Forwarding profile's log types - `PANORAMA_FORWARDABLE_LOG_TYPES` records which and why
    # `correlation` is not among them.
    "panorama_log_type_gaps": "Log types not forwarded to Panorama or the Logging Service",
    # PAN-LOG-007. THE VENDOR'S OWN LABEL, Help 11.2 p.708 verbatim: "Require Audit Comment on
    # Policies - Requires Audit Comment when creating a new policy rule."
    "require_audit_comment": "Require Audit Comment on Policies",
    # PAN-LOG-008. Help 11.2 p.920 is the Email server profile and p.911 the match list that
    # names one; neither has a word for "a critical-severity System filter names one", so this
    # heading is ours. The control is the one the model's own docstring says no query rests on -
    # see the stage 9 artifact's `disagreed_with_input`.
    "email_alerting_for_critical_system_events": "Critical system events reach an email relay",
    # PAN-LOG-009. THE VENDOR'S OWN WORDS, Help 11.2 p.716 verbatim on this very screen:
    # "Expiration periods and storage quotas for reports and for the following log types." And
    # p.717: "By default, there is no expiration period, which means logs never expire."
    "log_retention_configured": "An expiration period or storage quota is set",
    # PAN-LOG-010. "Central log store" is ours; the vendor's pair is Panorama/Logging Service, as
    # above. This column is true only on positive evidence of a completed forward, so the
    # companion column in the subject block is what tells a No apart from a silence.
    "central_store_delivery_healthy": "Logs are reaching the central store",
    # PAN-MGT-011's, NOT THIS DOMAIN'S CONTROL - labelled anyway, and the call is recorded in the
    # stage 9 artifact. THE VENDOR'S OWN LABEL, Help 11.2 p.720 verbatim: "Enable Log on High DP
    # Load (Firewall only; disabled by default)". The run that owns PAN-MGT-011 inherits this and
    # may replace it; an eleven-column tab with one bare heading is worse than one with eleven
    # labelled, and labelling a column changes nothing about its control.
    "log_on_high_dp_load": "Enable Log on High DP Load",
}


#: PROPOSAL. The tab's description is the SHEET's, and the sheet now carries nine controls rather
#: than one, so the sentence it had - "What the firewall does about logging when the data plane is
#: under load" - describes PAN-MGT-011's single setting and says nothing about off-box
#: destinations, severity coverage, configuration-change logs or retention. Eight of this
#: domain's ten controls report here.
LOGGING_SETTINGS_DESCRIPTION = (
    "Whether this firewall's logs leave it, reach somewhere that keeps them, and cover the "
    "events an investigation needs: how many off-box destinations it defines and whether a "
    "forwarding rule names any of them, which System-log severities no destination covers, "
    "whether every configuration change leaves the box, which log types never reach Panorama or "
    "the Logging Service, whether a policy change must record a reason, whether critical events "
    "reach anybody, whether anything bounds how long logs are kept, and whether delivery to the "
    "central store is actually completing. The syslog and e-mail destinations themselves are a "
    "tab of their own, and a virtual system's Log Forwarding coverage another.")


# ------------------------------------------------------------------------------------------
# Tab 2 - Syslog and Email Destinations (integrations.LogServerTarget)
# ------------------------------------------------------------------------------------------

#: One server entry inside one server profile, in one scope of one appliance - which is the whole
#: of its identity, and every part of it is needed to say which destination a finding is about.
#: `unique(appliance, scope, vsys_name, kind, profile_name, server_name)`.
#:
#: `Kind` IS A CLAUSE FIELD and is here rather than in the settings block, which buys two things.
#: It reads `get_kind_display()`, so the cell says "Syslog" and not the stored key `syslog` -
#: `display_value` never calls a display method and a derived settings column would print the key.
#: And it costs NOTHING for that: a `value_reader` would have been the other way to label it, and
#: a reader makes `build_rows` hand the field `stored=False` to `remediation_accessor`, which
#: never reads its row. A subject column's own lambda is free.
#:
#: `Location` IS THE VENDOR'S OWN WORD for the scope, Help 11.2 p.918 and p.920 verbatim: "Location
#: - Select the scope in which the profile is available. In the context of a firewall that has
#: more than one virtual system (vsys), select a vsys or select Shared (all virtual systems)."
#: `scope_of` folds `scope` and `vsys_name` into the one cell the vendor shows, so the column
#: declares `scope`; `vsys_name` has no clause on it and no column of its own, which is stated
#: here rather than left to be discovered.
#:
#: `Server` AND `Address` ARE THE VENDOR'S WORDS TOO, p.918: the Servers tab's columns are "Name",
#: "Server" ("Enter the IP address or FQDN of the syslog server"), "Transport" and "Port". On the
#: e-mail kind p.920 spells the same column "Email Gateway", so ONE heading covers two vendor
#: words - the model holds one column for both and the heading says the general thing.
def _server_address(obj) -> str:
    return obj.server_address or NONE


LOG_SERVER_TARGET_SUBJECT = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
    ("Location", 12, False,
     lambda s, _p: (s.vsys_name or s.scope) if s.scope == "vsys" else (s.scope or NONE),
     "scope"),
    ("Kind", 10, False, lambda s, _p: s.get_kind_display(), "kind"),
    ("Server profile", 20, False, lambda s, _p: s.profile_name or NONE, "profile_name"),
    ("Server", 20, False, lambda s, _p: s.server_name or NONE, "server_name"),
    ("Address", 20, False, lambda s, _p: _server_address(s), "server_address"),
    # Help 11.2 p.918: "Port - Enter the port number of the syslog server (the standard port for
    # UDP is 514; the standard port for SSL is 6514; for TCP you must specify a port number)." No
    # clause reads it, and it is how a reader tells a TLS destination from a cleartext one at a
    # glance when the transport key is absent.
    ("Port", 8, False, lambda s, _p: findings_sheet.display_value(s.port), "port"),
)

#: TWO derived settings columns: `transport` and `profile_referrer_count`. `kind` is the third
#: clause field and the subject block above presents it, so `setting_columns` skips it.
LOG_SERVER_TARGET_SETTING_LABELS = {
    # THE VENDOR'S OWN WORD AND ITS OWN SENTENCE, Help 11.2 p.918: "Transport - Select whether to
    # transport the syslog messages over UDP, TCP, or SSL. Use SSL to encrypt and secure data
    # sent to a syslog server. Data is sent over UDP or TCP in cleartext and is readable in
    # transit."
    "transport": "Transport",
    # PAN-LOG-002's applicability clause. No vendor word: Help 11.2 p.918 says only "You cannot
    # delete a server profile that the firewall uses in any System or Config log settings or Log
    # Forwarding profile", which is the same relation counted from the other end.
    "profile_referrer_count": "Forwarding rules naming this profile (count)",
}

#: NO `value_readers` ON THIS SHEET, AND `transport` IS THE ONE THAT WAS CONSIDERED AND REFUSED.
#:
#: It is a `CharField` with `choices`, so the labelling rule says a reader is available and would
#: be needed if a label differed from its stored key. Measured against the field's own definition:
#: `Transport.UDP = "UDP", "UDP"` and `Transport.TCP = "TCP", "TCP"` - label and key are the same
#: string - and only `SSL` differs, at `"SSL (TLS)"`. SSL is PAN-LOG-002's `no_finding` placement
#: and its assertion clause is `transport is not SSL`, so no SSL row can ever draw a finding here:
#: the two values reachable on a row of this tab print identically with or without a reader.
#:
#: AND THE READER WOULD COST THE ONE THING THIS CONTROL IS ABOUT. `transport` is a stored key with
#: a real `FieldProvenance` row; a reader makes `build_rows` pass `stored=False` to
#: `remediation_accessor`, which sets `row=None` and walks to `__entry__` - so whether the key was
#: ABSENT or explicitly set to UDP stops reaching the cell. The absent state is exactly what this
#: control reports: the column carries `default=Transport.UDP` precisely so that an unconfigured
#: server does not pass a control about cleartext, and stage 8's own note on the firing row reads
#: "the absent transport key materialises UDP". Refusing the reader keeps that row.
#:
#: THE `(empty)` CASE IS RECORDED AND IS NOT THIS SHEET'S TO FIX. One built row reads `(empty)` in
#: the Transport cell, with the mark on it, where the honest words are "no transport key is set,
#: and the device materialises UDP". That is `display_value`'s three answers, and the cause is a
#: defect in the TEST HARNESS and not in the device reading - see the stage 9 artifact.
LOG_SERVER_TARGET_READERS: dict = {}

#: PROPOSAL. A new tab, so the vendor's two screens decide the sentence - Help 11.2 p.918 and
#: p.920 - and the row is a SERVER ENTRY rather than a profile, because transport is per server:
#: one profile can hold a TLS server and a UDP one, which the model's own docstring records as
#: measured on the lab PA-5220.
LOG_SERVER_TARGET_DESCRIPTION = (
    "Every syslog collector and mail relay this firewall can send logs to, one row per server "
    "entry, and whether that destination is reached in the clear. Transport is per SERVER and not "
    "per profile - one profile can hold a TLS collector and a UDP one - so the row names the "
    "server to change. A profile is only an address book until a Log Settings match list or a Log "
    "Forwarding profile names it, which is what the referrer count says: a cleartext destination "
    "nothing sends to is not a finding.")

#: PROPOSAL, and it fits. Excel caps a sheet name at 31 characters and truncates silently past
#: it; this is 29. "Log Server Target" is the control type's label and is our own coinage, so the
#: tab takes the two vendor screens' own words instead.
LOG_SERVER_TARGET_TITLE = "Syslog and Email Destinations"


# ------------------------------------------------------------------------------------------
# Tab 3 - Virtual System Log Forwarding (integrations.VsysLogForwarding)
# ------------------------------------------------------------------------------------------

def profiles_available_cell(obj) -> str:
    """The Log Forwarding profiles this virtual system can reach, and what each sends off-box.

    `profile_names` is a JSONField with no clause on it, so `setting_columns` derives no column
    for it - and without it a row says "ten log types are not sent off-box" with nothing naming
    the profile to change or saying whether there is one at all. An em dash where the branch does
    not exist: `layout.NONE`, U+2014, which is the state `display_value` cannot express - no
    profile reaches this virtual system, which is not the same observation as a profile reaching
    it and sending nothing.
    """
    rows = obj.profile_names or []
    if not rows:
        return NONE
    lines = []
    for row in rows:
        if not isinstance(row, dict):
            lines.append(str(row))
            continue
        types = row.get("offbox_log_types") or []
        lines.append("%s (%s): %s" % (
            row.get("name") or "(unnamed)", row.get("source") or "?",
            ", ".join(types) if types else "sends nothing off-box"))
    return "\n".join(lines)


#: The appliance, its HA role, the virtual system, and the profiles it can reach.
#:
#: THE VSYS IS THE ROW AND NOT THE PROFILE, which the control type's own docstring states: "the
#: gap this control reports is a vsys with no adequate profile and a profile-keyed row cannot
#: report something that does not exist." `Virtual system` is the vendor's own word - Help 11.2
#: p.918 "a firewall that has more than one virtual system (vsys)".
#:
#: `Profiles available` is EVIDENCE and declares its field, on the same precedent as the three
#: evidence columns on the big tab.
VSYS_LOG_FORWARDING_SUBJECT = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
    ("Virtual system", 14, False, lambda s, _p: s.vsys_name or NONE, "vsys_name"),
    ("Profiles available", 34, True, lambda s, _p: profiles_available_cell(s), "profile_names"),
)

VSYS_LOG_FORWARDING_SETTING_LABELS = {
    # Help 11.2 p.332, the Log Forwarding screen's OWN list, verbatim: "Log Forwarding profiles
    # define forwarding destinations for the following Log Types: Authentication, Data Filtering,
    # GTP, SCTP, Threat, Traffic, Tunnel, URL Filtering, and WildFire Submissions logs." THE
    # VENDOR DISAGREES WITH ITSELF ABOUT THE SIZE OF THIS SET and the disagreement is already on
    # the record in OptivEdgeProbe's `reference/known-vendor-contradictions.md`, found by this
    # domain's stage 1 run: p.332 lists NINE types and the two screens that point at it - p.909
    # `Device > Log Settings` and p.918 `Device > Server Profiles > Syslog` - each list EIGHT,
    # omitting SCTP. The heading below names no count for that reason, and the model measured a
    # TENTH the vendor's list omits entirely (`decryption`) and records that it did. Nothing here
    # ranks the three pointers.
    "offbox_log_type_gaps": "Log types no profile sends off-box",
    # PAN-LOG-005's APPLICABILITY clause, and it suppresses the control when the answer is No.
    # The heading has to say what it is, because a reader meeting "No" needs to know that the row
    # beside it then reports nothing at all.
    "pushed_profile_sources_collected": "Pushed and predefined profiles were collected",
}

#: PROPOSAL. 29 characters, under Excel's 31, and it is the control type's own label because that
#: label is already built from the vendor's two words - "Virtual System" (Help 11.2 p.918) and
#: "Log Forwarding" (Help 11.2 p.332, `Objects > Log Forwarding`).
VSYS_LOG_FORWARDING_TITLE = "Virtual System Log Forwarding"

# ------------------------------------------------------------------------------------------
# The explorer pages, and the ONE place the two-kinds-one-model shape actually bites
# ------------------------------------------------------------------------------------------

#: WHERE THE PER-KIND PROBLEM REALLY IS, measured, because the brief predicted it on the findings
#: tab and the findings tab is not where it lands.
#:
#: Stage 5 declares TWO subjects over `integrations.LogServerTarget` - `syslog-server-target` with
#: ten columns and `email-server-target` with fourteen - discriminated by the `kind` column, and
#: the contract's finding 4 warns that one column can mean two different things on adjacent rows
#: of one tab. On the FINDINGS tab it cannot happen: PAN-LOG-002 is the only control of this type
#: and its SCOPE clause is `kind = "syslog"`, so no e-mail row can ever draw a finding. Measured
#: on built rows: five server entries in the estate, zero of them e-mail, and stage 8's own census
#: records the one e-mail row it held and that the kind clause withholds it.
#:
#: THE EXPLORER PAGE IS THE SURFACE THAT HOLDS BOTH KINDS, because it lists the configuration
#: rather than the findings. So the per-kind branch belongs here, and these four helpers are it.
#: An EM DASH - `layout.NONE`, U+2014 - for a column that does not exist on this kind BY
#: STRUCTURE, which is the state the shared `display_value` cannot say: `transport` carries
#: `default=Transport.UDP` and therefore reads "UDP" on an e-mail relay that has no transport at
#: all, and `protocol`/`tls_version`/`auth_method` are blank on every syslog server for the same
#: kind of reason in reverse. A cell reading "UDP" against a mail relay is not merely untidy - it
#: is the exact false reading the model's own docstring says a control without the kind clause
#: would make about the whole estate.
def transport_cell(target) -> str:
    """The transport, or an em dash on the kind that has none."""
    from optivedge_integrations.integrations.models import LogServerTarget

    if target.kind != LogServerTarget.Kind.SYSLOG:
        return NONE
    # `get_transport_display()` and not the stored key: `SSL` is labelled "SSL (TLS)", which is
    # the one of the three where they differ, and SSL is the only value that encrypts.
    return target.get_transport_display() if target.transport else "(no transport key)"


def protocol_cell(target) -> str:
    """The mail relay's protocol, or an em dash on the kind that has none."""
    from optivedge_integrations.integrations.models import LogServerTarget

    if target.kind != LogServerTarget.Kind.EMAIL:
        return NONE
    return target.get_protocol_display() if target.protocol else "(no protocol key)"


def email_only_cell(target, attribute) -> str:
    """A column that exists on the e-mail kind alone, or an em dash."""
    from optivedge_integrations.integrations.models import LogServerTarget

    if target.kind != LogServerTarget.Kind.EMAIL:
        return NONE
    value = getattr(target, attribute)
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value) if value else "(not set)"


def location_cell(target) -> str:
    """The vendor's `Location`: the vsys where the scope is vsys, else the scope's own name.

    Help 11.2 p.918 and p.920 both spell it "Location - Select the scope in which the profile is
    available ... select a vsys or select Shared (all virtual systems)."
    """
    if target.scope == "vsys":
        return target.vsys_name or target.scope
    return target.scope or NONE


#: The explorer page's headings for the `LogServerTarget` columns that are the e-mail kind's
#: alone. Every heading that also heads a findings column is the SAME WORD, character for
#: character - `LOG_SERVER_TARGET_SETTING_LABELS` and `LOG_SERVER_TARGET_SUBJECT` above hold
#: those - so one column cannot read two ways on two surfaces.
#:
#: All four are the vendor's own words from Help 11.2 p.920, `Device > Server Profiles > Email`,
#: except `transport_grade`, which is OURS: the vendor keeps protocol and TLS version in two
#: fields and a severity grading has to place values of ONE column, so the model folds the pair
#: and this heading names the fold. And note the vendor's own typo, recorded in the model: the
#: Email grid's column header reads "TLS VESRION".
EMAIL_ONLY_LABELS = {
    "protocol": "Protocol",
    "tls_version": "TLS Version",
    "auth_method": "Authentication Method",
    "meets_authenticated_tls": "Authenticated and encrypted",
    "transport_grade": "Protocol and version, graded",
}

#: PROPOSAL.
VSYS_LOG_FORWARDING_DESCRIPTION = (
    "Which dataplane log types each virtual system can get off the box at all, taken over every "
    "Log Forwarding profile available to it - its own, the ones Panorama pushes, and the "
    "vendor's predefined one. A profile that exists but names no destination contributes no "
    "coverage, so the row reports the log types that reach nowhere rather than the profiles that "
    "exist. Where the pushed and predefined reads did not answer, the row says so and the "
    "assertion is withheld rather than guessed.")
