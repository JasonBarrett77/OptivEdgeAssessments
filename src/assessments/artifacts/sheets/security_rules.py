"""Engineer-detail xlsx, prototype: the security-policy controls. PAN-POL-004 today.

The first NAMED-OBJECT findings sheet, and the first whose subject is not an appliance. Jason,
2026-09-17: "one row per subject finding, or per finding, except where multiple findings exist per
subject ... Later, we can implement a collapse function that collapses by provenance + subject, and
then lists the targets. Let's build the per target+subject view first." So: one row per finding.

WHAT A RULE NEEDS THAT A DEVICE SETTING DID NOT.
- ITS OWN SUBJECT COLUMNS. A rule is identified by its name and where it sits - the vsys and the
  rulebase - and read by what it does: its action and its service. Those four are columns, not
  lines inside a tested-value cell, because they are what an engineer scans a policy sheet for.
- NO APPLIANCE. A rule belongs to a vsys, which on an HA pair spans both firewalls, so there is
  no one appliance to name or to link to. The Firewalls column lists the pair, from the same
  topology the Appliances tab reports.
- A VALUE HELD ON RELATED ROWS. `service` is not a column: a rule's services are
  `SecurityRuleService` rows. `SERVICE_READER` reads them, for the Service column and for any
  control that tests the field without this sheet presenting it.
- ONE SOURCE, FOR THE RULE. A rule is pushed as a unit and an override replaces all of an
  object's values, so "where did this come from" has one answer per rule - the Device group
  column, blank where the rule is the firewall's own. The exception is the Notes column.

WHAT IT SHOWS ABOUT THE RULE ITSELF, from 2026-11-01. The hand-named columns above are what an
engineer SCANS; the eighteen derived setting columns after them are what the PAN-POL controls
actually assert on - the port count, the logging pair, the duplicate verdict and the check behind
it, the hit-count age and whether it can be believed, the schedule pair, the two site-inspection
columns, the description and the open-zone count. They are derived from the controls' own clauses,
so a control added to the catalogue brings its column with it; only the HEADINGS are typed, in
`SETTING_LABELS`, and every one of those is a proposal.

WHAT IS NOT HERE YET. The collapse by provenance + subject Jason described: 205 of this run's 390
findings are rules, and most are one device group's pushed rules repeated per vsys. This sheet is
the per target+subject view that collapse would fold.
"""
from __future__ import annotations

from assessments.models import Control

from . import findings as findings_sheet
from . import profile_kinds
from optivedge_integrations.integrations.presentation import address_breadth_label

from ..layout import NONE, SheetInfo, appliance_names

def joined(rows, attribute="value") -> str:
    """Member values in CONFIGURED order, ONE PER LINE - the order PAN-OS shows them in.

    A line each rather than a comma list (Jason, 2026-09-18): a rule names objects whose own names
    contain hyphens and read as phrases, and a wrapped comma list makes the boundary between two
    of them a guess.

    "(empty)" rather than a blank cell: a rule with no member of a kind is a real state, and on a
    security rule it is usually `any` written another way.
    """
    return "\n".join(str(getattr(row, attribute)) for row in rows) or "(empty)"


def with_breadth(members: str, num_hosts) -> str:
    """Member names, then how much address space they come to - PAN-POL-002's subject.

    In this cell rather than a column of its own because the names and their size are one fact:
    a list of names says nothing about how much space it covers, and one name can be a /8. The
    same line appears on the configuration explorer's rule rows, from the same helper.

    On a NEGATED side the number is the size of the complement, so it is deliberately the one
    line here that does not describe the names above it. That is what the rule permits, and
    `raw_value` keeps the "NOT" implicit in the control's own Fires when cell.
    """
    return f"{members}\n{address_breadth_label(num_hosts)}"


#: What a rule's protection RESOLVES to, which is not what it names. The group name alone is
#: misleading in exactly the case PAN-POL-008 exists for: the lab's `default` group names no
#: profiles, so 113 rules read "default" here and inspect nothing. Both halves are shown - what
#: the rule names, and what is in force after resolving it.
PROFILE_TYPE_LABELS = (
    ("has_antivirus_profile", "antivirus"),
    ("has_spyware_profile", "anti-spyware"),
    ("has_vulnerability_profile", "vulnerability"),
)


def profiles_in_force(rule, verdict_fields=None) -> str:
    """What the rule NAMES, what is actually in force, and what WildFire analysis amounts to.

    The WildFire line is here rather than in a column of its own because the value is the
    same kind of fact as the "in force" line below it - what the named profiles resolve to -
    and because PAN-AVW-003 needs it shown somewhere. `hidden_fields` records that this
    column is where it shows.
    """
    named = [g.value for g in rule.securityruleprofilegroups.all()]
    direct = [f"{p.profile_type}: {p.value}" for p in rule.securityruleprofiles.all()]
    in_force = [label for column, label in PROFILE_TYPE_LABELS if getattr(rule, column, False)]
    lines = []
    if named:
        lines.append("group " + ", ".join(named))
    lines.extend(direct)
    if not lines:
        lines.append("(none named)")
    lines.append("in force: " + (", ".join(in_force) if in_force else "NONE"))
    if rule.wildfire_analysis_submits_all is True:
        lines.append("WildFire analysis: all file types")
    elif rule.wildfire_analysis_detail:
        lines.append(f"WildFire analysis: {rule.wildfire_analysis_detail}")
    else:
        lines.append("WildFire analysis: not yet computed - re-normalize")
    lines.extend(threat_profile_lines(rule, verdict_fields))
    return "\n".join(lines)


#: The nine per-rule threat-profile assertions, with the words that read on a row. Only the
#: FAILING ones are printed: nine satisfied lines on every healthy rule would bury the one line
#: that matters, and the finding itself already names which control fired.
THREAT_VERDICT_LABELS = (
    ("antivirus_blocks_malware", "antivirus malware"),
    ("antivirus_inline_ml_blocks", "antivirus inline ML"),
    ("spyware_blocks_critical_high", "anti-spyware severity"),
    ("spyware_dns_sinkholes", "DNS sinkhole"),
    ("spyware_dns_categories_enforced", "DNS Security categories"),
    ("spyware_inline_analysis_blocks", "anti-spyware inline analysis"),
    ("spyware_exceptions_minimal", "anti-spyware exceptions"),
    ("vulnerability_blocks_critical_high", "vulnerability severity"),
    ("vulnerability_blocks_brute_force", "brute-force source"),
    ("vulnerability_inline_analysis_blocks", "vulnerability inline analysis"),
    ("vulnerability_exceptions_minimal", "vulnerability exceptions"),
    # PAN-VLN-003's FIRST HALF and the twelfth assertion. It was added to the model's
    # `VULNERABILITY_ASSERTIONS` tuple - which is where each per-kind sheet takes its
    # `hidden_fields` from - before any control queried it, so it was DECLARED presented and
    # printed nowhere. A label is what makes that declaration true.
    ("vulnerability_inline_analysis_enabled", "vulnerability real-time analysis"),
)


def threat_profile_lines(rule, fields=None) -> list[str]:
    """One line per FAILING threat-profile assertion, naming the profile and the reason.

    These nine fields are listed in `hidden_fields`, which is a statement that another column
    already says them - so they are rendered here, in the cell that carries what the named
    profiles resolve to. Printing them nowhere while declaring them presented would make that
    declaration false.

    A None verdict PRINTS, because it is a finding: no profile of that kind reaches the rule, so
    the rule gets none of that inspection (Jason, 2026-10-12). The "in force" line above says
    which kinds are present; this says what each absence costs, per control.

    `fields` narrows it to one kind's assertions, for the per-kind views: on the anti-spyware
    sheet a vulnerability gap is another sheet's subject, and printing it there is the noise
    those views exist to remove.
    """
    wanted = set(fields) if fields else None
    # NOBODY LOOKED IS NOT THE SAME AS NOT SATISFIED, and without this line it reads as it.
    # A verdict row is written for EVERY assertion including the no-profile case, so the absence
    # of every row means the coverage pass has not run over this rule - which is the one state
    # `SecurityRule.vulnerability_verdict_written` is False in, and the state the four PAN-VLN
    # controls' coverage companion query fires on. The per-assertion lines below would otherwise
    # print "not satisfied" for each, which a reader takes as a configuration gap and which the
    # customer cannot clear.
    #
    # Only the satellite-backed labels are consulted: the WildFire view's two fields are COLUMNS
    # on the rule and have no verdict row to be missing.
    satellite = [field for field, _label in THREAT_VERDICT_LABELS
                 if wanted is None or field in wanted]
    if satellite and all(rule.profile_verdict(field) is None for field in satellite):
        return ["assessment has not run for this rule - no verdict recorded for any assertion"]
    lines = []
    for field, label in THREAT_VERDICT_LABELS:
        if wanted is not None and field not in wanted:
            continue
        # `is True` passes; both False and None are findings since 2026-10-12, so both print.
        if getattr(rule, field, None) is True:
            continue
        detail = getattr(rule, f"{field}_detail", "")
        text = detail or "not satisfied"
        # THE GRADED VALUE, WHERE THE ASSERTION HAS ONE, because a calibration query clauses on
        # it and `hidden_fields` then declares it presented - and for one axis no cell carried
        # it. `spyware_worst_engine_action` is the case that forced this: the detail beside it
        # names the DETECTORS that do not block and never says whether they sit at `allow` or
        # `alert`, which is the whole difference between PAN-SPY-004 at high and at medium. The
        # other axes' details do happen to state their value - the severity detail leads with
        # the worst un-stopped band, the DNS one names the action - so this makes two
        # declarations explicit and the third one true. Read off the verdict row rather than a
        # per-axis property, so a tenth graded assertion needs nothing here.
        verdict_row = rule.profile_verdict(field)
        graded = (verdict_row.grading_value if verdict_row else "") or ""
        if graded:
            text = f"{text} (graded {graded})"
        lines.append(f"{label}: {text}")
    return lines


#: PROPOSED HEADINGS for the eighteen derived setting columns this sheet gained on 2026-11-01,
#: when the fifteen PAN-POL controls' tested fields outgrew the columns the sheet was built with.
#: EVERY ONE OF THESE IS A PROPOSAL AND NONE IS A DECISION. A heading is what a customer reads,
#: so changing one is an edit here and not a rebuild: the column set is derived from the controls'
#: clauses and only the words are typed. Without an entry a column keeps its raw field name -
#: `url_inspection_posture`, `days_since_last_hit` - which is what 23 of the other findings tabs
#: live with and what this map exists to avoid.
#:
#: Each line says which control the column is for, because that is the question a reader of the
#: heading will have.
SETTING_LABELS = {
    # PAN-POL-003. "Ports" rather than "Port count": the cell holds a number and the heading does
    # not need to say so. `(none)` here is NOT zero - see `hidden_fields` below.
    "permitted_port_count": "Ports permitted",
    # PAN-POL-006. Both halves are columns: the boolean is what the control asserts and the
    # characteristic is the axis its severity varies with, and neither states the other.
    "permits_high_risk_application": "Permits a high-risk application",
    "high_risk_application_characteristic": "High-risk characteristic",
    # PAN-POL-009. The vendor's own two words for the key, not `log_end`: the Actions tab of a
    # rule calls the checkbox "Log at Session End".
    "log_end": "Log at session end",
    # PAN-POL-009's second half. "Profile" rather than "Setting", because the value is the name of
    # a log-forwarding profile and `(empty)` means the records stay on the firewall.
    "log_setting": "Log forwarding profile",
    # PAN-POL-012. The verdict, then whether the comparison behind it ran at all - which is the
    # only thing separating "no duplicate" from "nobody compared".
    "has_exact_duplicate": "Duplicate of another rule",
    "duplicate_comparison_computed": "Duplicate check ran",
    # PAN-POL-013. Named for what it counts rather than for the column, so a reader does not have
    # to know that a hit is a match against this rule.
    "days_since_last_hit": "Days since last hit",
    # PAN-POL-013 and PAN-POL-015. "Believable" rather than "Known": the reading SUCCEEDS on an
    # appliance that is not counting and returns a zero indistinguishable from a real one, so what
    # this column says is whether the number beside it can be trusted.
    "hit_count_reading_known": "Hit count believable",
    # PAN-POL-015.
    "busy_rule_placed_late": "Busy rule placed late",
    # PAN-POL-020. Two columns again: the boolean fires the control and the posture chooses the
    # band, and the posture's middle state - a profile is bound and the rule excuses a category -
    # is invisible in the boolean.
    "has_url_filtering_profile": "URL filtering in force",
    "url_inspection_posture": "Site inspection posture",
    # PAN-POL-021. The vendor's own field name, and the one word a reader will look for.
    "description": "Description",
    # PAN-POL-022. "Kind" rather than "Type", which is PAN-OS's own word for the recurrence
    # branch; `(empty)` means nothing parsed the schedule rather than that there is none.
    "schedule_kind": "Schedule kind",
    "schedule_window_expired": "Schedule window expired",
    # PAN-POL-024. A count of two, so the heading says which two things are being counted.
    "open_zone_side_count": "Zone sides left open",
    # PAN-POL-008. A count of three, named for what IS there rather than what is missing, so
    # that 3 is the healthy answer and 0 is the finding - the same direction as every other
    # column on this tab.
    "threat_profile_kinds_in_force": "Inspection kinds in force",
    # PAN-POL-003's companion. "Established" rather than "Known", because what it answers is
    # whether the count beside it exists at all - and it is the only cell that tells that
    # column's `(none)` apart from a count of nothing.
    "permitted_port_count_known": "Port count established",
}


PROFILES_READER = findings_sheet.ValueReader(
    read=profiles_in_force,
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)


#: Zones live on their own rows too, like services. PAN-POL-024 tests `from_zone` and
#: `to_zone`, and until it was built this sheet had no zone column at all - a finding about a
#: rule's zones with nowhere to show them. The configuration explorer's rule table has carried
#: Source Zone and Destination Zone from the start; this now matches it.
FROM_ZONES_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.securityrulefromzones.all()),
)
TO_ZONES_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.securityruletozones.all()),
)

#: A rule's services live on `SecurityRuleService` rows, in configured order.
SERVICE_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.securityruleservices.all()),
)

#: None of these carries a `provenance` line: a rule member records a raw marker string of its own
#: rather than a `FieldProvenance` row, and this tab shows the rule's single source instead - a
#: rule is pushed as a unit. The readers exist so a control testing one of these fields finds its
#: value.
#:
#: Addresses are REFERENCES: `raw_value` is what the rule names - an object, a group, `any` - which
#: is what an engineer reads in the UI and searches the configuration for. What each reference
#: resolves to is a question for the objects domain, not for this cell.
SOURCES_READER = findings_sheet.ValueReader(
    read=lambda rule: with_breadth(
        joined(rule.source_address_refs.all(), "raw_value"), rule.source_num_hosts),
)
DESTINATIONS_READER = findings_sheet.ValueReader(
    read=lambda rule: with_breadth(
        joined(rule.destination_address_refs.all(), "raw_value"), rule.destination_num_hosts),
)
APPLICATIONS_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.securityruleapplications.all()),
)


def firewalls(rule) -> str:
    """The appliances that enforce this rule's vsys, one per line - the enforcement point's OWNER,
    which the model guarantees is exactly one of an appliance group or an appliance."""
    point = rule.enforcement_point
    return appliance_names(point.appliance_group or point.appliance)


def enforcement_point_label(rule) -> str:
    """"fw-core-tpa-a+fw-core-tpa-b/vsys1" - the vsys AND the firewalls that run it.

    A vsys name is unique only per firewall (Jason, 2026-09-18): pan-fw-111 vsys1 and the tpa
    pair's vsys1 are different entities, so a list of bare vsys names across firewalls says
    nothing about which is which. On an HA pair both members run the same vsys, and both are
    named.
    """
    return f"{firewalls(rule).replace(chr(10), '+')}/{rule.enforcement_point.vsys_name}"


def device_group(rule, provenance_of) -> str:
    """The device group that pushed the RULE, or blank where it is the firewall's own.

    A rule is pushed as a unit and an override replaces all of an object's values, so this is one
    answer for the whole rule rather than one per tested field. Blank means local: the Rulebase
    column says so in the same breath, and a word here would only repeat it. The exception - a
    field recording a different source - is what the Notes column is for.
    """
    row = provenance_of("__entry__")
    if row is None:
        return "Not recorded"
    return row.raw_value if row.provenance_type == "device_group" else ""


def field_source_notes(rule, provenance_of, fields) -> str:
    """The exception to "one rule, one source", and nothing when there is none.

    Where a field records a source different from the rule's own - another device group, or a
    template - the Provenance cell alone would be wrong for that field, so it is written out here.
    """
    entry = provenance_of("__entry__")
    entry_key = (entry.provenance_type, entry.raw_value) if entry is not None else None
    notes = []
    for field, stored in fields:
        row = provenance_of(field) if stored else None
        if row is None:
            continue
        if (row.provenance_type, row.raw_value) != entry_key:
            source = row.raw_value or row.get_provenance_type_display()
            notes.append(f"{field} came from {source}")
    return "\n".join(notes)


def rulebase(rule) -> str:
    """"Pre-Rulebase", not "Pushed Pre-Rulebase": the Device group column beside it already says
    what pushed it, so the vendor label's prefix is a second answer to a question nobody asked."""
    return rule.get_config_source_display().removeprefix("Pushed ")


#: What an engineer scans a policy sheet for, left to right (Jason, 2026-09-17): the rule, who
#: enforces it, where it lives, who pushed it, and what it does. `hidden_fields` keeps the same
#: fields out of the tested-value cells; the derived setting columns after them carry what the
#: controls assert on, in `SETTING_LABELS`' proposed words.
SUBJECT_COLUMNS = (
    # Where it is enforced, then which rule, then what it matches and does.
    ("Firewalls", 16, True, lambda rule, _p: firewalls(rule)),
    ("Vsys", 10, False, lambda rule, _p: rule.enforcement_point.vsys_name or NONE),
    ("Device group", 26, False, device_group),
    ("Rulebase", 16, False, lambda rule, _p: rulebase(rule)),
    ("Rule name", None, False, lambda rule, _p: rule.name or NONE),
    # Each zone before its own address side, the order both the rules page and the
    # configuration explorer use.
    ("Source zone", 14, True, lambda rule, _p: FROM_ZONES_READER.read(rule), "from_zone"),
    # Width None: sized to the longest LINE on the sheet, so no object name wraps and the list
    # reads as one name per line rather than a paragraph (Jason, 2026-09-18).
    ("Sources", None, True, lambda rule, _p: SOURCES_READER.read(rule), "source_address"),
    ("Destination zone", 14, True, lambda rule, _p: TO_ZONES_READER.read(rule), "to_zone"),
    ("Destinations", None, True, lambda rule, _p: DESTINATIONS_READER.read(rule),
     "destination_address"),
    ("Service", 24, True, lambda rule, _p: SERVICE_READER.read(rule), "service"),
    ("Application", 24, True, lambda rule, _p: APPLICATIONS_READER.read(rule), "application"),
    ("Action", 10, False, lambda rule, _p: rule.action or NONE, "action"),
    ("Profiles", 26, True, lambda rule, _p: profiles_in_force(rule), "has_antivirus_profile"),
)

SOURCE_COLUMNS = (
    ("Notes", 30, True, field_source_notes),
)

SPEC = findings_sheet.DeviceSettingSheet(
    title="Security Rules",
    #: The eleven controls about security profiles have their own per-kind views since
    #: 2026-10-12, so they are excluded here rather than reported twice. The PAN-POL controls
    #: stay, which is what this sheet has always been about: the rule itself rather than what
    #: inspects it. The list lives in `profile_kinds`, which neither sheet owns, because
    #: `profile_rules` builds its specs from this module's columns.
    exclude_control_ids=profile_kinds.EVERY_PROFILE_CONTROL,
    #: DERIVED AGAIN FROM 2026-11-01. This sheet named its settings itself - Sources, Service,
    #: Action - and set this False in September, when PAN-POL-004 was its only control and every
    #: field it tested had a column of its own. Fifteen PAN-POL controls reach it now and between
    #: them they clause on EIGHTEEN fields no column showed, which
    #: `check_every_tested_field_is_presented` raised on one at a time. All eighteen get a
    #: column here, derived, and none of them is in `hidden_fields` - see that tuple for why
    #: the two obvious candidates came back out.
    #: The hand-named columns above are unchanged and still lead the row - `setting_columns`
    #: skips any field a subject column already declares.
    auto_setting_columns=True,
    #: Proposals, every one of them - see `SETTING_LABELS`. A field with no entry would keep its
    #: raw name as its heading, and all eighteen have one.
    setting_labels=SETTING_LABELS,
    control_types=(Control.ControlType.SECURITY_RULE,),
    subject_columns=SUBJECT_COLUMNS,
    source_columns=SOURCE_COLUMNS,
    value_readers={
        "has_antivirus_profile": PROFILES_READER,
        "has_spyware_profile": PROFILES_READER,
        "has_vulnerability_profile": PROFILES_READER,
        "from_zone": FROM_ZONES_READER,
        "to_zone": TO_ZONES_READER,
        "service": SERVICE_READER,
        "source_address": SOURCES_READER,
        "destination_address": DESTINATIONS_READER,
        "application": APPLICATIONS_READER,
    },
    #: BACK FROM 2026-11-01, for the reason this line used to give for dropping it: it was ()
    #: while every field PAN-POL-004 tested had a column of its own, so the block printed nothing
    #: the sheet did not already say. Eighteen derived setting columns later it says one thing the
    #: sheet cannot otherwise:
    #:
    #: `Fires when` is the FAILING CONDITION, and without it two rules that look identical in
    #: every cell report differently - PAN-POL-002 and PAN-POL-014 split the same breadth reading
    #: at an exclusive threshold, and PAN-POL-004's and PAN-POL-005's `disabled equals false`
    #: applicability is a clause the row otherwise cannot explain.
    #:
    #: `Provenance` IS NOT TAKEN, and it was for an afternoon. Two reasons, the second measured:
    #:
    #: This sheet's own argument, at the top of this module - "ONE SOURCE, FOR THE RULE. A rule is
    #: pushed as a unit and an override replaces all of an object's values, so 'where did this
    #: come from' has one answer per rule - the Device group column". A per-FIELD provenance block
    #: repeats that column on every row that has an answer.
    #:
    #: AND ON TEN OF TWENTY-FOUR ROWS IT HAS NO ANSWER AT ALL. `build_rows` joins the provenance
    #: of the SHOWN fields - the tested fields not in `hidden_fields` - and every field PAN-POL-002
    #: and PAN-POL-014 assert on is hidden, so the cell rendered EMPTY on all ten of their rows.
    #: A blank cell where the honest value is "the rule was pushed as a unit, see Device group" is
    #: the first of the three failures this stage exists for, in the same shape.
    #:
    #: The data is not lost: the live findings pages pass `ALL_TESTED_COLUMNS`, so the Provenance
    #: column is on the page either way, and `test_a_surface_can_ask_for_provenance_the_workbook_
    #: tab_omits` holds that distinction as a claim about this very spec.
    tested_columns=("Fires when (failing condition)",),
    #: NAMING THE COLUMN, NOT JUST THE FIELD, FROM 2026-11-03 (Jason's call). Each entry says
    #: which cell on this sheet carries the fact, which is what lets `build_rows` mark the value
    #: at fault on a row whose every asserted field is hidden. PAN-POL-002 and PAN-POL-014 marked
    #: NOTHING on any of their 267 rows until this was written - every field they assert on is
    #: here - and the four by-rule sheets inherit this map, which is twelve more controls over
    #: 12,398 rows. The headings are the ones in `SUBJECT_COLUMNS` above and have to match
    #: exactly; `Device group` is not one of them, because the column that reads `config_source`
    #: is `Rulebase`.
    hidden_fields={"config_source": "Rulebase", "action": "Action", "service": "Service",
                   "source_address": "Sources", "destination_address": "Destinations",
                   "application": "Application",
                   # PAN-POL-002. The Sources and Destinations columns carry both the members and
                   # the side's host count, so a column per breadth field would repeat them -
                   # and `*_breadth_known` is the same fact as the count being Unknown. Each is
                   # mapped to the side it belongs to, so a breadth finding marks the side at
                   # fault rather than both.
                   "source_num_hosts": "Sources", "destination_num_hosts": "Destinations",
                   "source_breadth_known": "Sources",
                   "destination_breadth_known": "Destinations",
                   # PAN-AVW-003. The Profiles column already carries what the rule names and
                   # what is in force; the WildFire verdict and its reason are two more lines
                   # in that cell, because they are the same kind of fact - what the named
                   # profiles actually resolve to. A column of its own would also break this
                   # sheet's agreement with the rules page's column set.
                   "wildfire_analysis_submits_all": "Profiles",
                   "wildfire_analysis_detail": "Profiles",
                   # PAN-SPY-001..005 and PAN-VLN-001..004, converted from profile-based to
                   # rule-based 2026-10-12. Same reasoning as the WildFire pair above: each is
                   # a fact about what the named profiles resolve to, so the Profiles column
                   # carries them as further lines in that cell rather than nine columns the
                   # rules page would then have to match. `threat_profile_lines` renders them.
                   "spyware_blocks_critical_high": "Profiles",
                   "spyware_dns_sinkholes": "Profiles",
                   "spyware_dns_categories_enforced": "Profiles",
                   "spyware_inline_analysis_blocks": "Profiles",
                   "spyware_exceptions_minimal": "Profiles",
                   "vulnerability_blocks_critical_high": "Profiles",
                   "vulnerability_blocks_brute_force": "Profiles",
                   "vulnerability_inline_analysis_blocks": "Profiles",
                   "vulnerability_exceptions_minimal": "Profiles",
                   # PAN-AVW-001 and PAN-AVW-002, converted the same day and for the same
                   # reason. The antivirus profile's four ways of letting malware through, and
                   # its inline ML models, are facts about what the named profile resolves to.
                   "antivirus_blocks_malware": "Profiles",
                   "antivirus_inline_ml_blocks": "Profiles",
                   # A SCOPE condition rather than an observation, and the Fires when cell is
                   # what states it - which is why `tested_columns` is no longer ().
                   #
                   # THE SECOND HALF OF THIS COMMENT WAS FALSE AND IS CORRECTED, 2026-11-01. It
                   # said "every row on this sheet is an enabled rule by construction", which
                   # PAN-POL-014 has not been true of since it was built: its baseline asserts
                   # `disabled equals true` - a switched-off permissive rule is its whole
                   # subject - so disabled and enabled rules sit on this tab side by side,
                   # reported by different controls, and with `tested_columns=()` NOTHING on the
                   # row said which was which. That is the third failure this stage exists for,
                   # verbatim: "a derived scoping clause the row did not explain, so two
                   # identical-looking rows reported differently". `Fires when` now reads
                   # `disabled = Yes` on a PAN-POL-014 row and `disabled = No` on a PAN-POL-002
                   # one, which says it indirectly. A column of its own would say it directly,
                   # and that is a PROPOSAL in this run's handback rather than a change made
                   # here - a cell a customer reads is Jason's to decide.
                   #
                   # MAPPED TO "" DELIBERATELY: no subject or settings column on this sheet reads
                   # `disabled`, so there is no cell for a mark to land on, and `Fires when` is a
                   # tested column rather than one of the two blocks the fill walks. PAN-POL-014
                   # marks its other asserted field - `source_num_hosts`, on Sources - so the row
                   # does name a value at fault; this entry says the applicability clause is not
                   # one, rather than leaving the reader to wonder which cell was meant.
                   "disabled": "",
                   # The Profiles column declares has_antivirus_profile and renders all three
                   # on its "in force" line, so a column each would repeat it.
                   "has_spyware_profile": "Profiles",
                   "has_vulnerability_profile": "Profiles",
                   # NOTHING WAS ADDED TO THIS LIST ON 2026-11-01, AND TWO FIELDS WERE TAKEN
                   # OUT OF IT AGAIN BEFORE THIS WAS SHIPPED. `threat_profile_kinds_in_force`
                   # and `permitted_port_count_known` were here for a day: the first because the
                   # Profiles column's "in force:" line names exactly the three kinds it counts
                   # (set in the same loop, from the same three booleans), the second because
                   # the field is a PROPERTY returning `permitted_port_count is not None`, so
                   # that column's own `(none)` IS this value. Both statements are true.
                   #
                   # THEY CAME OUT BECAUSE A HIDDEN FIELD CANNOT BE MARKED, measured on rendered
                   # rows. `build_rows` computes the value-at-fault fill by walking the subject
                   # and settings columns and matching their declared `field` against the
                   # matched queries' `asserted_fields`; `hidden_fields` records that something
                   # else says the fact but not WHICH column, so there is no cell to mark. With
                   # those two hidden, the PAN-POL-008 row and the PAN-POL-003 row whose matched
                   # query is "The open-port count could not be established" rendered with NO
                   # marked cell at all - a finished-looking row with nothing indicated as the
                   # thing to fix. Each now has a column, and each is marked.
                   #
                   # THAT IS NO LONGER THE ONLY WAY OUT, from 2026-11-03: a hidden field that
                   # names its carrying column is marked on that column, so the choice between a
                   # column of its own and a cell a reader cannot find is gone. The two fields
                   # above keep their own columns, because what was argued about them was whether
                   # a customer should read the value and not just where the mark lands.
                   },
    #: A rule belongs to a vsys, not to one appliance: nothing to link to on the Appliances tab.
    appliance_of=lambda rule: None,
    subject_select_related=("enforcement_point__appliance_group", "enforcement_point__appliance"),
    #: The service members every row reads, and the HA pair the Firewalls column lists.
    subject_prefetch=("securityruleprofilegroups", "securityruleprofiles",
                      "securityrulefromzones", "securityruletozones",
                      "securityruleservices", "securityruleapplications",
                      "source_address_refs", "destination_address_refs",
                      "enforcement_point__appliance_group__appliances",
                      # Every threat-profile property (`antivirus_blocks_malware` and its
                      # twenty-one siblings) walks this set, so without it each one is a query:
                      # 134k on the lab across the five rule tabs, 58 of the build's 61s.
                      "profile_verdicts"),
    description=("The security policy each firewall enforces: what the rules allow, how tightly "
                 "they are scoped, and where each rule comes from."),
)


def write_sheet(build) -> SheetInfo:
    return findings_sheet.write_sheet(build, SPEC)
