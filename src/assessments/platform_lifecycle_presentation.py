"""How the three platform-lifecycle tabs read: the cells whose wording is a judgment.

Written by the stage 9 run of OptivEdgeProbe's `platform-lifecycle` domain, 2026-11-02, for
PAN-PLT-002, PAN-PLT-004 and PAN-PLT-006 over three models - the appliance's installed content
streams, a verdict over its whole license table, and its log-database alarm mechanism. All
three are device-wide singletons with no entry name and no vsys, so a row IS one firewall.

THE DOMAIN'S OTHER THREE CONTROLS GET NOTHING HERE, and that is the correct state rather than an
omission: PAN-PLT-001, -003 and -005 are discharged `engineer_answers` by stage 5, so they
compile no query, have no catalog entry, write no finding and are owed no tab.

EVERY HEADING AND EVERY WORD BELOW IS A PROPOSAL. Report content is Jason's and he takes the
heading pass once across many domains rather than per domain (P399), so these are written to be
argued with, and the ones that are not merely cosmetic say why in their own comment.

FIVE COLUMNS HERE ARE `CharField`s WITH `choices` AND EVERY ONE OF THEM NEEDED A READER. The
cell is `read_value` -> `getattr` -> `display_value`, whose value branch ends in `str(value)`,
and `get_<field>_display()` is called NOWHERE in the sheets layer - so a `choices` field prints
the STORED KEY. Without the readers below a customer would have read `stream_never_installed`
under a heading about content currency, `absent_from_inventory` under one about a support
entitlement, and `on_with_thresholds_no_route` under one about alarms. Four of the five are
clause fields and reach the cell through `value_readers`; the fifth,
`LicenceInventory.licence_inventory_read`, is a hand-declared subject column and does its own
call. ALL FOUR CLAUSE FIELDS ARE IN THEIR MODEL'S `DERIVED_FIELDS`, so the readers cost nothing:
`build_rows` hands a reader field `stored=False` to `remediation_accessor`, which discards that
field's own `FieldProvenance` row - and these four have none to discard, measured at 0 rows on
`FirewallContentStreams` and `LicenceInventory` and 16 rows on `LogAlarmSettings` that belong to
four OTHER fields.

AND THE OTHER HALF OF THAT RULE IS WHY THE THREE NULLABLE BOOLEANS BELOW DO NOT GET ONE.
`get_<field>_display()` exists only on a field declaring `choices`; on
`LogAlarmSettings.alarm_generation_enabled` (`choices=None`) the call would raise
`AttributeError` at TEMPLATE RENDER - past `django check` and past all three cross-domain gates.
They are rendered by an explicit three-way branch instead.

THREE THINGS `display_value` CANNOT SAY ON THESE MODELS, each wrong in the reassuring direction:

  - `0` IS A CONTENT VERSION THAT WAS NEVER INSTALLED, NOT A LOW VERSION NUMBER. Every version
    column here is TEXT and the appliance spells "never installed" as `0` - except the URL
    filtering stream, which spells the same state `0000.00.00.000`. `str(value)` prints either
    one, and a customer reading `0` under a heading about antivirus content has been told a
    version number. `FirewallContentStreams.NEVER_INSTALLED_VERSIONS` holds both literals and
    these readers consult it rather than hard-coding them.

  - A BLANK RELEASE DATE ASSERTS THAT THE REPLY CARRIED NO DATE FOR THE STREAM, and must never
    be read as the stream being absent: on both PA-5220s "no date reported" is true while
    "content installed" is also true. `(empty)` says neither thing, so the cells say the first.

  - A NULL ALARM SWITCH IS "NOT IN THE CONFIGURATION", NOT "OFF". The model is explicit that
    NULL means the key is absent from the committed configuration and what the device does in
    that state is UNMEASURED - deliberately not stored as false, because false would mean an
    administrator switched alarms off. `(none)` in a column of Yes/No reads as off.

WHAT IS DELIBERATELY NOT HERE. No reader on any column of any of the three models is refused for
the `stored=False` price, because none of the presented columns is a measured payload key whose
provenance row a reader would discard: `LogAlarmSettings` is the only model of the three that
writes `FieldProvenance` rows at all, and its four rows belong to `alarm_generation_enabled`,
`cli_alarm_notification_enabled`, `web_alarm_notification_enabled` and
`log_db_alarm_thresholds`, which reach the row as SUBJECT columns rather than as tested fields -
and a subject column's cell has no provenance of its own either way. The loss is recorded in the
stage 9 artifact: those four rows say `not_configured` on the two appliances whose node is
absent and `local` on the two that have it, which is exactly the distinction a reader of this tab
wants, and no cell on the tab can reach them because no control clauses on those fields.
"""
from __future__ import annotations

from assessments.artifacts.sheets import findings as findings_sheet
from optivedge_integrations.integrations.models import FirewallContentStreams

#: The one word every Provenance cell on these three tabs reads.
#:
#: P451 IS REAL ON ALL THREE TABS AND THIS IS NOT WHAT FIXES IT, which was measured on built rows
#: three ways rather than assumed. With neither this cell nor the `choices` readers below, all
#: three tabs print "Not recorded" about a verdict this assessment computed: the default cell
#: answers per tested field through `remediation_accessor`, which skips a DERIVED row and walks to
#: the object's `__entry__`, and `write_node_row` never writes an `__entry__` row at all - two of
#: the three normalisers pass no provenance argument whatsoever (`platform_lifecycle.py:406` and
#: `:739`) and the third passes one naming four fields, none of which is its clause field (`:942`,
#: built at `:893`).
#:
#: BUT WITH THE READERS AND WITHOUT THIS CELL, ALL THREE ALREADY READ "Derived". A `value_reader`
#: on a tested field makes `tested_fields` return `stored=False`, and `provenance_cells` answers
#: with the DERIVED label before it looks at a row at all - so the four readers that P457 made
#: mandatory fix P451 here as a side effect, and the standing "one line per sheet fixes it"
#: remedy was not needed on this domain.
#:
#: SO WHAT THIS CELL EARNS IS TIDINESS, NOT CORRECTNESS, and it is kept for the reason
#: `DeviceSettingSheet.provenance_cell`'s own docstring gives: the per-field default prints one
#: line per tested field, which on the Licenses tab is `Derived\nDerived` for a subject that
#: answers once for the whole object. Repeating it says nothing the first line did not.
#: `vsys_rule_posture` and the four SaaS tabs set the same precedent.
DERIVED_CELL = (
    lambda _subject, _provenance_of, _fields:
    findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label)


def _state(field, blank):
    """A `choices` column's own English label, via `get_<field>_display()`.

    `blank` is what to print for the EMPTY STRING, which is a real state on all four of these
    columns and is deliberately absent from every one of their `choices` lists - it is what an
    unrecomputed or uncollected row holds, and Django's own `get_FIELD_display` returns the
    stored value unchanged for a key it does not know, so without this branch the cell would be
    blank. "Not computed" rather than an em dash: `layout.NONE` says "this branch does not exist
    on this subject", and that is not what an absent verdict means - the verdict was not
    computed, which is a different sentence and the one a reader needs. No row in the measured
    estate holds it; the branch is here because the models allow it and a blank cell in a verdict
    column is the failure this stage exists to catch.
    """
    def read(subject):
        value = getattr(subject, field)
        if not value:
            return blank
        return getattr(subject, f"get_{field}_display")()
    return findings_sheet.ValueReader(
        read=read, provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label)


def _three_way(field, absent="Not in the configuration"):
    """A NULLABLE boolean's three states, where NULL is not "no".

    NO `get_<field>_display()` HERE AND THAT IS THE POINT: these are `BooleanField`s with
    `choices=None`, so the method does not exist and calling it raises `AttributeError` at
    template render - past `django check` and past all three cross-domain gates (P462).
    """
    def read(subject, _provenance_of):
        value = getattr(subject, field)
        return absent if value is None else findings_sheet.display_value(value)
    return read


def _yes_no(field):
    def read(subject, _provenance_of):
        return findings_sheet.display_value(getattr(subject, field))
    return read


def _version(field):
    """A content version string, where `0` means NEVER INSTALLED and blank means nobody read it.

    Both literals come from the model's own `NEVER_INSTALLED_VERSIONS`, which records the
    measurement: the four content streams answer `0` and the URL filtering stream answers
    `0000.00.00.000` for one state.
    """
    def read(subject, _provenance_of):
        value = (getattr(subject, field) or "").strip()
        if not value:
            return "Not read"
        if value in FirewallContentStreams.NEVER_INSTALLED_VERSIONS:
            return "Never installed"
        return value
    return read


def _release_date(field):
    """A content release date, where blank asserts the reply carried NO date for the stream."""
    def read(subject, _provenance_of):
        return (getattr(subject, field) or "").strip() or "No release date reported"
    return read


def _count(field, none_word):
    """A count whose zero means something, said in words rather than printed as `0`.

    The findings tabs' own rule, from `configuration_results._nothing`: a bare zero in a
    reference column reads as "not counted" exactly where it means "counted, and the answer was
    none".
    """
    def read(subject, _provenance_of):
        value = getattr(subject, field)
        return none_word if not value else str(value)
    return read


def _thresholds(subject, _provenance_of):
    """Which log types carry an occupancy threshold, and at what percentage.

    THE DENOMINATOR OF THAT PERCENTAGE IS CONTRADICTED BY THE VENDOR and the cell does not
    pretend otherwise - `reference/known-vendor-contradictions.md` records the log-database
    alarm threshold as a share of "available disk space" on help 11.2 p.912 and of "the maximum
    size" on p.913, the field table for the very field p.912's sentence is about, and the two
    denominators measure 11 GB and 0.341 GB on one lab appliance. Both sentences are present in
    all three indexed Help editions. So the number is printed with its log type and NO unit
    sentence is attached: a heading claiming a denominator would pick a side the vendor has not.
    """
    thresholds = subject.log_db_alarm_thresholds or {}
    if not isinstance(thresholds, dict) or not thresholds:
        return "None recorded"
    # ONE PER LINE and not comma-joined, which is the repository's multi-value cell rule
    # (Jason, 2026-09-27) and is enforced for the explorer pages by
    # `test_no_presentation_module_comma_joins_a_list`. A findings cell is run through
    # `linebreaksbr` on the page and wrapped in the workbook, so the two surfaces agree.
    return "\n".join(f"{name} {value}" for name, value in sorted(thresholds.items()))


def _lowest_threshold(subject, _provenance_of):
    """The strictest threshold recorded, with the one value whose meaning is not established.

    The model carries the sentinel verbatim: zero is inside the grammar's range, the device
    accepts it, and whether it means "alarm always" or "alarm never" is UNMEASURED - so a query
    ranking "lower is stricter" may be exactly inverted at the one value an
    unconfigured-looking appliance would hold. A cell printing a bare `0` here invites the
    reader to make that ranking.
    """
    value = subject.log_db_alarm_threshold_lowest
    if value is None:
        return "No threshold recorded"
    if value == 0:
        return "0 - what this value means is not established"
    return str(value)


# --------------------------------------------------------------------------------------------
# Installed Content - PAN-PLT-002, `integrations.FirewallContentStreams`
# --------------------------------------------------------------------------------------------
# THE VENDOR'S SCREEN IS `Device > Dynamic Updates`, established in the corpus and present
# verbatim in all three indexed Help editions - 11.2 p.950-953, 11.1 p.940, 12.2 p.992. Help
# 11.2 p.950 names the content types this row holds: "new and modified applications, threat
# protection, device dictionary files for IoT Security, and GlobalProtect data files", with
# "Antivirus and Applications and Threats updates" and "WildFire updates" named as the vendor's
# own update rows and "Currently Installed" as the screen's own column for what is on the box.
#
# THE VERSION HEADINGS ARE OURS AND ARE FLAGGED. The firewall reports `app-version` and
# `threat-version` as TWO keys of `show system info` while the vendor's own Dynamic Updates
# screen carries them as ONE row called "Applications and Threats", so there is no vendor word
# for either half on its own. The headings below split them the way the device does, because the
# control asserts on them separately - stage 3 scopes PAN-PLT-002 to the applications, antivirus
# and threats streams - and a single heading would have to hide one of two values.
CONTENT_STREAMS_EVIDENCE = (
    # THE UNKNOWN-DETECTOR, FIRST OF THE EVIDENCE COLUMNS. Stage 5 declares this column's unknown
    # as reading `fires`, and the model's own docstring calls it "the only column here a control
    # may rely on to tell 'we never asked' from 'we asked and it was fine'". A reader meeting a
    # content verdict needs this before any version.
    ("Content read answered", 20, False, _yes_no("content_streams_collected"),
     "content_streams_collected"),
    ("Applications content version", 24, False, _version("app_version"), "app_version"),
    ("Applications content release date", 26, True, _release_date("app_release_date"),
     "app_release_date"),
    ("Antivirus content version", 22, False, _version("av_version"), "av_version"),
    ("Antivirus content release date", 26, True, _release_date("av_release_date"),
     "av_release_date"),
    ("Threat content version", 22, False, _version("threat_version"), "threat_version"),
    ("Threat content release date", 26, True, _release_date("threat_release_date"),
     "threat_release_date"),
    # NO WILDFIRE RELEASE DATE COLUMN BECAUSE THERE IS NO SUCH COLUMN ON THE MODEL: stage 5
    # declared none and the key is absent from the reply wherever the version is `0`. So this
    # stream can contribute "never installed" to the verdict and never "behind", which is worth
    # knowing when a WildFire cell reads Never installed and the verdict names a stream.
    ("WildFire content version", 22, False, _version("wildfire_version"), "wildfire_version"),
    # DECLARED AND NOT CLAUSED ON: stage 3 scopes the control to the other three streams, and
    # stage 5 marks this column presented. It is here so a reader can see the stream the verdict
    # does NOT cover rather than assume it was covered.
    ("URL filtering content version", 24, False, _version("url_filtering_version"),
     "url_filtering_version"),
)

#: PROPOSED heading for PAN-PLT-002's one clause field.
CONTENT_STREAMS_LABELS = {
    "content_currency_state": "Content currency",
}

CONTENT_STREAMS_READERS = {
    "content_currency_state": _state("content_currency_state", "Not computed"),
}


# --------------------------------------------------------------------------------------------
# Licenses - PAN-PLT-004, `integrations.LicenceInventory`
# --------------------------------------------------------------------------------------------
# THE VENDOR'S SCREEN IS `Device > Licenses`, established in the corpus and present verbatim in
# all three indexed Help editions - 11.2 p.954, 11.1 p.940, 12.2 p.992. Help 11.2 p.954: "Select
# Device > Licenses to activate licenses on all firewall models", and the same page names a
# support entitlement in its own words - "it allows you to free up all active licenses -
# subscription licenses, VM-Capacity licenses, and support entitlements".
#
# AND THE VENDOR DOES NOT DOCUMENT AN EXPIRY FIELD ON THAT SCREEN, which is already recorded:
# `reference/known-vendor-contradictions.md` carries it - the Threat Prevention guide p.35 sends
# a reader to `Device > Licenses` to "verify that the Threat Prevention expiration date is in the
# future", and the Help's own section for that screen documents no expiry, no status and no
# per-subscription field at all, checked across all three editions. So every expiry reading on
# this tab comes from `request license info`, an OPERATIONAL command, and not from the screen the
# rail item sends an assessor to. The rail item is still right - that is where licences live and
# where a renewal is applied - and this note is why the two surfaces can differ.
#
# BRITISH SPELLING ON OUR SIDE, AMERICAN ON THE VENDOR'S, deliberately unreconciled: the model is
# `LicenceInventory` and the vendor's screen is `Licenses`. The headings below follow the model
# except where they quote the screen.
LICENCE_INVENTORY_EVIDENCE = (
    # THE READ SHAPE, FIRST, AND THE FIFTH `choices` COLUMN OF THIS DOMAIN. It is named for the
    # SHAPE of the reply and never for a conclusion: `null_licenses_element` is the only shape an
    # unlicensed appliance produces AND the shape a licensed one would produce with every row
    # stripped, so it means unknown. Without the display call this cell would print
    # `null_licenses_element` to a customer.
    ("License table read", 22, True,
     lambda s, _p: (s.get_licence_inventory_read_display()
                    if s.licence_inventory_read else "Not computed"),
     "licence_inventory_read"),
    # ZERO HERE IS TWO DIFFERENT DEVICE STATES - a present-and-empty `licenses` element and a
    # read that never ran - told apart by the column above and never by this one, which is the
    # model's own warning. So the zero is printed in words.
    ("License rows returned", 20, False, _count("licence_row_count", "None returned"),
     "licence_row_count"),
    # COUNTED OFF THE VENDOR'S OWN `expired` FLAG and never off a date comparison: `expires`
    # holds the literal `Never` on every licence in the measured estate, which no date parser
    # accepts.
    ("Entitlements already expired", 24, False,
     _count("expired_entitlement_count", "None"), "expired_entitlement_count"),
    # THE VENDOR'S OWN HORIZON: a warning appears in the system log daily once a licence is
    # within thirty days of expiry (guide p.23). Counted AT NORMALIZATION against the date the
    # collection ran, so a stored row ages into being wrong without changing - which is the
    # model's own note and the reason the Config collected column at the end of the row matters
    # on this tab more than on most.
    ("Entitlements expiring within 30 days", 30, True,
     _count("expiring_within_30_days_count", "None"), "expiring_within_30_days_count"),
)

#: PROPOSED headings for PAN-PLT-004's two clause fields - one control stated as TWO assertion
#: records over two columns of one model, which is why there are two verdicts on one row.
#:
#: THE SECOND IS A DIFFERENT CONSEQUENCE AND NOT A SEVERITY TIER OF THE FIRST: a lapsed SUPPORT
#: licence removes the ability to obtain software at all, which is what blocks the remedy for
#: anything PAN-PLT-001 or PAN-PLT-003 would find. The headings keep them apart.
LICENCE_INVENTORY_LABELS = {
    "entitlement_state": "Subscription entitlements",
    "support_entitlement_state": "Support entitlement",
}

LICENCE_INVENTORY_READERS = {
    "entitlement_state": _state("entitlement_state", "Not computed"),
    "support_entitlement_state": _state("support_entitlement_state", "Not computed"),
}


# --------------------------------------------------------------------------------------------
# Alarm Settings - PAN-PLT-006, `integrations.LogAlarmSettings`
# --------------------------------------------------------------------------------------------
# THE VENDOR'S SCREEN IS `Device > Log Settings`, established in the corpus: the section is
# `Define Alarm Settings`, whose own breadcrumb line reads "Define Alarm Settings - Device > Log
# Settings", and it is present verbatim in all three indexed Help editions (11.2 p.912-914, 11.1
# p.898, 12.2 p.949). Help 11.2 p.912: "Use the Alarm Settings to configure Alarms for the CLI
# and the web interface", listing "The Log database for each log type is nearing full" as one of
# the three events, and "Alarms are visible only if you Enable Alarms. If you disable alarms, the
# firewall does not alert you to critical events that require action."
#
# THE VENDOR'S OWN FIELD LABELS, for the four columns it has words for: `Enable Alarms`, `Enable
# CLI Alarm Notifications`, `Enable Web Alarm Notifications` and `<Log-type> Log DB`. The headings
# below render them as STATES rather than as the imperative on the checkbox, because a findings
# row reports what is so rather than offering an action - and the vendor's exact wording is in
# this comment so the pass that settles headings can take it either way.
#
# THE VENDOR HAS NO WORD FOR THE TWO COMPUTED COLUMNS: whether the alarm node is in the
# configuration at all, and whether EITHER notification route is on. Both are readings this
# assessment makes - the second is a disjunction over two nullable booleans, which the model's own
# comment notes "is not expressible as a clause list at all" - and both headings are ours.
#
# AND THE CONTROL'S SECOND HALF IS REPORTED NOWHERE. PAN-PLT-006 was named `Device Health
# Headroom Monitored`; stage 5 discharged its dataplane-utilisation half `engineer_answers`
# because no configuration node on the firewall holds a dataplane CPU or session threshold and
# the vendor's own procedure puts the comparison off-box. A clean row on this tab is about the
# log-database alarm mechanism and nothing else, which the sheet's description says in the
# customer's words.
LOG_ALARM_EVIDENCE = (
    # NOT THE SAME CLAIM AS THE ALARM BEING OFF, which is the distinction stage 3's second rank
    # rests on: "nothing recorded at all, which cannot be told apart from a device sitting at the
    # vendor's documented default". False is the state of three of the four measured appliances.
    ("Alarm node in the configuration", 26, True,
     _yes_no("alarm_settings_node_present"), "alarm_settings_node_present"),
    ("Alarms enabled", 22, True, _three_way("alarm_generation_enabled"),
     "alarm_generation_enabled"),
    # ONE COMPANION FOR EVERY BOOLEAN ON THIS MODEL rather than one each - all three switches come
    # from the same node by the same read, so the node either answered or it did not. This is the
    # column that makes "Not in the configuration" above mean something: with it a reader can tell
    # a switch nobody asked about from one the configuration genuinely omits.
    ("Alarm switches read", 20, False, _yes_no("alarm_generation_enabled_known"),
     "alarm_generation_enabled_known"),
    ("Log-database thresholds", 34, True, _thresholds, "log_db_alarm_thresholds"),
    ("Log types with a threshold", 22, False,
     _count("log_db_alarm_threshold_count", "None"), "log_db_alarm_threshold_count"),
    ("Strictest threshold recorded", 30, True, _lowest_threshold,
     "log_db_alarm_threshold_lowest"),
    ("CLI alarm notifications", 22, True, _three_way("cli_alarm_notification_enabled"),
     "cli_alarm_notification_enabled"),
    ("Web alarm notifications", 22, True, _three_way("web_alarm_notification_enabled"),
     "web_alarm_notification_enabled"),
    ("A notification route is on", 22, True,
     _yes_no("alarm_notification_route_present"), "alarm_notification_route_present"),
)

#: PROPOSED heading for PAN-PLT-006's one clause field. It is a verdict over the whole mechanism
#: and not over any one leaf, which is stage 5's own reason for grading on it: stage 3's ordering
#: - "on with no threshold" being worse than "on with thresholds and no route" - is not
#: expressible as a conjunction of the leaves beside it.
LOG_ALARM_LABELS = {
    "alarm_mechanism_state": "Alarm mechanism",
}

LOG_ALARM_READERS = {
    "alarm_mechanism_state": _state("alarm_mechanism_state", "Not computed"),
}
