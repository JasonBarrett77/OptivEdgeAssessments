"""Finding generation for one appliance's device-wide logging posture.

PAN-MGT-011 (management-services), and PAN-LOG-001, 003, 004, 006, 007, 008, 009 and 010.

NINE CONTROLS OF TWO DOMAINS ON ONE TYPE, AND THAT IS WHY THE DISPATCH BELOW EXISTS. Until
2026-11-01 `_subject` was ONE UNCONDITIONAL SENTENCE about the high-DP-load setting, because
PAN-MGT-011 was the only control on the type. Putting eight PAN-LOG controls on it as it stood
would have made every one of their findings assert that the high-DP-load setting is off - on a
finding about log retention, about syslog transport, about Panorama coverage. The sentence was
wrong on most of them and was not even their subject.

PAN-MGT-011's SENTENCE IS UNCHANGED, BYTE FOR BYTE, in its own arm. It belongs to another
domain, the reconciliation rule for a shipped control is to change nothing outside the domain
being built, and its prose is correct for what it asserts. Refactoring shared code is allowed;
changing that control's behavior is not. Measured before and after:

    pan-fw-201 does not log when the data plane is under high load - the setting is off, which
    is its default. Matched control query: Baseline.

THE DEFAULT ARM IS `()` AND THE FALLBACK DESCRIBES ONLY WHAT THE OBJECT IS. Measured across all
28 generators that key a dispatch by control id, 2026-11-01: eighteen default to another
control's arm tuple, five to `()` and five to `None` and then deliberately say everything. A
default that is another control's arms is how a control reusing a type gets its finding described
with someone else's claims - this repository has repaired exactly that in `zone_findings` for
PAN-ZON-001. With NINE controls on one type a non-empty default would mis-describe eight of
them, so an unmapped control gets a sentence naming the appliance and making no claim, which
reads as incomplete rather than as an answer to a different question.

WHAT NO FINDING ON THIS MODEL CAN SAY, and all of it is the columns' own recorded limits rather
than this module's:

- WHICH PEER OF AN HA PAIR IS RIGHT. One row per appliance means two rows for one real
  configuration, and the integrations model records that the two peers' management containers
  have been measured DIFFERING while config sync reported synchronized. So an asymmetric reading
  between peers is data rather than a normalization fault, and no column here can say which peer
  the estate should follow.
- HOW MUCH RETENTION IS ENOUGH. PAN-LOG-009's column is a PRESENCE test over about 170 keys in
  two platform-dependent shapes, so any one of them being set makes it true. The numbers
  themselves exist only in `show system logdb-quota`, which no configuration read carries, and
  the never-expire sentinel cannot be written at all. The window is the engineer's answer.
- WHETHER A MISSING SEVERITY BAND IS MISSING BECAUSE NOTHING IS ATTACHED OR BECAUSE A FILTER
  EXCLUDES IT. PAN-LOG-003's column cannot tell those apart - both arrive as a gap list - and
  stage 6 recorded that one subject realises both of stage 3's rungs. They grade identically and
  the REMEDIATION differs, which is why `_system_severity_gaps` names both possibilities rather
  than picking one.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_logging_settings_control_queries
from assessments.models import (
    Control, LoggingSettingsFinding, LoggingSettingsFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import LoggingSettings


def _appliance(obj) -> str:
    return str(obj.appliance)


def _gap_list(value) -> list[str]:
    """The tokens of a comma-joined gap column, in the order the normalizer wrote them."""
    return [token for token in str(value or "").split(",") if token]


# --- PAN-MGT-011 (management-services) --------------------------------------------------------
def _high_dp_load(obj) -> list[str]:
    """UNCHANGED PROSE. This is the whole of what `_subject` returned before the dispatch
    existed, as one arm, so the joined sentence is byte-identical for this control."""
    return [f"{obj.appliance} does not log when the data plane is under high load "
            f"- the setting is off, which is its default"]


# --- PAN-LOG-001 --------------------------------------------------------------------------
def _offbox_destinations(obj) -> list[str]:
    """Record 0: how many distinct off-box log destinations the appliance DEFINES."""
    count = obj.offbox_destination_count
    if count >= 2:
        return []
    if count == 0:
        return [
            f"{_appliance(obj)} DEFINES NO OFF-BOX LOG DESTINATION AT ALL, so nothing this "
            f"appliance records survives the appliance: no syslog server entry at either scope, "
            f"no Panorama or log-collector path, and no HTTP collector",
            "zero is also the value a row that has never been recomputed holds, so this finding "
            "is the correct reading of both an unconfigured appliance and an unmeasured one - "
            "the direction is deliberate, because the opposite default would report every "
            "firewall in the estate as covered the day a migration lands",
        ]
    return [
        f"{_appliance(obj)} defines exactly ONE off-box log destination, so the audit trail "
        f"leaves the box by a single path and has no second path to survive the loss of it",
        "the vendor's availability advice is two; one meets the floor and not the redundancy, "
        "which is why this reports one rank below an appliance with none",
    ]


def _syslog_destination_unused(obj) -> list[str]:
    """Record 1: a defined profile that nothing forwards to sends nothing."""
    if obj.syslog_destination_in_use:
        return []
    return [
        f"NO SYSLOG SERVER PROFILE ON {_appliance(obj)} IS NAMED BY A FORWARDING RULE THAT IS "
        f"ACTUALLY IN PLACE, so every syslog profile this appliance holds is an address book "
        f"rather than a destination - existence is not enough, and nothing is sent until a "
        f"Device > Log Settings match list or a Log Forwarding profile match list names one",
        "this is a different remediation from defining a destination: the profile may already "
        "be correct and the match list is what is missing",
    ]


# --- PAN-LOG-003 --------------------------------------------------------------------------
def _system_severity_gaps(obj) -> list[str]:
    """Which System-log severities no off-box destination covers."""
    missing = _gap_list(obj.system_log_severity_gaps)
    if not missing:
        return []
    parts = [
        f"NO OFF-BOX DESTINATION ON {_appliance(obj)} CARRIES THE SYSTEM-LOG SEVERITIES "
        f"{', '.join(missing)}, so management-plane events at those bands exist only on the "
        f"appliance and are lost with it",
    ]
    parts.append(
        "THE COLUMN CANNOT SAY WHICH OF TWO SHAPES THIS IS and the remediation differs between "
        "them: either no System match list is attached to an off-box destination at all, or one "
        "is and its filter excludes these bands. Read Device > Log Settings > System before "
        "choosing between adding a destination and widening a filter")
    parts.append(
        "e-mail and SNMP-trap destinations are deliberately not counted as off-box here - they "
        "notify rather than retain - so a band covered only by an alert is still reported")
    return parts


# --- PAN-LOG-004 --------------------------------------------------------------------------
def _config_log_not_fully_offbox(obj) -> list[str]:
    """Whether EVERY configuration-change log leaves the appliance, and which half failed."""
    if obj.config_log_fully_offbox:
        return []
    parts = [f"NOT EVERY CONFIGURATION-CHANGE LOG LEAVES {_appliance(obj)}, so the record of "
             f"who changed what is not wholly outside the reach of a change"]
    # THE DISJUNCTION'S ARMS, which is the whole reason the two half-columns are stored beside
    # the verdict: the verdict is one boolean and the failure has two causes.
    #
    # `elif` AND NOT A SECOND `if`, AND THAT IS A CORRECTION RATHER THAN A STYLE. The normaliser
    # keeps `config_log_filter_narrows` TRUE where NO off-box entry exists at all - its own
    # comment says why, that it is the firing side and that nothing has been shown to be
    # unrestricted - so on an appliance with no destination BOTH columns read as failing. Two
    # independent `if`s therefore printed "the destination is configured and some records still
    # never leave" about an appliance with no destination, which is false prose on the exact row
    # the first arm had just described correctly. Measured on the census, 2026-11-01, on the
    # appliance reproducing fw-core-tpa-a.
    if not obj.config_log_offbox_destination:
        parts.append(
            "NO OFF-BOX CONFIGURATION DESTINATION IS CONFIGURED: no Configuration match list "
            "names a syslog profile, an HTTP profile or Panorama. A missing match list means no "
            "destination, because that object is the only forwarding path for this log type")
    elif obj.config_log_filter_narrows:
        parts.append(
            "A FILTER ON THE CONFIGURATION PATH HOLDS SOMETHING BACK, so the destination is "
            "configured and some configuration records still never leave. The `filter` key is "
            "mandatory at commit validation on this node, so every committed entry carries one "
            "and none can be assumed unrestricted until it is read")
    return parts


# --- PAN-LOG-006 --------------------------------------------------------------------------
def _panorama_log_type_gaps(obj) -> list[str]:
    """Which forwardable log types do not reach the management station or logging service."""
    missing = _gap_list(obj.panorama_log_type_gaps)
    if not missing:
        return []
    return [
        f"{_appliance(obj)} DOES NOT FORWARD THE LOG TYPES {', '.join(missing)} to its "
        f"management station or logging service, taken across both the Device > Log Settings "
        f"match lists and the Log Forwarding profile match lists",
        "`correlation` is excluded from this count by construction rather than by omission: it "
        "carries no `send-to-panorama` key at all on the one platform that has the kind, so a "
        "gap list cannot report a kind that cannot forward",
        "the absent-key reading was measured on the SYSTEM kind against the device's own "
        "forwarding counters and is carried to the rest, which is the firing direction: a log "
        "type nobody can show to be forwarded counts as not forwarded",
    ]


# --- PAN-LOG-007 --------------------------------------------------------------------------
def _audit_comment_not_required(obj) -> list[str]:
    """Whether a policy-rule change can be committed with no stated reason."""
    if obj.require_audit_comment:
        return []
    return [
        f"{_appliance(obj)} DOES NOT REQUIRE AN AUDIT COMMENT ON A POLICY-RULE CHANGE, so a "
        f"rule can be added, edited or removed with no record of why",
        "the absence of the key reads as off, measured in BOTH directions against the commit "
        "gate: with the key absent a policy change committed with no comment, with it set the "
        "same commit was refused, and deleting it let the rule commit again. So an untouched "
        "appliance genuinely does not require one rather than being unread",
        "WHAT THE GATE ACTUALLY IS matters for the remediation: it fires at commit SUBMISSION, "
        "so NO JOB IS CREATED - an instruction to watch for a failed commit job describes "
        "something that will not happen",
    ]


# --- PAN-LOG-008 --------------------------------------------------------------------------
def _no_email_alerting_for_critical(obj) -> list[str]:
    """Whether a critical-severity System-log path names a mail relay."""
    if obj.email_alerting_for_critical_system_events:
        return []
    return [
        f"NO SYSTEM-LOG PATH ON {_appliance(obj)} WHOSE FILTER INCLUDES CRITICAL SEVERITY NAMES "
        f"AN EMAIL SERVER PROFILE, so a critical management-plane event reaches nobody until "
        f"somebody goes looking for it",
        "THIS IS THE CONFIGURATION HALF ONLY, and the control's own floor is that alerting is "
        "not required where SIEM coverage of critical events already exists - which is a "
        "question for the operator and not a value this appliance holds",
        "AND WHETHER THE RELAY IS REACHED SAFELY IS NOT ASSESSED BY THIS FINDING. Whether the "
        "mail path uses an authenticated encrypted session is a fact about a server entry on "
        "another model, and no control in this domain asserts it - so a relay that exists and "
        "is reached in the clear satisfies everything said here",
    ]


# --- PAN-LOG-009 --------------------------------------------------------------------------
def _retention_undecided(obj) -> list[str]:
    """Whether anybody has taken a log retention decision on this appliance at all."""
    if obj.log_retention_configured:
        return []
    return [
        f"NO PER-LOG-TYPE DISK QUOTA OR LOG EXPIRATION PERIOD IS SET ANYWHERE ON "
        f"{_appliance(obj)}, so every log type keeps the platform's shipped share and expires "
        f"on the platform's shipped terms: nobody has taken a retention decision here",
        "THE SHARES AND THE WINDOW ARE NOT ASSERTED BY THIS FINDING and cannot be read off the "
        "configuration. The quota numbers exist only in `show system logdb-quota`, which no "
        "configuration read carries, and the device refuses a written never-expire value - so "
        "setting something is where this remediation starts and not where it ends",
        "AND THE TEST IS PRESENCE RATHER THAN SUFFICIENCY: any one of about 170 keys being set "
        "makes this pass, so an appliance with one log type apportioned and the rest shipped "
        "produces no finding. The compliant direction of this column is weaker than it reads",
    ]


# --- PAN-LOG-010 --------------------------------------------------------------------------
def _central_store_delivery(obj) -> list[str]:
    """Whether the appliance is known to be delivering to its central log store."""
    if obj.central_store_delivery_healthy:
        return []
    # THE COMPANION COLUMN IS WHY THIS ARM CAN SAY WHICH CASE THE FALSE IS. It is not a clause
    # on this control and must not become one - it was an applicability clause until
    # 2026-10-23, which SUPPRESSED the control for exactly the appliances nobody had read.
    if not obj.central_store_status_collected:
        return [
            f"THERE IS NO DELIVERY READING FOR {_appliance(obj)} AT ALL, so nothing shows its "
            f"logs reaching a central store. This is reported rather than passed over: a "
            f"missing reading treated as healthy is a customer told they are safe on the "
            f"strength of nothing",
            "so the first step is to take the reading, not to change the configuration",
        ]
    return [
        f"{_appliance(obj)} IS NOT KNOWN TO BE DELIVERING TO ITS CENTRAL LOG STORE with no "
        f"backlog building up. A reading exists and it does not show a completed forward",
        "A CONNECTION IS NOT A DELIVERY, which is the inversion this reading exists to survive: "
        "a collector can report every sub-block of its handshake as successful and have "
        "delivered nothing, and an appliance's connection list can name an inactive collector "
        "first. Positive evidence of a completed forward is what this column requires",
        "HOW LONG A STOP COULD GO UNNOTICED IS NOT ASSESSED HERE. The monitoring arrangement - "
        "nothing watching, a manual cadence, automated alerting - is a question for the "
        "operator and the appliance holds no value for any of it",
    ]


#: Keyed by control id, defaulting to `()`. See the module docstring for why the default is
#: empty and why that matters more on this type than on most.
PARTS_BY_CONTROL = {
    "PAN-MGT-011": (_high_dp_load,),
    "PAN-LOG-001": (_offbox_destinations, _syslog_destination_unused),
    "PAN-LOG-003": (_system_severity_gaps,),
    "PAN-LOG-004": (_config_log_not_fully_offbox,),
    "PAN-LOG-006": (_panorama_log_type_gaps,),
    "PAN-LOG-007": (_audit_comment_not_required,),
    "PAN-LOG-008": (_no_email_alerting_for_critical,),
    "PAN-LOG-009": (_retention_undecided,),
    "PAN-LOG-010": (_central_store_delivery,),
}


def _subject(obj, control_id: str = "") -> str:
    parts: list[str] = []
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    if not parts:
        # An unmapped control, or a mapped one whose arms all declined. Describe what the object
        # IS and claim nothing - see the module docstring on the empty default.
        return f"the device-wide logging posture of {_appliance(obj)}"
    return "; ".join(parts)


def build_logging_settings_finding_summary(obj, matched_queries) -> str:
    # The control id comes off the first matched query, which is safe for the reason
    # `object_findings.generate_object_findings` makes it safe: it iterates `for control in
    # controls` and creates the finding with that same control, so `matched_queries` can only
    # ever hold one control's queries. The loop is a spelling of `control.control_id`.
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="logging settings",
    control_type=Control.ControlType.LOGGING_SETTINGS,
    finding_model=LoggingSettingsFinding,
    link_model=LoggingSettingsFindingControlQuery,
    subject_fk="logging_settings",
    link_fk="logging_settings_finding",
    queryset=lambda: LoggingSettings.objects.select_related("appliance"),
    evaluate=evaluate_logging_settings_control_queries,
    summary=build_logging_settings_finding_summary,
    #: The policy has no name of its own, so the appliance IS the subject name.
    subject_name=lambda obj: str(obj.appliance),
)

LoggingSettingsFindingRunResult = ObjectFindingRunResult


def generate_logging_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_logging_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
