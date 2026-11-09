"""Finding generation for one appliance's log-database alarm mechanism. PAN-PLT-006's first half.

THE SENTENCE DISTINGUISHES THE FOUR WAYS THE MECHANISM FAILS, because they are four different
remediations and the verdict token alone does not carry which:

* THE NODE IS ABSENT ENTIRELY, which is the state every appliance in this estate shipped with. No
  alarm is raised when a log database fills, and the oldest records are discarded silently - so the
  evidence an investigation would want is gone and nothing says it went.
* THE NODE IS PRESENT AND THE MASTER SWITCH IS NOT ON. The thresholds and routes beneath it may be
  configured and are inert. This token ALSO covers the master switch being absent from a present
  node, which is the one place the classification cannot keep "off" and "unknown" apart - the
  companion column is what a reader consults, and the direction fires either way.
* THE SWITCH IS ON AND NO LOG TYPE CARRIES A THRESHOLD, so there is no occupancy at which anything
  would fire. Stage 3 ranks this WORSE than a configured mechanism with no notification route, and
  a conjunction of the leaves cannot say so - which is why the control grades one ordered verdict.
* THE SWITCH AND THRESHOLDS ARE SET AND NEITHER NOTIFICATION ROUTE IS ON, so a raised alarm reaches
  nobody who is not already looking at the screen. That is graded one tier below the control's own
  severity: the mechanism works and the message does not leave the box.

AN ABSENT NODE AND AN EMPTIED CONTAINER ARE DIFFERENT VERDICTS, measured. Deleting the leaves alone
leaves a container that reads as PRESENT, so a truthiness test on the container reports an alarm
mechanism where there is none; deleting the node returns the appliance to `node_absent`.

A SEVERITY DIRECTION THIS FINDING DOES NOT ASSERT, stated because the hazard outlives this control.
A log-type threshold of `0` is STORABLE - written, validated and committed on one lab appliance and
read back as `0` from the running view - and what it MEANS is unmeasured. "Alarm always" and "alarm
never" are both readings and nothing on the device says which. This control counts the log types
that carry a threshold and never reads their magnitude, so no sentence here ranks one threshold
against another; a later control that does must measure that value first.

AND THE OTHER HALF OF PAN-PLT-006 IS NOT REPORTED ANYWHERE, which a reader of this row must not
mistake for a pass. Its second assertion record - a dataplane under sustained load - is discharged
`engineer_answers` by stage 5 and owes no query, because there is no configuration node anywhere on
the firewall holding a dataplane CPU or session-utilization threshold, so "sustained" has no stored
definition and the vendor's own monitoring procedure puts the comparison on the SNMP manager. That
is a measurable expression nobody can write, not a model this control failed to reach.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_log_alarm_settings_control_queries
from assessments.models import (
    Control,
    LogAlarmSettingsFinding,
    LogAlarmSettingsFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import LogAlarmSettings


def _routes(obj) -> str:
    on = [name for name, value in (("the CLI route", obj.cli_alarm_notification_enabled),
                                   ("the web route", obj.web_alarm_notification_enabled))
          if value is True]
    return ", ".join(on) if on else "neither notification route"


def _mechanism(obj) -> list[str]:
    """PAN-PLT-006's first record: would this appliance raise an alarm, and would anyone see it."""
    state = obj.alarm_mechanism_state or ""
    if state == "on_with_thresholds_and_route":
        return []
    parts = []
    if state == "node_absent":
        parts.append(
            "THE ALARM NODE IS ABSENT FROM THIS APPLIANCE'S CONFIGURATION ENTIRELY - no master "
            "switch, no log-database threshold and no notification switch recorded anywhere - so "
            "nothing raises an alarm when a log database fills and the oldest records are "
            "discarded silently. What is lost is the evidence an investigation would ask for, and "
            "nothing on the box says it went")
    elif state == "generation_off":
        parts.append(
            f"the alarm node is PRESENT and alarm generation is not on, so anything configured "
            f"beneath it is inert: {obj.log_db_alarm_threshold_count} log-database threshold"
            f"{'s' if obj.log_db_alarm_threshold_count != 1 else ''} recorded and "
            f"{_routes(obj)} switched on, none of which fires. THIS TOKEN ALSO COVERS THE SWITCH "
            f"BEING ABSENT from a present node, which is the one state this verdict cannot keep "
            f"apart from `off` - and the column that says which is "
            f"`alarm_generation_enabled_known`, which reads "
            f"`{obj.alarm_generation_enabled_known}` here")
    elif state == "on_without_thresholds":
        parts.append(
            "alarm generation is ON and NO LOG TYPE CARRIES AN OCCUPANCY THRESHOLD, so there is no "
            "level at which anything would fire and the switch being on is cosmetic. Stage 3 ranks "
            "this worse than a configured mechanism whose message cannot leave the box, which is "
            "why it sits at the control's own severity")
    elif state == "on_with_thresholds_no_route":
        parts.append(
            f"alarm generation is on and {obj.log_db_alarm_threshold_count} log-database "
            f"threshold{'s' if obj.log_db_alarm_threshold_count != 1 else ''} "
            f"{'are' if obj.log_db_alarm_threshold_count != 1 else 'is'} recorded, but NEITHER "
            f"NOTIFICATION ROUTE IS ON - so an alarm is raised and reaches nobody who is not "
            f"already looking at the screen. That is graded one tier below this control's own "
            f"severity because the mechanism works; what fails is the delivery")
    else:
        parts.append(
            f"this appliance's alarm mechanism reads `{state or '(empty)'}`, which this generator "
            f"has no sentence for - a token was added to the column and not to this control. Treat "
            f"the verdict as unexplained rather than as any of the states named above")
    parts.append(
        "WHAT TO OPEN: Device > Setup > Management > Logging and Reporting Settings > Log Export "
        "and Reporting, and the node at `deviceconfig/setting/management/"
        "common-criteria-alarm-generation`. DELETE OR ADD THE WHOLE NODE RATHER THAN ITS LEAVES: "
        "an emptied container reads as PRESENT and is a different verdict from an absent one, and "
        "the parent `deviceconfig/setting/management` is shared furniture carrying other settings "
        "this control does not own")
    parts.append(
        "AND WHAT THIS ROW DOES NOT ASSERT: how large any threshold is. A threshold of `0` is "
        "storable on this platform and what it MEANS is unmeasured - `alarm always` and `alarm "
        "never` are both readings and nothing on the device says which - so this control counts "
        "the log types that carry a threshold and never ranks their values")
    parts.append(
        "THE OTHER HALF OF THIS CONTROL IS REPORTED NOWHERE and a clean row would not have covered "
        "it. Whether this appliance's dataplane runs under sustained load is discharged to an "
        "engineer: no configuration node on the firewall holds a dataplane CPU or session "
        "threshold, so `sustained` has no stored definition and the vendor's own procedure puts "
        "the comparison on the SNMP manager")
    return parts


#: One control, one reading. PAN-PLT-006 is the only control over this model.
PARTS_BY_CONTROL = {
    "PAN-PLT-006": (_mechanism,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"log database alarms on {obj.appliance} (serial {obj.appliance.serial_number})"]
    for build in PARTS_BY_CONTROL.get(control_id, (_mechanism,)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_log_alarm_settings_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="log database alarm mechanism",
    control_type=Control.ControlType.LOG_ALARM_SETTINGS,
    finding_model=LogAlarmSettingsFinding,
    link_model=LogAlarmSettingsFindingControlQuery,
    subject_fk="log_alarm_settings",
    link_fk="log_alarm_settings_finding",
    queryset=lambda: LogAlarmSettings.objects.select_related("appliance", "appliance_group"),
    evaluate=evaluate_log_alarm_settings_control_queries,
    summary=build_log_alarm_settings_finding_summary,
    # A DEVICE-WIDE SINGLETON, so the appliance IS the subject name and this model declares no
    # `subject_scope`. THE HA PAIR IS ONE ADDRESS FOR THIS NODE, measured - `deviceconfig/setting`
    # synchronises on that pair - so the two rows it yields agree by construction, which is a
    # duplication rather than two facts.
    subject_name=lambda obj: str(obj.appliance),
)


def generate_log_alarm_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_log_alarm_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
