"""Finding generation for the App-ID Cloud Engine. PAN-SAS-005.

THE SENTENCE NAMES THE CONDITION AND NOT THE SYMPTOM, which is the whole reason
`ace_failure_reason` exists beside the verdict. The device certificate is a SECOND precondition
and it is not in `request license info` at all, so a remediation that reads only the license
would buy a subscription and still have no engine.

AND THE LICENSE IS THE ONE REASON THAT PRODUCES NO FINDING. The control's applicability clause is
a negated equality against `license_check_failed`: an appliance with no subscription was never
what this half of the control was about, and it falls to the half that asks whether the adoption
decision is on the record - which is an engineer's answer and has no query. So the absence of a
finding on an appliance is not a statement that the engine is healthy, and it is most often a
statement that the license check failed.

TWO THINGS THE SENTENCE IS NOT ALLOWED TO SAY:

* THAT THE ENGINE IS SWITCHED OFF, unless the reason says so. The configured `disable` key is
  absent on every lab appliance, and the implicit `false` this consumer stores for that absence
  is AN INFERENCE AND NOT A VENDOR FACT - the key's negated spelling, the vendor's checkbox
  polarity and the device's own help string are all leads, and what the device does with the key
  absent cannot be measured on an estate whose license check fails. So the configuration half is
  reported only where `ace_failure_reason` is `disabled_by_configuration`.
* THAT THE ENGINE IS HEALTHY WHERE NOBODY ASKED. `unread` means the operational command was never
  issued, and the verdict is true until a pass asks. The sentence says nobody asked rather than
  naming a condition it did not read - and `healthy` is a token no appliance in this lab can
  reach, because every condition is unsatisfied until the reply says otherwise.

THE CADENCE HALF IS IN NO COLUMN AND NO SENTENCE CLAIMS IT. The recommendation feed is
operational-only and lists what the cloud has OFFERED rather than what anybody imported, so
"the recommendations are reviewed and taken into policy on a stated cadence" is not readable from
the firewall at all.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_cloud_app_engine_control_queries
from assessments.models import (
    CloudAppEngineFinding,
    CloudAppEngineFindingControlQuery,
    Control,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import CloudAppEngineSetting

#: What each reason means to a reader, and what it asks them to do about it. The licence entry is
#: here for an unmapped control only: PAN-SAS-005's applicability clause excludes it.
REASON_PROSE = {
    CloudAppEngineSetting.REASON_LICENSE_CHECK_FAILED: (
        "the engine reports its license check failing, so no cloud application subscription is "
        "installed and active on this appliance"),
    CloudAppEngineSetting.REASON_DEVICE_CERTIFICATE_MISSING: (
        "the engine reports the device certificate as not installed, invalid or not pushed to "
        "its daemons - a SECOND precondition that `request license info` does not mention at "
        "all, so a remediation that buys a subscription and stops there still has no engine"),
    CloudAppEngineSetting.REASON_CLOUD_CONNECTION_FAILED: (
        "the engine reports its connection to the cloud as failed, so it holds a subscription "
        "and a certificate and still fetches nothing"),
    CloudAppEngineSetting.REASON_DISABLED_BY_CONFIGURATION: (
        "this appliance's configuration carries the key that switches the engine off "
        "deliberately - Device > Setup > Content-ID, 'Disable App-ID Cloud Engine'"),
    CloudAppEngineSetting.REASON_UNREAD: (
        "NOBODY ASKED THE ENGINE: the operational read that reports its condition was never "
        "issued for this appliance, so this is not a reading of its state. The verdict is true "
        "until a pass asks, because an appliance nobody asked has no working engine anybody "
        "established"),
}


def _engine(obj) -> list[str]:
    if not obj.ace_not_operational:
        return []
    prose = REASON_PROSE.get(
        obj.ace_failure_reason,
        f"the engine reports a condition recorded as `{obj.ace_failure_reason}`, which this "
        f"control does not interpret")
    parts = [f"the App-ID Cloud Engine is not working on this appliance: {prose}"]
    parts.append(
        "the rules and application filters that name cloud-delivered App-IDs stay VISIBLE in "
        "the policy while they stop enforcing, so this is a premise under every control over "
        "those App-IDs and not only a finding of its own")
    if obj.ace_failure_reason != CloudAppEngineSetting.REASON_DISABLED_BY_CONFIGURATION:
        # NOT a claim that the key is absent. The implicit this consumer stores for an absent key
        # is an inference, so the sentence declines to report the configuration at all.
        parts.append(
            "nothing here reports that somebody switched the engine off: the configured key is "
            "read separately, its absence is an inference rather than a measured vendor default, "
            "and this finding rests on the engine's own account of itself")
    if not obj.cloudapp_node_read:
        parts.append(
            "and the configuration half was NOT EXAMINED either - this appliance's merged "
            "snapshot carried no device-setting subtree, so whether anybody switched the engine "
            "off is unknown rather than answered")
    return parts


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. One control and one half of it: its other half
#: asks whether the adoption decision is on the record, which no firewall read answers, so no
#: part here speaks to it.
PARTS_BY_CONTROL = {
    "PAN-SAS-005": (_engine,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"App-ID Cloud Engine on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, (_engine,)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_cloud_app_engine_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="App-ID Cloud Engine",
    control_type=Control.ControlType.CLOUD_APP_ENGINE_SETTING,
    finding_model=CloudAppEngineFinding,
    link_model=CloudAppEngineFindingControlQuery,
    subject_fk="cloud_app_engine_setting",
    link_fk="cloud_app_engine_finding",
    queryset=lambda: CloudAppEngineSetting.objects.select_related("appliance"),
    evaluate=evaluate_cloud_app_engine_control_queries,
    summary=build_cloud_app_engine_finding_summary,
    # The appliance, because the node is a device-wide singleton. No `subject_scope`: a hostname
    # is the scope.
    subject_name=lambda obj: obj.appliance.hostname,
)


def generate_cloud_app_engine_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_cloud_app_engine_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
