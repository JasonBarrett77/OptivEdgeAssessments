"""Finding generation for the NTP controls. PAN-SVC-001 and 002.

The sentence names the servers, because the remediation is "add a second one" or "authenticate
the ones you have" and an engineer needs to know which is which.

It also says, on every finding, that SYNCHRONIZATION IS NOT ASSESSED. `show ntp` reports
`reachable` and `status: synched` per server and the corpus marks PAN-SVC-001 `live-device-state`
for that reason, but this control reads configuration: two servers configured is what it claims,
and a configured server that answers nothing would satisfy it. Saying so on the finding is the
difference between a scope limit and a false reassurance.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_ntp_settings_control_queries
from assessments.models import Control, NtpSettingsFinding, NtpSettingsFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import NtpSettings
from optivedge_integrations.integrations.models.device_services import (
    TimeSourceInForce,
)

#: WHAT THIS SAID UNTIL 2026-11-01, and why it had to change in the same pass as the clause:
#: "Whether a configured server is reachable or synchronized is not assessed - this reads
#: configuration, and `show ntp` is where that state lives". PAN-SVC-001's SECOND assertion
#: record now ships as two queries over `synched_to_a_configured_server` and
#: `time_source_in_force`, both filled from that very command - so a finding raised BY those
#: queries would have ended with a sentence saying the thing it was raised for is not assessed.
SYNC_CAVEAT = ("Whether a configured server is REACHABLE is not assessed; which source is "
               "keeping the clock is, from `show ntp`, and an appliance whose operational read "
               "was never taken is reported as anchored to nothing rather than as compliant")


def _time_source_sentence(obj) -> str:
    """Which class of source is keeping the clock. PAN-SVC-001's second assertion record.

    THE THREE MEMBERS ARE NOT THREE SPELLINGS OF ONE STATE. `not_synchronised_or_never_read`
    covers both "nothing upstream is keeping this clock" and "the operational read was never
    taken", deliberately and in that order of safety. The middle member is a clock that IS being
    kept, by an address no configured slot names - a different finding with a different
    remediation from a clock keeping its own local time.
    """
    if obj.time_source_in_force == TimeSourceInForce.SYNCHRONISED_TO_A_CONFIGURED_SERVER:
        return "and its clock is anchored to one of those configured servers"
    if obj.time_source_in_force == TimeSourceInForce.SYNCHRONISED_TO_AN_UNNAMED_SOURCE:
        return ("and its clock is anchored to a source this configuration does not name, so the "
                "time it writes on every log line comes from somewhere nobody here chose")
    return ("and nothing upstream is keeping its clock - it is either running on its own local "
            "time or the reading was never taken, which this reports the same way")


def _subject(obj) -> str:
    names = [name for name in (obj.primary_server, obj.secondary_server) if name]
    if not names:
        head = f"{obj.appliance} configures no NTP server"
    elif len(names) == 1:
        head = (f"{obj.appliance} configures one NTP server ({names[0]}) and no secondary, so it "
                f"has a single time source")
    else:
        head = f"{obj.appliance} configures two NTP servers ({', '.join(names)})"

    parts = [head]
    if not names:
        pass
    elif obj.all_servers_symmetric_key:
        algorithms = {a for a in (obj.primary_algorithm, obj.secondary_algorithm) if a}
        detail = "authenticated with a symmetric key"
        if algorithms:
            detail += f" ({', '.join(sorted(algorithms))})"
        parts.append(detail)
    else:
        # An autokey server is authenticated and still fails the control, so the sentence has to
        # distinguish it from one with no authentication at all - they are different fixes.
        by_type = []
        for name, auth in ((obj.primary_server, obj.primary_auth_type),
                           (obj.secondary_server, obj.secondary_auth_type)):
            if not name or auth == NtpSettings.AuthType.SYMMETRIC_KEY:
                continue
            by_type.append(f"{name} ({'no authentication' if auth in ('', 'none') else auth})")
        parts.append(f"time updates unauthenticated on {', '.join(by_type)}")
    parts.append(_time_source_sentence(obj))
    return "; ".join(parts) + f". {SYNC_CAVEAT}"


def build_ntp_settings_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="NTP",
    control_type=Control.ControlType.NTP_SETTINGS,
    finding_model=NtpSettingsFinding,
    link_model=NtpSettingsFindingControlQuery,
    subject_fk="ntp_settings",
    link_fk="ntp_settings_finding",
    queryset=lambda: NtpSettings.objects.select_related("appliance"),
    evaluate=evaluate_ntp_settings_control_queries,
    summary=build_ntp_settings_finding_summary,
    subject_name=lambda obj: str(obj.appliance),
)


def generate_ntp_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_ntp_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
