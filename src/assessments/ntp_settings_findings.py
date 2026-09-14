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

SYNC_CAVEAT = ("Whether a configured server is reachable or synchronized is not assessed - this "
               "reads configuration, and `show ntp` is where that state lives")


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
