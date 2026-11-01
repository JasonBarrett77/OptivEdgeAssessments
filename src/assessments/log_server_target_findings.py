"""Finding generation for one server entry of one log-settings server profile. PAN-LOG-002.

ONE CONTROL ON THIS TYPE TODAY, AND THE DISPATCH IS HERE ANYWAY. The type is minted for a model
that holds TWO of stage 5's subjects under one `kind` column, and only the syslog half has a
control: PAN-LOG-008's second group would have asserted the e-mail half and stage 5 left it in
its record's `undetermined` rather than in `clauses`. So a second control on this type is a
realistic near-term addition, and the thing that makes that safe is a dispatch whose default is
`()` rather than this control's arms. The repository has repaired the other shape twice.

WHY A SERVER ENTRY AND NOT A PROFILE IS THE SUBJECT. Transport is per SERVER: one syslog profile
can hold a TLS server and a UDP one, measured on the lab PA-5220, and the remediation is to
change that server's transport. A profile-keyed finding could not say which server sends in the
clear.

THE SUBJECT NAME IS `server_name` AND NOT `name`, WHICH THIS MODEL DOES NOT HAVE.
`ObjectFindingSpec.subject_name` defaults to `obj.name`, and a spec left at that default imports
cleanly, passes every check that reads the registry and raises `AttributeError` inside
`generate_object_findings` the first time a query matches a row. It is passed explicitly below.
`subject_scope` is passed too, because a server entry's name is unique only inside its parent
profile.

WHAT NO FINDING HERE CAN SAY:

- WHERE AN ENTRY WITH NO PORT KEY ACTUALLY SENDS. The stored port is a materialised implicit -
  514 on syslog, 25 on e-mail - and no oracle has watched an absent-port entry's datagrams on
  the wire. Nothing clauses on the port, so this is about what a finding PRINTS, and the
  sentence below therefore names the transport and not the port.
- WHETHER A TEMPLATE-SUPPLIED ENTRY CAN BE REMEDIATED HERE. A profile that exists only in a
  pushed Panorama template is stored as though the appliance defined it - there is no fourth
  scope token - and only the per-field provenance row says otherwise. An engineer sent to the
  firewall for one of those finds the grid read-only.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_log_server_target_control_queries
from assessments.models import (
    Control, LogServerTargetFinding, LogServerTargetFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import LogServerTarget


def _where(obj) -> str:
    """The appliance, the config scope and the parent profile - what a reader needs to find it."""
    scope = f"{obj.scope}:{obj.vsys_name}" if obj.vsys_name else obj.scope
    return f"{obj.appliance} {scope} profile {obj.profile_name}"


def _cleartext_transport(obj) -> list[str]:
    """PAN-LOG-002's only assertion: the collector is reached over an unencrypted transport."""
    if obj.transport == LogServerTarget.Transport.SSL:
        return []
    address = obj.server_address or "an address the configuration does not record"
    transport = obj.transport or "no recorded transport"
    parts = [
        f"syslog server {obj.server_name} on {_where(obj)} sends to {address} over "
        f"{transport}, WHICH DOES NOT ENCRYPT - so the log stream, and everything a log line "
        f"discloses about this network, crosses it in the clear",
    ]
    if obj.transport == LogServerTarget.Transport.UDP:
        parts.append(
            "UDP is also unacknowledged, so neither the content nor the FACT of delivery is "
            "protected: a collector that stops listening is indistinguishable from one that is")
        parts.append(
            "and UDP is the value an entry holding only its address reports - measured on two "
            "oracles, the grid and the wire - so an unconfigured transport lands here rather "
            "than reading as unknown")
    elif obj.transport == LogServerTarget.Transport.TCP:
        parts.append(
            "TCP acknowledges delivery and still carries the content in the clear, which is why "
            "this reports one rank below the unacknowledged transport rather than passing")
    parts.append(
        "THE VENDOR'S OWN NAME FOR THE SECURE TRANSPORT IS `SSL` AND NOT `TLS` on this node - a "
        "write of `TLS` is refused - so the remediation is `set ... server <name> transport SSL`")
    parts.append(
        "THE PORT IS NOT ASSERTED. A secure session on another agreed port still satisfies this "
        "control, and the vendor's own instruction makes the number an agreement between two "
        "systems rather than a setting with a right value")
    return parts


#: Keyed by control id, defaulting to `()`. See the module docstring: a second control on this
#: type is a realistic addition and a default of this control's arms is how it would be
#: described with the wrong claim.
PARTS_BY_CONTROL = {
    "PAN-LOG-002": (_cleartext_transport,),
}


def _subject(obj, control_id: str = "") -> str:
    parts: list[str] = []
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    if not parts:
        kind = obj.get_kind_display() if obj.kind else "log"
        return f"{kind.lower()} server {obj.server_name} on {_where(obj)}"
    return "; ".join(parts)


def build_log_server_target_finding_summary(obj, matched_queries) -> str:
    # The control id comes off the first matched query, which is safe because
    # `object_findings.generate_object_findings` iterates `for control in controls` and creates
    # the finding with that same control, so `matched_queries` holds one control's queries.
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="log server target",
    control_type=Control.ControlType.LOG_SERVER_TARGET,
    finding_model=LogServerTargetFinding,
    link_model=LogServerTargetFindingControlQuery,
    subject_fk="log_server_target",
    link_fk="log_server_target_finding",
    queryset=lambda: LogServerTarget.objects.select_related("appliance"),
    evaluate=evaluate_log_server_target_control_queries,
    summary=build_log_server_target_finding_summary,
    # The server entry's own name. NOT `obj.name`, which this model does not have - the default
    # would raise inside generation rather than at import.
    subject_name=lambda obj: obj.server_name,
    # The parent profile and the scope, because a server name is unique only inside its profile.
    subject_scope=lambda obj: _where(obj)[:128],
)

LogServerTargetFindingRunResult = ObjectFindingRunResult


def generate_log_server_target_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_log_server_target_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
