"""Finding generation for the management service-path control. PAN-SVC-006.

ONE SUBJECT IS ONE ENFORCEMENT POINT, so the sentence says WHICH half of the firewall it is
about before it says anything else: the firewall-wide paths, or one virtual system's own set.
The two halves are one control and ask different questions, and a reader given only "no path
set" cannot tell which.

THE SENTENCE NAMES WHAT IT CANNOT ATTEST. `services_originated` is a table in the normalizer -
five `deviceconfig` sources and twelve profile branches - and SEVENTEEN of the service
identifiers the device offers are deliberately unclaimed, because this configuration cannot show
that a flow for them exists. So "every originated service has a chosen path" is a statement
about the services this assessment can attribute, and the finding says so rather than implying
a complete inventory. Stage 7's `spec_gaps[3]` is the gap and names what would close it.

THE PER-SYSTEM COLUMNS ARE MEANINGLESS ON THE FIREWALL-WIDE ROW and hold their firing defaults
there by construction. The generator must therefore branch on `scope` and not on those columns,
and every query of the per-system half carries `scope eq vsys` for the same reason.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_service_route_control_queries
from assessments.models import Control, ServiceRouteFinding, ServiceRouteFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models.device_services import (
    PerSystemPathPosture,
    ServicePathPosture,
    ServiceRouteScope,
)
from optivedge_integrations.integrations.models import ServiceRoute


def _device_local(obj) -> str:
    originated = list(obj.services_originated or [])
    head = (f"{obj.appliance}: of the {len(originated)} management service(s) this assessment "
            f"can attribute to this firewall's configuration, "
            f"{obj.services_with_a_chosen_path} name a source interface and a source address")
    parts = [head]
    if obj.service_path_posture == ServicePathPosture.NO_PATH_SET:
        if not originated:
            parts.append("no service could be attributed at all, so nothing has been shown "
                         "about where this firewall's management traffic leaves from")
        else:
            parts.append("so at least one service it originates leaves by whatever route the "
                         "forwarding table happens to choose")
    elif obj.service_path_posture == ServicePathPosture.ONE_FAMILY_ONLY:
        parts.append("every one of them has an IPv4 path and at least one has no IPv6 path, so "
                     "a service that falls back to IPv6 leaves by an unchosen route")
    else:
        parts.append("each for both address families")
    return "; ".join(parts) + "."


def _per_vsys(obj) -> str:
    head = f"{obj.appliance} virtual system {obj.vsys_name or 'unnamed'}"
    parts = [head]
    if obj.per_system_path_posture == PerSystemPathPosture.NEITHER_RECORDED:
        parts.append("records no service-path choice of its own, so nothing says whether it is "
                     "inheriting the firewall-wide paths deliberately or whether nobody looked "
                     "- the device stores the choice and not the reasoning, and on this screen "
                     "the two are identical")
    elif obj.per_system_path_posture == PerSystemPathPosture.SOME_SERVICES_ONLY:
        parts.append(f"customises a path for {obj.services_with_a_chosen_path} of the "
                     f"{len(obj.services_originated or [])} service(s) attributed to it, so the "
                     f"rest fall back to the firewall-wide set without that being recorded")
    else:
        parts.append("has its service-path choice recorded for every service attributed to it")
    return "; ".join(parts) + "."


def _subject(obj) -> str:
    if obj.scope == ServiceRouteScope.VSYS:
        return _per_vsys(obj)
    return _device_local(obj)


def build_service_route_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj).rstrip("."), matched_queries)


SPEC = ObjectFindingSpec(
    label="management service paths",
    control_type=Control.ControlType.SERVICE_ROUTE,
    finding_model=ServiceRouteFinding,
    link_model=ServiceRouteFindingControlQuery,
    subject_fk="service_route",
    link_fk="service_route_finding",
    queryset=lambda: ServiceRoute.objects.select_related("appliance"),
    evaluate=evaluate_service_route_control_queries,
    summary=build_service_route_finding_summary,
    # `ServiceRoute` has no `name`, and the subject is an enforcement point rather than an
    # appliance: the partition name is what distinguishes two rows of one firewall.
    subject_name=lambda obj: (obj.vsys_name or str(obj.appliance))[:64],
    subject_scope=lambda obj: str(obj.appliance)[:128],
)


def generate_service_route_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_service_route_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
