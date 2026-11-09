"""Finding generation for one appliance's management-plane addressing. PAN-MGT-004.

Minted by stage 8 of `management-services` on 2026-11-01.

WHAT THIS CONTROL CAN AND CANNOT ESTABLISH, which the sentence has to carry because the
alternative reading is a claim nobody measured. The firewall holds the management address, the
mask and whether a static default route leaves the segment. It holds NOTHING about whether the
networks those reach are ones the organization controls. So the graded column reports the
configuration's CONTRIBUTION to exposure and a finding here is not a statement that the plane is
reachable from anywhere in particular - stage 5 records the reachability half as not stored at
all, and the remediation the control carries is a reachability test a person runs.

THE DISPATCH DEFAULTS TO `()`, although one control uses this type today. That is the convention
the repository has now repaired twice elsewhere: a default that is this control's arms is how the
NEXT control on the type gets described with this control's claim. `zone_findings` defaults to
PAN-IOT-002's three arms and a different control reusing `zone` had its finding described with
PAN-IOT-002's claims, which is the measured instance.

THE DHCP CLASS IS THE ONE A READER MUST NOT MISREAD, and the sentence says so explicitly rather
than reporting the class alone. On a DHCP-addressed appliance the configuration holds neither an
address nor a mask nor a gateway while the plane is both addressed and routed - measured on two
lab PA-VMs, where `show system info` reported an address and a gateway at the same moment the
three configuration leaves answered `No such node`. So the reassuring posture, a private address
with no default route, would be reached by READING AN ABSENCE. The classifier tests the
allocation mode FIRST for exactly that reason, and this finding reports the posture as
unassessable from configuration rather than letting the absence read as the compliant state.

AND SUCH A ROW REPORTS AT A SEVERITY NOBODY ASSIGNED. Stage 3 left `dynamically_allocated`
UNRANKED; the control's assertion is that the posture is not the preferred one, which is true of
a DHCP-addressed plane, so the row fires, matches no calibration and
`derive_control_query_severity_value` falls back to the control's own default. The stage 8
artifact raises that as an open question for a person; this module's job is to make sure the
SENTENCE does not pretend the grade was earned.

NO REMEDIATION HERE IMPLIES CHANGING AN ADDRESS. Jason's standing restriction: no change to a
management IP address or to management-plane routing is to be proposed or implied.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_management_plane_addressing_control_queries)
from assessments.models import (
    Control, ManagementPlaneAddressingFinding,
    ManagementPlaneAddressingFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import ManagementPlaneAddressing


def _owner(obj) -> str:
    return str(obj.appliance)


def _posture(obj) -> list[str]:
    """PAN-MGT-004's assertion: the management plane's posture is not the preferred one.

    One arm per class, and the DHCP arm is the one that must not read as the compliant class.
    """
    posture = str(obj.exposure_posture or "")
    M = ManagementPlaneAddressing
    if posture == M.POSTURE_DYNAMIC:
        return [
            f"THE MANAGEMENT PLANE OF {_owner(obj)} TAKES ITS ADDRESS FROM A DHCP SERVER, so "
            f"the configuration holds no address, no mask and no default gateway while the "
            f"plane is both addressed and routed - the posture cannot be assessed from "
            f"configuration at all, and this is reported rather than read as the preferred "
            f"state, because the preferred state would be reached here by reading an absence",
            "the rank this class would carry was deliberately left unassigned, so the severity "
            "on this row is the control's own default and not a grade anybody gave this "
            "configuration",
        ]
    if posture == M.POSTURE_ROUTABLE:
        return [
            f"THE MANAGEMENT PLANE OF {_owner(obj)} IS ON A GLOBALLY ROUTABLE ADDRESS "
            f"({obj.management_ip_address or 'no address stored'}), so the configuration places "
            f"the administrative plane on an address the public internet can route to",
        ]
    if posture == M.POSTURE_PRIVATE_WITH_ROUTE:
        return [
            f"THE MANAGEMENT PLANE OF {_owner(obj)} IS PRIVATELY ADDRESSED "
            f"({obj.management_ip_address or 'no address stored'}) AND CARRIES A STATIC DEFAULT "
            f"ROUTE ({obj.static_default_gateway or 'no gateway stored'}), so it can reach, and "
            f"be reached through, whatever that route leads to - the catalog's preferred state "
            f"is the absence of the route",
        ]
    if posture == M.POSTURE_PRIVATE_NO_ROUTE:
        # Reachable only if a query ever matches this class, which none does today: stage 5
        # grades it `no_finding`. Kept so the arm exists rather than falling through to silence.
        return [
            f"the management plane of {_owner(obj)} is privately addressed with no static "
            f"default route, which is this control's preferred configuration",
        ]
    return [
        f"the management plane of {_owner(obj)} carries an exposure posture this build does not "
        f"recognize ({posture!r}), which is itself the finding: a class nobody classified has "
        f"not been shown to be safe",
    ]


def _not_established(obj) -> list[str]:
    """The half the configuration cannot deliver, on every row this control reports."""
    return [
        "WHAT THIS DOES NOT ESTABLISH: nothing on the firewall says whether the networks this "
        "plane reaches are ones the organization controls, so this is the configuration's "
        "contribution to exposure and not a demonstration that the plane is reachable - "
        "confirming that is a reachability test rather than a configuration read, and no "
        "remediation here is a change to a management address or to management-plane routing"
    ]


#: Keyed by control id, defaulting to `()`. See the module docstring.
PARTS_BY_CONTROL = {
    "PAN-MGT-004": (_posture, _not_established),
}


def _subject(obj, control_id: str = "") -> str:
    parts: list[str] = []
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    if not parts:
        return f"the management plane addressing of {_owner(obj)}"
    return "; ".join(parts)


def build_management_plane_addressing_finding_summary(obj, matched_queries) -> str:
    # The control id comes off the first matched query, which is safe because
    # `object_findings.generate_object_findings` iterates `for control in controls` and creates
    # the finding with that same control, so `matched_queries` holds one control's queries.
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="management plane addressing",
    control_type=Control.ControlType.MANAGEMENT_PLANE_ADDRESSING,
    finding_model=ManagementPlaneAddressingFinding,
    link_model=ManagementPlaneAddressingFindingControlQuery,
    subject_fk="management_plane_addressing",
    link_fk="management_plane_addressing_finding",
    queryset=lambda: ManagementPlaneAddressing.objects.select_related("appliance"),
    evaluate=evaluate_management_plane_addressing_control_queries,
    summary=build_management_plane_addressing_finding_summary,
    # The appliance. This model has no `name`, which the `ObjectFindingSpec.subject_name`
    # default would reach for and raise on inside generation rather than at import.
    subject_name=lambda obj: _owner(obj),
)

ManagementPlaneAddressingFindingRunResult = ObjectFindingRunResult


def generate_management_plane_addressing_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_management_plane_addressing_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
