"""Finding generation for the tunnel inspection coverage control. PAN-NET-006.

THE SUBJECT IS AN ENFORCEMENT POINT'S WHOLE RULEBASE, AS A VERDICT, because the commonest
failing state is that no rule exists and a per-rule finding cannot report it. An engineer fixing
it does not open a rule either.

FOUR THINGS THE SENTENCE IS NOT ALLOWED TO SAY, each from a measurement:

* THAT A TUNNEL ACTUALLY TRANSITS THIS FIREWALL. That is traffic and not configuration. The
  counters that LOOK like an answer are not one - `num-gtpu-active` and `num-active` read zero
  on all four lab appliances, which is a lab with no traffic rather than an estate with no
  tunnels - so the verdict fires on a vsys with no policy whether or not a tunnel has ever
  crossed it, and the sentence attaches the question instead of answering it.
* THAT THE PRESENCE OF A RULE IS COVERAGE. A rule that exists can be switched off, can cover
  some transiting protocols and not others, can be scoped to zone pairs the tunnels do not
  traverse, and can open one level of encapsulation where the tunnels are nested two deep.
* THAT A VSYS COVERED FROM PANORAMA HAS NO POLICY. The merge view does NOT carry a device
  group's tunnel-inspect rulebase, so counting rules from that read alone reports this control's
  WORST rank on exactly the estates whose coverage is centrally managed. `scope` is what says
  which copy a row is about, and the sentence prints it.
* THAT ACCELERATION MAKES THE FIREWALL COMPLIANT. Where tunnel acceleration is on the vendor
  says a GTP-U inspection rule is not required - but that exemption is PER PROTOCOL, and an
  absent acceleration node asserts ENABLED, so reading it as a blanket exemption would switch
  the control off on every appliance that has never touched the setting. The sentence reports
  the setting and applies no exemption.

AND ONE IT MUST SAY: that four of the eight ranks cannot be computed from configuration at all.
`protocol_subset`, `zone_pair_gap`, `single_level_only` and `overlay_id_scoped` each need to know
what transited, so a row reaching `coverage_unverified_without_traffic_answer` is the honest end
of what a configuration-only reading can establish - rules exist and are enabled, and whether
they cover what actually crosses the firewall is unknown. Under the pipeline's own rule an
unknown fires, and it fires at the control's own severity because an unknown has no rank.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_tunnel_inspection_control_queries
from assessments.models import (
    Control, TunnelInspectionFinding, TunnelInspectionFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import PanOsTunnelInspectionCoverage

T = PanOsTunnelInspectionCoverage

STATE_PROSE = {
    T.STATE_NO_POLICY: (
        "no tunnel inspection policy at all: every tunnel crossing this enforcement point is "
        "reported as one permitted session and anything inside it reaches its destination "
        "unexamined"),
    T.STATE_ALL_RULES_DISABLED: (
        "every tunnel inspection rule it holds is switched off, which is indistinguishable in "
        "effect from holding none"),
    T.STATE_PROTOCOL_SUBSET: (
        "its rules cover some of the transiting tunnel protocols and not others, so the "
        "uncovered protocol's traffic is allowed on the strength of the outer header alone"),
    T.STATE_ZONE_PAIR_GAP: (
        "its rules cover the protocols but are scoped to zone pairs that do not include every "
        "pair the tunnels traverse"),
    T.STATE_SINGLE_LEVEL_ONLY: (
        "its rules cover one level of encapsulation where the tunnels are nested two deep, so "
        "the inner tunnel's contents are never matched"),
    T.STATE_OVERLAY_ID_SCOPED: (
        "its rules name the overlay network identifiers they inspect, where tunnels on other "
        "identifiers also transit"),
    T.STATE_UNVERIFIED: (
        "rules exist and are enabled, and whether they cover what actually transits cannot be "
        "computed from configuration - four of this control's ranks need to know what crossed "
        "the firewall, so this is the honest end of a configuration-only reading rather than a "
        "clean result"),
}


def _coverage(obj) -> list[str]:
    detail = STATE_PROSE.get(obj.tunnel_inspection_coverage_state)
    if detail is None:
        if obj.tunnel_inspection_coverage_state == T.STATE_FULLY_OPENED:
            return ["it is recorded as fully opened, which is this control's acceptable state - "
                    "this finding should not have been raised and the clause that raised it is "
                    "wider than the control"]
        return [f"its coverage is recorded as "
                f"`{obj.tunnel_inspection_coverage_state}`, which this control's grading does "
                f"not rank"]
    counted = (f"{obj.tunnel_inspect_rule_count} rule(s) counted at `{obj.scope}` scope"
               if obj.tunnel_inspect_rules_collected
               else f"the rulebase at `{obj.scope}` scope is not recorded as collected, so the "
                    f"count of {obj.tunnel_inspect_rule_count} is not evidence")
    return [detail, counted]


def _acceleration(obj) -> list[str]:
    if obj.tunnel_acceleration:
        return ["tunnel acceleration is on for this appliance, which the vendor says removes the "
                "requirement for an inspection rule FOR ONE PROTOCOL only - the exemption is per "
                "protocol and is not applied here, because an absent acceleration node asserts "
                "enabled and a blanket reading would switch this control off estate-wide"]
    return ["tunnel acceleration is off for this appliance, so no protocol is exempt"]


def _traffic_qualification(obj) -> list[str]:
    return ["which tunnel protocols and zone pairs actually transit this enforcement point is "
            "traffic rather than configuration, is not held on any row, and narrows which gaps "
            "this is scored against without turning the finding off"]


PARTS_BY_CONTROL = {
    "PAN-NET-006": (_coverage, _acceleration, _traffic_qualification),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"Tunnel inspection coverage for {obj.scope}:{obj.vsys_name} on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(
            control_id, (_coverage, _acceleration, _traffic_qualification)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_tunnel_inspection_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="tunnel inspection coverage",
    control_type=Control.ControlType.TUNNEL_INSPECTION,
    finding_model=TunnelInspectionFinding,
    link_model=TunnelInspectionFindingControlQuery,
    subject_fk="tunnel_inspection_coverage",
    link_fk="tunnel_inspection_finding",
    queryset=lambda: PanOsTunnelInspectionCoverage.objects.select_related("appliance"),
    evaluate=evaluate_tunnel_inspection_control_queries,
    summary=build_tunnel_inspection_finding_summary,
    subject_name=lambda obj: obj.vsys_name,
    #: The one subject in this domain whose name can collide: the same vsys has a different
    #: answer depending on which config subtree its rules came from.
    subject_scope=lambda obj: obj.scope,
)


def generate_tunnel_inspection_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_tunnel_inspection_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
