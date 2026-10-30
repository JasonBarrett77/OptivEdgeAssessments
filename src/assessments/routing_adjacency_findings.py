"""Finding generation for the dynamic routing control. PAN-NET-007.

THE SUBJECT IS THE ADJACENCY AND NOT THE PROFILE. A profile is reusable, so reporting it once
would understate how many adjacencies are unauthenticated - and the adjacency is what an engineer
opens to attach authentication or a prefix ceiling.

WHAT THE SENTENCE MAY NOT CONTAIN AT ALL, from the standing ruling on stored secrets: the key. No
column holds the authentication secret or the OSPF password in plaintext or in the device's
stored form - they are encrypted-text and cannot be read back from the firewall - and nothing
here reaches a value through the finding's own prose either. What the finding reports is the
STRENGTH the attachment amounts to, computed from which child a profile carries. Whether a key is
unique to an adjacency or shared across sites is unanswerable from any read and is the engineer's
question.

FOUR MORE THINGS THE SENTENCE IS NOT ALLOWED TO SAY:

* THAT A PROFILE BEING ATTACHED IS AUTHENTICATION. Four states rank at the top severity with
  something attached or nothing to attach: a profile whose authentication is explicitly the
  disabled member, a cleartext password, a weaker attachment inside an area that has a stronger
  one, and no authentication at all.
* THAT THE AREA-WIDE OVERRIDE WAS SEEN HERE. `weaker_inner_attachment` is reachable ONLY on the
  Advanced Routing Engine: `action=complete` at an OSPF area returns exactly interface, range,
  type and virtual-link and no authentication node, identically on four appliances, so on the
  legacy engine no row can hold it. The sentence says which engine the row came from.
* THAT A PEER WITH A CEILING HAS A LIMIT. `max-prefixes` takes the keyword `unlimited` - the only
  member of its completion on all four appliances - so a peer storing it has a value and no
  ceiling, and a presence test would call it compliant while the firewall accepts the peer's
  whole table. Absence and the keyword mean the same thing to the firewall and are two different
  row states, which is why the verdict collapses them and the sentence names which one it found.
* THAT THE CEILING'S NUMBER IS RIGHT OR WRONG. A ceiling far above any plausible table size still
  enforces and takes the acceptable rank; what the number should be, and who agreed it with the
  peer's owner, is not recorded on the firewall.

AND ONE IT MUST SAY: that `warn_only` is not computable today. The peer's measured key set
carries connection-options and max-prefixes and no key saying whether the limit warns or stops,
so a peer whose ceiling only warns is stored as `enforcing` and produces NO finding. That is a
false pass this control cannot currently detect, and the sentence on an enforcing-looking peer
would be silence - so it is recorded here and in the stage 8 artifact rather than in prose
nobody reads.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_routing_adjacency_control_queries
from assessments.models import (
    Control, RoutingAdjacencyFinding, RoutingAdjacencyFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import PanOsRoutingAdjacency

R = PanOsRoutingAdjacency

STRENGTH_PROSE = {
    R.STRENGTH_NONE: (
        "no authentication is configured, so the adjacency accepts routes from anything that can "
        "reach the interface: one host on that segment can advertise a better path to any "
        "destination and pull the traffic for it through itself"),
    R.STRENGTH_EXPLICITLY_DISABLED: (
        "a profile is attached whose authentication is explicitly set to the disabled member the "
        "device offers, which reads as configured and authenticates nothing"),
    R.STRENGTH_WEAKER_INNER: (
        "an area-wide profile is configured and this attachment inside that area is weaker or "
        "absent, and the narrower attachment wins"),
    R.STRENGTH_CLEARTEXT: (
        "the password is sent in the clear, which authenticates the peer to anyone who can read "
        "the segment - the population this control is defending against"),
    R.STRENGTH_WEAK_DIGEST: (
        "the keyed digest uses an algorithm the vendor's own guidance elsewhere calls not "
        "secure, which raises the cost of the attack without removing it"),
}

LIMIT_PROSE = {
    R.LIMIT_NO_CEILING: (
        "no prefix ceiling is configured on this peer, so a peer that leaks its whole table "
        "fills the routing table until there is no room for the routes the business depends on"),
    R.LIMIT_UNLIMITED: (
        "the ceiling is configured as the keyword `unlimited`, which is a present literal that "
        "is the negation of the field's purpose and is indistinguishable for this control from "
        "setting no limit at all"),
    R.LIMIT_WARN_ONLY: (
        "the ceiling is configured to warn when it is reached rather than to stop, so it raises "
        "an alarm and takes the routes anyway"),
}


def _authentication(obj) -> list[str]:
    detail = STRENGTH_PROSE.get(obj.authentication_strength)
    if detail is None:
        # strong_digest and authenticated_and_encrypted are the two acceptable states.
        return [f"its authentication is recorded as `{obj.authentication_strength}`, which this "
                f"control accepts - this finding should not have been raised and the clause that "
                f"raised it is wider than the control"]
    engine = (f"read from the {obj.get_routing_engine_display()} routing tree"
              if obj.routing_engine != R.ENGINE_UNKNOWN
              else "which routing engine is in effect was never established on this appliance, "
                   "so which of the two trees this row's siblings came from is a reading nobody "
                   "has taken")
    attached = (f"the profile in use is `{obj.authentication_profile}`"
                if obj.authentication_profile else "no profile is attached")
    return [detail, f"{attached}, {engine}"]


def _prefix_limit(obj) -> list[str]:
    if obj.protocol != R.PROTOCOL_BGP:
        return []
    detail = LIMIT_PROSE.get(obj.prefix_limit_state)
    if detail is None:
        return []
    stored = (f"the stored `max-prefixes` value is `{obj.max_prefixes}`"
              if obj.max_prefixes is not None else "no `max-prefixes` key is stored")
    return [detail, f"{stored} - and a peer whose ceiling only WARNS is indistinguishable from "
                    f"one that enforces, because no measured key on this node says which"]


def _engineer_question(obj) -> list[str]:
    return ["what prefix count this peer should be expected to advertise, and who agreed it, is "
            "not recorded on the firewall; neither is whether the authentication key is unique "
            "to this adjacency, which no read can return"]


PARTS_BY_CONTROL = {
    "PAN-NET-007": (_authentication, _prefix_limit, _engineer_question),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"{obj.get_protocol_display()} adjacency {obj.adjacency_name} in router "
             f"{obj.router_name} on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(
            control_id, (_authentication, _prefix_limit, _engineer_question)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_routing_adjacency_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="routing adjacency",
    control_type=Control.ControlType.ROUTING_ADJACENCY,
    finding_model=RoutingAdjacencyFinding,
    link_model=RoutingAdjacencyFindingControlQuery,
    subject_fk="routing_adjacency",
    link_fk="routing_adjacency_finding",
    queryset=lambda: PanOsRoutingAdjacency.objects.select_related("appliance"),
    evaluate=evaluate_routing_adjacency_control_queries,
    summary=build_routing_adjacency_finding_summary,
    subject_name=lambda obj: obj.adjacency_name,
)


def generate_routing_adjacency_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_routing_adjacency_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
