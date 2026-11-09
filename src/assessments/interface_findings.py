"""Finding generation for the interface controls. PAN-NET-001 and PAN-NET-003.

TWO CONTROLS OVER ONE ROW, ASKING UNRELATED QUESTIONS, so `PARTS_BY_CONTROL` is load-bearing
rather than tidy: a residue finding that also reported what the port announces would send a
reader to the LLDP screen for a problem on the interface screen, and two controls reporting one
fact is two findings for one condition.

FOUR THINGS THE SENTENCE IS NOT ALLOWED TO SAY, each from a measurement upstream:

* THAT THE PORT IS OUT OF SERVICE. Nothing in the configuration says so, and stage 3 chose
  deliberately not to make it a clause: a port carrying an address and a zone may be a spare
  built in advance of a project, and a port carrying nothing may be a live uplink waiting on the
  far end. So the sentence reports what the port HOLDS and attaches the qualification, and the
  customer's own list is what narrows the rows at presentation time. Written the other way -
  as an applicability clause on a customer-supplied column - it would suppress the control
  wherever the answer had not arrived, which reads as careful and is how a control stops
  reporting.
* THAT THE PORT IS ADMINISTRATIVELY UP. `administrative_state_unknown` covers two states and
  the vocabulary has no member for the second: a port holding no residue whose administrative
  state is not readable, and a port holding no residue that IS readable as `auto` or `up`.
  `link_state` beside the verdict is what separates them - NULL against a value - and the
  sentence reads it rather than guessing. No port in the lab estate stored the key at all.
* THAT THE PORT IS FACING AN UNTRUSTED NETWORK. The configuration holds each port's zone,
  address and routing instance and nothing about where the cable goes, and the same LLDP setting
  is routine on an internal access port and serious on a transit port.
* WHAT A SUPPRESSED LLDP PROFILE STILL ANNOUNCES. The mandatory items - chassis identifier and
  port name - go out whenever the protocol transmits at all, whatever the profile suppresses, so
  every rank ADDS to that floor. And where no profile is bound the firewall uses its GLOBAL
  defaults, which no document in the vendor corpus describes - searched at rung 1 over all eight
  and read at rung 3 on the two sections that would carry it - so what such a port leaks is
  UNKNOWN rather than nothing, and the sentence says so.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_interface_control_queries
from assessments.models import Control, InterfaceFinding, InterfaceFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import Interface

#: What each residue rank costs someone who patches a cable into the port - read as what they
#: GAIN, which is the direction stage 3 graded in. The two unranked members are absent: the
#: baseline excludes them, so no finding carries one.
RESIDUE_PROSE = {
    Interface.RESIDUE_UNRESTRICTED_MANAGEMENT: (
        "it names an interface management profile with no permitted-source list, so the services "
        "that profile permits answer ANY host that can reach the port - an absent list means any "
        "source, and no credential or policy stands between the two"),
    Interface.RESIDUE_RESTRICTED_MANAGEMENT: (
        "it names an interface management profile whose permitted-source list is the only thing "
        "holding it, and that list was written for wherever the profile was first used rather "
        "than for this port"),
    Interface.RESIDUE_ZONE_MEMBERSHIP: (
        "it is a member of a security zone, so traffic entering on it is treated as that zone's "
        "traffic by every rule written for the zone"),
    Interface.RESIDUE_ADDRESS_ONLY: (
        "it holds a configured address, which makes it routable and reachable without granting a "
        "service or a policy position"),
}

#: What each announced-content rank puts on the wire, ABOVE the mandatory floor.
ANNOUNCED_PROSE = {
    Interface.ANNOUNCED_MANAGEMENT_ADDRESS: (
        "an address of the firewall's own management plane, which is the one thing the rest of "
        "the hardening program is about keeping unreachable"),
    Interface.ANNOUNCED_SYSTEM_DESCRIPTION: (
        "the software build, which tells whoever owns the next hop which advisories to read"),
    Interface.ANNOUNCED_HOSTNAME_OR_ROLE: (
        "the hostname and deployment role, placing the device in the estate's topology without "
        "granting reachability"),
    Interface.ANNOUNCED_PORT_AND_CHASSIS_ONLY: (
        "the mandatory chassis identifier and port name only - which still go out, because they "
        "are transmitted whenever the protocol transmits at all and no profile suppresses them"),
}


def _residue(obj) -> list[str]:
    detail = RESIDUE_PROSE.get(obj.out_of_service_residue)
    if detail:
        return [detail]
    if obj.out_of_service_residue == Interface.RESIDUE_ADMIN_STATE_UNKNOWN:
        if obj.link_state is None:
            # NOT "the port is shut down" and NOT "the port is up". The only oracle for the
            # configured administrative state conflates it with the physical link, and no port in
            # the lab estate stored the key, so this is an unknown and it fires.
            return ["it holds nothing a cable could use, and whether it is administratively shut "
                    "down was never established - no `link-state` key is stored on this port and "
                    "the only oracle for the configured state conflates it with the physical link"]
        return [f"it holds nothing a cable could use but is administratively `{obj.link_state}` "
                f"rather than shut down, so one patched cable brings it into service"]
    # A member the baseline was not expected to reach. Say so rather than printing a bare token:
    # a finding with no detail is indistinguishable from a finding about a sound port.
    return [f"its residue is recorded as `{obj.out_of_service_residue}`, which this control's "
            f"grading does not rank, so this finding carries the control's own severity"]


def _announced(obj) -> list[str]:
    floor = ("it transmits link-layer discovery, so the mandatory chassis identifier and port "
             "name go out on it whatever else is suppressed")
    content = obj.lldp_announced_content
    if content == Interface.ANNOUNCED_UNKNOWN_GLOBAL_DEFAULTS:
        bound = (f"the profile `{obj.lldp_profile_name}`" if obj.lldp_profile_name
                 else "no LLDP profile")
        return [f"{floor}; {bound} is bound, so the firewall uses its GLOBAL defaults and what "
                f"those defaults transmit is not documented anywhere in the vendor corpus - so "
                f"what this port leaks is unknown rather than nothing"]
    if content == Interface.ANNOUNCED_RECEIVE_ONLY_OR_OFF:
        # Reachable only if the baseline is widened; recorded so the sentence never claims a leak
        # it cannot support.
        return ["it is recorded as receive-only or off, which puts nothing on the wire - this "
                "finding should not have been raised and the clause that raised it is wider than "
                "the control"]
    detail = ANNOUNCED_PROSE.get(content)
    if detail:
        return [f"{floor}, and above that floor it announces {detail}"]
    return [f"{floor}; its announced content is recorded as `{content}`, which this control's "
            f"grading does not rank"]


def _untrusted_qualification(obj) -> list[str]:
    return ["whether this port faces a network whose adjacent devices the customer controls is "
            "not in the configuration and is not asserted here"]


def _out_of_service_qualification(obj) -> list[str]:
    return ["whether this port is in service is the customer's to confirm - the configuration "
            "cannot answer it and this control does not suppress itself waiting for the answer"]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. See this module's docstring: a finding describes
#: what ITS OWN control asserts, not everything the row happens to hold.
PARTS_BY_CONTROL = {
    "PAN-NET-001": (_residue, _out_of_service_qualification),
    "PAN-NET-003": (_announced, _untrusted_qualification),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"Interface {obj.name} on {obj.appliance}"]
    builders = PARTS_BY_CONTROL.get(control_id)
    if builders is None:
        # An unmapped control on this model: say everything rather than nothing.
        builders = (_residue, _announced, _out_of_service_qualification,
                    _untrusted_qualification)
    for build in builders:
        parts.extend(build(obj))
    return "; ".join(parts)


def build_interface_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="interface",
    control_type=Control.ControlType.FIREWALL_INTERFACE,
    finding_model=InterfaceFinding,
    link_model=InterfaceFindingControlQuery,
    subject_fk="interface",
    link_fk="interface_finding",
    queryset=lambda: Interface.objects.select_related("appliance"),
    evaluate=evaluate_interface_control_queries,
    summary=build_interface_finding_summary,
    subject_name=lambda obj: obj.name,
)


def generate_interface_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_interface_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
