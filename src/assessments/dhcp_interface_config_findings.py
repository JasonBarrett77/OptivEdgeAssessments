"""Finding generation for the interface DHCP control. PAN-NET-004.

THE FINDING NAMES THE CONFIGURATION AND NOT THE PORT, because the configuration is what the
engineer deletes. A row exists only where `network/dhcp/interface` carries an entry, so this
control's passing state for its server half is the ABSENCE of the row - and that is why the
sentence never says "DHCP is correctly absent here": there is no row on which to say it.

THREE THINGS THE SENTENCE IS NOT ALLOWED TO SAY:

* THAT `auto` IS A SAFE MIDDLE SETTING. The vendor's own gloss makes it an enabled server:
  "Auto mode enables the server and disables it if another DHCP server is detected on the
  network". So it is a serving server with a back-off, and it is ranked level with `enabled`.
* THAT A MISSING MODE KEY MEANS THE SERVER IS OFF. `dhcp_server_mode` is null where
  `server/mode` is absent and nobody has established whether the key is mandatory on a bare
  server branch. Two of its three values ENABLE the server, so the sentence says the mode was
  not recorded rather than naming one - and such a row falls into none of the three graded
  placements, so it is reported by the baseline alone.
* THAT THE RELAY ANSWER COVERS BOTH ADDRESS FAMILIES EQUALLY. The two families are independent
  switches and the IPv6 family has NO column: stage 4's measured key set for this node carries
  `relay`, `relay/ip`, `relay/ip/enabled` and `relay/ip/server` and no ipv6 sibling. The
  verdict reads both families, the stored switch answers for IPv4 only, and a relay configured
  for IPv6 alone reads `not_configured` and produces no finding. That is the one place in this
  domain where a gap produces silence rather than a firing default, and the sentence says the
  verdict covers one measured family.

AND ONE IT MUST SAY: that a configured-and-switched-off relay or server is one commit from live.
Stage 3 ranks both as findings for exactly that reason - the pool, the gateway, the resolver and
the relayed server addresses are all still written down on a port that should carry none of it.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_dhcp_interface_config_control_queries
from assessments.models import (
    Control, DhcpInterfaceConfigFinding, DhcpInterfaceConfigFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import PanOsDhcpInterfaceConfig

SERVER_MODE_PROSE = {
    PanOsDhcpInterfaceConfig.MODE_ENABLED: (
        "serving: every host that appears on that segment gets a gateway, a resolver, a time "
        "source and a name suffix of this firewall's choosing"),
    PanOsDhcpInterfaceConfig.MODE_AUTO: (
        "set to `auto`, which the vendor describes as enabling the server and disabling it only "
        "if another DHCP server is detected - a serving server with a back-off and not a safe "
        "middle setting"),
    PanOsDhcpInterfaceConfig.MODE_DISABLED: (
        "switched off but fully configured: the pool, the gateway and the resolver are all still "
        "written down and one commit away from being handed out"),
}

RELAY_PROSE = {
    PanOsDhcpInterfaceConfig.RELAY_RELAYING: (
        "it relays address requests on at least one address family, so anything able to "
        "broadcast on that wire has a delivered path to internal address servers it could never "
        "have routed to - and the internal gateway, resolver and time-server addresses come back "
        "out to it"),
    PanOsDhcpInterfaceConfig.RELAY_CONFIGURED_AND_OFF: (
        "it carries a relay configuration with every switch off, so the relayed server addresses "
        "are recorded on this port and one commit from being used"),
}


def _server(obj) -> list[str]:
    if not obj.dhcp_server_configured:
        return []
    detail = SERVER_MODE_PROSE.get(obj.dhcp_server_mode)
    if detail is None:
        # NOT "the server is off". Two of the three modes enable it and the key was not read.
        return ["it carries a DHCP SERVER branch whose `mode` key is not recorded, so whether it "
                "is serving was not established - the branch itself is what this control asserts "
                "against, in any mode"]
    return [f"it carries a DHCP SERVER branch, {detail}"]


def _relay(obj) -> list[str]:
    detail = RELAY_PROSE.get(obj.dhcp_relay_state)
    if detail is None:
        return []
    family = ("the IPv4 switch reads "
              f"`{obj.dhcp_relay_ipv4_enabled}`" if obj.dhcp_relay_ipv4_enabled is not None
              else "the IPv4 switch was not recorded")
    return [f"{detail} - {family}, and the IPv6 family is read for this verdict but has no "
            f"column of its own, so a relay configured for IPv6 alone would not appear here"]


def _untrusted_qualification(obj) -> list[str]:
    return ["whether this interface faces a network the customer controls is not in the "
            "configuration and is not asserted here"]


#: Both halves belong to ONE control, so there is no per-control split to make - and the sentence
#: carries whichever halves the row actually violates.
PARTS_BY_CONTROL = {
    "PAN-NET-004": (_server, _relay, _untrusted_qualification),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"DHCP configuration on {obj.interface_name} on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(
            control_id, (_server, _relay, _untrusted_qualification)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_dhcp_interface_config_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="DHCP interface configuration",
    control_type=Control.ControlType.DHCP_INTERFACE_CONFIG,
    finding_model=DhcpInterfaceConfigFinding,
    link_model=DhcpInterfaceConfigFindingControlQuery,
    subject_fk="dhcp_interface_config",
    link_fk="dhcp_interface_config_finding",
    queryset=lambda: PanOsDhcpInterfaceConfig.objects.select_related("appliance"),
    evaluate=evaluate_dhcp_interface_config_control_queries,
    summary=build_dhcp_interface_config_finding_summary,
    subject_name=lambda obj: obj.interface_name,
)


def generate_dhcp_interface_config_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_dhcp_interface_config_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
