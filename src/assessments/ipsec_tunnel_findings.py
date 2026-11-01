"""Finding generation for the IPSec tunnel controls. PAN-IPS-006, 007 and 008.

THE WHOLE DIFFICULTY IN THIS MODULE IS THE DIFFERENCE BETWEEN "OFF" AND "NOT DETERMINED", and
stage 5 names that distinction as the point of two of the three controls. `anti_replay` and
`tunnel_monitor_enable` are both `null=True`: the key is present and `no`, or the key is simply
ABSENT, and stage 4 measured NO implicit for either - so neither value may be materialised.
A NULL matches no positive comparison, so each control carries a second query on a non-nullable
`*_determined` companion, and the sentence here reads the ROW rather than the query that matched
so that it cannot drift from it.

    "we asked and it was off"      -> the key is present and false
    "we never asked"               -> the key is absent, and the companion fired

Writing the second as the first would raise a finding on behalf of a measurement nobody took.
Writing it as compliance would clear every tunnel that never mentions the field. Both are worse
than saying which one it is.

AND ONE SENTENCE THIS MODULE MUST NOT WRITE: that an unmonitored tunnel is visibly broken. Stage
5 measured that the firewall's own interface indicator only reddens when monitoring is ON and
the far end is unreachable - so a tunnel with monitoring off or never configured stays green
while nothing watches it, which is exactly why PAN-IPS-007 exists.

PAN-IPS-008 ASSERTS ON THE TRUE SIDE OF ITS COLUMN, which is the opposite direction from every
other verdict in this domain: a tunnel left switched off IS the finding. No applicability clause
suppresses a disabled tunnel anywhere in this module, and none should - all three controls are
written over tunnels nothing is routed through.

THE DISPATCH DEFAULT IS `()`. See the sibling module's docstring for why: eighteen of the
twenty-eight shipped generators that key a dispatch by control id default to another control's
arm tuple, and that describes one control's finding with a different control's claims.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_ipsec_tunnel_control_queries
from assessments.models import (
    Control, IpsecTunnelFinding, IpsecTunnelFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import IpsecTunnel

#: The sentence a `*_determined` false earns, parameterised by what was not determined. It says
#: WE NEVER ASKED and it never says the setting is off.
_NOT_DETERMINED = (
    "the `{key}` key is ABSENT from this tunnel's configuration, so what the device does with it "
    "here was NOT DETERMINED - this is not a report that {what} is switched off. Stage 4 measured "
    "no implicit value for the absent key in either direction, so neither reading may be assumed: "
    "treating it as off would raise a finding on a measurement nobody took, and treating it as on "
    "would clear every tunnel that never mentions the field"
)


def _anti_replay(obj) -> list[str]:
    if obj.anti_replay is True:
        return []
    if obj.anti_replay is None:
        return [_NOT_DETERMINED.format(key="anti-replay", what="replay protection")]
    return ["replay protection is explicitly DISABLED on this tunnel - the key is present and "
            "set to `no`, so a captured packet can be re-injected into the tunnel and the "
            "receiver will accept it"]


def _tunnel_monitor(obj) -> list[str]:
    if obj.tunnel_monitor_enable is True:
        return []
    if obj.tunnel_monitor_enable is None:
        return [_NOT_DETERMINED.format(key="tunnel-monitor/enable",
                                       what="far-end probing")
                + "; and a tunnel whose `tunnel-monitor` branch is absent entirely reads the "
                  "same way here as one whose branch exists with the key left out, which is "
                  "deliberate - neither has been shown to be monitored"]
    return ["far-end probing is explicitly DISABLED on this tunnel, so nothing on this firewall "
            "detects that the far end has stopped answering. The interface indicator does not "
            "help: it only reddens when monitoring is ON and the peer is unreachable, so an "
            "unmonitored tunnel stays green while carrying nothing"]


def _disabled(obj) -> list[str]:
    if not obj.is_disabled:
        return []
    return ["this tunnel is switched OFF - `disabled` is set - so it carries no traffic while "
            "remaining in the configuration as a complete, ready-to-enable peer relationship "
            "with whatever algorithms and credentials it was last given"]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. One control, one claim: a replay-protection
#: finding that also reported the monitoring state would be two controls' findings in one
#: sentence and would send a reader to two tabs of one dialog.
#:
#: PAN-IPS-009 IS DELIBERATELY ABSENT. Its tunnel half - a tunnel running on a crypto profile
#: nobody chose - is a query on this model, and the control ships as its PROFILE half because
#: `_CONTROL_TYPE_TARGET_MODEL` is one-to-one. The column that answers the tunnel-side question,
#: `effective_crypto_profile_chosen`, is registered in this model's compiler and carries no
#: query today; the stage 8 artifact for `ipsec-crypto` records the choice.
PARTS_BY_CONTROL = {
    "PAN-IPS-006": (_anti_replay,),
    "PAN-IPS-007": (_tunnel_monitor,),
    "PAN-IPS-008": (_disabled,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"IPSec tunnel {obj.tunnel_name} on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_ipsec_tunnel_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="IPSec tunnel",
    control_type=Control.ControlType.IPSEC_TUNNEL,
    finding_model=IpsecTunnelFinding,
    link_model=IpsecTunnelFindingControlQuery,
    subject_fk="ipsec_tunnel",
    link_fk="ipsec_tunnel_finding",
    queryset=lambda: IpsecTunnel.objects.select_related("appliance"),
    evaluate=evaluate_ipsec_tunnel_control_queries,
    summary=build_ipsec_tunnel_finding_summary,
    # SET EXPLICITLY: the spec's default is `obj.name` and this model keys on `tunnel_name`,
    # which fails at GENERATION time rather than at import.
    subject_name=lambda obj: obj.tunnel_name,
)


def generate_ipsec_tunnel_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_ipsec_tunnel_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
