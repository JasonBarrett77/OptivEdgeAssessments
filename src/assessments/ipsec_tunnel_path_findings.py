"""Finding generation for the IPSec tunnel path. PAN-IKE-002 to -005 and PAN-IPS-001 to -005.

ONE FINDING PER TUNNEL AND NOT PER PROFILE, which is the whole reason this module exists. Jason,
2026-11-04: *"A weak profile use on one IPSec tunnel should not receive the same treatment as a
weak profile used on 1000 IPSec tunnels. The best way to accomplish this is to raise a finding per
effected tunnel."* So one weak crypto profile referenced by six tunnels earns six findings, each
naming its own tunnel, and the count on the findings page is the reach of the weakness rather than
the number of objects that hold it.

EVERY SENTENCE HERE NAMES THE PLACE BEFORE THE FAULT - the tunnel, the gateway it runs through and
the profile the fault is in - because a path finding is read by somebody who has to go and change
one of three objects, and the one to change differs by control: PAN-IKE-002 to -005 are the IKE
crypto profile, PAN-IPS-001 to -005 are the IPSec crypto profile.

THE ALGORITHM HALF OF EVERY SENTENCE IS THE PROFILE GENERATOR'S OWN. This module writes the
PLACE - the tunnel, the gateway, and which profile stands behind each half of the path - and
defers the reading of the proposal itself to `ike_crypto_profile_findings` and
`ipsec_crypto_profile_findings`, whose builders run on a path row unchanged. So a path finding
says the same thing about a weak proposal that the profile finding said, with a place in front of
it, and the measurements those sentences carry cannot drift from this one.

THE UNRESOLVED STATES SAY SO IN TERMS, and they are the lab's commonest state rather than an edge
case: three of pan-fw-111's four tunnels name no gateway at all and no crypto profile, which Jason
ruled on - *"IKE Crypto is a required field on IPSec Tunnel. If the value is missing, that is an
invalid configuration"* - and the fourth names a gateway with a profile. An unresolved path never
reports a weak ALGORITHM, because no algorithm was read; it reports that nothing stands behind the
path, which is a different defect with a different remedy.

THE DISABLED FLAG IS NOT READ ANYWHERE IN THIS MODULE. Jason, 2026-11-04: *"The 'disabled' value
is ignored. So give a tunnel/gateway the same treatment regardless of the disabled state."*

THE DISPATCH DEFAULT IS `()`, as on the sibling modules: a control id with no arm here contributes
the place and nothing else, rather than borrowing another control's claims.
"""

from __future__ import annotations

from assessments import ike_crypto_profile_findings as ike_profile
from assessments import ipsec_crypto_profile_findings as ipsec_profile
from assessments.control_queries import evaluate_ipsec_tunnel_path_control_queries
from assessments.models import (
    Control, IpsecTunnelPathFinding, IpsecTunnelPathFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import IpsecTunnelPath

_RESOLUTION = IpsecTunnelPath.Resolution

#: What an unresolved IKE crypto profile means, by WHY it does not resolve. Three states and three
#: remedies: there is no gateway on the path, the gateway names no profile, or it names one this
#: appliance does not hold.
_IKE_CRYPTO_UNRESOLVED = {
    _RESOLUTION.NO_GATEWAY: (
        "this tunnel names NO IKE GATEWAY, so no phase 1 proposal stands behind it at all - an "
        "invalid configuration rather than a weak one, and not reachable through the dialog, "
        "which requires a gateway selection"),
    _RESOLUTION.NOT_NAMED: (
        "the IKE gateway on this path names NO IKE CRYPTO PROFILE for the version it "
        "negotiates, so what it proposes in phase 1 is not stated anywhere in the configuration"),
    _RESOLUTION.MISSING: (
        "the IKE crypto profile this path's gateway names does NOT EXIST on this appliance, so "
        "the reference dangles and nothing here states what phase 1 proposes"),
}

#: And for the IPSec crypto profile. The `default` case is its own: the name resolves or it does
#: not, and either way the content is unknowable from here.
_IPSEC_CRYPTO_UNRESOLVED = {
    _RESOLUTION.DEFAULT_ASSUMED: (
        "this tunnel stores NO IPSec crypto profile reference, so it runs on whatever PAN-OS "
        "renders as `default` - and what that offers cannot be read from the configuration. "
        "Jason's ruling of 2026-11-04 is that this fails rather than passes: \"We can't know what "
        "the 'default' value means, so we should assume that it fails if it is default, "
        "unspecified, or otherwise unknown\""),
    _RESOLUTION.NOT_NAMED: (
        "this tunnel names NO IPSec crypto profile, so nothing in the configuration states what "
        "it proposes for the payload"),
    _RESOLUTION.MISSING: (
        "the IPSec crypto profile this tunnel names does NOT EXIST on this appliance, so the "
        "reference dangles and nothing here states what the payload is protected with"),
    _RESOLUTION.RESOLVED: (
        "this tunnel names the profile `default`, which resolves to an entry on this appliance - "
        "but a profile called `default` says nothing about what it offers, and the entry is "
        "ordinary writable configuration rather than anything PAN-OS shipped, so it is treated as "
        "unknown"),
}


def _place(obj) -> str:
    """Where the engineer goes, before anything about what is wrong there."""
    if not obj.tunnel_name:
        return (f"IKE gateway {obj.gateway_name} on {obj.appliance}, which NO IPSEC TUNNEL ON "
                f"THIS APPLIANCE NAMES - so this path carries no traffic today and the gateway "
                f"stands ready for whichever tunnel names it next")
    place = f"IPSec tunnel {obj.tunnel_name} on {obj.appliance}"
    if obj.gateway_name and obj.gateway_resolution == _RESOLUTION.RESOLVED:
        return f"{place}, through IKE gateway {obj.gateway_name}"
    if obj.gateway_name:
        return (f"{place}, which names the IKE gateway {obj.gateway_name} - A GATEWAY THIS "
                f"APPLIANCE DOES NOT HOLD")
    return place


def _ike_crypto(obj) -> list[str]:
    """The phase 1 profile half of the place, or why there is not one."""
    if obj.ike_crypto_unresolved:
        return [_IKE_CRYPTO_UNRESOLVED.get(
            obj.ike_crypto_resolution,
            "no IKE crypto profile stands behind this path")]
    return [f"running the IKE crypto profile {obj.ike_crypto_profile_name}"]


def _ipsec_crypto(obj) -> list[str]:
    """The phase 2 profile half, or why there is not one."""
    if obj.ipsec_crypto_unresolved:
        return [_IPSEC_CRYPTO_UNRESOLVED.get(
            obj.ipsec_crypto_resolution,
            "no IPSec crypto profile stands behind this path")]
    return [f"running the IPSec crypto profile {obj.ipsec_crypto_profile_name}"]


#: THE ALGORITHM SENTENCES ARE THE TWO PROFILE GENERATORS' OWN, IMPORTED RATHER THAN REWRITTEN.
#: Each of those builders reads the profile's offer sets and verdict columns off the row it is
#: handed, and the path carries every one of those columns under the source model's own field
#: name - so they run on a path unchanged. Each also holds a measurement this module must not
#: lose: that a lifetime nobody read is not a long one, that `0` for the authentication multiple
#: disables re-authentication rather than shortening it, that `non-auth` means opposite things
#: with and without an AEAD cipher, and that a post-quantum key-agreement name has no severity
#: rank at all. A second phrasing here would be a second set of claims to keep true.
_IKE_PARTS = {
    "PAN-IKE-002": ike_profile._dh_group,
    "PAN-IKE-003": ike_profile._encryption,
    "PAN-IKE-004": ike_profile._hash,
}

_IPSEC_PARTS = {
    "PAN-IPS-001": ipsec_profile._branch,
    "PAN-IPS-002": ipsec_profile._encryption,
    "PAN-IPS-003": ipsec_profile._integrity,
    "PAN-IPS-004": ipsec_profile._dh_group,
    "PAN-IPS-005": ipsec_profile._lifetime,
}


def _ike_algorithms(control_id):
    """One IKE control's algorithm sentence, silent where no profile stands behind the path."""
    builder = _IKE_PARTS[control_id]

    def build(obj) -> list[str]:
        return [] if obj.ike_crypto_unresolved else builder(obj)
    return build


def _ike_lifetime(obj) -> list[str]:
    """PAN-IKE-005's two halves, both of the profile generator's own."""
    if obj.ike_crypto_unresolved:
        return []
    return ike_profile._lifetime(obj) + ike_profile._reauth(obj)


def _ipsec_algorithms(control_id):
    """One IPSec control's payload sentence, silent where no profile stands behind the path."""
    builder = _IPSEC_PARTS[control_id]

    def build(obj) -> list[str]:
        return [] if obj.ipsec_crypto_profile_id is None else builder(obj)
    return build


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. One control, one claim - and one profile: an IKE
#: control's finding names the IKE crypto profile and says nothing about the payload proposal,
#: because the two live in different objects under different menus and a reader sent to both has
#: been told to fix two things to clear one finding.
PARTS_BY_CONTROL = {
    "PAN-IKE-002": (_ike_crypto, _ike_algorithms("PAN-IKE-002")),
    "PAN-IKE-003": (_ike_crypto, _ike_algorithms("PAN-IKE-003")),
    "PAN-IKE-004": (_ike_crypto, _ike_algorithms("PAN-IKE-004")),
    "PAN-IKE-005": (_ike_crypto, _ike_lifetime),
    "PAN-IPS-001": (_ipsec_crypto, _ipsec_algorithms("PAN-IPS-001")),
    "PAN-IPS-002": (_ipsec_crypto, _ipsec_algorithms("PAN-IPS-002")),
    "PAN-IPS-003": (_ipsec_crypto, _ipsec_algorithms("PAN-IPS-003")),
    "PAN-IPS-004": (_ipsec_crypto, _ipsec_algorithms("PAN-IPS-004")),
    "PAN-IPS-005": (_ipsec_crypto, _ipsec_algorithms("PAN-IPS-005")),
}


def _subject(obj, control_id: str) -> str:
    parts = [_place(obj)]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_ipsec_tunnel_path_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


def path_subject_name(obj) -> str:
    """The name frozen onto the finding, and it has to carry BOTH ends of the path.

    A tunnel alone would collide across the two rows of a tunnel naming two gateways, and an
    orphan-gateway row has no tunnel to be named by at all.
    """
    if not obj.tunnel_name:
        return f"(no tunnel) / {obj.gateway_name}"
    if not obj.gateway_name:
        return f"{obj.tunnel_name} / (no gateway)"
    return f"{obj.tunnel_name} / {obj.gateway_name}"


SPEC = ObjectFindingSpec(
    label="IPSec tunnel path",
    control_type=Control.ControlType.IPSEC_TUNNEL_PATH,
    finding_model=IpsecTunnelPathFinding,
    link_model=IpsecTunnelPathFindingControlQuery,
    subject_fk="ipsec_tunnel_path",
    link_fk="ipsec_tunnel_path_finding",
    queryset=lambda: IpsecTunnelPath.objects.select_related("appliance"),
    evaluate=evaluate_ipsec_tunnel_path_control_queries,
    summary=build_ipsec_tunnel_path_finding_summary,
    # SET EXPLICITLY: the spec's default is `obj.name` and this model has no `name` column.
    subject_name=path_subject_name,
)


def generate_ipsec_tunnel_path_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_ipsec_tunnel_path_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
