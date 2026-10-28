"""Finding generation for the IKE gateway controls. PAN-IKE-001, 006 to 009.

FOUR SENTENCES THIS GENERATOR IS NOT PERMITTED TO WRITE, each refused on a measurement rather
than on taste:

* "THIS GATEWAY NEGOTIATES IKEv1." The configured version is not the negotiated one. On
  `ikev2-preferred` the gateway negotiates version 2 with any peer that supports it and falls
  back to version 1 for one that declines, and the operational read that would say which a
  tunnel is actually running - `show vpn ike-sa` - is refused to this project with HTTP 403. So
  the sentence says what the gateway is CONFIGURED to negotiate and stops there.
* "THE VERSION IS IKEv1" WHERE NO VERSION KEY EXISTS. `ike_version` holds the empty string for
  an absent or unread key, which is what makes the control fire on it. What the device does in
  that state is UNMEASURED and the two available readings disagree - stage 4 has the schema
  default at `ikev2` on one release and an ikemgr phase-1 abort naming the IKEv1 section on a
  keyless gateway. The sentence reports the absence.
* "THIS GATEWAY CANNOT DETECT A DEAD PEER" on the version-2 branch. Help p.652: "The IKEv2
  Liveness Check is always on; all IKEv2 packets serve the purpose of a liveness check." What
  is true is that it sends no IDLE probe, which is a narrower claim than the version-1 branch's
  and is the whole difference between this control's two halves.
* "THE PEER IS AUTHENTICATED BY A PRE-SHARED KEY" without saying where that was read. The choice
  is expressed by WHICH OF TWO SUBTREES EXISTS, the two are exclusive, and the exclusion is
  enforced by SILENT REPLACEMENT at the write: staging a certificate profile over a committed
  pre-shared key deletes the PSK branch from the candidate while the running view still shows
  it. This domain reads the candidate, so the answer is the STAGED one and the sentence says so.

AND THE ONE PLACE THIS GENERATOR SAYS MORE THAN ITS COLUMN CAN.
`relies_on_factory_named_proposal` is true both where a pointer names a factory-shipped proposal
and where NEITHER pointer is set, and stage 5 records that a finding "cannot distinguish" them.
The COLUMN cannot; the ROW can, because both pointer names are on it. So the sentence
distinguishes the two cases, which it must: they carry different remediations - repoint the
gateway, against work out what proposal an unpointed gateway is consuming.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_ike_gateway_control_queries
from assessments.models import Control, IkeGatewayFinding, IkeGatewayFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import IkeGateway

#: The three entries a firewall ships with. Not evidence of weakness - the assertion is about
#: provenance and ownership, and an estate may have hardened `default` in place.
FACTORY_PROFILE_NAMES = ("default", "Suite-B-GCM-128", "Suite-B-GCM-256")

VERSION_PROSE = {
    "ikev1": "configured for IKE version 1 only, so no version 2 exchange is possible on it",
    "ikev2-preferred": ("configured to prefer IKE version 2 while still completing a version 1 "
                        "exchange with any peer that declines version 2"),
    "ikev2": "configured for IKE version 2 only",
}


def _version(obj) -> list[str]:
    if not obj.ike_version:
        return ["no protocol version key is configured, so which version this gateway "
                "negotiates is not established from its configuration - and what the device "
                "does with the key absent is unmeasured"]
    if obj.ike_version == "ikev2":
        return []
    return [VERSION_PROSE.get(obj.ike_version, f"IKE version {obj.ike_version}")]


def _exchange_mode(obj) -> list[str]:
    if obj.ikev1_exchange_mode == "auto":
        return ["the version 1 exchange mode is `auto`, which is not a middle setting: the "
                "device accepts both main-mode and aggressive-mode negotiation requests, so it "
                "completes the exposing exchange whenever the peer initiates one"]
    if obj.ikev1_exchange_mode == "aggressive":
        return ["the version 1 exchange mode is `aggressive`, so the gateway both initiates and "
                "accepts the exchange that exposes the identities"]
    if not obj.ikev1_exchange_mode:
        return ["no version 1 exchange mode is configured, which both of the vendor's own "
                "statements read as `auto` - both main and aggressive mode accepted"]
    return []


def _authentication(obj) -> list[str]:
    if obj.peer_authentication == "pre-shared-key":
        return ["the peer is authenticated by a pre-shared key in the staged configuration. The "
                "stored value is ciphertext, so nothing here reads the secret and this finding "
                "makes no claim about its length, randomness or reuse"]
    if obj.peer_authentication == "certificate-without-profile":
        return ["the peer is authenticated by certificate in the staged configuration with no "
                "certificate profile named, so nothing is configured to constrain validation of "
                "the credential that replaced the shared secret"]
    if not obj.peer_authentication:
        return ["how this gateway authenticates its peer is not established - neither "
                "authentication subtree was read on it"]
    return []


def _ikev1_dpd(obj) -> list[str]:
    # SCOPED BY VERSION, exactly as the query is. An absent version 1 key on a gateway pinned to
    # version 2 asserts NOTHING - that branch is not in use - and reporting it as a setting
    # would describe a subtree the gateway never consults.
    if obj.ike_version == "ikev2":
        return []
    if obj.ikev1_dpd_enabled_known and obj.ikev1_dpd_enabled is False:
        detail = ("version 1 dead-peer detection is switched off, so a stale security "
                  "association is not torn down and traffic to a peer that has gone away is "
                  "black-holed")
        if obj.ikev1_dpd_retry is not None:
            # The retry count describes a probe that is not being sent. Said so a reader does
            # not read the number as evidence the probe exists.
            detail += (f" - the retry count of {obj.ikev1_dpd_retry} describes a probe the "
                       f"switch stops being sent")
        return [detail]
    if not obj.ikev1_dpd_enabled_known:
        return ["the version 1 dead-peer-detection switch could not be read on this gateway - "
                "the key is absent or the gateway was never collected - so whether a dead peer "
                "is detected is not established rather than known to be fine"]
    return []


def _ikev2_dpd(obj) -> list[str]:
    # The complement of the sibling: the version 2 branch applies to a gateway configured for
    # version 2 or version-2-preferred, and to one whose version nobody read.
    if obj.ike_version == "ikev1":
        return []
    if obj.ikev2_dpd_enabled_known and obj.ikev2_dpd_enabled is False:
        # NOT "cannot detect a dead peer": the IKEv2 liveness check is always on.
        return ["the version 2 idle liveness probe is switched off - IKEv2 packets still serve "
                "as a liveness check, so what is missing is the probe sent while the tunnel is "
                "idle rather than peer detection altogether"]
    if not obj.ikev2_dpd_enabled_known:
        detail = ("the version 2 liveness-check switch could not be read on this gateway, so "
                  "whether an idle probe is sent is not established")
        if obj.ikev2_dpd_interval is not None:
            detail += (f" - the gateway does carry an idle interval of "
                       f"{obj.ikev2_dpd_interval} seconds, which describes a probe whose switch "
                       f"was never read")
        return [detail]
    return []


def _proposal(obj) -> list[str]:
    if not obj.relies_on_factory_named_proposal:
        return []
    named = [n for n in (obj.ikev1_crypto_profile_name, obj.ikev2_crypto_profile_name) if n]
    factory = sorted({n for n in named if n in FACTORY_PROFILE_NAMES})
    if factory:
        return [f"it names the factory-shipped crypto profile {', '.join(factory)}, a proposal "
                f"set that arrived with the firewall rather than being defined for this estate - "
                f"the finding is about provenance and ownership, not about the algorithms that "
                f"entry happens to hold today"]
    if not named:
        return ["neither crypto-profile pointer is set, so this gateway consumes a proposal set "
                "that nothing in its configuration identifies"]
    return []


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. A finding describes what ITS OWN control
#: asserts, so a reader is sent to one screen rather than to the whole gateway. PAN-IKE-007 and
#: 008 carry the version too, because their populations are defined by it and a reader has to
#: know which branch the finding is about.
PARTS_BY_CONTROL = {
    "PAN-IKE-001": (_version,),
    "PAN-IKE-006": (_authentication,),
    "PAN-IKE-007": (_version, _exchange_mode),
    "PAN-IKE-008": (_version, _ikev1_dpd, _ikev2_dpd),
    "PAN-IKE-009": (_proposal,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"IKE gateway {obj.entry_name} on {obj.appliance}"]
    builders = PARTS_BY_CONTROL.get(control_id)
    if builders is None:
        builders = (_version, _exchange_mode, _authentication, _ikev1_dpd, _ikev2_dpd, _proposal)
    for build in builders:
        parts.extend(build(obj))
    return "; ".join(parts)


def build_ike_gateway_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="IKE gateway",
    control_type=Control.ControlType.IKE_GATEWAY,
    finding_model=IkeGatewayFinding,
    link_model=IkeGatewayFindingControlQuery,
    subject_fk="ike_gateway",
    link_fk="ike_gateway_finding",
    queryset=lambda: IkeGateway.objects.select_related("appliance"),
    evaluate=evaluate_ike_gateway_control_queries,
    summary=build_ike_gateway_finding_summary,
    subject_name=lambda obj: obj.entry_name,
)


def generate_ike_gateway_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_ike_gateway_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
