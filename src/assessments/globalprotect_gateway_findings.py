"""Finding generation for one GlobalProtect gateway entry of one vsys. PAN-GPG-001, -006, -007.

NO ROW OF THIS SUBJECT EXISTS IN THE MEASURED ESTATE, so not one sentence below has ever been
built from a device reading. Stage 6 spent eleven lease windows trying to commit a gateway and met
a new commit requirement each time; the merged configuration carries no `global-protect-gateway`
key under any of the twelve virtual systems of the four appliances. The three controls here ship
UNEXERCISED and the stage 8 artifact says so in `needs_human`.

THE DISPATCH DEFAULTS TO `()` AND THAT IS THE POINT OF WRITING IT THAT WAY. Measured across all 28
generators in this repository that key a dispatch by control id, EIGHTEEN default to a non-empty
arm tuple - some other control's arms - so a control reusing one of those types has its findings
described with another control's compliance claims unless it adds its own entry. An unrecognised id
here contributes the subject line and no claim, which is thin rather than wrong, and is what the
three most recent runs adopted.

THE SENTENCE SAYS WHICH HALF FAILED, because the columns the queries assert on are DERIVED
disjunctions and the inputs beside them are the only way to tell two remediations apart.
`tls_profile_resolves_to_an_explicit_floor` is false both where the bound name reached no row the
collection carries and where the row it reached states no protocol floor - two different repairs on
two different objects - so the arm reads `ssl_tls_service_profile` and `bound_tls_min_version`
beside the verdict and names which.

AND IT MAY NOT RESOLVE A REFERENCE INTO THE MODEL IT POINTS AT.
`tests/test_query_service_boundary.py::test_asserted_models_are_filtered_only_in_the_search_service`
fails a module outside `assessments/search/` that invents its own filter over an asserted model, and
its docstring gives the reason: such a module "decides what the configuration means privately, where
no payload contract records it and no test pins it". So where a reader needs the far row's values -
what the TLS profile actually states, what the certificate profile actually refuses - the audit text
sends them there and this sentence names the binding rather than following it. Every value printed
below is a column of the gateway's own row.

THE LICENCE GOES IN THE WORDING AND NEVER IN A CLAUSE, and that is a decision worth not reversing.
`globalprotect_gateway_licensed` is `default=False` and two of the four lab appliances answer the
licence read with `{'licenses': None}` - truthy, empty, status=success - which is the instrument
saying nothing rather than saying unlicensed. An applicability clause on it would SUPPRESS these
controls on exactly the appliances whose licence state is unknown, where an assertion clause would
raise them. `licence_state_known` is what tells the two apart and the arms below print it.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_globalprotect_gateway_control_queries
from assessments.models import (
    Control,
    GlobalProtectGatewayFinding,
    GlobalProtectGatewayFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import GlobalProtectGateway


def _licence_note(obj) -> list[str]:
    """Shared by every arm. The licence is a qualifier on the finding and never a suppressor."""
    if not obj.licence_state_known:
        return ["THE LICENCE QUESTION BEHIND THIS GATEWAY WAS NEVER ANSWERED: the appliance's "
                "licence reply carried no entries at all, so whether GlobalProtect is licensed "
                "here is unknown rather than no. These controls fire on an unknown by design - an "
                "appliance nobody could read is not an appliance that answered no - and "
                "suppressing on it would convert an unanswered licensing question into silence"]
    if not obj.globalprotect_gateway_licensed:
        return ["AND THIS APPLIANCE'S LICENCE LIST CARRIES NO UNEXPIRED GlobalProtect Gateway "
                "FEATURE, which the vendor requires before any of this takes effect. Every "
                "setting named here is configurable on an unlicensed firewall and none of it "
                "runs, so a configuration read of this gateway looks the same either way"]
    return []


def _tls_floor(obj) -> list[str]:
    """PAN-GPG-001's first record: is the protocol floor a choice somebody made."""
    parts: list[str] = []
    if obj.tls_profile_resolves_to_an_explicit_floor:
        return parts
    bound = (obj.ssl_tls_service_profile or "").strip()
    if not bound:
        parts.append(
            "THIS GATEWAY'S SSL/TLS SERVICE PROFILE BINDING IS EMPTY IN WHAT WAS COLLECTED, which "
            "is evidence about the READ and not about the device: the binding is MANDATORY AT "
            "COMMIT - `validate full` refuses a gateway without one, naming it - so no committed "
            "gateway in any estate has nothing bound. Treat this as a collection to repeat rather "
            "than a setting to change")
    else:
        parts.append(
            f"this gateway binds the SSL/TLS service profile `{bound}` AND THAT NAME DOES NOT "
            f"RESOLVE TO A PROTOCOL FLOOR anybody chose - either the name reaches no profile row "
            f"this collection carries, or the profile it reaches states no minimum version. The "
            f"two are different repairs: the first is a broken or vendor-PREDEFINED reference, the "
            f"second is a profile that exists and leaves the floor to the platform")
        if (obj.bound_tls_min_version or "").strip():
            parts.append(
                f"the lowest protocol version read off that binding was "
                f"`{obj.bound_tls_min_version}`")
        else:
            parts.append(
                "no minimum protocol version was read off that binding at all, which is the "
                "second of those two cases or an unresolved reference")
    parts.append(
        "SO WHAT THIS GATEWAY OFFERS A REMOTE ENDPOINT IS WHATEVER THE PLATFORM FALLS BACK TO, and "
        "nothing on the firewall reports what was actually negotiated. A review that confirms a "
        "hardened profile exists somewhere on the device does not answer this, because the "
        "question is which profile THIS gateway binds")
    parts.append(
        "AND WHETHER THIS GATEWAY FACES A NETWORK YOU DO NOT CONTROL IS NOT A FIREWALL FACT. The "
        "configuration is identical on an internet-facing gateway and on one reachable only from "
        "inside, and nothing on the device tells them apart - so confirm which this is before "
        "ranking the exposure")
    return parts + _licence_note(obj)


def _transport(obj) -> list[str]:
    """PAN-GPG-006's three records: is a tunnel built, over what, with what offered first."""
    parts: list[str] = []
    if obj.tunnel_mode is False:
        parts.append(
            "THIS GATEWAY DOES NOT BUILD A TUNNEL FOR ITS ENDPOINTS - `tunnel-mode` is off - so "
            "the population it serves gets identity and nothing else. Their traffic never reaches "
            "this firewall, which means every policy, profile and log the organisation has bought "
            "applies to the office and not to the people outside it, and no error appears "
            "anywhere. The vendor makes the tunnel OPTIONAL for a gateway that exists only to "
            "identify users already inside the network, and no field on any gateway object "
            "records which kind this is - so confirm that before reading this as a defect")
    elif obj.tunnel_mode is None:
        parts.append(
            "WHETHER THIS GATEWAY BUILDS A TUNNEL WAS NOT READ. The key is absent from what was "
            "collected, and the device REFUSES to commit a gateway that omits it - measured, "
            "`validate full` reports it missing by name - so on a committed gateway this is a "
            "collection failure rather than a setting")
    if obj.tunnel_mode and obj.ipsec_enabled is False:
        parts.append(
            "the tunnel is built over the WEAKER of the two available transports: IPSec is not "
            "enabled, so every endpoint gets the SSL transport. Fallback between the two is silent "
            "and per-endpoint, so a fleet can sit entirely on one while the preference reads as "
            "the other, and one of the two causes the vendor names is this firewall's own address "
            "translation rather than anything on the network path")
    if not obj.ipsec_enabled_known:
        parts.append(
            "THE NETWORKING HALF OF THIS GATEWAY WAS NOT READ, so whether IPSec is offered is "
            "unknown rather than no. This half is a SEPARATE READ AT A DIFFERENT SCOPE - a "
            "device-local entry of the same name under `network/tunnel` - so it is the half most "
            "likely to be missing while the gateway's own entry exists, and `equals false` over an "
            "absent key matches nothing and would have passed in silence. Stage 4 could not settle "
            "what an absent enable key means and the two candidate readings are opposite postures, "
            "so this is reported rather than guessed")
    elif not obj.networking_half_present:
        parts.append(
            "AND NO DEVICE-LOCAL ENTRY OF THIS GATEWAY'S NAME WAS FOUND UNDER `network/tunnel` AT "
            "ALL, which means the transport, crypto and video-exclusion content was never read. "
            "The two halves of one dialog can be owned by different people and a template that "
            "pushes one need not push the other")
    if obj.ipsec_enabled and not obj.app_crypto_offers_gcm_first:
        first = (obj.bound_app_crypto_first_encryption or "").strip()
        profile = (obj.ipsec_crypto_profile_name or "").strip()
        if first:
            parts.append(
                f"IPSec is preferred AND THE ALGORITHM IT OFFERS FIRST IS `{first}`, not the "
                f"256-bit authenticated-encryption option. The order is the order this firewall "
                f"applies, so the gateway negotiates that algorithm with every endpoint that will "
                f"accept it - which means the stated reason for preferring this transport is not "
                f"delivered, and a check comparing algorithm SETS rather than sequences would "
                f"report the shipped order and a hardened one as identical")
        else:
            parts.append(
                "IPSec is preferred AND WHICH ALGORITHM IT OFFERS FIRST IS NOT KNOWN - the gateway "
                "binds no app crypto profile, or the name it binds reaches no row this collection "
                "carries. An unknown head of the proposal list means nobody knows what this "
                "gateway negotiates, and the one profile this estate holds offers the weakest "
                "value available")
        if profile:
            parts.append(f"the profile bound for it is `{profile}`")
        parts.append(
            "TWO THINGS THIS CANNOT RANK AND BOTH ARE REAL. The authentication half of this "
            "profile kind offers sha1 AND NOTHING ELSE - measured on all four appliances, and the "
            "vendor's own help says so in terms - so it has no rank, no remediation, and a finding "
            "against it would fire on every correctly configured gateway on this platform. And a "
            "gateway whose endpoints negotiate the newer key-exchange protocol takes its "
            "algorithms from a DIFFERENT profile kind entirely, which nothing here establishes")
    return parts + _licence_note(obj) if parts else []


def _session_bounds(obj) -> list[str]:
    """PAN-GPG-007's two records: is the login lifetime bounded, is an idle tunnel torn down."""
    parts: list[str] = []
    if not obj.login_lifetime_known:
        parts.append(
            "NO LOGIN LIFETIME IS BOUNDED ON THIS GATEWAY - no value was read in any of the three "
            "unit branches, so there is no number to compare. THIS IS THE COMMONEST FAILING STATE "
            "ON THIS CONTROL and it is why the finding is about the gateway rather than about an "
            "agent role entry: stage 4 found NO agent role entry on any appliance in this estate, "
            "so the usual failure is that nobody has bounded anything, and at the role-entry grain "
            "there would be no row to report it with. A null also passes `greater than 24 hours` "
            "in silence, which is why this is stated as an absence and not as a number")
    elif obj.login_lifetime_hours is not None and obj.login_lifetime_hours > 24:
        unit = (obj.login_lifetime_unit or "").strip()
        entered = obj.login_lifetime_as_entered
        as_typed = (f" - entered as {entered} {unit}" if entered is not None and unit else "")
        parts.append(
            f"a login on this gateway lasts up to {obj.login_lifetime_hours} hours before the user "
            f"must authenticate again{as_typed}. Until that expires the tunnel survives everything "
            f"the organisation might do about the user: disabling the account, revoking the "
            f"certificate, changing the password, losing the laptop. The product's own untouched "
            f"state is the worst value this setting can hold")
        parts.append(
            "AND THE NUMBER ON THIS GATEWAY IS A CEILING ONLY IF NOBODY HAS RAISED IT FROM THE "
            "OTHER SIDE. The vendor added an app setting letting end users extend their own "
            "session, it lives on the PORTAL's app configuration, and this gateway's configuration "
            "cannot see it")
    if not obj.inactivity_logout_known:
        parts.append(
            "AND NO IDLE LOGOUT IS BOUNDED EITHER - no value was read, so an unattended endpoint "
            "holds its tunnel for the whole of the login lifetime. The temptation here is sharper "
            "than on the lifetime beside it and it is why this is reported rather than assumed: "
            "the vendor DOCUMENTS a 180-minute default that would already satisfy this control, so "
            "materialising it would make this half pass by default while its sibling fails by "
            "default, on a pair of guesses pointing opposite ways")
    elif obj.inactivity_logout_minutes is not None and obj.inactivity_logout_minutes > 180:
        parts.append(
            f"an idle tunnel on this gateway is held for {obj.inactivity_logout_minutes} minutes "
            f"before it is logged out. An idle tunnel is a live route into the network attached to "
            f"an endpoint nobody is sitting at, and the login lifetime is far too coarse to close "
            f"that window on its own")
        parts.append(
            "ON AN ESTATE THAT COLLECTS HOST POSTURE THIS TIMER MEASURES SOMETHING ELSE. The "
            "vendor says it is reset by a posture check as well as by traffic, so the agent itself "
            "keeps the tunnel alive and the number stops describing idleness")
    return parts + _licence_note(obj) if parts else []


#: Keyed by control id, DEFAULTING TO `()`. Three controls over this model, each reading its own
#: columns. The empty default is the safe convention: an unrecognised id contributes the subject
#: line and no claim, rather than some other control's compliance claims - which is what eighteen
#: of this repository's twenty-eight dispatching generators do instead.
PARTS_BY_CONTROL = {
    "PAN-GPG-001": (_tls_floor,),
    "PAN-GPG-006": (_transport,),
    "PAN-GPG-007": (_session_bounds,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"GlobalProtect gateway {obj.name} of {obj.vsys_name} on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_globalprotect_gateway_finding_summary(obj, matched_queries) -> str:
    # The control id comes from the first matched query and CANNOT be another control's:
    # `object_findings.generate_object_findings` iterates one control at a time and builds the
    # finding with that same control, so `matched_queries` only ever holds one control's queries.
    # This loop is a redundant spelling of `control.control_id` and is written the way every
    # sibling generator writes it.
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="GlobalProtect gateway",
    control_type=Control.ControlType.GLOBALPROTECT_GATEWAY,
    finding_model=GlobalProtectGatewayFinding,
    link_model=GlobalProtectGatewayFindingControlQuery,
    subject_fk="globalprotect_gateway",
    link_fk="globalprotect_gateway_finding",
    queryset=lambda: GlobalProtectGateway.objects.select_related(
        "appliance", "appliance_group"),
    evaluate=evaluate_globalprotect_gateway_control_queries,
    summary=build_globalprotect_gateway_finding_summary,
    #: The gateway's own entry name, which is what an engineer opens.
    subject_name=lambda obj: obj.name,
    #: The appliance and the vsys, because a gateway name is operator-chosen and this estate's
    #: four appliances carry twelve virtual systems between them.
    subject_scope=lambda obj: f"{obj.appliance} {obj.vsys_name}",
)


def generate_globalprotect_gateway_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_globalprotect_gateway_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
