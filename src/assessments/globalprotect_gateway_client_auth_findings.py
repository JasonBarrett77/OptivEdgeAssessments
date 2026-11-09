"""Finding generation for one row of one GlobalProtect gateway's client-authentication table.
PAN-GPG-002.

NOT THE PORTAL'S TABLE. `globalprotect_portal_client_auth_findings.py` beside this one is the other
object; `client-auth` is a leaf both GlobalProtect objects carry under different parents.

NO ROW OF THIS SUBJECT EXISTS IN THE MEASURED ESTATE. The collection exists only nested inside a
gateway entry and no gateway exists anywhere in this lab, so this control ships UNEXERCISED and the
stage 8 artifact says so in `needs_human`.

THE SENTENCE NAMES THE CLIENT OPERATING SYSTEM AND NOT ONLY THE ROW, because the row's own entry
name is free text an operator chose and carries no meaning. The whole reason this grain exists is
that one gateway can point a Windows row at a strong identity service and an `Any` row at the
firewall's own local database, and a reader who is told only the row name cannot tell which
platform to repoint.

THE DISPATCH DEFAULTS TO `()`, for the reason the sibling gateway generator records: eighteen of
this repository's twenty-eight dispatching generators default to some other control's arms, so a
control reusing such a type has its findings described with claims it never assessed. An
unrecognized id here contributes the subject line and nothing else.

PAN-GPG-002 IS ONE CONTROL OVER TWO MODELS AND THIS SENTENCE CARRIES BOTH HALVES, which is unusual
enough to state. Its first record asserts on the row's own
`backend_can_deliver_a_second_factor`; its second asserts on the GATEWAY-wide
`client_certificate_is_a_second_factor`, reached through the row's own to-one upward `gateway`
foreign key - the walk standing ruling 6 permits. **That FK is `null=True`, so on a row whose
gateway did not resolve the second half is silent and this sentence says so rather than omitting
it.** `gateway_name` is present even then, because it is a path element from the xpath the row was
read at rather than a key on the row, so the arm below can name the parent it could not reach.

AND IT MAY NOT FOLLOW THE AUTHENTICATION NAME INTO THE PROFILE IT POINTS AT.
`test_query_service_boundary` forbids a module outside `assessments/search/` from filtering an
asserted model, so where the reader needs to know what the identity service actually demands the
audit text sends them there. That is also the honest limit: the firewall records WHICH service it
asks and never what that service demands, so no sentence here can claim a second factor is
enforced. `authentication_backend_method` is the method name resolved at normalization, and it
cannot tell an authentication PROFILE from a SEQUENCE whose last member may be the firewall's own
local user database.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_globalprotect_gateway_client_auth_control_queries,
)
from assessments.models import (
    Control,
    GlobalProtectGatewayClientAuthFinding,
    GlobalProtectGatewayClientAuthFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import GlobalProtectGatewayClientAuth


def _admission(obj) -> list[str]:
    """PAN-GPG-002, both records: can a password alone build a tunnel from this platform."""
    parts: list[str] = []
    backend = (obj.authentication_backend_method or "").strip()
    named = (obj.authentication_profile_name or "").strip()
    if not obj.backend_can_deliver_a_second_factor:
        if backend:
            parts.append(
                f"THE IDENTITY SERVICE THIS ROW AUTHENTICATES AGAINST CANNOT DELIVER A SECOND "
                f"FACTOR: it resolves to a `{backend}` back end, so a working username and "
                f"password is on its own enough to build a tunnel into the network from "
                f"{obj.client_os or 'this client platform'}")
        elif named:
            parts.append(
                f"THIS ROW NAMES `{named}` FOR AUTHENTICATION AND THAT NAME RESOLVES TO NOTHING "
                f"this collection carries, so what admits "
                f"{obj.client_os or 'this client platform'} was not established. It is reported "
                f"rather than passed over: an unresolved first factor is not evidence of a strong "
                f"one, and the commonest cause is an authentication SEQUENCE rather than a profile")
        else:
            parts.append(
                f"THIS ROW NAMES NOTHING FOR AUTHENTICATION in what was collected, so there is no "
                f"first factor to assess for {obj.client_os or 'this client platform'} and "
                f"certainly no second")
        parts.append(
            "AND WHETHER THE SERVICE BEHIND THAT NAME ENFORCES A SECOND FACTOR IS NOT A FIREWALL "
            "FACT AT ALL. This firewall records which service it asks and never what that service "
            "demands, so a row naming a SAML or RADIUS object is not evidence of MFA - a "
            "configuration review reads the same whether the second factor is enforced or was "
            "switched off at the identity provider last month. Confirm it there, and ask which "
            "population is exempted")
        if named:
            parts.append(
                f"ALSO ESTABLISH WHETHER `{named}` IS A PROFILE OR A SEQUENCE. A sequence is tried "
                f"member by member until one succeeds, so one whose last member is this firewall's "
                f"own local user database accepts a locally held password whenever the identity "
                f"service is unreachable - and nothing stored here can tell the two apart")
    if obj.gateway_id is None:
        parts.append(
            f"THE GATEWAY-WIDE HALF OF THIS CONTROL COULD NOT BE ASSESSED FOR THIS ROW. Whether a "
            f"client certificate is a genuine SECOND factor here - rather than an alternative to "
            f"the password - is a setting on the gateway `{obj.gateway_name}` above this row, and "
            f"this row's link to that gateway did not resolve, so the question was not asked. It "
            f"is not a pass. Read `portal-config/certificate-profile` on that gateway and the "
            f"and/or switch on every row beneath it by hand")
    elif not obj.gateway.client_certificate_is_a_second_factor:
        gw = obj.gateway
        parts.append(
            "A CLIENT CERTIFICATE IS NOT A GENUINE SECOND FACTOR ON THE GATEWAY ABOVE THIS ROW, "
            "so the gateway reports two factors while enforcing one")
        if not (gw.certificate_profile_name or "").strip():
            parts.append(
                "the gateway binds NO certificate profile at all, so there is nothing to validate "
                "a presented certificate against and nothing for an either/or switch to reach")
        elif not gw.bound_certificate_profile_blocks_unauthenticated_cert:
            parts.append(
                f"the gateway binds the certificate profile `{gw.certificate_profile_name}` and "
                f"that profile does NOT refuse a certificate which was not issued to the machine "
                f"presenting it - so a certificate file copied to another machine travels with "
                f"whoever copied it")
        if gw.any_client_auth_row_permits_either_or:
            parts.append(
                "and at least one row of this gateway's table accepts a client certificate "
                "INSTEAD of credentials rather than in addition to them, which makes a copied "
                "certificate a complete credential on its own")
    if obj.user_credential_or_client_cert_required:
        parts.append(
            "THIS ROW'S OWN AND/OR SWITCH IS THE PERMISSIVE ONE AND THE VENDOR'S LABEL READS "
            "BACKWARDS: the setting is on, which means a password OR a client certificate will do. "
            "The hardened value is the one spelled `No (User Credentials AND Client Certificate "
            "Required)`, so a reviewer who selected the affirmative believing it was the strict "
            "setting selected exactly the permissive one")
    return parts


#: Keyed by control id, DEFAULTING TO `()`. One control over this model today.
PARTS_BY_CONTROL = {
    "PAN-GPG-002": (_admission,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"GlobalProtect gateway authentication row {obj.name} for "
             f"{obj.client_os or 'an unrecorded client platform'} on gateway "
             f"{obj.gateway_name} of {obj.vsys_name} on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_globalprotect_gateway_client_auth_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="GlobalProtect gateway authentication row",
    control_type=Control.ControlType.GLOBALPROTECT_GATEWAY_CLIENT_AUTH,
    finding_model=GlobalProtectGatewayClientAuthFinding,
    link_model=GlobalProtectGatewayClientAuthFindingControlQuery,
    subject_fk="globalprotect_gateway_client_auth_row",
    link_fk="globalprotect_gateway_client_auth_finding",
    #: `gateway` IS SELECTED because the sentence reads the parent's three certificate columns
    #: through it. The FK is nullable and the arm tests `gateway_id is None` before touching it.
    queryset=lambda: GlobalProtectGatewayClientAuth.objects.select_related(
        "appliance", "appliance_group", "gateway"),
    evaluate=evaluate_globalprotect_gateway_client_auth_control_queries,
    summary=build_globalprotect_gateway_client_auth_finding_summary,
    #: The row's own entry name. `client_os` is what a reader goes by and the sentence names it.
    subject_name=lambda obj: obj.name,
    #: The appliance, the vsys and the GATEWAY, without which a reader cannot find the row: the
    #: entry name is operator-chosen and not unique within a vsys.
    subject_scope=lambda obj: f"{obj.appliance} {obj.vsys_name} {obj.gateway_name}",
)


def generate_globalprotect_gateway_client_auth_findings(
        assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_globalprotect_gateway_client_auth_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
