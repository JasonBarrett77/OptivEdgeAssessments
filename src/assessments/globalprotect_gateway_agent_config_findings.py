"""Finding generation for one agent client-settings row of one GlobalProtect gateway.
PAN-GPG-003, PAN-GPG-004.

TWO CONTROLS SHARE THIS GENERATOR because they share a model and therefore a `control_type`: a
finding model may appear in `finding_registry.FINDING_KINDS` exactly once, and
`generate_object_findings` selects its controls by type. Their findings are told apart by the
`control` foreign key and by the arms below.

NO ROW OF THIS SUBJECT EXISTS IN THE MEASURED ESTATE, and this is the model where that costs most.
Stage 7's own sentence for this stage: every column of this model is a normaliser's output checked
against a fixture, and **the two columns that SUPPRESS on their default -
`accept_cookie_configured` and `authentication_override_configured` - have no device instance of
either branch.** Both are PAN-GPG-003's applicability clauses, and an applicability clause that is
false drops the row out of the control in silence. So the population of that control rests on two
switches whose behaviour no device reading confirms. Both controls ship UNEXERCISED.

THE COOKIE SENTENCE NAMES THE UNIT THE ADMINISTRATOR TYPED AND NOT ONLY THE CONVERTED SPAN. The
device accepts minutes, hours or days; the grading compares one converted number because a clause
is a comparison against one literal, but a remediation is an edit to the number on the screen. So
the arm prints both and says which is which.

THE EGRESS SENTENCE SAYS "NO RECORD OF THE DECISION" AND NEVER "THE POSTURE IS WRONG", which is
stage 3's own distinction and the one no column can carry. An empty split-tunnel configuration and
an UNDOCUMENTED one read identically off this row: the count is zero in both cases, and zero is
also the best value the field can hold. `egress_inventory_computed` is what separates a row nobody
computed from a full tunnel with nothing excluded, and the arm reads it first.

THE DISPATCH DEFAULTS TO `()`, for the reason the sibling gateway generator records.

AND NEITHER ARM FOLLOWS THE COOKIE CERTIFICATE'S NAME INTO THE CERTIFICATE IT NAMES.
`test_query_service_boundary` forbids a module outside `assessments/search/` from filtering an
asserted model, and the limit is the right one here anyway: when the certificate was last replaced,
what else uses it and who owns the schedule are none of them firewall facts. The sentence names the
certificate and the audit text sends the reader to the owner.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_globalprotect_gateway_agent_config_control_queries,
)
from assessments.models import (
    Control,
    GlobalProtectGatewayAgentConfigFinding,
    GlobalProtectGatewayAgentConfigFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import GlobalProtectGatewayAgentConfig


def _cookie(obj) -> list[str]:
    """PAN-GPG-003's two records: how long the cookie lasts, and what encrypts it."""
    parts: list[str] = []
    if obj.accept_cookie_configured and not obj.cookie_lifetime_known:
        parts.append(
            "THIS ROW ACCEPTS A RECONNECTION COOKIE AND HOLDS NO LIFETIME FOR IT in any of the "
            "three unit branches, so how long the cookie is honoured was not established. It is "
            "reported rather than graded as acceptable: an absent value in all three branches "
            "reads as nobody having looked, and a null passes `greater than 24 hours` in silence")
    elif (obj.accept_cookie_configured and obj.cookie_lifetime_hours is not None
            and obj.cookie_lifetime_hours > 24):
        unit = (obj.cookie_lifetime_unit or "").strip()
        entered = obj.cookie_lifetime_as_entered
        as_typed = (f", entered on the screen as {entered} {unit}"
                    if entered is not None and unit else "")
        parts.append(
            f"THIS ROW LETS AN ENDPOINT RECONNECT ON A STORED COOKIE FOR UP TO "
            f"{obj.cookie_lifetime_hours} HOURS INSTEAD OF AUTHENTICATING AGAIN{as_typed}. The "
            f"cookie is a bearer token for the whole network: whoever holds a copy reconnects as "
            f"that user with no password, no certificate and no second factor for as long as it is "
            f"valid, and DISABLING THE USER'S ACCOUNT DOES NOT REVOKE IT - so a lost laptop stays "
            f"connected to the estate until the cookie expires, which on this product can be set "
            f"to most of a year")
        parts.append(
            "'TURN COOKIES OFF' IS NOT A REMEDIATION YOU CAN OFFER EVERYWHERE. The vendor "
            "recommends the reconnection cookie specifically where a one-time-password or "
            "software-token service is in use, so on such a deployment the right answer is a SHORT "
            "cookie rather than none - establish which this is before writing the remediation")
    if obj.authentication_override_configured:
        cert = (obj.cookie_encrypt_decrypt_cert or "").strip()
        if not cert:
            parts.append(
                "AND THIS ROW NAMES NO CERTIFICATE TO ENCRYPT AND DECRYPT THAT COOKIE. Whoever can "
                "forge or decrypt it reconnects as any user of this gateway without "
                "authenticating, leaving nothing behind on the gateway. Note that this applies to "
                "a row that merely ACCEPTS a cookie as well as one that generates it: the "
                "certificate is a sibling of the accept switch and serves both sides, which is why "
                "the wider of the two switches gates this half")
        else:
            parts.append(
                f"the certificate that encrypts and decrypts that cookie is `{cert}`, and WHAT "
                f"THIS FIREWALL HOLDS IS THE NAME AND NOTHING ELSE - not when it was last "
                f"replaced, not what else on the estate uses it, not who owns the schedule for "
                f"replacing it. The same certificate has to serve the portal as well, so replacing "
                f"it carelessly takes remote access down for everyone at once")
    return parts


def _egress(obj) -> list[str]:
    """PAN-GPG-004: which paths leave the tunnel uninspected, and whether anybody decided them."""
    parts: list[str] = []
    if not obj.egress_inventory_computed:
        parts.append(
            "THE UNINSPECTED-EGRESS INVENTORY FOR THIS ROW HAS NOT BEEN COMPUTED, so the count of "
            "paths leaving the tunnel is not a reading. It is reported because the count's honest "
            "empty value is ZERO, which is indistinguishable from a full tunnel with nothing "
            "excluded - the most compliant state the field can hold - so a row the normalisation "
            "pass has not reached would otherwise report itself as the best configuration in the "
            "estate")
        return parts
    if obj.uninspected_egress_path_count > 0:
        parts.append(
            f"{obj.uninspected_egress_path_count} PATH(S) BY WHICH THIS ROW'S ENDPOINTS REACH THE "
            f"INTERNET OR THEIR OWN LOCAL NETWORK WITHOUT PASSING THROUGH THIS FIREWALL. Each "
            f"carries none of the firewall's inspection, logging or policy, so each is a route in "
            f"and out of the estate the firewall will never report on")
        if obj.no_direct_access_to_local_network is False:
            parts.append(
                "ONE OF THEM IS THE ENDPOINT'S OWN ATTACHED NETWORK, which is a screen of its own "
                "rather than a member of any exclusion list - so an inventory built from the "
                "exclusion lists alone reports a clean posture on this row while leaving the whole "
                "local network open")
        elif obj.no_direct_access_to_local_network is None:
            parts.append(
                "AND WHETHER THE ENDPOINT'S OWN ATTACHED NETWORK IS ALSO OPEN WAS NOT READ: the "
                "key is absent, and it is counted as open here because the key's name is the "
                "negation of what it permits, so an absence most likely leaves access in place")
        parts.append(
            "THIS IS 'NO RECORD OF THE DECISION' AND NOT 'THE POSTURE IS WRONG', and the "
            "distinction is the finding. An approved, documented exclusion and an undocumented one "
            "read identically off this configuration - the firewall holds the lists and holds "
            "nothing at all about whether anybody decided them. What is owed is the approver's "
            "name and the review date for each path, not necessarily a change to the list")
    return parts


#: Keyed by control id, DEFAULTING TO `()`. Two controls over this model, each reading its own
#: columns, so neither can be described with the other's claims.
PARTS_BY_CONTROL = {
    "PAN-GPG-003": (_cookie,),
    "PAN-GPG-004": (_egress,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"GlobalProtect gateway agent configuration {obj.name} on gateway "
             f"{obj.gateway_name} of {obj.vsys_name} on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_globalprotect_gateway_agent_config_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="GlobalProtect gateway agent configuration",
    control_type=Control.ControlType.GLOBALPROTECT_GATEWAY_AGENT_CONFIG,
    finding_model=GlobalProtectGatewayAgentConfigFinding,
    link_model=GlobalProtectGatewayAgentConfigFindingControlQuery,
    subject_fk="globalprotect_gateway_agent_config",
    link_fk="globalprotect_gateway_agent_config_finding",
    queryset=lambda: GlobalProtectGatewayAgentConfig.objects.select_related(
        "appliance", "appliance_group"),
    evaluate=evaluate_globalprotect_gateway_agent_config_control_queries,
    summary=build_globalprotect_gateway_agent_config_finding_summary,
    #: The settings row's own name, which is what an engineer opens.
    subject_name=lambda obj: obj.name,
    #: The appliance, the vsys and the gateway, for the same reason as the client-auth row.
    subject_scope=lambda obj: f"{obj.appliance} {obj.vsys_name} {obj.gateway_name}",
)


def generate_globalprotect_gateway_agent_config_findings(
        assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_globalprotect_gateway_agent_config_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
