"""Finding generation for one GlobalProtect portal entry of one vsys.
PAN-GPP-001, PAN-GPP-003, PAN-GPP-004, PAN-GPP-005.

FOUR CONTROLS ON ONE ROW, because the portal is an internet-facing TLS endpoint and an
agent-configuration server at the same time. Two of them read `portal-config` - the transport
binding and the browser login page - and two read the FIRST agent configuration an endpoint would
match, because the portal delivers the first match and stops. The sentence each control builds is
the part that carries meaning and it is written per control here, beside the control it describes.

THE SENTENCES NAME THE SENTINEL RATHER THAN THE ABSENCE, and that is the single most consequential
thing stage 4 measured for this domain. A portal that hands out NO agent configuration at all is
the measured state of the estate's one pre-existing portal, and a comparison on a nested key
matches no row for it and drops it silently - so the two posture columns carry sentinels
(`no_agent_configuration`, `not_set`, `several_members`) and the sentences below say which one was
read. A finding that said only "the upgrade setting is wrong" would be wrong about the commonest
case in the estate, where there is no setting at all.

WHAT NO SENTENCE HERE IS ALLOWED TO CLAIM, and each is a stage 3 or stage 5 limit rather than
caution added here:

* THAT THE TRANSPORT THE PORTAL NEGOTIATES IS ACCEPTABLE. PAN-GPP-001's clause is on the BINDING.
  The bound value is a NAME and nothing else, and on a template-managed appliance the profile it
  names is not in the same payload - measured, the estate's one adopted portal binds `oep-tpl-tls`,
  which answers `No such node` in both committed views. What that profile permits is PAN-CRT-005's
  subject and this control says nothing about it.
* THAT THE CERTIFICATE THE PORTAL PRESENTS IS TRUSTED. That is PAN-GPP-001's SECOND half, which
  stage 5 discharged `engineer_answers`: no column exists for it, it owes no query, and a reader of
  a clean PAN-GPP-001 finding must not read it as a trusted chain. The sentence says so.
* THAT THE AGENTS ACTUALLY CONNECTING ARE CURRENT. PAN-GPP-003's stage 3 assertion has two halves
  and only one has a column. The only read in the estate that could answer the fleet half returns
  None with status=success and carries no counter, no row count and no timestamp, so "no agent has
  ever connected" and "this is never populated here" are the same reply. Per rules.md that is an
  unknown per field and it fires - what it cannot do is fire as a comparison, because there is
  nothing to compare.
* THAT A HARDENED `save-user-credentials` MEANS A PROMPT PER CONNECTION. The
  authentication-override cookie is a neighbouring node on the same agent configuration and
  pre-empts re-entry of credentials. PAN-GPP-004 is about what is STORED on the endpoint, which is
  what its node decides, and the sentence keeps to that.

THE PART OF PAN-GPP-003 THAT IS SILENT HERE, stated because a reader would otherwise take this for
the whole control. Its second record - access conditioned on the app version the endpoint reports,
so that an endpoint below the floor is refused rather than asked - clauses on
`integrations.GlobalProtectEnforcementPoint`. That is a different model, `ControlQuery.clean()`
refuses a query whose model differs from its control's target, and standing ruling 6's relation
remedy has nothing to walk: there is no Django relation between the portal and the enforcement
point in either direction. The portal took the id because the control's own language leads with the
portal's agent configuration, because the grading with eight placements is on this half, and
because this half carries the control's own severity while the other carries stage 3's
`preferred_gap_severity`. The stage 8 artifact for `globalprotect-portal` records it in
`subjects_in_two_models`.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_globalprotect_portal_control_queries
from assessments.models import (
    Control,
    GlobalProtectPortalFinding,
    GlobalProtectPortalFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import GlobalProtectPortal


#: What the portal tells an endpoint to do when a new app version appears, in the vendor's own
#: labels, so the sentence prints what the GUI shows rather than the stored token. The three
#: sentinels are this project's and are described rather than labelled.
UPGRADE_LABELS = {
    "prompt": "Allow with Prompt",
    "disabled": "Disallow",
    "manual": "Allow Manually",
    "transparent": "Allow Transparently",
    "internal": "Allow Transparently (Internal Network Only)",
}

#: What the app may keep on the endpoint. THE STORED ORDER IS NOT THE EXPOSURE ORDER - the column
#: runs 0,1,2,3 and the exposure runs 0 < 2 < 3 < 1 - which is why every calibration on it is an
#: equality and why the sentence spells out what each value keeps.
SAVED_CREDENTIAL_LABELS = {
    "0": "No",
    "1": "Yes",
    "2": "Save Username Only",
    "3": "Only with User Fingerprint",
}


def _no_agent_configuration_clause() -> str:
    return (
        "the portal hands out NO agent configuration at all - there is no `client-config` node "
        "beneath it - so there is no setting to read and nothing a remediation can edit. This is "
        "not a missing reading: it is a committed state, it is the state of the one portal in this "
        "estate that nobody here configured, and a comparison written against the setting's own "
        "key matches no row for it and drops the portal silently")


def _transport_profile(obj) -> list[str]:
    """PAN-GPP-001's first record: is a transport profile bound to this portal at all."""
    if not obj.tls_profile_binding_missing:
        return []
    parts = [
        "no SSL/TLS service profile is bound to this portal, so nothing on the portal decides "
        "what a remote user's browser or agent is allowed to negotiate and the handshake falls "
        "back to whatever the platform offers"]
    parts.append(
        "THE BINDING IS MANDATORY ON A COMMITTED PORTAL, measured three ways - the device refuses "
        "to commit a portal without `portal-config/ssl-tls-service-profile` - so a row reading "
        "this way is one whose configuration a collection did not carry, rather than a portal an "
        "operator left unbound. Confirm the read before taking this to the customer as a "
        "configuration defect; `mandatory_keys_present` beside this row is what records it")
    parts.append(
        "WHAT THIS DOES NOT SAY. It says nothing about what any bound profile PERMITS: the leaf "
        "holds a NAME and nothing else, and the floor, the algorithms and the certificate on the "
        "profile that name points at belong to PAN-CRT-005, PAN-CRT-009 and PAN-CRT-001. Nor does "
        "it say the certificate the portal presents chains to an authority the endpoint already "
        "trusts - that is this control's other half, which rests on evidence the firewall does not "
        "hold and is answered by the engineer rather than by this row")
    parts.append(
        "AND WHERE A GATEWAY TERMINATES ON THE SAME INTERFACE, THE PORTAL'S OWN SETTING IS NOT "
        "WHAT IS IN FORCE. The vendor states twice that the gateway's configuration takes "
        "precedence over the portal's during the SSL handshake where the two share an interface "
        "and do not share a profile, so the interface-sharing question decides whose transport "
        "settings apply")
    return parts


def _login_page(obj) -> list[str]:
    """PAN-GPP-005's record: is the browser-reachable login page served."""
    parts = []
    value = obj.custom_login_page or ""
    if value == "factory-default":
        parts.append(
            "the portal serves a browser the login page the platform ships - `custom-login-page` "
            "holds `factory-default` - which is an unauthenticated credential prompt published "
            "wherever this portal is reachable, answers whether a username is real, and is the "
            "exact surface PAN-OS pre-authentication exploit chains have arrived at. It is also "
            "the page every scanner and every published chain has already seen")
    elif value and value != "Disable":
        parts.append(
            f"the portal serves a browser an imported response page, `{value}` - so the login "
            f"surface is present and decorated rather than absent. The page being the "
            f"organisation's own does not reduce what it is: an unauthenticated credential prompt "
            f"that answers whether a username is real")
    if not obj.mandatory_keys_present:
        parts.append(
            "AND THIS ROW'S READ DID NOT CARRY THE FOUR KEYS A COMMITTED PORTAL ALWAYS HAS - "
            "local-address, ssl-tls-service-profile, custom-login-page and custom-home-page. So "
            "what the portal serves a browser was NOT ESTABLISHED on this row rather than "
            "established and found wrong. This is the reading that would otherwise pass silently: "
            "an unknown login page matches no comparison and SQL decides it the compliant way, so "
            "without this sentence a portal nobody could read would appear in a clean report")
    if not parts:
        return []
    parts.append(
        "WHETHER THIS SURFACE IS NEEDED IS THE CUSTOMER'S FACT AND NOT THE FIREWALL'S. An estate "
        "that distributes its agents through endpoint management does not use the page at all and "
        "is carrying the exposure for nothing; an estate that does use it needs the page and needs "
        "the decision written down. `Disable` is the only state in which the surface is ABSENT "
        "rather than decorated, and the vendor describes it in exactly those terms")
    return parts


def _agent_upgrade(obj) -> list[str]:
    """PAN-GPP-003's first record: does the portal drive endpoints to a current version."""
    value = obj.upgrade_posture or ""
    parts = []
    if value == "no_agent_configuration":
        parts.append(
            _no_agent_configuration_clause() + " - and for this control that means NOTHING WILL "
            "EVER RETIRE A SUPERSEDED APP on an endpoint this portal serves, because the portal is "
            "the only thing that reaches those endpoints")
    elif value == "not_set":
        parts.append(
            "the portal hands out an agent configuration that says nothing about upgrades: the "
            "`client-upgrade` member is absent from it. Three sources agree the FORM's default is "
            "`Allow with Prompt` and none of the three is a measurement of what the agent does "
            "when the member is absent - and the agent is the thing that acts on it - so this "
            "reads as unknown and is reported rather than assumed compliant")
    elif value == "several_members":
        parts.append(
            "the agent configuration's upgrade setting holds MORE THAN ONE value while the "
            "vendor's own schema marks it single-valued, so there is no effective instruction to "
            "report. The list APPENDS rather than replaces, with neither the member value nor the "
            "entry name validated at the write, so a configuration tool that wrote one member "
            "without reading first produces exactly this")
    elif value in ("disabled", "manual", "internal"):
        label = UPGRADE_LABELS.get(value, value)
        if value == "disabled":
            parts.append(
                f"the first agent configuration an endpoint matches sets the upgrade behaviour to "
                f"`{label}`, so nothing will move an endpoint matching it and the superseded app "
                f"is permanent until somebody edits the portal. The vendor prescribes exactly this "
                f"state TEMPORARILY on every configuration but one during a staged rollout, which "
                f"is the one case where it is deliberate - confirm whether this population is "
                f"being held back on purpose before reporting it as neglect")
        elif value == "manual":
            parts.append(
                f"the first agent configuration an endpoint matches sets the upgrade behaviour to "
                f"`{label}`: an upgrade is possible and nothing initiates it, so convergence "
                f"depends on individual users deciding to look")
        else:
            parts.append(
                f"the first agent configuration an endpoint matches sets the upgrade behaviour to "
                f"`{label}` - the fifth value the vendor's dictionary permits, which upgrades "
                f"automatically but waits until the endpoint is connected internally to the "
                f"corporate network. WHETHER IT CONVERGES DEPENDS ON HOW OFTEN THIS POPULATION IS "
                f"ON THE CORPORATE NETWORK, which is the customer's fact and not the firewall's, "
                f"and stage 3's four ranks gave it no severity. It is reported at the baseline "
                f"rather than silently, because a reader of a clean report has no way to tell this "
                f"configuration from one that upgrades unconditionally")
    if not parts:
        return []
    parts.append(
        "THE SETTING THAT COUNTS IS THE ONE ON THE FIRST AGENT CONFIGURATION AN ENDPOINT MATCHES, "
        "because the portal delivers the first match and stops. The collection is a flat entry "
        "list with no priority key, so the order is the DOCUMENT order; the row beside this "
        "finding carries the whole list in that order and a remediation should name which "
        "configuration to edit")
    parts.append(
        "AND THIS SAYS NOTHING ABOUT THE VERSIONS ACTUALLY CONNECTING. Stage 3 asserts both that "
        "the portal drives upgrades and that the fleet is within one major release of current; the "
        "second has no column anywhere, because the only read that could answer it returns an "
        "empty success with no counter, no row count and no timestamp - so `no agent has ever "
        "connected` and `this is never populated here` arrive identically. The current-version "
        "baseline is the customer's to supply in any case")
    return parts


def _saved_credentials(obj) -> list[str]:
    """PAN-GPP-004's record: may the app keep the user's password on the endpoint."""
    value = obj.saved_credentials_posture or ""
    parts = []
    if value == "no_agent_configuration":
        parts.append(
            _no_agent_configuration_clause() + " - and for this control that means WHAT THE APP "
            "KEEPS ON THE ENDPOINT IS DECIDED BY THE APP and not by this firewall. Both the "
            "device's schema default and the vendor's documentation name `Yes` - this control's "
            "worst value - as what the form shows, so the unknown is reported rather than read as "
            "a pass")
    elif value == "not_set":
        parts.append(
            "the portal hands out an agent configuration with no `save-user-credentials` value "
            "recorded at all, so whether a working remote-access credential is sitting in an "
            "endpoint's storage was not established. The device's schema marks `Yes` as this "
            "field's default, which is the worst of its four values")
    elif value in ("1", "2", "3"):
        label = SAVED_CREDENTIAL_LABELS.get(value, value)
        if value == "1":
            parts.append(
                f"the first agent configuration an endpoint matches permits the app to keep the "
                f"user's password on the endpoint - `save-user-credentials` is `{value}`, which "
                f"the device labels `{label}` - so a laptop that is stolen, resold or compromised "
                f"carries a working remote-access credential for the corporate network in its own "
                f"storage. This is also the value the device's schema marks as the default, so it "
                f"is where an estate that never touched the field most likely sits")
        elif value == "3":
            parts.append(
                f"the password is STILL STORED on the endpoint and a local biometric gates its "
                f"release - `save-user-credentials` is `{value}`, `{label}`. What gates it is a "
                f"check this firewall cannot see and that whoever holds the device may be able to "
                f"satisfy, so the credential is on the device and the control over it is not the "
                f"firewall's. THE CATALOGUE'S OWN NOTES LABEL THIS VALUE THE OTHER WAY ROUND - "
                f"`Yes with User Fingerprint` - which points at a weaker reading than the device "
                f"and the vendor agree on")
        else:
            parts.append(
                f"the app keeps the username and no password - `save-user-credentials` is "
                f"`{value}`, `{label}` - so nothing can be lifted off the device and used to "
                f"connect. What remains is a confirmed account name against a confirmed portal, "
                f"which is reconnaissance rather than access")
    if not parts:
        return []
    parts.append(
        "AND THE HARDENED VALUE DOES NOT BY ITSELF PRODUCE A CREDENTIAL PROMPT PER CONNECTION: the "
        "authentication-override cookie is a neighbouring node on this same agent configuration "
        "and pre-empts re-entry. This control is about what is STORED on the endpoint, which is "
        "what its own node decides; connect-before-logon and single sign-on are what cover the "
        "user-experience need instead of a cached password")
    return parts


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. Four controls over one model, so the mapping is
#: per control id and a control never borrows another's sentence - PAN-GPP-004's reading would be
#: wrong on a PAN-GPP-001 row and a reader could not tell.
PARTS_BY_CONTROL = {
    "PAN-GPP-001": (_transport_profile,),
    "PAN-GPP-003": (_agent_upgrade,),
    "PAN-GPP-004": (_saved_credentials,),
    "PAN-GPP-005": (_login_page,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"GlobalProtect portal {obj.name} in {obj.vsys_name} on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_globalprotect_portal_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="GlobalProtect portal",
    control_type=Control.ControlType.GLOBALPROTECT_PORTAL,
    finding_model=GlobalProtectPortalFinding,
    link_model=GlobalProtectPortalFindingControlQuery,
    subject_fk="globalprotect_portal",
    link_fk="globalprotect_portal_finding",
    queryset=lambda: GlobalProtectPortal.objects.select_related(
        "appliance", "appliance_group"),
    evaluate=evaluate_globalprotect_portal_control_queries,
    summary=build_globalprotect_portal_finding_summary,
    subject_name=lambda obj: obj.name,
    # The vsys and the appliance, because the portal name's namespace is one APPLIANCE - measured
    # at the write - so two appliances and an HA pair all collide on it.
    subject_scope=lambda obj: f"{obj.appliance} / {obj.vsys_name}",
)


def generate_globalprotect_portal_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_globalprotect_portal_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
