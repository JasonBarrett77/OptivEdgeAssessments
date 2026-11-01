"""Finding generation for one virtual system's GlobalProtect objects taken as a whole.
PAN-GPP-006.

THE FINDING NAMES THE VIRTUAL SYSTEM AND NOT A PORTAL, because what this control asserts is an
ABSENCE and nothing that does not exist can carry a row. PAN-GPP-006 asserts that no portal
publishes internal web applications for browser access AND that neither the portal nor the firewall
holds the application definitions or application groups such publishing would draw on.

THE SENTENCE DISTINGUISHES LIVE FROM LATENT, because they are two different remediations and the
same verdict column holds both:

* LIVE - at least one portal carries a `clientless-vpn` branch and the vsys holds at least one
  application definition or group, so the surface is reachable by any browser that can reach the
  portal.
* LATENT - the definitions exist and NO portal publishes them, so nothing is reachable today. What
  is present is a configuration one edit from being live and a record that somebody built this once
  and may not know it is still there. THIS IS THE RANK THE VSYS GRAIN EXISTS FOR: there is no
  portal row for it to be reported on, measured on vsys6 of this estate - one definition, no
  portal, no interface imported - so a portal-keyed finding is silent on it by construction.
* UNKNOWN - the row was not resolved. It is reported at the baseline with the engineer's questions
  attached, because the two directions of error are different and both matter: an absence must not
  be reported as a decision to keep the feature off, and a presence must not be reported as an
  undocumented one.

NODE PRESENCE IS THE WRONG TEST AND THE SENTENCE RESTS ON COUNTS. Deleting the last entry leaves
the container present and empty; deleting the container leaves `global-protect` present and empty;
one appliance in this estate carries exactly that, committed and undecorated, with `action=get`
answering a count of one for it. A truthiness test on the container reports a portal where there is
none, and the counts beside this row are what the sentence prints instead.

THERE IS NO OFF SWITCH TO READ. Stage 4 enumerated the `clientless-vpn` container's children on
three builds - ten of them, and not one is a boolean - so `absent OR disabled` collapses to "the
element exists or it does not". A reader who looked for a switch and found none would report every
portal with the feature fully configured as compliant.

TWO THINGS NO SENTENCE HERE MAY CLAIM:

* THAT THE FEATURE IS SUPPORTED HERE, OR THAT IT IS NOT. The vendor says it is unsupported on a
  firewall with multiple virtual systems IF the clientless traffic must traverse several virtual
  systems - a statement about where traffic GOES, which no configuration node holds. Stage 3 left
  it as the engineer's question rather than approximating it by a multi-vsys test, which would
  suppress the control on every multi-vsys appliance including the ones where the feature is
  perfectly supported.
* THAT AN UNLICENSED APPLIANCE WAS CHECKED. The applicability clause suppresses this control only
  where a POPULATED licence list carries no GlobalProtect feature - a definite no. On two
  appliances of this estate the reply is `{'licenses': None}`, truthy and empty, so the answer is
  UNKNOWN rather than no and the control fires. Suppressing on an unknown reads as careful and does
  the opposite.

THE HALF OF PAN-GPP-006 THAT IS SILENT HERE, stated because a reader would otherwise take this for
the whole control. Its second record - where a portal DOES publish, the browser sessions carrying
those applications may not negotiate weaker transport than the portal itself requires - clauses on
`integrations.GlobalProtectPortal`, a different model, so no query on this control can carry it.
Standing ruling 6's relation remedy has nothing to walk: there is no Django relation between this
model and the portal in EITHER direction, introspected rather than argued. The two share only
`appliance`, and that reverse accessor is to-MANY and crosses vsys boundaries, so it would fire one
virtual system's row for a portal in another. The clientless transport is a SECOND, independently
configured transport on the same internet-facing service, weaker than the portal's own in every
respect - four values with no TLS 1.3 at all against the service profile's tls1-0 through tls1-3,
and a schema default of tls1-0 against the profile's tls1-2 - and PAN-CRT-005, which looks as
though it covers every TLS floor on the device, does not cover this one. So where this finding says
a feature is LIVE, the transport those sessions negotiate is unasserted by anything. The stage 8
artifact for `globalprotect-portal` records the half in `subjects_in_two_models`.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_globalprotect_enforcement_point_control_queries,
)
from assessments.models import (
    Control,
    GlobalProtectEnforcementPointFinding,
    GlobalProtectEnforcementPointFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import GlobalProtectEnforcementPoint


def _definitions_clause(obj) -> str:
    return (
        f"{obj.clientless_app_count} clientless application definition(s) and "
        f"{obj.clientless_app_group_count} application group(s) are held in this virtual system, "
        f"with {obj.portals_publishing_clientless_apps} of its {obj.portal_count} portal(s) "
        f"carrying a `clientless-vpn` branch. BOTH OBJECT KINDS ARE COUNTED and not only the "
        f"definitions: the vendor's own sentence names two screens, and an application reachable "
        f"only through a GROUP would have made this virtual system look clean")


def _clientless_vpn(obj) -> list[str]:
    """PAN-GPP-006's first record: is the clientless-VPN surface present at all."""
    state = obj.clientless_vpn_feature_state or ""
    if state == "absent":
        return []
    parts = []
    if state == "live":
        parts.append(
            "this virtual system PUBLISHES INTERNAL WEB APPLICATIONS FOR BROWSER ACCESS - a portal "
            "carries the clientless-VPN branch and the application definitions exist - so the "
            "firewall is in the business of rewriting and proxying those applications' pages on "
            "behalf of an internet-facing service. That is a far larger surface than a tunnel and "
            "one that has carried pre-authentication exploit chains")
    elif state == "latent":
        parts.append(
            "the pieces of clientless VPN are HELD HERE AND NOTHING PUBLISHES THEM: no portal in "
            "this virtual system carries a `clientless-vpn` branch, so nothing is reachable today. "
            "What is present is a configuration one edit from being live, and a record that "
            "somebody built this once and may not know it is still there. THERE IS NO PORTAL ROW "
            "FOR THIS TO BE REPORTED ON, which is why it is reported here")
    else:
        parts.append(
            "WHETHER THIS VIRTUAL SYSTEM PUBLISHES WEB APPLICATIONS FOR BROWSER ACCESS WAS NOT "
            "RESOLVED, and that is reported rather than counted as clean. The two directions of "
            "error are different and both matter: an absence must not be reported as a decision to "
            "keep the feature off, and a presence must not be reported as an undocumented one")
    parts.append(_definitions_clause(obj))
    parts.append(
        "THERE IS NO OFF SWITCH TO READ ANYWHERE UNDER THE BRANCH - ten children and not one of "
        "them a boolean, measured on three builds - so this reading is the PRESENCE of the "
        "elements and an entry count over them, not a setting. A reviewer who opens the portal "
        "looking for a checkbox to confirm this will not find one; what to look at is whether the "
        "Clientless VPN tab has applications in it")
    parts.append(
        "WHETHER THE BUSINESS NEEDS THIS IS THE CUSTOMER'S FACT. The control's own standard is that "
        "the feature is absent unless somebody can point to the need that requires it, so confirm "
        "the need and the review of each published application rather than reading this as a "
        "misconfiguration")
    parts.append(
        "AND THE TRANSPORT THOSE BROWSER SESSIONS NEGOTIATE IS NOT ASSERTED BY ANYTHING. It is a "
        "SECOND, independently configured transport on the same internet-facing service, weaker "
        "than the portal's own in every respect - it offers no TLS 1.3 at all and its schema "
        "default is TLS 1.0, against the portal's service profile which offers 1.3 and defaults to "
        "1.2 - and the control that looks as though it covers every TLS floor on this device does "
        "not cover this node. Read the floor on each publishing portal by hand")
    if not obj.licence_reply_collected:
        parts.append(
            "THE LICENCE QUESTION BEHIND THIS ROW WAS NEVER ASKED: no licence reply was obtained "
            "from this appliance at all, so whether GlobalProtect is licensed here is unknown "
            "rather than answered. The control fires on an unknown by design - an appliance that "
            "was never asked is not an appliance that answered no")
    elif obj.globalprotect_portal_licensed == "unknown":
        parts.append(
            f"THE LICENCE ANSWER IS UNKNOWN RATHER THAN YES OR NO: the appliance reported "
            f"{obj.licence_entry_count} licence entr(ies), so the list is not populated enough to "
            f"settle whether GlobalProtect is licensed. The control fires rather than suppressing, "
            f"because suppressing on an unknown would convert an unanswered licensing question "
            f"into silence")
    return parts


#: One control, one reading. PAN-GPP-006 is the only control over this model - and only the first
#: of its two records; see the module docstring.
PARTS_BY_CONTROL = {
    "PAN-GPP-006": (_clientless_vpn,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"GlobalProtect objects of {obj.vsys_name} on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, (_clientless_vpn,)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_globalprotect_enforcement_point_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="GlobalProtect enforcement point",
    control_type=Control.ControlType.GLOBALPROTECT_ENFORCEMENT_POINT,
    finding_model=GlobalProtectEnforcementPointFinding,
    link_model=GlobalProtectEnforcementPointFindingControlQuery,
    subject_fk="globalprotect_enforcement_point",
    link_fk="globalprotect_enforcement_point_finding",
    queryset=lambda: GlobalProtectEnforcementPoint.objects.select_related(
        "appliance", "appliance_group"),
    evaluate=evaluate_globalprotect_enforcement_point_control_queries,
    summary=build_globalprotect_enforcement_point_finding_summary,
    # The vsys, because the row has no entry name at all - one portal's name would be the wrong
    # thing to print on a verdict about whether any of them publishes anything.
    subject_name=lambda obj: obj.vsys_name,
    # And the appliance, because `vsys1` exists on every single-vsys platform in the estate.
    subject_scope=lambda obj: str(obj.appliance),
)


def generate_globalprotect_enforcement_point_findings(
        assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_globalprotect_enforcement_point_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
