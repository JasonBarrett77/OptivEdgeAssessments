"""Finding generation for one row of one GlobalProtect portal's client-authentication table.
PAN-GPP-002.

THE FINDING NAMES THE ROW AND THE ENDPOINT CLASS, which is the whole reason this subject is the
row and not the portal. The table is KEYED BY `os` - `Any`, `Browser`, `Satellite`, or one of
eleven per-platform names the leaf also references - so one portal can demand both factors of one
class and neither of another. Measured on this estate: two rows of ONE portal on pan-fw-111 sit at
`high` and at `no_finding`. A finding at the portal grain would report one verdict for both, could
not say which class was weak, and would show the compliant row beside the failing one as though
they agreed.

THE SENTENCE DISTINGUISHES THE THREE WAYS ADMISSION FAILS, because they are three different
remediations on two different objects and the derived verdict alone cannot tell them apart:

* NO CERTIFICATE PROFILE IS BOUND TO THE PORTAL AT ALL, so no client certificate can be demanded
  of any endpoint class whatever this row says. The fix is on the PARENT portal, not on this row.
* ONE IS BOUND AND THE AND/OR SWITCH IS PERMISSIVE, so the endpoint is admitted on whichever of
  the two factors it can produce. The fix is this row's own switch, and it is one value.
* THE SWITCH IS ABSENT, so what this row demands was not established. Both candidate readings are
  the two ENDS of the grading, which is why stage 5 reports it at the worst rank rather than
  resolving it.

THE VENDOR'S POLARITY IS KEPT AND IT READS BACKWARDS, which the sentence spells out rather than
leaving to a reader. `yes` on `user-credential-or-client-cert-required` means a password OR a
client certificate will do - the PERMISSIVE state - and `no` means both are required, which is the
hardened one. The device's own help string carries it: `No (User Credentials AND Client Certificate
Required)`. A reviewer who selected `yes` believing they had the hardened rows selected exactly the
permissive ones.

TWO THINGS NO SENTENCE HERE MAY CLAIM, both stage 3 and stage 5 limits rather than caution added
here:

* THAT THE IDENTITY SERVICE ENFORCES A SECOND FACTOR. The firewall records WHICH authentication
  object it asks and never what that object demands, so stage 3's acceptable minimum - a password
  verified by a service the customer confirms enforces MFA - is not a value of any column and
  stage 5 placed no rank for it. A row naming a SAML or RADIUS object is not evidence of MFA here.
* THAT THE FALLBACK PATH IS COVERED. The first factor may be an authentication PROFILE or an
  authentication SEQUENCE - two different objects, both shipped downstream - and this column cannot
  say which. A sequence is tried member by member until one succeeds, so a portal bound to one
  whose last member is the firewall's own local user database accepts a locally held password
  whenever the identity service is unreachable. That is stage 3's fallback assertion and it is
  unexpressed rather than satisfied; the finding names the bound object so an engineer can resolve
  it by hand.

AND THE WEAKEST ADMISSION STATE THE DEVICE PERMITS PRODUCES NO FINDING HERE AT ALL. A portal with
an EMPTY authentication table demands nothing of anybody, which is weaker than every rank this
control grades, and it produces no row of this model to report on.
`GlobalProtectPortal.client_auth_row_count` is the only column anywhere that can see it, and a
control's queries all compile against one model. That is a gap in this domain and the stage 8
artifact names it.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_globalprotect_portal_client_auth_control_queries,
)
from assessments.models import (
    Control,
    GlobalProtectPortalClientAuthFinding,
    GlobalProtectPortalClientAuthFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import GlobalProtectPortalClientAuthRow


def _admission(obj) -> list[str]:
    """PAN-GPP-002's record: does this row demand more than a password."""
    demand = obj.admission_demand or ""
    if demand == "password_and_certificate":
        return []
    parts = []
    endpoint_class = obj.os or "every class of endpoint this row applies to"
    if demand == "password_only":
        parts.append(
            f"this row admits `{endpoint_class}` on a PASSWORD ALONE. The and/or switch is set to "
            f"the permissive value - the vendor labels it `Allow Authentication with User "
            f"Credentials OR Client Certificate` - and the portal above this row binds NO "
            f"certificate profile, so there is no second factor for the OR to reach and a "
            f"credential that can be phished, sprayed or reused is the whole of the admission test")
    elif demand == "password_or_certificate":
        parts.append(
            f"this row admits `{endpoint_class}` on WHICHEVER of the two factors the endpoint can "
            f"produce. The and/or switch is set to the permissive value, and unlike the "
            f"password-only case a certificate profile IS bound above - so a client certificate is "
            f"available and is not required. An attacker needs only the easier of the two, which "
            f"is the password. The node's own name reads as the hardened value and means the "
            f"opposite")
    else:
        parts.append(
            f"WHAT THIS ROW DEMANDS OF `{endpoint_class}` WAS NOT ESTABLISHED, and that is "
            f"reported rather than resolved. The and/or switch is absent - the key is optional on "
            f"a committed row, measured - so one of the two inputs the verdict needs is missing. "
            f"Its two candidate meanings are the two ENDS of this control's grading, so "
            f"materialising either would report a rank nobody read; this is reported at the worst "
            f"of the two because a missing reading about whether a password alone opens the portal "
            f"is not a pass")
    if not obj.certificate_profile_bound:
        parts.append(
            "THE FIX FOR THE CERTIFICATE HALF IS ON THE PARENT PORTAL AND NOT ON THIS ROW: no "
            "certificate profile is bound at `portal-config/certificate-profile`, so no client "
            "certificate can be demanded of ANY endpoint class of this portal, whatever any row's "
            "switch says. Binding one is a portal-level write; this row's switch is only half the "
            "remediation")
    else:
        parts.append(
            "a certificate profile IS bound to the portal above this row, so the second factor "
            "exists and the remaining change is this row's own and/or switch - one value, set to "
            "require both rather than either")
    if obj.authentication_profile:
        parts.append(
            f"the first factor is `{obj.authentication_profile}`, and THIS ROW CANNOT SAY WHETHER "
            f"THAT NAME IS AN AUTHENTICATION PROFILE OR A SEQUENCE - two different objects, both "
            f"stored by this project. A sequence is tried member by member until one succeeds, so "
            f"if that name is a sequence whose last member is the firewall's own local user "
            f"database, this portal accepts a locally held password whenever the identity service "
            f"is unreachable. Resolve it by opening the name")
    else:
        parts.append(
            "this row names NO authentication object as its first factor, so what verifies the "
            "user is not recorded here at all")
    parts.append(
        "AND NOTHING HERE ESTABLISHES WHETHER A SECOND FACTOR IS ENFORCED BY THE IDENTITY SERVICE. "
        "The firewall records which object it asks and never what that object demands, so a row "
        "naming a SAML or RADIUS object is not evidence of MFA - that is the customer's to confirm, "
        "and it is why this control's acceptable minimum is not a value of any column")
    parts.append(
        "WHAT A FINDING ON THIS ROW COSTS AN ATTACKER WHO SUCCEEDS: the portal hands over the agent "
        "configuration and the network behind it, and the reconnection credential the portal then "
        "issues turns one phished password into access that outlives the session it was stolen in")
    return parts


#: One control, one reading. PAN-GPP-002 is the only control over this model.
PARTS_BY_CONTROL = {
    "PAN-GPP-002": (_admission,),
}


def _subject(obj, control_id: str) -> str:
    parts = [
        f"GlobalProtect portal authentication row {obj.name} on portal {obj.portal_name} "
        f"in {obj.vsys_name} on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, (_admission,)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_globalprotect_portal_client_auth_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="GlobalProtect portal authentication row",
    control_type=Control.ControlType.GLOBALPROTECT_PORTAL_CLIENT_AUTH,
    finding_model=GlobalProtectPortalClientAuthFinding,
    link_model=GlobalProtectPortalClientAuthFindingControlQuery,
    subject_fk="globalprotect_portal_client_auth_row",
    link_fk="globalprotect_portal_client_auth_finding",
    queryset=lambda: GlobalProtectPortalClientAuthRow.objects.select_related(
        "appliance", "appliance_group", "portal"),
    evaluate=evaluate_globalprotect_portal_client_auth_control_queries,
    summary=build_globalprotect_portal_client_auth_finding_summary,
    subject_name=lambda obj: obj.name,
    # The portal as well as the appliance and vsys: the row name is operator-chosen and carries no
    # meaning, and four portals of one vsys were measured each carrying a row called `r1`.
    subject_scope=lambda obj: f"{obj.appliance} / {obj.vsys_name} / {obj.portal_name}",
)


def generate_globalprotect_portal_client_auth_findings(
        assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_globalprotect_portal_client_auth_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
