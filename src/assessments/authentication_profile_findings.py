"""Finding generation for authentication profile controls.

One finding per profile per appliance per scope, for the reason the certificate objects record:
the same object pushed from a template exists separately in each firewall's merged config, and a
`shared` definition and a vsys one can share a name.

The subject sentence leads with the METHOD, because it is the fact that decides whether the
profile means anything. Three of the lab's four profiles on one device are `method none`, which
performs no authentication at all - a finding that named only the profile would read as though
something were configured.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_authentication_profile_control_queries
from assessments.models import (
    AuthenticationProfileFinding,
    AuthenticationProfileFindingControlQuery,
    Control,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import AuthenticationProfile

#: How PAN-OS names each method in the UI, so a finding reads the way the screen does.
METHOD_LABELS = {
    "": "no method set",
    "none": "no authentication (method None)",
    "local-database": "the local user database",
    "cloud": "the Cloud Authentication Service",
    "radius": "RADIUS",
    "tacplus": "TACACS+",
    "ldap": "LDAP",
    "kerberos": "Kerberos",
    "saml-idp": "SAML",
}


def _subject(obj) -> str:
    where = f"{obj.scope}:{obj.vsys_name}" if obj.vsys_name else obj.scope
    subject = (f"Authentication profile {obj.name} ({where}) on {obj.appliance} "
               f"authenticates against {METHOD_LABELS.get(obj.method, obj.method)}")
    if obj.lockout_failed_attempts == 0:
        # 0 is UNLIMITED attempts, not a strict limit. Saying "0" alone invites the opposite
        # reading, which is the whole trap in this field.
        subject += " and allows unlimited failed login attempts"
    else:
        subject += f" and locks out after {obj.lockout_failed_attempts} failed attempts"
    if not obj.mfa_enabled:
        subject += ", with no multi-factor authentication"
    return subject


def build_authentication_profile_finding_summary(obj, matched_queries) -> str:
    """The one sentence this object type contributes to its findings."""
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="authentication profile",
    control_type=Control.ControlType.AUTHENTICATION_PROFILE,
    finding_model=AuthenticationProfileFinding,
    link_model=AuthenticationProfileFindingControlQuery,
    subject_fk="authentication_profile",
    link_fk="authentication_profile_finding",
    queryset=lambda: AuthenticationProfile.objects.select_related("appliance"),
    evaluate=evaluate_authentication_profile_control_queries,
    summary=build_authentication_profile_finding_summary,
    subject_name=lambda obj: obj.name,
    subject_scope=lambda obj: obj.scope,
)

#: Kept so importers do not have to know the generator was factored out.
AuthenticationProfileFindingRunResult = ObjectFindingRunResult


def generate_authentication_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_authentication_profile_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
