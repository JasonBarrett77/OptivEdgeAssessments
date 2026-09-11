"""Finding generation for AAA server profile controls. PAN-AAA-001, 002, 004, 006, 008, 009, 013.

The subject sentence names the KIND and the value, because six kinds share one table and
"corp-ldap does not require SSL/TLS" is only actionable if the reader knows which of six screens
to open and what the setting currently says.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_server_profile_control_queries
from assessments.models import (
    Control, ServerProfileFinding, ServerProfileFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import ServerProfile


def _setting(obj) -> str:
    """The value the reader has to change, in the words of the screen it lives on."""
    if obj.kind == ServerProfile.Kind.LDAP:
        return (f"SSL/TLS {'on' if obj.ldap_ssl else 'OFF'}, "
                f"certificate verification "
                f"{'on' if obj.ldap_verify_server_certificate else 'OFF'}")
    if obj.kind in (ServerProfile.Kind.RADIUS, ServerProfile.Kind.TACPLUS):
        return f"protocol {obj.protocol or 'unset'}"
    if obj.kind == ServerProfile.Kind.SAML_IDP:
        return (f"IdP certificate validation "
                f"{'on' if obj.saml_validate_idp_certificate else 'OFF'}, "
                f"message signing "
                f"{'on' if obj.saml_want_auth_requests_signed else 'OFF'}")
    if obj.kind == ServerProfile.Kind.MFA:
        return f"vendor {obj.mfa_vendor_type or 'unset'}"
    return f"{obj.server_count} server(s)"


def _subject(obj) -> str:
    where = obj.scope if obj.scope == "shared" else f"{obj.scope} {obj.vsys_name}"
    used = ("referenced by nothing" if obj.referrer_count == 0
            else f"referenced from {obj.referrer_count} place(s)")
    return (f"{obj.get_kind_display()} server profile {obj.name} in {where} on "
            f"{obj.appliance} has {_setting(obj)} and is {used}")


def build_server_profile_finding_summary(obj, matched_queries) -> str:
    """The one sentence this object type contributes to its findings."""
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="AAA server profile",
    control_type=Control.ControlType.SERVER_PROFILE,
    finding_model=ServerProfileFinding,
    link_model=ServerProfileFindingControlQuery,
    subject_fk="server_profile",
    link_fk="server_profile_finding",
    queryset=lambda: ServerProfile.objects.select_related("appliance"),
    evaluate=evaluate_server_profile_control_queries,
    summary=build_server_profile_finding_summary,
    subject_name=lambda obj: obj.name,
    subject_scope=lambda obj: obj.scope if obj.scope == "shared" else f"{obj.scope}:{obj.vsys_name}",
)

ServerProfileFindingRunResult = ObjectFindingRunResult


def generate_server_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_server_profile_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
