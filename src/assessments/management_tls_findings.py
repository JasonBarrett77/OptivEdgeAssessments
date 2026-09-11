"""Finding generation for the management TLS controls. PAN-MGT-010 and PAN-CRT-006.

The sentence states the FLOOR and the CERTIFICATE VERDICT together, because the two controls
fail independently on one row and the interesting row is the one where they disagree: the
shipped TLSv1.3_Default profile gives the strongest floor available and still serves the device's
own self-signed certificate. A finding that named only its own half would hide that the "easy
fix" for one control is exactly what leaves the other failing.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_management_tls_control_queries
from assessments.models import (
    Control, ManagementTlsFinding, ManagementTlsFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import ManagementTlsBinding


def _subject(obj) -> str:
    if not obj.profile_name:
        # Measured 2026-09-02: an unbound management interface accepts TLS 1.1 and serves the
        # device's own certificate. Absence fails, it does not pass by default.
        return f"{obj.appliance} binds no SSL/TLS service profile to its management interface"
    if obj.ssl_tls_service_profile is None:
        return (f"{obj.appliance} binds SSL/TLS profile {obj.profile_name!r}, which resolves "
                f"to no predefined or shared profile")
    floor = obj.min_version or "no stated floor"
    trust = obj.get_certificate_trust_display().lower() if obj.certificate_trust else "no certificate"
    return (f"{obj.appliance} serves {obj.profile_name} ({obj.profile_scope}): minimum {floor}, "
            f"certificate {obj.certificate_name or '-'} - {trust}")


def build_management_tls_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="management TLS binding",
    control_type=Control.ControlType.MANAGEMENT_TLS,
    finding_model=ManagementTlsFinding,
    link_model=ManagementTlsFindingControlQuery,
    subject_fk="management_tls_binding",
    link_fk="management_tls_finding",
    queryset=lambda: ManagementTlsBinding.objects.select_related(
        "appliance", "ssl_tls_service_profile"),
    evaluate=evaluate_management_tls_control_queries,
    summary=build_management_tls_finding_summary,
    subject_name=lambda obj: str(obj.appliance),
)

ManagementTlsFindingRunResult = ObjectFindingRunResult


def generate_management_tls_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_management_tls_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
