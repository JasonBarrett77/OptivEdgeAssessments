"""Finding generation for SSL/TLS service profile controls.

One finding per object per appliance per scope, for the reason
`interface_management_profile_findings` records: the same object pushed from a template
exists separately in each firewall's merged config, and aggregating the copies would read
better while asserting something the data does not support.

Scope is carried on the finding because a name is not unique on a device. `TLSv1.3_Default`
exists as both a predefined and a shared entry, measured 2026-09-02, and only one of them is
in force - a finding naming the profile without its scope would not say which was assessed.

The machinery below - load controls, evaluate, delete, create, link - lives in
`object_findings`. It was 111 of 122 lines identical across five modules. What stays here is
the subject sentence, which is the part that carries meaning and belongs next to the object it
describes.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_ssl_tls_service_profile_control_queries
from assessments.models import (
    Control,
    SslTlsServiceProfileFinding,
    SslTlsServiceProfileFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import SslTlsServiceProfile


def _subject(obj) -> str:
    where = f"{obj.scope}:{obj.vsys_name}" if obj.vsys_name else obj.scope
    return (f"SSL/TLS service profile {obj.name} ({where}) on {obj.appliance}"
            f" sets a minimum protocol version of {obj.min_version or 'unset'}")


def build_ssl_tls_service_profile_finding_summary(obj, matched_queries) -> str:
    """The one sentence this object type contributes to its findings."""
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="SSL/TLS service profile",
    control_type=Control.ControlType.SSL_TLS_SERVICE_PROFILE,
    finding_model=SslTlsServiceProfileFinding,
    link_model=SslTlsServiceProfileFindingControlQuery,
    subject_fk="ssl_tls_service_profile",
    link_fk="ssl_tls_service_profile_finding",
    queryset=lambda: SslTlsServiceProfile.objects.select_related("appliance"),
    evaluate=evaluate_ssl_tls_service_profile_control_queries,
    summary=build_ssl_tls_service_profile_finding_summary,
    subject_name=lambda obj: obj.name,
    subject_scope=lambda obj: obj.scope,
)

#: Kept so importers do not have to know the generator was factored out.
SslTlsServiceProfileFindingRunResult = ObjectFindingRunResult


def generate_ssl_tls_service_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_ssl_tls_service_profile_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
