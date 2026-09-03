"""Finding generation for certificate controls.

One finding per object per appliance per scope, for the reason
`interface_management_profile_findings` records: the same object pushed from a template
exists separately in each firewall's merged config, and aggregating the copies would read
better while asserting something the data does not support.

Scope is carried on the finding because a name is not unique on a device. `TLSv1.3_Default`
exists as both a predefined and a shared entry, measured 2026-09-02, and only one of them is
in force - a finding naming the certificate without its scope would not say which was
assessed. Scope also decides whether a finding is actionable at all: a predefined certificate
is read-only, so it cannot be remediated on the device.

The machinery below - load controls, evaluate, delete, create, link - lives in
`object_findings`. It was 111 of 122 lines identical across five modules. What stays here is
the subject sentence, which is the part that carries meaning and belongs next to the object it
describes.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_certificate_control_queries
from assessments.models import (
    Control,
    CertificateFinding,
    CertificateFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import Certificate


def _subject(obj) -> str:
    where = f"{obj.scope}:{obj.vsys_name}" if obj.vsys_name else obj.scope
    subject = f"Certificate {obj.name} ({where}) on {obj.appliance}"
    detail = []
    if obj.key_algorithm:
        detail.append(f"{obj.key_algorithm} {obj.key_size_bits or '?'}-bit")
    if obj.signature_algorithm:
        detail.append(f"signed {obj.signature_algorithm}")
    if obj.not_valid_after:
        detail.append(f"expires {obj.not_valid_after:%Y-%m-%d}")
    if obj.parse_error:
        detail.append(f"could not be decoded ({obj.parse_error})")
    if detail:
        subject += " is " + ", ".join(detail)
    return subject


def build_certificate_finding_summary(obj, matched_queries) -> str:
    """The one sentence this object type contributes to its findings."""
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="certificate",
    control_type=Control.ControlType.CERTIFICATE,
    finding_model=CertificateFinding,
    link_model=CertificateFindingControlQuery,
    subject_fk="certificate",
    link_fk="certificate_finding",
    queryset=lambda: Certificate.objects.select_related("appliance"),
    evaluate=evaluate_certificate_control_queries,
    summary=build_certificate_finding_summary,
    subject_name=lambda obj: obj.name,
    subject_scope=lambda obj: obj.scope,
)

#: Kept so importers do not have to know the generator was factored out.
CertificateFindingRunResult = ObjectFindingRunResult


def generate_certificate_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_certificate_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
