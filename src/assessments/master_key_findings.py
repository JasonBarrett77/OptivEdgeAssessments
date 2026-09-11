"""Finding generation for the master key control. PAN-CRT-007.

The sentence distinguishes the three states, because two of them fire and they are not the same
problem: a FACTORY DEFAULT key is a device nobody has hardened, and UNDETERMINED is a device
nobody has asked. The remediation for the first is to set a key; for the second it is to collect
`show masterkey properties`.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_master_key_control_queries
from assessments.models import (
    Control, MasterKeyFinding, MasterKeyFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import MasterKey


def _subject(obj) -> str:
    if obj.state == obj.__class__.STATE_SET:
        return f"Master key on {obj.appliance} is configured (expires {obj.expires_at})"
    if obj.state == obj.__class__.STATE_DEFAULT:
        return f"Master key on {obj.appliance} is the FACTORY DEFAULT"
    return f"Master key on {obj.appliance} could not be determined - it was never read"


def build_master_key_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="master key",
    control_type=Control.ControlType.MASTER_KEY,
    finding_model=MasterKeyFinding,
    link_model=MasterKeyFindingControlQuery,
    subject_fk="master_key",
    link_fk="master_key_finding",
    queryset=lambda: MasterKey.objects.select_related("appliance"),
    evaluate=evaluate_master_key_control_queries,
    summary=build_master_key_finding_summary,
    #: The policy has no name of its own, so the appliance IS the subject name.
    subject_name=lambda obj: str(obj.appliance),
)

MasterKeyFindingRunResult = ObjectFindingRunResult


def generate_master_key_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_master_key_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
