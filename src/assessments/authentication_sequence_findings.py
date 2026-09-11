"""Finding generation for authentication sequence controls. PAN-AAA-012.

One finding per sequence per appliance per scope, for the reason the authentication profiles
record: a template-pushed object exists separately in each firewall's merged config, and a
`shared` and a vsys definition can share a name.

The subject sentence lists the members IN ORDER with each one's method, because the order is
the meaning - the same two members the other way round put the local check first - and a
finding that said only "has a local member" would send an engineer to the device to find out
which, and where.
"""

from __future__ import annotations

from assessments.authentication_profile_findings import METHOD_LABELS
from assessments.control_queries import evaluate_authentication_sequence_control_queries
from assessments.models import (
    AuthenticationSequenceFinding,
    AuthenticationSequenceFindingControlQuery,
    Control,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import AuthenticationSequence


def _subject(obj) -> str:
    where = f"{obj.scope}:{obj.vsys_name}" if obj.vsys_name else obj.scope
    steps = [f"{name} ({METHOD_LABELS.get(method, method) if method else 'unresolved'})"
             for name, method in zip(obj.member_names, obj.member_methods)]
    subject = (f"Authentication sequence {obj.name} ({where}) on {obj.appliance} tries "
               + (", then ".join(steps) if steps else "no profiles"))
    if obj.is_administrative:
        subject += ", and an administrator authenticates through it"
    return subject


def build_authentication_sequence_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="authentication sequence",
    control_type=Control.ControlType.AUTHENTICATION_SEQUENCE,
    finding_model=AuthenticationSequenceFinding,
    link_model=AuthenticationSequenceFindingControlQuery,
    subject_fk="authentication_sequence",
    link_fk="authentication_sequence_finding",
    queryset=lambda: AuthenticationSequence.objects.select_related("appliance"),
    evaluate=evaluate_authentication_sequence_control_queries,
    summary=build_authentication_sequence_finding_summary,
    subject_name=lambda obj: obj.name,
    subject_scope=lambda obj: obj.scope,
)


def generate_authentication_sequence_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_authentication_sequence_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
