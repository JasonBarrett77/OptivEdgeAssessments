"""Finding generation for management-surface controls.

One finding per SURFACE, not per appliance. An appliance carries several administrative
surfaces and each is a separate exposure, so a control asserting "management access is
restricted" legitimately produces several findings for one device. The subject name is
frozen onto the finding at generation time for the same reason `matched_query_names` is:
an interface can be renamed or a profile unbound, and a finding must still say what it
found when it found it.

The machinery below - load controls, evaluate, delete, create, link - lives in
`object_findings`. It was 111 of 122 lines identical across five modules. What stays here is
the subject sentence, which is the part that carries meaning and belongs next to the object it
describes.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_management_interface_control_queries
from assessments.models import (
    Control,
    ManagementInterfaceFinding,
    ManagementInterfaceFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from assessments.management_interface_naming import surface_label
from optivedge_integrations.integrations.models import ManagementInterface


def _subject(obj) -> str:
    return f"{surface_label(obj)} on {obj.appliance}"


def build_management_interface_finding_summary(obj, matched_queries) -> str:
    """Lead with the subject - a finding that does not name its door is not actionable."""
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="management interface",
    control_type=Control.ControlType.MANAGEMENT_INTERFACE,
    finding_model=ManagementInterfaceFinding,
    link_model=ManagementInterfaceFindingControlQuery,
    subject_fk="management_interface",
    link_fk="management_interface_finding",
    queryset=lambda: ManagementInterface.objects.select_related("appliance"),
    evaluate=evaluate_management_interface_control_queries,
    summary=build_management_interface_finding_summary,
    subject_name=lambda obj: surface_label(obj),
)

#: Kept so importers do not have to know the generator was factored out.
ManagementInterfaceFindingRunResult = ObjectFindingRunResult


def generate_management_interface_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_management_interface_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
