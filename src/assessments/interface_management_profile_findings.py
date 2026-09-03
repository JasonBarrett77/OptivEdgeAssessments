"""Finding generation for interface-management-profile controls.

One finding per profile per appliance. A profile pushed from a Panorama template to ten
firewalls and bound on two produces eight findings, and that is the honest count: eight
devices carry a profile that does nothing. Collapsing them to one would read better and
assert something the data does not support, since each device's binding state is its own
fact. If that proves too noisy the fix belongs in presentation, which is where the policy
plane already makes the equivalent choice.

The machinery below - load controls, evaluate, delete, create, link - lives in
`object_findings`. It was 111 of 122 lines identical across five modules. What stays here is
the subject sentence, which is the part that carries meaning and belongs next to the object it
describes.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_interface_management_profile_control_queries
from assessments.models import (
    Control,
    InterfaceManagementProfileFinding,
    InterfaceManagementProfileFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import InterfaceManagementProfile


def _subject(obj) -> str:
    subject = f"Profile {obj.name} on {obj.appliance}"
    if obj.bound_interface_count == 0:
        return subject + " is bound to no interface"
    return subject + f" is bound to {', '.join(obj.bound_interface_names)}"


def build_interface_management_profile_finding_summary(obj, matched_queries) -> str:
    """Lead with the subject, and say what it is - not what it exposes, because it does not."""
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="interface management profile",
    control_type=Control.ControlType.INTERFACE_MANAGEMENT_PROFILE,
    finding_model=InterfaceManagementProfileFinding,
    link_model=InterfaceManagementProfileFindingControlQuery,
    subject_fk="interface_management_profile",
    link_fk="interface_management_profile_finding",
    queryset=lambda: InterfaceManagementProfile.objects.select_related("appliance"),
    evaluate=evaluate_interface_management_profile_control_queries,
    summary=build_interface_management_profile_finding_summary,
    subject_name=lambda obj: obj.name,
)

#: Kept so importers do not have to know the generator was factored out.
InterfaceManagementProfileFindingRunResult = ObjectFindingRunResult


def generate_interface_management_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_interface_management_profile_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
