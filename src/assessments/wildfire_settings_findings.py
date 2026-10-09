"""Finding generation for the device-wide WildFire settings. PAN-AVW-004 and PAN-AVW-005.

TWO CONTROLS, ONE MODEL, OPPOSITE POLARITIES - so the sentence is built per control rather
than once for the object. PAN-AVW-004 fires when nothing has been TUNED; PAN-AVW-005 when
something is WITHHELD or unreported. One shared sentence would have to be vague enough to
cover both, which is how a finding stops telling an engineer what to do.

Both fire on an UNTOUCHED device, and the sentence says so. A finding that reads like a
misconfiguration when it is really an unset default sends an assessor looking for who changed
it - the same reason PAN-MGT-011's sentence names its default.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_wildfire_settings_control_queries
from assessments.models import (
    Control, WildfireSettingsFinding, WildfireSettingsFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import WildfireSettings

#: Which control a matched query belongs to decides which sentence to write.
TUNING = "PAN-AVW-004"


def _tuning_subject(obj) -> str:
    """PAN-AVW-004. Names the count, not the eleven types - the row carries those."""
    total = len(obj.DEFAULT_SIZE_LIMITS)
    untuned = len(obj.untuned_file_types)
    if untuned == total:
        return (f"{obj.appliance} has not sized ANY WildFire file size limit for this estate "
                f"- all {total} file types are still at the PAN-OS default")
    return (f"{obj.appliance} has {untuned} of {total} WildFire file size limits still at "
            f"the PAN-OS default ({', '.join(obj.untuned_file_types)})")


def _sharing_subject(obj) -> str:
    """PAN-AVW-005. Names what is withheld, in the screen's own terms."""
    gaps = obj.session_info_gaps
    if not gaps:
        return (f"{obj.appliance} shares full session information with WildFire and reports "
                f"both benign and grayware verdicts")
    return f"{obj.appliance}: {'; '.join(gaps)}"


def build_wildfire_settings_finding_summary(obj, matched_queries) -> str:
    control_ids = {
        q.control.control_id for q in matched_queries
        if getattr(q, "control", None) is not None}
    subject = _tuning_subject(obj) if control_ids == {TUNING} else _sharing_subject(obj)
    return matched_query_sentence(subject, matched_queries)


SPEC = ObjectFindingSpec(
    label="wildfire settings",
    control_type=Control.ControlType.WILDFIRE_SETTINGS,
    finding_model=WildfireSettingsFinding,
    link_model=WildfireSettingsFindingControlQuery,
    subject_fk="wildfire_settings",
    link_fk="wildfire_settings_finding",
    queryset=lambda: WildfireSettings.objects.select_related("appliance"),
    evaluate=evaluate_wildfire_settings_control_queries,
    summary=build_wildfire_settings_finding_summary,
    #: These settings have no name of their own, so the appliance IS the subject name.
    subject_name=lambda obj: str(obj.appliance),
)

WildfireSettingsFindingRunResult = ObjectFindingRunResult


def generate_wildfire_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_wildfire_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
