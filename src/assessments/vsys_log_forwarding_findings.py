"""Finding generation for one virtual system's Log Forwarding availability. PAN-LOG-005.

THE VSYS IS THE SUBJECT AND NOT THE PROFILE, because the gap this control reports is a vsys with
NO adequate profile available to it, and a profile-keyed row cannot report something that does
not exist. The verdict spans FOUR namespaces - the vsys's own profiles, shared,
Panorama-pushed and vendor-predefined - and the integrations model records that name resolution
between them has no single true precedence ladder: for one profile name only the pushed copy was
offered to a rule and the local one shadowed, for another only the local one was offered and the
predefined dropped. So the gap column takes the UNION rather than a winner, and this sentence
follows it.

THE SUBJECT NAME IS `vsys_name` AND NOT `name`, WHICH THIS MODEL DOES NOT HAVE - the
`ObjectFindingSpec.subject_name` default would raise inside generation rather than at import.
`subject_scope` carries the appliance, because `vsys1` is not unique in an estate and is not
unique on one Panorama.

THE DISPATCH DEFAULTS TO `()` although one control uses this type today, for the reason the
repository has now repaired twice elsewhere: a default that is this control's arms is how the
next control on the type gets described with this control's claim.

WHAT NO FINDING HERE CAN SAY:

- WHETHER A COVERING PROFILE WAS PUSHED OR LOCAL. The device-group scope lives in provenance on
  the profile rows and this model stores none, which the integrations model's docstring records
  as a real `false` rather than a lapse. So a finding cannot tell an engineer whether the fix
  belongs on the firewall or on Panorama.
- WHETHER A LOG TYPE IS MISSING BECAUSE NOTHING SENDS IT OR BECAUSE NOTHING GENERATES IT. The
  threat record, for one, is only produced where a security profile is attached, and no column
  of this subject holds that.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_vsys_log_forwarding_control_queries
from assessments.models import (
    Control, VsysLogForwardingFinding, VsysLogForwardingFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import VsysLogForwarding

#: The log types stage 3 ranks above the rest, so the sentence can say which of the missing ones
#: are the ones an investigation starts from. The remaining members of the profile's own enum are
#: UNRANKED in stage 3 and this module does not invent a rank for them - it names them as not
#: ranked, which is what the stage 8 artifact raises for a person.
_SERIOUS = ("traffic", "threat", "url", "data", "wildfire")


def _owner(obj) -> str:
    return str(obj.appliance)


def _offbox_gaps(obj) -> list[str]:
    """PAN-LOG-005's only assertion: log types no reachable profile sends off the box."""
    missing = [token for token in str(obj.offbox_log_type_gaps or "").split(",") if token]
    if not missing:
        return []
    serious = [token for token in missing if token in _SERIOUS]
    unranked = [token for token in missing if token not in _SERIOUS]
    parts = [
        f"NO LOG FORWARDING PROFILE AVAILABLE TO {obj.vsys_name} ON {_owner(obj)} SENDS "
        f"{', '.join(missing)} OFF THE BOX, so those records exist only on the appliance and "
        f"are lost with it - counted across all four namespaces this vsys can reach, so this "
        f"is not a gap a shared or pushed profile closes elsewhere",
    ]
    if serious:
        parts.append(
            f"of those, {', '.join(serious)} are the records an investigation starts from: the "
            f"base account of what crossed the firewall and what was found in it")
    if unranked:
        parts.append(
            f"and {', '.join(unranked)} are log types the catalog has not ranked, so this "
            f"finding reports them as missing without claiming how much it matters")
    parts.append(
        "e-mail and SNMP-trap destinations do NOT count as off-box here - they notify rather "
        "than retain - so a log type delivered only as an alert is still reported")
    return parts


#: Keyed by control id, defaulting to `()`. See the module docstring.
PARTS_BY_CONTROL = {
    "PAN-LOG-005": (_offbox_gaps,),
}


def _subject(obj, control_id: str = "") -> str:
    parts: list[str] = []
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    if not parts:
        return f"the log forwarding available to {obj.vsys_name} on {_owner(obj)}"
    return "; ".join(parts)


def build_vsys_log_forwarding_finding_summary(obj, matched_queries) -> str:
    # The control id comes off the first matched query, which is safe because
    # `object_findings.generate_object_findings` iterates `for control in controls` and creates
    # the finding with that same control, so `matched_queries` holds one control's queries.
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="virtual system log forwarding",
    control_type=Control.ControlType.VSYS_LOG_FORWARDING,
    finding_model=VsysLogForwardingFinding,
    link_model=VsysLogForwardingFindingControlQuery,
    subject_fk="vsys_log_forwarding",
    link_fk="vsys_log_forwarding_finding",
    queryset=lambda: VsysLogForwarding.objects.select_related("appliance"),
    evaluate=evaluate_vsys_log_forwarding_control_queries,
    summary=build_vsys_log_forwarding_finding_summary,
    # The vsys's own name. NOT `obj.name`, which this model does not have.
    subject_name=lambda obj: obj.vsys_name,
    # The appliance that owns the virtual system - `vsys1` is not unique in an estate.
    subject_scope=lambda obj: _owner(obj)[:128],
)

VsysLogForwardingFindingRunResult = ObjectFindingRunResult


def generate_vsys_log_forwarding_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_vsys_log_forwarding_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
