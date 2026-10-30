"""Finding generation for the approved-application inventory. PAN-SAS-001.

THE SENTENCE HAS TO SAY WHAT THE COUNT MEANS, because zero here is not a small number - it is the
vendor's own rule that a partition marking nothing treats EVERY application as unsanctioned. A
finding reading "sanctioned application count: 0" states the column and not the consequence.

AND IT HAS TO SAY WHAT THE SCREEN WILL LOOK LIKE WHEN THE ENGINEER OPENS IT, which is the one
measured trap on this control. On an appliance where `application-tag` is absent in every view,
the Objects > Applications grid's TAGS column is POPULATED on most rows - `Web App`, `Uploading`,
`Deleting` - and the filter panel counts them, because the grid renders the vendor's predefined
application CHARACTERISTIC tags and the operator's approval markings in the same chips. A reader
who opens the screen, sees tags and closes it again has refuted nothing. The sentence says so.

THREE THINGS THE SENTENCE IS NOT ALLOWED TO SAY:

* THAT THE MARKED SET IS THE APPROVED SET. The firewall holds no list of what the business
  approved; the marking IS the firewall's only record of it. So the finding reports whether the
  mechanism is used and never that the right applications are in it.
* THAT A MARKING WAS AUTHORED HERE. A marking pushed from a Panorama device group counts toward
  the count and the row has no column saying where it came from, so where the count is non-zero
  the sentence does not claim the partition's own configuration holds it.
* WHICH PARTITION IS IN FORCE where they disagree. Precedence for this node across vsys, shared
  and a Panorama push is UNMEASURED, so the inconsistency sentence reports the divergence and
  declines to say which side wins.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_sanctioned_application_marking_control_queries,
)
from assessments.models import (
    Control,
    SanctionedApplicationMarkingFinding,
    SanctionedApplicationMarkingFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import SanctionedApplicationMarking

#: How many marked application names the sentence lists before it stops. The list is what the
#: remediation is written against, and an inventory of two hundred applications in one sentence
#: is not a remediation anybody reads.
NAMES_SHOWN = 8


def _inventory(obj) -> list[str]:
    if obj.sanctioned_application_count:
        names = list(obj.marked_application_names or [])
        shown = ", ".join(str(n) for n in names[:NAMES_SHOWN])
        more = (f" and {len(names) - NAMES_SHOWN} more"
                if len(names) > NAMES_SHOWN else "")
        return [f"{obj.sanctioned_application_count} application(s) carry the predefined "
                f"approval tag in this virtual system"
                + (f" ({shown}{more})" if shown else "")
                + " - where the marking was AUTHORED is not recorded on this row, so a pushed "
                  "inventory reads the same as one this partition holds"]
    # THE WHOLE CONTROL, in the vendor's own terms rather than as a count of nothing.
    return ["no application in this virtual system carries the predefined approval tag, so the "
            "firewall has no record of which cloud applications the business approved - and by "
            "the vendor's own rule it then treats every application as unsanctioned. THE "
            "Objects > Applications GRID IS NOT THE PLACE TO CHECK THIS: it renders the "
            "vendor's predefined application characteristic tags in the same chips as the "
            "operator's approval markings, so that column can be full on a partition that marks "
            "nothing"]


def _consistency(obj) -> list[str]:
    if not obj.appliance_is_multi_vsys:
        # Not reachable through the companion query, which gates on this column - included so an
        # unmapped control reading every part cannot produce a sentence that claims agreement.
        return ["this appliance runs one virtual system, so there is no second partition for the "
                "marking to disagree with"]
    if not obj.marking_is_inconsistent_across_vsys:
        return []
    return ["at least one application is marked approved in another virtual system of this "
            "appliance and not in this one, or the reverse - so the appliance classifies the "
            "same application two ways. WHICH PARTITION IS IN FORCE IS NOT STATED HERE: "
            "precedence for this node across a virtual system, the firewall's shared namespace "
            "and a Panorama push has never been measured, so this is a report that they diverge "
            "and not a report of which one wins"]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. One control here, two halves, and they are kept
#: apart on purpose: a finding about an empty inventory that also reported cross-partition
#: disagreement would send a reader to compare partitions that all hold nothing.
PARTS_BY_CONTROL = {
    "PAN-SAS-001": (_inventory, _consistency),
}


def _subject(obj, control_id: str) -> str:
    appliance = obj.enforcement_point.appliance or obj.enforcement_point.appliance_group
    parts = [f"approved-application inventory of {obj.enforcement_point.vsys_name} "
             f"on {appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, (_inventory, _consistency)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_sanctioned_application_marking_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


def _appliance_scope(obj) -> str:
    appliance = obj.enforcement_point.appliance
    return str(appliance.hostname if appliance is not None
               else obj.enforcement_point.appliance_group)


SPEC = ObjectFindingSpec(
    label="sanctioned application marking",
    control_type=Control.ControlType.SANCTIONED_APPLICATION_MARKING,
    finding_model=SanctionedApplicationMarkingFinding,
    link_model=SanctionedApplicationMarkingFindingControlQuery,
    subject_fk="sanctioned_application_marking",
    link_fk="sanctioned_application_marking_finding",
    queryset=lambda: SanctionedApplicationMarking.objects.select_related(
        "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group"),
    evaluate=evaluate_sanctioned_application_marking_control_queries,
    summary=build_sanctioned_application_marking_finding_summary,
    # THE PARTITION AND NOT AN ENTRY KEY, because the subject is a verdict - see the finding
    # model's docstring. The appliance carries it, since `vsys1` is not unique in an estate.
    subject_name=lambda obj: obj.enforcement_point.vsys_name,
    subject_scope=_appliance_scope,
)


def generate_sanctioned_application_marking_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_sanctioned_application_marking_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
