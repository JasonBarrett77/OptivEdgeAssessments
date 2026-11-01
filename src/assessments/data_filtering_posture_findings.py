"""Finding generation for one enforcement point's outward data-filtering posture. PAN-FIL-003.

THE SENTENCE DISTINGUISHES THE THREE WAYS THE VERDICT FAILS, because they are three different
remediations and the verdict column alone cannot tell them apart:

* NO PROFILE IN FORCE - nobody configured data filtering, or nothing references what was
  configured. The fix starts with a profile and a rule that names it.
* IN FORCE BUT NAMING NO PATTERN - a profile reached by a rule whose rules name no data pattern
  object at all, which is valid configuration that scans nothing.
* NAMING A PATTERN OBJECT THAT DEFINES NOTHING - the reference resolves, because the device
  refuses a dangling `data-object` at the write, and the object behind it matches nothing. This is
  the one a configuration review passes every time.

TWO THINGS THE SENTENCE IS NOT ALLOWED TO CLAIM, and both are stage 3's own limits rather than
caution added here.

* THAT A PASS MEANS SENSITIVE DATA CANNOT LEAVE. The vendor's disclaimer on this screen says the
  file-type selection "does not block all possible file types, just the listed ones", and that
  list measured THIRTEEN members on both lab platforms - office documents, PDFs and HTML. A zip, a
  CSV export, a plain text file, a database dump or an image passes this mechanism unexamined, so
  the sentence names the bound rather than letting a reader supply their own.
* THAT THE ORGANISATION HAS NO DATA-LOSS PROTECTION. An Enterprise DLP subscription supersedes
  pattern-based data filtering where licensed, and this control's own evidence source for that is
  another system. Stage 3 deliberately declined to make the licensing question an applicability
  clause, "because the suppressing form would convert an unanswered licensing question into
  silence". So the finding says this firewall's own pattern matching is not in force, and no more.

AND IT DOES NOT SAY WHICH TRAFFIC IS OUTWARD. Which of this firewall's zones and destinations are
outside the organisation's control is a question the configuration cannot answer - it shows the
zones and what each rule permits, not where a zone goes - so the finding applies to whichever
rules carry traffic outward, named rather than assumed.

THE HALF OF THIS CONTROL THAT IS SILENT HERE, stated because a reader of the finding would
otherwise take it for the whole control: PAN-FIL-003's second record asserts that every rule of a
watching profile carries both the alert count and the block count. Its clauses are on
`integrations.SecurityProfile` and nothing in this module can reach them. The stage 8 artifact for
`file-data-filtering` records it in `subjects_in_two_models`, with the measurement behind the
decision.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_data_filtering_posture_control_queries
from assessments.models import (
    Control,
    DataFilteringPostureFinding,
    DataFilteringPostureFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import DataFilteringPosture


#: THE THIRTEEN FILE TYPES THIS MECHANISM READS, as a count rather than a list: the names are
#: content-supplied and the point of the sentence is the BOUND, not the enumeration.
WATCHED_FILE_TYPE_COUNT = 13


def _not_effective(obj) -> list[str]:
    """PAN-FIL-003's first record: is anything watching the traffic that leaves."""
    if obj.outward_data_filtering_effective:
        return []
    parts = []
    if not obj.data_filtering_in_force:
        parts.append(
            "no data-filtering profile carrying any rule reaches the traffic this enforcement "
            "point permits, by any route - no security rule names one and no profile group a "
            "rule names does either, at any scope, local or pushed - so nothing on this firewall "
            "is examining what leaves it for regulated data")
    elif not obj.named_patterns_defined:
        parts.append(
            "a data-filtering profile IS in force here and the data pattern object its rules "
            "name DEFINES NO PATTERN, so the mechanism is wired up and matches nothing. The "
            "reference itself is not the problem and cannot be: the firewall refuses a dangling "
            "`data-object` at the write, so a committed rule always names something that exists "
            "- the question is whether that something has any pattern in it, and here it does not")
    else:
        parts.append(
            "the verdict over this enforcement point's outward data filtering is false while "
            "both of its recorded parts read true, which should not be reachable - read the "
            "profile evidence beside this row rather than this sentence")
    profiles = obj.profiles_in_force or []
    if profiles:
        parts.append(
            f"{len(profiles)} data-filtering profile(s) are visible at this enforcement point and "
            f"the row beside this finding names each one, its namespace, whether it carries rules "
            f"and the route it is reached by")
    else:
        parts.append(
            "NO DATA-FILTERING PROFILE IS VISIBLE HERE AT ALL - not at this vsys, not in the "
            "firewall's shared area, none pushed into this point's tree, and the vendor ships "
            "none for this profile kind, so there is nothing to attach and the remediation starts "
            "by creating one. This is the commonest state of this control: three of the four "
            "appliances measured are in it")
    parts.append(
        f"WHAT A PASS ON THIS CONTROL WOULD AND WOULD NOT MEAN, because it bounds this finding "
        f"too: the mechanism reads {WATCHED_FILE_TYPE_COUNT} file types - office documents, PDFs "
        f"and HTML - and the vendor's own text on this screen says the selection 'does not block "
        f"all possible file types, just the listed ones'. A zip, a comma-separated export, a "
        f"plain text file, a database dump or an image is not examined by it whatever this row "
        f"says")
    parts.append(
        "AND THIS DOES NOT SAY THE ORGANISATION HAS NO DATA-LOSS PROTECTION. An Enterprise DLP "
        "subscription supersedes pattern-based data filtering where it is licensed, and a system "
        "off the firewall entirely leaves no evidence here at all - so confirm which of the three "
        "delivers it before reporting this as an absence of control rather than an absence of "
        "THIS control")
    return parts


#: WHICH FACTS THIS CONTROL'S FINDING MAY STATE. One control and one of its two halves - the
#: other asserts over the profile row and reaches no query on this model; see the module
#: docstring and the stage 8 artifact's `subjects_in_two_models`.
PARTS_BY_CONTROL = {
    "PAN-FIL-003": (_not_effective,),
}


def _subject(obj, control_id: str) -> str:
    appliance = obj.appliance or obj.enforcement_point.appliance \
        or obj.enforcement_point.appliance_group
    parts = [f"outward data filtering at {obj.enforcement_point.vsys_name} on {appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, (_not_effective,)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_data_filtering_posture_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


def _appliance_scope(obj) -> str:
    appliance = obj.appliance or obj.enforcement_point.appliance
    return str(appliance.hostname if appliance is not None
               else obj.enforcement_point.appliance_group)


SPEC = ObjectFindingSpec(
    label="data filtering posture",
    control_type=Control.ControlType.DATA_FILTERING_POSTURE,
    finding_model=DataFilteringPostureFinding,
    link_model=DataFilteringPostureFindingControlQuery,
    subject_fk="data_filtering_posture",
    link_fk="data_filtering_posture_finding",
    queryset=lambda: DataFilteringPosture.objects.select_related(
        "appliance", "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group"),
    evaluate=evaluate_data_filtering_posture_control_queries,
    summary=build_data_filtering_posture_finding_summary,
    # The vsys, because the row has no entry name - one profile's name would be the wrong thing
    # to print on a verdict about whether any of them is in force.
    subject_name=lambda obj: obj.enforcement_point.vsys_name,
    subject_scope=_appliance_scope,
)


def generate_data_filtering_posture_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_data_filtering_posture_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
