"""Build the PAN Health Check: Optiv's client deliverable, as a generated .docx.

A THIRD DELIVERABLE. The findings workbook says what is wrong, one row per finding; the
remediation workbook says where to go, one row per place; this says what the health check FOUND,
in Optiv's own document, for a reader who will never open a spreadsheet. The two workbooks and
every sheet they write are untouched - this shares `errors`, `naming` and the engagement metadata
with them and nothing else.

HOW IT IS SHAPED. Jason, 2026-11-05: *"I'm wary of using the .dotx, because modifying something
in place comes with its own challenges. If possible, I'd rather copy the style visually, build
our own partials that can easily be generated from the data, and create a new .docx file every
time."* And, on the recommendation that followed: *"Go with the scaffold approach."* So the
template is a STYLE DONOR: `docx/health-check-scaffold.docx` is opened read-only, this module
builds a list of WordprocessingML elements out of `docx.partials`, and `Scaffold.insert` puts
them in front of the `{{OEA-BODY}}` marker and takes the marker out.

THREE KINDS OF CONTENT, and they are kept visibly apart because a reader of the output has to be
able to tell which is which:

* **GENERATED** - measured from the run. Every sentence of it carries numbers.
* **FIXED** - the template's own boilerplate, with the client's names substituted. Re-emitted
  here rather than left in the scaffold, because the scaffold's body is stripped to a marker and
  prose that has to sit between two generated sections is easier to keep in document order than
  to splice around.
* **MANUAL** - a clearly marked placeholder a consultant fills in. NOT prose invented to make the
  document look finished: a health check's environment description, its interview findings and
  its rule-base screenshots are things a person did, and a generator that wrote them would be
  fabricating evidence.

`MANUAL` is the literal word a placeholder starts with, and `manual_placeholders()` counts them
for the build's report, so "what is left to write" is a number the engineer is told rather than
something they discover on page nine.

THE RATING SCALE. Jason, 2026-11-05: *"We are not going to use 'No Deviation' for now. that can
be replaced with Informational."* The template grades `D-1`..`D-5`; with D-5 retired the scale is
1:1 with the catalogue's five severities, so the `D-n` codes are dropped and the severity words
used - which is also why the template already ships the unused `Rating - Informational` style.
`Table 1: Risk Ratings` keeps the template's four descriptions and carries a NEW sentence for
Informational, because the one the template ships for D-5 ("Meets or exceeds ... pose no risk")
describes a pass and would contradict a row graded Informational.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from django.db.models import Max

from docx.oxml.ns import qn

from assessments import finding_registry
from assessments import remediation as surface
from assessments.control_queries import SEVERITY_RANK
from assessments.environment import get_application_environment
from assessments.models import Control

from django.contrib.contenttypes.models import ContentType

from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, DecryptionRulebaseVerdict, DeviceGroup, FieldProvenance,
    LicenceInventory, ManagementStation, ManagementPlaneAddressing, Snapshot)

from .docx import partials as p
from .docx.scaffold import (
    COVER_CLIENT, COVER_OPPORTUNITY, COVER_REVISION, SHORTNAME, open_scaffold)
from .errors import ArtifactBuildError
from .layout import plural

#: The grid every three-column body table in the template declares, and the per-cell widths that
#: go with it. Measured 2026-11-05 - see `docx.partials`.
OBSERVATION_GRID = (3408, 5227, 1589)
OBSERVATION_WIDTHS = ((1667, "pct"), (2556, "pct"), (777, "pct"))
#: `tblW` on the fixed-width tables, and their own grids.
FIXED_WIDTH = (10224, "dxa")
SUMMARY_GRID = (505, 3871, 3871, 1977)
SUMMARY_WIDTHS = ((247, "pct"), (1893, "pct"), (1893, "pct"), (967, "pct"))
RATINGS_GRID = (1800, 8424)
RATINGS_WIDTHS = ((1800, "dxa"), (8424, "dxa"))
AREA_RECOMMENDATION_GRID = (1440, 8784)
AREA_RECOMMENDATION_WIDTHS = ((1440, "dxa"), (8784, "dxa"))
BENEFIT_RISK_GRID = (3060, 3756, 3408)
BENEFIT_RISK_WIDTHS = ((3060, "dxa"), (3756, "dxa"), (3408, "dxa"))
DEVICES_GRID = (1530, 1980, 1602, 1704, 1704, 1704)
DEVICES_WIDTHS = tuple((w, "dxa") for w in DEVICES_GRID)
VERSION_GRID = (2875, 7349)
VERSION_WIDTHS = ((2875, "dxa"), (7349, "dxa"))
CONTAINER_GRID = (3060, 2160, 2700, 2304)
CONTAINER_WIDTHS = tuple((w, "dxa") for w in CONTAINER_GRID)

#: The two planes the rule-class tables are written for. They outlived the Area mapping, which
#: used to own them: a rule DEFINED on Panorama and one defined on a firewall are still two
#: tables, because the engineer edits them in different places.
PANORAMA = "panorama"
FIREWALL = "firewall"

#: Severities worst-first, for ordering anything a reader scans.
WORST_FIRST = sorted(Control.Severity.values, key=lambda value: SEVERITY_RANK[value],
                     reverse=True)

#: How many rows a per-rule-class risk table carries before it says how many more there are.
#:
#: WHY IT IS CAPPED when nothing else in this document is. The template's rule tables are one
#: specimen row under a caption and above a screenshot - they are exemplars, pointed at by a
#: picture of the rule base. On the lab, 1,083 security rule DEFINITIONS carry findings, and a
#: thousand-row table in a client document is not a section anybody reads; the findings workbook
#: is where every one of them is listed, and the overflow row says so. Fifteen fills most of a
#: page beside a screenshot.
RULE_RISK_ROW_LIMIT = 15

#: Severity bands for the High-Level Firewall Recommendations table, which the template lays out
#: as `High Priority:` / `Medium Priority:` / `Low Priority:` bullet lists. The template's own
#: preamble says the section "focuses on the remediation of D-1, D-2, and D-3 level severity
#: findings; D-4 level findings are addressed but have a lower priority", so critical and high
#: fold together at the top and low and informational together at the bottom.
PRIORITY_BANDS = (
    ("High Priority:", ("critical", "high")),
    ("Medium Priority:", ("medium",)),
    ("Low Priority:", ("low", "informational")),
)

#: The two recommendation tables that carry `Recommendation | Benefit | Risk` are restricted to
#: the work the template's preamble says this section is about.
RECOMMENDED_SEVERITIES = ("critical", "high", "medium")

#: WHAT GOES IN THE `Benefit` COLUMN, which is the one column of this deliverable the catalogue
#: has no field for. `Control.rationale` is why a finding matters, which is the RISK;
#: `Control.remediation` is the recommendation itself; nothing says what the client gains, and
#: the template's own specimen benefits are capability sentences an engineer wrote.
#:
#: SO IT CARRIES THE MEASURED REACH instead, which is the remediation surface's own statement of
#: itself - "the count beside it is what one edit costs and what it buys" - and is true rather
#: than written: this many findings cleared, from this many places to edit. A row-by-row
#: placeholder was the first version and it put 66 of them in these two tables, which makes a
#: document look abandoned rather than honest; the business benefit is asked for ONCE, above
#: each table, where a consultant can answer it in a sentence per row if they want to.
BENEFIT_NOTE = ("optionally add the business benefit of each change below - the measured reach "
                "is generated, but what {shortname} gains from it is a judgement")


def plural_noun(count: int, singular: str) -> str:
    """`2 licence inventories`, not `2 licence inventorys`.

    `layout.plural` appends a bare `s`, which is right for every heading the workbooks use
    because those are words somebody chose. These nouns are `FindingKind.label` - the registry's
    own singular for whatever a finding is about - and two of the twenty-four do not take a bare
    `s`: measured on the lab, `licence inventory` became "licence inventorys" and
    `security profile group` is fine but `authentication sequence` would not be if it ended in
    `s`. So the three English endings that matter are handled and nothing else is.
    """
    if count == 1:
        return singular
    if singular.endswith("y") and not singular.endswith(("ay", "ey", "iy", "oy", "uy")):
        return singular[:-1] + "ies"
    if singular.endswith(("s", "x", "z", "ch", "sh")):
        return singular + "es"
    return singular + "s"


def tally(count: int) -> str:
    """`4,647`, not `4647`.

    Every other number in this document is a year, a key length or a port, and those are never
    grouped. These are counts of findings, objects and places to edit, and on the lab the
    largest is five figures: "4647 findings across 1083 places to edit" is a client reading a
    serial number. Grouped at the point of printing rather than in the dataclasses, because the
    counts are also compared, summed and sorted.
    """
    return f"{count:,}"


def controls_clause(with_findings: int, total: int) -> str:
    """`from 4 of the 6 controls that assess this area`, and the singular that reads.

    `plural` gets the noun right and leaves the VERB behind, so the first lab build printed
    "from 1 of the 1 control that assess this area" on the two Areas that have one control. A
    row of a client deliverable cannot be ungrammatical, and the singular wants different words
    rather than a different suffix.
    """
    if total == 1:
        return "from the one control that assesses this area"
    return f"from {with_findings} of the {total} controls that assess this area"


def long_date(date: dt.date) -> str:
    """`February 4, 2026` - the template's own cover and delivery-date format.

    Built rather than handed to `strftime`: the natural format string is `%B %-d, %Y`, and `%-d`
    is a GNU extension that is not available on Windows - which an engagement's VDI is, and
    which `pyproject.toml` already carries a workaround for elsewhere.
    """
    return f"{date.strftime('%B')} {date.day}, {date.year}"


def manual(text: str) -> str:
    """A placeholder, marked so it cannot be mistaken for a finding.

    Square brackets and the word MANUAL, both: the brackets are the template's own convention
    for something to replace (`[Client Long Name, Inc.]`, `[Shortname]`), and the word is what
    makes a search of the finished document find every one of them.
    """
    return f"[MANUAL: {text}]"


# --------------------------------------------------------------------------------------------
# What the run measured, read once
# --------------------------------------------------------------------------------------------

@dataclass
class Measured:
    """Every finding in the database, folded by control, read in one pass.

    ONE PASS over the finding models rather than a query per Area. There are 218 controls and 24
    Areas, and the obvious shape - ask each Area for its controls' counts - is 218 `COUNT(*)`
    queries plus 218 more for the distinct subjects. This is one `values_list` per finding model,
    which is what `sheets.controls.finding_counts` does for the same reason.

    `subjects` holds the SET of things each control has findings about, and not a count, because
    the number an observation sentence needs is the size of the UNION over an Area's controls.
    Counting per control and adding them up was the first version, and it is wrong in the way
    that is hardest to see: sixteen controls report on the security rulebase, so a rule with
    findings from all sixteen was counted sixteen times and the Security row read "2,635 findings
    across 2,635 objects" - two numbers that look like a measurement and are the same number
    twice. The union gives 1,124 rules, which is the number a reader can picture.

    The key carries the MODEL as well as the pk: twenty-four finding models number their own
    subjects, so `(RuleFinding, 7)` and `(ZoneFinding, 7)` are different objects with the same
    id, and a set of bare ids would quietly merge them.
    """

    by_severity: dict = field(default_factory=lambda: defaultdict(Counter))
    subjects: dict = field(default_factory=lambda: defaultdict(set))
    #: (control id, severity) -> the objects THAT severity's findings are about.
    #:
    #: A SECOND INDEX RATHER THAN A FILTER, because the observation table prints one row per
    #: control AND severity (Jason, 2026-11-06: *"If a control has findings of different
    #: severities, each finding + severity will get its own row."*) and each row states how many
    #: objects ITS findings are about. Deriving that from `subjects` is not possible - the set
    #: has already lost which severity each object came in at.
    subjects_by_severity: dict = field(default_factory=lambda: defaultdict(set))
    #: control id -> the singular noun its findings are about ("security rule", "zone").
    subject_label: dict = field(default_factory=dict)
    #: Every run id any finding belongs to. More than one means the tables are mixed.
    runs: set = field(default_factory=set)

    def count(self, control_ids) -> int:
        return sum(sum(self.by_severity[control_id].values()) for control_id in control_ids)

    def distinct_subjects(self, control_ids) -> int:
        """How many distinct objects those controls have findings about, counted once each."""
        seen = set()
        for control_id in control_ids:
            seen |= self.subjects[control_id]
        return len(seen)

    def severities(self, control_ids) -> Counter:
        total = Counter()
        for control_id in control_ids:
            total.update(self.by_severity[control_id])
        return total

    def worst(self, control_ids) -> str | None:
        """The worst severity among those controls' findings, or None where there are none."""
        present = [severity for severity, count in self.severities(control_ids).items() if count]
        if not present:
            return None
        return max(present, key=lambda severity: SEVERITY_RANK[severity])


def measure() -> Measured:
    measured = Measured()
    for kind in finding_registry.FINDING_KINDS:
        subject_column = f"{kind.subject_field}_id"
        rows = kind.model.objects.values_list(
            "control__control_id", "severity", subject_column, "assessment_run_id")
        for control_id, severity, subject_id, run_id in rows:
            measured.by_severity[control_id][severity] += 1
            measured.subject_label[control_id] = kind.label
            measured.runs.add(run_id)
            measured.subjects[control_id].add((kind.name, subject_id))
            measured.subjects_by_severity[(control_id, severity)].add((kind.name, subject_id))
    return measured


def control_line(control, measured: Measured) -> str:
    """One control, read as a sentence - the remediation workbook's own idiom.

    `Critical · 9 findings · PAN-MGT-006 · Administrative Services on Data-Plane Interfaces`.
    Jason, 2026-11-04, on the workbook's version of this: *"There should only be one 'line' per
    control id."* The severity leads here rather than the count, because these lines sit in a
    cell whose own grade is the worst of them and a reader is checking which control earned it.
    """
    severities = measured.by_severity[control.control_id]
    count = sum(severities.values())
    worst = max((s for s, n in severities.items() if n),
                key=lambda s: SEVERITY_RANK[s], default=None)
    grade = Control.Severity(worst).label if worst else "No findings"
    return (f"{grade} · {tally(count)} {plural(count, 'finding')} · {control.control_id} · "
            f"{control.name}")


# --------------------------------------------------------------------------------------------
# The subjects: what was assessed, grouped by what a client calls the object
# --------------------------------------------------------------------------------------------

#: The common name for the controls that report on OUR OWN collection rather than on the
#: estate - `coverage` and `normalization`. Jason, 2026-11-06: *"Assessment Coverage should
#: probably be a separate sub section, not 'PAN Panorama' or 'PAN Firewall(s)'."* It is a
#: statement about the review, so it sits in a section of its own rather than being read as a
#: finding against a firewall.
COVERAGE_SUBJECT = "Assessment Coverage"


@dataclass(frozen=True)
class SubjectRow:
    """One row of an observation table: a control at one severity, or a control that passed."""

    control_name: str
    severity: str | None
    findings: int
    objects: int
    #: The noun those objects are, singular - `FindingKind.label`.
    noun: str


@dataclass(frozen=True)
class Subject:
    """One object kind as a client names it, with every control that reports on it.

    DERIVED, NOT MAPPED. Jason, 2026-11-06: *"We should seek to minimize any statically set data
    and instead generate the data from the control and finding information."* The grouping is
    `FindingKind.common_name`, joined to the control by `control_type` - a join measured total on
    2026-11-06, 75 kinds against 75 distinct control types, every active control resolving. So a
    control added to the catalogue appears under its object with no edit here, and a finding kind
    added to the registry brings its own heading. The 594-line Area mapping this replaced had
    three guards whose whole job was to notice when somebody forgot.
    """

    name: str
    rows: tuple
    #: The worst severity any of its controls raised, or None where every one of them passed.
    worst: str | None


def read_subjects(measured: Measured) -> tuple[list, str]:
    """Every active control, grouped under the common name of the object it reports on."""
    kinds = {kind.control_type: kind for kind in finding_registry.FINDING_KINDS}
    grouped = defaultdict(list)
    unnamed = []
    for control in Control.objects.filter(is_active=True).order_by("control_id"):
        kind = kinds.get(control.control_type)
        if kind is None:
            unnamed.append(control.control_id)
            continue
        grouped[kind.common_name].append((control, kind))
    if unnamed:
        # The join is what makes the grouping total, so a control whose type no finding kind
        # claims would vanish from the document rather than appear under a wrong heading.
        raise ArtifactBuildError(
            f"no finding kind reports on the control type of {', '.join(sorted(unnamed))}, so "
            f"there is no object name to file {plural(len(unnamed), 'it')} under. Add the kind "
            f"to finding_registry, or deactivate the control.")

    subjects = []
    for name, members in grouped.items():
        rows = []
        for control, kind in sorted(members, key=lambda m: control_order(m[0], measured)):
            severities = measured.by_severity[control.control_id]
            present = [severity for severity in WORST_FIRST if severities[severity]]
            if not present:
                # ASSESSED AND CLEAN IS A RESULT. Jason, 2026-11-06: *"Below the header, there
                # should be a row for each control."* A control left out because it found
                # nothing would make the table a list of problems rather than a review.
                rows.append(SubjectRow(control.name, None, 0, 0, kind.label))
                continue
            for severity in present:
                rows.append(SubjectRow(
                    control.name, severity, severities[severity],
                    len(measured.subjects_by_severity[(control.control_id, severity)]),
                    kind.label))
        worst = measured.worst([control.control_id for control, _ in members])
        subjects.append(Subject(name=name, rows=tuple(rows), worst=worst))

    subjects.sort(key=lambda subject: (-SEVERITY_RANK[subject.worst] if subject.worst else 1,
                                       subject.name))
    graded = sum(1 for subject in subjects if subject.worst)
    return subjects, (f"Subjects: {len(subjects)} object kinds from "
                      f"{sum(len(s.rows) for s in subjects)} rows, {graded} with findings")


def control_order(control, measured: Measured):
    """Worst severity first, then the most findings - the order a reader scans."""
    worst = measured.worst([control.control_id])
    return (-SEVERITY_RANK[worst] if worst else 1,
            -measured.count([control.control_id]), control.control_id)


def subject_rows(subjects: list) -> list:
    """`Subject | Finding | Rating`, with the subject's name as a row spanning all three.

    Jason, 2026-11-06: *"The subject should be a header row that spans the columns ... Below the
    header, there should be a row for each control ... If a control has findings of different
    severities, each finding + severity will get its own row."*
    """
    rows = [[_spanning("PAN Firewall", style=p.TABLE_HEADING)]]
    for subject in subjects:
        rows.append([_spanning(subject.name, bold=True)])
        for row in subject.rows:
            rows.append([
                p.text_cell(row.control_name, width=OBSERVATION_WIDTHS[0]),
                p.text_cell(subject_detail(row), width=OBSERVATION_WIDTHS[1]),
                p.rating_cell(row.severity or "informational",
                              Control.Severity(row.severity).label if row.severity
                              else "Informational",
                              width=OBSERVATION_WIDTHS[2]),
            ])
    return rows


def _spanning(text: str, *, bold: bool = False, style: str = None):
    cell = p.text_cell(text, width=(5000, "pct"), bold=bold,
                       **({"style": style} if style else {}))
    cell.span = 3
    return cell


def subject_detail(row: SubjectRow) -> str:
    """What one row SAYS, which is the measured reach of that control at that severity."""
    if row.severity is None:
        return "No findings. Every object reviewed satisfied this control."
    return (f"{tally(row.findings)} {plural(row.findings, 'finding')} across "
            f"{tally(row.objects)} {plural_noun(row.objects, row.noun)}.")


# --------------------------------------------------------------------------------------------
# The Panorama containers: where the configuration this review read was defined
# --------------------------------------------------------------------------------------------

#: The provenance markers that name a Panorama container, and the word the document uses for
#: each. `@loc` carries a device group or Shared; `@ptpl` carries a template, and the marker does
#: not tell a template from a template stack.
CONTAINER_TYPES = {"device_group": "Device group", "template": "Template"}

#: What the `Within` column says for a container nothing contains - Shared, and every template.
NO_PARENT = "—"


@dataclass(frozen=True)
class Container:
    """One Panorama container, and how much of this estate's configuration it defines."""

    name: str
    kind: str
    #: The container this one sits inside, for a device group; `NO_PARENT` otherwise.
    within: str
    #: Distinct objects whose values this container authors, counted from their own provenance
    #: markers. Zero is a real answer: see `read_containers`.
    objects: int


def _in_hierarchy_order(groups: list) -> list:
    """Shared first, then its children by name, depth first - Panorama's own tree order.

    A group whose parent row is missing, or a tree with a cycle in it, leaves rows unvisited;
    they are appended rather than dropped, because this list is the Scope section and a device
    group left out of it is a client told their estate is smaller than it is.
    """
    children = defaultdict(list)
    for group in groups:
        children[group.parent_id].append(group)

    order = []
    stack = sorted(children[None], key=lambda group: (not group.is_shared, group.name),
                   reverse=True)
    while stack:
        group = stack.pop()
        order.append(group)
        stack.extend(sorted(children[group.pk], key=lambda child: child.name, reverse=True))

    placed = {group.pk for group in order}
    order.extend(group for group in groups if group.pk not in placed)
    return order


def read_containers() -> tuple[list[Container], str]:
    """Every Panorama container behind this estate's configuration, and what each one defines.

    TWO SOURCES, BECAUSE ONLY ONE OF THEM IS COLLECTED.

    * **Device groups are collected.** `show dg-hierarchy` is read into `DeviceGroup`, Shared
      included, so a group is known whether or not it has pushed anything - the lab has two
      that pushed nothing this collection reached, and `DeviceGroupBinding`'s docstring makes
      the same point: "a group that has pushed nothing this collection reached has no bindings
      and is still a real group". A client checking the Scope list against their own Panorama
      wants to see those two.
    * **Templates are not collected.** Nothing reads Panorama's template list, so a template
      appears here only because a value in the configuration names it through `@ptpl`. These
      rows are what the configuration SAID, where the device group rows are what Panorama HAS.

    WHY THE COUNT IS OBJECTS AND NOT SETTINGS. A provenance row is one field, so counting rows
    would rank a container by how many columns its objects happen to carry - `shared` authors
    2,009 fields on the lab, and that number means nothing to a reader. Distinct
    `(content type, object id)` pairs are profiles, rules and interfaces, which is what an
    engineer counts.
    """
    defined, spelling = defaultdict(set), {}
    rows = FieldProvenance.objects.filter(
        provenance_type__in=CONTAINER_TYPES).values_list(
            "provenance_type", "raw_value", "content_type_id", "object_id")
    for provenance_type, name, content_type_id, object_id in rows:
        if not name:
            continue
        # CASE-FOLDED, because the two sources spell one container differently: Panorama
        # returns Shared as a container named `Shared` and the markers on the values it holds
        # read `shared`. Matching them literally filed every Shared-held object under a second
        # container nobody has.
        key = (provenance_type, name.casefold())
        defined[key].add((content_type_id, object_id))
        spelling.setdefault(key, name)

    containers, placed = [], set()
    for group in _in_hierarchy_order(list(DeviceGroup.objects.select_related("parent"))):
        key = ("device_group", group.name.casefold())
        placed.add(key)
        containers.append(Container(
            name=group.name,
            kind="Shared" if group.is_shared else CONTAINER_TYPES["device_group"],
            within=group.parent.name if group.parent else NO_PARENT,
            objects=len(defined.get(key, ())),
        ))

    # A CONTAINER THE CONFIGURATION NAMES AND THE HIERARCHY DOES NOT. `DeviceGroup` records one
    # (`discovered_from` = "Seen only in provenance") for a group the hierarchy missed, but a
    # deployment whose Panorama was never collected has the markers and no hierarchy at all, and
    # dropping those rows would leave the document claiming a Panorama-managed estate has no
    # containers.
    for key, objects in sorted(defined.items(), key=lambda item: (-len(item[1]), item[0][1])):
        if key in placed:
            continue
        provenance_type, _ = key
        containers.append(Container(
            name=spelling[key],
            kind=CONTAINER_TYPES[provenance_type],
            within=NO_PARENT,
            objects=len(objects),
        ))

    groups = sum(1 for container in containers if container.kind != "Template")
    templates = len(containers) - groups
    objects = sum(container.objects for container in containers)
    return containers, (f"Panorama containers: {groups} device "
                        f"{plural(groups, 'group')} including Shared and {templates} "
                        f"{plural(templates, 'template')}, defining {objects} "
                        f"{plural(objects, 'object')}")


def container_rows(containers: list) -> list:
    rows = [[
        p.text_cell("Container", width=CONTAINER_WIDTHS[0], style=p.TABLE_HEADING),
        p.text_cell("Kind", width=CONTAINER_WIDTHS[1], style=p.TABLE_HEADING),
        p.text_cell("Within", width=CONTAINER_WIDTHS[2], style=p.TABLE_HEADING),
        p.text_cell("Objects it defines", width=CONTAINER_WIDTHS[3], style=p.TABLE_HEADING),
    ]]
    for container in containers:
        rows.append([
            p.text_cell(container.name, width=CONTAINER_WIDTHS[0]),
            p.text_cell(container.kind, width=CONTAINER_WIDTHS[1]),
            p.text_cell(container.within, width=CONTAINER_WIDTHS[2]),
            # NOT `0`. A device group that has pushed nothing this collection reached is not a
            # group holding zero objects, and the distinction is the one `DeviceGroupBinding`
            # draws; the sentence above the table says where the rows come from.
            p.text_cell(tally(container.objects) if container.objects
                        else "none in this collection", width=CONTAINER_WIDTHS[3]),
        ])
    return rows


# --------------------------------------------------------------------------------------------
# The engagement: who it is about, what was collected, and when
# --------------------------------------------------------------------------------------------

@dataclass
class Engagement:
    """The names and dates every section substitutes into the template's prose."""

    client_name: str
    shortname: str
    opportunity: str
    revision: str
    built_on: dt.date
    collected_on: dt.date | None
    firewalls: list
    panoramas: list

    @property
    def collection_date(self) -> str:
        """The date the configuration this report describes was collected.

        The BUILD date is not a substitute and is not used here: a deliverable that said it
        reported on today's estate when the last collection was three weeks ago would be wrong
        in the one way a client would act on.
        """
        return long_date(self.collected_on) if self.collected_on else manual(
            "state the date the configuration was collected - no collection is recorded")


MERGED_CONFIG = "show_merged_config"
#: What to call a deployment with no `ApplicationEnvironment`. The lab spends its first minutes
#: in that state and it is not worth refusing a document over - `naming.workbook_filename` takes
#: the same line - but a client document cannot leave the cover blank, so it says so.
UNNAMED_CLIENT = manual("set the client's long name in the application environment")
UNNAMED_SHORTNAME = manual("set the client's short name")


def read_engagement(*, today: dt.date | None = None, revision: str = "1.0") -> Engagement:
    environment = get_application_environment()
    collected = (Snapshot.objects.filter(source_type=MERGED_CONFIG)
                 .aggregate(latest=Max("collected_at"))["latest"])
    return Engagement(
        client_name=(environment.client_name if environment and environment.client_name
                     else UNNAMED_CLIENT),
        shortname=(environment.client_short_name or environment.client_name
                   if environment else "") or UNNAMED_SHORTNAME,
        # THE TEMPLATE ALREADY PRINTS `OP-`. Its cover run reads
        # `Opportunity Number: OP-[op_number]`, and the lab's stored value is `OP-1234567`, so
        # substituting it whole gives `OP-OP-1234567`. The prefix is stripped on the way in.
        opportunity=((environment.opportunity_number if environment else "") or "").removeprefix(
            "OP-") or manual("opportunity number"),
        revision=revision,
        built_on=today or dt.date.today(),
        collected_on=collected.date() if collected else None,
        firewalls=sorted(Appliance.objects.all(),
                         key=lambda a: a.hostname or a.serial_number),
        panoramas=sorted(ManagementStation.objects.all(), key=lambda s: s.name),
    )


def fill(text: str, engagement: Engagement) -> str:
    """The template's `[Shortname]` and `[Client Long Name, Inc.]`, substituted."""
    return (text.replace(SHORTNAME, engagement.shortname)
                .replace(COVER_CLIENT, engagement.client_name))


# --------------------------------------------------------------------------------------------
# Section writers. One per section, each returning (elements, report line)
# --------------------------------------------------------------------------------------------

def write_contents() -> tuple[list, str]:
    """The heading and an empty `TOC` field. Word fills it on first open - see
    `partials.toc_field` and the scaffold's `updateFields`."""
    return ([p.paragraph(p.TOC_HEADING, "Table of Contents"), p.toc_field()],
            "Table of Contents: a TOC field Word fills on first open")


def write_executive_summary(engagement: Engagement, captions: p.CaptionCounters,
                            groups: list) -> tuple[list, str]:
    """FIXED prose, then the one GENERATED table an executive reads."""
    elements = [
        p.paragraph(p.HEADING_1, "Executive Summary"),
        p.paragraph(p.NORMAL, fill(
            "[Client Long Name, Inc.] ([Shortname]) engaged Optiv Security Inc. (Optiv) to "
            "perform a review of the organization’s existing Palo Alto Networks (PAN) "
            "environment. This report details the findings and makes recommendations for the "
            "current [Shortname] security design and implementation, a list of issues requiring "
            "remediation, a list of recommendations to address these issues, and a list of "
            "recommendations to better integrate and leverage the deployed technologies.",
            engagement)),
        p.paragraph(p.HEADING_2, "Objectives"),
        p.paragraph(p.NORMAL, "The high-level objectives for this engagement were to:"),
        p.paragraph(p.BULLET, "Review the current PAN Panorama(s) and identify any gaps."),
        p.paragraph(p.BULLET, "Review the current PAN firewall(s) and identify any gaps."),
        p.paragraph(p.HEADING_2, "Phases"),
        p.paragraph(p.NORMAL, "The phases of this engagement included:"),
        p.paragraph(p.BULLET, "Planning"),
        p.paragraph(p.BULLET, "Environmental Review and Planning"),
        p.paragraph(p.BULLET,
                    "Closing (Documentation and review of findings and recommendations)"),
        p.paragraph(p.HEADING_2, "Summary of Findings and Recommendations"),
    ]
    rows, report = summary_of_findings_rows(groups)
    elements.append(captions.table("Summary of Findings and Recommendations"))
    elements.append(p.table(rows, SUMMARY_GRID, width=(5000, "pct")))
    elements.append(p.paragraph(p.NORMAL, ""))
    elements.append(p.paragraph(p.NORMAL, fill(
        "Optiv understands the importance [Shortname] places on IT security and sincerely "
        "appreciates the opportunity to have worked on this engagement. Please contact the "
        "Optiv project manager with any questions regarding these findings or the contents of "
        "this report.", engagement)))
    return elements, report


def summary_of_findings_rows(groups: list) -> tuple[list, str]:
    """`# | Finding/Observation | Recommendation | Importance`, one row per remediation group.

    The template's comment on this table: *"Tie these to the Recommendations section of this
    document. Order the findings by priority, if applicable."*

    ONE ROW PER REMEDIATION GROUP, not one per control. 203 of the catalogue's 218 controls have
    findings on the lab, and that is not an executive summary. A remediation group is one object
    kind and one body of work - `Antivirus profile`, `Security rule` - which is the unit somebody
    schedules, and the surface already computes what a row needs. The Recommendation cell is the
    group's worst control's `Control.remediation`, which the catalogue already writes
    client-facing (see `sheets.controls`).

    ORDERED BY WORST SEVERITY, THEN BY FINDING COUNT DESCENDING. "Order the findings by
    priority" with the volume as the tie-break, so the biggest piece of work at each grade comes
    first.

    IT IS COMPLETE, and on the lab that is 69 rows - one per remediation group with findings.
    Flagged for Jason: he may want it capped, or restricted to critical and high. Capping it here would be a policy decision
    nobody has made, and a summary that silently stopped at twenty would be worse than a long
    one.
    """
    rows = [[
        p.text_cell("#", width=SUMMARY_WIDTHS[0], style=p.TABLE_HEADING),
        p.text_cell("Finding/Observation", width=SUMMARY_WIDTHS[1], style=p.TABLE_HEADING),
        p.text_cell("Recommendation", width=SUMMARY_WIDTHS[2], style=p.TABLE_HEADING),
        p.text_cell("Importance", width=SUMMARY_WIDTHS[3], style=p.TABLE_HEADING),
    ]]
    ranked = sorted(
        groups, key=lambda summary: (-SEVERITY_RANK[summary.worst], -summary.findings,
                                     summary.label))
    for number, summary in enumerate(ranked, start=1):
        rows.append([
            # A LITERAL NUMBER in `Table - Text` rather than the template's own
            # `Table - List Number 1`. That style is a numbered list, so a cell holding the text
            # "7" under it renders "7. 7"; the numbers are known at build time for the same
            # reason the captions are literal.
            p.text_cell(str(number), width=SUMMARY_WIDTHS[0]),
            p.text_cell(summary.observation, width=SUMMARY_WIDTHS[1]),
            p.text_cell(summary.recommendation, width=SUMMARY_WIDTHS[2]),
            p.rating_cell(summary.worst, Control.Severity(summary.worst).label,
                          width=SUMMARY_WIDTHS[3]),
        ])
    if len(rows) == 1:
        # NOTHING TO SUMMARISE SAYS WHICH KIND OF NOTHING, the same distinction
        # `rule_risk_rows` draws and for the same reason. "No findings were identified" over an
        # estate with no controls applied is true and reads as a pass; it is the sentence a
        # client would quote back.
        if Control.objects.filter(is_active=True).exists():
            rows.append([
                p.text_cell("1", width=SUMMARY_WIDTHS[0]),
                p.text_cell("No findings were identified in the configuration reviewed.",
                            width=SUMMARY_WIDTHS[1]),
                p.text_cell("No remediation is recommended.", width=SUMMARY_WIDTHS[2]),
                p.rating_cell("informational", "Informational", width=SUMMARY_WIDTHS[3]),
            ])
        else:
            rows.append([
                p.text_cell("—", width=SUMMARY_WIDTHS[0]),
                p.text_cell("No controls are active in this deployment's catalogue, so nothing "
                            "has been assessed and there is nothing to summarise.",
                            width=SUMMARY_WIDTHS[1]),
                p.text_cell("Apply a controls catalogue and run findings.",
                            width=SUMMARY_WIDTHS[2]),
                p.rating_cell(None, "Not assessed", width=SUMMARY_WIDTHS[3]),
            ])
    return rows, (f"Summary of Findings and Recommendations: {len(ranked)} rows, one per "
                  f"remediation group with findings")


@dataclass
class GroupSummary:
    """One remediation group, reduced to what the executive summary and the recommendations
    tables need. Computed once and shared, because both read the same four facts off it."""

    slug: str
    label: str
    worst: str
    findings: int
    places: int
    observation: str
    #: The client-facing recommendation - `Control.short_remediation`, one sentence. NOT
    #: `Control.remediation`, which is the engineer's instruction and belongs on the remediation
    #: page and in the findings workbook. Jason, 2026-11-06: *"The 'Recommendation' is too long,
    #: and the values themselves aren't appropriate for this customer facing artifact."* It used
    #: to be the full instruction, which put `set shared log-settings system match-list ...` in
    #: front of a client on the page after the executive summary.
    recommendation: str
    risk: str
    #: True where any of the group's rows is defined in a Panorama container rather than on a
    #: firewall - see `read_groups`.
    panorama_held: bool


#: `remediation` row authorities that mean PANORAMA holds the object. `Local` is the firewall's
#: own configuration and `Predefined` is PAN-OS's, and neither belongs to Panorama. `Shared` is
#: here for the authority the surface would report for a Panorama shared container; none of the
#: lab's rows carries it today, and leaving it out would file those rows under the firewall.
PANORAMA_AUTHORITIES = {"Device group", "Template", "Shared"}


def read_groups(measured: Measured) -> tuple[list, str]:
    """Every remediation group that has findings, with its worst control and where it is held.

    IT IS CHEAP. Run Findings stores every group's rows as its last step, so `stored_group_rows`
    decodes them rather than folding 17,555 findings again - the remediation workbook's own
    bargain, and the reason this document costs a fraction of what it looks like it should.

    WHERE IT IS HELD, from the rows' own `authority`. `Device group` and `Template` are Panorama
    containers; `Local` is the firewall's own configuration; `Predefined` is PAN-OS's and is
    neither. That is what tells the Panorama and the firewall recommendation tables apart -
    without it they would be the same table printed twice, which is what the template's two
    captions would then be lying about.

    ONE COST, MEASURED 2026-11-05 AND WORTH KNOWING. `stored.layout_version` hashes every `.py`
    under `artifacts/`, so adding this module and `health_check_areas` changed it, every one of
    the lab's 140 `PresentedTable` rows missed, and the first build after the change re-folded
    and re-stored all of them - the remediation docstring's 13.2s, paid once. That is
    `layout_version` working as its docstring says it should ("a needless rebuild costs seconds
    and a missed one costs a wrong deliverable"), but it means every edit to THIS file
    invalidates the findings tabs' cache as well, and it is a write to a database a build is
    otherwise only reading. Flagged rather than worked around: narrowing the hash's reach is a
    decision about the caching contract, not about this deliverable.
    """
    summaries = []
    for group in surface.REMEDIATION_GROUPS:
        controls = surface.group_controls(group)
        control_ids = [control.control_id for control in controls]
        findings = measured.count(control_ids)
        if not findings:
            continue
        worst = measured.worst(control_ids)
        worst_control = max(
            (control for control in controls if measured.by_severity[control.control_id]),
            key=lambda control: (SEVERITY_RANK[measured.worst([control.control_id])],
                                 measured.count([control.control_id])))
        rows = surface.stored_group_rows(group)
        places = len(rows)
        summaries.append(GroupSummary(
            slug=group.slug,
            label=group.label,
            worst=worst,
            findings=findings,
            places=places,
            #: WHAT A CLIENT READS IN THE Finding/Observation COLUMN. The control's name and
            #: how many findings it raised, and nothing else. Jason, 2026-11-06: *"We can
            #: remove the control.id and just use the name that's on there now. And then
            #: include only the findings count."*
            #:
            #: ONE PARAGRAPH RATHER THAN TWO. Breaking the count onto its own line was the
            #: first shape proposed; measured on the lab it costs a full page across the 69
            #: rows - 5.0 against 3.9 - to give three words a line of their own.
            #:
            #: `places` is still carried on this record: the Benefit column of both
            #: recommendation tables prints it, which is where the size of the job belongs.
            observation=(f"{worst_control.name}. "
                         f"{tally(findings)} {plural(findings, 'finding')}."),
            recommendation=worst_control.short_remediation or manual(
                f"write a short_remediation for {worst_control.control_id} - one imperative "
                f"sentence, 100 characters or fewer"),
            risk=worst_control.rationale or manual(
                f"write a rationale for {worst_control.control_id}"),
            panorama_held=any(row["authority"] in PANORAMA_AUTHORITIES for row in rows),
        ))
    panorama = sum(1 for summary in summaries if summary.panorama_held)
    return summaries, (f"Remediation groups: {len(summaries)} with findings, {panorama} with "
                       f"objects defined in a Panorama container")


def write_project_overview(engagement: Engagement, containers: list,
                           captions: p.CaptionCounters) -> tuple[list, str]:
    """FIXED, except the Scope bullets, the Panorama containers and the collection date."""
    firewalls = ", ".join(a.hostname or a.serial_number for a in engagement.firewalls)
    panoramas = ", ".join(s.hostname or s.name for s in engagement.panoramas)
    # SORTED BY NAME HERE AND BY WEIGHT IN THE TABLE, deliberately. A Scope list is read to look
    # a name up; the methodology table is read to see where the configuration comes from, and
    # its order says so. Shared is not a device group, so it is named in the table and not in
    # this bullet.
    device_groups = ", ".join(sorted(c.name for c in containers if c.kind == "Device group"))
    templates = ", ".join(sorted(c.name for c in containers if c.kind == "Template"))
    elements = [
        p.paragraph(p.HEADING_1, "Project Overview"),
        p.paragraph(p.NORMAL, fill("The [Shortname] PAN Health Check project consists of:",
                                   engagement)),
        p.paragraph(p.BULLET, "A comprehensive review of the deployed PAN firewall(s)."),
        p.paragraph(p.BULLET, "A comprehensive review of the deployed Panorama(s)."),
        p.paragraph(p.NORMAL,
                    "Based on the findings, it presents a high-level design broken into a "
                    "review of each device or High Availability (HA) cluster."),
        p.paragraph(p.HEADING_2, "Purpose"),
        p.paragraph(p.NORMAL, fill(
            f"The purpose of this document is to present the results of the PAN Health Check "
            f"performed for [Shortname] on {engagement.collection_date}.", engagement)),
        p.paragraph(p.HEADING_2, "Scope"),
        p.paragraph(p.NORMAL, fill(
            "This document provides information specific to the [Shortname] PAN Health Check "
            "and includes details on the following:", engagement)),
        # The template's two bullets end in a colon and its comments read "List names of
        # firewalls" / "List names of Panoramas". These are those lists.
        p.paragraph(p.BULLET, f"Firewall(s): {firewalls}" if firewalls
                    else "Firewall(s): none were collected."),
        p.paragraph(p.BULLET, f"Panorama(s): {panoramas}" if panoramas
                    else "Panorama(s): none were collected."),
        # TWO BULLETS THE TEMPLATE DOES NOT HAVE. Jason, 2026-11-06: *"If we have information
        # about the device groups and templates from provenance, that information can be
        # included in the document's sections that talk about scope, methodology, or summarize
        # locations of findings."* These are the names; the table under Approach/Methodology is
        # what each one defines.
        p.paragraph(p.BULLET, f"Device group(s): {device_groups}" if device_groups
                    else "Device group(s): none were collected."),
        p.paragraph(p.BULLET, f"Template(s): {templates}" if templates
                    else "Template(s): none are named in the configuration collected."),
        p.paragraph(p.HEADING_2, "Objective"),
        p.paragraph(p.NORMAL, fill(
            "After reviewing this document, [Shortname] security personnel should be able to:",
            engagement)),
        p.paragraph(p.BULLET, "Identify the risks of the deployed PAN firewall(s)."),
        p.paragraph(p.BULLET, "Identify the risks of the deployed PAN Panorama(s)."),
        p.paragraph(p.BULLET, "Propose remediation steps for any identified issues."),
        p.paragraph(p.HEADING_2, "Approach/Methodology"),
        p.paragraph(p.NORMAL, "The approach used was based primarily on best practice guidelines "
                              "and Optiv’s best practices."),
        p.paragraph(p.BULLET, "Conduct an initial internal and client kickoff call to determine "
                              "the overall architecture and collect pertinent documentation."),
        p.paragraph(p.BULLET, "Perform a detailed walkthrough of the architecture together with "
                              "the client key players based on the available documentation and "
                              "in-house knowledge."),
        p.paragraph(p.BULLET, "Obtain access and inspect the configuration of key devices."),
        p.paragraph(p.BULLET, "Conduct on-site interviews with client key players to ensure the "
                              "successful capture of all details and requirements."),
        *container_section(containers, captions),
        p.paragraph(p.NORMAL,
                    "The findings are documented and assigned a risk-level rating (see the table "
                    "below), which describes the deviation from industry, vendor, and Optiv "
                    "standards. It is meant to provide guidance and focus for remediation and "
                    "improvement activities."),
        captions.table("Risk Ratings"),
        p.table(risk_rating_rows(), RATINGS_GRID, width=FIXED_WIDTH),
    ]
    return elements, (f"Project Overview: {len(engagement.firewalls)} "
                      f"{plural(len(engagement.firewalls), 'firewall')}, "
                      f"{len(engagement.panoramas)} "
                      f"{plural(len(engagement.panoramas), 'Panorama')} and "
                      f"{len(containers)} Panorama "
                      f"{plural(len(containers), 'container')} in scope, collected "
                      f"{engagement.collected_on or 'never'}")


def container_section(containers: list, captions: p.CaptionCounters) -> list:
    """Where the configuration this review read was defined, under Approach/Methodology.

    IT GOES HERE AND NOT IN AN OBSERVATION ROW. The two observation tables carry a risk rating
    in their third column, so a container named there would be an inventory in a cell that says
    Critical or High. This is the methodology section: it says what was read and where it came
    from, which is the one claim in the deliverable a client can check on their own Panorama in
    a minute.
    """
    if not containers:
        return [p.paragraph(p.NORMAL,
                            "No setting read in this review was defined in a Panorama "
                            "container: every value is the firewall's own.")]
    return [
        p.paragraph(p.NORMAL,
                    "Every setting read carries a marker naming where it was defined, so the "
                    "containers below are read from the configuration itself rather than "
                    "asserted. Panorama's device-group hierarchy was collected, so a device "
                    "group appears whether or not it has pushed anything this collection "
                    "reached; Panorama's template list was not, so a template appears only "
                    "where a value names it as its source, and the marker does not tell a "
                    "template from a template stack."),
        captions.table("Panorama Containers"),
        p.table(container_rows(containers), CONTAINER_GRID, width=FIXED_WIDTH),
    ]


#: `Risk Level | Description`, the template's four descriptions verbatim and a new one for
#: Informational.
#:
#: THE FIFTH SENTENCE IS OURS. The template's D-5 row reads "Meets or exceeds industry, vendor,
#: and Optiv standards and leading practices or processes pose no risk ...", which describes a
#: PASS. With `No Deviation` retired in favour of `Informational`, a row graded Informational is
#: one where a control fired and the deviation carries no risk by itself - the template's
#: sentence would contradict the row it is explaining.
RISK_RATINGS = (
    ("critical", "Critical Deviation",
     "Extreme deviation from industry, vendor, and Optiv standards, leading practices, or "
     "processes that pose extreme risk to the availability of the network and security "
     "infrastructure"),
    ("high", "High Deviation",
     "Major deviation from industry, vendor, and Optiv standards or processes poses a high risk "
     "to the availability of the network and security infrastructure"),
    ("medium", "Medium Deviation",
     "Moderate deviation from industry, vendor, and Optiv standards or processes poses a medium "
     "risk to the availability of the network and security infrastructure"),
    ("low", "Low Deviation",
     "Slight deviation from industry, vendor, and Optiv standards and leading practices or "
     "processes poses a low risk to the availability of the network and security infrastructure"),
    ("informational", "Informational",
     "A deviation from industry, vendor, and Optiv standards or leading practices that carries "
     "no risk to the network and security infrastructure on its own. It is recorded so that it "
     "can be weighed alongside the findings above rather than discovered later"),
)


def risk_rating_rows() -> list:
    rows = [[
        p.text_cell("Risk Level", width=RATINGS_WIDTHS[0], style=p.TABLE_HEADING),
        p.text_cell("Description", width=RATINGS_WIDTHS[1], style=p.TABLE_HEADING),
    ]]
    for severity, heading, description in RISK_RATINGS:
        rows.append([
            p.rating_cell(severity, Control.Severity(severity).label, width=RATINGS_WIDTHS[0]),
            p.Cell(paragraphs=[p.paragraph(p.TABLE_TEXT_BOLD, heading),
                               p.paragraph(p.TABLE_TEXT, description)],
                   width=RATINGS_WIDTHS[1]),
        ])
    return rows


# --------------------------------------------------------------------------------------------
# The health check itself: the two observation tables and the rule-class tables
# --------------------------------------------------------------------------------------------

def write_health_check(engagement: Engagement, measured: Measured, subjects: list,
                       captions: p.CaptionCounters) -> tuple[list, list]:
    elements = [
        p.paragraph(p.HEADING_1, fill("[Shortname] Firewall Health Check", engagement)),
        p.paragraph(p.HEADING_2, fill("[Shortname] Environment Review and Analysis",
                                      engagement)),
        # MANUAL. The template's comment on this paragraph: "Describe the sites that the health
        # check will cover". The estate knows hostnames and management addresses; it does not
        # know where a site is or what it does.
        p.paragraph(p.NORMAL, manual(
            "describe the sites this health check covers - the estate records hostnames and "
            "management addresses but not locations or what each site does")),
        p.paragraph(p.NORMAL,
                    "Based on the review and discussions with the Network team, the review "
                    "results are summarized in the table below."),
        p.paragraph(p.NORMAL,
                    "These results pertain to the global network and security environment. A "
                    "specific review of the currently installed firewall policies is presented "
                    "in the next section."),
        captions.table("Process Observations"),
        p.table(process_observation_rows(), OBSERVATION_GRID, width=(5000, "pct")),
    ]
    reports = ["Process Observations: 5 placeholder rows, all interview findings"]

    # PANORAMA CARRIES NO OBSERVATION TABLE. Every control in the catalogue reads a firewall's
    # configuration, so there is nothing to grade here - Jason, 2026-11-06: *"All of the
    # controls currently defined are firewall controls. As a result, the 'Review and Analysis of
    # Panorama' section will not have any findings."* What Panorama holds is still reported: the
    # rule tables below split by where each rule is DEFINED, and the Panorama Containers table
    # under Approach/Methodology names every device group and template.
    elements.append(p.paragraph(p.HEADING_2, "Panorama"))
    elements.append(p.paragraph(p.HEADING_3, "Review and Analysis of Panorama"))
    elements.append(p.paragraph(p.NORMAL,
                                "Optiv was able to perform a review of the PAN Panorama "
                                "environment."))
    elements.append(p.paragraph(p.NORMAL,
        "The configuration reviewed was collected through Panorama. Every control in this "
        "review reads a firewall's own configuration, so the observations are reported under "
        "the firewalls below; what Panorama holds is shown in the rule tables that follow and "
        "in the table of Panorama containers above. Panorama's own device configuration was "
        "not in scope for this assessment."))
    panorama_rules, panorama_reports = write_rule_classes(PANORAMA, captions)
    elements.extend(panorama_rules)
    reports.extend(panorama_reports)

    elements.append(p.paragraph(p.HEADING_2, "PAN Firewall(s)"))
    elements.append(p.paragraph(p.HEADING_3, "Review and Analysis of Firewall(s)"))
    elements.append(p.paragraph(p.NORMAL,
                                "Optiv was able to perform a review of the PAN firewall(s) "
                                "environment."))
    estate = [subject for subject in subjects if subject.name != COVERAGE_SUBJECT]
    elements.append(captions.table("Firewall Observations"))
    elements.append(p.table(subject_rows(estate), OBSERVATION_GRID, width=(5000, "pct")))
    reports.append(f"Firewall Observations: {len(estate)} subjects, "
                   f"{sum(len(subject.rows) for subject in estate)} rows")
    firewall_rules, firewall_reports = write_rule_classes(FIREWALL, captions)
    elements.extend(firewall_rules)
    reports.extend(firewall_reports)

    coverage = [subject for subject in subjects if subject.name == COVERAGE_SUBJECT]
    if coverage:
        # A SECTION OF ITS OWN. These controls report on what THIS REVIEW could not read, not on
        # anything a firewall is doing, and under either device heading they would be read as a
        # finding against the estate.
        elements.append(p.paragraph(p.HEADING_2, COVERAGE_SUBJECT))
        elements.append(p.paragraph(p.NORMAL,
            "These rows are about the review rather than about the estate: each one records "
            "configuration this assessment could not read, and what it would take to close the "
            "gap. They carry a severity because an unread setting is an ungraded one, not "
            "because the firewall is doing anything wrong."))
        elements.append(captions.table("Assessment Coverage"))
        elements.append(p.table(subject_rows(coverage), OBSERVATION_GRID, width=(5000, "pct")))
        reports.append(f"Assessment Coverage: "
                       f"{sum(len(subject.rows) for subject in coverage)} rows")
    return elements, reports


#: The five rows of `Table 2: Process Observations`, which are ALL interview findings: what
#: documentation exists, whether there is a security policy and whether it is adhered to, how a
#: firewall change is requested and reviewed, and who manages the firewalls and how well they
#: know the environment. Nothing in a configuration answers any of them, so each is a marked
#: placeholder with the template's own prompt in it.
PROCESS_OBSERVATIONS = (
    ("Documentation", "Network Documentation",
     "state what network documentation exists and how current it is"),
    ("Documentation", "Device Configuration",
     "state what configuration documentation exists and how current it is"),
    ("Policy", "Policy, Standards, Guidelines",
     "is there a security policy or firewall standard, and is it adhered to?"),
    ("Process", "Firewall Change Control",
     "how is a firewall change requested, reviewed and recorded, and who else is involved?"),
    ("Resources", "Personnel",
     "who manages the firewalls, are they trained, and how well do they know the environment?"),
)


def process_observation_rows() -> list:
    rows = [[p.text_cell("Review Current Architecture", width=(5000, "pct"),
                         style=p.TABLE_HEADING)]]
    rows[0][0].span = 3
    for area, subject, prompt in PROCESS_OBSERVATIONS:
        rows.append([
            p.text_cell(area, width=OBSERVATION_WIDTHS[0], bold=True),
            p.Cell(paragraphs=[p.paragraph(p.TABLE_TEXT_BOLD, subject),
                               p.paragraph(p.TABLE_TEXT, manual(prompt))],
                   width=OBSERVATION_WIDTHS[1]),
            # NOT GRADED. An interview finding nobody has written cannot carry a severity, and a
            # placeholder Informational would read as a pass on a question nobody asked.
            p.rating_cell(None, manual("grade"), width=OBSERVATION_WIDTHS[2]),
        ])
    return rows


# --------------------------------------------------------------------------------------------
# The rule-class tables: one per rulebase the template gives a table and a screenshot to
# --------------------------------------------------------------------------------------------
#
# REBUILT 2026-11-06 after I deleted the original by mistake, against the last good build
# (`health-check-v6.docx`) rather than from memory: the table shapes, the captions, the
# screenshot frames and the sentences below are what that file contains. Two numbers in the
# build's own report are reconstructions - see `rule_definitions` - and the document's text is
# not affected by either.


@dataclass(frozen=True)
class RuleClass:
    """One rulebase: a table of its riskiest rules, and a screenshot frame under it."""

    #: How the template names it in prose and in the caption - "Security", "Decryption", "DoS".
    label: str
    #: The control type whose finding kind reports on this rulebase.
    control_type: str


#: THE RULEBASES THIS ASSESSMENT READS, which is not the list of tables Optiv's template
#: ships. Jason, 2026-11-06: *"OptivEdgeAssessments defines what goes into the template. The
#: template does not define the controls or findings. We should not be attempting to derive or
#: organize OEA's data into the template's definitions."* So there is no list here of the
#: rulebases the template has rows for and this assessment does not read, and no sentence
#: apologising for them: a rulebase appears when a finding kind reports on one.
RULE_CLASSES = (
    RuleClass("Security", "security_rule"),
    RuleClass("Decryption", "decryption_policy_rule"),
    RuleClass("DoS", "dos_policy_rule"),
)

#: The provenance types on a rule's own entry that mean PANORAMA pushed it.
_PUSHED_ENTRY = {"device_group", "template", "panorama"}


@dataclass(frozen=True)
class RuleDefinition:
    """One rule as an engineer edits it, with every finding raised against it."""

    position: str
    name: str
    findings: int
    worst: str
    #: `Critical · 7 findings · PAN-POL-008 · Security Profiles on All Allow Rules`, worst first.
    lines: tuple


def rule_plane(scope: str) -> str:
    """Which plane a rule is DEFINED on, from the finding's own subject scope.

    The three rule kinds spell their scope differently - `pushed_pre:vsys3` on a security rule,
    `ha-pair-013201001085-013201001475 / vsys2 / local` on a decryption rule - so the test is
    for the word rather than the shape. A pushed rule is Panorama's to edit; anything else is
    the firewall's own.
    """
    return PANORAMA if "pushed" in (scope or "") else FIREWALL


def rule_definitions(rule_class: RuleClass, plane: str) -> list:
    """Every rule of this class on this plane that carries a finding, worst first.

    A DEFINITION IS `(position, name)`, NOT A ROW IN THE DATABASE. One pushed rule reaches
    several virtual systems and is stored once per system, but an engineer edits it once - so
    counting stored rules would tell a reader to fix the same rule eleven times. Measured on the
    lab 2026-11-06: 622 stored security rules carry findings on the Panorama plane against 606
    definitions, and the 606 is the number the original of this function printed.
    """
    kind = next((k for k in finding_registry.FINDING_KINDS
                 if k.control_type == rule_class.control_type), None)
    if kind is None:
        return []
    rows = kind.model.objects.values_list(
        "subject_scope", "subject_name", f"{kind.subject_field}__rule_position",
        "control__control_id", "control__name", "severity")

    grouped = defaultdict(lambda: defaultdict(Counter))
    names = {}
    for scope, name, position, control_id, control_name, severity in rows:
        if rule_plane(scope) != plane:
            continue
        key = (position, name)
        names[key] = (control_id, control_name)
        grouped[key][(control_id, control_name)][severity] += 1

    definitions = []
    for (position, name), by_control in grouped.items():
        findings = sum(sum(counts.values()) for counts in by_control.values())
        severities = Counter()
        for counts in by_control.values():
            severities.update(counts)
        worst = max((s for s, n in severities.items() if n), key=lambda s: SEVERITY_RANK[s])
        lines = []
        for (control_id, control_name), counts in by_control.items():
            for severity in WORST_FIRST:
                if not counts[severity]:
                    continue
                lines.append((SEVERITY_RANK[severity], counts[severity],
                              f"{Control.Severity(severity).label} · {tally(counts[severity])} "
                              f"{plural(counts[severity], 'finding')} · {control_id} · "
                              f"{control_name}"))
        lines.sort(key=lambda line: (-line[0], -line[1]))
        definitions.append(RuleDefinition(
            position="" if position is None else str(position), name=name, findings=findings,
            worst=worst, lines=tuple(line[2] for line in lines)))

    definitions.sort(key=lambda d: (-SEVERITY_RANK[d.worst], -d.findings, d.name))
    return definitions


def rules_defined(rule_class: RuleClass, plane: str) -> int:
    """How many rule definitions of this class exist on this plane, findings or not.

    For the build's REPORT line only - the document says nothing about it. Read from each rule's
    own entry provenance, which is what says who authored it. Reconstructed 2026-11-06 and one
    rule out from the original on the lab (626 against 625 on Panorama), because a definition
    whose `(position, name)` exists on both planes is counted on both.
    """
    kind = next((k for k in finding_registry.FINDING_KINDS
                 if k.control_type == rule_class.control_type), None)
    if kind is None:
        return 0
    model = kind.model._meta.get_field(kind.subject_field).related_model
    content_type = ContentType.objects.get_for_model(model)
    authored = dict(FieldProvenance.objects
                    .filter(content_type=content_type, field_name="__entry__")
                    .values_list("object_id", "provenance_type"))
    # THE THREE RULE MODELS DO NOT AGREE ON WHAT A NAME IS CALLED: a security rule has `name`
    # and a decryption rule has `rule_name`. Asked of the model rather than assumed, because
    # getting it wrong here is a crash on a deployment that happens to have decryption rules.
    columns = {field.name for field in model._meta.get_fields()}
    name_column = "name" if "name" in columns else "rule_name"
    seen = set()
    for pk, position, name in model.objects.values_list("id", "rule_position", name_column):
        where = PANORAMA if authored.get(pk) in _PUSHED_ENTRY else FIREWALL
        if where == plane:
            seen.add((position, name))
    return len(seen)


def write_rule_classes(plane: str, captions: p.CaptionCounters) -> tuple[list, list]:
    """A table, a screenshot frame and a figure caption for each rulebase, then what was not
    reviewed at all."""
    where = "the Panorama" if plane == PANORAMA else "the firewall(s)"
    titled = "Panorama" if plane == PANORAMA else "the Firewall(s)"
    bare = "Panorama" if plane == PANORAMA else "the firewall(s)"
    elements, reports = [], []
    for rule_class in RULE_CLASSES:
        definitions = rule_definitions(rule_class, plane)
        if definitions:
            elements.append(p.paragraph(p.NORMAL,
                f"The following {rule_class.label} rules show risks identified for {where}."))
        else:
            elements.append(p.paragraph(p.NORMAL,
                f"No {rule_class.label} rules are defined on {where}."))
        elements.append(captions.table(f"{rule_class.label} Rule Risks in {titled}"))
        elements.append(p.table(rule_risk_rows(rule_class, definitions, titled, bare),
                                OBSERVATION_GRID, width=(5000, "pct")))
        # The template frames its screenshots with an empty bordered paragraph, and the
        # engineer pastes the picture into it.
        elements.append(p.paragraph(p.SCREENSHOT, ""))
        elements.append(p.paragraph(p.NORMAL, manual(
            f"paste a screenshot of the {rule_class.label} rule base, with line numbers "
            f"visible, so the rows above can be identified")))
        elements.append(captions.figure(f"{rule_class.label} Rules in {titled}"))
        shown = min(len(definitions), RULE_RISK_ROW_LIMIT)
        reports.append(
            f"{rule_class.label} rule risks ({plane}): {shown} of {len(definitions)} rule "
            f"definitions with findings shown, out of {rules_defined(rule_class, plane)} "
            f"defined here")
    return elements, reports


def rule_risk_rows(rule_class: RuleClass, definitions: list, titled: str, bare: str) -> list:
    """`# | Rule and its findings | Rating`, capped at `RULE_RISK_ROW_LIMIT`."""
    heading = p.text_cell(f"Risks in {rule_class.label} Rules for {titled}",
                          width=(5000, "pct"), style=p.TABLE_HEADING)
    heading.span = 3
    rows = [[heading]]
    if not definitions:
        # NOT A PASS. No rule of this class exists, so there is nothing to grade - the same
        # distinction the observation rows draw between a clean result and an unasked question.
        rows.append([
            p.text_cell("—", width=OBSERVATION_WIDTHS[0]),
            p.text_cell(f"No {rule_class.label} rules are defined on {bare}, so there is "
                        f"nothing here to review and no finding - or absence of one - to "
                        f"report.", width=OBSERVATION_WIDTHS[1]),
            p.rating_cell(None, "Not assessed", width=OBSERVATION_WIDTHS[2]),
        ])
        return rows
    for definition in definitions[:RULE_RISK_ROW_LIMIT]:
        rows.append([
            p.text_cell(definition.position, width=OBSERVATION_WIDTHS[0]),
            p.bullet_cell(f"{definition.name} — {tally(definition.findings)} "
                          f"{plural(definition.findings, 'finding')}",
                          list(definition.lines), width=OBSERVATION_WIDTHS[1]),
            p.rating_cell(definition.worst, Control.Severity(definition.worst).label,
                          width=OBSERVATION_WIDTHS[2]),
        ])
    remaining = len(definitions) - RULE_RISK_ROW_LIMIT
    if remaining > 0:
        overflow = p.text_cell(
            f"A further {tally(remaining)} {rule_class.label} rule definitions carry findings. "
            f"Every one of them is listed in the accompanying findings workbook; the "
            f"{RULE_RISK_ROW_LIMIT} above are the worst by severity and then by volume.",
            width=(5000, "pct"))
        overflow.span = 3
        rows.append([overflow])
    return rows


def manual_placeholders(scaffold) -> int:
    """How many `[MANUAL: ...]` placeholders the finished document carries.

    COUNTED OFF THE ASSEMBLED BODY, not off the sections that wrote them, so a placeholder the
    scaffold's own cover or back cover carries is counted too. It goes in the build's report
    because "what is left for a person to write" is a number an engineer should be told rather
    than discover on page nine - see the module docstring.

    Rebuilt 2026-11-06 with the rest of this file's lost section; it reported 28 on the lab
    before, which is the number to expect from an unchanged estate.
    """
    # COUNTED OVER THE CONCATENATED TEXT, not per run: Word splits a run wherever the proofing
    # state or the revision id changes, so the cover's own placeholders arrive in pieces and
    # counting runs misses them. Measured 2026-11-06: 39 by run against 43 by text.
    text = "".join(node.text or "" for node in scaffold.body.iter(qn("w:t")))
    return text.count("[MANUAL:")


def write_recommendations(engagement: Engagement, groups: list,
                          captions: p.CaptionCounters) -> tuple[list, list]:
    elements = [
        p.paragraph(p.HEADING_1, "Recommendations"),
        p.paragraph(p.NORMAL,
                    "This section presents a set of recommendations based on the above "
                    "findings."),
        # The template's own version of this sentence names D-1..D-5. With the codes retired it
        # names the severities, which is the same statement in the vocabulary the rest of the
        # document now uses.
        p.paragraph(p.NORMAL,
                    "In general, this section focuses on the remediation of Critical, High and "
                    "Medium findings; Low findings are addressed but have a lower priority. "
                    "Informational findings carry no risk on their own and are therefore not "
                    "listed below."),
        p.paragraph(p.HEADING_2, "High-Level Recommendations"),
        # MANUAL. The template's comment: "Provide a high-level recommendation based on what is
        # seen". Its own specimen paragraphs are three pages of an engineer's reading of one
        # estate, and that is a judgement rather than a measurement.
        p.paragraph(p.NORMAL, manual(
            "write the high-level reading of this estate - what the findings below add up to, "
            "and what to do first")),
        p.paragraph(p.HEADING_3, "High-Level Firewall Recommendations"),
        captions.table("High-Level Firewall Recommendations"),
        p.table(priority_rows(groups), AREA_RECOMMENDATION_GRID, width=FIXED_WIDTH),
        p.paragraph(p.NORMAL, ""),
    ]
    reports = [f"High-Level Firewall Recommendations: {len(groups)} recommendations in three "
               f"priority bands"]

    for title, lead, held in (
        ("Panorama Recommendations",
         "The following Panorama recommendations are listed to show the benefits and risks.",
         True),
        ("Firewall Recommendations",
         "The following firewall recommendations are listed to show the benefits and risks.",
         False),
    ):
        # WHICH TABLE A GROUP LANDS IN comes from its rows' own authority - see `read_groups`.
        # Without that the two tables would be one table printed twice under two captions, and
        # the captions would be the part that was wrong.
        selected = [summary for summary in groups
                    if summary.worst in RECOMMENDED_SEVERITIES
                    and summary.panorama_held == held]
        elements.append(p.paragraph(p.NORMAL, lead))
        elements.append(p.paragraph(
            p.NORMAL, manual(BENEFIT_NOTE.format(shortname=engagement.shortname))))
        elements.append(captions.table(title))
        elements.append(p.table(benefit_risk_rows(selected), BENEFIT_RISK_GRID,
                                width=FIXED_WIDTH))
        reports.append(f"{title}: {len(selected)} rows")
    return elements, reports


def priority_rows(groups: list) -> list:
    """`Area | Recommendation`, the template's three priority bands.

    THE TEMPLATE'S OWN SHAPE: three rows, each a bold `High Priority:` / `Medium Priority:` /
    `Low Priority:` label over a bullet list, with the Area column naming the subject once on
    the first row. Kept rather than redesigned per Area, because the template's comment ties
    this table to the observation tables above and three bands of bullets is how it does it.

    EACH BULLET NAMES ITS OBSERVATION AREA. That is what ties the two together: a reader who saw
    `Threat Prevention` graded High above finds the bullets that got it there here, rather than
    having to match a remediation sentence to a row by eye.
    """
    rows = [[
        p.text_cell("Area", width=AREA_RECOMMENDATION_WIDTHS[0], style=p.TABLE_HEADING),
        p.text_cell("Recommendation", width=AREA_RECOMMENDATION_WIDTHS[1],
                    style=p.TABLE_HEADING),
    ]]
    # THE PREFIX IS THE OBJECT, derived the same way the observation table's headings are, so a
    # bullet here and a row there name the same thing. It used to be the Area a control was
    # mapped into by hand.
    kinds = {kind.control_type: kind for kind in finding_registry.FINDING_KINDS}
    subject_of_group = {}
    for control in Control.objects.filter(is_active=True):
        group = surface.GROUP_BY_CONTROL_ID.get(control.control_id)
        kind = kinds.get(control.control_type)
        if group is not None and kind is not None:
            subject_of_group.setdefault(group.slug, kind.common_name)

    for index, (label, severities) in enumerate(PRIORITY_BANDS):
        banded = [summary for summary in groups if summary.worst in severities]
        banded.sort(key=lambda summary: (-summary.findings, summary.label))
        lines = []
        for summary in banded:
            subject = subject_of_group.get(summary.slug)
            prefix = f"{subject} — " if subject else ""
            lines.append(f"{prefix}{summary.recommendation}")
        if not lines:
            lines = [f"No {label.rstrip(':').lower()} recommendations arise from this review."]
        rows.append([
            # The template names the subject once, on the first row, and leaves the cell empty
            # beneath - which is how it reads as one block of three bands rather than three
            # unrelated rows.
            p.text_cell("PAN" if index == 0 else "", width=AREA_RECOMMENDATION_WIDTHS[0],
                        bold=index > 0),
            p.bullet_cell(label, lines, width=AREA_RECOMMENDATION_WIDTHS[1],
                          lead_style=p.TABLE_TEXT_BOLD),
        ])
    return rows


def benefit_risk_rows(selected: list) -> list:
    """`Recommendation | Benefit | Risk`.

    The Risk column is `Control.rationale` - the catalogue's own one-sentence statement of why
    the finding matters, written client-facing - carried as a bullet the way the template carries
    it. The Benefit column carries the measured reach of the change; see `BENEFIT_NOTE`.
    """
    rows = [[
        p.text_cell("Recommendation", width=BENEFIT_RISK_WIDTHS[0], style=p.TABLE_HEADING),
        p.text_cell("Benefit", width=BENEFIT_RISK_WIDTHS[1], style=p.TABLE_HEADING),
        p.text_cell("Risk", width=BENEFIT_RISK_WIDTHS[2], style=p.TABLE_HEADING),
    ]]
    if not selected:
        rows.append([
            p.text_cell("—", width=BENEFIT_RISK_WIDTHS[0]),
            p.text_cell("No recommendations of Critical, High or Medium priority arise here.",
                        width=BENEFIT_RISK_WIDTHS[1]),
            p.Cell(paragraphs=[p.paragraph(p.TABLE_BULLET, "No risk is outstanding.")],
                   width=BENEFIT_RISK_WIDTHS[2]),
        ])
        return rows
    for summary in sorted(selected, key=lambda s: (-SEVERITY_RANK[s.worst], -s.findings,
                                                   s.label)):
        rows.append([
            p.text_cell(summary.label, width=BENEFIT_RISK_WIDTHS[0]),
            p.text_cell(f"Resolves {tally(summary.findings)} "
                        f"{plural(summary.findings, 'finding')} of up to "
                        f"{Control.Severity(summary.worst).label.lower()} severity, from "
                        f"{tally(summary.places)} {plural(summary.places, 'place')} to edit.",
                        width=BENEFIT_RISK_WIDTHS[1]),
            p.Cell(paragraphs=[p.paragraph(p.TABLE_BULLET, summary.risk)],
                   width=BENEFIT_RISK_WIDTHS[2]),
        ])
    return rows


# --------------------------------------------------------------------------------------------
# Appendices and the back matter
# --------------------------------------------------------------------------------------------

def write_appendices(engagement: Engagement,
                     captions: p.CaptionCounters) -> tuple[list, list]:
    """A-C are MANUAL; D is the device inventory.

    THE HEADINGS CARRY NO `Appendix A:` PREFIX. `Heading1-AppendixList` declares
    `<w:numPr w:numId="52"/>`, which prints it - measured on the scaffold, and confirmed by the
    template's own table of contents reading `Appendix A: Reports` over a heading whose text is
    `Reports`. Writing the prefix would print it twice.
    """
    elements = [
        p.paragraph(p.HEADING_APPENDIX, "Reports"),
        p.paragraph(p.NORMAL,
                    "The following reports give visibility into the applications that are "
                    "hitting the overly general rules. The PDFs are best viewed through a PDF "
                    "reader to preserve the formatting."),
        p.paragraph(p.NORMAL, manual(
            "list the reports attached to this deliverable - this assessment generates the "
            "findings and remediation workbooks; anything else is attached by hand")),
        p.paragraph(p.HEADING_APPENDIX, "Interviews"),
        p.paragraph(p.NORMAL,
                    "The following people were interviewed to gain insight into the "
                    "environment."),
        p.paragraph(p.NORMAL, manual("list who was interviewed, their role, and when")),
        p.paragraph(p.HEADING_APPENDIX, "References"),
        p.paragraph(p.NORMAL, "The following references are used in the Health Check."),
        p.paragraph(p.NORMAL, manual(
            "list the vendor and Optiv references this health check was measured against")),
        p.paragraph(p.HEADING_APPENDIX, "Devices Included in Review"),
        captions.table("Reviewed Devices"),
    ]
    rows, report = device_rows(engagement)
    elements.append(p.table(rows, DEVICES_GRID, width=FIXED_WIDTH))
    return elements, [report]


def device_rows(engagement: Engagement) -> tuple[list, str]:
    """`Hostname | Management IP | Type | Hardware | URL Filtering | SSL Decryption`.

    EVERY DEVICE THE REVIEW TOUCHED, which includes the Panorama: the configuration in this
    report was collected through it, so a device list that left it out would misdescribe the
    review. Its own cells say `Not collected` rather than carrying a firewall's values - see
    `health_check_areas` for why there are none.

    `URL Filtering` is read off the licence inventory and `SSL Decryption` off the decryption
    rulebase verdict, because those are the two questions the column headings ask: whether the
    subscription is held, and whether decryption is actually in force.
    """
    headings = ("Hostname", "Management IP", "Type", "Hardware", "URL Filtering",
                "SSL Decryption")
    rows = [[p.text_cell(heading, width=DEVICES_WIDTHS[index], style=p.TABLE_HEADING)
             for index, heading in enumerate(headings)]]

    # One pass, two columns. Read twice in the first version, which is two queries for a
    # four-row table - cheap, and still the habit `appliances.collected_at_by_appliance` was
    # rewritten to break.
    addressing, allocation = {}, {}
    for row in ManagementPlaneAddressing.objects.values_list(
            "appliance_id", "management_ip_address", "allocation_mode"):
        addressing[row[0]], allocation[row[0]] = row[1], row[2]
    licences = {row.appliance_id: row for row in LicenceInventory.objects.all()}
    decrypting = defaultdict(lambda: [0, 0])
    for verdict in DecryptionRulebaseVerdict.objects.select_related("enforcement_point"):
        group_id = verdict.enforcement_point.appliance_group_id
        decrypting[group_id][1] += 1
        if verdict.opens_outbound_web:
            decrypting[group_id][0] += 1

    for appliance in engagement.firewalls:
        ip = addressing.get(appliance.pk)
        if not ip:
            mode = allocation.get(appliance.pk)
            ip = (f"Leased ({mode})" if mode else "Not collected")
        inventory = licences.get(appliance.pk)
        decrypts, total = decrypting.get(appliance.appliance_group_id, [0, 0])
        rows.append([
            p.text_cell(appliance.hostname or appliance.serial_number,
                        width=DEVICES_WIDTHS[0]),
            p.text_cell(ip, width=DEVICES_WIDTHS[1]),
            p.text_cell(firewall_type(appliance), width=DEVICES_WIDTHS[2]),
            p.text_cell(appliance.model or "Not collected", width=DEVICES_WIDTHS[3]),
            p.text_cell(url_filtering_cell(inventory), width=DEVICES_WIDTHS[4]),
            p.text_cell(
                f"In force on {decrypts} of {total} {plural(total, 'virtual system')}"
                if total else "Not collected", width=DEVICES_WIDTHS[5]),
        ])
    for station in engagement.panoramas:
        rows.append([
            p.text_cell(station.hostname or station.name, width=DEVICES_WIDTHS[0]),
            p.text_cell("Not collected", width=DEVICES_WIDTHS[1]),
            p.text_cell(station.get_station_type_display()
                        if hasattr(station, "get_station_type_display") else "Panorama",
                        width=DEVICES_WIDTHS[2]),
            p.text_cell("Not collected", width=DEVICES_WIDTHS[3]),
            p.text_cell("Not applicable", width=DEVICES_WIDTHS[4]),
            p.text_cell("Not applicable", width=DEVICES_WIDTHS[5]),
        ])
    if len(rows) == 1:
        rows.append([p.text_cell("No devices were collected.", width=DEVICES_WIDTHS[0])]
                    + [p.text_cell("", width=DEVICES_WIDTHS[i]) for i in range(1, 6)])
    return rows, (f"Reviewed Devices: {len(engagement.firewalls)} "
                  f"{plural(len(engagement.firewalls), 'firewall')} and "
                  f"{len(engagement.panoramas)} "
                  f"{plural(len(engagement.panoramas), 'management station')}")


def firewall_type(appliance) -> str:
    """`Firewall`, with the HA role where there is one - which is what makes a pair readable."""
    group = appliance.appliance_group
    if group is None or group.group_type == ApplianceGroup.TYPE_STANDALONE:
        return "Firewall"
    return "Firewall (HA pair)"


#: What a URL filtering entitlement is called in the licence inventory. Two of them, because
#: PAN-DB and Advanced URL Filtering are separate features and an estate can hold either.
URL_FILTERING_FEATURES = ("PAN-DB URL Filtering", "Advanced URL Filtering")


def url_filtering_cell(inventory) -> str:
    if inventory is None:
        return "Not collected"
    held = [feature for feature in (inventory.entitlement_features_held or [])
            if feature in URL_FILTERING_FEATURES]
    if held:
        return "Licensed: " + ", ".join(held)
    if not inventory.entitlement_features_held:
        return "No licence rows returned"
    return "Not licensed"


def write_general(engagement: Engagement) -> tuple[list, str]:
    """Copyright, verbatim, and the Version Control table.

    THE YEAR IS THE BUILD'S. The template's two copyright lines are dated 2026 because that is
    when it was written; a document generated in a later year with a stale year in its copyright
    line is a small error on a page a lawyer reads.
    """
    year = engagement.built_on.year
    elements = [
        p.paragraph(p.HEADING_1, "General"),
        p.paragraph(p.HEADING_2, "Copyright"),
        p.paragraph(p.NORMAL,
                    "The information transmitted in this document is intended only for the "
                    "addressee and may contain confidential and/or privileged material. Any "
                    "interception, review, retransmission, dissemination, or other use of or "
                    "taking of any action upon this information by persons or entities other "
                    "than the intended recipient is prohibited by law and may subject them to "
                    "criminal or civil liability."),
        p.paragraph(p.NORMAL,
                    f"Copyright © {year} Optiv Security Inc. All rights reserved. The "
                    f"Optiv Security logo is a registered trademark of Optiv Security. All "
                    f"other products and company names mentioned herein are trademarks or "
                    f"registered trademarks of their respective owners."),
        p.paragraph(p.HEADING_2, "Version Control"),
        p.table(version_rows(engagement), VERSION_GRID, width=FIXED_WIDTH),
    ]
    return elements, ("Version Control: 4 generated values, 5 placeholders for the names a "
                      "person supplies")


def version_rows(engagement: Engagement) -> list:
    """The template's ten rows: four we hold, five nobody but a person can fill, and the
    classification.

    FIVE PLACEHOLDERS, not the four the spec expected. The template's rows are Client Contact,
    Author(s), Peer Reviewer, QA Reviewer and Project Manager - the contact is a fifth name and
    the estate holds none of them.
    """
    header = p.text_cell("PAN Health Check", width=FIXED_WIDTH, style=p.TABLE_HEADING)
    header.span = 2
    rows = [[header]]
    values = (
        ("Client Name", engagement.client_name),
        ("Client Contact", manual("client contact")),
        ("Document Revision Number", engagement.revision),
        ("Author(s)", manual("author")),
        ("Peer Reviewer", manual("peer reviewer")),
        ("QA Reviewer", manual("QA reviewer")),
        ("Project Manager", manual("project manager")),
        ("Delivery Date", long_date(engagement.built_on)),
        ("Data Classification", "Client Confidential"),
    )
    for name, value in values:
        rows.append([p.text_cell(name, width=VERSION_WIDTHS[0]),
                     p.text_cell(value, width=VERSION_WIDTHS[1])])
    return rows


# --------------------------------------------------------------------------------------------
# Guards and the build
# --------------------------------------------------------------------------------------------

def check_the_run_is_one_run(measured: Measured) -> None:
    """Every finding in the document comes from ONE findings run.

    The same refusal `artifact_store` explains for the workbooks, and the reason it refuses a
    build and a run at the same time: this reads some thirty tables one after another, and a run
    landing mid-build hands the later sections a different run's findings than the earlier ones.
    A client document whose executive summary and whose observation tables disagree is worse than
    no document.
    """
    if len(measured.runs) > 1:
        raise ArtifactBuildError(
            f"the findings in the database belong to {len(measured.runs)} different runs "
            f"({', '.join(str(run) for run in sorted(measured.runs))}), so this document's "
            f"sections would not describe one assessment. Run findings again before building it.")


def check_every_finding_reached_the_spine(measured: Measured) -> None:
    """Every finding is under a subject heading the document prints.

    The counterpart of `remediation_workbook.check_every_finding_reached_a_tab`, counted the
    other way round. It used to ask whether every finding's control had been mapped into an
    Area by hand; with the headings derived from `FindingKind.common_name` the only way to fail
    is a finding against a control whose type no finding kind claims - which `read_subjects`
    refuses outright - or against a control the catalogue no longer holds.
    """
    kinds = {kind.control_type: kind for kind in finding_registry.FINDING_KINDS}
    named = {control.control_id
             for control in Control.objects.filter(is_active=True)
             if control.control_type in kinds}
    missed = {control_id: sum(severities.values())
              for control_id, severities in measured.by_severity.items()
              if control_id not in named and sum(severities.values())}
    if missed:
        total = sum(missed.values())
        raise ArtifactBuildError(
            f"{total} findings are against controls this document cannot name an object for "
            f"({', '.join(sorted(missed))}), so they would not appear in it at all.")


def build_health_check_document(*, today: dt.date | None = None,
                               revision: str = "1.0") -> tuple[bytes, list[str]]:
    """The document as bytes, and the line each section reports about itself.

    Bytes and no path, for the reason `build_workbook` gives: "the caller decides whether that is
    a download, a stored artifact or a test."

    `revision` IS A PARAMETER AND NOTHING SUPPLIES IT YET. It goes on the cover and into the
    Version Control table, and nothing in the estate holds a document revision - there is no
    field on `ApplicationEnvironment` for it, and `artifact_store` calls this with no arguments.
    So every build is `1.0` until somebody adds a way to say otherwise, which is a parameter
    here rather than a literal on the cover so that the way is one argument away. Flagged rather
    than invented: a second issue of a deliverable numbered 1.0 is a real problem, and it is a
    product decision about where the number lives.
    """
    measured = measure()
    check_the_run_is_one_run(measured)
    check_every_finding_reached_the_spine(measured)

    engagement = read_engagement(today=today, revision=revision)
    captions = p.CaptionCounters()
    groups, groups_report = read_groups(measured)
    containers, containers_report = read_containers()
    subjects, subjects_report = read_subjects(measured)

    elements, reports = [], [groups_report, containers_report, subjects_report]
    for section in (
        lambda: write_contents(),
        lambda: write_executive_summary(engagement, captions, groups),
        lambda: write_project_overview(engagement, containers, captions),
    ):
        produced, report = section()
        elements.extend(produced)
        reports.append(report)

    produced, section_reports = write_health_check(engagement, measured, subjects, captions)
    elements.extend(produced)
    reports.extend(section_reports)

    produced, section_reports = write_recommendations(engagement, groups, captions)
    elements.extend(produced)
    reports.extend(section_reports)

    produced, section_reports = write_appendices(engagement, captions)
    elements.extend(produced)
    reports.extend(section_reports)

    produced, report = write_general(engagement)
    elements.extend(produced)
    reports.append(report)

    scaffold = open_scaffold()
    scaffold.substitute_cover({
        COVER_CLIENT: engagement.client_name,
        COVER_OPPORTUNITY: engagement.opportunity,
        COVER_REVISION: engagement.revision,
    })
    scaffold.insert(elements)
    reports.append(f"Captions: {captions.tables} tables and {captions.figures} figures, "
                   f"numbered in document order")
    reports.append(f"Placeholders: {manual_placeholders(scaffold)} marked MANUAL for a "
                   f"consultant to fill")
    return scaffold.to_bytes(), reports
