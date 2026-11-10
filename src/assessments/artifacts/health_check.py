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
1:1 with the catalog's five severities, so the `D-n` codes are dropped and the severity words
used - which is also why the template already ships the unused `Rating - Informational` style.
`Table 1: Risk Ratings` keeps the template's four descriptions and carries a NEW sentence for
Informational, because the one the template ships for D-5 ("Meets or exceeds ... pose no risk")
describes a pass and would contradict a row graded Informational.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace

from django.db.models import Max

from docx.oxml.ns import qn

from assessments import finding_registry
from assessments import remediation as surface
from assessments.control_queries import SEVERITY_RANK
from assessments.environment import get_application_environment
from assessments.models import Control, FindingControlQueryBase

from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, DecryptionRulebaseVerdict, DeviceGroup, FieldProvenance,
    LicenceInventory, ManagementStation, ManagementPlaneAddressing, Snapshot)

from .docx import partials as p
from . import scope
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
#: The Control Detail table: a label column and the line it labels. The label column holds
#: `What it checks` at 10pt without wrapping, and the value column the rest of the text width.
#:
#: FOUR COLUMNS, not two (Jason, 2026-11-06): the control's id and its severity are both a
#: couple of words, and a row apiece spent two of a seven-row table's rows on four words, so
#: they share the first row as two label-and-value pairs. Every row below it is one label and
#: one value cell covering the other three columns, so what the reader sees under that row is
#: still a short word on the left and a sentence on the right. The widths still sum to the same
#: 10224 twips, which is the text width every body table in this template is fixed to.
DETAIL_GRID = (1800, 1800, 1800, 4824)
DETAIL_WIDTHS = ((1800, "dxa"), (8424, "dxa"))
#: The four cells of that first row: `Control`, the id, `Severity`, the grade.
DETAIL_PAIR_WIDTHS = tuple((width, "dxa") for width in DETAIL_GRID)

#: Severities worst-first, for ordering anything a reader scans.
WORST_FIRST = sorted(Control.Severity.values, key=lambda value: SEVERITY_RANK[value],
                     reverse=True)

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
                "is generated, but what {shortname} gains from it is a judgment")


def plural_noun(count: int, singular: str) -> str:
    """`2 license inventories`, not `2 license inventorys`.

    `layout.plural` appends a bare `s`, which is right for every heading the workbooks use
    because those are words somebody chose. These nouns are `FindingKind.label` - the registry's
    own word for whatever a finding is about - and a few of the seventy-five do not take a bare
    `s`: measured on the lab, `license inventory` became "license inventorys".

    A LABEL THAT ALREADY ENDS IN `s` IS LEFT ALONE. Measured over all 75 kinds 2026-11-06, every
    one of them is already plural or a mass noun - `logging settings`, `session settings`,
    `firewall content streams` - so the `es` that English wants after a sibilant produced
    "logging settingses" in the Control Detail section's own Findings line. Seven labels, seven
    wrong words. The `es` branch stays for the one label it is right for, `rulebase device
    match`, and for the `x`, `z` and `sh` endings no label carries yet.

    NOTHING IN THIS PACKAGE PLURALIZES A LABEL ANY MORE. The Findings line was its one caller
    and it now prints `FindingKind.client_plural`, because 31 of the 75 labels are not the
    client's word for the object in any number. What is left is the rule itself and the
    measurements behind it, which `test_finding_registry` uses to assert that a client plural
    is ALREADY plural - and the question of whether a new noun takes `s`, `es` or `ies` is
    answered here rather than per caller.
    """
    if count == 1:
        return singular
    if singular.endswith("y") and not singular.endswith(("ay", "ey", "iy", "oy", "uy")):
        return singular[:-1] + "ies"
    if singular.endswith("s"):
        return singular
    if singular.endswith(("x", "z", "ch", "sh")):
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
    #: (control id, severity) -> {the firewalls that own it: how many findings}.
    #:
    #: A NAIVE BLAST RADIUS, and worth reading as one. The finding is about an object on an
    #: enforcement point, and this counts the appliances that enforcement point runs on - so it
    #: says how far a control's findings reach across the estate, not how many separate things
    #: there are to fix. Jason, 2026-11-06: *"We're really talking about enforcement points. So
    #: these counts will give a naive view of the blast radius by firewall."*
    #:
    #: An HA pair is ONE key holding both members, not two keys. The pair shares one
    #: configuration and is fixed once, so counting the finding against each member would
    #: double the row's own total and read as two jobs.
    firewalls: dict = field(default_factory=lambda: defaultdict(Counter))
    #: control id -> what a CLIENT calls the things its findings are about, as
    #: `(plural, singular)` - ("security rules", "security rule").
    #:
    #: THE CLIENT'S PLURAL AND NOT `FindingKind.label`, which this carried first. The Findings
    #: line is always about a count, so the noun is always printed plural, and the registry's
    #: singular pluralized gave a client "12 password complexities" and "coverages". The
    #: registry's own comment on the field has the measurement.
    subject_nouns: dict = field(default_factory=dict)
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


def firewalls_by_snapshot() -> dict:
    """snapshot id -> the firewalls whose configuration that snapshot describes.

    THREE PATHS, because a snapshot names its owner in three ways. It is taken from an
    appliance; or from an enforcement point, which is a virtual system and belongs to the
    appliance group it runs on; or from the group itself. Measured on the lab 2026-11-06: all
    17,555 findings resolve, 8,439 of them to one appliance and 9,116 to an HA pair's two.

    A snapshot taken from the management station resolves to nothing, which is correct - its 90
    snapshots carry no findings, because no control reads Panorama's own configuration.
    """
    members = defaultdict(list)
    # IN SCOPE ONLY, so a pair's label cannot name a firewall this engagement did not assess.
    # Collection resolves whole groups, so both halves of a pair are normally in scope together.
    for hostname, serial, group_id in scope.appliances_in_scope().values_list(
            "hostname", "serial_number", "appliance_group_id"):
        if group_id:
            members[group_id].append(hostname or serial)

    owners = {}
    for snapshot_id, hostname, serial, group_id, point_group_id in Snapshot.objects.values_list(
            "id", "appliance__hostname", "appliance__serial_number",
            "appliance_group_id", "enforcement_point__appliance_group_id"):
        if hostname or serial:
            owners[snapshot_id] = (hostname or serial,)
            continue
        group = point_group_id or group_id
        if group and members.get(group):
            owners[snapshot_id] = tuple(sorted(members[group]))
    return owners


def measure() -> Measured:
    measured = Measured()
    owners = firewalls_by_snapshot()
    for kind in finding_registry.FINDING_KINDS:
        subject_column = f"{kind.subject_field}_id"
        rows = kind.model.objects.values_list(
            "control__control_id", "severity", subject_column, "assessment_run_id",
            "snapshot_id")
        for control_id, severity, subject_id, run_id, snapshot_id in rows:
            owner = owners.get(snapshot_id)
            if owner:
                measured.firewalls[(control_id, severity)][owner] += 1
            measured.by_severity[control_id][severity] += 1
            measured.subject_nouns[control_id] = (
                kind.client_plural, kind.client_singular or kind.label)
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
# What a client calls the object, and how far a control's findings reach
# --------------------------------------------------------------------------------------------

#: The common name for the controls that report on OUR OWN collection rather than on the
#: estate - `coverage` and `normalization`. Jason, 2026-11-06: *"Assessment Coverage should
#: probably be a separate sub section, not 'PAN Panorama' or 'PAN Firewall(s)'."* It is a
#: statement about the review, so it sits in a section of its own rather than being read as a
#: finding against a firewall.
COVERAGE_SUBJECT = "Assessment Coverage"




def group_controls_by_subject() -> dict:
    """object name -> the active controls that report on it, by control id.

    The join `Subject` describes, read once: `FindingKind.common_name` against the control's
    `control_type`. TWO SECTIONS READ IT - the observation tables, which print one row per
    control and severity, and Control Detail, which prints one block per control - and a second
    copy of the join would be a second chance for the two to disagree about which heading a
    control sits under.
    """
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
    return grouped


def affected_firewalls(counts: Counter) -> tuple:
    """EVERY firewall carrying the control's findings at this grade, worst affected first.

    NOT A TOP FIVE AND A COUNT. It was that until Jason, 2026-11-10: *"Do not truncate the
    Firewalls list."* The first version named five - *"the five named should be the worst
    affected by count"*, and *"If the number of firewalls exceeds 5, then state something like
    and \'n\' others"*, both 2026-11-06 - and an engineer reading the block then knew that
    three more firewalls needed the same change without knowing which three. The ranking stays,
    because the worst affected is still what a reader wants first.
    """
    return tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


# --------------------------------------------------------------------------------------------
# Detailed Findings and Recommendations: one block per control and severity
# --------------------------------------------------------------------------------------------

#: What the Firewalls line says when nothing names a firewall for a control's findings. Every
#: one of the lab's 17,555 findings resolves to one - see `firewalls_by_snapshot` - so this is
#: the snapshot that was not taken from an appliance, and a blank cell in a client document is
#: a question rather than an answer.
NO_FIREWALL_NAMED = "No firewall is named by the configuration these findings were read from."

#: The catalogue lines this table prints, and the label each sits under. The order is the
#: mock-up's, agreed 2026-11-06: what the control examines, what it costs, then what to do.
#: `where_to_confirm` is NOT here: Jason, 2026-11-06, *"Move 'Why it matters.' and 'What to
#: change' to the table"* - which moved three lines in and left that one outside, as prose.
DETAIL_LINES = (
    ("what_it_checks", "What it checks"),
    ("why_it_matters", "Why it matters"),
    ("what_to_change", "What to change"),
)


@dataclass(frozen=True)
class ControlDetail:
    """One control at ONE SEVERITY: a row of the summary table and the block it links to.

    PER CONTROL AND SEVERITY, NOT PER CONTROL. Jason, 2026-11-09: *"If there are 10000 medium
    and 1 critical, that would be a misrepresentation of the facts"* - a single row carrying
    one grade and both counts says the wrong thing about 10,000 of them. And a control grades
    its findings differently because a DIFFERENT QUERY matched: *"this allows us to be more
    specific about the query/parameters that caused the finding too, which is nice"*, which is
    what `matched` carries.

    156 of the lab's 203 controls fire at one severity only, so the split costs 61 extra blocks
    on 264 - and buys the summary and the detail the SAME ORDER and a link from each row to its
    own block.
    """

    control: Control
    severity: str
    findings: int
    #: How many distinct objects those findings are about, and what a client calls them -
    #: the registry's own `(plural, singular)`, printed as they stand.
    objects: int
    object_nouns: tuple
    #: `(firewalls, findings)` for EVERY firewall affected, worst first - an HA pair is one
    #: entry naming both.
    reach: tuple
    #: The client sentences of the control queries that matched at this severity.
    matched: tuple
    #: How many PLACES AN ENGINEER OPENS to clear these findings - the remediation surface's
    #: own rows. 0 where that surface has no row for this control.
    places: int
    #: What a client calls the object - the heading this block used to sit under.
    subject: str
    #: The bookmark its summary row links to, assigned in document order.
    anchor: str = ""


def remediation_places() -> dict:
    """(control id, severity) -> how many places an engineer opens to clear it.

    THE NUMBER A CLIENT PLANS WITH. Jason, 2026-11-09: *"Remediation one object may clear
    multiple findings. That's the number I'm looking for."* A finding is a control failing on
    an object, but the object an engineer OPENS is often something else and often shared:
    PAN-VLN-003 raised 1,067 findings on the lab - one per rule - and all of them are cleared
    by editing sixteen vulnerability protection profiles.

    READ OFF THE REMEDIATION SURFACE RATHER THAN RECOMPUTED, because that surface is what the
    engineer will actually work from: its rows ARE the edits, and `severity_by_control` on each
    row says which control graded it and how. A second definition of "things to fix" that
    disagreed with the remediation pages would be worse than none.

    THE WORD IS `place`, which is the Benefit column's own - *"1,083 places to edit"* - and
    not the remediation group's label. Six of the thirty-four labels are not count nouns, and
    pluralizing them printed `forward proxy signings` and `portal authentications` at a client.
    One vocabulary across the document beats a noun that is right most of the time.
    """
    places = defaultdict(int)
    for group in surface.REMEDIATION_GROUPS:
        for row in surface.stored_group_rows(group):
            for control_id in row.get("controls", ()):
                severity = (row.get("severity_by_control") or {}).get(control_id)
                if severity:
                    places[(control_id, severity)] += 1
    return dict(places)


def findings_phrase(detail: ControlDetail) -> str:
    """`1,027 findings, 24 places to edit` - the impact, and the work.

    TWO NUMBERS THAT GENUINELY DIFFER, which the first version of this line did not have. It
    printed the findings count and the count of objects the findings are ABOUT, and those are
    the same number by construction - a finding is one control failing on one object, measured
    0 of 264 blocks apart on the lab. Jason spot-checked the built document and said so:
    *"Either thats circumstance or a defect."* The second number he wanted is the REMEDIATION
    count, which is a different thing and smaller on 77 of the 264: *"Remediation one object
    may clear multiple findings."*

    THE SECOND HALF IS DROPPED WHERE THE REMEDIATION SURFACE HAS NO ROW - 8 blocks on the lab,
    the ones whose subject is the review rather than the estate - rather than printing a zero
    that would read as "nothing to do".
    """
    if not detail.places:
        return f"{tally(detail.findings)} {plural(detail.findings, 'finding')}"
    return (f"{tally(detail.findings)} {plural(detail.findings, 'finding')}, "
            f"{tally(detail.places)} {plural(detail.places, 'place')} to edit")


def firewalls_phrase(detail: ControlDetail) -> str:
    """EVERY firewall affected and what each carries, worst first, named as the rest of the
    document names them: `remediation.firewall_label` writes an HA pair once, as
    `fw-core-tpa-a/b`.

    THE WHOLE LIST, HOWEVER LONG. Jason, 2026-11-10: *"Do not truncate the Firewalls list."*
    A control that fires estate-wide names the estate here, which is the point of the line: it
    is the list of appliances somebody has to open, and a client who is handed five of them
    and the word "others" has to come back and ask for the rest.
    """
    if not detail.reach:
        return NO_FIREWALL_NAMED
    return ", ".join(f"{surface.firewall_label(firewalls)} ({tally(count)})"
                     for firewalls, count in detail.reach)


def matched_phrase(detail: ControlDetail) -> str:
    """What the control actually looked for to grade these findings this way.

    THE QUERIES' OWN CLIENT SENTENCES. `ControlQuery.short_description` is written for a reader
    - *"Rules whose antivirus profile lets malware through on a decoder or an application
    exception."* - and a finding records which query matched it, so a block at one severity can
    say what that severity means rather than leaving the reader to infer it from the grade.

    SEVERAL WHERE SEVERAL MATCHED, joined rather than listed: a control with two queries at one
    grade is two readings of the same check, and the pair is one sentence's worth of thought.
    """
    if not detail.matched:
        return manual(f"write a short_description for the {detail.control.control_id} "
                      f"{Control.Severity(detail.severity).label.lower()} query, for the client "
                      f"who reads this section")
    return " ".join(detail.matched)


def query_sentences() -> dict:
    """(control id, severity) -> the client sentences of the queries that graded it that way.

    ONE DISTINCT QUERY PER FINDING KIND rather than a walk over the findings. Every kind has a
    `FindingControlQueryBase` join beside it recording which query matched which finding, and
    the three columns this needs - control, severity, sentence - have at most a few hundred
    distinct combinations across the estate, against 17,555 findings on the lab.
    """
    found = defaultdict(list)
    for kind in finding_registry.FINDING_KINDS:
        for related in kind.model._meta.related_objects:
            model = related.related_model
            if not issubclass(model, FindingControlQueryBase):
                continue
            rows = model.objects.values_list(
                "control_query__control__control_id",
                f"{related.field.name}__severity",
                "control_query__short_description").distinct()
            for control_id, severity, sentence in rows:
                if sentence and sentence not in found[(control_id, severity)]:
                    found[(control_id, severity)].append(sentence)
    return found


def read_control_detail(measured: Measured, places: dict | None = None) -> list:
    """Every control and severity that raised a finding, WORST FIRST - one entry per block.

    ONE ORDER FOR BOTH SURFACES. Jason, 2026-11-09: *"The detail re-orders to match, and the
    summary is a doc link to the detail."* The summary table and the detail section walk this
    same list, so row 12 is block 12 and the link cannot point at the wrong thing.

    Only the controls that RAISED a finding are in it, which the section's own first line says:
    on the lab that is 203 of the 216 active controls, over 264 blocks.
    """
    subjects = {control.control_id: name
                for name, members in group_controls_by_subject().items()
                for control, _kind in members}
    sentences = query_sentences()
    # PASSED IN BY `build`, which already pays for the remediation tables through `read_groups`;
    # computed here for a caller that has none, which is every test of this function.
    places = remediation_places() if places is None else places
    detail = []
    for name, members in group_controls_by_subject().items():
        for control, _kind in members:
            severities = measured.by_severity[control.control_id]
            for severity in WORST_FIRST:
                if not severities[severity]:
                    continue
                reach = affected_firewalls(
                    measured.firewalls[(control.control_id, severity)])
                detail.append(ControlDetail(
                    control=control,
                    severity=severity,
                    findings=severities[severity],
                    objects=len(measured.subjects_by_severity[
                        (control.control_id, severity)]),
                    object_nouns=measured.subject_nouns[control.control_id],
                    reach=reach,
                    matched=tuple(sentences.get((control.control_id, severity), ())),
                    places=places.get((control.control_id, severity), 0),
                    subject=subjects[control.control_id]))
    detail.sort(key=lambda one: (-SEVERITY_RANK[one.severity], -one.findings,
                                 one.control.name))
    return [replace(one, anchor=f"_Ref{p.REFERENCE_BASE + index}")
            for index, one in enumerate(detail)]


def split_coverage(detail: list) -> tuple[list, list]:
    """The estate's blocks and the review's own, which get a section each.

    Jason, 2026-11-06: *"Assessment Coverage should probably be a separate sub section"*, and
    again on 2026-11-09 when the observation table that carried it was dropped. These controls
    report on what THIS REVIEW could not read, not on anything a firewall is doing, and under
    the estate's heading they would be read as a finding against it.
    """
    return ([one for one in detail if one.subject != COVERAGE_SUBJECT],
            [one for one in detail if one.subject == COVERAGE_SUBJECT])


def control_detail_rows(detail: ControlDetail) -> list:
    """`Control` and `Severity` on one row, then `Findings`, `Firewalls`, and the catalog's
    three lines.

    THE ID AND THE GRADE SHARE THE FIRST ROW, Jason 2026-11-06: *"Control id and severity can
    probably be on the same row."* Both are a couple of words, so they read as one line about
    which control this is, and the table is six rows rather than seven.

    THE CONTROL ID IS IN THE TABLE because a client who follows one of these up quotes it -
    which is also why the catalog's validator refuses a line that names the control's own id,
    the row above having said it already.

    A LINE THE CATALOG DOES NOT CARRY IS A MARKED PLACEHOLDER, not an empty cell and not the
    engineer-facing field beside it: the same call `priority_rows` makes for a control with no
    `short_remediation`. The catalog's own validator requires all four of an active control,
    so a placeholder here is a control somebody added through the UI, and `manual_placeholders`
    counts it into the build's report.
    """
    rows = [[p.text_cell("Control", width=DETAIL_PAIR_WIDTHS[0], bold=True),
             p.text_cell(detail.control.control_id, width=DETAIL_PAIR_WIDTHS[1]),
             p.text_cell("Severity", width=DETAIL_PAIR_WIDTHS[2], bold=True),
             p.text_cell(Control.Severity(detail.severity).label,
                         width=DETAIL_PAIR_WIDTHS[3])]]
    lines = [
        ("Findings", findings_phrase(detail)),
        ("Firewalls", firewalls_phrase(detail)),
        ("What was matched", matched_phrase(detail)),
    ]
    for name, label in DETAIL_LINES:
        lines.append((label, getattr(detail.control, name) or detail_placeholder(
            name, detail.control.control_id)))
    rows += [[p.text_cell(label, width=DETAIL_WIDTHS[0], bold=True), _detail_value(value)]
             for label, value in lines]
    return rows


def _detail_value(text: str):
    """The value cell of a labeled row, covering the three columns the first row splits."""
    cell = p.text_cell(text, width=DETAIL_WIDTHS[1])
    cell.span = 3
    return cell


def detail_placeholder(name: str, control_id: str) -> str:
    """What stands in for a catalog line nobody has written, naming the field to write."""
    return manual(f"write the {name.replace('_', ' ')} line for {control_id}, for the client "
                  f"who reads this section")


def write_control_detail(detail: list) -> tuple[list, list]:
    """Detailed Findings and Recommendations: one block per control and severity, worst first.

    THE SEVERITY IS THE HEADING AND THE CONTROL SITS UNDER IT, which is the order the summary
    table is in - Jason, 2026-11-09: *"The detail re-orders to match, and the summary is a doc
    link to the detail."* A control that fires at three grades appears three times, under three
    headings, which is the truth about it: three different queries matched and each is a
    different reading of the same check.

    REAL HEADINGS, not a shaded band (Jason, 2026-11-06). Heading 2 for the grade and Heading 3
    for the control, so both reach the table of contents and Word's navigation pane - which is
    how a reader gets to one control in forty pages. Each Heading 3 also carries the BOOKMARK
    its summary row links to.

    NO TABLE CAPTIONS. Every other table in this document is captioned and numbered; two
    hundred more would be two hundred `Table n: ...` entries in a list of tables that has
    eleven. A caption is a way of sending a reader to a table, and these tables are what the
    reader was sent to.
    """
    elements = [
        p.paragraph(p.HEADING_1, "Detailed Findings and Recommendations"),
        p.paragraph(p.NORMAL,
                    "Every control that raised a finding, worst first: what was matched, how "
                    "far it reaches, why it matters and what to change. A control graded at "
                    "more than one severity appears once for each. A control that raised no "
                    "finding is not listed."),
    ]
    unwritten = _write_blocks(elements, detail, heading=True)
    report = (f"Detailed Findings and Recommendations: {len(detail)} "
              f"{plural(len(detail), 'block')} over "
              f"{len({one.control.control_id for one in detail})} controls")
    if unwritten:
        report += f", {unwritten} lines marked MANUAL for a consultant to write"
    return elements, [report]


def write_coverage(detail: list) -> tuple[list, list]:
    """Assessment Coverage: the same blocks, for the controls that report on the REVIEW.

    A SECTION OF ITS OWN, Jason 2026-11-06 and again 2026-11-09. Every row here records
    configuration this assessment could not read - under the estate's heading each one would be
    read as a finding against a firewall, which is the opposite of what it says.
    """
    if not detail:
        return [], []
    elements = [
        p.paragraph(p.HEADING_1, COVERAGE_SUBJECT),
        p.paragraph(p.NORMAL,
                    "These blocks are about the review rather than about the estate: each one "
                    "records configuration this assessment could not read, and what it would "
                    "take to close the gap. They carry a severity because an unread setting is "
                    "an ungraded one, not a setting known to be right."),
    ]
    unwritten = _write_blocks(elements, detail, heading=True)
    report = f"{COVERAGE_SUBJECT}: {len(detail)} {plural(len(detail), 'block')}"
    if unwritten:
        report += f", {unwritten} lines marked MANUAL for a consultant to write"
    return elements, [report]


def _write_blocks(elements: list, detail: list, *, heading: bool) -> int:
    """The blocks themselves, grouped under their severity. Returns the MANUAL lines written."""
    unwritten = 0
    grade = None
    for one in detail:
        if heading and one.severity != grade:
            grade = one.severity
            elements.append(p.paragraph(p.HEADING_2,
                                        Control.Severity(grade).label))
        title = p.paragraph(p.HEADING_3, one.control.name)
        p.bookmark(title, one.anchor, int(one.anchor.removeprefix("_Ref")))
        elements.append(title)
        elements.append(p.table(control_detail_rows(one), DETAIL_GRID, width=FIXED_WIDTH))
        elements.append(p.paragraph(p.NORMAL, ""))
        # THE ONE LINE OUTSIDE THE TABLE, and the only one of the four allowed to carry a
        # screen path - `Device > Server Profiles > LDAP` - because a path is what it is.
        elements.append(p.lead_paragraph(
            p.NORMAL, "Where to confirm it.",
            one.control.where_to_confirm
            or detail_placeholder("where_to_confirm", one.control.control_id)))
        unwritten += sum(1 for line, _label in DETAIL_LINES
                         if not getattr(one.control, line))
        unwritten += 0 if one.control.where_to_confirm else 1
        unwritten += 0 if one.matched else 1
    return unwritten


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
        # Jason, 2026-11-07: *"an out-of-scope firewall should vanish from Reviewed
        # Devices"*. These two lists are Project Overview's counts and the Reviewed Devices
        # table - see `artifacts.scope`.
        firewalls=sorted(scope.appliances_in_scope(),
                         key=lambda a: a.hostname or a.serial_number),
        panoramas=sorted(scope.management_stations_in_scope(), key=lambda s: s.name),
    )


def fill(text: str, engagement: Engagement) -> str:
    """The template's `[Shortname]` and `[Client Long Name, Inc.]`, substituted."""
    return (text.replace(SHORTNAME, engagement.shortname)
                .replace(COVER_CLIENT, engagement.client_name))


# --------------------------------------------------------------------------------------------
# Section writers. One per section, each returning (elements, report line)
# --------------------------------------------------------------------------------------------

def write_contents() -> list:
    """The heading and an empty `TOC` field, for `partials.table_of_contents` to fill.

    OUT OF THE SECTION LOOP because it is the one section whose content is the rest of the
    document: the field goes in here, at the front where it belongs, and the entries are
    written once every other section has produced its headings.
    """
    return [p.paragraph(p.TOC_HEADING, "Table of Contents"), p.toc_field()]


def write_executive_summary(engagement: Engagement, captions: p.CaptionCounters,
                            detail: list) -> tuple[list, str]:
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
    rows, report = summary_of_findings_rows(detail)
    elements.append(captions.table("Summary of Findings and Recommendations"))
    elements.append(p.table(rows, SUMMARY_GRID, width=(5000, "pct")))
    elements.append(p.paragraph(p.NORMAL, ""))
    elements.append(p.paragraph(p.NORMAL, fill(
        "Optiv understands the importance [Shortname] places on IT security and sincerely "
        "appreciates the opportunity to have worked on this engagement. Please contact the "
        "Optiv project manager with any questions regarding these findings or the contents of "
        "this report.", engagement)))
    return elements, report


def summary_of_findings_rows(detail: list) -> tuple[list, str]:
    """`# | Finding/Observation | Recommendation | Importance`, one row per control and severity.

    The template's comment on this table: *"Tie these to the Recommendations section of this
    document. Order the findings by priority, if applicable."*

    ONE ROW PER BLOCK OF THE DETAIL SECTION, in the same order, each one a link to its block.
    This table used to be one row per REMEDIATION GROUP named after the group's worst control,
    which put `Source/Destination Address Breadth Bounded. 75,664 findings.` on a client's
    page when that control's own findings were 5,428 and the other 70,236 belonged to the
    fifteen other controls of the Security rule group (Jason, 2026-11-09). A row now counts
    exactly what it names.

    AND IT IS SPLIT BY SEVERITY. Jason, 2026-11-09: *"If there are 10000 medium and 1 critical,
    that would be a misrepresentation of the facts."* A control graded both ways is two rows
    carrying their own counts, not one row carrying the worse grade and both.

    THE RECOMMENDATION REPEATS ON EACH OF A CONTROL'S ROWS, and that was the call rather than
    an oversight (Jason, 2026-11-09: *"leave it"*). 61 of the lab's 264 rows repeat the row
    above them this way, and the alternative - a blank cell on the second and third - costs a
    reader skimming one severity band the remedy for what they are looking at.

    IT IS COMPLETE, and on the lab that is 264 rows over 203 controls, about eleven pages. That
    is what a comprehensive catalog earns: *"Yes it will be long, but that's simply because
    we have a very comprehensive set of controls."*
    """
    rows = [[
        p.text_cell("#", width=SUMMARY_WIDTHS[0], style=p.TABLE_HEADING),
        p.text_cell("Finding/Observation", width=SUMMARY_WIDTHS[1], style=p.TABLE_HEADING),
        p.text_cell("Recommendation", width=SUMMARY_WIDTHS[2], style=p.TABLE_HEADING),
        p.text_cell("Importance", width=SUMMARY_WIDTHS[3], style=p.TABLE_HEADING),
    ]]
    for number, one in enumerate(detail, start=1):
        rows.append([
            # A LITERAL NUMBER in `Table - Text` rather than the template's own
            # `Table - List Number 1`. That style is a numbered list, so a cell holding the text
            # "7" under it renders "7. 7"; the numbers are known at build time for the same
            # reason the captions are literal.
            p.text_cell(str(number), width=SUMMARY_WIDTHS[0]),
            p.Cell(paragraphs=[
                p.link_paragraph(p.TABLE_TEXT, one.control.name, one.anchor, tight=True),
                p.paragraph(p.TABLE_TEXT, findings_phrase(one), tight=True)],
                width=SUMMARY_WIDTHS[1]),
            p.text_cell(one.control.short_remediation or manual(
                f"write a short_remediation for {one.control.control_id} - one imperative "
                f"sentence, 100 characters or fewer"), width=SUMMARY_WIDTHS[2]),
            p.rating_cell(one.severity, Control.Severity(one.severity).label,
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
                p.text_cell("No controls are active in this deployment's catalog, so nothing "
                            "has been assessed and there is nothing to summarize.",
                            width=SUMMARY_WIDTHS[1]),
                p.text_cell("Apply a controls catalog and run findings.",
                            width=SUMMARY_WIDTHS[2]),
                p.rating_cell(None, "Not assessed", width=SUMMARY_WIDTHS[3]),
            ])
    return rows, (f"Summary of Findings and Recommendations: {len(detail)} "
                  f"{plural(len(detail), 'row')} over "
                  f"{len({one.control.control_id for one in detail})} controls, each linked to "
                  f"its block")


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

def write_health_check(engagement: Engagement,
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
                    "These results pertain to the global network and security environment. "
                    "Every control that raised a finding is set out in Detailed Findings and "
                    "Recommendations, in the order the summary table lists them."),
        captions.table("Process Observations"),
        p.table(process_observation_rows(), OBSERVATION_GRID, width=(5000, "pct")),
    ]
    reports = ["Process Observations: 5 placeholder rows, all interview findings"]

    # NO PANORAMA SECTION, AND SINCE 2026-11-09 NO FIREWALL ONE EITHER. Every control in the
    # catalogue reads a firewall's own configuration and every rule it graded was a firewall
    # rule, so the Panorama section had a heading, two paragraphs explaining why it was empty,
    # and nothing else - Jason, 2026-11-06: *"we can just drop the panorama section"*. The
    # firewall section went the same way three days later: what stood under it was the Firewall
    # Observations table, which printed, per control and severity, the count and the firewalls
    # that every Detailed Findings block already prints. Jason, 2026-11-09: *"it goes. It was a
    # bit awkward anyway"*. What Panorama holds is still in the document - the containers table
    # under Approach/Methodology names every device group and template, and the remediation
    # pages name the one each fix is made in.
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


# NO RULEBASE TABLES. Jason, 2026-11-06: *"remove table 6 and all other tables/content all
# the way down to 'Assessment Coverage'"*. The section carried a table of the worst rules
# per rulebase, a screenshot frame and a figure caption for each of Security, Decryption
# and DoS. Every finding in them is in the observation table above already, reported
# against the control that raised it and the firewalls that carry it, so they said the
# same thing a second time and at greater length.


def manual_placeholders(scaffold) -> int:
    """How many `[MANUAL: ...]` placeholders the finished document carries.

    COUNTED OFF THE ASSEMBLED BODY, not off the sections that wrote them, so a placeholder the
    scaffold's own cover or back cover carries is counted too. It goes in the build's report
    because "what is left for a person to write" is a number an engineer should be told rather
    than discover on page nine - see the module docstring.

    COUNTED OVER THE CONCATENATED TEXT, not per run: Word splits a run wherever the proofing
    state or the revision id changes, so the cover's own placeholders arrive in pieces and
    counting runs misses them.
    """
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

    The Risk column is `Control.rationale` - the catalog's own one-sentence statement of why
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

    `URL Filtering` is read off the license inventory and `SSL Decryption` off the decryption
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
        return "No license rows returned"
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
    refuses outright - or against a control the catalog no longer holds.
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

    THE DETAIL IS NO LONGER OPTIONAL. It was a parameter defaulting to OFF, on the reading
    that forty pages of control blocks about doubles the document and a client might not want
    them. That reading died with the Firewall Observations table: the counts a reader needs now
    break out in the detail and nowhere else, so a build without it ships a summary whose rows
    link into empty space. Jason, 2026-11-09: *"Control Detail is no longer optional. We can
    remove that code entirely."*

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
    scope_lines = scope.scope_report()

    engagement = read_engagement(today=today, revision=revision)
    captions = p.CaptionCounters()
    groups, groups_report = read_groups(measured)
    containers, containers_report = read_containers()
    estate, coverage = split_coverage(read_control_detail(measured, remediation_places()))

    elements, reports = [], [*scope_lines, groups_report, containers_report]
    elements.extend(write_contents())
    #: Where the contents line goes in the report - ahead of the sections, as on the page. Its
    #: count is not known until they have all been written.
    contents = len(reports)
    for section in (
        lambda: write_executive_summary(engagement, captions, estate),
        lambda: write_project_overview(engagement, containers, captions),
    ):
        produced, report = section()
        elements.extend(produced)
        reports.append(report)

    produced, section_reports = write_health_check(engagement, captions)
    elements.extend(produced)
    reports.extend(section_reports)

    for section in (lambda: write_control_detail(estate), lambda: write_coverage(coverage)):
        produced, section_reports = section()
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

    # LAST, because it reads its entries back out of the headings above.
    reports.insert(contents, f"Table of Contents: {p.table_of_contents(elements)} entries, "
                             f"each one a link to its heading")

    scaffold = open_scaffold()
    scaffold.substitute_cover({
        COVER_CLIENT: engagement.client_name,
        COVER_OPPORTUNITY: engagement.opportunity,
        COVER_REVISION: engagement.revision,
    })
    # The template asks Word for the date; this build knows it. See
    # `Scaffold.write_date_fields` - which also stops Word offering to update the fields when
    # a reader opens the file.
    scaffold.write_date_fields({'"MMMM d, yyyy"': long_date(engagement.built_on),
                                '"yyyy"': str(engagement.built_on.year)})
    scaffold.insert(elements)
    reports.append(f"Captions: {captions.tables} tables and {captions.figures} figures, "
                   f"numbered in document order")
    reports.append(f"Placeholders: {manual_placeholders(scaffold)} marked MANUAL for a "
                   f"consultant to fill")
    return scaffold.to_bytes(), reports
