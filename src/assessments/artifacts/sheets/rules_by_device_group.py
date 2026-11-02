"""Engineer-detail xlsx, prototype: the policy findings folded to ONE ROW PER FIX.

Jason, 2026-09-18: "the rows are by Device group + Rule name. The intent is that the operator can
better see what impact a specific fix will have." Same findings as the Security Rules tab, same
readers, grouped on the key that decides where a fix is made: a rule pushed by a device group is
edited once there, and every vsys it reaches stops failing.

MEASURED FIRST, on run 59: this key folds NOTHING on the lab - 205 findings become 205 rows,
because each device group here pushes to one vsys and its rule names are unique. Grouping by
device group alone gives 6. The tab is built anyway because the fold is a property of the ESTATE,
not of the report: a group pushing one rule to forty vsys is the case this answers, and the
Findings column says how many a fix clears. On this estate every row reads 1, which is the honest
answer rather than a broken one.

WHERE A GROUP HOLDS MORE THAN ONE RULE OBJECT the values are compared rather than assumed: a
column showing one value means every member agreed, and "(differs)" means they did not, with the
Notes column naming which. Two local rules can share a name in different vsys and hold different
services, and a row claiming one service for both would be wrong.

ITS COLUMN LIST IS A SECOND COPY OF THE PER-FINDING TAB'S, AND THAT IS A DEFECT RATHER THAN A
DESIGN. `COLUMNS`, `VALUE_READERS` and `FIELD_BY_COLUMN` are hand-kept here while the Security
Rules tab derives its setting columns from the controls' own clauses, and the guard in `fold()`
below is a hand-kept copy of `findings.check_every_tested_field_is_presented`. On 2026-11-01 the
same EIGHTEEN columns had to be added in both places, in the same order, from the same headings -
and only the headings are actually shared. A control added to the catalogue brings its column to
the other tab by itself and raises here until somebody types it. Inside this module they had to
go in FOUR places, which is why `SETTING_FIELDS` below exists: the first version of this change
appended the last two to each list separately and put one of them eleven columns away from where
the other tab draws it.

NO LINKS ON THIS TAB. A collapsed row can name several controls, and Excel allows one hyperlink
per cell - so the Control ID cell lists them as text. The Controls tab is a click away in the tab
strip, sorted by id.
"""
from __future__ import annotations

from collections import defaultdict

from assessments.control_queries import SEVERITY_RANK
from assessments.models import Control

from . import security_rules as security_rules_sheet
from ..layout import (
    NONE, SEVERITY_FILL, SheetInfo, TAB_COLOURS, plural, severity_group, utc, write_header_block,
    write_table)
from .enforcement_points import natural_key
from .findings import (collected_at_by_snapshot, display_value, implicated_format, load,
                       newest_collection, provenance_index, tested_fields)
from ..errors import ArtifactBuildError

TITLE = "Rules by Device Group"

#: The eighteen fields the Security Rules tab derives a setting column for, IN THAT TAB'S ORDER -
#: by control id, and within a control in its baseline's clause order. Stated once here because
#: this module needs it four times (the column list, the readers, the field map and the row) and
#: four copies drift; it is still a SECOND copy of a list the other tab derives, which is the
#: defect this module's docstring records.
#:
#: THE ORDER IS LOAD-BEARING. `tested_fields()` decides which setting a customer reads first on
#: the per-finding tab, and a reader moving between the two tabs reads the same row twice - so a
#: different order here is a second layout for one fact. Appending the two late columns at the
#: end, which is what the first version of this did, put "Inspection kinds in force" eleven
#: columns away from where the other tab puts it.
SETTING_FIELDS = (
    "permitted_port_count", "permitted_port_count_known",        # PAN-POL-003
    "permits_high_risk_application", "high_risk_application_characteristic",   # PAN-POL-006
    "threat_profile_kinds_in_force",                             # PAN-POL-008
    "log_end", "log_setting",                                    # PAN-POL-009
    "has_exact_duplicate", "duplicate_comparison_computed",      # PAN-POL-012
    "days_since_last_hit", "hit_count_reading_known",            # PAN-POL-013
    "busy_rule_placed_late",                                     # PAN-POL-015
    "has_url_filtering_profile", "url_inspection_posture",       # PAN-POL-020
    "description",                                               # PAN-POL-021
    "schedule_kind", "schedule_window_expired",                  # PAN-POL-022
    "open_zone_side_count",                                      # PAN-POL-024
)

#: Width and wrap per setting column, since neither is derivable from the field name.
SETTING_WIDTHS = {
    "permitted_port_count": (14, False), "permitted_port_count_known": (14, False),
    "permits_high_risk_application": (16, True),
    "high_risk_application_characteristic": (18, True),
    "threat_profile_kinds_in_force": (12, False), "log_end": (12, False),
    "log_setting": (20, True), "has_exact_duplicate": (14, False),
    "duplicate_comparison_computed": (14, False), "days_since_last_hit": (14, False),
    "hit_count_reading_known": (14, False), "busy_rule_placed_late": (14, False),
    "has_url_filtering_profile": (14, False), "url_inspection_posture": (18, True),
    "description": (34, True), "schedule_kind": (14, False),
    "schedule_window_expired": (14, False), "open_zone_side_count": (12, False),
}

COLUMNS = [
    ("Findings", 10, False),
    ("Finding #", 12, True),
    ("Control ID", 14, True),
    ("Control", 34, True),
    ("Severity", 10, False),
    ("Status", 9, False),
    # Kept even though every Vsys label below names its firewalls too (Jason, 2026-09-18): "how
    # many devices does this touch" is the blast radius, and counting distinct hostnames out of a
    # column of six qualified vsys labels is not something a reader can do at a glance.
    ("Firewalls", 16, True),
    # Qualified by firewall: two firewalls' vsys1 are different entities.
    ("Vsys", None, True),
    ("Device group", 26, False),
    ("Rulebase", 16, False),
    ("Rule name", None, False),
    ("Source zone", 14, True),
    ("Sources", None, True),
    ("Destination zone", 14, True),
    ("Destinations", None, True),
    ("Service", 24, True),
    ("Application", 24, True),
    ("Action", 10, False),
    ("Profiles", 26, True),
    # THE EIGHTEEN SETTING COLUMNS, 2026-11-01, in the order the per-finding tab derives them -
    # by control id, and within a control in its baseline's clause order. They are hand-kept
    # here and derived there, which is the defect this run filed rather than fixed: this
    # module's own guard below is a second copy of
    # `findings.check_every_tested_field_is_presented`, and the two can only be kept in step by
    # somebody remembering. The HEADINGS are `security_rules.SETTING_LABELS`, read rather than
    # retyped, so a heading changes in one place.
    *((security_rules_sheet.SETTING_LABELS[field], *SETTING_WIDTHS[field])
      for field in SETTING_FIELDS),
    ("Notes", 30, True),
    ("Config collected (UTC)", 20, False),
]

#: Columns holding a value read off the rule. Where a group holds several rule objects, these are
#: compared across them rather than taken from the first.
VALUE_READERS = {
    "Rulebase": security_rules_sheet.rulebase,
    "Source zone": security_rules_sheet.FROM_ZONES_READER.read,
    "Sources": security_rules_sheet.SOURCES_READER.read,
    "Destination zone": security_rules_sheet.TO_ZONES_READER.read,
    "Destinations": security_rules_sheet.DESTINATIONS_READER.read,
    "Service": security_rules_sheet.SERVICE_READER.read,
    "Application": security_rules_sheet.APPLICATIONS_READER.read,
    "Action": lambda rule: rule.action or NONE,
    "Profiles": security_rules_sheet.profiles_in_force,
    # The eighteen settings, read the same way the per-finding tab reads them: `display_value`,
    # so "Yes"/"No"/"(none)"/"(empty)" mean the same thing on both tabs. A plain `getattr` would
    # print `True`, `None` and `` - three spellings this workbook does not use anywhere else.
    **{security_rules_sheet.SETTING_LABELS[field]:
       (lambda rule, _f=field: display_value(getattr(rule, _f)))
       for field in SETTING_FIELDS},
}

#: Which column presents which tested field, so the value at fault is marked here as it is on the
#: per-finding tab.
FIELD_BY_COLUMN = {
    "Source zone": "from_zone", "Sources": "source_address",
    "Destination zone": "to_zone", "Destinations": "destination_address",
    "Service": "service", "Application": "application", "Action": "action",
    # Declares one of the three; its "in force" line renders all of them. It does NOT declare
    # `threat_profile_kinds_in_force`: that count has a column of its own below, because a field
    # declared through `hidden_fields` cannot be marked as the value at fault.
    "Profiles": "has_antivirus_profile",
    # The eighteen settings, 2026-11-01. One column each, so each declares its own field and the
    # value at fault is marked here as it is on the per-finding tab.
    **{security_rules_sheet.SETTING_LABELS[field]: field
       for field in SETTING_FIELDS},
}

#: Sorts before every device group name, and renders as an empty cell - the Rulebase column says
#: "Local" on the same row.
LOCAL = ""


def agreed(values) -> str:
    """One value where every member agrees, "(differs)" where they do not."""
    unique = set(values)
    return unique.pop() if len(unique) == 1 else "(differs)"


def lines(values) -> str:
    """The distinct values, one per line, in first-seen order."""
    seen = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return "\n".join(seen)


def notes_for(members, values) -> str:
    differs = sorted(header for header, value in values.items() if value == "(differs)")
    if not differs:
        return ""
    return (f"{len(members)} rule objects under this name; "
            f"{', '.join(differs)} differ between them")


def fold(subjects=None) -> dict:
    """The tab's rows, and what it reports about them - everything that reads the database.

    A plain dict because it is what `stored.stored_payload` keeps: "count" is the number of
    findings the rows account for, which is what a stored copy is checked against.
    """
    spec = security_rules_sheet.SPEC
    controls, findings = load(spec, subjects)
    # FIELD_BY_COLUMN is hand-kept, so it goes stale silently: a control testing a field no column
    # here presents would fold into a row that says nothing about why it fired.
    presented = set(FIELD_BY_COLUMN.values()) | set(spec.hidden_fields)
    for control in controls:
        model = spec.subject_model(spec.kind_for(control.control_type))
        for field, _stored in tested_fields(model, control, spec.value_readers):
            if field not in presented:
                raise ArtifactBuildError(
                    f"{TITLE}: {control.control_id} tests {field!r} and no column here shows it. "
                    f"Add it to COLUMNS and FIELD_BY_COLUMN.")

    rules_by_finding = {f: spec.kind_for(f.control.control_type).subject_of(f) for f in findings}
    provenance = provenance_index(set(rules_by_finding.values()))
    #: Same map the findings tabs use, and for the same reason: this column read the date off
    #: `rule.source_snapshot`, which brought the snapshot's payload back once per rule.
    collected = collected_at_by_snapshot(findings)

    def device_group_of(rule):
        from django.contrib.contenttypes.models import ContentType
        row = provenance.get(
            (ContentType.objects.get_for_model(type(rule)).pk, rule.pk, "__entry__"))
        if row is None or row.provenance_type != "device_group":
            return LOCAL
        return row.raw_value

    groups = defaultdict(list)
    for finding, rule in rules_by_finding.items():
        groups[(device_group_of(rule), rule.name)].append((finding, rule))

    rows, implicated = [], []
    for (group_name, rule_name), members in sorted(
            groups.items(), key=lambda item: (item[0][0], natural_key(item[0][1]))):
        group_findings = [finding for finding, _rule in members]
        rules = [rule for _finding, rule in members]
        worst = max((f.severity for f in group_findings), key=lambda s: SEVERITY_RANK[s])
        values = {header: agreed(read(rule) for rule in rules)
                  for header, read in VALUE_READERS.items()}

        tested = set()
        for finding, rule in members:
            tested |= {field for field, _stored
                       in tested_fields(type(rule), finding.control, spec.value_readers)}
        row_index = len(rows)
        for i, (header, _width, _wrap) in enumerate(COLUMNS):
            if FIELD_BY_COLUMN.get(header) in tested:
                implicated.append((row_index, i))

        rows.append([
            len(members),
            lines(f.reference for f in group_findings),
            lines(f.control.control_id for f in group_findings),
            lines(f.control.name for f in group_findings),
            Control.Severity(worst).label,
            lines(f.get_status_display() for f in group_findings),
            lines(security_rules_sheet.firewalls(rule) for rule in rules),
            lines(sorted(security_rules_sheet.enforcement_point_label(rule)
                         for rule in rules)),
            group_name,
            values["Rulebase"],
            rule_name,
            values["Source zone"],
            values["Sources"],
            values["Destination zone"],
            values["Destinations"],
            values["Service"],
            values["Application"],
            values["Action"],
            values["Profiles"],
            # The eighteen settings, in COLUMNS order. Read off `values`, so a group holding
            # several rule objects that disagree on one of them shows "(differs)" and the Notes
            # column names which - the same treatment Service and Action have always had.
            *(values[security_rules_sheet.SETTING_LABELS[field]]
              for field in SETTING_FIELDS),
            notes_for(members, values),
            newest_collection(group_findings, collected),
        ])
    assert all(len(r) == len(COLUMNS) for r in rows), "row/column mismatch"

    by_severity = defaultdict(int)
    for finding in findings:
        by_severity[finding.severity] += 1
    return {"count": len(findings), "rows": rows, "implicated": [list(c) for c in implicated],
            "by_severity": dict(by_severity),
            "runs": sorted({f.assessment_run_id for f in findings})}


def stored_fold(subjects=None, *, allow_running=False) -> dict:
    """`fold()`, read from storage where the run's copy is current - see `artifacts/stored.py`."""
    from ..stored import stored_payload

    compute = lambda: fold(subjects)  # noqa: E731
    return (stored_payload("RulesByDeviceGroup", security_rules_sheet.SPEC, compute,
                           allow_running=allow_running)
            or compute())


def write_sheet(build) -> SheetInfo:
    workbook = build.workbook
    folded = stored_fold(build.subjects)
    rows = folded["rows"]
    implicated = [tuple(cell) for cell in folded["implicated"]]
    by_severity = folded["by_severity"]
    finding_count = folded["count"]

    sheet = workbook.add_worksheet(TITLE)
    top = write_header_block(build, sheet, title=TITLE, last_col=len(COLUMNS) - 1,
        tab_colour=TAB_COLOURS["Policies"],
        count_groups=[
            [(len(rows), plural(len(rows), "rule to fix", "rules to fix"), None),
             (finding_count, plural(finding_count, "finding"), None)],
            severity_group(by_severity),
        ])
    write_table(build, sheet, top=top, name="RulesByDeviceGroup", columns=COLUMNS, rows=rows,
                empty_text="No findings")

    for row_index, col_index in implicated:
        _header, _width, wrap = COLUMNS[col_index]
        sheet.write(top + 1 + row_index, col_index, rows[row_index][col_index],
                    implicated_format(build, wrap))

    severity_col = [h for h, _, _ in COLUMNS].index("Severity")
    for text, colour in SEVERITY_FILL.items():
        fmt = {"bg_color": colour, "bold": True}
        if text == "Critical":
            fmt["font_color"] = "#FFFFFF"
        sheet.conditional_format(top + 1, severity_col, top + len(rows), severity_col, {
            "type": "cell", "criteria": "==", "value": f'"{text}"',
            "format": workbook.add_format(fmt)})

    # Every finding must reach a row: the fold may make rows fewer, never findings.
    counted = sum(row[0] for row in rows)
    if counted != finding_count:
        raise ArtifactBuildError(f"{TITLE}: rows account for {counted} findings but {finding_count} exist")
    return SheetInfo(
        title=TITLE,
        description="The same policy findings, one row per rule as it is FIXED - by device group "
                    "and rule name - so a row says how many findings one change clears.",
        count=f"{len(rows)} {plural(len(rows), 'rule')}",
        category="Policies",
        secondary=True,
        report=f"{TITLE}: {len(rows)} rows from {finding_count} findings "
               f"({finding_count - len(rows)} folded)",
        runs=set(folded["runs"]))
