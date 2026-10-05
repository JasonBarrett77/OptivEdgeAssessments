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
from .findings import (collected_at_by_snapshot, implicated_format, load, newest_collection,
                       provenance_index, tested_fields)
from ..errors import ArtifactBuildError

TITLE = "Rules by Device Group"

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
    ("Sources", None, True),
    ("Destinations", None, True),
    ("Service", 24, True),
    ("Application", 24, True),
    ("Action", 10, False),
    ("Notes", 30, True),
    ("Config collected (UTC)", 20, False),
]

#: Columns holding a value read off the rule. Where a group holds several rule objects, these are
#: compared across them rather than taken from the first.
VALUE_READERS = {
    "Rulebase": security_rules_sheet.rulebase,
    "Sources": security_rules_sheet.SOURCES_READER.read,
    "Destinations": security_rules_sheet.DESTINATIONS_READER.read,
    "Service": security_rules_sheet.SERVICE_READER.read,
    "Application": security_rules_sheet.APPLICATIONS_READER.read,
    "Action": lambda rule: rule.action or NONE,
}

#: Which column presents which tested field, so the value at fault is marked here as it is on the
#: per-finding tab.
FIELD_BY_COLUMN = {
    "Sources": "source_address", "Destinations": "destination_address",
    "Service": "service", "Application": "application", "Action": "action",
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


def write_sheet(build) -> SheetInfo:
    workbook = build.workbook
    spec = security_rules_sheet.SPEC
    controls, findings = load(spec)
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
            values["Sources"],
            values["Destinations"],
            values["Service"],
            values["Application"],
            values["Action"],
            notes_for(members, values),
            newest_collection(group_findings, collected),
        ])
    assert all(len(r) == len(COLUMNS) for r in rows), "row/column mismatch"

    sheet = workbook.add_worksheet(TITLE)
    by_severity = defaultdict(int)
    for finding in findings:
        by_severity[finding.severity] += 1
    top = write_header_block(build, sheet, title=TITLE, last_col=len(COLUMNS) - 1,
        tab_colour=TAB_COLOURS["Policies"],
        count_groups=[
            [(len(rows), plural(len(rows), "rule to fix", "rules to fix"), None),
             (len(findings), plural(len(findings), "finding"), None)],
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
    if counted != len(findings):
        raise ArtifactBuildError(f"{TITLE}: rows account for {counted} findings but {len(findings)} exist")
    return SheetInfo(
        title=TITLE,
        description="The same policy findings, one row per rule as it is FIXED - by device group "
                    "and rule name - so a row says how many findings one change clears.",
        count=f"{len(rows)} {plural(len(rows), 'rule')}",
        category="Policies",
        secondary=True,
        report=f"{TITLE}: {len(rows)} rows from {len(findings)} findings "
               f"({len(findings) - len(rows)} folded)",
        runs={f.assessment_run_id for f in findings})
