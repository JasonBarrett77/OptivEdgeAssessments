"""Engineer-detail xlsx, prototype: the shape EVERY device-setting findings sheet uses.

Jason, 2026-09-15, after the first such sheet worked: "Let's look at the next set of controls that
can be naturally grouped in a single sheet." The second group has the same shape as the first, so
the sheet is built once, here, and each group supplies only a `DeviceSettingSheet` - its control
type and what the domain is. Copying this module per group is exactly the mistake
`object_findings.py` exists to stop in OptivEdgeAssessments.

WHAT SHAPE THIS FITS. Control types whose subject is an appliance-scoped settings row - one row per
firewall, no object name. A sheet may span SEVERAL such types where they answer one question of the
device (NTP, SNMP and system identity are "device services"), because the row shape is identical
and only the model behind it differs. A control may test more than one field: the tested fields,
their values and their provenance are then written one per line in the same order, so the cells
read across.

A named-object domain - administrators, certificates, server profiles - needs subject columns of
its own, which a sheet declares; everything else here is shared with them.

WHAT IS DERIVED, NOT TYPED.
- The finding model and its subject come from `finding_registry.FINDING_KINDS`, by control type.
- The controls come from the catalog, by the same control type.
- The field a control tests is read from its baseline query.
- "Fires when" is rendered from the baseline clauses. It is the FAILING condition; printing it as
  the expected value inverts every threshold.
- The Template cell is `FieldProvenance.raw_value`, which normalization already stores as the bare
  template or stack name. It is not parsed out of anything here.
- PROVENANCE IS READ, NOT DECIDED. Integrations records what a key's absence meant since
  2026-09-21 - a measured PAN-OS default, an assumed one, or nothing configured - and declares the
  computed columns on the model. Before that this sheet resolved a blank per spec, which could not
  be right: implicit values are per KEY and point opposite ways inside one node.

WHAT IT REFUSES TO DO.
- Write a sheet that does not hold every finding of the kind, or findings spanning two runs.
- Present an assumed default as a vendor fact. `assumed_default` reads "Assumed - not measured".
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, NamedTuple

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldDoesNotExist

from assessments import finding_registry
from assessments.control_queries import SEVERITY_RANK
from assessments.models import Control
from optivedge_integrations.integrations.models import Appliance, FieldProvenance

from ..layout import (
    NONE, SEVERITY_FILL, SheetInfo, TAB_COLOURS, category_of, ha_role, plural, severity_group, utc, write_header_block, write_link,
    write_table)
from ..errors import ArtifactBuildError

class ValueReader(NamedTuple):
    """How to read a tested field that is not a column on the subject.

    `members` returns the child objects the value lives on - a surface's services, its permitted
    sources - and their own provenance rows answer the cell, because that is where the keys are
    (OptivEdgeIntegrations, 2026-09-21: "Read provenance from the object the field is on"). Where
    the value has no such rows, `provenance` states in prose where it does come from.
    """
    read: Callable
    provenance: str = ""
    members: Callable | None = None


def member_provenance(reader, subject) -> str:
    """The distinct answers the child rows give, worst-known-first order kept as encountered."""
    labels = []
    for member in reader.members(subject):
        row = member.provenance_for("__entry__")
        label = row.get_provenance_type_display() if row is not None else "Not recorded"
        if label not in labels:
            labels.append(label)
    return "\n".join(labels) or "Not recorded"


def _default_template_cell(subject, provenance_of, fields):
    """One template name per tested field, blank where none was pushed by a template."""
    names = []
    for field, stored in fields:
        row = provenance_of(field) if stored else None
        names.append(row.raw_value if row is not None and row.provenance_type == "template" else "")
    return "\n".join(names) if any(names) else ""


DEFAULT_SOURCE_COLUMNS = (
    ("Template", 22, True, _default_template_cell),
)


#: (header, width, wrap, read(subject, provenance_of)) for an appliance-scoped settings row.
DEFAULT_SUBJECT_COLUMNS = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
)

@dataclass(frozen=True)
class DeviceSettingSheet:
    """One worksheet: every finding of one or more control types, over appliance-scoped models.

    `description` is the DOMAIN, for the Summary tab - what is assessed, not how the sheet is laid
    out. `title` is needed only where a sheet spans several control types and so has no single
    control-type label to take it from. Everything else is derived: the finding models and their
    subjects from the registry, the controls from the catalog, the table name from the title.
    """
    control_types: tuple
    description: str
    title: str = ""
    #: The columns naming the subject, between Status and the tested value. The default suits an
    #: appliance-scoped settings row; a named object declares its own - a rule needs its name, its
    #: vsys and its rulebase, and an appliance column would be wrong for it (a rule belongs to a
    #: vsys, which on an HA pair spans both firewalls). Each is
    #: (header, width, wrap, read(subject, provenance_of)).
    subject_columns: tuple = DEFAULT_SUBJECT_COLUMNS
    #: Tested fields whose value is NOT on the subject row - `service` lives on the rule's service
    #: members. Each reader also states what its Provenance cell says, because "no FieldProvenance
    #: row" means something different here than it does for an absent key.
    value_readers: dict = field(default_factory=dict)
    #: The appliance a finding's row links to on the Appliances tab, or None where a subject has no
    #: single appliance. Vsys-scoped subjects return None: linking a rule to one half of an HA
    #: pair would assert something false.
    appliance_of: Callable = lambda subject: subject.appliance
    #: What to fetch with the findings, relative to the subject. The defaults suit a settings row
    #: reached through its appliance; a sheet whose subject columns walk somewhere else says so,
    #: rather than paying a query per row for it.
    subject_select_related: tuple = ("appliance__appliance_group", "source_snapshot")
    subject_prefetch: tuple = ()
    #: The columns after Provenance saying WHERE a pushed value came from. The default names the
    #: template per tested field. A sheet whose subjects are pushed as a unit says it once instead
    #: - a rule comes from ONE device group, so naming it per field would repeat it - and carries
    #: the exception in a note. Each is (header, width, wrap, read(subject, provenance_of, fields)).
    source_columns: tuple = DEFAULT_SOURCE_COLUMNS
    #: One column per SETTING the sheet's controls test, derived from their baseline queries and
    #: filled for every row - so a row shows the whole object, with the value that caused the
    #: finding marked. A sheet that names its settings itself (the policy tab has Service, Action
    #: and the rest) sets this False and declares `field=` on those columns instead.
    auto_setting_columns: bool = True
    #: Which of TESTED_COLUMNS this sheet carries. A sheet whose subject columns already show
    #: every field its controls test - as the policy sheet does with Action and Service - passes
    #: () and drops the block rather than printing a column of dashes.
    tested_columns: tuple = ("Provenance",)
    #: How the Provenance cell reads. The default answers per tested field, which is right where
    #: a row can take one value from a template and another locally. A subject pushed as a UNIT
    #: answers once for the whole object instead - repeating "Device Group" per field says nothing
    #: the first line did not. Signature: read(subject, provenance_of, fields).
    provenance_cell: Callable = None
    #: Tested fields a subject column already presents, so the per-field cells do not repeat them.
    #: `Fires when` still shows the whole condition: the control tests what it tests, and dropping
    #: a clause from it would misreport the control.
    hidden_fields: tuple = ()

    def kind_for(self, control_type):
        """The registry's entry for a control type - not restricted to this sheet's own types, so
        a borrowed control's findings can be read the same way."""
        return next(k for k in finding_registry.FINDING_KINDS
                    if k.control_type == control_type)

    def kinds_for(self, controls):
        """The finding kinds the sheet's controls actually write to."""
        return tuple(dict.fromkeys(self.kind_for(c.control_type) for c in controls))

    @staticmethod
    def subject_model(kind):
        return kind.model._meta.get_field(kind.subject_field).related_model

    @property
    def sheet_title(self) -> str:
        if self.title:
            return self.title
        (control_type,) = self.control_types
        return Control.ControlType(control_type).label

    @property
    def table_name(self) -> str:
        return re.sub(r"[^A-Za-z0-9]", "", self.sheet_title) + "Findings"

OPERATORS = {"eq": "=", "lt": "<", "lte": "≤", "gt": ">", "gte": "≥"}
#: Negating a comparison, rather than writing "not (x = y)".
NEGATED_OPERATORS = {"eq": "≠", "lt": "≥", "lte": ">", "gt": "≤", "gte": "<"}
#: Operators whose value is not printed - the operator IS the condition.
UNARY_OPERATORS = {"is_empty": "is empty", "is_not_empty": "is not empty"}


# --------------------------------------------------------------------------------------------
# Reading the catalog
# --------------------------------------------------------------------------------------------

def baseline_query(control):
    baselines = [q for q in control.queries.all() if q.is_baseline and q.is_active]
    if len(baselines) != 1:
        raise ValueError(f"{control.control_id}: expected one active baseline query, "
                         f"found {len(baselines)}")
    return baselines[0]


def clauses(node):
    if "clauses" in node:
        for child in node["clauses"]:
            yield from clauses(child)
    elif "field" in node:
        yield node


def tested_fields(subject_model, control, readers=()) -> list[tuple[str, bool]]:
    """(field, stored) in the order the baseline's clauses name them - the order every per-field
    cell on the row is written in, so Setting, Observed value, Provenance and Template read across.

    `stored` is False for a field the model does not store: `ManagementTlsBinding.min_version` is a
    property reading through the SSL/TLS profile, and a value resolved from another object has no
    provenance of its own to show."""
    names = []
    for clause in clauses(baseline_query(control).canonical_query):
        if clause["field"] not in names:
            names.append(clause["field"])
    fields = []
    for name in names:
        if name in readers:
            fields.append((name, False))
            continue
        try:
            subject_model._meta.get_field(name)
            stored = True
        except FieldDoesNotExist:
            if not hasattr(subject_model, name):
                raise ValueError(f"{control.control_id} tests {name!r}, which "
                                 f"{subject_model.__name__} neither stores nor computes. A value "
                                 f"held on related rows needs a value_reader on the sheet.")
            stored = False
        fields.append((name, stored))
    return fields


def tested_cells(spec, finding, subject, shown, provenance):
    """The Setting / Observed value / Fires when / Provenance cells this sheet carries, in the
    order `columns_for` lays them out."""
    by_header = {
        "Fires when (failing condition)": lambda: fires_when(finding.control),
        "Provenance": lambda: provenance,
    }
    return [make() for header, _w, _wrap in TESTED_COLUMNS
            if header in spec.tested_columns for make in (by_header[header],)]


#: The value at fault: bold on a light amber fill. Not one of the severity fills - those are the
#: Severity column's vocabulary, and a reader should not have to ask whether this cell is a
#: severity. One format per wrap setting, made once per workbook BY THE BUILD - the cache was a
#: module dict keyed on `id(workbook)`, and CPython reuses an address once an object is freed,
#: so a later workbook could be handed a format belonging to a closed one.
IMPLICATED_FILL = "#FFF2CC"


def implicated_format(build, wrap):
    return build.format(
        ("implicated", bool(wrap)),
        {"bold": True, "bg_color": IMPLICATED_FILL, "valign": "top", "text_wrap": bool(wrap)})


def read_value(spec, subject, field) -> str:
    reader = spec.value_readers.get(field)
    return reader.read(subject) if reader else display_value(getattr(subject, field))


def display_value(value) -> str:
    """A cell that says what it means. An empty string is a real observation - pan-fw-111 binds no
    TLS profile, so its `profile_name` and the `min_version` behind it are both empty - and a blank
    cell would read as a gap in the report instead."""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if value is None:
        return "(none)"
    if value == "":
        return "(empty)"
    return str(value)


def fires_when(control) -> str:
    """The baseline as one line. A nested group keeps its parentheses: PAN-MGT-010's fourth clause
    is an AND inside an OR, and flattening it would print a condition the control does not have."""
    return render_node(control, baseline_query(control).canonical_query, top=True)


def render_node(control, node, top=False) -> str:
    if "clauses" in node:
        joiner = f" {node.get('operator', 'and')} "
        rendered = joiner.join(render_node(control, child) for child in node["clauses"])
        return rendered if top or len(node["clauses"]) == 1 else f"({rendered})"

    negated = bool(node.get("negated"))
    if node["op"] in UNARY_OPERATORS:
        op = node["op"]
        if negated:
            op = "is_not_empty" if op == "is_empty" else "is_empty"
        return f"{node['field']} {UNARY_OPERATORS[op]}"
    table = NEGATED_OPERATORS if negated else OPERATORS
    op = table.get(node["op"])
    if op is None:
        raise ValueError(f"{control.control_id}: operator {node['op']!r}"
                         f"{' negated' if negated else ''} is not rendered yet")
    return f"{node['field']} {op} {display_value(node['value'])}"


def severity_basis(finding) -> str:
    """Why the finding carries its severity: the control default, or the queries that moved it."""
    control = finding.control
    matched = set(finding.matched_query_names)
    adjusting = [q for q in control.queries.all()
                 if q.name in matched and not q.is_baseline and q.adjusted_severity]
    derived = (max(adjusting, key=lambda q: SEVERITY_RANK[q.adjusted_severity]).adjusted_severity
               if adjusting else control.default_severity)
    if derived != finding.severity:
        return (f"Catalog has changed since this run:\ncurrent queries give {derived},\n"
                f"the run recorded {finding.severity}")
    if not adjusting:
        return "Control default"
    # Not "Adjusted from High to Medium": the Severity column beside it already says Medium, and
    # the control's own default is on the Controls tab (Jason, 2026-09-18).
    return "\n".join([
        f"Adjusted to {finding.get_severity_display()} by:",
        *(q.name for q in adjusting),
    ])


# --------------------------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------------------------

def provenance_index(subjects) -> dict[tuple[int, int, str], FieldProvenance]:
    """(content type id, object id, field) -> row, over subjects of any number of models."""
    index = {}
    by_model = defaultdict(list)
    for subject in subjects:
        by_model[type(subject)].append(subject.pk)
    for model, pks in by_model.items():
        content_type = ContentType.objects.get_for_model(model)
        for row in FieldProvenance.objects.filter(content_type=content_type, object_id__in=pks):
            index[(content_type.pk, row.object_id, row.field_name)] = row
    return index


def provenance_cells(row: FieldProvenance | None, *, stored=True) -> tuple[str, str]:
    """(provenance, template) for one field, from what Integrations RECORDED.

    Nothing is decided here. Until 2026-09-21 a missing row was the only answer for a key the
    payload did not carry, and this sheet resolved it per spec - which could not be right, because
    implicit values are per KEY and point opposite ways inside one node: in `deviceconfig/system`
    an absent `disable-http` means the service is ON while an absent `enable-log-high-dp-load`
    means it is OFF. Integrations now stores which of those a blank was, so the sheet reads it.

    A missing row now means one thing: nothing tracks that field.
    """
    if not stored:
        # A field the model does not store at all - `ManagementTlsBinding.min_version` reads
        # through the SSL/TLS profile. The same word the model uses for a column it computes.
        return FieldProvenance.ProvenanceType.DERIVED.label, ""
    if row is None:
        return "Not recorded", ""
    if row.provenance_type == FieldProvenance.ProvenanceType.TEMPLATE:
        # Stored bare by normalization; @ptpl names a template OR a stack, and we do not guess.
        return row.get_provenance_type_display(), row.raw_value
    if row.provenance_type == FieldProvenance.ProvenanceType.ASSUMED_DEFAULT:
        # NEVER "PAN-OS default": the value is our inference, not a fact about the device. 57 rows
        # in the lab carry it - server-profile admin_use_only, the authentication-profile lockout
        # pair, certificate-profile timeouts - and printing them as vendor behaviour would state
        # something about a customer's firewall that nobody established.
        return "Assumed - not measured", ""
    return row.get_provenance_type_display(), ""


# --------------------------------------------------------------------------------------------
# Building the rows
# --------------------------------------------------------------------------------------------

#: (header, width, wrap). A width of None is sized to the longest LINE of any value, so a cell
#: never wraps mid-line. Every column is also at least as wide as its header plus the table's
#: filter button - see `column_width`.
HEAD_COLUMNS = [
    ("Finding #", None, False),
    ("Control ID", 13, False),
    ("Control", None, False),
    ("Severity", 10, False),
    ("Severity basis", None, True),
    ("Status", 9, False),
]

TESTED_COLUMNS = [
    ("Fires when (failing condition)", 30, True),
    ("Provenance", 15, True),
]

TAIL_COLUMNS = [
    ("Matched queries", 24, True),
    ("Config collected (UTC)", 20, False),
]


def as_column(entry):
    """(header, width, wrap, read, field). `field` names the setting a column presents, where it
    presents one - that is what lets the cell be marked when the row's control tests it."""
    header, width, wrap, read, *rest = entry
    return header, width, wrap, read, (rest[0] if rest else None)


def setting_columns(spec, controls):
    """One column per setting the sheet's controls test, in control order.

    Derived rather than typed: a control added to the catalog brings its setting with it. A field
    belongs to the model its control targets, so on a sheet spanning several models a row shows
    "-" in the columns belonging to the others - the setting is not absent, it is not applicable.
    """
    if not spec.auto_setting_columns:
        return []
    # A field a subject column already presents is not repeated: the AAA sheet names `kind` as a
    # column of its own, and a second column of the same name is both noise and an invalid table.
    columns = []
    seen = {column[4] for column in map(as_column, spec.subject_columns) if column[4]}
    for control in controls:
        model = spec.subject_model(spec.kind_for(control.control_type))
        for field, _stored in tested_fields(model, control, spec.value_readers):
            if field in seen or field in spec.hidden_fields:
                continue
            seen.add(field)

            def read(subject, _p, _field=field, _model=model):
                return read_value(spec, subject, _field) if isinstance(subject, _model) else NONE

            columns.append((field, None, False, read, field))
    return columns


def columns_for(spec, settings):
    """One layout for every findings tab (Jason, 2026-09-18): which finding and which control,
    its status, WHERE it occurs and where the values came from, then the SETTINGS themselves, and
    metadata last. The policy tab set the order; the rest follow it."""
    return (HEAD_COLUMNS
            + [c[:3] for c in map(as_column, spec.subject_columns)]
            + [c for c in TESTED_COLUMNS if c[0] in spec.tested_columns]
            + [c[:3] for c in map(as_column, spec.source_columns)]
            + [c[:3] for c in settings]
            + TAIL_COLUMNS)


def build_rows(spec, findings, controls, settings):
    subject_by_finding = {f: spec.kind_for(f.control.control_type).subject_of(f) for f in findings}
    provenance = provenance_index(set(subject_by_finding.values()))
    fields_by_control = {
        c.pk: tested_fields(spec.subject_model(spec.kind_for(c.control_type)), c,
                            spec.value_readers)
        for c in controls}
    columns = columns_for(spec, settings)
    #: (row index, column index) of every cell holding a value the row's control tests.
    implicated = []

    rows = []
    for row_index, finding in enumerate(findings):
        policy = subject_by_finding[finding]
        fields = fields_by_control[finding.control_id]
        content_type_id = ContentType.objects.get_for_model(type(policy)).pk

        def provenance_of(field, _pk=policy.pk, _ct=content_type_id, _model=type(policy)):
            """The bulk-fetched row, or the model's own answer for a column it COMPUTES.

            `DERIVED_FIELDS` is declared on the model beside the column it describes - 103 of them
            across 21 models - rather than hand-kept here, a repository away from the field.
            """
            row = provenance.get((_ct, _pk, field))
            if row is None and field in _model.DERIVED_FIELDS:
                return FieldProvenance(
                    provenance_type=FieldProvenance.ProvenanceType.DERIVED)
            return row

        shown = [(f, stored) for f, stored in fields if f not in spec.hidden_fields]
        cells = []
        for field, stored in shown:
            reader = spec.value_readers.get(field)
            if reader is not None:
                cells.append(((member_provenance(reader, policy) if reader.members
                               else reader.provenance), ""))
            else:
                cells.append(provenance_cells(provenance_of(field), stored=stored))
        if spec.provenance_cell is not None:
            prov = spec.provenance_cell(policy, provenance_of, shown)
        else:
            prov = "\n".join(p for p, _ in cells)

        subject_cells = [read(policy, provenance_of)
                         for _h, _w, _wrap, read, _f in map(as_column, spec.subject_columns)]
        setting_cells = [read(policy, provenance_of) for _h, _w, _wrap, read, _f in settings]

        tested_cell_values = tested_cells(spec, finding, policy, shown, prov)
        source_cells = [read(policy, provenance_of, shown)
                        for _h, _w, _wrap, read, _f in map(as_column, spec.source_columns)]

        tested_names = {field for field, _ in fields}
        offset = len(HEAD_COLUMNS)
        for i, column in enumerate(map(as_column, spec.subject_columns)):
            if column[4] in tested_names:
                implicated.append((row_index, offset + i))
        offset += len(subject_cells) + len(tested_cell_values) + len(source_cells)
        for i, column in enumerate(settings):
            if column[4] in tested_names:
                implicated.append((row_index, offset + i))

        snapshot = policy.source_snapshot
        rows.append([
            # The app's own identifier (FindingBase.reference), so a row here and the same
            # finding anywhere else in the app carry one name.
            finding.reference,
            finding.control.control_id,
            finding.control.name,
            finding.get_severity_display(),
            severity_basis(finding),
            finding.get_status_display(),
            *subject_cells,
            *tested_cell_values,
            *source_cells,
            *setting_cells,
            "\n".join(finding.matched_query_names) or NONE,
            utc(snapshot.collected_at),
        ])
    assert all(len(r) == len(columns) for r in rows), "row/column mismatch"
    return rows, implicated


# --------------------------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------------------------



def load(spec):
    controls = list(Control.objects.filter(control_type__in=spec.control_types, is_active=True)
                    .prefetch_related("queries").order_by("control_id"))
    findings = []
    for kind in spec.kinds_for(controls):
        findings += list(
            kind.model.objects
            .filter(control__in=controls)
            .select_related("control", "assessment_run",
                            *(f"{kind.subject_field}__{path}"
                              for path in spec.subject_select_related))
            .prefetch_related("control__queries",
                              *(f"{kind.subject_field}__{path}"
                                for path in spec.subject_prefetch)))
    # Reference order: the run allocates by generator, then control, then subject, so this is
    # also control-then-appliance within a kind - and every tab's numbers read upward.
    findings.sort(key=lambda f: f.reference_number)

    runs = {f.assessment_run_id for f in findings}
    if len(runs) > 1:
        raise ArtifactBuildError(f"{spec.sheet_title}: rows span runs {sorted(runs)}; refusing to merge")
    return controls, findings


def check_every_tested_field_is_presented(spec, controls, settings):
    """A control must not fire onto a sheet that shows nothing about why.

    The policy tab names its own columns and drops the generic Setting / Observed value pair, which
    is right while every field its controls test has a column. A control added later that tests
    something else - a profile group, a log setting - would land as a row whose cells all look
    fine. This fails the build instead, naming the control and the field (Jason, 2026-09-18).

    A field is presented when a setting column carries it, when a subject column declares it, or
    when the sheet lists it in `hidden_fields` - which is a deliberate statement that another
    column already says it, and carries a comment saying which.
    """
    presented = ({column[4] for column in map(as_column, spec.subject_columns)}
                 | {column[4] for column in settings}
                 | set(spec.hidden_fields))
    for control in controls:
        model = spec.subject_model(spec.kind_for(control.control_type))
        for field, _stored in tested_fields(model, control, spec.value_readers):
            if field not in presented:
                raise ArtifactBuildError(
                    f"{spec.sheet_title}: {control.control_id} tests {field!r} and no column on "
                    f"the sheet shows it. Add a column for it, or list it in hidden_fields with "
                    f"the column that does.")


def write_sheet(build, spec) -> SheetInfo:
    workbook = build.workbook
    controls, findings = load(spec)
    settings = setting_columns(spec, controls)
    check_every_tested_field_is_presented(spec, controls, settings)
    rows, implicated = build_rows(spec, findings, controls, settings)
    title = spec.sheet_title
    sheet = workbook.add_worksheet(title[:31])

    appliances = Appliance.objects.count()
    by_severity = defaultdict(int)
    for finding in findings:
        by_severity[finding.severity] += 1
    rationales = {c.rationale for c in controls if c.rationale}

    # From the SPEC's control type rather than from the controls that were loaded: a type
    # whose controls are all inactive loads none, and indexing the empty result raised
    # IndexError instead of drawing an empty tab. Deactivating one control was enough.
    category = category_of(spec.subject_model(spec.kind_for(spec.control_types[0])))
    columns = columns_for(spec, settings)
    top = write_header_block(build, sheet, title=title, last_col=len(columns) - 1,
        tab_colour=TAB_COLOURS[category],
        count_groups=[
            [(len(controls), plural(len(controls), "active control"), None),
             (appliances, plural(appliances, "appliance"), None),
             (len(findings), plural(len(findings), "finding"), None)],
            severity_group(by_severity),
        ],
        rationale=rationales.pop() if len(rationales) == 1 else None)
    write_table(build, sheet, top=top, name=spec.table_name, columns=columns,
                rows=rows, empty_text="No findings")

    # The value that caused the finding, marked where it sits - one cell per tested setting,
    # among the row's other settings shown for context (Jason, 2026-09-18).
    for row_index, col_index in implicated:
        _header, _width, wrap = columns[col_index]
        sheet.write(top + 1 + row_index, col_index, rows[row_index][col_index],
                    implicated_format(build, wrap))

    headers = [h for h, _, _ in columns]
    # The Control ID cell opens that control's row on the Controls tab, where its remediation,
    # audit path and firing condition are written once instead of down every row.
    control_col = headers.index("Control ID")
    for i, finding in enumerate(findings):
        write_link(build, sheet, top + 1 + i, control_col, "control", finding.control_id,
                   rows[i][control_col])

    # The Appliance cell opens that appliance's row on the Appliances tab, where the subject has
    # one appliance to open.
    if "Appliance" in headers:
        appliance_col = headers.index("Appliance")
        for i, finding in enumerate(findings):
            subject = spec.kind_for(finding.control.control_type).subject_of(finding)
            appliance = spec.appliance_of(subject)
            if appliance is not None:
                write_link(build, sheet, top + 1 + i, appliance_col, "appliance", appliance.pk,
                           rows[i][appliance_col])

    severity_col = headers.index("Severity")
    for text, colour in SEVERITY_FILL.items():
        fmt = {"bg_color": colour, "bold": True}
        if text == "Critical":
            fmt["font_color"] = "#FFFFFF"
        sheet.conditional_format(top + 1, severity_col, top + len(rows), severity_col, {
            "type": "cell", "criteria": "==", "value": f'"{text}"',
            "format": workbook.add_format(fmt)})

    # The reference document presents every finding OF THE CONTROLS THIS TAB CARRIES. That no
    # control falls off every tab is checked once, for the workbook, in `build_workbook`.
    expected = sum(kind.model.objects.filter(control__in=controls).count()
                   for kind in spec.kinds_for(controls))
    if len(rows) != expected:
        raise ArtifactBuildError(f"{title}: wrote {len(rows)} rows but {expected} findings exist for its "
                         f"controls")
    runs = {f.assessment_run_id for f in findings}
    return SheetInfo(
        title=title,
        description=spec.description,
        count=f"{len(rows)} {plural(len(rows), 'finding')}",
        report=f"{title}: {len(rows)} of {expected} findings, {len(controls)} controls, "
               f"run {sorted(runs)}",
        by_severity=dict(by_severity),
        category=category,
        runs=runs)
