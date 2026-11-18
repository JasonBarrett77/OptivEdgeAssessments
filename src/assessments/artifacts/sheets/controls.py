"""Engineer-detail xlsx: the Controls tab. ONE ROW PER CONTROL AND SEVERITY.

Jason, 2026-09-17: "Create a Controls tab where we can link to from the various findings tabs, and
allows us to remove columns like 'Remediation' which is the same repeated text for all related
findings." Remediation, the audit path and the condition a control fires on belong to the CONTROL,
not to the finding: on the policy tab one remediation sentence was repeated down 205 rows. They are
written once here, and every findings tab links its Control ID cell to the row.

THE GRAIN IS CONTROL AND SEVERITY, since 2026-11-18. Jason: *"Can we remove that column and adjust
the control link to the specific control+severity on the control sheet?"* - the column being
`Severity basis` on the findings rows. A findings row now LINKS to the grade rather than explaining
it in a cell of its own, so the grade needs a row to land on. 325 rows over the 218 controls; the
218 that grade at one severity have one row each, and 84 controls have between two and five.

WHY NOT ONE ROW PER QUERY. The catalog holds 579 active queries, and the pair a findings row can
name is the control and its severity, not the query. 133 of the 325 pairs hold more than one query
- seven on PAN-DCP-001 at high - so at that grain a link target is a choice between rows rather
than a row. Those queries' names, conditions and Evidence sentences stack in three cells that read
ACROSS, which is the convention the findings tabs already use for a control's tested fields. It is
also the shape the health check document prints: one block per control AND severity, with Evidence
as the row that tells two blocks of one control apart.

WHAT A SEVERITY ROW SAYS, and this is the hole P619 recorded: until now the only severity on this
sheet was `Default severity`, so nothing in the whole workbook said that PAN-POL-002 runs from
informational to critical or at what thresholds. The `Severity` and `Default severity` columns sit
side by side for that reason - a row whose grade is above the control's default is a band, and the
condition beside it is the threshold that reaches it.

WHAT IT LISTS. Every control the catalog holds, not only the ones that fired, and every severity
each can grade at whether or not a finding landed there. A control with no findings is a result -
the estate satisfies it - and a control that can never fire is one too: PAN-AUTH-020 is complete as
an INTERVIEW question, carries its question in its description, and is inactive by design. The
Findings column and the Active column say which is which.

THE ONE CLIENT-FACING FIELD IT CARRIES is Evidence, `ControlQuery.short_description` - the sentence
the health check document prints as its Evidence row. It is here because it is the only one of
those fields written PER QUERY, and because a findings row's `Matched queries` cell names queries
and had nothing to look them up in. The rest of this sheet is the engineer's own vocabulary:
`rationale`, `audit` and `remediation`, which is what `models.Control` says this surface prints.

WHAT IT DOES NOT CARRY. `Control.description`, which is written for whoever builds the control -
measurement notes, dated decisions, names - and is not client-facing prose.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from assessments import finding_registry
from assessments.control_queries import SEVERITY_RANK
from assessments.models import Control

from . import findings as findings_sheet
from ..layout import (
    NONE, SheetInfo, TAB_COLOURS, plural, register_row_anchor, write_simple_header, write_table)
from ..errors import ArtifactBuildError

TITLE = "Controls"

COLUMNS = [
    ("Control ID", 14, False),
    ("Control", None, False),
    ("Domain", 28, False),
    ("Severity", 12, False),
    ("Default severity", 12, False),
    ("Active", 9, False),
    ("Findings", 10, False),
    ("Queries that grade here", 34, True),
    ("Fires when (failing condition)", 40, True),
    ("Evidence", 55, True),
    ("Rationale", 60, True),
    ("Where to look", 46, True),
    ("Remediation", 70, True),
]


def finding_counts() -> Counter:
    """{(control id, severity): findings} across every finding model, from the registry.

    KEYED ON THE PAIR because the rows are. A control's own total is still one sum away, and the
    per-pair number is the one worth having: it says which of a control's bands the estate
    actually landed in, which no column of this sheet could say while it was one row per control.
    """
    counts = Counter()
    for kind in finding_registry.FINDING_KINDS:
        for control_id, severity in kind.model.objects.values_list(
                "control__control_id", "severity"):
            counts[(control_id, severity)] += 1
    return counts


def severity_of(control, query) -> str:
    """The severity a finding reports when this query is the worst one that matched.

    A non-baseline query carries it; a baseline does not, and falls back to the control's own
    default - which is what `Control.default_severity` is defined to be. Measured 2026-11-18
    over the 579 active queries: no baseline carries an adjusted severity and no other query
    is without one, so the fallback is a guard rather than a path.
    """
    return query.adjusted_severity or control.default_severity


def queries_by_severity(control) -> dict:
    """{severity: [query]} over the control's ACTIVE queries, baseline first then by name.

    The order inside the list is the order the three stacked cells are written in, so they read
    across. It is the same ordering `findings.tested_fields` uses to lay out a control's columns.
    """
    grouped = defaultdict(list)
    for query in control.queries.all():
        if query.is_active:
            grouped[severity_of(control, query)].append(query)
    for queries in grouped.values():
        queries.sort(key=lambda query: (not query.is_baseline, query.name, query.pk))
    return grouped


def fires_when(control, query) -> str:
    """One query's OWN condition, rendered by the same code the findings tabs use.

    Until 2026-11-18 this rendered the control's BASELINE for every row, which is P613: 29
    controls carry 46 queries whose clause fields are wholly disjoint from their baseline's, so
    the cell could state a condition about fields the query never constrains. Here each query
    renders itself.

    A query this prototype cannot render yet says so rather than stopping the build: the row is
    still worth having.
    """
    try:
        return findings_sheet.render_node(control, query.canonical_query, top=True)
    except (ValueError, KeyError) as exc:
        return f"Not rendered: {exc}"


def stacked(values) -> str:
    """Several facts in one cell, one per line - or `NONE` where every one of them is empty."""
    lines = [value for value in values if value]
    return "\n".join(lines) if lines else NONE


def sheet_rows(controls, counts) -> tuple:
    """The table, and where to anchor each row: `(rows, placements)`.

    A placement is `(anchor key, row index)`. There are two kinds, and both are written for
    every control: the pair `(control pk, severity)`, which is what a findings row links to, and
    the bare `control pk`, which points at the control's FIRST row and is what a findings row
    falls back to when its recorded severity is one no active query produces any more.
    """
    rows = []
    placements = []
    for control in controls:
        grouped = queries_by_severity(control)
        first = None
        for severity in sorted(grouped, key=lambda name: SEVERITY_RANK[name]):
            queries = grouped[severity]
            rows.append([
                control.control_id,
                control.name,
                control.get_control_type_display(),
                control.Severity(severity).label,
                control.get_default_severity_display(),
                "Yes" if control.is_active else "No",
                counts.get((control.control_id, severity), 0),
                stacked(query.name for query in queries),
                stacked(fires_when(control, query) for query in queries),
                stacked(query.short_description for query in queries),
                control.rationale or NONE,
                (control.audit or NONE).rstrip("."),
                control.remediation or NONE,
            ])
            index = len(rows) - 1
            first = index if first is None else first
            placements.append(((control.pk, severity), index))
        if first is None:
            raise ArtifactBuildError(
                f"{TITLE}: {control.control_id} has no active query, so it has no severity row "
                f"for a findings row to link to")
        placements.append((control.pk, first))
    return rows, placements


def write_sheet(build) -> SheetInfo:
    workbook = build.workbook
    controls = list(Control.objects.prefetch_related("queries").order_by("control_id"))
    counts = finding_counts()
    rows, placements = sheet_rows(controls, counts)

    sheet = workbook.add_worksheet(TITLE)
    top = write_simple_header(build, sheet, title=TITLE,
                             last_col=len(COLUMNS) - 1,
                             tab_colour=TAB_COLOURS["reference"])
    # Locked: every findings tab links to these rows by cell address.
    write_table(build, sheet, top=top, name="Controls", columns=COLUMNS, rows=rows,
                empty_text="No controls", locked=True)
    for key, index in placements:
        register_row_anchor(build, "control", key, TITLE, top + 1 + index, len(COLUMNS) - 1)

    expected = Control.objects.count()
    written = len({row[0] for row in rows})
    if written != expected:
        raise ArtifactBuildError(f"{TITLE}: wrote {written} controls but {expected} exist")
    active = sum(1 for c in controls if c.is_active)
    return SheetInfo(
        title=TITLE,
        description="Every control in the catalog at every severity it can grade at: what fires "
                    "it, what a finding there means, where to look, and how to fix it.",
        count=f"{len(rows)} {plural(len(rows), 'row')} over {written} "
              f"{plural(written, 'control')} ({active} active)",
        report=f"{TITLE}: {len(rows)} rows over {written} controls, {active} active, "
               f"{sum(counts.values())} findings between them")
