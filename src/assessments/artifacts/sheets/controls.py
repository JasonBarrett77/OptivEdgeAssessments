"""Engineer-detail xlsx, prototype: the Controls tab. One row per control in the catalog.

Jason, 2026-09-17: "Create a Controls tab where we can link to from the various findings tabs, and
allows us to remove columns like 'Remediation' which is the same repeated text for all related
findings." Remediation, the audit path and the condition a control fires on belong to the CONTROL,
not to the finding: on the policy tab one remediation sentence was repeated down 205 rows. They are
written once here, and every findings tab links its Control ID cell to the row.

WHAT IT LISTS. Every control the catalog holds, not only the ones that fired. A control with no
findings is a result - the estate satisfies it - and a control that can never fire is one too:
PAN-AUTH-020 is complete as an INTERVIEW question, carries its question in its description, and is
inactive by design. The Findings column and the Active column say which is which.

WHAT IT DOES NOT CARRY. `Control.description`, which is written for whoever builds the control -
measurement notes, dated decisions, names - and is not client-facing prose. Rationale, audit and
remediation are.
"""
from __future__ import annotations

from collections import Counter

from assessments import finding_registry
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
    ("Default severity", 12, False),
    ("Active", 9, False),
    ("Findings", 10, False),
    ("Why it matters", 60, True),
    ("Fires when (failing condition)", 40, True),
    ("Where to look", 46, True),
    ("Remediation", 70, True),
]


def finding_counts() -> Counter:
    """{control id: findings} across every finding model, from the registry rather than a list."""
    counts = Counter()
    for kind in finding_registry.FINDING_KINDS:
        for control_id in kind.model.objects.values_list("control__control_id", flat=True):
            counts[control_id] += 1
    return counts


def fires_when(control) -> str:
    """The baseline condition, rendered by the same code the findings tabs use.

    A control with no active baseline - or one whose query this prototype cannot render yet -
    says so rather than stopping the build: the row is still worth having.
    """
    try:
        return findings_sheet.fires_when(control)
    except ValueError as exc:
        return f"Not rendered: {exc}"


def write_sheet(build) -> SheetInfo:
    workbook = build.workbook
    controls = list(Control.objects.prefetch_related("queries").order_by("control_id"))
    counts = finding_counts()
    rows = [[
        control.control_id,
        control.name,
        control.get_control_type_display(),
        control.get_default_severity_display(),
        "Yes" if control.is_active else "No",
        counts.get(control.control_id, 0),
        control.rationale or NONE,
        fires_when(control),
        (control.audit or NONE).rstrip("."),
        control.remediation or NONE,
    ] for control in controls]

    sheet = workbook.add_worksheet(TITLE)
    top = write_simple_header(build, sheet, title=TITLE,
                             last_col=len(COLUMNS) - 1,
                             tab_colour=TAB_COLOURS["reference"])
    # Locked: every findings tab links to these rows by cell address.
    write_table(build, sheet, top=top, name="Controls", columns=COLUMNS, rows=rows,
                empty_text="No controls", locked=True)
    for i, control in enumerate(controls):
        register_row_anchor(build, "control", control.pk, TITLE, top + 1 + i, len(COLUMNS) - 1)

    expected = Control.objects.count()
    if len(rows) != expected:
        raise ArtifactBuildError(f"{TITLE}: wrote {len(rows)} rows but {expected} controls exist")
    active = sum(1 for c in controls if c.is_active)
    return SheetInfo(
        title=TITLE,
        description="Every control in the catalog: what it asserts, where to look, and how to "
                    "fix a finding.",
        count=f"{len(rows)} {plural(len(rows), 'control')} ({active} active)",
        report=f"{TITLE}: {len(rows)} controls, {active} active, "
               f"{sum(counts.values())} findings between them")
