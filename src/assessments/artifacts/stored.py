"""Findings tables, kept for the run they describe instead of rebuilt on every read.

Jason, 2026-10-15: "Findings themselves are already stored, and the view only ever presents
findings from the latest run. What if we lazily store that data that is derived for each
finding?" A table is a function of three things and nothing else:

* **the run** - its findings and, through them, their subjects. A run does not outlive the
  configuration it was computed from: normalization discards it (`lifecycle.py`), and with it,
  by CASCADE, every table kept here.
* **the catalog** - which controls, their names, their queries. A control edited after the run
  changes the fingerprint, so its tables miss and are rebuilt rather than shown as they were.
* **the code that lays it out** - `layout_version()` hashes it, so an upgraded package misses too.

So `PresentedTable` holds the table under a fingerprint of the last two, and a read that finds a
matching one decodes it instead of loading findings, subjects and member sets. Run Findings
stores every table as its last step (`store_run_tables`), so nobody waits for the first build;
a table missing or stale for any other reason is built and stored by whoever reads it first.

**One table per domain, the pages' version.** The pages carry every tested column and the
workbook's tabs carry what their spec says; those are the only difference, so the workbook's
table is the stored one with columns removed (`narrow`), not a second copy.

**The row count is checked on every read.** It costs one query, and it is what makes a table
stored part-way through anything impossible to show as complete.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import zlib
from pathlib import Path

from django.db import IntegrityError, transaction

from assessments.models import AssessmentRun, Control, ControlQuery, PresentedTable

from .sheets.findings import (
    ALL_TESTED_COLUMNS, HEAD_COLUMNS, TESTED_COLUMNS, FindingsTable, build_findings_table,
    selected_controls,
)

logger = logging.getLogger(__name__)


@functools.cache
def layout_version() -> str:
    """A hash of the code a table's cells come from.

    Read off the source rather than kept as a number somebody bumps: a column reworded and a
    version forgotten would show the old wording, from a table that looks current, for as long
    as the run lasted. The reach is deliberately wide - this package's layout, search phrasing
    and models, and Integrations' models and presentation helpers, whose properties the cells
    read - because a needless rebuild costs seconds and a missed one costs a wrong deliverable.
    """
    import assessments
    import optivedge_integrations.integrations as integrations

    oea = Path(assessments.__file__).parent
    oei = Path(integrations.__file__).parent
    paths = []
    for root, pattern in ((oea / "artifacts", "**/*.py"), (oea / "search", "**/*.py"),
                          (oea, "control_queries.py"), (oea, "models.py"),
                          (oei / "models", "**/*.py"), (oei, "presentation.py")):
        paths += sorted(root.glob(pattern))
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def fingerprint(key: str, controls) -> str:
    """The catalog a table reads, and the code that lays it out, as one hash."""
    pks = [control.pk for control in controls]
    data = [
        key,
        layout_version(),
        sorted(Control.objects.filter(pk__in=pks).values(), key=lambda row: row["id"]),
        sorted(ControlQuery.objects.filter(control_id__in=pks).values(),
               key=lambda row: row["id"]),
    ]
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def run_and_count(spec, controls) -> tuple[int | None, int]:
    """The single run these controls' findings belong to, and how many there are.

    None when there are no findings - nothing worth keeping - or when they span runs, which
    `load` refuses; the build then raises as it always did.
    """
    runs, count = set(), 0
    for kind in spec.kinds_for(controls):
        for run_id, in (kind.model.objects.filter(control__in=controls)
                        .values_list("assessment_run_id").distinct()):
            runs.add(run_id)
        count += kind.model.objects.filter(control__in=controls).count()
    return (runs.pop() if len(runs) == 1 else None), count


def _encode(payload: dict) -> bytes:
    return zlib.compress(json.dumps(payload, separators=(",", ":")).encode(), 6)


def _decode(blob) -> dict:
    return json.loads(zlib.decompress(bytes(blob)))


def stored_payload(key: str, spec, compute, *, allow_running: bool = False) -> dict | None:
    """The stored payload for `key`, or `compute()`'s - stored when it may be.

    `compute()` returns a JSON-able dict carrying "count", the number of findings it
    accounts for. Returns None where there is no single run to keep it for; the caller builds.

    Nothing is stored for a run still filling, unless the caller is the run itself
    (`allow_running`): a page opened mid-run would otherwise keep a table of half the findings,
    and the count check would be the only thing standing between it and a reader.
    """
    controls = list(selected_controls(spec).order_by("control_id"))
    run_id, count = run_and_count(spec, controls)
    if run_id is None:
        return None
    signature = fingerprint(key, controls)
    row = (PresentedTable.objects.filter(assessment_run_id=run_id, key=key)
           .values_list("fingerprint", "payload").first())
    if row is not None and row[0] == signature:
        payload = _decode(row[1])
        if payload["count"] == count:
            return payload

    payload = compute()
    running = AssessmentRun.objects.filter(
        pk=run_id, status=AssessmentRun.Status.RUNNING).exists()
    if payload["count"] == count and (allow_running or not running):
        try:
            with transaction.atomic():
                PresentedTable.objects.update_or_create(
                    assessment_run_id=run_id, key=key,
                    defaults={"fingerprint": signature, "payload": _encode(payload)})
        except IntegrityError:
            pass  # stored by a concurrent reader meanwhile - the same table
    return payload


def _table_payload(table: FindingsTable) -> dict:
    return {
        "count": len(table.rows),
        "columns": [list(column) for column in table.columns],
        "rows": table.rows,
        "implicated": [list(cell) for cell in table.implicated],
        "row_meta": table.row_meta,
        "by_severity": table.by_severity,
        "runs": sorted(table.runs),
    }


def _table(spec, payload: dict, controls) -> FindingsTable:
    from .sheets.findings import category_of

    return FindingsTable(
        spec=spec,
        title=spec.sheet_title,
        description=spec.description,
        category=category_of(spec.subject_model(spec.kind_for(spec.control_types[0]))),
        columns=[tuple(column) for column in payload["columns"]],
        rows=payload["rows"],
        implicated=[tuple(cell) for cell in payload["implicated"]],
        findings=[],
        controls=controls,
        by_severity=payload["by_severity"],
        runs=set(payload["runs"]),
        row_meta=payload["row_meta"],
    )


def narrow(table: FindingsTable, spec, tested=None) -> FindingsTable:
    """The table a surface carrying `tested` would have built, from one carrying all of them.

    `columns_for` lays out HEAD, the subject columns, then the tested block - every one of
    `TESTED_COLUMNS` in order, on a table built with `ALL_TESTED_COLUMNS` - so the columns to
    drop are found by position, never by a header that a subject column could share.
    """
    carried = spec.tested_columns if tested is None else tested
    start = len(HEAD_COLUMNS) + len(spec.subject_columns)
    dropped = {start + i for i, (header, _w, _wrap) in enumerate(TESTED_COLUMNS)
               if header not in carried}
    if not dropped:
        return table
    kept = [i for i in range(len(table.columns)) if i not in dropped]
    position = {old: new for new, old in enumerate(kept)}
    return FindingsTable(
        spec=table.spec, title=table.title, description=table.description,
        category=table.category,
        columns=[table.columns[i] for i in kept],
        rows=[[row[i] for i in kept] for row in table.rows],
        implicated=[(r, position[c]) for r, c in table.implicated],
        findings=table.findings, controls=table.controls, by_severity=table.by_severity,
        runs=table.runs, row_meta=table.row_meta)


def stored_findings_table(spec, *, tested=None, subjects=None,
                          allow_running: bool = False) -> FindingsTable:
    """`build_findings_table`, read from storage where the run's table is current."""
    built = []

    def compute():
        table = build_findings_table(spec, tested=ALL_TESTED_COLUMNS, subjects=subjects)
        built.append(table)
        return _table_payload(table)

    payload = stored_payload(spec.table_name, spec, compute, allow_running=allow_running)
    if payload is None:
        return build_findings_table(spec, tested=tested, subjects=subjects)
    if built:
        table = built[0]
    else:
        table = _table(spec, payload, list(
            selected_controls(spec).prefetch_related("queries").order_by("control_id")))
    return narrow(table, spec, tested)


def store_run_tables(assessment_run) -> None:
    """Every table, stored as the run's last step - so the first reader does not wait.

    A table that cannot be built - a guard refusing - is logged and left for the page to report,
    which is where it always surfaced: it does not fail the run, whose findings are complete.
    """
    from .domains import DOMAINS
    from .sheets import rules_by_device_group

    subjects = {}
    for domain in DOMAINS:
        try:
            stored_findings_table(domain.spec, subjects=subjects, allow_running=True)
        except Exception:
            logger.exception("Could not store the %s table for run %s",
                             domain.slug, assessment_run.pk)
    try:
        rules_by_device_group.stored_fold(subjects=subjects, allow_running=True)
    except Exception:
        logger.exception("Could not store the rules-by-device-group table for run %s",
                         assessment_run.pk)
