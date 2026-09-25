"""Build the engineer-detail workbook: every worksheet, in order, into one file.

Prototyped in OptivEdgeProbe/scratch from 2026-09-15 and moved here once the layout settled.

The entry point returns the bytes rather than writing a path, so the caller decides where a
client deliverable lands - a `FileField`, a download response, a test's temporary directory.
"""
from __future__ import annotations

import io
from functools import partial

import xlsxwriter

from .context import WorkbookBuild

from .sheets import appliances as appliances_sheet
from .sheets import controls as controls_sheet
from .sheets import management_crypto as management_crypto_sheet
from .sheets import authentication_settings as authentication_settings_sheet
from .sheets import management_stations as management_stations_sheet
from .sheets import summary as summary_sheet
from .layout import SUMMARY_TITLE
from .sheets import enforcement_points as enforcement_points_sheet
from .sheets import password_complexity as password_complexity_sheet
from .sheets import findings as findings_sheet
from .sheets import objects as object_sheets
from .sheets import rules_by_device_group as rules_by_device_group_sheet
from .errors import ArtifactBuildError

#: Worksheet order after the Summary, which is always first: the reference tabs, then the findings
#: tabs in the order the SUMMARY lists them (Jason, 2026-09-21) - by PAN-OS category, and within a
#: category in `finding_run.GENERATORS` order. `check_tabs_follow_the_summary` holds the two in
#: step. A sheet that links INTO another's rows must still come after it (see `common.ANCHORS`).
#:
#: F-numbers no longer ascend across the tab strip: the run allocates them in GENERATORS order, so
#: policy - last to be generated, first to be read - carries the highest numbers on the first
#: findings tab. They still ascend DOWN each tab, which is where a reader follows them.
T = object_sheets.T


def findings_sheets():
    """One writer per domain, from `domains.DOMAINS`, plus the grouped policy view.

    Derived rather than listed, so the tab strip and the app's findings pages cannot fall out
    of order with each other: both read that one list.
    """
    from .domains import DOMAINS  # local: domains imports the sheets this module imports

    sheets = []
    for domain in DOMAINS:
        spec = domain.spec
        sheets.append(partial(findings_sheet.write_sheet, spec=spec))
        if domain.slug == "security-rules":
            # The same findings folded to one row per fix. A second view of ONE domain rather
            # than a domain of its own, which is why it is not in DOMAINS.
            sheets.append(rules_by_device_group_sheet.write_sheet)
    return tuple(sheets)


SHEETS = (
    management_stations_sheet,
    appliances_sheet,
    enforcement_points_sheet,
    # Before the findings tabs: they link into its rows.
    controls_sheet,
) + findings_sheets()


def check_every_finding_reached_a_tab(infos):
    """Every finding in the database is on exactly one findings tab.

    Each tab checks its own controls, which stops a tab losing rows - but not a CONTROL losing its
    tab. Tabs now select controls individually (PAN-SVC-007 reads on Management Interface rather
    than with system identity), so a control could be excluded from one tab and never added to
    another, and every per-tab check would still pass. This counts the whole run instead.
    """
    from assessments import finding_registry

    stored = sum(kind.model.objects.count() for kind in finding_registry.FINDING_KINDS)
    shown = sum(sum(info.by_severity.values()) for info in infos
                if info.by_severity and not info.secondary)
    if shown != stored:
        raise ArtifactBuildError(
            f"{shown} findings are on a tab but {stored} exist: a control is on no tab, or on two.")


def check_tabs_follow_the_summary(infos):
    """The tab strip and the Summary's Findings list are one order, not two.

    The Summary groups findings tabs by PAN-OS category; the tab strip is hand-ordered here. This
    fails when they disagree - a new tab dropped at the end of SHEETS would otherwise read one way
    in the strip and another on the page nobody edits to match.
    """
    from assessments.configuration_navigation import CATEGORIES

    categories = [info.category for info in infos if info.by_severity is not None or info.secondary]
    ranks = [CATEGORIES.index(category) for category in categories]
    if ranks != sorted(ranks):
        raise ArtifactBuildError(
            f"findings tabs are not in the Summary's category order: {categories}")


def build_workbook() -> tuple[bytes, list[str]]:
    """The workbook as bytes, and the lines each sheet reported about itself.

    In memory rather than to a path: xlsxwriter writes to a file-like object, and the caller
    is the one that knows whether this is a download, a stored artifact or a test.
    """
    buffer = io.BytesIO()
    workbook = xlsxwriter.Workbook(buffer, {"in_memory": True})
    build = WorkbookBuild(workbook=workbook)
    try:
        # Created first so it is the first tab; filled last, from what the other sheets report.
        summary_worksheet = workbook.add_worksheet(SUMMARY_TITLE)
        infos = [getattr(sheet, "write_sheet", sheet)(build) for sheet in SHEETS]
        check_every_finding_reached_a_tab(infos)
        check_tabs_follow_the_summary(infos)
        summary_report = summary_sheet.write_sheet(build, summary_worksheet, infos)
        summary_worksheet.activate()
    except BaseException:
        workbook.close()
        raise
    workbook.close()
    return buffer.getvalue(), [summary_report] + [info.report for info in infos]
