"""Build the remediation workbook: the Controls reference, then one tab per object group.

A SECOND DELIVERABLE, not a tab added to the first. Jason, 2026-11-03: *"I don't want the
remediation view in the current workbook artifact"*, and 2026-11-05: *"Remediation needs its own
artifact, separate from the existing Findings artifact. However, the existing findings (detail)
artifact is an excellent example of features and formatting."* So `workbook.build_workbook` and
every sheet it writes are untouched, and everything shared lives in `layout` and is imported by
both: one palette, one header block, one table idiom, one set of tab colours.

WHY THE TWO ARE SEPARATE FILES AND NOT TWO VIEWS OF ONE. They answer different questions, and a
reader opening one is not part-way through the other: the findings workbook says what is wrong,
one row per finding; this says where to go, one row per place. The same finding appears on both,
counted once per surface, and the Summary of each says how many.

THE CONTROLS TAB IS HERE DELIBERATELY. It is the findings workbook's own tab, written by the
same module with no change, and it carries each control's remediation sentence, audit path and
firing condition. A remediation deliverable without the remediation text would send a reader
back to the other file.

IT IS CHEAP. Run Findings stores every group's rows as its last step, so this reads them back
rather than folding 17,529 findings again - see `artifacts.stored.store_run_tables`.
"""
from __future__ import annotations

import io

import xlsxwriter

from assessments import remediation as surface

from .context import WorkbookBuild
from .errors import ArtifactBuildError
from .layout import SUMMARY_TITLE, link_budget_report
from . import scope
from .sheets import controls as controls_sheet
from .sheets import remediation as remediation_sheet
from .sheets import remediation_summary


def groups_in_summary_order() -> list:
    """Every group, in the order the Summary lists them: by PAN-OS category, then as declared.

    DERIVED, not a second list to keep in step - the same reason `workbook.findings_sheets`
    derives the findings tabs from `DOMAINS`. Within a category the declaration order stands,
    which is the order `REMEDIATION_GROUPS` was built in and the order the web index shows
    inside its own category headings.
    """
    from assessments.configuration_navigation import CATEGORIES

    return sorted(surface.REMEDIATION_GROUPS,
                  key=lambda group: CATEGORIES.index(surface.group_category(group)))


def check_every_finding_reached_a_tab(infos) -> None:
    """Every finding of every control a group covers is on exactly one tab.

    Each tab refuses its own incomplete fold, which stops a tab losing rows - but not a GROUP
    losing its tab, or two groups claiming one control. This counts the whole surface against
    the groups' own controls, the way `workbook.check_every_finding_reached_a_tab` counts the
    findings tabs against the database.

    IT DOES NOT COUNT THE ESTATE. PAN-COV-001 and the zone-protection family have findings and
    no group, so the number here is smaller than the findings workbook's by exactly those - 26
    on the lab - and that is a statement about which questions this surface answers rather than
    a discrepancy to reconcile. The Summary of each file carries its own total.
    """
    expected = 0
    for group in surface.REMEDIATION_GROUPS:
        for control in surface.group_controls(group):
            expected += surface._kind_for(control.control_type).model.objects.filter(
                control=control).count()
    shown = sum(sum(info.by_severity.values()) for info in infos if info.by_severity is not None)
    if shown != expected:
        raise ArtifactBuildError(
            f"{shown} findings are on a remediation tab but its groups' controls hold "
            f"{expected}: a group is on no tab, or a control is in two groups.")


def check_tabs_follow_the_summary(infos) -> None:
    """The tab strip and the Summary's own order are one order, not two."""
    from assessments.configuration_navigation import CATEGORIES

    ranks = [CATEGORIES.index(info.category)
             for info in infos if info.by_severity is not None]
    if ranks != sorted(ranks):
        raise ArtifactBuildError(
            "remediation tabs are not in the Summary's category order: "
            f"{[info.category for info in infos if info.by_severity is not None]}")


def build_remediation_workbook() -> tuple[bytes, list[str]]:
    """The workbook as bytes, and the line each tab reported about itself.

    In memory and with no filename, for the reason `build_workbook` gives: the caller is the one
    that knows whether this is a download, a stored artifact or a test.
    """
    groups = groups_in_summary_order()
    remediation_sheet.check_tab_names_are_distinct(groups)
    scope_lines = scope.scope_report()

    buffer = io.BytesIO()
    workbook = xlsxwriter.Workbook(buffer, {"in_memory": True})
    build = WorkbookBuild(workbook=workbook)
    try:
        # Created first so it is the first tab; filled last, from what the others report.
        summary_worksheet = workbook.add_worksheet(SUMMARY_TITLE)
        # Before the group tabs, as in the findings workbook: they would link into its rows.
        infos = [controls_sheet.write_sheet(build)]
        infos += [remediation_sheet.write_sheet(build, group) for group in groups]
        check_every_finding_reached_a_tab(infos)
        check_tabs_follow_the_summary(infos)
        summary_report = remediation_summary.write_sheet(build, summary_worksheet, infos)
        summary_worksheet.activate()
    except BaseException:
        workbook.close()
        raise
    workbook.close()
    reports = [summary_report] + [info.report for info in infos] + scope_lines
    # Nothing here can reach Excel's hyperlink limit - the only links are one per tab on the
    # Summary - but the budget is shared with the findings workbook, and a fallback nobody
    # reports is the failure this was added to stop.
    reports += link_budget_report(build)
    return buffer.getvalue(), reports
