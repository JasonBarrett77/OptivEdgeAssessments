"""Engineer-detail xlsx, prototype: the Enforcement Points worksheet.

Jason, 2026-09-15: appliance-specific values (serial, model, PAN-OS, HA role and peer, managing
station, config collected) live on the Appliances sheet. This sheet carries the appliance hostname
only, as the key back to it.

ONE ROW PER APPLIANCE PER VSYS - an `EnforcementNode`. An enforcement point is a vsys (AGENTS.md:
"a single-vsys firewall is still a vsys"), and on an HA pair ONE enforcement point spans BOTH
appliances. A row per enforcement point would have to put two hostnames in one cell; the node is
the grain at which every column has exactly one value.

WHAT IS SHOWN AS STORED. `vsys_display_name` is printed as collected. Panorama invents it when a
vsys has no label, so "vsys6 / vsys6" is not a defect in the sheet, and a display name can even
name a different slot (the lab's vsys8 is labelled "vsys1"). Key on the Vsys column.

WHAT IT REFUSES TO DO. Write a sheet that omits an enforcement point or a node.
"""
from __future__ import annotations

import re

from optivedge_integrations.integrations.models import EnforcementNode, EnforcementPoint

from ..layout import (
    NONE, SheetInfo, TAB_COLOURS, plural, write_link, write_simple_header, write_table)
from ..errors import ArtifactBuildError

TITLE = "Enforcement Points"

COLUMNS = [
    ("Appliance", None, False),
    ("Vsys", None, False),
    ("Vsys display name", None, False),
    ("In scope", None, False),
]


def natural_key(text: str):
    """vsys2 before vsys10."""
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", text)]


def build_rows(nodes):
    rows = []
    for node in nodes:
        appliance, point = node.appliance, node.enforcement_point
        rows.append([
            appliance.hostname or appliance.serial_number or NONE,
            point.vsys_name,
            point.vsys_display_name or NONE,
            "Yes" if point.in_scope else "No",
        ])
    assert all(len(r) == len(COLUMNS) for r in rows), "row/column mismatch"
    return rows


def write_sheet(build) -> SheetInfo:
    workbook = build.workbook
    nodes = sorted(
        EnforcementNode.objects.select_related("appliance", "enforcement_point"),
        key=lambda n: (n.appliance.hostname or "", natural_key(n.enforcement_point.vsys_name)))
    points = list(EnforcementPoint.objects.all())

    # Every enforcement point is shown through a node, so one with no node would silently vanish.
    shown = {n.enforcement_point_id for n in nodes}
    orphans = [str(p) for p in points if p.pk not in shown]
    if orphans:
        raise ArtifactBuildError(f"{TITLE}: no node row would show {', '.join(orphans)}")

    rows = build_rows(nodes)
    sheet = workbook.add_worksheet(TITLE)

    top = write_simple_header(build, sheet, title=TITLE,
                             last_col=len(COLUMNS) - 1,
                             tab_colour=TAB_COLOURS["reference"])
    write_table(build, sheet, top=top, name="EnforcementPoints", columns=COLUMNS, rows=rows,
                empty_text="No enforcement points")

    # The Appliance cell opens that appliance's row on the Appliances tab.
    appliance_col = [h for h, _, _ in COLUMNS].index("Appliance")
    for i, node in enumerate(nodes):
        write_link(build, sheet, top + 1 + i, appliance_col, "appliance", node.appliance_id,
                   rows[i][appliance_col])

    expected = EnforcementNode.objects.count()
    if len(rows) != expected:
        raise ArtifactBuildError(f"{TITLE}: wrote {len(rows)} rows but {expected} nodes exist")
    return SheetInfo(
        title=TITLE,
        description="Virtual systems on each firewall, and which are in assessment scope.",
        count=f"{len(points)} {plural(len(points), 'enforcement point')}",
        report=f"{TITLE}: {len(rows)} rows ({len(points)} enforcement points)")
