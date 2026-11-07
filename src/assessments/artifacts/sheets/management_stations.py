"""Engineer-detail xlsx, prototype: the Management Stations worksheet. One row per station.

Jason, 2026-09-15: a tab before Appliances. A management station is what the configuration was
collected through - a Panorama, or (once that collection path exists) a firewall managed directly.
The Appliances tab links each firewall's "Managed by" cell to its row here, so this table is
locked against sorting the same way Appliances is.

WHAT IT NEVER SHOWS. `ManagementStation` stores the collection credentials - username, password and
API key - in plain text columns. None of them is read here. Neither are `verify_tls` or
`ca_bundle_path`, which describe how the COLLECTOR connected, not the client's configuration.

WHAT IT REFUSES TO DO. Write a sheet that omits a station.
"""
from __future__ import annotations

from collections import Counter

from optivedge_integrations.integrations.models import Appliance, ManagementStation

from ..layout import (
    NONE, SheetInfo, TAB_COLOURS, plural, register_row_anchor, write_simple_header, write_table)
from ..errors import ArtifactBuildError
from .. import scope

TITLE = "Management Stations"

COLUMNS = [
    ("Management station", None, False),
    ("Hostname", None, False),
    ("Type", None, False),
    ("Appliances", None, False),
]


def write_sheet(build) -> SheetInfo:
    workbook = build.workbook
    # A station with nothing in scope on it collects nothing and reports nothing, and the
    # appliances counted against one are the in-scope ones - see `artifacts.scope`.
    stations = sorted(scope.management_stations_in_scope(), key=str)
    managed = Counter(scope.appliances_in_scope().values_list(
        "management_station_id", flat=True))
    rows = [[str(station), station.hostname or NONE, station.get_station_type_display(),
             managed[station.pk]] for station in stations]
    assert all(len(r) == len(COLUMNS) for r in rows), "row/column mismatch"

    sheet = workbook.add_worksheet(TITLE)
    top = write_simple_header(build, sheet, title=TITLE,
                             last_col=len(COLUMNS) - 1,
                             tab_colour=TAB_COLOURS["reference"])
    # Locked: the Appliances tab links to these rows by cell address.
    write_table(build, sheet, top=top, name="ManagementStations", columns=COLUMNS, rows=rows,
                empty_text="No management stations", locked=True)
    for i, station in enumerate(stations):
        register_row_anchor(build, "management_station", station.pk, TITLE, top + 1 + i,
                            len(COLUMNS) - 1)

    expected = scope.management_stations_in_scope().count()
    if len(rows) != expected:
        raise ArtifactBuildError(
            f"{TITLE}: wrote {len(rows)} rows but {expected} stations are in scope")
    return SheetInfo(
        title=TITLE,
        description="The Panorama and other management platforms the configuration was "
                    "collected through.",
        count=f"{len(rows)} {plural(len(rows), 'management station')}",
        report=f"{TITLE}: {len(rows)} of {expected} stations")
