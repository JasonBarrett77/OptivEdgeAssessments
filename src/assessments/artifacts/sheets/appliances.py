"""Engineer-detail xlsx, prototype: the Appliances worksheet. One row per firewall.

Jason, 2026-09-15: first serial, model, PAN-OS version and the HA peer moved off the findings sheets
onto Enforcement Points; then everything appliance-specific moved off Enforcement Points onto this
sheet. Other sheets carry the appliance HOSTNAME only, as the key back to this one.

WHAT IS SHOWN AS STORED.
- Hostname, serial, model and PAN-OS version are Panorama's `show devices all` values.
- The HA peer is the other appliance in the same `ApplianceGroup` of type HA pair. The group's own
  name is machine-generated (`ha-pair-<serial>-<serial>`) and is not shown.
- Config collected is the appliance's latest `show merged config` snapshot - the snapshot the
  device-wide findings sheets cite.

WHAT IT REFUSES TO DO. Write a sheet that omits an appliance.
"""
from __future__ import annotations

from collections import defaultdict

from optivedge_integrations.integrations.models import Appliance, ApplianceGroup, Snapshot

from ..layout import (
    NONE, SheetInfo, TAB_COLOURS, ha_role, plural, register_row_anchor, utc, write_link,
    write_simple_header, write_table)
from ..errors import ArtifactBuildError

TITLE = "Appliances"
MERGED_CONFIG = "show_merged_config"

COLUMNS = [
    ("Appliance", None, False),
    ("Serial", None, False),
    ("Model", None, False),
    ("PAN-OS", None, False),
    ("HA role", None, False),
    ("HA peer", None, False),
    ("Managed by", None, False),
    ("Config collected (UTC)", None, False),
]

def latest_merged_config(appliances) -> dict[int, Snapshot]:
    latest = {}
    snapshots = Snapshot.objects.filter(
        appliance__in=appliances, source_type=MERGED_CONFIG).order_by("collected_at", "pk")
    for snapshot in snapshots:
        latest[snapshot.appliance_id] = snapshot  # ascending, so the last one wins
    return latest


def build_rows(appliances):
    members = defaultdict(list)
    for appliance in appliances:
        members[appliance.appliance_group_id].append(appliance)
    snapshots = latest_merged_config(appliances)

    rows = []
    for appliance in appliances:
        group = appliance.appliance_group
        peers = ([a for a in members[group.pk] if a.pk != appliance.pk]
                 if group is not None and group.group_type != ApplianceGroup.TYPE_STANDALONE
                 else [])
        snapshot = snapshots.get(appliance.pk)
        rows.append([
            appliance.hostname or NONE,
            appliance.serial_number or NONE,
            appliance.model or NONE,
            appliance.software_version or NONE,
            ha_role(appliance),
            "\n".join(p.hostname or p.serial_number for p in peers),
            str(appliance.management_station),
            utc(snapshot.collected_at) if snapshot else "Not collected",
        ])
    assert all(len(r) == len(COLUMNS) for r in rows), "row/column mismatch"
    return rows


def write_sheet(build) -> SheetInfo:
    workbook = build.workbook
    appliances = sorted(
        Appliance.objects.select_related("appliance_group", "management_station"),
        key=lambda a: a.hostname or a.serial_number)
    rows = build_rows(appliances)
    sheet = workbook.add_worksheet(TITLE)

    top = write_simple_header(build, sheet, title=TITLE,
                             last_col=len(COLUMNS) - 1,
                             tab_colour=TAB_COLOURS["reference"])
    # Locked: Enforcement Points and the findings sheets link to these rows by cell address.
    write_table(build, sheet, top=top, name="Appliances", columns=COLUMNS, rows=rows,
                empty_text="No appliances", locked=True)
    for i, appliance in enumerate(appliances):
        register_row_anchor(build, "appliance", appliance.pk, TITLE, top + 1 + i, len(COLUMNS) - 1)

    # "Managed by" opens the station's row on the Management Stations tab.
    station_col = [h for h, _, _ in COLUMNS].index("Managed by")
    for i, appliance in enumerate(appliances):
        write_link(build, sheet, top + 1 + i, station_col, "management_station",
                   appliance.management_station_id, rows[i][station_col])

    expected = Appliance.objects.count()
    if len(rows) != expected:
        raise ArtifactBuildError(f"{TITLE}: wrote {len(rows)} rows but {expected} appliances exist")
    return SheetInfo(
        title=TITLE,
        description="Firewall models, software versions and HA pairing.",
        count=f"{len(rows)} {plural(len(rows), 'appliance')}",
        report=f"{TITLE}: {len(rows)} of {expected} appliances")
