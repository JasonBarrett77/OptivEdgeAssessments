"""Engineer-detail xlsx, prototype: how administrators reach the device - SSH and TLS.

The fourth findings group: management SSH (PAN-MCR-001 to 005) and management TLS (PAN-CRT-006,
PAN-MGT-010). Two models, two control types, one question - what an administrator's connection to
the management plane is protected by. Both are one row per appliance, so the shared
`DeviceSettingSheet` carries them.

WHAT THIS GROUP ADDS THAT THE FIRST THREE DID NOT.
- A NESTED query. PAN-MGT-010's baseline is an OR whose fourth clause is an AND: bound to a
  profile AND no protocol floor resolved, which catches a binding that resolves to no profile at
  all. The Fires-when cell keeps the parentheses.
- Values read THROUGH A JOIN. `min_version` is not stored on the binding; it is the bound SSL/TLS
  service profile's floor, so its Provenance cell reads "Derived" rather than inventing one. This
  is the rule in OptivEdgeAssessments' AGENTS.md - "show only the provenance you actually have".
- DERIVED verdict columns. `ciphers_below_preferred` and its two siblings are what normalization
  concluded about the effective offer, not keys in the configuration; `host_key_type` and
  `host_key_bits` are measured from the server's own host key. The MODEL declares them, so the
  cell says so without this sheet having an opinion.

WHAT THE ROWS DO NOT SAY. The SSH offer is the EFFECTIVE one: the bound profile's lists where it
sets them, the device default where it does not. `ciphers_default` and its siblings record which,
because the remediation differs - bind a profile, or edit the one already bound - but no control
asserts them, so they are not tested fields and do not appear.
"""
from __future__ import annotations

from assessments.models import Control

from . import findings as findings_sheet
from ..layout import SheetInfo

T = Control.ControlType

SPEC = findings_sheet.DeviceSettingSheet(
    title="Management SSH and TLS",
    control_types=(T.MANAGEMENT_SSH, T.MANAGEMENT_TLS),
    description=("What protects an administrator's connection to the firewall: the SSH server's "
                 "ciphers, key exchange, MACs and host key, and the certificate and TLS protocol "
                 "floor the web interface presents."),
)


def write_sheet(build) -> SheetInfo:
    return findings_sheet.write_sheet(build, SPEC)
