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

---------------------------------------------------------------------------------------------
WHAT THE STAGE 9 RUN ON `mgmt-crypto` READ HERE, 2026-11-01. NOTHING BELOW CHANGES A CELL. It is
written here because the next person to open this file is the one who needs it, and because every
remedy it names is a column or a heading, which are Jason's and not a run's to choose.

ALL ELEVEN PAN-MCR ROWS WERE READ, CELL BY CELL, in both media, over the three appliances stage 6
measured - rebuilt through OptivEdgeIntegrations' own `normalize_management_ssh` from stage 6's
recorded read-backs, which reproduced all fifteen of stage 8's verdicts. All eleven value-at-fault
marks are CORRECT: every PAN-MCR baseline carries assertion clauses and nothing else, and stage 8
wrote `asserted_fields` on all five, so `implicated` has nothing to get wrong on this tab. The
structural gates were green before that run and are green after it.

THE TAB IS NEVERTHELESS TOO THIN TO ACT ON, in three specific places.

1. NOTHING ON A ROW NAMES THE BOUND PROFILE. `profile_name` IS a column, and it is PAN-MGT-010's
   over `ManagementTlsBinding`: `setting_columns` dedupes by bare field name across the models a
   sheet spans, binds the reader to the first control that tests the name in `control_id` order,
   and `PAN-MGT` sorts after `PAN-MCR`. Both models carry `profile_name`, only the TLS control
   tests it, so every SSH row fails the `isinstance` guard and renders the en-dash while the row
   underneath holds `oep-ssh-ciphers` or `oep-mcr6-01`. The en-dash is correct on
   `certificate_trust`, `floor_below_minimum` and `min_version` - an SSH row has no such field -
   and false here. PROPOSED: an SSH-side subject column for the bound profile.

2. THE ROW CANNOT TELL "BIND A PROFILE" FROM "EDIT THE ONE YOU BOUND", which is the distinction
   the paragraph above this one already says the `*_default` flags exist for. Measured: the
   PAN-MCR-001 rows for pan-fw-111 and fw-core-tpa-a are cell-for-cell identical apart from
   Appliance, HA role and `host_key_type`, and they need opposite fixes - one device binds
   nothing, the other binds a profile whose cipher list is wrong. Stage 8's diff says it in terms:
   the two arms "are told apart only by `ciphers_default`". THE FACT IS ALREADY COLLECTED and one
   column away: `FieldProvenance` for `ciphers`, `kex` and `macs` reads `pan_os_default` or
   `local` per list on every row. The Provenance cell cannot reach it, because the walk is keyed
   on the ASSERTED field - `ciphers_below_preferred`, which is DERIVED, which
   `remediation_accessor` discards on purpose - and then falls through to an `__entry__` row this
   model has none of, so the cell reads "Not recorded", whose documented meaning is the opposite
   of the truth. PROPOSED: `provenance_cell` on this spec, answering from the three list fields.
   NOT WRITTEN, because this spec also serves PAN-MGT-010, whose domain has not had its stage 9 -
   `PAN-MGT` is still in `AWAITING_PRESENTATION` - and a Provenance cell is shared by both halves
   of the tab.

3. THE HEADINGS ARE RAW FIELD NAMES. This is one of the eight findings tabs carrying no
   `setting_labels`, so a customer reads `ciphers_below_preferred`, `macs_below_preferred` and
   `rekey_interval_known`. PROPOSED, not written: a heading on this tab is report content.

ONE ROW IS EXEMPLARY AND IS THE ONE TO CHECK A CHANGE AGAINST: PAN-MCR-004 on pan-fw-201. Four
reassuring cells, one marked cell, and they are the right four and the right one.

THE HA GRAIN: ONE ROW PER APPLIANCE, NOT FOLDED ON THE PAIR, AND THE QUESTION IS LEFT OPEN. Stage
5 declares this subject device-wide and the model's unique constraint is on the appliance alone,
so an HA pair yields two rows for one SSH service: measured on the built page, adding the passive
peer with the same profile takes this tab from 11 rows to 16, the peer rows differing only in
Finding #, Appliance and HA role. The stage 9 contract's rule is to fold on the PAIR. This tab does
not, for three reasons. The pair's `deviceconfig/system/ssh` was collected on the ACTIVE MEMBER
ONLY - the passive peer has no row at all - so in any data this surface can reach there is nothing
to fold. Stage 6 contradicts ITSELF about whether this subtree synchronises, in the two sibling
`removal` notes of its own artifact, and neither claim is backed by a measurement in it. And
PAN-MCR-004 reports on the host KEY, which OptivEdgeIntegrations' own model records as
per-appliance and NOT determined by the configuration - so two peers agreeing about
`host_key_type` is not two peers serving the same key, and folding would collapse the one respect
in which they are independent. The HA role column is what makes the pair legible instead. What
would settle it is in `pipeline/artifacts/stage9-mgmt-crypto.json`, under `device_wide_subjects`.
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
