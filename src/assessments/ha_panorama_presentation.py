"""Presentation for the `ha-panorama` domain: PAN-HAP-001 to 005, over two models.

TWO TABS AND NOT ONE, and the reason is the remediation rather than the model count.
`HighAvailabilityConfig` is `Device > High Availability` and `PanoramaRegistration` is the
`Panorama Settings` panel of `Device > Setup > Management` - two vendor screens, two sets of
columns that share nothing but the appliance, and two different acts to fix. One tab would also
print "-" in every other column of every row, because `setting_columns` reads a field off the
model its control targets and answers `layout.NONE` for a subject of the other model.

THE PROVENANCE CELL BRANCHES, AND IT IS THE FIRST ONE IN THIS REPOSITORY THAT DOES.
Every `provenance_cell` shipped before this returns the constant "Derived" - `platform_lifecycle.
DERIVED_CELL`, `objects._saas_derived_cell`, the `data-filtering-posture` and
`content-update-schedule` lambdas - because on those models EVERY field a control clauses on is
declared in `DERIVED_FIELDS`. On BOTH models here that is false, so a constant would print a
falsehood about a measured key. Measured on a built row of `fw-core-tpa-a`, 2026-11-03:

    HighAvailabilityConfig  7 clause fields  6 declared derived  1 NOT: `ha_enabled`
    PanoramaRegistration    3 clause fields  2 declared derived  1 NOT: `panorama_server_secondary`

`ha_enabled` is `deviceconfig/high-availability/enabled`, a real key an administrator wrote, and
the normalizer records a real `FieldProvenance` row for it (`normalization/high_availability.py`
writes fourteen, `ha_enabled` among them). `panorama_server_secondary` is
`local-panorama/panorama-server-2`, likewise. A cell reading "Derived" over either would tell a
customer we computed a value the firewall holds, and on `panorama_server_secondary` that is the
value PAN-HAP-005's own calibration asserts on.

WHY A BRANCHING CELL IS NEEDED AT ALL, since `provenance_of` already answers correctly. The
DEFAULT cell does not read `provenance_of`; it reads `remediation_accessor`, which discards a
DERIVED row ON PURPOSE - "DERIVED counts as no answer", `findings.py:563-564` - and walks to the
object's `__entry__` row. Neither normalizer writes one (measured: `'__entry__' row present:
False` on both models), so `provenance_cells` falls through to its `row is None` arm and the cell
reads **"Not recorded"**, which states that nothing TRACKS the field. Measured on built rows:
"Not recorded" on 6 of 7 HA clause fields and 2 of 3 management-channel ones. The value is not
untracked; it is derived, deliberately and by a documented rule.

So this cell reads `provenance_of` directly and prints what is RECORDED, per clause field, in the
order the row's own per-field cells are written. Nothing is decided here.

NO `ValueReader` ON EITHER TAB, and that is a decision rather than an omission. Neither model
declares `choices=` on any field (grep: zero in both), so a reader calling `get_<field>_display()`
would raise `AttributeError` at template render - past `django check` and past all three
cross-domain gates (P462). The three classification columns therefore print their stored band key
(`unencrypted-port-unknown` and the like) and NOT an English label. That is recorded as a
presentation defect this stage declined to fix rather than as a clean result: see the artifact's
`derived_without_renderer`. A dict-lookup reader would not call the display method and so would
not 500, but the contract and this domain's brief forbid a reader here in terms, and the band keys
are self-describing rather than misleading - unlike the measured harm case, where a `choices`
field printed `0` under the vendor's heading *Save User Credentials*.
"""

from __future__ import annotations

from .artifacts.layout import NONE, ha_role
from .artifacts.sheets import findings as findings_sheet


def provenance_cell(subject, provenance_of, fields) -> str:
    """What is RECORDED about each clause field, derived and measured told apart.

    Signature is `build_rows`' own: (subject, provenance_of, [(field, stored), ...]), with
    `fields` already narrowed to what the row shows and in the order the per-field cells are
    written, so this cell reads across with Setting and Fires when.

    `provenance_of` is the closure `build_rows` binds to this subject. It answers the stored
    `FieldProvenance` row where there is one and synthesises a `DERIVED` row for a column the
    model declares in `DERIVED_FIELDS`, which is exactly the distinction this cell has to print -
    so it is read directly rather than through `remediation_accessor`, whose job is the different
    question of where to go and change the value.

    DISTINCT ANSWERS, worst-known-first as encountered, matching `member_provenance`'s rule: a
    tab whose seven clause fields are six DERIVED and one Local prints two lines, not seven.
    """
    labels = []
    for field, _stored in fields:
        label, _template = findings_sheet.provenance_cells(provenance_of(field), stored=True)
        if label not in labels:
            labels.append(label)
    return "\n".join(labels) or "Not recorded"


#: The appliance, its HA role, and the three readings that say WHICH gap a verdict names.
#:
#: WHY THERE ARE THREE EXTRA COLUMNS HERE AT ALL, since `setting_columns` derives a column for
#: every field an active query has a CLAUSE on and none of these three is one. Stage 8 shipped no
#: band query for PAN-HAP-003 or PAN-HAP-004 - both controls' bands sit at the control's own
#: severity, which the compiler's docstring calls "safely queryless" - so the SEVERITY does not
#: carry the distinction either, and without these the row says "monitoring watches nothing" and
#: "no second keepalive path" with nothing to say which state that is. The two states need
#: OPPOSITE remediations:
#:
#:   `enabled-with-no-group`  monitoring is on and watches nothing -> add a link group
#:   `neither-enabled`        both switches explicitly off          -> turn them on AND add a group
#:   `backup-link-without-peer-address`  a half-built backup link -> give it a far end
#:   `neither-mechanism`      nothing at all                        -> build one
#:
#: Hand-declared because that is the documented way to settle it: `presented` on a stage 5 column
#: is a record of what the column is FOR and not an instruction, and the machinery derives only
#: clause fields. `COVERAGE_SUBJECT`'s "Device's own count" is the precedent for a subject-block
#: column that is EVIDENCE rather than identity, with the reason written beside it.
#:
#: EACH DECLARES ITS `field`, so a control later clausing on it marks THIS cell rather than
#: drawing a second column under a different heading - which the duplicate-header guard would not
#: catch, because the headings differ.
#:
#: AND THE TWO COLUMNS THAT ARE DELIBERATELY NOT HERE: `link_monitoring_enabled` and
#: `path_monitoring_enabled`. Stage 5 marks both `presented` and the model FORBIDS a clause on
#: either, in these words - "this default reassures on the control that asserts the thing it is
#: the default for, and no clause may be written on it". Both are
#: `BooleanField(default=True)`, and the default is the DEVICE's, measured in both directions on
#: fw-core-tpa-a across commit jobs 538 and 539: `show high-availability state` answers
#: `link-monitoring: {enabled: yes, groups: null}` on an appliance holding no monitoring node at
#: all. So on the PAN-HAP-004 row - which fires on `ha_monitors_nothing` - those two cells would
#: read `Yes` and `Yes` BY DEFAULT RATHER THAN BY MEASUREMENT, beside a verdict saying this
#: firewall monitors nothing. That is a row arguing against its own finding, and the most
#: reassuring cells on it would be the two nobody read.
#:
#: WHAT IS LOST BY LEAVING THEM OFF, stated rather than hidden: a reader cannot see the two
#: switches on this tab at all. THERE IS NO HONEST COLUMN TO ADD, which is the strongest form of
#: the argument - both are non-nullable with no `*_known` companion, so the model cannot express
#: "we never asked" for them, and the pair of columns that would tell "off" from "never asked"
#: cannot be written here. What would remove the loss is a `link_monitoring_enabled_known` /
#: `path_monitoring_enabled_known` pair on the model, which is stage 7's and not this stage's.
#: `ha_monitoring_state` is what carries the honest version of the same question, with an
#: explicit `unknown` member, and it is the first of the three columns below.
HIGH_AVAILABILITY_SUBJECT = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    # The column that makes two rows for one pair READ as two members rather than as a
    # duplicate. Active / Passive / Standalone off the appliance group.
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
    ("Monitoring state", 26, False, lambda s, _p: s.ha_monitoring_state or NONE,
     "ha_monitoring_state"),
    ("Second keepalive path", 30, False,
     lambda s, _p: s.second_keepalive_path_state or NONE, "second_keepalive_path_state"),
    # THE SWITCH, AND IT IS NOT PROOF OF ENCRYPTION. Three honest states, because the column is
    # nullable and `display_value` prints `(none)` for a NULL: `Yes` is the key present and on,
    # `No` present and off, `(none)` ABSENT from the configuration. It earns its place because
    # the exposure band beside it classifies by PORT only (`_exposure_band` branches on the port
    # once `not_encrypted` is true), so without this a reader cannot tell "encryption was never
    # switched on" - a one-step remediation - from "switched on and never confirmed in force",
    # which is two steps and needs the HA key imported first. The vendor's own word for it is
    # "Encryption Enabled" (Help 11.2, HA Communications) and the heading deliberately is NOT
    # that: `validate full` refuses the commit without an imported HA key, measured as job 535,
    # so the switch reading `yes` does not mean the link is encrypted and a heading saying
    # "encryption enabled" would invite exactly that reading.
    ("HA1 encryption switch", 22, False,
     lambda s, _p: findings_sheet.display_value(s.ha1_encryption_enabled),
     "ha1_encryption_enabled"),
)


#: EVERY HEADING BELOW IS A PROPOSAL, on `objects.py`'s own terms - Jason takes the heading pass
#: once across many domains (P399). Each is sourced to the vendor's own word where the vendor has
#: one, with the Help version and page, and SAYS SO where it does not. The Help is
#: `PAN-OS Web Interface Help 11.2`, read through `probe.corpus` on 2026-11-03.
#:
#: Declaring a column without a label IS choosing to show a customer a database field name:
#: `setting_labels` falls back to the raw field name. So every derived column a control clauses
#: on is named here.
HIGH_AVAILABILITY_LABELS = {
    # PAN-HAP-001's assertion. OURS - the vendor has no word for this, because no vendor screen
    # reports it: the verdict spans `deviceconfig/high-availability/enabled` and
    # `show high-availability all`, and the Help's own HA widget reports a STATE rather than
    # whether the relationship was ever formed. Named as the verdict and not as the switch,
    # because `enabled: yes` is not a formed relationship - this lab's pair answers
    # `state-sync: User-disabled` with both members holding the switch on.
    "no_live_redundant_peer": "No live redundant peer",
    # Vendor: "Enable HA Pair to activate HA pair functionality", Help 11.2 p.801, under
    # `Device > High Availability > General`, HA Pair Settings - Setup.
    "ha_enabled": "HA pair enabled",
    # OURS, and it is the column that tells "nobody looked" from "we looked and it was off".
    # The vendor has no word because it is a fact about this assessment, not about the firewall.
    "ha_config_collected": "HA configuration collected",
    # PAN-HAP-002's assertion, and THE HEADING MUST NOT BE THE VENDOR'S WORD HERE. The vendor's
    # field is "Encryption Enabled - Enable encryption after exporting the HA key from the HA
    # peer and importing it onto this firewall" (Help 11.2, HA Communications), and that switch
    # DOES NOT MEAN THE LINK IS ENCRYPTED: `validate full` refuses the commit without an
    # imported key, measured as job 535. This column is the VERDICT over the switch, the
    # imported key and the runtime confirmation, so it is named as the verdict. A heading reading
    # "Encryption enabled" would let a reader take a `No` for the switch's own value.
    "ha1_control_link_not_encrypted": "HA1 control link not encrypted",
    # OURS: a classification this layer invents over the port the link rides. The device offers
    # no such value set, which is why stage 5 could not record it as `measured`.
    "ha1_control_link_exposure": "Control link exposure",
    # PAN-HAP-003's assertion. OURS - the control is a DISJUNCTION over two vendor fields in two
    # different subtrees ("Backup Peer HA1 IP Address", Help 11.2 p.802, and "Heartbeat Backup",
    # p.803, which is under Election Settings and not under HA Communications at all), so no one
    # vendor word names it.
    "no_independent_second_keepalive_path": "No second keepalive path",
    # PAN-HAP-004's assertion. OURS, and deliberately about the GROUPS rather than the switches:
    # the vendor's own "Link Monitoring - Enabled" reads `yes` on an appliance holding no
    # monitoring node at all, so a heading naming the switch would name the thing this control
    # exists NOT to test.
    "ha_monitors_nothing": "HA monitoring watches nothing",
}

PANORAMA_REGISTRATION_LABELS = {
    # PAN-HAP-005's BASELINE assertion - the hardening half, at `low`. OURS: the three firewall
    # switches it folds in are the vendor's "Secure Client Communication" and "Check Server
    # Identity" (Help 11.2 p.710-711), and the verdict over them has no vendor word. Named as
    # the verdict because even all three on the hardened side does not make the channel
    # authenticated - the station may still accept the certificate every appliance of this make
    # ships with, and that switch is on Panorama.
    "management_channel_not_hardened": "Management channel not hardened",
    # OURS, and the honest heading is the one that says it was ASSUMED. The answer lives on the
    # management appliance's own `deviceconfig/high-availability`, which `rules.md` puts out of
    # assessment scope, so nothing collects it and the column holds its default `true` on every
    # row. A heading reading "Management estate is a pair" would state as measured the one thing
    # on this tab that was never read.
    "management_estate_is_a_pair": "Management estate assumed a pair",
    # Vendor: "Panorama Servers - Enter the IP address or FQDN of the Panorama server. If
    # Panorama is in a high availability (HA) configuration, in the second Panorama Servers
    # field, enter the IP address or FQDN of the secondary Panorama server", Help 11.2 p.709.
    # That sentence is also the whole of stage 5's narrowing: the vendor conditions the second
    # slot on the management estate being a pair, which is why the applicability column above
    # exists.
    "panorama_server_secondary": "Secondary Panorama server",
}
