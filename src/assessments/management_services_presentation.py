"""Headings, readers and provenance cells for the `management-services` domain's eight tabs.

Stage 9 of `management-services`, 2026-11-03 - run 28 of 28, and the run that empties
`AWAITING_PRESENTATION`. THIRTEEN controls on the roster, TWELVE in the catalog (PAN-MGT-005 was
dropped by a standing ruling of 2026-08-31 and its number is retired), EIGHT models, TEN stage 5
subjects, and SIX findings tabs that already existed - more than any other domain has inherited.
Two tabs are new here: `management-addressing` for PAN-MGT-004 and `operational-mode` for
PAN-MGT-012, whose models were minted by this domain's own stage 7/8 and had never been queried
from this repository.

EVERY HEADING AND BOTH TAB TITLES BELOW ARE PROPOSALS (P399), sourced to the vendor's own Help
where the vendor has a word and said to be OURS where it does not. `objects.py` sets the form:
"EVERY HEADING BELOW IS A PROPOSAL ... Jason takes the heading pass once across many domains."

------------------------------------------------------------------------------------------------
THE RAW-HEADING CENSUS, measured on built rows with THE WHOLE CATALOG SEEDED (217 controls),
because `setting_columns` derives a column per clause field of the controls PRESENT in the build -
so a shared tab's denominator is whatever was seeded, and the 12-control measurement of the same
tabs reports 6 instead of 14.

    tab                             headings   RAW before   RAW after   whose columns
    interface-management-profiles       16          1            0       PAN-MGT-013
    login-banner                        15          2            0       PAN-MGT-007, -008
    update-server                        14          1            0       PAN-MGT-009
    management-crypto                    23         10            0       3 ours, 7 not
    logging-settings                     27          0            0       run 26 labeled them
    management-interfaces                18          0            0       `user-id` labeled them
    ------------------------------------------------------------------------------------
                                        113         14            0

FOURTEEN, which is the count the dispatch brief predicted and which I re-measured rather than
inherited. SEVEN of the fourteen are NOT this domain's columns - `certificate_trust` belongs to
PAN-CRT-006 (`certificates`) and six belong to the five PAN-MCR controls (`mgmt-crypto`) - and
they are labeled here anyway, on run 26's precedent: labeling a column changes nothing about its
control, and a 23-column tab with ten bare Django field names is worse than one with 23 labeled.
Each owning domain inherits the words and may replace them. The brief said "4 yours and 6 not" for
the crypto tab; measured, it is 3 ours (PAN-MGT-010) and 7 not (6 PAN-MCR + 1 PAN-CRT-006).

`Management SSH and TLS` WAS THE OLDEST UNLABELLED TAB IN THE WORKBOOK and its own stage 9 run
could not label it. `sheets/management_crypto.py`'s docstring records three things it PROPOSED and
did not write - a bound-profile column, a `provenance_cell`, and these headings - and says why:
"NOT WRITTEN, because this spec also serves PAN-MGT-010, whose domain has not had its stage 9 -
`PAN-MGT` is still in `AWAITING_PRESENTATION` - and a Provenance cell is shared by both halves of
the tab." This run is what unblocks that, so two of its three proposals are implemented here.

------------------------------------------------------------------------------------------------
THE `choices` RULE, ANSWERED PER FIELD AND PER MODEL rather than once per tab, over the sixteen
clause fields of the eight models. A field WITH `choices` needs a reader calling
`get_<field>_display()` or the cell prints the stored key to a customer (P457); a reader CALLING
that method on a field WITHOUT `choices` raises `AttributeError` at TEMPLATE RENDER, past
`django check` and past all three cross-domain gates (P462).

    THREE carry `choices`, so a display reader is MANDATORY:
        plane                   ManagementInterface          already a subject column, and that
                                                             column already calls get_plane_display()
        unbound_exposure_class  InterfaceManagementProfile    reader written here. It was printing
                                                             `unencrypted_administrative_login` to
                                                             a customer under a raw heading.
        exposure_posture        ManagementPlaneAddressing     reader written here, new tab
      AND A FOURTH NOBODY HAD COUNTED, because it is another domain's column on a shared tab:
        certificate_trust       ManagementTlsBinding          PAN-CRT-006's. `choices=True`,
                                                             declared derived, and raw - so it was
                                                             printing a stored key too. Reader
                                                             written here.

    NINE carry none, so a display reader is FATAL and none is written:
        is_management_surface, text, acknowledgement_required, verify_identity, profile_name,
        floor_below_minimum, log_on_high_dp_load, approved_cryptography_mode, operational_mode

    FOUR ARE NOT MODEL FIELDS AT ALL, and they are not one case but TWO:
        service_enabled   ManagementInterface          `FieldDoesNotExist` AND no attribute, so
        exposure          ManagementInterface          `tested_fields` RAISES without a reader -
        binding_count     InterfaceManagementProfile   the reader is the only state in which the
                                                       tab exists. All three already have one.
        min_version       ManagementTlsBinding         a PROPERTY. `hasattr` is true, so
                                                       `tested_fields` resolves it `stored=False`
                                                       and no reader is needed or written. The
                                                       brief called this the one with no reader and
                                                       no subject column, which is right, and the
                                                       reason it works is that it is a property
                                                       rather than a compiler-only name.

ONE READER IS WRITTEN ON A FIELD WITH NO `choices`, DELIBERATELY, AND IT DOES NOT CALL THE DISPLAY
METHOD. `operational_mode` is a `CharField(blank=True)` whose EMPTY VALUE MEANS THE READ WAS NEVER
TAKEN - the normalizer says so in terms, and that is a different state from any mode a device can
report. `display_value` has exactly three answers and renders it `(empty)`, which reads as "the
appliance answered with nothing". `OPERATIONAL_MODE_READ` says "no operational read was taken"
instead. The fatal half of the `choices` rule is specifically about calling
`get_<field>_display()`; a reader returning a plain string is safe, which `BINDING_COUNT` in
`objects.py` has shipped on a no-choices field since PAN-MGT-013 shipped.

------------------------------------------------------------------------------------------------
THE PROVENANCE CELL, measured on BUILT ROWS, PER TAB AND PER CONTROL - because `build_rows` hands
the cell the clause fields of the ROW'S OWN control, not the tab's whole set, so a shared tab's
distinct answers appear across rows and never meet in one cell.

    tab / control                     DEFAULT cell            decision
    login-banner / -007, -008         "Local" / "Not conf..." KEEP THE DEFAULT. Both clause
                                                              fields are stored, `DERIVED_FIELDS`
                                                              is EMPTY, and both carry a real
                                                              FieldProvenance row. This is the one
                                                              tab in the pipeline where the
                                                              default was already honest, and a
                                                              cell reproducing it would be noise.
    update-server / -009              the recorded row        KEEP THE DEFAULT, same reason:
                                                              `verify_identity` is stored, not
                                                              derived, and has its own row.
    interface-management-profiles     the recorded row        KEEP THE DEFAULT. `binding_count`
      / -013                                                  exists ONLY through a reader, which
                                                              is the one case where branching is
                                                              worse than doing nothing: a
                                                              sheet-level cell cannot see the
                                                              sheet's readers, so `provenance_of`
                                                              answers nothing for it, while the
                                                              default sends it to
                                                              `remediation_accessor` and reaches
                                                              this model's `__entry__` row - which
                                                              it HAS (`ENTRY_FIELD = "__entry__"`).
    management-interfaces             the recorded row        KEEP THE DEFAULT, same reason:
      / -001, -002, -003, -006                                `service_enabled` and `exposure` are
                                                              reader-only, and the model carries
                                                              `__entry__` rows.
    logging-settings / -011           "PAN-OS default"        KEEP WHAT `logging` WROTE. That run
                                                              measured PAN-MGT-011's row at
                                                              "PAN-OS default" under both its cell
                                                              and the default, and both are right:
                                                              the key was ABSENT on all three
                                                              appliances and the normalizer records
                                                              an absent key as a vendor implicit.
    management-addressing / -004      "Derived"               WRITE A CELL. The single clause field
                                                              `exposure_posture` is derived with no
                                                              row and this model has NO `__entry__`
                                                              row, so the walk reaches nothing and
                                                              the cell falls back to the mandatory
                                                              reader's own prose. "Derived" is true
                                                              of the verdict and is not a location,
                                                              while the verdict's three INPUTS each
                                                              carry a real row. Measured: the cell
                                                              tells the three appliances apart -
                                                              "PAN-OS default | Not configured",
                                                              "PAN-OS default | Local",
                                                              "Local | Not configured" - where the
                                                              default said "Derived" on all three.
                                                              See `addressing_provenance_cell`.
    operational-mode / -012           "Not recorded"          WRITE A CELL. Both clause fields are
                                                              derived and this model carries NO
                                                              FieldProvenance row of any kind, on
                                                              purpose - `management_plane.py` passes
                                                              `provenance=()` and explains that
                                                              `classify_prov_type` would label a
                                                              RUNTIME reading `local`, "defined on
                                                              this device", which is the one thing
                                                              it is not.
    management-crypto / -010 and      "Not recorded" on       WRITE A CELL, which that tab's own
      PAN-MCR-001..005, PAN-CRT-006   the derived verdicts    stage 9 run proposed and could not
                                                              write. See `crypto_provenance_cell`.

THE VOCABULARY HAS NO MEMBER FOR "READ FROM AN OPERATIONAL COMMAND", which is why the
`operational-mode` tab's cell has to print the repository's own word for something it is not.
`FieldProvenance.ProvenanceType` has ten members and all ten are about where a CONFIGURATION value
came from. The model declares both runtime columns in `DERIVED_FIELDS` - the convention
`LoggingSettings` set for its two runtime columns - so `provenance_of` synthesises a DERIVED row
and the cell prints "Derived", meaning "we computed it", over a value the appliance reported
verbatim. It is the honest answer available rather than the honest answer; recorded in this run's
stage 9 artifact and in `consumer-repo-notes.md`.
"""
from __future__ import annotations

from assessments.artifacts.sheets import findings as findings_sheet
from assessments.artifacts.layout import NONE, ha_role

DERIVED = findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label


def _display_reader(field, *, provenance=DERIVED):
    """A reader printing a `choices` field's ENGLISH LABEL rather than its stored key.

    `display_value` is choices-unaware - the cell goes `read_value` -> `getattr` ->
    `display_value`, whose value branch ends in `str(value)`, and `get_<field>_display()` is
    called NOWHERE in the sheets layer - so a `choices` field prints the stored key to a customer
    without one of these (P457).

    `provenance` is set deliberately because that string is what the Provenance cell PRINTS where
    the walk finds nothing: a reader's field goes to `remediation_accessor`, which sets `row=None`
    the moment `stored_by_field` says False and returns the object's `__entry__` row, and with no
    `__entry__` row the cell falls back to this prose. Every field these are written for is
    declared in its model's `DERIVED_FIELDS`, so the reader costs nothing - there is no
    `FieldProvenance` row for `stored=False` to discard.
    """
    return findings_sheet.ValueReader(
        read=lambda subject, _f=field: getattr(subject, f"get_{_f}_display")(),
        provenance=provenance,
    )


# --------------------------------------------------------------------------- the six inherited tabs

#: PAN-MGT-007 and PAN-MGT-008. Both headings are the VENDOR'S OWN WORDS from the screen that
#: carries both settings: PAN-OS Web Interface Help 11.2 p.701, `Device > Setup > Management` ->
#: General Settings - "Login Banner Enter text (up to 3,200 characters) to display on the web
#: interface login page below the Name and Password fields." and "Force Admins to Acknowledge
#: Login Banner Select this option to display and force administrators to select I Accept and
#: Acknowledge the Statement Below".
#:
#: AND THE GROUP THEY ARE IN IS NOT THE ONE ITS NAME SUGGESTS, which is already recorded in
#: `reference/known-vendor-contradictions.md` under "`Banners and Messages` does not hold the login
#: banner" - the group literally called `Banners and Messages` carries the Message of the Day, and
#: both of these are in `General Settings`. The rail item's `where` says General Settings for that
#: reason.
LOGIN_BANNER_SETTING_LABELS = {
    "text": "Login Banner",
    "acknowledgement_required": "Force Admins to Acknowledge Login Banner",
}

#: PAN-MGT-009. The vendor's own words, and NOT from the screen the config node suggests: the leaf
#: is `deviceconfig/system/server-verification` but the setting is on
#: `Device > Setup > Services` -> Global Services Settings, Help 11.2 p.749 - "Verify Update Server
#: Identity If you enable this option, the firewall or Panorama will verify that the server from
#: which the software or content package is download has an SSL certificate signed by a trusted
#: authority."
UPDATE_SERVER_SETTING_LABELS = {
    "verify_identity": "Verify Update Server Identity",
}

#: PAN-MGT-013. THE HEADING IS OURS AND THE VENDOR HAS NO WORD FOR IT, which was established by
#: search rather than assumed: `not assigned to any interface`, `unused`+`Interface Management
#: profile`, `not attached to an interface`, `unattached`, `no interface` and `orphaned` each
#: return "SECTIONS MATCHING: none / nothing in: help, help-11-1, help-12-2, api, guide,
#: networking, url, threat, dns, gp, cli <- a complete count, so this is silence". An unbound
#: interface management profile is this assessment's concept, not the vendor's.
#:
#: HEADED AS THE COUNTERFACTUAL IT IS. The column does not say what the profile does - it is bound
#: to nothing, so it does nothing - it says what ATTACHING it would permit in one action, which is
#: the whole of why an unused definition is worth reporting. The vendor's own partition of the
#: eleven services is `Administrative Management Services` and `Network Services` (Help 11.2
#: p.661), and the three classes read that partition the other way up.
INTERFACE_MGMT_PROFILE_SETTING_LABELS = {
    "unbound_exposure_class": "What attaching this profile would permit",
}

#: ONE READER, MANDATORY AND FREE. `unbound_exposure_class` carries `choices` and is declared in
#: `InterfaceManagementProfile.DERIVED_FIELDS`, so the label costs nothing and its absence cost a
#: customer the stored key: measured before this reader, the firing cell on `oep-mgt6-p01` read
#: `unencrypted_administrative_login` under the heading `unbound_exposure_class`.
INTERFACE_MGMT_PROFILE_READERS = {
    "unbound_exposure_class": _display_reader("unbound_exposure_class"),
}

#: The ten raw headings on `Management SSH and TLS`, which is not this domain's tab and carries
#: seven columns that are not this domain's controls'. Vendor words where the vendor has them.
#:
#: THE SSH ALGORITHM NAMES ARE THE VENDOR'S, from `Device > Certificate Management > SSH Service
#: Profile`, Help 11.2 p.904 - "Ciphers Select the cipher algorithms your server will support for
#: SSH session encryption. KEX Select the key exchange algorithms your server will support during
#: an SSH session. MAC Select the message authentication code algorithms your server will support
#: during an SSH session. Hostkey Select a host key type and key length". The three
#: `*_below_preferred` columns are VERDICTS over those lists rather than the lists themselves, so
#: each heading names the vendor's noun and says what the verdict is about it; the lists are on the
#: configuration page.
#:
#: `SSL/TLS Service Profile` IS THE VENDOR'S LABEL FOR THE BINDING, Help 11.2 p.701 - "SSL/TLS
#: Service Profile Assign an existing SSL/TLS service profile or create a new one to specify a
#: certificate and the SSL/TLS protocol settings allowed on the management interface". It heads
#: `profile_name`, which is PAN-MGT-010's clause field over `ManagementTlsBinding`.
#:
#: FOUR HEADINGS ARE OURS BECAUSE THEY NAME A VERDICT THE VENDOR DOES NOT COMPUTE:
#: `floor_below_minimum`, `rekey_interval_known`, and the three `*_below_preferred`. A verdict
#: about a vendor setting is not a vendor setting, and heading one in the vendor's words alone
#: would read as the setting itself.
#:
#: `rekey_interval_known` IS A COMPANION COLUMN ABOUT THE READING AND NOT ABOUT THE DEVICE, which
#: is why it is headed as a question rather than as a fact: it is the registered-predicate
#: convention (`management_ssh`'s compiler) that separates "no rekey interval is set" from "nobody
#: established what the absent key means", and those are the two states a single nullable integer
#: cannot tell apart.
MANAGEMENT_CRYPTO_SETTING_LABELS = {
    # PAN-MGT-010's, this domain's.
    "profile_name": "SSL/TLS Service Profile",
    "floor_below_minimum": "Protocol floor is below the required generation",
    "min_version": "Protocol floor in force",
    # PAN-CRT-006's, the `certificates` domain's.
    "certificate_trust": "Trust in the certificate presented",
    # PAN-MCR-001 to -005, the `mgmt-crypto` domain's.
    "ciphers_below_preferred": "Ciphers weaker than preferred are offered",
    "kex_below_preferred": "KEX algorithms weaker than preferred are offered",
    "macs_below_preferred": "MAC algorithms weaker than preferred are offered",
    "host_key_type": "Hostkey type",
    "rekey_interval_seconds": "Rekey interval (seconds)",
    "rekey_interval_known": "A rekey interval was established",
}

#: ONE READER ON THAT TAB, for the one column there that carries `choices`. `certificate_trust` is
#: PAN-CRT-006's and is declared in `ManagementTlsBinding.DERIVED_FIELDS`, so the reader is free,
#: and without it the cell prints the stored key.
#:
#: NO READER ON `profile_name`, `min_version` OR `floor_below_minimum`, and that is the rule rather
#: than an omission: none of the three carries `choices`, so `get_<field>_display()` does not exist
#: on them and a reader calling it would raise at template render.
def _min_version_read(subject) -> str:
    """The protocol floor in force, or why there is none to read.

    MEASURED on built rows: both PAN-MGT-010 findings in this estate are appliances that bind
    NOTHING, and the cell read `(empty)` - `display_value`'s answer for the empty string - which
    says "the bound configuration declares no floor" over a row where nothing is bound at all.
    Those are two different states and PAN-MGT-010'S OWN CALIBRATIONS DISTINGUISH THEM: `No
    transport-security configuration bound` and `Bound floor could not be resolved` are separate
    queries at the same severity, so a reader that cannot tell them apart loses a distinction the
    catalog already makes.

    `display_value` has exactly three answers - a value, `(none)` for NULL and `(empty)` for the
    empty string - and none of them can say "this branch does not exist on this subject", which is
    the contract's fourth finding. `layout.NONE`, the em dash, says exactly that and is wrong here
    for the opposite reason: the branch is not inapplicable, it is UNREACHED, and this row is the
    one the control is reporting.

    FREE: `min_version` is a PROPERTY reading through the bound profile, so `tested_fields` already
    resolves it `stored=False` and there is no `FieldProvenance` row for a reader to cost. It
    carries no `choices`, so this does NOT call `get_min_version_display()` - that call would raise
    `AttributeError` at template render (P462).
    """
    if not subject.profile_name:
        return "no configuration is bound, so no floor is in force"
    return subject.min_version or "bound, and no floor could be read from it"


MANAGEMENT_CRYPTO_READERS = {
    "certificate_trust": _display_reader("certificate_trust"),
    "min_version": findings_sheet.ValueReader(read=_min_version_read, provenance=DERIVED),
}

#: WHICH STORED KEY ANSWERS "WHERE DO I GO AND CHANGE THIS" for a derived verdict on the crypto
#: tab. Read by `crypto_provenance_cell`; each entry is the verdict's own INPUT on the SAME model,
#: named by the normaliser that computes it.
#:
#: THE TLS HALF HAS NO SUCH ENTRY AND THAT IS DELIBERATE. `floor_below_minimum` and `min_version`
#: are resolved from the BOUND PROFILE, which is another object, and
#: `normalization/management_tls.py` says in its own words that "Only the BINDING has provenance.
#: The resolved values live on another object and carry no @ptpl of their own, so a provenance line
#: under them would be an invention." So those two fall back to the binding's own `profile_name`
#: row, which is the actionable location either way: an empty binding is fixed by binding a
#: profile and a bound one by editing the profile it names.
CRYPTO_VERDICT_INPUTS = {
    "ciphers_below_preferred": ("ciphers",),
    "kex_below_preferred": ("kex",),
    "macs_below_preferred": ("macs",),
    "floor_below_minimum": ("profile_name",),
    "min_version": ("profile_name",),
    "certificate_trust": ("profile_name",),
}


def crypto_provenance_cell(subject, provenance_of, fields) -> str:
    """What is RECORDED about each of the row's clause fields, reaching the verdict's own INPUT.

    WRITTEN HERE AND NOT ON THAT TAB'S OWN SPEC because that tab's stage 9 run could not write it:
    `sheets/management_crypto.py` proposes it in terms - "PROPOSED: `provenance_cell` on this spec,
    answering from the three list fields. NOT WRITTEN, because this spec also serves PAN-MGT-010,
    whose domain has not had its stage 9" - and this run is the one that serves PAN-MGT-010.

    THE PROBLEM IT FIXES, in that run's own measurement: the Provenance cell "reads 'Not recorded',
    whose documented meaning is the opposite of the truth". The walk is keyed on the ASSERTED field
    - `ciphers_below_preferred`, which is DERIVED, which `remediation_accessor` discards on purpose
    (`findings.py:563-564`) - and then falls through to an `__entry__` row NEITHER of this tab's
    models carries. Measured on built rows: `ManagementSshSettings` holds 27 `FieldProvenance` rows
    over nine fields and NOT ONE of them is `__entry__`; `ManagementTlsBinding` holds rows for
    `profile_name` alone.

    So `ciphers`, `kex` and `macs` each carry a real row saying `pan_os_default` or `local` while
    the cell above them said nothing was recorded - which is the distinction that tab needs most,
    because it is what separates "bind a profile" from "edit the one you bound". That run measured
    the two PAN-MCR-001 rows as "cell-for-cell identical apart from Appliance, HA role and
    `host_key_type`" while needing opposite fixes.

    MEASURED LIMIT, AND IT IS THIS RUN'S AND NOT THAT TAB'S. This domain's stage 6 records no
    `deviceconfig/system/ssh` subject at all, so on the estate this cell was measured against every
    SSH row is the UNCOLLECTED state and its rows read `pan_os_default` or `not_configured`. The
    mechanism is measured; that the cell is right about a real device's SSH configuration is not,
    and the `mgmt-crypto` domain's own estate is where that belongs.

    Prints what was recorded and decides nothing, distinct answers in the order encountered.
    """
    labels = []
    for field, _stored in fields:
        row = provenance_of(field)
        if row is None or row.provenance_type == row.ProvenanceType.DERIVED:
            for source in CRYPTO_VERDICT_INPUTS.get(field, ()):
                candidate = provenance_of(source)
                if candidate is not None:
                    row = candidate
                    break
        label, _template = findings_sheet.provenance_cells(
            row, stored=True if row is not None else False)
        if label not in labels:
            labels.append(label)
    return "\n".join(labels) or "Not recorded"


# --------------------------------------------------------------------- management plane addressing

MANAGEMENT_ADDRESSING_TITLE = "Management Plane Addressing"

#: 27 characters, under `DeviceSettingSheet.title`'s silent 31-character truncation (Excel's cap on
#: a sheet name). Counted rather than eyeballed, because `probe.surface_for` prints the untruncated
#: title and so the tool and the workbook would disagree with the tool looking right.

MANAGEMENT_ADDRESSING_DESCRIPTION = (
    "How each firewall's management plane is addressed, and what that addressing exposes: whether "
    "the address is one an administrator chose or one a DHCP server handed out, what it is, and "
    "whether a default gateway routes the management port off its own segment. WHAT IS ASSESSED IS "
    "THE CONFIGURATION'S CONTRIBUTION TO EXPOSURE AND NOT REACHABILITY - a firewall holds nothing "
    "about who can actually reach its management address, so a private address with no default "
    "gateway is the preferred state here and is not a promise that the plane is unreachable. TWO "
    "NULLS WITH DIFFERENT MEANINGS SHARE THE ADDRESS COLUMN: a DHCP-addressed appliance stores no "
    "address and no gateway even when the read succeeded, which is why those cells name the "
    "allocation rather than printing a blank. NOTHING ON THIS TAB IS A CHANGE TO PROPOSE - a "
    "management address and the route to it are not remediation this assessment recommends; the "
    "columns exist so an assessor can go and look at the value."
)

#: APPLIANCE, then the three columns stage 5 marks `presented: true` that NO clause names. They are
#: SUBJECT columns rather than derived settings columns, and that is the whole of the decision:
#:
#: (1) they are the identity of the row in the sense that matters - an engineer reads the address
#:     and the gateway first, and `exposure_posture` is a verdict over them;
#: (2) declaring `field=` on each means `setting_columns` dedupes them, so no second column of the
#:     same name derives and the duplicate-header guard is not relied on;
#: (3) `get_allocation_mode_display()` comes FREE in a subject column, where a derived settings
#:     column would have needed a `value_reader` to avoid printing the stored key; and
#: (4) it is the remedy `device-services` established for the fourth provenance case - a field with
#:     a real `FieldProvenance` row on a model with no `__entry__` row - except that here the three
#:     fields WITH rows are the ones being moved, and the clause field that has none keeps its
#:     derived column.
#:
#: THE TWO ADDRESS CELLS BRANCH ON THE ALLOCATION MODE AND NOT ON "IS IT NULL", which is the rule
#: `globalprotect-gateway` established on its cookie lifetime: one column holding two nulls with
#: opposite meanings has to branch on the state the control already distinguishes, so that the
#: firing row never reads "not applicable" about the very thing it reports. Under DHCP the
#: configuration HOLDS no address - the null is the measured state, not an unread one - and under
#: static a null is a gap in the configuration. An em dash on the second would say "this branch
#: does not exist" about a static appliance that simply has no gateway, and that appliance is
#: exactly the one PAN-MGT-004 prefers.
MANAGEMENT_ADDRESSING_SUBJECT = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
)


def _address_cell(subject, _provenance_of):
    """The management address, or what the configuration holds instead of one."""
    if subject.management_ip_address:
        return subject.management_ip_address
    if subject.allocation_mode == subject.AllocationMode.DHCP_CLIENT:
        return "assigned by DHCP; the configuration holds no address"
    return "no address in the configuration"


def _gateway_cell(subject, _provenance_of):
    """The management port's default gateway, or what its absence means here.

    A NULL HAS TWO MEANINGS AND NEITHER IS "NOT APPLICABLE". On a statically addressed appliance no
    gateway means the management port is not routed off its own segment, which is this control's
    PREFERRED state and must not read as missing data. On a DHCP-addressed one the firewall stores
    no gateway and may still be routed, which is the trap stage 3 named: a reading that reported
    "no default route on the management port" there would report the preferred state about a device
    that has a default route.
    """
    if subject.static_default_gateway:
        return subject.static_default_gateway
    if subject.allocation_mode == subject.AllocationMode.DHCP_CLIENT:
        return "assigned by DHCP; the configuration holds no gateway"
    return "none configured, so the port is not routed off its segment"


#: The vendor's own labels, and the two screens spell one of them differently. `Device > Setup >
#: Interfaces` is the screen that carries all three (Help 11.2 p.757-759): "Type (MGT interface
#: only) For IPv4, for Type, select one: Static ... DHCP Client", "IP Address (IPv4 Static) If you
#: chose IPv4 Static, assign an IPv4 address to the interface", "Default Gateway (IPv4) If you
#: assigned an IPv4 address to the interface, you must also assign an IPv4 address to the default
#: gateway". `Device > Setup > Management` calls the first one `Management Interface IP Type`
#: instead (p.701, under `Accept DHCP server-provided Hostname`: "Applies only when the Management
#: Interface IP Type is DHCP Client"), and that longer spelling is the one used here because `Type`
#: alone heads nothing a reader can place.
ADDRESSING_IDENTITY = (
    ("Management Interface IP Type", 24, False,
     lambda s, _p: s.get_allocation_mode_display(), "allocation_mode"),
    ("IP Address", 26, True, _address_cell, "management_ip_address"),
    ("Default Gateway", 26, True, _gateway_cell, "static_default_gateway"),
)

MANAGEMENT_ADDRESSING_SUBJECT = MANAGEMENT_ADDRESSING_SUBJECT + ADDRESSING_IDENTITY

#: PAN-MGT-004's one clause field, and the heading is OURS: the vendor computes no such verdict and
#: names no such setting. Headed as what it is about - the exposure the ADDRESSING creates - rather
#: than as a statement that the plane is exposed, which the firewall holds nothing about.
MANAGEMENT_ADDRESSING_SETTING_LABELS = {
    "exposure_posture": "Exposure the addressing creates",
}

def _exposure_posture_read(subject) -> str:
    """The posture class, saying so where it is the FIRING DEFAULT rather than a classification.

    MANDATORY AND FREE as a labeling reader: `exposure_posture` is
    `CharField(choices=POSTURE_CHOICES)` and is declared in
    `ManagementPlaneAddressing.DERIVED_FIELDS`, so without a reader the firing cell prints
    `routable_address` to a customer and the reader costs no provenance row.

    AND IT BRANCHES, BECAUSE THIS COLUMN HOLDS TWO STATES WITH OPPOSITE MEANINGS UNDER ONE WORD -
    which is the shape `globalprotect-gateway` established on its cookie lifetime and the shape the
    contract's fourth finding names. MEASURED on a built row before this branch existed:
    `pan-fw-1085` has NO addressing subject in stage 6 at all, so its `management_ip_address` is
    null, `address_is_globally_routable("")` answers True - the default that FIRES - and the posture
    resolves to `routable_address`. The row therefore read

        IP Address  "no address in the configuration"
        Exposure    "On a globally routable address"        at CRITICAL

    which is a row arguing against its own finding: the cell asserted a globally routable address
    about an appliance whose configuration holds none. The FIRING DIRECTION is right and is stage
    5's declared intent - "true is the default and the firing side, so an unparsed, absent or
    unrecomputed address reports at this control's top grade rather than passing" - and the WORD
    was wrong.

    THE BRANCH IS ON THE STATE THE MODEL ALREADY DISTINGUISHES and not on "is it null", so the
    firing row never reads as "not applicable" about the very thing it reports: a static row with no
    stored address keeps firing and says that the class is the default rather than a reading. The
    four posture classes have no member for "no address was recorded", which is recorded in this
    run's stage 9 artifact as a vocabulary gap rather than papered over with an em dash - an em dash
    would say the branch does not exist, and every appliance has a management address.
    """
    label = subject.get_exposure_posture_display()
    if (subject.allocation_mode == subject.AllocationMode.STATIC
            and not subject.management_ip_address):
        return (f"{label} - but no address is recorded, so this is the firing default rather "
                f"than a classification of one")
    return label


MANAGEMENT_ADDRESSING_READERS = {
    "exposure_posture": findings_sheet.ValueReader(
        read=_exposure_posture_read, provenance=DERIVED),
}


def addressing_provenance_cell(subject, provenance_of, fields) -> str:
    """Where the addressing this verdict is computed FROM was recorded.

    MEASURED, not chosen, AND THE FIRST VERSION OF THIS PARAGRAPH WAS WRONG about what the default
    says - it predicted "Not recorded" and the build answered "Derived". The correction is the
    useful part: `exposure_posture` is PAN-MGT-004's only clause field, it is declared derived, it
    carries no `FieldProvenance` row, and `ManagementPlaneAddressing` carries NO `__entry__` row
    either - but it also has a mandatory labeling READER, so `build_rows` takes the reader arm
    (`findings.py:743-754`), `remediation_accessor` returns no row, and the cell falls back to
    `reader.provenance`, the reader's own prose. Measured on built rows: the default prints
    "Derived" on all three rows, not "Not recorded". WITHOUT the reader it would print
    "Not recorded"; the reader is not optional, so that state never ships.

    "Derived" is true of the verdict and is not a location, which is the case
    `remediation_accessor`'s own rule says the OBJECT has to answer: the three leaves the verdict is
    computed from
    - `allocation_mode`, `management_ip_address` and `static_default_gateway` - each carry a real
    row on every appliance in this estate. So this reads those, which is where an assessor goes to
    look at the value, and prints the distinct recorded answers.

    IT READS FIELDS IT WAS NOT HANDED, which is allowed and is the generalisation of the remedy
    `logging` wrote: `provenance_of` is a plain lookup into the row index `build_rows` bulk-loaded,
    so asking it for a field outside `fields` costs no query and invents nothing. The three are the
    verdict's own inputs rather than an arbitrary selection.

    IT DOES NOT PRINT "Derived" BESIDE THEM. The verdict having been computed by us is true and is
    not a location, and `remediation_accessor`'s own rule is that DERIVED counts as no answer
    because it is the case the object has to answer.
    """
    labels = []
    for field in ("allocation_mode", "management_ip_address", "static_default_gateway"):
        row = provenance_of(field)
        if row is None:
            continue
        label, _template = findings_sheet.provenance_cells(row, stored=True)
        if label not in labels:
            labels.append(label)
    if labels:
        return "\n".join(labels)
    # Nothing recorded about any of the three. Fall back to what the handed fields say rather than
    # asserting a location, so the cell cannot claim more than the rows hold.
    for field, _stored in fields:
        label, _template = findings_sheet.provenance_cells(provenance_of(field), stored=True)
        if label not in labels:
            labels.append(label)
    return "\n".join(labels) or "Not recorded"


# ------------------------------------------------------------------- appliance operational mode

OPERATIONAL_MODE_TITLE = "Cryptographic Operational Mode"

#: 30 characters, under the 31-character truncation. Counted.

OPERATIONAL_MODE_DESCRIPTION = (
    "The cryptographic mode each firewall reports itself to be running in, and whether that is an "
    "approved one. THIS IS NOT CONFIGURATION AND THERE IS NO NODE FOR IT AT ANY SCOPE: the value "
    "is read from `show system info`, the mode is set per appliance from maintenance mode, and "
    "nothing synchronises it between high-availability peers - so two peers can genuinely differ "
    "and neither row is a duplicate of the other. AN EMPTY MODE MEANS THE READ WAS NEVER TAKEN "
    "rather than that the appliance answered with nothing, and the two must not be read as one "
    "thing: `normal` is itself the NON-approved value, so an appliance nobody asked would look "
    "compliant if the unread state were stored as a mode. The vendor names no screen that displays "
    "this; it shows in the web interface status bar once an approved mode is in force."
)

#: PAN-MGT-012's two clause fields, both headings OURS - the vendor names no screen that displays
#: the mode and no label for it, established by search rather than assumed: `operational-mode`
#: returns "nothing in: help, help-11-1, help-12-2, guide, networking, threat, dns, gp <- a
#: complete count, so this is silence", matching only the CLI hierarchies and the API guide, and
#: `normal mode`, `mode of operation` and `current operational mode` each return "0 page(s) match,
#: which is all of them" across all three Web Interface Help editions. The vendor's one
#: web-interface placement is the status bar - PAN-OS Administrator's Guide 11.2 p.1307, "Change
#: the Operational Mode to FIPS-CC Mode": "FIPS-CC displays at all times in the status bar at the
#: bottom of the web interface" - which is chrome rather than a field on a screen.
#:
#: THE TWO COLUMNS ARE A PAIR AND THE PAIR IS THE POINT. A single boolean collapses "not in an
#: approved mode" and "nobody asked", and those need telling apart because FALSE is both the
#: firing side and the default. The mode column is what separates them: empty means no operational
#: read was taken, and any value means one was.
OPERATIONAL_MODE_SETTING_LABELS = {
    "approved_cryptography_mode": "Running an approved cryptographic mode",
    "operational_mode": "Mode the appliance reports",
}


#: THE ONE READER IN THIS MODULE ON A FIELD WITH NO `choices`, and it does not call a display
#: method - see this module's docstring. `display_value` has exactly three answers and renders the
#: empty string `(empty)`, which reads as "the appliance answered with nothing" over a row where no
#: operational read was taken at all. The normaliser's own words:
#: "EMPTY MEANS THE READ WAS NOT TAKEN and never that the field was absent from a reply that
#: arrived: the field cannot be absent, there being no xpath at which it could be missing".
#:
#: NOT AN EM DASH EITHER. `layout.NONE` says "this branch does not exist on this subject", and the
#: branch does exist here - every appliance has an operational mode. What is missing is the
#: reading, which is a different sentence and is this assessment's own state rather than the
#: device's.
#:
#: FREE: `operational_mode` is declared in `ApplianceOperationalMode.DERIVED_FIELDS` and this model
#: carries no `FieldProvenance` row of any kind, so there is no row for `stored=False` to discard.
OPERATIONAL_MODE_READERS = {
    "operational_mode": findings_sheet.ValueReader(
        read=lambda s: s.operational_mode or "no operational read was taken",
        provenance=DERIVED,
    ),
}


def operational_mode_provenance_cell(subject, provenance_of, fields) -> str:
    """What was recorded about each clause field - which on this model is DERIVED for both.

    MEASURED: `ApplianceOperationalMode` carries NO `FieldProvenance` row of any kind, on purpose,
    and both clause fields are declared derived. So `provenance_of` synthesises a DERIVED row for
    each, `remediation_accessor` discards it, the walk reaches an `__entry__` row this model does
    not have, and the DEFAULT cell reads "Not recorded" on every row of this tab. Measured on built
    rows before this cell was written.

    WRITTEN AS A BRANCH RATHER THAN AS THE CONSTANT "Derived", although both fields are derived
    today and the all-derived rule permits a constant: a clause field added to this model later
    would make a constant lie, and the two previous tabs that took the constant were the two the
    rule has since been wrong about.

    AND THE WORD IT PRINTS IS THE REPOSITORY'S AND NOT THE TRUTH ABOUT THIS VALUE.
    `FieldProvenance.ProvenanceType` has ten members and every one of them is about where a
    CONFIGURATION value came from; this value was reported by the appliance in answer to an
    operational command. The model declares both columns derived - the convention `LoggingSettings`
    set for its two runtime columns - so "Derived" is what is recorded and what this prints. The
    missing vocabulary member is recorded in this run's stage 9 artifact rather than papered over
    here, because inventing a word in a sheet would put it in one tab and leave the other nine
    runtime columns in the repository saying something else.
    """
    labels = []
    for field, _stored in fields:
        label, _template = findings_sheet.provenance_cells(provenance_of(field), stored=True)
        if label not in labels:
            labels.append(label)
    return "\n".join(labels) or "Not recorded"
