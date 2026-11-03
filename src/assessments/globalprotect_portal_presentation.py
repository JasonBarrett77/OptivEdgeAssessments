"""Readers, evidence cells and proposed headings for the three globalprotect-portal findings tabs.

`globalprotect-portal`, 2026-11-02. Three subjects, three grains, three tabs:

- `integrations.GlobalProtectPortal` - one named portal entry in one virtual system of one
  appliance. Four controls: PAN-GPP-001, -003, -004, -005.
- `integrations.GlobalProtectPortalClientAuthRow` - one row of one portal's client-authentication
  table, keyed by the endpoint CLASS it serves. PAN-GPP-002 alone.
- `integrations.GlobalProtectEnforcementPoint` - one virtual system as a verdict over its
  GlobalProtect objects as a whole. PAN-GPP-006.

WHY THREE AND NOT ONE, and the middle one is the interesting half. The portal and its
client-authentication rows are ONE PAN-OS dialog, so a reader could reasonably expect one tab -
and the grain is what refuses it. The control type's own comment in `models.py` states the
measurement: a portal can demand both factors of one endpoint class and neither of another, and
two rows of one portal in this estate sit at `high` and at no finding at all. A portal-grain tab
would have to pick one of those to print, and either choice reports the compliant sibling as the
fault or hides the real one. So the row is the grain a PAN-GPP-002 finding names, which is what
this domain's `AWAITING_PRESENTATION` comment predicted when it said the two "will want two pages
rather than one".

EVERY HEADING IN THIS MODULE IS A PROPOSAL (P399). Jason takes the heading pass once across many
domains; what is decided here is the column SET, which comes from the controls' own clauses.
EIGHT clause fields over three models and not one of them had a heading before today - there was
no sheet for any of these three control types to inherit a `setting_labels` entry from - so
without this module all eight would head a customer-facing column with a Django field name.

THE SOURCE FOR EVERY VENDOR WORD IS ONE RAIL GROUP. PAN-OS Web Interface Help 11.2,
`Network > GlobalProtect > Portals`, whose field tables are General (p.999-1001), Authentication
Configuration (p.1001-1003), Agent Authentication (p.1005-1007), Agent App (p.1012-1036) and
Clientless VPN (p.1037-1039). The section path is the corpus's own `within:` line and the Help's
own verbatim text - "GlobalProtect Portals General Tab • Network > GlobalProtect > Portals >
<portal-config> > General" - and it reads identically in ALL THREE indexed Help versions (11.1
p.985, 11.2 p.999, 12.2 p.1039), as does the Clientless VPN tab's own path (11.1 p.1024, 11.2
p.1037, 12.2 p.1077). The vendor's own list of the eight GlobalProtect screens is at 11.2 p.997.

WHERE THE VENDOR HAS NO WORD THIS SAYS SO. Four of the eight columns are verdicts this assessment
computes over two or more device leaves, and the vendor's screens hold no label at that position.
Each entry below says which it is.
"""
from __future__ import annotations

from .artifacts.sheets import findings as findings_sheet
from .artifacts.layout import NONE

DERIVED = findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label


# --------------------------------------------------------------------------------------------
# THE FOUR VALUE READERS, AND THE ONE THAT WAS REFUSED
#
# `display_value` IS CHOICES-UNAWARE, which is the measurement this section rests on and the
# opposite of what this run was told. Its three answers are a value, `(none)` and `(empty)`, and
# the value branch ends in `str(value)` - it never calls `get_<field>_display()`. So a CharField
# WITH `choices` prints the raw choice KEY to a customer unless a reader says otherwise.
# `objects.REFERENCE_REACH` records the same thing measured from the other side on 2026-11-02:
# "the cell printed the raw choice KEY - `named_by_a_rule`, `unreferenced`, `undetermined` - to a
# customer", and the configuration explorer's own pages for the same column already called the
# display method, so the two surfaces disagreed about what one column says.
#
# WHAT THAT WOULD HAVE PUT ON THESE TABS, read off the four fields' own choice lists: a column
# headed "Save User Credentials" reading `0`, `1`, `2`, `3` or `no_agent_configuration`; a column
# about what admits an endpoint reading `password_and_certificate`; and the clientless-VPN verdict
# reading `latent`. The `0` is the worst of them - it is the PASSING value of PAN-GPP-004 and it
# would read to a customer as a count, or as a failure, or as nothing at all.
#
# AND IT COSTS NOTHING ON ANY OF THE FOUR, measured rather than assumed. `tested_fields` reports a
# reader's field `stored=False`, `remediation_accessor` then skips `provenance_of(field)` and walks
# to the object's `__entry__` row, and `provenance_cells` answers DERIVED without reading one. The
# row that walk skips is the field's own `FieldProvenance` row - and for all four of these there is
# no such row to lose: every one is in its model's `DERIVED_FIELDS`, and
# `normalization/globalprotect.py` writes provenance for `ssl_tls_service_profile`,
# `certificate_profile`, `custom_login_page`, `clientless_vpn_min_version`,
# `clientless_vpn_max_version`, `os`, `authentication_profile` and
# `user_credential_or_client_cert_required` and for nothing else. None of the four is in that list.
# This is the free case `url-filtering` established and `decryption-policy` corrected the
# orchestrator about: free on a `DERIVED_FIELDS` column, paid on a measured payload key.

UPGRADE_POSTURE_READER = findings_sheet.ValueReader(
    read=lambda portal: portal.get_upgrade_posture_display(),
    provenance=DERIVED,
)
SAVED_CREDENTIALS_READER = findings_sheet.ValueReader(
    read=lambda portal: portal.get_saved_credentials_posture_display(),
    provenance=DERIVED,
)
ADMISSION_DEMAND_READER = findings_sheet.ValueReader(
    read=lambda row: row.get_admission_demand_display(),
    provenance=DERIVED,
)
CLIENTLESS_FEATURE_STATE_READER = findings_sheet.ValueReader(
    read=lambda point: point.get_clientless_vpn_feature_state_display(),
    provenance=DERIVED,
)

#: NO `members=` ON ANY OF THE FOUR. A reader with `members` sends `member_provenance_index` to
#: build a provenance index over CHILD rows, and all four of these values are computed on the
#: subject row itself from keys in the same payload - there are no child rows to walk. The
#: client-auth row IS a child of the portal, but it is a subject of its own with a tab of its own,
#: not a member another row reads through.

PORTAL_VALUE_READERS = {
    "upgrade_posture": UPGRADE_POSTURE_READER,
    "saved_credentials_posture": SAVED_CREDENTIALS_READER,
}
CLIENT_AUTH_VALUE_READERS = {
    "admission_demand": ADMISSION_DEMAND_READER,
}
ENFORCEMENT_POINT_VALUE_READERS = {
    "clientless_vpn_feature_state": CLIENTLESS_FEATURE_STATE_READER,
}

# `custom_login_page` IS THE ONE READER THIS RUN REFUSED, and the reason is the rule
# `file-data-filtering` wrote for its two graded action columns: where whether a key was ABSENT is
# what the control is about, refuse the reader and let the marked companion column say it.
#
# IT IS THE ONLY ONE OF THE EIGHT THAT IS STORED. It is not in `GlobalProtectPortal.DERIVED_FIELDS`
# and the normalizer writes it a `FieldProvenance` row by name, so a reader here would cost exactly
# that row - and that row is the only thing on the tab that separates a portal whose
# `custom-login-page` key was read from one whose key the collector never carried. PAN-GPP-005's
# third shipped query is literally about that distinction: stage 5 records that the restatement
# clauses `custom_login_page is not Disable`, that SQL answers a comparison against a NULL by not
# matching, and that the key is MANDATORY on a committed portal - so a null is never a device
# state, it is always a reading nobody took, and `mandatory_keys_present` is the column a control
# clauses on instead.
#
# AND IT NEEDS NO READER ON ITS OWN MERITS, which is the half that makes this an easy call rather
# than a trade. The field has no `choices`, so there is no display method to reach - and the tokens
# it holds are THE VENDOR'S OWN WORDS, not Django's. Help 11.2 p.1001 verbatim: "Portal Login Page
# (Optional) Choose a custom login page for user access to the portal. You can select the
# factory-default page or Import a custom page. The default is None. To prevent access to this page
# from a web browser, Disable this page." So `factory-default` and `Disable` are the two words that
# screen offers, and the cell already reads in them. This is the opposite of `url-filtering`'s
# `credential_detection_mode`, where the stored token `ip-user` is the device's internal spelling
# and the vendor's screen says something else.


# --------------------------------------------------------------------------------------------
# PROPOSED HEADINGS - the five derived setting columns of the GlobalProtect Portals tab, every
# clause field of the four controls that report there, in `tested_fields` order.
#
# CHECKED FOR COLLISIONS. Nothing in either repository checks that a tab's headings are unique and
# a duplicate header is a workbook Excel refuses to open - xlsxwriter drops the table with a
# warning and leaves a sheet of stray cells. The near miss on this tab is "Portal Login Page"
# against the subject column "Object", which is the portal's own name, and the two read as
# different things; nothing else is close.
PORTAL_SETTING_LABELS = {
    # OURS, AND A SAFETY DECISION RATHER THAN A WORDING ONE. The vendor's word for the thing is
    # "SSL/TLS Service Profile" (Help 11.2 p.1001, Authentication tab: "Select an existing SSL/TLS
    # Service profile. The profile specifies a certificate and the allowed protocols for securing
    # traffic on the management interface.") - but this column is not that profile, it is a
    # BOOLEAN saying the binding is missing, and TRUE is the firing side.
    #
    # So the heading is phrased so that "Yes" is plainly the problem. Headed with the vendor's
    # bare noun it would read the other way round: a cell saying "No" under "SSL/TLS Service
    # Profile" would look like the answer to "is one bound?", which is the opposite of what the
    # store holds, and the most reassuring cell on the row would be the finding. That is the
    # failure Jason caught once already and the one this stage exists to catch.
    #
    # THE PROFILE'S NAME IS BESIDE IT as a subject column, because this cell cannot say what is
    # bound - only that nothing is. See `PORTAL_SUBJECT`'s TLS profile column.
    "tls_profile_binding_missing": "No SSL/TLS service profile is bound",
    # VENDOR'S OWN WORD, Help 11.2 p.1016 verbatim: "Allow User to Upgrade GlobalProtect App
    # Specifies whether end users can upgrade the GlobalProtect app software and, if they can,
    # whether they can choose when to upgrade: • Disallow-Prevent users from upgrading the app
    # software. • Allow Manually-Allow users to manually check for and initiate upgrades by
    # selecting Check Version in the GlobalProtect app. • Allow with Prompt (default)-Prompt users
    # when a new version is a..." - the Agent App tab, at
    # `Network > GlobalProtect > Portals > <portal-config> > Agent > <agent-config> > App`.
    #
    # KEPT AT THE VENDOR'S FULL LENGTH rather than shortened to "Upgrade policy". The screen's
    # label is what an assessor will search the interface for, and the five device-facing values
    # the column can hold are the vendor's own five labels, so a shortened heading would be the
    # only word on the row that is not the vendor's.
    #
    # THREE OF ITS EIGHT VALUES ARE OURS AND THE VENDOR HAS NO LABEL FOR THEM -
    # `no_agent_configuration`, `not_set` and `several_members` - which is why this column needs
    # its reader: the model's own choice labels spell all three out as sentences, and the raw keys
    # would not.
    "upgrade_posture": "Allow User to Upgrade GlobalProtect App",
    # VENDOR'S OWN WORD, Help 11.2 p.1006 verbatim: "Save User Credentials Select Yes to save the
    # username and password on the app or select No to force the users to provide the password -
    # either transparently via the endpoint or by manually entering one - each time they connect.
    # Select Save Username Only to save only the username each time a user connects. Select Only
    # with User Fingerprint to allow biometric sign-in." The Agent Authentication tab.
    #
    # THE COLUMN THAT MOST NEEDED ITS READER. The store holds the device's own `0`, `1`, `2`, `3`,
    # and `0` - the PASSING value - would print to a customer under this heading as a count or as a
    # blank. The model's choice labels are the vendor's four words, which is what the cell now
    # reads.
    "saved_credentials_posture": "Save User Credentials",
    # VENDOR'S OWN WORD, Help 11.2 p.1001, quoted in full in the refused-reader note above. The
    # cell prints the device's own token and those tokens are this screen's own two words.
    #
    # "Portal Login Page" AND NOT "Login page disabled", although PAN-GPP-005's assertion is that
    # it is NOT `Disable`. The column holds four states, not two - a custom page, the
    # factory-default page, `None`, and `Disable` - and a boolean heading over a four-state column
    # would make three of them unreadable.
    "custom_login_page": "Portal Login Page",
    # OURS. The vendor has no word for it and no screen position either: it is a verdict over
    # whether the four keys PAN-OS refuses to commit a portal without - `portal-config` holding
    # `local-address`, `ssl-tls-service-profile`, `custom-login-page` and `custom-home-page` -
    # all arrived in the read.
    #
    # PHRASED SO THAT "No" IS PLAINLY THE PROBLEM. The column defaults FALSE and FALSE is the
    # firing side, so the heading is in the healthy direction and the firing cell reads "No" - the
    # mirror image of the polarity decision on `tls_profile_binding_missing` above, and for the
    # same reason.
    #
    # WHAT IT IS ACTUALLY FOR, which the heading cannot carry: it is the only column on this tab
    # that tells an ABSENT key from a key the collector never asked for. The model's own comment
    # says so - "an absent node and a path a collector never asked for arrive as the same nothing,
    # so no column can separate them unless the collector records that it ASKED" - and stage 8
    # parked PAN-GPP-005's coverage clause on this control for exactly that reason, visibly, with
    # the request for a coverage control filed. A reader meeting "No" here should read the Portal
    # Login Page cell beside it as unestablished rather than as a value.
    "mandatory_keys_present": "All four keys the device requires were read",
}

#: PROPOSED HEADING for the GlobalProtect Portal Authentication tab's one derived setting column -
#: PAN-GPP-002's single clause field.
CLIENT_AUTH_SETTING_LABELS = {
    # OURS, AND THE VENDOR HAS NO WORD AT THIS POSITION - measured rather than assumed. The
    # Authentication Configuration tab (Help 11.2 p.1003) holds the two leaves this is computed
    # from and labels them separately: "Allow Authentication with User Credentials OR Client
    # Certificate - If you select No, users must authenticate to the gateway using both user
    # credentials and client certificates. If you select Yes, users can authenticate to the
    # gateway using either user credentials or client certificates", and "Certificate Profile -
    # (Optional) Select the Certificate Profile the portal uses to match those client certificates
    # that come from user endpoints." There is no third label over the pair.
    #
    # ONE COLUMN AND NOT TWO, which is the model's measurement and not a presentation choice. The
    # vendor's own text above is why: `yes` on the switch means "a password OR a client certificate
    # will do", and where no certificate profile is bound there is no second factor for the OR to
    # reach - so the switch alone says nothing. The model carries the pair down onto the row for
    # that reason and `admission_demand` is the verdict over both.
    #
    # PHRASED AS A QUESTION ABOUT THE DEMAND rather than in either leaf's polarity, because all
    # four of its values are states a reader acts on differently and three of them fire. The cells
    # are the model's own choice sentences - "A password alone admits an endpoint", "Both a
    # password AND a client certificate are required" - so the heading is the short noun and the
    # CELL carries the meaning, which is only true because of the reader above.
    "admission_demand": "What this row demands before admitting an endpoint",
}

#: PROPOSED HEADINGS for the GlobalProtect Coverage tab's two derived setting columns - every
#: clause field of PAN-GPP-006, in `tested_fields` order: the applicability gate first, because it
#: is the baseline's first clause, and then the assertion.
ENFORCEMENT_POINT_SETTING_LABELS = {
    # OURS, AND AN APPLICABILITY GATE THAT READS "No" ON EVERY ROW THIS TAB HAS. The vendor has no
    # word for it: it is a verdict over the appliance's licence list, which lives at a different
    # rail address entirely (`Device > Licenses`) and in a different PAN-OS category.
    #
    # WHY IT IS A COLUMN AT ALL. PAN-GPP-006's baseline pins it to FALSE, so a vsys where it reads
    # "Yes" is OUT of the population and draws no row - and this cell is therefore the evidence
    # that the vsys assessed is one the control applies to. That is the same shape and the same
    # argument as the `Disabled` column on the decryption rules tab, which also reads one value on
    # every row it has.
    #
    # THE POLARITY IS THE DEVICE'S, not the healthy direction: TRUE means a populated licence list
    # carries no GlobalProtect feature, which SUPPRESSES. Stage 5 built the clause so that it
    # suppresses ONLY on a populated list, so "No" covers two states - licensed, and never asked -
    # and the licence columns beside it in the subject block say which. A reader meeting "No" here
    # should not read it as "licensed".
    "licence_excludes_globalprotect": "Licensing rules GlobalProtect out",
    # OURS, OVER THE VENDOR'S OWN FEATURE NAME. "Clientless VPN" is the vendor's word and its own
    # tab - `Network > GlobalProtect > Portals > <portal-config> > Clientless VPN`, verbatim in all
    # three indexed Help versions - and Help 11.2 p.1037 describes it: "You can now configure the
    # GlobalProtect portal to provide secure remote access to common enterprise web applications
    # that use HTML, HTML5, and JavaScript technologies. Users have the advantage of secure access
    # from SSL-enabled web browsers without installing GlobalProtect software."
    #
    # "surface" IS OURS AND IS DOING WORK. What is graded here is PRESENCE, not configuration
    # quality: stage 5 says there is no acceptable rank in stage 3's sense, because the acceptable
    # state is that the feature is not there. So the heading names the thing that exists rather
    # than a setting that is wrong, and the four cells - the model's own choice sentences, reached
    # through the reader above - say how much of it exists.
    #
    # NOT HEADED "Clientless VPN" BARE. The bare feature name over a cell reading "Definitions or
    # groups exist and no portal publishes them" would read as the name of a thing the reader
    # should go and configure; the column is a verdict over whether it is there at all, and the
    # `latent` rank is the state that makes the difference matter - a vsys holding definitions that
    # no portal publishes has no portal row anywhere in this report.
    "clientless_vpn_feature_state": "Clientless VPN surface",
}


# --------------------------------------------------------------------------------------------
# THE EVIDENCE CELLS. Each is a SUBJECT column, each reads a value no shipped PAN-GPP query
# clauses on, and each is here because a row that omitted it would argue against its own finding
# or be silent on a state worse than anything it reports.
#
# NOT ONE OF THEM DECLARES A `field`, and on these three tabs that is the SAFE side of lesson 5
# rather than the unsafe one. A subject column that declares no field does not suppress the
# derived setting column for the same attribute, so one value can reach a tab twice under two
# headings and the duplicate-header guard never fires because the headings differ. None of the
# attributes below is a clause field of any PAN-GPP control - checked against the shipped
# canonical queries, not against `asserted_fields` - so there is no derived column for any of them
# and nothing to collide with. Declaring a field would also offer these cells to the
# value-at-fault mark, which can only ever be wrong here: none of them is the thing to change.

def portal_tls_profile(portal, _provenance_of) -> str:
    """Which SSL/TLS service profile the portal binds, beside the verdict that says none is.

    THE VERDICT COLUMN CANNOT SAY WHAT IS BOUND, only that nothing is, and a PAN-GPP-001 finding
    sends a reader to change this value. Stage 5 pairs the two explicitly: `ssl_tls_service_profile`
    reads as `fires` when unknown "because the key is mandatory on a committed portal, so a null
    is never a device state", and `tls_profile_binding_missing` "is the column that reports it on
    the firing side". So this cell is the evidence and that column is the verdict.

    NO SHIPPED QUERY CLAUSES ON IT and it is not in
    `search/globalprotect_portal/compiler.py`'s registry either, which is the same fact from the
    other side - the repo's rule is that only a column a control asks for is registered. So it
    draws no setting column and cannot be the value at fault.

    THE EMPTY STRING IS THE OBSERVED STATE ON THIS ESTATE'S PA-5220 PORTAL, not a gap: the model's
    own docstring records that a row cannot say whether the floor the portal negotiates is
    acceptable, because the binding is a NAME and on a template-managed appliance the profile it
    names is not in the same payload. `display_value` prints `(empty)` for that, which is the
    honest word - the key was read and carries nothing.
    """
    return findings_sheet.display_value(portal.ssl_tls_service_profile)


def portal_client_auth_rows(portal, _provenance_of) -> str:
    """How many client-authentication rows this portal carries.

    THE WORST STATE THE DEVICE PERMITS IS ONE NO CONTROL ON THIS TAB REPORTS, and zero here is it.
    Stage 5's note on PAN-GPP-002 says so in terms: `portal-config/client-auth` is OPTIONAL on a
    committed portal, measured, "so a portal can demand NOTHING AT ALL, which is weaker than this
    grading's `critical` rank" - and a portal with no rows has no child row for PAN-GPP-002 to
    report on, so the gap is silent on exactly the portals where it is worst. This cell is the only
    place in the report that state appears.

    A portal reading 0 here should be read as admitting endpoints on whatever the gateway demands,
    with the portal asking nothing - not as a portal with nothing to review.

    PRINTED AS A NUMBER rather than through `display_value`, on the ruling this repository's other
    count columns took: zero is the reportable end, and a word like "None" on a column named for a
    count reads as "not counted" instead of "none found".
    """
    return str(portal.client_auth_row_count)


def row_operating_system(row, _provenance_of) -> str:
    """The endpoint class this authentication row serves - the key the table is actually keyed by.

    THE ROW'S NAME CARRIES NO MEANING AND THIS DOES. Stage 5 measured it: the row's own name is
    operator-chosen, "so it serves only to keep two rows apart and `os` is what a reader goes by".
    Two rows of one portal differ in their demand BECAUSE they differ here, and a PAN-GPP-002
    finding on `r2` and silence on `r1` is unreadable without this cell - which is the measured
    case on this estate, on pan-fw-7d6e's `oep-gpp6-e`.

    THE VENDOR'S OWN LABEL IS "OS", Help 11.2 p.1002: "To deploy a client authentication profile
    specific to the operating system (OS) on an endpoint, Add the OS (Any, Android, Chrome, iOS,
    Linux, Mac, Windows, or WindowsUWP). The OS is the primary differentiator between
    configurations." The heading on the sheet spells it out, because a two-letter column heading
    beside "Object" reads as an abbreviation of the row name.

    `(none)` HERE IS A READING NOBODY TOOK, not a row that serves every endpoint: the key is
    mandatory to commit and stage 5 reads its unknown as firing for that reason. `Any` is how the
    device spells "every class", and it is a value rather than an absence.
    """
    return findings_sheet.display_value(row.os)


def row_authentication_profile(row, _provenance_of) -> str:
    """The first factor this row demands, by name, beside the verdict over both factors.

    THE VERDICT COLUMN GRADES THE COMBINATION AND THIS NAMES THE PROFILE, which is what a reader
    fixing a PAN-GPP-002 finding opens. Help 11.2 p.1002: "In addition to distinguishing a client
    authentication configuration by an OS, you can further differentiate by specifying an
    authentication profile."

    WHAT IT CANNOT SAY, and the model's own docstring carries it as a stated limit: whether the
    thing named is a PROFILE or a SEQUENCE. The two are different objects at different rail
    addresses and the row holds only a name, so a reader following this cell may land on either.

    `(none)` IS A READING NOBODY TOOK. The key is mandatory on a committed row, so stage 5 reads a
    null as uncollected rather than as a row demanding no first factor - and it reads it as firing,
    because "the direction of error on an admission test means an unread first factor must not read
    as a strong one".
    """
    return findings_sheet.display_value(row.authentication_profile)


def row_either_factor_switch(row, _provenance_of) -> str:
    """The vendor's own OR switch, as the device holds it.

    ONE OF THE TWO LEAVES THE VERDICT IS COMPUTED FROM, and the reason it is on the row is that the
    verdict cannot be acted on without it: the setting an engineer changes is this switch, at
    `Network > GlobalProtect > Portals > <portal-config> > Authentication`. Help 11.2 p.1003
    verbatim: "Allow Authentication with User Credentials OR Client Certificate - If you select No,
    users must authenticate to the gateway using both user credentials and client certificates. If
    you select Yes, users can authenticate to the gateway using either user credentials or client
    certificates."

    THE VENDOR'S POLARITY IS THE DANGEROUS ONE and this cell keeps it rather than flipping it. "No"
    is the HARDENED answer here - both factors required - which is the reverse of almost every
    other switch in this report, and stage 5 records that a naive reading of this leaf alone is
    INVERTED: it would read `yes` as the hardened value. The cell prints the device's own `yes` or
    `no` so that it reads as the screen reads, and the verdict column beside it carries the
    direction.

    `(none)` IS TWO STATES AT ONCE and stage 5 says neither is safe - the key absent on a committed
    row, whose meaning nobody measured, or a row the collector did not carry. Both fire, because
    materialising either candidate lands on a different rank of the grading.
    """
    return findings_sheet.display_value(row.user_credential_or_client_cert_required)


def row_certificate_profile_bound(row, _provenance_of) -> str:
    """Whether the OWNING PORTAL binds a certificate profile - the second leaf behind the verdict.

    THE OTHER HALF OF WHAT MAKES THE OR SWITCH MEAN ANYTHING, and the model carries it DOWN from
    the portal onto the row for that reason. Its own words: "`yes` means 'a password OR a client
    certificate will do', and where no certificate profile is bound there is no second factor for
    the OR to reach." So a row whose switch says `yes` and whose profile reads "No" admits an
    endpoint on a password alone, and neither cell says that by itself.

    IT IS A FACT ABOUT THE PORTAL AND IS SHOWN ON THE ROW, which is a duplication worth stating: on
    a portal with three authentication rows this cell reads the same on all three, because there is
    one certificate profile per portal. Help 11.2 p.1003: "The certificate profile is independent of
    the OS."

    FALSE IS BOTH THE DEFAULT AND THE FIRING SIDE, so an unrecomputed row and a portal with no
    profile read the same way - which stage 5 says is correct, "because they have the same
    consequence for an endpoint".
    """
    return findings_sheet.display_value(row.certificate_profile_bound)


def point_portal_count(point, _provenance_of) -> str:
    """How many GlobalProtect portals this virtual system holds.

    THE CELL THAT TELLS THIS TAB'S TWO SILENCES APART. A vsys reading `absent` for the clientless
    surface is a vsys with nothing to fix; a vsys reading 0 here as well has no GlobalProtect at
    all, and those are different conversations. It is also the only cell that explains why a vsys
    appears on this tab with no row anywhere on the Portals tab - which is the whole reason this
    subject exists, and the `latent` rank is the state stage 5 says it exists FOR.

    PRINTED AS A NUMBER, on the same ruling as the client-auth count above.
    """
    return str(point.portal_count)


def point_clientless_definitions(point, _provenance_of) -> str:
    """The application definitions this vsys holds, and how many portals publish any of them.

    THE THREE COUNTS THE VERDICT IS COMPUTED FROM, in one cell rather than three columns. The
    verdict reads `live` where a portal publishes and definitions exist, `latent` where the
    definitions are there and nothing publishes them, and `absent` where neither - so the numbers
    are what a reader needs to know WHICH PIECE to remove, and they live at two different rail
    addresses: `Network > GlobalProtect > Clientless Apps` and `Clientless App Groups` for the
    definitions (Help 11.2 p.997 lists both), and the portal's own Clientless VPN tab for the
    publishing.

    ONE CELL AND NOT THREE because the three are read together and never apart: no control clauses
    on any of them, the verdict column is what fires, and three count columns would widen the tab
    for a reading no row takes separately. Each is labelled in place so the cell is legible without
    a column heading per number.

    NODE PRESENCE IS THE WRONG TEST AND A COUNT IS THE RIGHT ONE, which the model's own docstring
    measured: deleting the last entry leaves the container present and empty, so a zero here is a
    real reading and not a missing one.
    """
    return (f"{point.clientless_app_count} app(s), "
            f"{point.clientless_app_group_count} group(s), "
            f"published by {point.portals_publishing_clientless_apps} portal(s)")


def point_licence(point, _provenance_of) -> str:
    """What the appliance said about its GlobalProtect Portal licence, in the model's own words.

    WHAT "No" IN THE APPLICABILITY COLUMN ACTUALLY COVERS. `licence_excludes_globalprotect` reads
    False both where the licence IS installed and where the appliance was never asked, and stage 5
    built the clause to suppress only on a populated list that lacks the feature - so this cell is
    the only place the two are told apart. The model keeps `unknown` apart from `no` for exactly
    that reason: its own comment records that `{'licenses': None}` arrives with status=success on
    an appliance that holds nothing, so "a count of zero cannot tell 'asked and holds none' from
    'never asked'".

    THE DISPLAY LABEL AND NOT THE TOKEN, called directly here because this is a subject column
    whose reader is this function: `yes`, `no` and `unknown` are three words a customer cannot act
    on, and the model's choice labels are three sentences they can. The entry count is appended
    because zero entries is what `unknown` means on the wire.

    THE LICENCE IS DEVICE-WIDE AND THE ROW IS PER VSYS, so this cell repeats across every vsys of
    one appliance. Stage 5 names that as the reason a licence column is not the row's own grain and
    records it rather than hiding it.
    """
    return (f"{point.get_globalprotect_portal_licensed_display()} "
            f"({point.licence_entry_count} licence entr"
            f"{'y' if point.licence_entry_count == 1 else 'ies'} read)")


def portal_of_row(row, _provenance_of) -> str:
    """The portal this authentication row sits inside - part of the row's identity, not decoration.

    STAGE 5 MADE IT AN IDENTITY COLUMN and the shipped constraint agrees: the model keys on
    (appliance, scope, vsys_name, portal_name, name), because `name` alone is not unique within a
    vsys. The model's own comment carries the measurement - "two portals of one vsys routinely use
    the same row name ... four portals of vsys4 each carrying a row called `r1`" - so without this
    column four rows of this tab would be indistinguishable, and a reader following a PAN-GPP-002
    finding would not know which dialog to open.

    IT READS THE STORED `portal_name` AND NOT THE FOREIGN KEY. The model carries the portal twice
    on purpose and says why: the FK is the join a reader follows, and `portal_name` is the identity.
    Reading the name avoids a query per row and is the value the uniqueness constraint uses, so the
    cell cannot disagree with the row's own identity even on a dangling row - which the FK's
    SET_NULL makes possible and which the model keeps visible deliberately.
    """
    return row.portal_name or NONE
