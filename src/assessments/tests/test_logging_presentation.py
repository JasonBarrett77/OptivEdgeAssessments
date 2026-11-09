"""The three `logging` findings tabs, and the cells on them that were judgments.

Stage 9 of the OptivEdgeProbe pipeline, domain `logging`, 2026-11-03. Nothing obliges a stage 9
run to add a test file; a new tab that nothing asserts on is a tab the next refactor can silently
break, and every judgment this run made about a cell is pinned here.

EVERY TABLE IN THIS FILE GOES THROUGH `self.table()`, WHICH CALLS THE FINDING RUN AND THEN
ASSERTS THE TABLE IS NON-EMPTY. `build_findings_table` LOADS a domain's findings rather than
computing them, and its only row-count guard compares the rows it built against what the DATABASE
holds - so with no findings generated both sides are zero, nothing raises, the HEADINGS still come
out right because they derive from the controls, and every assertion written `for row in
table.rows:` iterates nothing and passes. That has already shipped once, in
`test_platform_lifecycle_presentation`. The helper makes it impossible here.

THE SUBJECT ROWS ARE WRITTEN DIRECTLY RATHER THAN NORMALIZED, and that is deliberate: the
normalizers are stage 7's and have their own tests, the stage 6 payloads live in another
repository and are gitignored, and what this file is about is what a ROW SAYS once the columns
hold known values. Each payload value below is the one the stage 6 artifact recorded for the
subject named beside it, transcribed by hand.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments import logging_presentation as logging_pres
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets.findings import (
    ALL_TESTED_COLUMNS, build_findings_table, display_value)
from assessments.artifacts.layout import NONE
from assessments.finding_run import regenerate_findings
from assessments.models import Control
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, LoggingSettings, LogServerTarget, ManagementStation, Snapshot,
    VsysLogForwarding)
from optivedge_integrations.integrations.models.provenance import FieldProvenance

#: Every control that reports on one of the three tabs, including PAN-MGT-011 - which is
#: `management-services`' and shares the `logging_settings` type. STATED HERE because
#: `setting_columns` derives a column per clause field of the controls PRESENT in the build, so
#: the heading count below is a function of this list and is not comparable to another run's
#: number for the same tab.
SEEDED = ["PAN-LOG-001", "PAN-LOG-002", "PAN-LOG-003", "PAN-LOG-004", "PAN-LOG-005",
          "PAN-LOG-006", "PAN-LOG-007", "PAN-LOG-008", "PAN-LOG-009", "PAN-LOG-010",
          "PAN-MGT-011"]

#: The eleven settings columns of the shared tab, in the order a built table puts them. The
#: baseline clauses in stage 5's clause order, then each non-baseline query's clauses
#: ALPHABETICALLY BY QUERY NAME, then the next control by `control_id` - so `syslog_destination_
#: in_use` arrives SECOND, from PAN-LOG-001's calibration "No forwarding rule names any syslog
#: profile" sorting before "No off-box log destination at all" on `f` < `o`; `panorama_managed`
#: appears ONCE although it is the applicability clause of BOTH -006 and -010; and
#: `log_on_high_dp_load` is LAST because `PAN-LOG-001` sorts before `PAN-MGT-011`.
#:
#: NOTHING IN EITHER REPOSITORY GATES THIS ORDER and `auto_setting_columns` is all or nothing, so
#: renaming a shipped calibration query would silently reorder a customer-facing column. This is
#: the gate.
LOGGING_SETTINGS_ORDER = [
    "Off-box log destinations (count)",
    "A forwarding rule names a syslog profile",
    "System-log severities with no off-box destination",
    "Every configuration-change log leaves the firewall",
    "Has a Panorama or Logging Service to send to",
    "Log types not forwarded to Panorama or the Logging Service",
    "Require Audit Comment on Policies",
    "Critical system events reach an email relay",
    "An expiration period or storage quota is set",
    "Logs are reaching the central store",
    "Enable Log on High DP Load",
]


class LoggingPresentationTests(TestCase):

    maxDiff = None

    def setUp(self):
        seed_controls(SEEDED)
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="20.185.152.225")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-standalone",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="691665AC334B458", hostname="pan-fw-201")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

    # ------------------------------------------------------------------ fixtures

    def posture(self, **overrides):
        """One `LoggingSettings` row, firing every control of the shared tab unless overridden.

        The two STORED keys carry real `FieldProvenance` rows, which is what the provenance cell
        is about: `require_audit_comment` is a key an administrator wrote (`local`), and
        `log_on_high_dp_load` was ABSENT and the normalizer recorded it as a vendor implicit
        (`pan_os_default`) - which is neither written by anyone nor derived by us, and is the
        third answer a two-way branch would have got wrong.
        """
        values = dict(
            offbox_destination_count=0,
            syslog_destination_in_use=False,
            system_log_severity_gaps="critical,high,medium,low,informational",
            config_log_fully_offbox=False,
            config_log_offbox_destination=False,
            config_log_filter_narrows=True,
            panorama_managed=True,
            panorama_log_type_gaps="system,config,traffic,threat",
            require_audit_comment=False,
            email_alerting_for_critical_system_events=False,
            log_retention_configured=False,
            central_store_delivery_healthy=False,
            central_store_status_collected=False,
            log_on_high_dp_load=False,
            log_settings_match_lists=[],
        )
        values.update(overrides)
        row = LoggingSettings.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot, **values)
        content_type = ContentType.objects.get_for_model(LoggingSettings)
        FieldProvenance.objects.create(
            content_type=content_type, object_id=row.pk, field_name="require_audit_comment",
            provenance_type=FieldProvenance.ProvenanceType.LOCAL,
            raw_key="require-audit-comment-on-policies", raw_value="no")
        FieldProvenance.objects.create(
            content_type=content_type, object_id=row.pk, field_name="log_on_high_dp_load",
            provenance_type=FieldProvenance.ProvenanceType.PAN_OS_DEFAULT,
            raw_key="enable-log-high-dp-load", raw_value="")
        return row

    def server(self, *, kind="syslog", server_name="s1", transport="UDP", referrers=1,
               entry_provenance=FieldProvenance.ProvenanceType.LOCAL, **overrides):
        """One `LogServerTarget` row, with the object's `__entry__` provenance row.

        `transport` carries a real per-field row because it is a STORED key and whether it was
        absent is what PAN-LOG-002 is about; `kind` deliberately carries NONE, because the
        normalizer takes the kind from the config subtree the profile was read at rather than
        from any key of the entry - which is the shape that makes a branching provenance cell
        print "Not recorded" about it.
        """
        values = dict(scope="shared", vsys_name="", kind=kind, profile_name="oep-log6-01",
                      server_name=server_name, server_address="198.51.100.41", port=514,
                      transport=transport, protocol="", tls_version="", auth_method="",
                      meets_authenticated_tls=False, transport_grade="",
                      profile_referrer_count=referrers)
        values.update(overrides)
        row = LogServerTarget.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot, **values)
        content_type = ContentType.objects.get_for_model(LogServerTarget)
        FieldProvenance.objects.create(
            content_type=content_type, object_id=row.pk, field_name="__entry__",
            provenance_type=entry_provenance, raw_key="@name", raw_value="oep-log6-01")
        if values["transport"]:
            FieldProvenance.objects.create(
                content_type=content_type, object_id=row.pk, field_name="transport",
                provenance_type=FieldProvenance.ProvenanceType.LOCAL,
                raw_key="transport", raw_value=values["transport"])
        return row

    def vsys(self, *, gaps="gtp,sctp", collected=True, profiles=None, vsys_name="vsys1"):
        return VsysLogForwarding.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot, vsys_name=vsys_name,
            profile_names=profiles if profiles is not None else [],
            offbox_log_type_gaps=gaps, pushed_profile_sources_collected=collected)

    # ------------------------------------------------------------------ the guarded table

    def table(self, slug):
        """THE ONLY WAY A TEST IN THIS FILE REACHES A ROW.

        Calls the finding run itself rather than trusting something else to have done it, and
        refuses an empty table - because an empty one passes every `for row in table.rows:`
        assertion silently and its headings still come out correct.
        """
        regenerate_findings()
        table = build_findings_table(DOMAIN_BY_SLUG[slug].spec, tested=ALL_TESTED_COLUMNS)
        self.assertTrue(table.rows, f"{slug}: EMPTY TABLE - no assertion below is evidence")
        return table

    def cells(self, table, row_index):
        return dict(zip(table.headers, table.rows[row_index]))

    def marked(self, table, row_index):
        return {table.headers[column] for row, column in table.implicated
                if row == row_index}

    # ------------------------------------------------------------------ headings and order

    def test_no_heading_on_any_of_the_three_tabs_is_a_django_field_name(self):
        """`setting_labels` falls back to the raw field name, so a column with no entry IS a
        database field name shown to a customer. This tab had ONE settings column and ZERO label
        entries before this domain arrived, so `log_on_high_dp_load` was raw on a shipped tab."""
        self.posture()
        self.server()
        self.vsys()
        for slug in ("logging-settings", "log-server-profiles", "log-forwarding"):
            table = self.table(slug)
            raw = [header for header in table.headers if "_" in header]
            self.assertEqual(raw, [], f"{slug} has raw Django field names as headings")

    def test_the_settings_column_order_on_the_shared_tab(self):
        """READ OFF THE BUILT TABLE, not derived from stage 5. Nothing else gates this."""
        self.posture()
        self.server()
        self.vsys()
        table = self.table("logging-settings")
        settings = [header for header in table.headers if header in LOGGING_SETTINGS_ORDER]
        self.assertEqual(settings, LOGGING_SETTINGS_ORDER)

    def test_pan_mgt_011s_column_is_last_although_it_was_first(self):
        """`setting_columns` walks `order_by("control_id")` and `PAN-LOG-001` sorts before
        `PAN-MGT-011`, so the one column this tab had before the `logging` controls arrived moves
        from first to eleventh. Nothing gates it and no sheet can change it."""
        self.posture()
        self.server()
        self.vsys()
        table = self.table("logging-settings")
        settings = [header for header in table.headers if header in LOGGING_SETTINGS_ORDER]
        self.assertEqual(settings[-1], "Enable Log on High DP Load")
        self.assertEqual(settings[0], "Off-box log destinations (count)")

    def test_both_new_tab_titles_fit_excels_thirty_one_character_cap(self):
        """A sheet name over 31 characters truncates SILENTLY, and `probe.surface_for` prints the
        untruncated title - so the tool and the workbook disagree and the tool looks right."""
        for slug in ("log-server-profiles", "log-forwarding"):
            title = DOMAIN_BY_SLUG[slug].spec.sheet_title
            self.assertLessEqual(len(title), 31, f"{slug}: {title!r} is {len(title)}")
        self.assertEqual(DOMAIN_BY_SLUG["log-server-profiles"].spec.sheet_title,
                         "Syslog and Email Destinations")
        self.assertEqual(DOMAIN_BY_SLUG["log-forwarding"].spec.sheet_title,
                         "Virtual System Log Forwarding")

    def test_no_sheet_declares_hidden_fields(self):
        """`check_every_tested_field_is_presented` counts a field as presented if the sheet merely
        LISTS it in `hidden_fields`, so a non-empty one is a claim accepted as proof - and it is
        the only known cause of a findings row that marks nothing as the thing to fix."""
        for slug in ("logging-settings", "log-server-profiles", "log-forwarding"):
            self.assertEqual(DOMAIN_BY_SLUG[slug].spec.hidden_fields, ())

    def test_every_row_on_every_tab_marks_something(self):
        """A row that marks nothing offers a customer no value to change."""
        self.posture()
        self.server(server_name="s1", transport="TCP")
        self.vsys()
        for slug in ("logging-settings", "log-server-profiles", "log-forwarding"):
            table = self.table(slug)
            self.assertTrue(table.rows)
            unmarked = [index for index in range(len(table.rows))
                        if not self.marked(table, index)]
            self.assertEqual(unmarked, [], f"{slug}: rows marking nothing")

    # ------------------------------------------------------------------ the provenance cells

    def test_the_shared_tabs_provenance_cell_prints_three_answers_and_the_default_prints_a_falsehood(self):
        """MIXED clause fields, so the cell must branch - and there are THREE answers, not two.

        Nine of the eleven are declared derived; `require_audit_comment` is `Local`; and
        `log_on_high_dp_load` was absent and is recorded as a vendor implicit, which is neither.
        The DEFAULT cell reads "Not recorded" for the nine, because `remediation_accessor`
        discards DERIVED and walks to an `__entry__` row this model never carries.
        """
        self.posture()
        self.server()
        self.vsys()
        table = self.table("logging-settings")
        cells = {row[table.headers.index("Control ID")]: row[table.headers.index("Provenance")]
                 for row in table.rows}
        # THE CELL IS PER ROW AND THE FIELDS ARE PER CONTROL, which this run measured wrongly
        # first: `build_rows` hands `provenance_cell` the fields of the row's OWN control, not
        # the tab's eleven. So the three answers appear across three ROWS of one tab rather than
        # on one row, and a constant string would be a falsehood on two of the three.
        self.assertEqual(cells["PAN-LOG-001"], "Derived")
        self.assertEqual(cells["PAN-LOG-007"], "Local")
        self.assertEqual(cells["PAN-MGT-011"], "PAN-OS default")

        # And what the DEFAULT says on the same rows: right about the two stored keys, and
        # "Not recorded" about every derived one - which is nine of the eleven columns.
        spec = DOMAIN_BY_SLUG["logging-settings"].spec
        default = build_findings_table(
            type(spec)(**{**spec.__dict__, "provenance_cell": None}),
            tested=ALL_TESTED_COLUMNS)
        self.assertTrue(default.rows)
        was = {row[default.headers.index("Control ID")]:
               row[default.headers.index("Provenance")] for row in default.rows}
        self.assertEqual(was["PAN-LOG-001"], "Not recorded\nNot recorded")
        self.assertEqual(was["PAN-LOG-007"], "Local")
        self.assertEqual(was["PAN-MGT-011"], "PAN-OS default")

    def test_the_vsys_tabs_provenance_cell_is_the_honest_constant(self):
        """Both clause fields are declared derived and the model carries no `choices`, so a
        labeling reader would be FATAL and the sheet-level cell is the only remedy left. The
        DEFAULT reads "Not recorded" on every row, which is false about a computed column."""
        self.vsys()
        table = self.table("log-forwarding")
        self.assertEqual(self.cells(table, 0)["Provenance"], "Derived")

        spec = DOMAIN_BY_SLUG["log-forwarding"].spec
        default = build_findings_table(
            type(spec)(**{**spec.__dict__, "provenance_cell": None}),
            tested=ALL_TESTED_COLUMNS)
        self.assertTrue(default.rows)
        # One line per clause field under the default, and both of them false about a computed
        # column; one line under the branch, and true.
        self.assertEqual(default.rows[0][default.headers.index("Provenance")],
                         "Not recorded\nNot recorded")

    def test_the_server_tab_keeps_the_defaults_answer_and_a_branch_would_state_a_falsehood(self):
        """THE FOURTH BRANCH. The two-grep rule says MIXED clause fields must branch on
        `provenance_of`, and here that is wrong: `kind` is a STORED clause field with no
        `FieldProvenance` row of its own, because the normalizer takes it from the config subtree
        rather than from a key - so a cell printing what `provenance_of` recorded prints
        "Not recorded" about a column whose location is simply the object's.

        And only the default's walk reaches the `__entry__` row, which is the one thing that can
        say "Template" about a template-contributed server entry.
        """
        self.server(server_name="local", transport="UDP")
        self.server(server_name="pushed", transport="TCP",
                    entry_provenance=FieldProvenance.ProvenanceType.TEMPLATE)
        table = self.table("log-server-profiles")
        self.assertEqual(len(table.rows), 2)
        by_server = {row[table.headers.index("Server")]:
                     row[table.headers.index("Provenance")] for row in table.rows}
        self.assertEqual(by_server["local"], "Local")
        # Template for the object, Local for the one key an administrator overrode on it - two
        # true answers, where the DEFAULT would print "Template" twice and then "Local".
        self.assertEqual(by_server["pushed"], "Template\nLocal")

        # What a branch on `provenance_of` alone would have printed, on the same rows.
        spec = DOMAIN_BY_SLUG["log-server-profiles"].spec
        branched = build_findings_table(
            type(spec)(**{**spec.__dict__,
                          "provenance_cell": logging_pres.provenance_cell}),
            tested=ALL_TESTED_COLUMNS)
        self.assertTrue(branched.rows)
        for row in branched.rows:
            self.assertIn("Not recorded", row[branched.headers.index("Provenance")])

    # --------------------------------------- the unranked gap set, and the severity basis

    def test_a_vsys_whose_only_gap_is_unranked_reports_the_controls_own_default(self):
        """STAGE 8 PARKED THIS AS A `needs_human` AND THIS IS THE MEASURED ANSWER.

        Stage 5 grades `offbox_log_type_gaps` over all ten members of the Log Forwarding log-type
        enum and gives five of them - `gtp`, `sctp`, `tunnel`, `auth`, `decryption` - `produces:
        unranked` with NO severity, so no calibration query exists for any of them. A row whose
        gap set is exactly those tokens therefore matches the BASELINE alone.

        The row DOES appear, the Severity cell reads High - the control's own default - and the
        Severity basis says "Control default" in those words rather than naming a calibration.
        What a customer cannot read anywhere on the row is that those two types are ones nobody
        graded; the gap cell names them, and nothing says they are unranked.
        """
        self.vsys(gaps="gtp,sctp",
                  profiles=[{"name": "oep-logging-06", "source": "vsys",
                             "offbox_log_types": []}])
        table = self.table("log-forwarding")
        cells = self.cells(table, 0)
        self.assertEqual(cells["Severity"], "High")
        self.assertEqual(cells["Severity basis"], "Control default")
        self.assertEqual(cells["Matched queries"], "Baseline")
        self.assertEqual(cells["Log types no profile sends off-box"], "gtp,sctp")
        self.assertEqual(self.marked(table, 0), {"Log types no profile sends off-box"})

    def test_a_row_missing_five_ranked_types_prints_five_query_names_three_of_them_medium(self):
        """P450's WORST INSTANCE, and it needs only ONE column.

        `findings.py:510-524` collects every matched non-baseline query carrying an adjusted
        severity, grades on the MAXIMUM, and prints them ALL under "Adjusted to <max> by:".
        `offbox_log_type_gaps` is a GAP SET rather than a state, so membership is non-exclusive
        and five calibrations at three severities match one row at once - and three of the five
        names printed as the basis of a High grade are `medium` queries.

        The sufficient condition for this defect is therefore NOT "clauses spanning two or more
        columns": one column of non-exclusive membership does it.
        """
        self.vsys(gaps="traffic,threat,wildfire,url,data")
        table = self.table("log-forwarding")
        cells = self.cells(table, 0)
        self.assertEqual(cells["Severity"], "High")
        self.assertEqual(cells["Severity basis"].splitlines(), [
            "Adjusted to High by:",
            "Missing off-box log type: data",
            "Missing off-box log type: threat",
            "Missing off-box log type: traffic",
            "Missing off-box log type: url",
            "Missing off-box log type: wildfire",
        ])

    def test_the_row_that_argues_against_its_own_finding_carries_the_value_that_fired(self):
        """`fires_when` renders the BASELINE's condition alone, with no per-spec hook.

        PAN-LOG-001's baseline is `offbox_destination_count < 2` and its calibration "No
        forwarding rule names any syslog profile" asserts on a DIFFERENT column, so an appliance
        with two destinations and no forwarding rule naming one gets a row whose stated condition
        it does not meet. The workaround is the one the contract names: get the value that fired
        onto the row, so the marked cell, `Matched queries` and `Severity basis` resolve it
        between them.
        """
        self.posture(offbox_destination_count=2, syslog_destination_in_use=False)
        table = self.table("logging-settings")
        row = next(index for index, row in enumerate(table.rows)
                   if row[table.headers.index("Control ID")] == "PAN-LOG-001")
        cells = self.cells(table, row)
        self.assertEqual(cells["Fires when (failing condition)"], "offbox_destination_count < 2")
        self.assertEqual(cells["Off-box log destinations (count)"], "2")
        self.assertEqual(cells["A forwarding rule names a syslog profile"], "No")
        self.assertEqual(self.marked(table, row), {"A forwarding rule names a syslog profile"})
        self.assertEqual(cells["Matched queries"], "No forwarding rule names any syslog profile")

    def test_every_stated_condition_still_reads_in_django_field_names(self):
        """A RECORDED DEFECT, NOT A PREFERENCE. `render_node` consults `setting_labels` nowhere,
        so a tab with every heading labeled still prints its firing conditions in field names -
        the same value named two ways on one row. Nothing a sheet declares changes it. Pinned so
        that the day it IS fixed, this test fails and says so."""
        self.posture()
        self.server()
        self.vsys()
        for slug in ("logging-settings", "log-server-profiles", "log-forwarding"):
            table = self.table(slug)
            column = table.headers.index("Fires when (failing condition)")
            conditions = {row[column] for row in table.rows}
            self.assertTrue(conditions)
            self.assertTrue(all("_" in condition for condition in conditions),
                            f"{slug}: a condition no longer reads in field names - good news, "
                            f"and this test is now the stale half")

    # ------------------------------------------------ the columns no clause would have drawn

    def test_the_two_halves_of_pan_log_004s_verdict_reach_the_row(self):
        """`config_log_fully_offbox` is an AND of two readings and no clause reads either half, so
        `tested_fields` derives no column for them - and the two halves need OPPOSITE
        remediations. Hand-declared in the subject block, which is the documented way."""
        self.posture(config_log_fully_offbox=False, config_log_offbox_destination=True,
                     config_log_filter_narrows=True)
        table = self.table("logging-settings")
        row = next(index for index, row in enumerate(table.rows)
                   if row[table.headers.index("Control ID")] == "PAN-LOG-004")
        cells = self.cells(table, row)
        self.assertEqual(cells["Every configuration-change log leaves the firewall"], "No")
        self.assertEqual(cells["Configuration logs have a destination"], "Yes")
        self.assertEqual(cells["A filter holds configuration logs back"], "Yes")

    def test_pan_log_010s_row_says_whether_anybody_took_the_delivery_reading(self):
        """`central_store_delivery_healthy` is computed from an OPERATIONAL reply and reads False
        where that reply was never collected - which is the FIRING side. So without the companion
        column the row reports "logs are not reaching the central store" about an appliance nobody
        asked. rules.md's rule: a reading that cannot tell ZERO from UNKNOWN is an unknown, per
        field."""
        self.posture(central_store_delivery_healthy=False, central_store_status_collected=False)
        table = self.table("logging-settings")
        row = next(index for index, row in enumerate(table.rows)
                   if row[table.headers.index("Control ID")] == "PAN-LOG-010")
        cells = self.cells(table, row)
        self.assertEqual(cells["Logs are reaching the central store"], "No")
        self.assertEqual(cells["Delivery status was collected"], "No")
        self.assertEqual(self.marked(table, row), {"Logs are reaching the central store"})

    def test_a_vsys_no_profile_reaches_prints_an_em_dash_and_not_an_empty_list(self):
        """`layout.NONE` is U+2014 EM DASH, and it is the vocabulary member `display_value` has
        no way to say: no profile reaches this partition at ALL, which is a different observation
        from a profile reaching it and sending nothing off the box. The two need opposite
        remediations - build a profile, or give the one that exists a destination."""
        self.assertEqual(NONE, "—")
        self.vsys(gaps="traffic,threat", profiles=[])
        table = self.table("log-forwarding")
        self.assertEqual(self.cells(table, 0)["Profiles available"], NONE)

    def test_a_profile_that_exists_and_sends_nothing_says_so_in_words(self):
        self.vsys(gaps="gtp,sctp",
                  profiles=[{"name": "oep-logging-06", "source": "vsys",
                             "offbox_log_types": []},
                            {"name": "predefined-dataplane", "source": "predefined",
                             "offbox_log_types": ["traffic", "threat"]}])
        table = self.table("log-forwarding")
        self.assertEqual(self.cells(table, 0)["Profiles available"].splitlines(), [
            "oep-logging-06 (vsys): sends nothing off-box",
            "predefined-dataplane (predefined): traffic, threat",
        ])

    # ------------------------------------------------ `kind`, the label, and the refused reader

    def test_the_kind_cell_prints_the_vendors_word_and_not_the_stored_key(self):
        """`display_value` NEVER calls `get_<field>_display()` - the cell is `read_value` ->
        `getattr` -> `display_value`, whose value branch ends in `str(value)` - so a derived
        settings column over a `choices` field prints the STORED KEY. `kind` is a clause field of
        PAN-LOG-002 and is presented by a SUBJECT column whose own lambda calls the display
        method, which costs nothing: a `value_reader` would have been the other way, and a reader
        makes `build_rows` hand the field `stored=False` to `remediation_accessor`."""
        self.server(kind="syslog")
        table = self.table("log-server-profiles")
        self.assertEqual(self.cells(table, 0)["Kind"], "Syslog")
        self.assertEqual(display_value("syslog"), "syslog")

    def test_no_reader_on_transport_and_the_provenance_row_is_what_that_buys(self):
        """THE READER WAS CONSIDERED AND REFUSED, and this pins the reason.

        `transport` is a `CharField` with `choices`, so a reader is available - but `UDP` and
        `TCP` label as themselves and only `SSL` differs, at "SSL (TLS)", and `SSL` is the
        `no_finding` placement so no SSL row can draw a finding here. Against that, a reader makes
        `remediation_accessor` set `row=None` and walk past the field's own `FieldProvenance` row,
        and whether the transport key was ABSENT is exactly what this control reports: the column
        carries `default=Transport.UDP` precisely so an unconfigured server does not pass a
        control about cleartext.
        """
        self.assertEqual(DOMAIN_BY_SLUG["log-server-profiles"].spec.value_readers, {})
        self.assertEqual(LogServerTarget.Transport.UDP.label, "UDP")
        self.assertEqual(LogServerTarget.Transport.TCP.label, "TCP")
        self.assertEqual(LogServerTarget.Transport.SSL.label, "SSL (TLS)")
        self.server(transport="UDP")
        table = self.table("log-server-profiles")
        self.assertEqual(self.cells(table, 0)["Transport"], "UDP")
        self.assertEqual(self.marked(table, 0), {"Transport"})

    def test_an_empty_transport_offers_the_empty_string_as_the_thing_to_fix(self):
        """A RECORDED DEFECT. `display_value` has exactly three answers - a value, `(none)` and
        `(empty)` - and none of them says "no transport key is set, and the device materialises
        UDP". Where a stored transport is the empty string the row MARKS `(empty)` as the value at
        fault, offering `(empty)` as the remedy. Nothing a sheet declares fixes it on a stored
        key: a `value_reader` would, and it would cost the field's own provenance row, which is
        the one thing this control needs."""
        self.server(transport="")
        table = self.table("log-server-profiles")
        self.assertEqual(self.cells(table, 0)["Transport"], "(empty)")
        self.assertEqual(self.marked(table, 0), {"Transport"})

    # ------------------------------------------------ the explorer pages

    def test_pan_log_is_no_longer_awaiting_presentation(self):
        """The exemption is a debt and clearing it is part of this stage's job: an entry that
        survives the work it was waiting for is a permanent hole. It is also what FORCES the rail
        entries - `test_every_query_in_the_shipped_catalog_has_somewhere_to_go` iterates the seed
        payload and never consults `is_active`."""
        self.assertNotIn("PAN-LOG", cr.AWAITING_PRESENTATION)

    def test_every_query_field_on_the_three_pages_is_registered_by_its_compiler(self):
        """A heading mapped to an unregistered field points the "build a query from these rows"
        button at a lookup that refuses itself or matches nothing. Stored, searchable and
        registered are three different things."""
        import importlib

        for slug, module in (("logging-and-reporting", "logging_settings"),
                             ("log-server-profiles", "log_server_target"),
                             ("log-forwarding", "vsys_log_forwarding")):
            registry = importlib.import_module(
                f"assessments.search.{module}.compiler").FIELD_OPERATOR_REGISTRY
            for heading, field in cr.RESULTS[slug].query_fields.items():
                self.assertIn(field, registry, f"{slug}: {heading!r} -> {field!r}")

    def test_every_results_row_has_one_cell_per_column_over_real_rows(self):
        """The shipped squareness check cannot exercise a `row` lambda over real objects."""
        self.posture()
        self.server(kind="syslog")
        self.server(kind="email", server_name="relay", transport="UDP", protocol="SMTP",
                    profile_name="oep-logging-mail")
        self.vsys()
        for slug in ("logging-and-reporting", "log-server-profiles", "log-forwarding"):
            spec = cr.RESULTS[slug]
            rows = list(spec.base_queryset())
            self.assertTrue(rows, f"{slug}: no rows to render")
            for row in rows:
                self.assertEqual(len(spec.row(row)), len(spec.columns), slug)

    def test_the_server_page_prints_an_em_dash_where_a_column_does_not_exist_on_that_kind(self):
        """WHERE THE TWO-KINDS-ONE-MODEL SHAPE ACTUALLY LANDS. The findings tab can only ever hold
        the syslog half, because PAN-LOG-002's SCOPE clause is `kind = "syslog"`. This page lists
        the configuration, so it holds both - and `transport` carries `default=Transport.UDP`, so
        without the branch every mail relay in the estate would read "UDP"."""
        syslog = self.server(kind="syslog", transport="SSL")
        email = self.server(kind="email", server_name="relay", transport="UDP", protocol="TLS",
                            tls_version="1.2", auth_method="Auto",
                            meets_authenticated_tls=True, transport_grade="TLS 1.2",
                            profile_name="oep-logging-mail")
        self.assertEqual(logging_pres.transport_cell(syslog), "SSL (TLS)")
        self.assertEqual(logging_pres.transport_cell(email), NONE)
        self.assertEqual(logging_pres.protocol_cell(email), "SMTP over TLS")
        self.assertEqual(logging_pres.protocol_cell(syslog), NONE)
        self.assertEqual(logging_pres.email_only_cell(email, "tls_version"), "1.2")
        self.assertEqual(logging_pres.email_only_cell(syslog, "tls_version"), NONE)
        self.assertEqual(logging_pres.email_only_cell(email, "meets_authenticated_tls"), "yes")
        self.assertEqual(logging_pres.email_only_cell(syslog, "meets_authenticated_tls"), NONE)

    def test_the_explorer_page_and_the_findings_tab_name_each_column_the_same_way(self):
        """One column must not read two ways on two surfaces. The headings are read out of
        `logging_presentation` by both, rather than retyped in either."""
        self.posture()
        self.vsys()
        shared = self.table("logging-settings")
        page = cr.RESULTS["logging-and-reporting"].columns
        for field in ("offbox_destination_count", "require_audit_comment",
                      "log_on_high_dp_load", "central_store_delivery_healthy"):
            heading = logging_pres.LOGGING_SETTING_LABELS[field]
            self.assertIn(heading, shared.headers)
            self.assertIn(heading, page)

    def test_the_email_kind_draws_no_row_on_the_findings_tab(self):
        """PAN-LOG-002 is the only control of this type and its SCOPE clause is
        `kind = "syslog"`, so stage 5's `email-server-target` subject reaches the explorer page
        and never the findings tab. Pinned because the contract warns about one column meaning
        two things on adjacent rows of one tab, and on THIS tab that cannot happen."""
        self.server(kind="syslog", server_name="s1", transport="UDP")
        self.server(kind="email", server_name="relay", transport="UDP",
                    profile_name="oep-logging-mail")
        table = self.table("log-server-profiles")
        self.assertEqual([row[table.headers.index("Kind")] for row in table.rows], ["Syslog"])

    # ------------------------------------------------ the HA pair

    def test_a_pair_with_identical_configuration_yields_two_rows_and_nothing_deduplicates(self):
        """Measured, and the reason it is NOT deduplicated is on the artifact: all three models
        key on the APPLIANCE, so a collected pair yields one row per peer for one configuration -
        and the vendor itself says these settings "are synchronized across high availability
        pairs" (Help 11.2 p.716), which makes a DIFFERENCE between peers a real defect worth
        seeing rather than a duplicate worth hiding."""
        pair = ApplianceGroup.objects.create(
            management_station=self.station, name="g-pair",
            group_type=ApplianceGroup.TYPE_HA_PAIR)
        self.appliance.appliance_group = pair
        self.appliance.save(update_fields=["appliance_group"])
        peer = Appliance.objects.create(
            management_station=self.station, appliance_group=pair,
            serial_number="HAPEER0000001", hostname="pan-fw-201-peer")
        peer_snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=peer,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        self.posture()
        LoggingSettings.objects.create(
            management_station=self.station, appliance=peer, appliance_group=pair,
            source_snapshot=peer_snapshot, offbox_destination_count=0,
            syslog_destination_in_use=False,
            system_log_severity_gaps="critical,high,medium,low,informational",
            config_log_fully_offbox=False, config_log_offbox_destination=False,
            config_log_filter_narrows=True, panorama_managed=True,
            panorama_log_type_gaps="system,config", require_audit_comment=False,
            email_alerting_for_critical_system_events=False, log_retention_configured=False,
            central_store_delivery_healthy=False, central_store_status_collected=False,
            log_on_high_dp_load=False, log_settings_match_lists=[])
        table = self.table("logging-settings")
        for control in ("PAN-LOG-001", "PAN-LOG-007", "PAN-MGT-011"):
            rows = [row for row in table.rows
                    if row[table.headers.index("Control ID")] == control]
            self.assertEqual(len(rows), 2, f"{control} on one pair")
        appliances = {row[table.headers.index("Appliance")] for row in table.rows}
        self.assertEqual(appliances, {"pan-fw-201", "pan-fw-201-peer"})
        roles = {row[table.headers.index("HA role")] for row in table.rows}
        self.assertTrue(roles)

    # ------------------------------------------------ the applicability suppression

    def test_a_vsys_whose_pushed_reads_did_not_answer_draws_no_row_at_all(self):
        """AN APPLICABILITY CLAUSE ON A "DID WE COLLECT IT" COLUMN SUPPRESSES THE CONTROL.

        PAN-LOG-005's baseline is `pushed_profile_sources_collected = Yes and
        offbox_log_type_gaps is not empty`, so a virtual system whose Panorama-pushed and
        predefined profile reads did NOT answer reports nothing - not an unknown, not a finding,
        no row. rules.md names this shape in terms: the same field with an assertion clause would
        have raised it, and the suppressing form reads as careful.

        Recorded rather than fixed: the clause is stage 5's and stage 8 implemented it, and a
        stage 9 run may not write a clause. The gap column is still on the explorer page, where a
        reader can see the state the findings tab is silent about.
        """
        self.vsys(gaps="traffic,threat,wildfire,url,data", collected=False)
        regenerate_findings()
        table = build_findings_table(DOMAIN_BY_SLUG["log-forwarding"].spec,
                                     tested=ALL_TESTED_COLUMNS)
        self.assertEqual(table.rows, [])
        # The explorer page does show it, which is the only surface that does.
        spec = cr.RESULTS["log-forwarding"]
        rendered = [spec.row(row) for row in spec.base_queryset()]
        self.assertEqual(len(rendered), 1)
        cells = dict(zip(spec.columns, rendered[0]))
        self.assertEqual(cells["Pushed and predefined profiles were collected"], "no")
        self.assertEqual(cells["Log types no profile sends off-box"],
                         "traffic,threat,wildfire,url,data")
