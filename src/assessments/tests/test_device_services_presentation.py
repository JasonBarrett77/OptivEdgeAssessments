"""The five `device-services` findings tabs, and every cell on them that was a judgment.

Stage 9 of the OptivEdgeProbe pipeline, domain `device-services`, 2026-11-03. Nothing obliges a
stage 9 run to add a test file; a new tab that nothing asserts on is a tab the next refactor can
silently break, and three of these five tabs shipped as bare stubs for weeks with all sixteen of
their settings columns headed by raw Django field names, which is exactly what nothing asserting
on them looks like.

EVERY TABLE IN THIS FILE GOES THROUGH `self.table()`, WHICH CALLS THE FINDING RUN AND THEN
ASSERTS THE TABLE IS NON-EMPTY. `build_findings_table` LOADS a domain's findings rather than
computing them, and its only row-count guard compares the rows it built against what the DATABASE
holds - so with no findings generated both sides are zero, nothing raises, the HEADINGS still come
out right because they derive from the controls, and every assertion written `for row in
table.rows:` iterates nothing and passes. That has already shipped once, in
`test_platform_lifecycle_presentation`. The helper makes it impossible here, and it is called in
the tests that need rows rather than in `setUp`, so the heading tests do not pay a finding run.

THE SUBJECT ROWS ARE WRITTEN DIRECTLY RATHER THAN NORMALIZED, and that is deliberate: the
normalizers are stage 7's and have their own tests, the stage 6 payloads live in another
repository and are gitignored, and what this file is about is what a ROW SAYS once the columns
hold known values. Every value below is the one the committed normalizers produced for the
appliance named beside it when this run built the domain's estate from its stage 6 artifact
through `print_findings_table`, transcribed by hand.

THE TWELVE READER COLUMNS ARE PINNED BY THEIR ENGLISH LABELS, which is the point of them: nothing
in the sheets layer calls `get_<field>_display()`, so a `choices` field prints its STORED KEY
without a reader (P457) - and the same call on the `BooleanField` beside it raises
`AttributeError` at TEMPLATE RENDER, past `django check` and past all three cross-domain gates
(P462). Both halves are invisible to every gate, so the labels are asserted here or nowhere.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone

from assessments import configuration_navigation as nav
from assessments import configuration_results as cr
from assessments import device_services_presentation as device_services
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.layout import NONE
from assessments.artifacts.sheets.findings import (
    ALL_TESTED_COLUMNS, build_findings_table)
from assessments.finding_run import regenerate_findings
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, DnsSettings, ManagementStation, NtpSettings, ServiceRoute,
    Snapshot, SnmpSettings, SystemIdentity)
from optivedge_integrations.integrations.models.device_services import (
    AddressingModePosture, DefaultCommunityExposure, HostnamePosture,
    ManagementResolverPosture, PerSystemPathPosture, ResolverMechanism,
    ServerAuthenticationMechanism, ServicePathPosture, SnmpVersionInForce, TimeSourceInForce,
    TimezoneOffsetClass)
from optivedge_integrations.integrations.models.provenance import FieldProvenance

#: The nine controls that report on these five tabs - which is EVERY control of the five types and
#: nothing else, measured over the seed payload 2026-11-03. STATED HERE because
#: `setting_columns` derives a column per clause field of the controls PRESENT in the build, so
#: every heading count below is a function of this list. Unlike a shared tab, this list is also
#: the whole population, so these counts ARE the tabs' real counts and not a sample.
#:
#: PAN-SVC-008 is absent and ships nothing: stage 5 discharged its one record to
#: `engineer_answers`, it has no catalogue entry at all, and `integrations.DeviceTelemetry` was
#: deliberately given no control type, no finding kind, no generator and no compiler.
SEEDED = ["PAN-SVC-001", "PAN-SVC-002", "PAN-SVC-003", "PAN-SVC-004", "PAN-SVC-005",
          "PAN-SVC-006", "PAN-SVC-007", "PAN-SVC-009", "PAN-SVC-010"]

#: THE SETTINGS COLUMNS OF EACH TAB, IN THE ORDER A BUILT TABLE PUTS THEM: the baseline's clauses
#: in stage 5's clause order, then each non-baseline query's clauses ALPHABETICALLY BY QUERY NAME
#: (`findings.py:363-396`), then the next control by `control_id` (`findings.py:887`).
#:
#: NOTHING IN EITHER REPOSITORY GATES THIS ORDER and `auto_setting_columns` is all or nothing, so
#: renaming a shipped calibration query would silently reorder a customer-facing column. This is
#: the gate. Measured against stage 5's own `clauses` lists: the order MATCHES on all five tabs,
#: and it matches for a reason worth stating rather than for luck - on every one of these nine
#: controls the baseline leads with that control's own clause fields and the calibrations only ADD
#: the classification column beside them, so there is no field whose position the alphabetical
#: pass could decide. A tenth control whose calibration introduced two new fields would not be
#: safe that way.
ORDER = {
    "ntp": ["NTP servers configured", "Clock anchored to a configured server",
            "Time source in force", "Every server on a symmetric key", "Authentication Type"],
    "snmp": ["SNMP agent configured", "Answers on an unauthenticated version",
             "SNMP version in force", "Community string is a default",
             "Default community exposure"],
    "system-identity": ["Management Interface IP Type", "Management addressing posture",
                        "Time Zone declares a zero offset", "Time Zone offset",
                        "Hostname is the factory default", "Name in force"],
    "dns-settings": ["Resolvers chosen", "Management resolver posture"],
    "service-routes": ["Every originated service has a chosen path",
                       "Virtual system records its own choice", "Virtual system path posture",
                       "Firewall-wide path posture"],
}

SLUGS = ("ntp", "snmp", "system-identity", "dns-settings", "service-routes")


class DeviceServicesPresentationTests(TestCase):

    maxDiff = None

    def setUp(self):
        seed_controls(SEEDED)
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="20.185.152.225")
        self.points = {}
        self.snapshots = {}
        for serial, hostname in (("691665AC334B458", "pan-fw-201"),
                                 ("6A9C0A9904E7D6E", "pan-fw-111")):
            group = ApplianceGroup.objects.create(
                management_station=self.station, name=f"standalone-{serial}",
                group_type=ApplianceGroup.TYPE_STANDALONE)
            appliance = Appliance.objects.create(
                management_station=self.station, appliance_group=group,
                serial_number=serial, hostname=hostname)
            self.points[hostname] = (group, appliance)
            self.snapshots[hostname] = Snapshot.objects.create(
                management_station=self.station, appliance=appliance,
                source_type="show_merged_config", collected_at=timezone.now(), payload={})

    # ------------------------------------------------------------------ fixtures

    def _common(self, hostname):
        group, appliance = self.points[hostname]
        return dict(management_station=self.station, appliance=appliance, appliance_group=group,
                    source_snapshot=self.snapshots[hostname])

    def _provenance(self, row, field, kind, raw_key="", raw_value=""):
        FieldProvenance.objects.create(
            content_type=ContentType.objects.get_for_model(type(row)), object_id=row.pk,
            field_name=field, provenance_type=kind, raw_key=raw_key, raw_value=raw_value)

    def ntp(self, hostname="pan-fw-201"):
        """pan-fw-201's row: ONE configured server, on autokey, and a clock anchored to nothing.

        THIS IS THE P450 ROW. `server_count=1` matches PAN-SVC-001's `medium` calibration and
        `time_source_in_force` matches its `high` one, so one row matches two calibrations at
        different severities and `severity_basis` prints the `medium` query as the basis of a High
        grade - see `test_a_medium_query_is_printed_as_the_basis_of_a_high_grade`.

        THE FOUR PROVENANCE ROWS ARE THE STORED KEYS NO CONTROL CLAUSES ON, which is the whole of
        why this tab needs a sheet-level provenance cell (P451, the `saas-security` shape): the
        normalizer calls `write_node_row` WITH a provenance list and every field in it is a key
        the clause columns are computed FROM, so the default cell never reads one and prints
        "Not recorded" about a column the model declares derived.
        """
        row = NtpSettings.objects.create(
            primary_server="10.0.0.251", secondary_server="",
            server_count=1,
            primary_auth_type="autokey", secondary_auth_type="none",
            primary_algorithm="", secondary_algorithm="",
            all_servers_symmetric_key=False, unauthenticated_servers=[],
            synched_to_a_configured_server=False,
            time_source_in_force=TimeSourceInForce.NOT_SYNCHRONISED_OR_NEVER_READ,
            server_authentication_mechanism=(
                ServerAuthenticationMechanism.AUTOKEY),
            **self._common(hostname))
        local = FieldProvenance.ProvenanceType.LOCAL
        default = FieldProvenance.ProvenanceType.PAN_OS_DEFAULT
        self._provenance(row, "primary_server", local, "ntp-server-address", "10.0.0.251")
        self._provenance(row, "secondary_server", default, "ntp-server-address", "")
        self._provenance(row, "primary_auth_type", local, "authentication-type", "autokey")
        self._provenance(row, "secondary_auth_type", default, "authentication-type", "")
        return row

    def snmp(self, hostname="pan-fw-111"):
        """A v2c agent with the default community, reachable from nothing.

        `community_is_default` IS A STORED KEY AND CARRIES A REAL ROW - it is the one clause field
        on this tab that is not in `DERIVED_FIELDS`, which the orchestrator's brief had wrong -
        so the Provenance cell on a PAN-SVC-005 row has to reach `Local` and the four derived
        columns' `Derived` both.
        """
        row = SnmpSettings.objects.create(
            is_configured=True, version="v2c", version_implicit=False, uses_v2c=True,
            community_set=True, community_is_default=True,
            v3_user_count=0, v3_view_count=0,
            is_exposed=False, exposed_surfaces=[],
            answers_on_an_unauthenticated_version=True,
            default_community_exposure=(
                DefaultCommunityExposure.SET_AND_EVERY_SURFACE_REFUSES),
            snmp_version_in_force=SnmpVersionInForce.V2C,
            **self._common(hostname))
        local = FieldProvenance.ProvenanceType.LOCAL
        self._provenance(row, "community_is_default", local, "snmp-community-string", "public")
        self._provenance(row, "version", local, "version", "v2c")
        return row

    def identity_chosen_name_on_a_lease(self, hostname="pan-fw-111"):
        """pan-fw-111: a CHOSEN name on an appliance now set to take its name from its lease.

        THE ROW STAGE 8 RAISED A `needs_human` ABOUT. Stage 3 grades this rank, stage 6 expects
        PAN-SVC-010 to fire here, and stage 5's clause `hostname_is_factory_default eq true`
        excludes it by the rank's own premise - a chosen name is not the factory default. So
        PAN-SVC-010 draws NO row for this appliance, and the distinction it drops is carried by
        the `Name in force` cell on the rows PAN-SVC-007 and PAN-SVC-009 do draw. See
        `test_the_rank_pan_svc_010_drops_is_on_the_tab_beside_another_controls_verdict`.

        `addressing_mode` IS A STORED KEY AND CARRIES A REAL ROW - the only clause field in the
        domain where a mandatory reader would cost a provenance row, and the only one the
        sheet-level cell buys back.
        """
        row = SystemIdentity.objects.create(
            hostname="pan-fw-111", hostname_is_factory_default=False,
            timezone="UTC", timezone_is_utc=False,
            addressing_mode=SystemIdentity.AddressingMode.DHCP_CLIENT,
            addressing_mode_explicit=True,
            accept_dhcp_hostname=True, accept_dhcp_domain=False,
            hostname_in_force_known=True, hostname_in_force="pan-fw-111",
            hostname_posture=(
                HostnamePosture.CHOSEN_NAME_THE_LEASE_MAY_REPLACE),
            timezone_declares_zero_offset=False,
            timezone_offset_class=(
                TimezoneOffsetClass.ZERO_TODAY_BUT_NOT_DECLARED),
            addressing_mode_posture=(
                AddressingModePosture.LEASED_ON_A_HARDWARE_APPLIANCE),
            **self._common(hostname))
        local = FieldProvenance.ProvenanceType.LOCAL
        self._provenance(row, "addressing_mode", local, "type", "dhcp-client")
        self._provenance(row, "hostname", local, "hostname", "pan-fw-111")
        self._provenance(row, "timezone", local, "timezone", "UTC")
        return row

    def identity_no_name_stored(self, hostname="pan-fw-201"):
        """pan-fw-201: no `hostname` leaf at all, which is the only state PAN-SVC-010 fires on."""
        row = SystemIdentity.objects.create(
            hostname="", hostname_is_factory_default=True,
            timezone="", timezone_is_utc=False,
            addressing_mode=SystemIdentity.AddressingMode.STATIC,
            addressing_mode_explicit=False,
            accept_dhcp_hostname=False, accept_dhcp_domain=False,
            hostname_in_force_known=False, hostname_in_force="",
            hostname_posture=HostnamePosture.NO_NAME_STORED,
            timezone_declares_zero_offset=False,
            timezone_offset_class=TimezoneOffsetClass.NO_ZONE_RECORDED,
            addressing_mode_posture=AddressingModePosture.FIXED,
            **self._common(hostname))
        self._provenance(row, "hostname", FieldProvenance.ProvenanceType.PAN_OS_DEFAULT,
                         "hostname", "")
        return row

    def dns(self, hostname="pan-fw-111"):
        """No resolver chosen at all, on a leased management address."""
        return DnsSettings.objects.create(
            primary_resolver_address="", secondary_resolver_address="",
            dns_proxy_object_name="", encrypted_dns_connection_type="",
            resolver_mechanism=ResolverMechanism.NONE,
            chosen_resolver_count=0, resolution_follows_the_management_lease=True,
            management_resolvers_in_force=[],
            management_resolver_posture=(
                ManagementResolverPosture.NONE_ON_A_LEASED_ADDRESS),
            **self._common(hostname))

    def route(self, hostname="pan-fw-201", *, scope="device-local", vsys_name=""):
        """One `ServiceRoute` row. `scope` is the row's IDENTITY and is why this tab has its own
        provenance cell: it is stored, is not derived, carries no `FieldProvenance` row, and this
        model carries no `__entry__` row either, so the fourth case's usual remedy does not
        exist here. `ServiceRoute` is seeded with NO provenance rows at all, which is what the
        normalizers do."""
        device_local = scope == "device-local"
        return ServiceRoute.objects.create(
            scope=scope, vsys_name=vsys_name,
            services_originated=["dns", "ntp", "snmp-trap", "syslog", "update-server"],
            services_with_a_chosen_path=0 if device_local else 5,
            every_originated_service_has_a_chosen_path=not device_local,
            path_covers_both_address_families=False,
            service_path_posture=ServicePathPosture.NO_PATH_SET,
            per_system_path_choice_recorded=False,
            per_system_path_posture=PerSystemPathPosture.NEITHER_RECORDED,
            **self._common(hostname))

    def everything(self):
        self.ntp()
        self.snmp()
        self.identity_chosen_name_on_a_lease()
        self.identity_no_name_stored()
        self.dns()
        self.route()
        self.route(scope="vsys", vsys_name="vsys1", hostname="pan-fw-111")

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

    def cells(self, table, control_id, appliance):
        """Exactly one row for this control and this appliance, or an error.

        Reaching a row through `next` rather than by index is the second half of the empty-table
        guard: it RAISES on a table that does not hold the row rather than passing quietly.
        """
        index = table.headers.index
        return next(
            dict(zip(table.headers, row)) for row in table.rows
            if row[index("Control ID")] == control_id
            and row[index("Appliance")] == appliance)

    # ------------------------------------------------------------------ headings

    def test_no_heading_on_any_of_the_five_tabs_is_a_raw_django_field_name(self):
        """16 of 55 were, on the three tabs that shipped as stubs. This is the gate on that.

        A heading lives in `setting_labels`, which falls back to the raw field name when it has
        no entry - so declaring a column without a label IS choosing to show a database field
        name to a customer.
        """
        raw = {}
        for slug in SLUGS:
            table = build_findings_table(DOMAIN_BY_SLUG[slug].spec, tested=ALL_TESTED_COLUMNS)
            raw[slug] = [h for h in table.headers if "_" in h and h == h.lower()]

        self.assertEqual(raw, {slug: [] for slug in SLUGS})

    def test_the_settings_columns_come_out_in_stage_5s_clause_order(self):
        """The one structural property with no gate behind it. See `ORDER`."""
        for slug in SLUGS:
            with self.subTest(slug=slug):
                table = build_findings_table(
                    DOMAIN_BY_SLUG[slug].spec, tested=ALL_TESTED_COLUMNS)
                first = table.headers.index("Template") + 1
                last = table.headers.index("Matched queries")

                self.assertEqual(table.headers[first:last], ORDER[slug])

    def test_both_new_tab_titles_fit_the_workbooks_31_character_cap(self):
        """A sheet title over 31 characters truncates SILENTLY, because that is Excel's cap on a
        sheet name - and `probe.surface_for` prints the untruncated title, so the tool and the
        workbook disagree and the tool looks right."""
        for slug in SLUGS:
            with self.subTest(slug=slug):
                self.assertLessEqual(len(DOMAIN_BY_SLUG[slug].spec.sheet_title), 31)

        self.assertEqual(DOMAIN_BY_SLUG["dns-settings"].spec.sheet_title, "DNS Settings")
        self.assertEqual(DOMAIN_BY_SLUG["service-routes"].spec.sheet_title, "Service Routes")

    def test_scope_is_presented_once_as_identity_and_not_twice(self):
        """`Scope` names `field="scope"`, so `setting_columns` seeds its `seen` set with it and
        derives no second column of the same name. A table with a duplicate header is rejected by
        Excel and xlsxwriter drops it, leaving a sheet of stray cells - and because the two
        headings would DIFFER, the duplicate-header guard would never fire."""
        table = build_findings_table(
            DOMAIN_BY_SLUG["service-routes"].spec, tested=ALL_TESTED_COLUMNS)

        self.assertEqual(table.headers.count("Scope"), 1)
        self.assertNotIn("scope", table.headers)
        self.assertEqual(len(table.headers), len(set(table.headers)))

    def test_no_sheet_claims_a_field_is_presented_through_hidden_fields(self):
        """`check_every_tested_field_is_presented` counts a field as presented if a subject
        column, a settings column, OR the sheet's own `hidden_fields` carries it - so a non-empty
        `hidden_fields` is a CLAIM accepted as proof, and it is the only known cause of a findings
        row that marks nothing as the thing to fix (P409). All five declare it empty, so the gate
        passes on real columns."""
        for slug in SLUGS:
            with self.subTest(slug=slug):
                self.assertEqual(DOMAIN_BY_SLUG[slug].spec.hidden_fields, ())

    def test_every_tab_carries_fires_when_as_well_as_provenance(self):
        """`tested_columns` defaults to `('Provenance',)`, which silently DROPS `Fires when` from
        the workbook while the live page keeps it, so the two surfaces disagree about which cell a
        reader meets (P427)."""
        for slug in SLUGS:
            with self.subTest(slug=slug):
                self.assertEqual(DOMAIN_BY_SLUG[slug].spec.tested_columns, ALL_TESTED_COLUMNS)

    # ------------------------------------------------------------------ the twelve readers

    def test_every_choices_column_prints_its_english_label_and_not_its_stored_key(self):
        """THE TWELVE READERS, pinned by what they print.

        Without a reader each of these cells prints the STORED KEY - `not_synchronised_or_never_
        read`, `dhcp-client`, `v2c` - because nothing in the sheets layer calls
        `get_<field>_display()` (P457). Nothing gates it, so this is the gate.
        """
        self.everything()

        ntp = self.cells(self.table("ntp"), "PAN-SVC-001", "pan-fw-201")
        self.assertEqual(ntp["Time source in force"], "Not synchronised, or never read")
        ntp2 = self.cells(self.table("ntp"), "PAN-SVC-002", "pan-fw-201")
        self.assertEqual(ntp2["Authentication Type"], "Autokey")

        snmp = self.cells(self.table("snmp"), "PAN-SVC-004", "pan-fw-111")
        self.assertEqual(snmp["SNMP version in force"], "The cleartext version")
        self.assertEqual(snmp["Default community exposure"], "Set, and every surface refuses")

        identity = self.cells(self.table("system-identity"), "PAN-SVC-007", "pan-fw-111")
        self.assertEqual(identity["Management Interface IP Type"], "DHCP client")
        self.assertEqual(identity["Management addressing posture"],
                         "Leased, on a hardware appliance")
        self.assertEqual(identity["Time Zone offset"], "Zero offset today, but not declared")
        self.assertEqual(
            identity["Name in force"],
            "A chosen name on a device that may take its name from the lease")

        dns = self.cells(self.table("dns-settings"), "PAN-SVC-003", "pan-fw-111")
        self.assertEqual(dns["Management resolver posture"],
                         "No resolver chosen, on a leased management address")

        route = self.cells(self.table("service-routes"), "PAN-SVC-006", "pan-fw-201")
        self.assertEqual(route["Firewall-wide path posture"], "No path set for a sensitive service")
        # `customized` IS OptivEdgeIntegrations' OWN CHOICES LABEL - see
        # `integrations.models.device_services` - which the 2026-11-09 spelling sweep did not
        # reach. Asserted as the code spells it rather than as the deliverable should.
        self.assertEqual(route["Virtual system path posture"],
                         "Neither inheritance nor a customized path recorded")
        # The subject lambda, not a `value_reader`: an identity column can call the display
        # method without paying the reader's price.
        self.assertEqual(route["Scope"], "The firewall-wide paths")

    def test_no_reader_is_declared_on_a_field_that_has_no_choices(self):
        """THE FATAL HALF OF THE SAME RULE, and the one that ships a 500 rather than a wrong word.

        `get_<field>_display()` exists ONLY on a field that declares `choices`; on the
        `BooleanField` beside it the call raises `AttributeError` at TEMPLATE RENDER, past
        `django check` and past all three cross-domain gates (P462). Eleven of this domain's 23
        clause fields are booleans or counts and sit on the same rows as the twelve that are not.
        """
        for slug in SLUGS:
            spec = DOMAIN_BY_SLUG[slug].spec
            model = spec.subject_model(spec.kind_for(spec.control_types[0]))
            for field in spec.value_readers:
                with self.subTest(slug=slug, field=field):
                    self.assertTrue(
                        model._meta.get_field(field).choices,
                        f"{model.__name__}.{field} has no `choices`, so a reader calling "
                        f"get_{field}_display() raises AttributeError at template render")

    def test_a_firewall_wide_row_reads_an_em_dash_for_the_virtual_system_it_does_not_have(self):
        """`layout.NONE` is U+2014 EM DASH. A firewall-wide row does not HAVE a virtual system
        rather than having an empty one, and that is the one state `display_value` cannot say:
        it would print `(empty)` and the value-at-fault fill can then offer `(empty)` as the
        remedy."""
        self.everything()
        table = self.table("service-routes")

        self.assertEqual(self.cells(table, "PAN-SVC-006", "pan-fw-201")["Virtual system"], NONE)
        self.assertEqual(NONE, "—")

    # ------------------------------------------------------------------ the provenance cell

    def test_the_provenance_cell_reaches_the_two_stored_keys_the_default_cannot(self):
        """BOTH CELLS, ON BUILT ROWS, PER TAB AND PER CONTROL - `build_rows` hands the cell the
        clause fields of the ROW'S OWN control, not the tab's, so the distinct answers appear
        ACROSS rows and never meet in one cell.

        The default prints "Not recorded" somewhere on every row of all five tabs, about columns
        the models declare derived (P451, the `saas-security` shape): these normalizers call
        `write_node_row` WITH a provenance list and every field in it is a stored key the clause
        columns are computed FROM rather than a field a control clauses on.
        """
        self.everything()

        self.assertEqual(
            self.cells(self.table("ntp"), "PAN-SVC-001", "pan-fw-201")["Provenance"], "Derived")
        # `community_is_default` is STORED and carries a real row. A constant "Derived" cell
        # would print a falsehood about it here.
        self.assertEqual(
            self.cells(self.table("snmp"), "PAN-SVC-005", "pan-fw-111")["Provenance"],
            "Derived\nLocal")
        # PAN-SVC-004's three clause fields are all derived, on the SAME TAB and the same
        # appliance. This is the per-control half.
        self.assertEqual(
            self.cells(self.table("snmp"), "PAN-SVC-004", "pan-fw-111")["Provenance"], "Derived")
        # `addressing_mode` is STORED. The reader marks it `stored=False`, so the per-field cell
        # loses the row and falls back to the reader's own prose - and this cell reads the index
        # directly and keeps it.
        self.assertEqual(
            self.cells(self.table("system-identity"), "PAN-SVC-007", "pan-fw-111")["Provenance"],
            "Local\nDerived")
        self.assertEqual(
            self.cells(self.table("system-identity"), "PAN-SVC-009", "pan-fw-111")["Provenance"],
            "Derived")
        self.assertEqual(
            self.cells(self.table("dns-settings"), "PAN-SVC-003", "pan-fw-111")["Provenance"],
            "Derived")

    def test_the_service_route_cell_says_nothing_about_the_rows_own_identity(self):
        """`scope` is the FOURTH provenance case - stored, not derived, not reader-only, and
        carrying no `FieldProvenance` row - and `ServiceRoute` carries no `__entry__` row either,
        so `provenance_of("__entry__")` buys nothing and the fourth case's usual remedy does not
        apply. The remedy is that `scope` is identity, presented by a subject column, and the
        Provenance column answers about the values a control TESTED."""
        self.everything()

        self.assertEqual(
            self.cells(self.table("service-routes"), "PAN-SVC-006", "pan-fw-201")["Provenance"],
            "Derived")
        # The generic cell, for contrast: it would print "Not recorded" about the row's own scope.
        route = ServiceRoute.objects.get(scope="device-local")
        self.assertEqual(
            device_services.provenance_cell(
                route, lambda _f: None, [("scope", True)]),
            "Not recorded")

    # ------------------------------------------------------------------ severity and the mark

    def test_a_medium_query_is_printed_as_the_basis_of_a_high_grade(self):
        """P450, ON THE MEASURED ESTATE AND NOT FORCED. PAN-SVC-001 grades on TWO independent
        column sets - `server_count` (`high` for none, `medium` for one-and-no-second) and
        `synched_to_a_configured_server`/`time_source_in_force` (`high` and `medium`) - so an
        appliance with one configured server whose clock is anchored to nothing the configuration
        names matches a `medium` and a `high` at once. `findings.py:510-524` collects every
        matched calibration carrying an adjusted severity, grades on the MAXIMUM, and prints them
        ALL, so the `medium` query is named as the basis of a High grade.

        The sufficient condition is two matched calibrations at DIFFERENT severities on one row,
        however achieved. PAN-SVC-005 and PAN-SVC-007 also carry spreads and neither is
        reachable: their calibrations sit on one mutually exclusive classification column each
        (`default_community_exposure`, `addressing_mode_posture`), so one row can match only one.
        """
        self.everything()
        row = self.cells(self.table("ntp"), "PAN-SVC-001", "pan-fw-201")

        self.assertEqual(row["Severity"], "High")
        self.assertEqual(row["Severity basis"],
                         "Adjusted to High by:\n"
                         "One configured time source and no second\n"
                         "The clock is anchored to nothing the configuration names")
        self.assertEqual(row["Matched queries"],
                         "Baseline\n"
                         "One configured time source and no second\n"
                         "The clock is anchored to nothing the configuration names")

    def test_the_two_controls_with_a_spread_on_one_column_cannot_reach_it(self):
        """The other half of the claim above, as a structural check rather than an observation:
        a classification column holds exactly one of its members, so calibrations that each name a
        different member of the SAME column are mutually exclusive on one row."""
        from assessments.models import Control

        for control_id, column in (("PAN-SVC-005", "default_community_exposure"),
                                   ("PAN-SVC-007", "addressing_mode_posture")):
            with self.subTest(control_id=control_id):
                control = Control.objects.get(control_id=control_id)
                graded = [q for q in control.queries.all()
                          if q.is_active and q.adjusted_severity]
                naming = [q for q in graded
                          if any(c.get("field") == column
                                 for c in q.canonical_query.get("clauses", []))]

                self.assertEqual(len(naming), len(graded))
                self.assertGreater(len(graded), 1)

    def test_every_row_marks_something_as_the_value_at_fault(self):
        """`implicated` marks the fields the MATCHED queries assert on, read from
        `ControlQuery.asserted_fields`, and falls back to every tested field only where that list
        is empty. Measured over the shipped catalog 2026-11-03: all 33 PAN-SVC queries carry
        `asserted_fields`, so no row on these tabs takes the fallback - and no row is unmarked,
        which is the thing a non-empty `hidden_fields` would have cost."""
        self.everything()
        for slug in SLUGS:
            with self.subTest(slug=slug):
                table = self.table(slug)
                marked = {row for row, _column in table.implicated}

                self.assertEqual(marked, set(range(len(table.rows))))

    def test_the_rank_pan_svc_010_drops_is_on_the_tab_beside_another_controls_verdict(self):
        """STAGE 8's SECOND `needs_human`, answered by measurement.

        Stage 3 grades "a chosen name on a device that may take its name from the lease"; stage 6
        expects PAN-SVC-010 to fire on that appliance; and stage 5's clause
        `hostname_is_factory_default eq true` excludes it, because a chosen name is not the
        factory default. So PAN-SVC-010 draws NO row for pan-fw-111.

        What this tab DOES show: `setting_columns` fills every settings column for every row of
        the matching model, not only the columns of the row's own control, so `Name in force`
        carries the dropped rank on the PAN-SVC-007 and PAN-SVC-009 rows the appliance does draw.
        The distinction is on the tab and is attached to somebody else's verdict - a reader who
        filters this tab to PAN-SVC-010 never sees it. Nothing presentation can declare fixes
        that; it needs the second assertion record stage 8 proposed, which is stage 5's to write.
        """
        self.everything()
        table = self.table("system-identity")
        index = table.headers.index

        self.assertEqual(
            [], [row for row in table.rows
                 if row[index("Control ID")] == "PAN-SVC-010"
                 and row[index("Appliance")] == "pan-fw-111"])

        for control_id, severity in (("PAN-SVC-007", "Medium"), ("PAN-SVC-009", "Low")):
            with self.subTest(control_id=control_id):
                row = self.cells(table, control_id, "pan-fw-111")

                self.assertEqual(row["Severity"], severity)
                self.assertEqual(row["Hostname is the factory default"], "No")
                self.assertEqual(
                    row["Name in force"],
                    "A chosen name on a device that may take its name from the lease")

    # ------------------------------------------------------------------ the rail and the pages

    def test_both_new_models_reach_a_results_page_and_a_findings_tab(self):
        """A rail item with a `search_model` is a PROMISE of a findings page: 73 of 73 carry one
        and every one has a findings domain, so there is no explorer-page-only state."""
        rail = {item.search_model: item for item in nav.CONFIG_OBJECTS}

        for model, slug in (("integrations.DnsSettings", "dns-settings"),
                            ("integrations.ServiceRoute", "service-routes")):
            with self.subTest(model=model):
                self.assertIn(model, rail)
                self.assertEqual(rail[model].slug, slug)
                self.assertIn(slug, cr.RESULTS)
                self.assertIn(slug, DOMAIN_BY_SLUG)

    def test_the_prefix_does_not_outlive_this_artifact(self):
        """Clearing the exemption is part of this stage's job rather than a side effect of it: an
        exemption that survives the work it was waiting for is a permanent hole, and clearing it
        is also what FORCES the two rail entries - `test_every_query_in_the_shipped_catalog_has_
        somewhere_to_go` iterates the seed payload and never consults `is_active`."""
        self.assertNotIn("PAN-SVC", cr.AWAITING_PRESENTATION)
        self.assertNotIn("PAN-SVC-", cr.AWAITING_PRESENTATION)

    def test_every_rail_icon_this_domain_names_is_one_of_the_vendored_files(self):
        """`ConfigObject.icon` is UNVALIDATED and a name that is not there raises
        `FileNotFoundError` at TEMPLATE RENDER on every explorer page - so one wrong name takes
        out every explorer test, for every rail item, with not one test name mentioning an icon.
        The nineteen files are in the OptivEdge HOST repo, not in this one, so this asserts
        against the set this run enumerated rather than against the filesystem."""
        vendored = {
            "book-marked", "chevron-right", "circle-question-mark", "clipboard-check",
            "download", "eye", "flag", "layout-dashboard", "list-checks", "monitor", "plus",
            "refresh-cw", "server", "settings", "shield", "trash-2", "triangle-alert",
            "wand-sparkles", "x"}

        for slug in ("ntp", "snmp", "system-identity", "dns-settings", "service-routes"):
            item = next(i for i in nav.CONFIG_OBJECTS if i.slug == slug)
            with self.subTest(slug=slug):
                self.assertIn(item.icon, vendored)

    def test_every_query_field_on_the_two_new_pages_is_a_registered_search_field(self):
        """Stored, searchable and REGISTERED are three different things. A heading mapped to an
        unregistered field points the "build a query from these rows" button at a lookup that
        refuses itself or silently matches nothing."""
        from assessments.search.dns_settings import compiler as dns_compiler
        from assessments.search.service_route import compiler as route_compiler

        for slug, compiler in (("dns-settings", dns_compiler),
                               ("service-routes", route_compiler)):
            with self.subTest(slug=slug):
                self.assertTrue(set(cr.RESULTS[slug].query_fields.values())
                                <= set(compiler.FIELD_OPERATOR_REGISTRY))

    def test_the_two_new_results_rows_render_over_real_objects(self):
        """The shipped squareness check cannot exercise a `row` lambda over a real row, and these
        two call `get_<field>_display()` and walk a JSON list."""
        self.dns()
        self.route()
        self.route(scope="vsys", vsys_name="vsys1", hostname="pan-fw-111")

        dns_spec = cr.RESULTS["dns-settings"]
        row = dns_spec.row(dns_spec.base_queryset().get())
        self.assertEqual(len(row), len(dns_spec.columns))
        self.assertEqual(row[1], "Nothing")
        self.assertEqual(row[2], "no resolver chosen")
        self.assertEqual(row[3], "No resolver chosen, on a leased management address")

        route_spec = cr.RESULTS["service-routes"]
        rows = [route_spec.row(r) for r in route_spec.base_queryset()]
        self.assertEqual({len(r) for r in rows}, {len(route_spec.columns)})
        device_local = next(r for r in rows if r[1] == "The firewall-wide paths")
        self.assertEqual(device_local[2], NONE)
        self.assertEqual(device_local[3], "0 of 5 with a chosen path")
        self.assertEqual(device_local[4], "No path set for a sensitive service")
        vsys = next(r for r in rows if r[1] == "One virtual system's own set")
        self.assertEqual(vsys[2], "vsys1")
        self.assertEqual(vsys[4], "Neither inheritance nor a customized path recorded")

    # ------------------------------------------------------------------ the description

    def test_the_ntp_description_no_longer_denies_a_clause_the_catalogue_ships(self):
        """The shipped description told a customer "Whether a configured server is reachable or
        synchronized is not assessed - that is live device state, not configuration", while
        PAN-SVC-001's third and fourth calibrations clause on `synched_to_a_configured_server`
        and `time_source_in_force`, one of them graded `high`, and both are drawn columns on this
        tab. The catalog says which half was wrong, in its own words: PAN-SVC-001's description
        carries "AND SYNCHRONIZATION IS NOW ASSESSED, which this paragraph said it was not until
        2026-11-01"."""
        description = DOMAIN_BY_SLUG["ntp"].spec.description

        self.assertNotIn("not assessed", description)
        self.assertIn("anchored to a server this configuration names", description)
