"""The `management-services` domain's eight findings tabs, and every cell on them that was a
judgement.

Stage 9 of the OptivEdgeProbe pipeline, domain `management-services`, 2026-11-03 - run 28 of 28,
and the run that empties `AWAITING_PRESENTATION`. SIX of the eight tabs already existed, which no
other domain has inherited, and FOUR of those six are shared with another domain's controls - so
most of what this file pins is a heading or a cell that somebody else's rows now carry.

EVERY TABLE IN THIS FILE GOES THROUGH `self.table()`, WHICH CALLS THE FINDING RUN AND THEN ASSERTS
THE TABLE IS NON-EMPTY. `build_findings_table` LOADS a domain's findings rather than computing
them, and its only row-count guard compares the rows it built against what the DATABASE holds - so
with no findings generated both sides are zero, nothing raises, the HEADINGS still come out right
because they derive from the controls, and every assertion written `for row in table.rows:`
iterates nothing and passes. That has already shipped once, in
`test_platform_lifecycle_presentation`. The helper makes it impossible here, and it is called in
the tests that need rows rather than in `setUp`, so the heading tests do not pay a finding run.

THE SUBJECT ROWS ARE WRITTEN DIRECTLY RATHER THAN NORMALISED, which is the house pattern and is
deliberate: the normalisers are stage 7's and have their own tests, and the stage 6 payloads live
in another repository and are gitignored. EVERY VALUE AND EVERY PROVENANCE TYPE BELOW IS THE ONE
THE COMMITTED NORMALISERS PRODUCED for the appliance named beside it when this run built the
domain's estate from `stage6-management-services.json`, transcribed by hand.

AND THAT ESTATE COULD NOT BE BUILT BY THE COMMITTED SEEDER, which is why the values are transcribed
rather than regenerated here. `print_findings_table` reconciled 20 of 42 verdicts and the estate it
builds for this domain is ALL DEFAULTS, for two reasons recorded in this run's stage 9 artifact: it
places each subject's `read_back` AT the subject's xpath where this artifact's keys are relative to
the xpath's PARENT, and `_estate._descend` replaces a scalar child with an empty dict, discarding a
leaf's value whenever `@ptpl`/`@src` are placed under it afterwards. With both corrected the estate
reproduces 23 of stage 8's 24 finding verdicts exactly, on severity AND on matched query names.

THE FOUR `choices` COLUMNS ARE PINNED BY THEIR ENGLISH LABELS, which is the point of them: nothing
in the sheets layer calls `get_<field>_display()`, so a `choices` field prints its STORED KEY
without a reader (P457) - and the same call on the `BooleanField` beside it raises `AttributeError`
at TEMPLATE RENDER, past `django check` and past all three cross-domain gates (P462). Both halves
are invisible to every gate, so the labels are asserted here or nowhere.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone

from assessments import configuration_navigation as nav
from assessments import configuration_results as cr
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets.findings import (
    ALL_TESTED_COLUMNS, build_findings_table)
from assessments.finding_run import regenerate_findings
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ApplianceOperationalMode, InterfaceManagementProfile, LoginBanner,
    ManagementPlaneAddressing, ManagementSshSettings, ManagementStation, ManagementTlsBinding,
    Snapshot, UpdateServerSettings)
from optivedge_integrations.integrations.models.provenance import FieldProvenance

#: The controls seeded here, and STATED because every heading and column count below is a function
#: of it: `setting_columns` derives a column per clause field of the controls PRESENT in the build,
#: so a shared tab's denominator is whatever was seeded. This list is this domain's twelve plus the
#: six that share the `Management SSH and TLS` tab, which is what makes the crypto assertions below
#: the real tab rather than a slice of it.
#:
#: PAN-MGT-005 IS ABSENT AND SHIPS NOTHING, and it is not PAN-SVC-008's shape: a standing ruling of
#: Jason's dated 2026-08-31 in `scratch/control-changes.json` DROPPED it - "Fully decomposes into
#: controls that now span all planes" - its two clauses becoming PAN-MGT-001, -002 and -003, and
#: its number stays retired rather than being reused, which is why 013 follows 012.
#: THE PAN-LOG AND PAN-MCR IDS ARE HERE BECAUSE OF WHAT HAPPENED WITHOUT THEM. The first version
#: of this list held this domain's twelve alone, and
#: `test_pan_mgt_011s_column_is_eleventh_on_a_tab_this_domain_does_not_own` then measured ONE
#: settings column on the Logging and Reporting tab rather than eleven - which is the denominator
#: rule proving itself on this file: a shared tab shows only the columns of the controls seeded,
#: so a count taken over this domain's controls alone is not the tab a customer meets.
SEEDED = ["PAN-MGT-001", "PAN-MGT-002", "PAN-MGT-003", "PAN-MGT-004", "PAN-MGT-006",
          "PAN-MGT-007", "PAN-MGT-008", "PAN-MGT-009", "PAN-MGT-010", "PAN-MGT-011",
          "PAN-MGT-012", "PAN-MGT-013",
          "PAN-CRT-006", "PAN-MCR-001", "PAN-MCR-002", "PAN-MCR-003", "PAN-MCR-004",
          "PAN-MCR-005",
          "PAN-LOG-001", "PAN-LOG-003", "PAN-LOG-004", "PAN-LOG-006", "PAN-LOG-007",
          "PAN-LOG-008", "PAN-LOG-009", "PAN-LOG-010",
          "PAN-UID-005"]

#: The nineteen vendored icon files, enumerated 2026-11-03 at
#: `OptivEdge/src/optivedge/templates/components/icons/` - the HOST repo and not this one, so this
#: asserts against the enumerated set rather than against a filesystem this repo cannot assume.
VENDORED_ICONS = {
    "book-marked", "chevron-right", "circle-question-mark", "clipboard-check", "download", "eye",
    "flag", "layout-dashboard", "list-checks", "monitor", "plus", "refresh-cw", "server",
    "settings", "shield", "trash-2", "triangle-alert", "wand-sparkles", "x"}

#: Every tab a PAN-MGT control reaches, measured with `probe.surface_for` per control rather than
#: taken from a control-type lookup.
MY_TABS = ("management-interfaces", "login-banner", "update-server", "management-crypto",
           "interface-management-profiles", "logging-settings",
           "management-addressing", "operational-mode")

#: THE SETTINGS COLUMNS OF THE TWO NEW TABS, IN THE ORDER A BUILT TABLE PUTS THEM: the baseline's
#: clauses in stage 5's clause order, then each non-baseline query's clauses ALPHABETICALLY BY
#: QUERY NAME, then the next control by `control_id`. NOTHING IN EITHER REPOSITORY GATES THIS
#: ORDER and `auto_setting_columns` is all or nothing, so this is the gate.
NEW_TAB_ORDER = {
    "management-addressing": ["Exposure the addressing creates"],
    "operational-mode": ["Running an approved cryptographic mode", "Mode the appliance reports"],
}


class ManagementServicesPresentationTests(TestCase):

    maxDiff = None

    def setUp(self):
        seed_controls(SEEDED)
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="20.185.152.225")
        self.points = {}
        self.snapshots = {}
        for serial, hostname in (("013201001085", "pan-fw-1085"),
                                 ("013201001475", "pan-fw-1475"),
                                 ("6A9C0A9904E7D6E", "pan-fw-7d6e")):
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

    # ------------------------------------------------------------------ helpers

    def _common(self, hostname):
        group, appliance = self.points[hostname]
        return dict(management_station=self.station, appliance=appliance, appliance_group=group,
                    source_snapshot=self.snapshots[hostname])

    def _provenance(self, row, field, kind, raw_key="", raw_value=""):
        FieldProvenance.objects.create(
            content_type=ContentType.objects.get_for_model(type(row)), object_id=row.pk,
            field_name=field, provenance_type=kind, raw_key=raw_key, raw_value=raw_value)

    def table(self, slug):
        """THE ONLY WAY A TEST IN THIS FILE REACHES A ROW.

        Calls the finding run itself rather than trusting something else to have done it, and
        refuses an empty table - because an empty one passes every `for row in table.rows:`
        assertion silently while its headings still come out correct.
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

    # ------------------------------------------------------------------ fixtures

    def addressing_no_address(self, hostname="pan-fw-1085"):
        """THE ROW THAT ARGUED AGAINST ITS OWN FINDING, before this run's reader branch.

        Stage 6 records NO addressing subject for this appliance at all - only
        `server-verification`, an absent `type` node and `service` - so the normaliser resolves the
        allocation mode to the measured default `static`, stores no address and no gateway, and
        `address_is_globally_routable("")` answers True, which is the default that FIRES. The
        posture therefore resolves to `routable_address` and the cell asserted a globally routable
        address about an appliance whose configuration holds none.
        """
        row = ManagementPlaneAddressing.objects.create(
            allocation_mode=ManagementPlaneAddressing.AllocationMode.STATIC,
            management_ip_address=None, static_default_gateway=None,
            address_is_globally_routable=True,
            exposure_posture=ManagementPlaneAddressing.POSTURE_ROUTABLE,
            **self._common(hostname))
        default = FieldProvenance.ProvenanceType.PAN_OS_DEFAULT
        absent = FieldProvenance.ProvenanceType.NOT_CONFIGURED
        self._provenance(row, "allocation_mode", default, "type", "static")
        self._provenance(row, "management_ip_address", absent, "ip-address", "")
        self._provenance(row, "static_default_gateway", absent, "default-gateway", "")
        return row

    def addressing_private_with_route(self, hostname="pan-fw-1475"):
        """A private address an administrator wrote, with a static default gateway beside it.

        The one PAN-MGT-004 row in the estate that fires through a CALIBRATION, so its severity is
        High rather than the control's critical default and `severity_basis` names the query.
        """
        row = ManagementPlaneAddressing.objects.create(
            allocation_mode=ManagementPlaneAddressing.AllocationMode.STATIC,
            management_ip_address="192.168.250.2", static_default_gateway="192.168.250.1",
            address_is_globally_routable=False,
            exposure_posture=ManagementPlaneAddressing.POSTURE_PRIVATE_WITH_ROUTE,
            **self._common(hostname))
        default = FieldProvenance.ProvenanceType.PAN_OS_DEFAULT
        local = FieldProvenance.ProvenanceType.LOCAL
        self._provenance(row, "allocation_mode", default, "type", "static")
        self._provenance(row, "management_ip_address", local, "ip-address", "192.168.250.2")
        self._provenance(row, "static_default_gateway", local, "default-gateway", "192.168.250.1")
        return row

    def addressing_dhcp(self, hostname="pan-fw-7d6e"):
        """A DHCP-addressed plane: the configuration holds NEITHER address nor gateway.

        THE SECOND OF THE TWO NULLS. Here the null is a measured state rather than an unread one -
        the firewall genuinely stores no address under DHCP - and the appliance may still be routed
        off its segment, which is the trap stage 3 named: a reading that reported "no default route
        on the management port" here would report this control's PREFERRED state about a device
        that has a default route.

        Stage 8 raised a `needs_human` about this row's SEVERITY, not its existence: stage 3
        withheld a rank for the dynamic class, no calibration matches, and
        `derive_control_query_severity_value` falls back to the control's own critical default. The
        `Severity basis` cell is what keeps that legible - it reads "Control default" rather than
        naming a query.
        """
        row = ManagementPlaneAddressing.objects.create(
            allocation_mode=ManagementPlaneAddressing.AllocationMode.DHCP_CLIENT,
            management_ip_address=None, static_default_gateway=None,
            address_is_globally_routable=True,
            exposure_posture=ManagementPlaneAddressing.POSTURE_DYNAMIC,
            **self._common(hostname))
        local = FieldProvenance.ProvenanceType.LOCAL
        absent = FieldProvenance.ProvenanceType.NOT_CONFIGURED
        self._provenance(row, "allocation_mode", local, "type", "dhcp-client")
        self._provenance(row, "management_ip_address", absent, "ip-address", "")
        self._provenance(row, "static_default_gateway", absent, "default-gateway", "")
        return row

    def mode_never_read(self, hostname="pan-fw-1085"):
        """No operational read was taken, so the mode is empty and the verdict fires.

        NO `FieldProvenance` ROW OF ANY KIND, and that is the normaliser's deliberate choice rather
        than an omission in this fixture: `management_plane.py` passes `provenance=()` and explains
        that `classify_prov_type`'s fallthrough would label a runtime reading `local`, "defined on
        this device", which is the one thing it is not.
        """
        return ApplianceOperationalMode.objects.create(
            operational_mode="", approved_cryptography_mode=False, **self._common(hostname))

    def mode_normal(self, hostname="pan-fw-7d6e"):
        """The appliance answered `normal`, which is itself the NON-approved value."""
        return ApplianceOperationalMode.objects.create(
            operational_mode="normal", approved_cryptography_mode=False,
            **self._common(hostname))

    def banner_absent(self, hostname="pan-fw-1475"):
        """No banner and no acknowledgement: both of PAN-MGT-007's and -008's rows fire here.

        THE ONE TAB IN THE PIPELINE WHERE THE DEFAULT PROVENANCE CELL IS ALREADY HONEST.
        `LoginBanner` declares `DERIVED_FIELDS` EMPTY, both clause fields are stored, and both
        carry a real row - so the default reads what was recorded rather than walking anywhere.
        The acknowledgement key on this appliance came from a TEMPLATE, which is the one answer on
        this tab that a constant cell would have destroyed.
        """
        row = LoginBanner.objects.create(
            text="", acknowledgement_required=False, **self._common(hostname))
        default = FieldProvenance.ProvenanceType.PAN_OS_DEFAULT
        template = FieldProvenance.ProvenanceType.TEMPLATE
        self._provenance(row, "text", default, "login-banner", "")
        self._provenance(row, "acknowledgement_required", template, "ack-login-banner",
                         "ptpl_fw-core-tpa")
        return row

    def update_server_unverified(self, hostname="pan-fw-1085"):
        """`server-verification: no`, written locally - the one PAN-MGT-009 finding in the estate."""
        row = UpdateServerSettings.objects.create(
            verify_identity=False, **self._common(hostname))
        self._provenance(row, "verify_identity", FieldProvenance.ProvenanceType.LOCAL,
                         "server-verification", "no")
        return row

    def unused_profile(self, name="oep-mgt6-p01", hostname="pan-fw-7d6e",
                       exposure="unencrypted_administrative_login"):
        """A profile bound to NO interface, and what attaching it would permit.

        `oep-mgt6-p01` enables telnet and http, so attaching it would permit an unencrypted
        administrative login in one action - the `medium` calibration, which is the rank stage 3
        gave that class and the reason this row reports above PAN-MGT-013's own `low` default.
        """
        row = InterfaceManagementProfile.objects.create(
            name=name, bound_interface_count=0, bound_interface_names=[],
            unbound_exposure_class=exposure, **self._common(hostname))
        self._provenance(row, "__entry__", FieldProvenance.ProvenanceType.LOCAL,
                         f"entry[@name='{name}']", name)
        return row

    def tls_binding_unbound(self, hostname="pan-fw-1085"):
        """Nothing bound, so the web interface is served under whatever the device falls back to.

        THE ROW WHOSE STATED CONDITION IS NOT THE ONE IT MET. It matches only the calibration
        `No transport-security configuration bound`, and `fires_when` renders the BASELINE's
        condition alone - `profile_name is not empty and floor_below_minimum = Yes` - which this
        row does not meet. Recorded in this run's stage 9 artifact against
        `argued_against_itself`; `Matched queries` and the marked cell are what resolve it.
        """
        row = ManagementTlsBinding.objects.create(
            profile_name="", profile_scope="", floor_below_minimum=True, **self._common(hostname))
        self._provenance(row, "profile_name", FieldProvenance.ProvenanceType.NOT_CONFIGURED,
                         "ssl-tls-service-profile", "")
        return row

    def ssh_defaults(self, hostname="pan-fw-1085"):
        """Nothing bound, so the SSH offer is the DEVICE DEFAULT on every list.

        THE ROWS THE CRYPTO PROVENANCE CELL EXISTS FOR. `ciphers`, `kex` and `macs` each carry a
        real `FieldProvenance` row reading `pan_os_default`, while the verdicts computed from them
        are declared derived and carry none - so before this run's cell the Provenance column read
        "Not recorded" over three fields with a perfectly good location, which is the opposite of
        what that word means.
        """
        row = ManagementSshSettings.objects.create(
            profile_name="", profile_found=False,
            ciphers=[], kex=[], macs=[],
            ciphers_default=True, kex_default=True, macs_default=True, defaults_measured=True,
            ciphers_below_preferred=True, kex_below_preferred=True, macs_below_preferred=True,
            non_preferred_ciphers=[], non_preferred_kex=[], non_preferred_macs=[],
            host_key_type="", rekey_interval_seconds=None,
            **self._common(hostname))
        default = FieldProvenance.ProvenanceType.PAN_OS_DEFAULT
        absent = FieldProvenance.ProvenanceType.NOT_CONFIGURED
        for field in ("ciphers", "kex", "macs"):
            self._provenance(row, field, default, field, "")
        self._provenance(row, "profile_name", absent, "ssh-service-profile", "")
        self._provenance(row, "host_key_type", absent, "host-key-type", "")
        self._provenance(row, "rekey_interval_seconds", absent, "rekey-interval", "")
        return row

    # ------------------------------------------------- the two new surfaces exist and are complete

    def test_both_new_models_reach_a_rail_item_a_results_page_and_a_findings_tab(self):
        """A rail item with a `search_model` is a PROMISE OF A FINDINGS PAGE and nothing says so
        until two anonymous tests fail: `views.findings_href_for` resolves through
        `domain_for_model` and both object templates require it. Measured over the whole rail:
        there is no precedent for an exception and `search_model=""` is a state no object is in."""
        for slug, model in (("management-addressing", "integrations.ManagementPlaneAddressing"),
                            ("operational-mode", "integrations.ApplianceOperationalMode")):
            with self.subTest(slug=slug):
                item = next(i for i in nav.CONFIG_OBJECTS if i.slug == slug)
                self.assertEqual(item.search_model, model)
                self.assertTrue(item.where.strip(), "a rail item with no path cannot be acted on")
                self.assertIn(item.category, nav.CATEGORIES)
                self.assertIn(slug, cr.RESULTS)
                self.assertIn(slug, DOMAIN_BY_SLUG)

    def test_the_prefix_does_not_outlive_this_artifact_and_the_map_is_now_empty(self):
        """Clearing the exemption is part of this stage's job rather than a side effect of it, and
        it is what FORCED both rail entries: `test_every_query_in_the_shipped_catalog_has_
        somewhere_to_go` iterates the seed payload and never consults `is_active`, so with the
        exemption gone there is no off-rail route left.

        AND `PAN-MGT` WAS THE LAST ENTRY, so this also pins the thing that makes this run the last
        one: the map is EMPTY for the first time since it was created. A later domain adding an
        entry should fail this and read the sentence rather than deleting it."""
        self.assertNotIn("PAN-MGT", cr.AWAITING_PRESENTATION)
        self.assertNotIn("PAN-MGT-", cr.AWAITING_PRESENTATION)
        self.assertEqual(cr.AWAITING_PRESENTATION, {})

    def test_every_rail_icon_this_domain_names_is_one_of_the_vendored_files(self):
        """`ConfigObject.icon` is UNVALIDATED and a name that is not there raises
        `FileNotFoundError` at TEMPLATE RENDER on every explorer page - so one wrong name takes out
        every explorer test, for every rail item, with not one test name mentioning an icon."""
        for slug in ("management-addressing", "operational-mode"):
            with self.subTest(slug=slug):
                item = next(i for i in nav.CONFIG_OBJECTS if i.slug == slug)
                self.assertIn(item.icon, VENDORED_ICONS)

    def test_neither_new_tab_title_is_long_enough_to_truncate(self):
        """`DeviceSettingSheet.title` over 31 characters truncates SILENTLY, because that is
        Excel's cap on a sheet name - and `probe.surface_for` prints the UNTRUNCATED title, so the
        tool and the workbook disagree with the tool looking right."""
        for slug in ("management-addressing", "operational-mode"):
            with self.subTest(slug=slug):
                self.assertLessEqual(len(DOMAIN_BY_SLUG[slug].spec.sheet_title), 31)

    def test_every_query_field_on_the_two_new_pages_is_a_registered_search_field(self):
        """Stored, searchable and REGISTERED are three different things. A heading mapped to an
        unregistered field points the "build a query from these rows" button at a lookup that
        refuses itself or silently matches nothing.

        Both compilers deliberately register FEWER columns than the model carries - the addressing
        one registers three of seven and says why in its own words - so the address, the gateway
        and the allocation mode are PRESENTED here and left unmapped, exactly as a composite
        column is."""
        from assessments.search.appliance_operational_mode import compiler as mode_compiler
        from assessments.search.management_plane_addressing import compiler as addr_compiler

        for slug, compiler in (("management-addressing", addr_compiler),
                               ("operational-mode", mode_compiler)):
            with self.subTest(slug=slug):
                self.assertTrue(set(cr.RESULTS[slug].query_fields.values())
                                <= set(compiler.FIELD_OPERATOR_REGISTRY))

    def test_the_two_new_results_rows_render_over_real_objects(self):
        """The shipped squareness check cannot exercise a `row` lambda over a real row, and both
        of these call `get_<field>_display()` and branch on a null."""
        self.addressing_dhcp()
        self.addressing_private_with_route()
        self.mode_normal()
        self.mode_never_read()

        spec = cr.RESULTS["management-addressing"]
        rows = [spec.row(r) for r in spec.base_queryset()]
        self.assertEqual({len(r) for r in rows}, {len(spec.columns)})
        dhcp = next(r for r in rows if r[1] == "DHCP client")
        self.assertEqual(dhcp[2], "assigned by DHCP")
        self.assertEqual(dhcp[3], "assigned by DHCP")
        self.assertEqual(dhcp[4], "Dynamically allocated - the configuration holds neither")
        static = next(r for r in rows if r[1] == "Static")
        self.assertEqual(static[2], "192.168.250.2")
        self.assertEqual(static[4], "Private, with a static default route")

        spec = cr.RESULTS["operational-mode"]
        rows = [spec.row(r) for r in spec.base_queryset()]
        self.assertEqual({len(r) for r in rows}, {len(spec.columns)})
        self.assertIn("no operational read was taken", [r[1] for r in rows])
        self.assertIn("normal", [r[1] for r in rows])
        self.assertEqual({r[2] for r in rows}, {"No"})

    # ------------------------------------------------------------------ headings

    def test_no_heading_on_any_tab_this_domain_reaches_is_a_raw_django_field_name(self):
        """FOURTEEN OF 125 HEADINGS WERE RAW BEFORE THIS RUN and none is now, measured over this
        seeded control list. A heading lives in `setting_labels`, which falls back to the RAW FIELD
        NAME when it has no entry - so declaring a column without a label IS choosing to show a
        database field name to a customer.

        SEVEN OF THE FOURTEEN WERE NOT THIS DOMAIN'S COLUMNS: `certificate_trust` is PAN-CRT-006's
        and six belong to the five PAN-MCR controls. They are labelled anyway, on run 26's
        precedent - labelling a column changes nothing about its control - and each owning domain
        inherits the words and may replace them.

        It checks against the MODEL's own field names rather than against a spelling heuristic,
        because the first version of this check used `[a-z]+(_[a-z]+)+` and missed `text`, which is
        a raw field name with no underscore in it."""
        for slug in MY_TABS:
            spec = DOMAIN_BY_SLUG[slug].spec
            table = build_findings_table(spec, tested=ALL_TESTED_COLUMNS)
            fields = set()
            for control_type in spec.control_types:
                model = spec.subject_model(spec.kind_for(control_type))
                fields |= {f.name for f in model._meta.get_fields()}
            raw = [h for h in table.headers if h in fields]
            with self.subTest(slug=slug):
                self.assertEqual(raw, [], f"{slug} heads a column with a raw field name")

    def test_the_column_order_on_both_new_tabs_is_the_order_this_run_emitted(self):
        """`tested_fields` returns the baseline's clauses IN CLAUSE ORDER and every per-field cell
        is written in that order, so the order stage 8 emitted decides which setting a customer
        reads first. THIS IS THE ONE STRUCTURAL PROPERTY WITH NO GATE BEHIND IT, and
        `auto_setting_columns` is all or nothing, so a sheet cannot fix a wrong one.

        Read off `FindingsTable.headers` on built rows rather than derived from stage 5."""
        self.addressing_dhcp()
        self.mode_normal()
        for slug, expected in NEW_TAB_ORDER.items():
            with self.subTest(slug=slug):
                table = self.table(slug)
                head = table.headers
                settings = head[head.index("Template") + 1:head.index("Matched queries")]
                self.assertEqual(settings, expected)

    # ------------------------------------------------- the four `choices` columns print English

    def test_the_four_choices_columns_print_their_labels_and_not_their_stored_keys(self):
        """`display_value` IS CHOICES-UNAWARE: the cell goes `read_value` -> `getattr` ->
        `display_value`, whose value branch ends in `str(value)`, and `get_<field>_display()` is
        called NOWHERE in the sheets layer. So a `choices` field prints the STORED KEY without a
        reader, under a heading carrying the vendor's own words.

        Measured before the readers existed: PAN-MGT-013's firing cell read
        `unencrypted_administrative_login` and PAN-MGT-004's read `routable_address`.

        `certificate_trust` is PAN-CRT-006's column on a shared tab and was in the same state; it
        is included here because nothing else asserts on it."""
        self.unused_profile()
        self.addressing_dhcp()
        self.tls_binding_unbound()
        self.ssh_defaults()

        profile = self.cells(self.table("interface-management-profiles"),
                             "PAN-MGT-013", "pan-fw-7d6e")
        self.assertEqual(profile["What attaching this profile would permit"],
                         "Would permit an unencrypted administrative login")

        addressing = self.cells(self.table("management-addressing"),
                                "PAN-MGT-004", "pan-fw-7d6e")
        self.assertEqual(addressing["Exposure the addressing creates"],
                         "Dynamically allocated - the configuration holds neither")

        crypto = self.cells(self.table("management-crypto"), "PAN-CRT-006", "pan-fw-1085")
        self.assertNotIn("_", crypto["Trust in the certificate presented"])

    def test_no_reader_is_written_on_a_clause_field_without_choices(self):
        """A reader calling `get_<field>_display()` on a field with NO `choices` raises
        `AttributeError` at TEMPLATE RENDER - past `django check`, past all three cross-domain
        gates, and past every test that does not render that page.

        So this asserts the SHAPE rather than a rendering: every field this domain's specs declare
        a reader for either carries `choices` or has a reader that does not call the display
        method. The two that do not carry choices are `binding_count`, which is not a model field
        at all, and `operational_mode`, whose reader exists to say that no read was taken."""
        from django.core.exceptions import FieldDoesNotExist

        allowed_without_choices = {"binding_count", "operational_mode", "service_enabled",
                                   "exposure", "userid_listener_state_established"}
        for slug in MY_TABS:
            spec = DOMAIN_BY_SLUG[slug].spec
            for field in spec.value_readers:
                if field in allowed_without_choices:
                    continue
                for control_type in spec.control_types:
                    model = spec.subject_model(spec.kind_for(control_type))
                    try:
                        declared = bool(model._meta.get_field(field).choices)
                    except FieldDoesNotExist:
                        continue
                    with self.subTest(slug=slug, field=field):
                        self.assertTrue(
                            declared,
                            f"{slug}: a display reader on {field} would raise at template render")

    # ------------------------------------------------------- the rows that were judgements

    def test_a_static_appliance_with_no_address_does_not_claim_a_globally_routable_one(self):
        """THE ROW THAT ARGUED AGAINST ITS OWN FINDING. `address_is_globally_routable("")` answers
        True - the default that FIRES - so the posture resolves to `routable_address` on an
        appliance whose configuration holds no address at all, and the cell asserted a globally
        routable address about it.

        The firing DIRECTION is right and is stage 5's declared intent; the WORD was wrong. The
        reader branches on the state the model already distinguishes rather than on "is it null",
        so the row keeps firing and says that the class is the default rather than a reading."""
        self.addressing_no_address()
        row = self.cells(self.table("management-addressing"), "PAN-MGT-004", "pan-fw-1085")

        self.assertEqual(row["IP Address"], "no address in the configuration")
        self.assertIn("firing default", row["Exposure the addressing creates"])
        self.assertEqual(row["Severity"], "Critical")

    def test_the_two_nulls_in_the_address_column_are_told_apart(self):
        """ONE COLUMN, TWO NULLS, OPPOSITE MEANINGS - the shape `globalprotect-gateway` established
        on its cookie lifetime. Under DHCP the firewall stores no address BY DESIGN and the null is
        a measured state; under static a null is a gap in the configuration. A blank cell, or an em
        dash, would say the same thing about both."""
        self.addressing_no_address()
        self.addressing_dhcp()
        table = self.table("management-addressing")

        static = self.cells(table, "PAN-MGT-004", "pan-fw-1085")
        dhcp = self.cells(table, "PAN-MGT-004", "pan-fw-7d6e")
        self.assertNotEqual(static["IP Address"], dhcp["IP Address"])
        self.assertIn("DHCP", dhcp["IP Address"])
        self.assertIn("DHCP", dhcp["Default Gateway"])
        self.assertIn("not routed off its segment", static["Default Gateway"])

    def test_an_unread_operational_mode_is_not_an_empty_one(self):
        """`display_value` has exactly three answers and renders the empty string `(empty)`, which
        reads as "the appliance answered with nothing" over a row where no operational read was
        taken at all. The normaliser says the opposite in terms: "EMPTY MEANS THE READ WAS NOT
        TAKEN and never that the field was absent from a reply that arrived".

        THE TWO COLUMNS ARE A PAIR AND THE PAIR IS THE POINT: a single boolean collapses "not in an
        approved mode" and "nobody asked", and FALSE is both the firing side and the default."""
        self.mode_never_read()
        self.mode_normal()
        table = self.table("operational-mode")

        unread = self.cells(table, "PAN-MGT-012", "pan-fw-1085")
        read = self.cells(table, "PAN-MGT-012", "pan-fw-7d6e")
        self.assertEqual(unread["Mode the appliance reports"], "no operational read was taken")
        self.assertEqual(read["Mode the appliance reports"], "normal")
        self.assertEqual(unread["Running an approved cryptographic mode"], "No")
        self.assertEqual(read["Running an approved cryptographic mode"], "No")
        self.assertNotIn("(empty)", unread.values())

    def test_the_mark_is_on_the_value_at_fault_and_the_calibration_adds_the_second(self):
        """`build_rows` marks the fields the MATCHED queries assert on, from
        `ControlQuery.asserted_fields`, and falls back to EVERY tested field where that list is
        empty. Measured over the whole shipped catalogue 2026-11-03: 578 queries, 12 with no
        `asserted_fields`, and PAN-MGT is at ZERO - so the marks on these rows are correct exactly
        insofar as that census says, and it says they are.

        The unread row marks only the verdict; the row that answered `normal` marks the mode too,
        because the calibration that matched asserts on it."""
        self.mode_never_read()
        self.mode_normal()
        table = self.table("operational-mode")
        index = table.headers.index
        marked = {}
        for row_index, column_index in table.implicated:
            marked.setdefault(table.rows[row_index][index("Appliance")], set()).add(
                table.headers[column_index])

        self.assertEqual(marked["pan-fw-1085"], {"Running an approved cryptographic mode"})
        self.assertEqual(marked["pan-fw-7d6e"],
                         {"Running an approved cryptographic mode", "Mode the appliance reports"})

    def test_the_tls_row_states_a_condition_it_does_not_meet(self):
        """`fires_when` is `render_node(baseline_query(control).canonical_query)` with no per-query
        hook, so a row that fired through a CALIBRATION prints the baseline's condition instead of
        the one it met. PAN-MGT-010's unbound row matches only `No transport-security configuration
        bound` while the baseline asks for a profile that IS bound.

        PINNED RATHER THAN FIXED: `fires_when` is shared machinery and recording a defect is not
        fixing one. What resolves it on the row is `Matched queries` beside the marked cell, so
        this asserts that both say the right thing while the condition does not."""
        self.tls_binding_unbound()
        self.ssh_defaults()
        row = self.cells(self.table("management-crypto"), "PAN-MGT-010", "pan-fw-1085")

        self.assertIn("profile_name is not empty", row["Fires when (failing condition)"])
        self.assertEqual(row["Matched queries"], "No transport-security configuration bound")
        self.assertEqual(row["SSL/TLS Service Profile"], "(empty)")

    def test_an_unbound_binding_does_not_report_a_floor_it_never_read(self):
        """`display_value` renders the empty string `(empty)`, which says "the bound configuration
        declares no floor" over a row where NOTHING IS BOUND - and PAN-MGT-010's own calibrations
        distinguish those two states as separate queries, `No transport-security configuration
        bound` and `Bound floor could not be resolved`. A cell that cannot tell them apart loses a
        distinction the catalogue already makes."""
        self.tls_binding_unbound()
        self.ssh_defaults()
        row = self.cells(self.table("management-crypto"), "PAN-MGT-010", "pan-fw-1085")

        self.assertEqual(row["Protocol floor in force"],
                         "no configuration is bound, so no floor is in force")

    # ------------------------------------------------------------------ the provenance cells

    def test_the_login_banner_default_cell_is_already_honest_and_reaches_a_template(self):
        """THE ONE TAB IN THE PIPELINE WHERE THE DEFAULT WAS ALREADY RIGHT, so no cell is declared
        and this is what says that was measured rather than assumed. `LoginBanner` declares
        `DERIVED_FIELDS` EMPTY, both clause fields are stored, and both carry a real row.

        A constant cell would have destroyed the one answer that matters here: the acknowledgement
        key on this appliance came from a TEMPLATE, which is where a reader has to go to change
        it."""
        self.banner_absent()
        table = self.table("login-banner")

        self.assertIsNone(DOMAIN_BY_SLUG["login-banner"].spec.provenance_cell)
        self.assertEqual(self.cells(table, "PAN-MGT-008", "pan-fw-1475")["Provenance"], "Template")
        self.assertEqual(self.cells(table, "PAN-MGT-007", "pan-fw-1475")["Provenance"],
                         "PAN-OS default")

    def test_the_addressing_cell_reaches_the_keys_the_verdict_is_computed_from(self):
        """The clause field `exposure_posture` is derived, carries no row, and this model has NO
        `__entry__` row - so the walk reaches nothing and the cell falls back to the mandatory
        reader's prose, "Derived". That is true of the verdict and is not a LOCATION, which is the
        case `remediation_accessor`'s own rule says the object has to answer.

        Measured: the cell tells the three appliances apart where the default said one word on all
        three."""
        self.addressing_no_address()
        self.addressing_private_with_route()
        self.addressing_dhcp()
        table = self.table("management-addressing")

        self.assertEqual(self.cells(table, "PAN-MGT-004", "pan-fw-1085")["Provenance"],
                         "PAN-OS default\nNot configured")
        self.assertEqual(self.cells(table, "PAN-MGT-004", "pan-fw-1475")["Provenance"],
                         "PAN-OS default\nLocal")
        self.assertEqual(self.cells(table, "PAN-MGT-004", "pan-fw-7d6e")["Provenance"],
                         "Local\nNot configured")

    def test_the_operational_mode_cell_does_not_say_nothing_was_recorded(self):
        """Both clause fields are declared derived and this model carries NO `FieldProvenance` row
        of any kind, so the default cell reads "Not recorded | Derived" - half false, because a
        declared-derived column is not an untracked one. Written as a BRANCH rather than as the
        constant "Derived" so that a stored clause field added later cannot make it lie."""
        self.mode_never_read()
        self.mode_normal()
        table = self.table("operational-mode")

        self.assertEqual({row["Provenance"] for row in
                          (self.cells(table, "PAN-MGT-012", host)
                           for host in ("pan-fw-1085", "pan-fw-7d6e"))},
                         {"Derived"})

    def test_the_crypto_cell_reaches_the_list_each_verdict_is_computed_from(self):
        """THE FIX THAT TAB'S OWN STAGE 9 RUN PROPOSED AND COULD NOT WRITE, because the spec also
        serves PAN-MGT-010 and that domain had not had its stage 9. `ciphers`, `kex` and `macs`
        each carry a real row while the verdicts computed from them are declared derived and carry
        none, so the cell read "Not recorded" over three fields with a perfectly good location -
        and that is the distinction the tab most needs, because it separates "bind a profile" from
        "edit the one you bound".

        MEASURED LIMIT: this domain's stage 6 records no `deviceconfig/system/ssh` subject, so
        every SSH row in the estate this was measured against is the UNCOLLECTED state. The
        mechanism is pinned here; whether the cell is right about a real device's SSH configuration
        belongs to that domain's own estate."""
        self.ssh_defaults()
        self.tls_binding_unbound()
        table = self.table("management-crypto")

        self.assertEqual(self.cells(table, "PAN-MCR-001", "pan-fw-1085")["Provenance"],
                         "PAN-OS default")
        self.assertEqual(self.cells(table, "PAN-MGT-010", "pan-fw-1085")["Provenance"],
                         "Not configured")

    def test_the_interface_management_profile_tab_keeps_the_default_cell(self):
        """THE ONE CASE WHERE BRANCHING IS WORSE THAN DOING NOTHING. `binding_count` exists ONLY
        through a `value_reader`, and a sheet-level cell is handed `(subject, provenance_of,
        fields)` and cannot see the sheet's readers - so `provenance_of` finds no stored row and no
        `DERIVED_FIELDS` entry for it and answers nothing, while the DEFAULT path sends it to
        `remediation_accessor`, which reaches this model's `__entry__` row.

        `interface_management_profiles.py` declares `ENTRY_FIELD = "__entry__"` and writes one per
        entry, so this is the one tab in the domain where that walk has somewhere to go."""
        self.unused_profile()
        table = self.table("interface-management-profiles")

        self.assertIsNone(DOMAIN_BY_SLUG["interface-management-profiles"].spec.provenance_cell)
        self.assertEqual(self.cells(table, "PAN-MGT-013", "pan-fw-7d6e")["Provenance"],
                         "Local\nLocal")

    def test_pan_mgt_011s_column_is_eleventh_on_a_tab_this_domain_does_not_own(self):
        """`setting_columns` walks `order_by("control_id")`, so `PAN-LOG-001` sorts before
        `PAN-MGT-011` and this domain's column - which was FIRST on that tab since the type was
        minted - is now behind ten PAN-LOG columns. Nothing gates that and nothing a sheet
        declares changes it: `auto_setting_columns` is all or nothing.

        Pinned because it is a customer-facing position decided by a control id, and because the
        `logging` run measured it and this run inherits the consequence."""
        spec = DOMAIN_BY_SLUG["logging-settings"].spec
        table = build_findings_table(spec, tested=ALL_TESTED_COLUMNS)
        head = table.headers
        settings = head[head.index("Template") + 1:head.index("Matched queries")]

        self.assertEqual(settings[-1], "Enable Log on High DP Load")
        self.assertEqual(len(settings), 11)
