"""The three globalprotect-portal findings tabs and the three rail items, pinned. Stage 9.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover the tabs generically:
every assertion here is a JUDGMENT this run made that nothing else in the repository states, and
a new tab nothing asserts on is one the next refactor can break silently.

  - THE FOUR `value_readers`, which are the single largest thing this stage changed about what a
    customer reads. `display_value` is CHOICES-UNAWARE - its value branch ends in `str(value)` -
    so without them a column headed "Save User Credentials" prints `0`, `1`, `2`, `3` or
    `no_agent_configuration`, and `0` is PAN-GPP-004's PASSING value. A refactor that drops one
    does not break a build; it quietly puts a database token in a customer's report.
  - THAT `custom_login_page` HAS NO READER, which is the reader this run refused. It is the one
    STORED field of the domain's eight and the normalizer writes it a `FieldProvenance` row; a
    reader would make `remediation_accessor` walk past that row, and whether the key was carried
    at all is exactly what PAN-GPP-005's third shipped query is about.
  - THE COVERAGE TAB'S `provenance_cell`, which is board record P451, and the fact that the OTHER
    TWO TABS DO NOT NEED ONE. That asymmetry is the measurement: `write_scoped_objects` always
    writes an `__entry__` row and `write_node_row` never does, so the portal and the client-auth
    row resolve to `Local` while the enforcement point lands on `provenance_cells`' `row is None`
    arm and prints "Not recorded" about values this assessment computed.
  - `Authentication rows`, which is the only cell in the whole report that shows the worst state
    this domain permits: `portal-config/client-auth` is OPTIONAL at commit, so a portal can demand
    NOTHING AT ALL, which is weaker than the lowest rank PAN-GPP-002 grades - and such a portal has
    no child row for that control to report on.
  - THE FOUR EVIDENCE CELLS ON THE CLIENT-AUTH TAB, because that tab has exactly one derived
    setting column and the verdict in it is computed from two leaves. `Credentials OR certificate`
    is the one whose polarity is INVERTED against the rest of this report - "no" is the hardened
    answer - and a row without it cannot be acted on.
  - THAT NO HEADING ON ANY OF THE THREE TABS READS AS A RAW DJANGO FIELD NAME. All eight clause
    fields of this domain were headed by one before this stage ran, and nothing in either
    repository says which columns head raw: it is found by building the table and looking.
  - that no tab repeats a heading, which nothing in either repository checks and which ships a
    workbook Excel refuses to open.
  - THE COLUMN ORDER, which is load-bearing and has no gate behind it. `tested_fields` returns the
    baseline's clauses in clause order and then every other active query's in ALPHABETICAL ORDER
    OF THE QUERY'S NAME, so renaming a shipped calibration silently reorders a customer-facing
    column (P435). Pinned here because this domain is one where it happens to come out matching
    stage 5, and nothing would say if that stopped being true.
  - THE HA PAIR DRAWING TWO ROWS FOR ONE CONFIGURATION, which is the opposite of the domain before
    this one. All three models key on `appliance`, so nothing below presentation folds them.
  - the explorer `ResultsSpec.row` lambdas over real rows. The shipped check asserts a row is the
    same LENGTH as its columns and cannot see what a cell says.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets.findings import build_findings_table
from assessments.configuration_navigation import CONFIG_OBJECTS, objects_for_model
from assessments.globalprotect_enforcement_point_findings import (
    generate_globalprotect_enforcement_point_findings)
from assessments.globalprotect_portal_client_auth_findings import (
    generate_globalprotect_portal_client_auth_findings)
from assessments.globalprotect_portal_findings import generate_globalprotect_portal_findings
from assessments.models import AssessmentRun, Control
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementNode, EnforcementPoint, GlobalProtectEnforcementPoint,
    GlobalProtectPortal, GlobalProtectPortalClientAuthRow, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.globalprotect import (
    normalize_globalprotect)

#: Every control of this domain, split by the type each one targets. THE FINDINGS-TAB TESTS SEED
#: ALL SIX and the reason is not incidental: a derived settings column exists only because some
#: control's query clauses on the field, so `build_findings_table` over an unseeded catalog draws
#: NO setting columns at all - and a "no heading reads as a raw field name" assertion over that
#: table passes vacuously.
PORTAL_CONTROLS = ("PAN-GPP-001", "PAN-GPP-003", "PAN-GPP-004", "PAN-GPP-005")
CLIENT_AUTH_CONTROLS = ("PAN-GPP-002",)
COVERAGE_CONTROLS = ("PAN-GPP-006",)

PAIR_A = "013201001085"
PAIR_B = "013201001086"
SOLO = "6A9C0A9904E7D6E"


def portal(name, **keys):
    """One GlobalProtect portal entry in the device's own shape.

    The four keys PAN-OS refuses to commit a portal without are present by default -
    `local-address`, `ssl-tls-service-profile`, `custom-login-page` and `custom-home-page` - so a
    test that wants `mandatory_keys_present` to read False removes one on purpose.
    """
    config = {"local-address": {"interface": "ethernet1/1"},
              "ssl-tls-service-profile": "oep-tls",
              "custom-login-page": "factory-default",
              "custom-home-page": "factory-default"}
    config.update(keys.pop("portal_config", {}))
    for absent in keys.pop("without", ()):
        config.pop(absent, None)
    entry = {"@name": name, "portal-config": config}
    entry.update(keys)
    return entry


def client_auth(name, os_value="Any", profile="oep-auth", switch=None):
    row = {"@name": name, "os": os_value, "authentication-profile": profile}
    if switch is not None:
        row["user-credential-or-client-cert-required"] = switch
    return row


def agent_config(name="c1", upgrade=None, save=None, gateway="10.0.0.1"):
    """One `client-config/configs` entry - the agent configuration the portal hands out.

    `upgrade_posture` and `saved_credentials_posture` are read off the FIRST such entry, so a
    portal with none at all reads `no_agent_configuration` on both, which is the materialised
    default and the firing side.
    """
    entry = {"@name": name,
             "gateways": {"external": {"list": {"entry": [
                 {"@name": "gw1", "ip": {"ipv4": gateway}}]}}}}
    if save is not None:
        entry["save-user-credentials"] = save
    if upgrade is not None:
        entry["gp-app-config"] = {"config": {"entry": [
            {"@name": "client-upgrade", "value": {"member": [upgrade]}}]}}
    return entry


def merged(vsys_name, portals=(), apps=(), groups=()):
    vsys = {"@name": vsys_name, "global-protect": {}}
    gp = vsys["global-protect"]
    gp["global-protect-portal"] = {"entry": list(portals)} if portals else {}
    gp["clientless-app"] = {"entry": list(apps)} if apps else {}
    gp["clientless-app-group"] = {"entry": list(groups)} if groups else {}
    return {"config": {"devices": {"entry": [
        {"@name": "localhost.localdomain", "vsys": {"entry": [vsys]}}]}}}


class GlobalProtectPortalTabTestCase(TestCase):
    """Three subjects at three grains, over an estate with a real HA pair in it."""

    def setUp(self):
        now = timezone.now()
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.gpp")
        self.run = AssessmentRun.objects.create(
            name="GlobalProtect portal", status=AssessmentRun.Status.RUNNING, started_at=now)
        seed_controls(list(PORTAL_CONTROLS),
                      control_type=Control.ControlType.GLOBALPROTECT_PORTAL)
        seed_controls(list(CLIENT_AUTH_CONTROLS),
                      control_type=Control.ControlType.GLOBALPROTECT_PORTAL_CLIENT_AUTH)
        seed_controls(list(COVERAGE_CONTROLS),
                      control_type=Control.ControlType.GLOBALPROTECT_ENFORCEMENT_POINT)

        # THE HA PAIR. Both members hold the same vsys4 and the same payload, which is what an HA
        # pair looks like to these normalisers - non-HA `deviceconfig` is synchronised, so both
        # peers answer the same portal configuration. Four portals, each exercising a different
        # rank of the two graded agent settings, plus one clientless app so the vsys verdict has
        # a definition to find.
        pair = merged("vsys4", portals=[
            # Every rank firing: upgrades disallowed, password kept on the endpoint, and a row
            # that demands a password alone.
            portal("oep-gpp6-a",
                   **{"portal-config": {"local-address": {"interface": "ethernet1/1"},
                                        "ssl-tls-service-profile": "oep-tls",
                                        "custom-login-page": "factory-default",
                                        "custom-home-page": "factory-default",
                                        "client-auth": {"entry": [
                                            client_auth("r1", switch="yes")]}},
                      "client-config": {"configs": {"entry": [
                          agent_config(upgrade="disabled", save="1")]}},
                      "clientless-vpn": {"dns-proxy": "oep-dns"}}),
            # THE PASSING PORTAL on both graded settings, and the one whose login page is
            # Disabled - so it is the row that passes PAN-GPP-003, -004 and -005 together.
            portal("oep-gpp6-b",
                   **{"portal-config": {"local-address": {"interface": "ethernet1/2"},
                                        "ssl-tls-service-profile": "oep-tls",
                                        "custom-login-page": "Disable",
                                        "custom-home-page": "factory-default"},
                      "client-config": {"configs": {"entry": [
                          agent_config(upgrade="transparent", save="0")]}}}),
            # The two LOWER ranks: upgrades left to the user, and the password behind a
            # biometric. Both are genuine severity adjustments.
            portal("oep-gpp6-c",
                   **{"portal-config": {"local-address": {"interface": "ethernet1/3"},
                                        "ssl-tls-service-profile": "oep-tls",
                                        "custom-login-page": "factory-default",
                                        "custom-home-page": "factory-default"},
                      "client-config": {"configs": {"entry": [
                          agent_config(upgrade="manual", save="3")]}}}),
            # NO SSL/TLS SERVICE PROFILE AT ALL - the PAN-GPP-001 row - and NO client-auth rows,
            # which is the worst state this domain permits and the one no control reports.
            portal("oep-gpp6-d", without=("ssl-tls-service-profile",),
                   **{"client-config": {"configs": {"entry": [
                       agent_config(upgrade="internal", save="2")]}}}),
        ], apps=[{"@name": "oep-gpp6-app-a", "application-home-url": "intranet.example"}])
        self.pair = self._group("g-pair", ApplianceGroup.TYPE_HA_PAIR, pair, now, [
            (PAIR_A, "pan-fw-1085-a"), (PAIR_B, "pan-fw-1085-b")], "vsys4")

        # A STANDALONE firewall whose one portal carries TWO client-auth rows of different
        # endpoint classes - the measured shape this domain's grain decision rests on: one row
        # demands either factor and the other demands both, so one fires and one does not.
        solo = merged("vsys1", portals=[
            portal("oep-gpp6-e",
                   **{"portal-config": {"local-address": {"interface": "ethernet1/1"},
                                        "ssl-tls-service-profile": "default",
                                        "certificate-profile": "quick-cert-profile",
                                        "custom-login-page": "factory-default",
                                        "custom-home-page": "factory-default",
                                        "client-auth": {"entry": [
                                            client_auth("r1", switch="yes"),
                                            client_auth("r2", os_value="Browser", switch="no")]}}}),
        ])
        self.solo = self._group("g-solo", ApplianceGroup.TYPE_STANDALONE, solo, now,
                                [(SOLO, "pan-fw-7d6e")], "vsys1")

        for appliance in Appliance.objects.all():
            normalize_globalprotect(appliance)
        generate_globalprotect_portal_findings(self.run)
        generate_globalprotect_portal_client_auth_findings(self.run)
        generate_globalprotect_enforcement_point_findings(self.run)

    def _group(self, name, group_type, payload, now, members, vsys_name):
        group = ApplianceGroup.objects.create(
            management_station=self.station, name=name, group_type=group_type)
        appliances = []
        for serial, hostname in members:
            appliance = Appliance.objects.create(
                management_station=self.station, appliance_group=group,
                serial_number=serial, hostname=hostname)
            appliances.append(appliance)
            Snapshot.objects.create(management_station=self.station, appliance=appliance,
                                    source_type="show_merged_config", collected_at=now,
                                    payload=payload)
        group.active_appliance = appliances[0]
        group.save(update_fields=["active_appliance"])
        point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=group, vsys_name=vsys_name,
            vsys_display_name=vsys_name, in_scope=True)
        for appliance in appliances:
            EnforcementNode.objects.create(management_station=self.station,
                                           enforcement_point=point, appliance=appliance)
        return group

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def table(slug):
        return build_findings_table(DOMAIN_BY_SLUG[slug].spec)

    def cells(self, slug, control_id, hostname, object_name):
        """The one row of `slug` for this control, appliance and object, as {heading: value}."""
        table = self.table(slug)
        wanted = []
        for row in table.rows:
            cells = dict(zip(table.headers, row))
            if (cells["Control ID"] == control_id
                    and cells["Appliance"] == hostname
                    and cells["Object"] == object_name):
                wanted.append(cells)
        self.assertEqual(
            1, len(wanted),
            f"expected exactly one {control_id} row for {hostname}/{object_name}, "
            f"got {len(wanted)}")
        return wanted[0]

    def marked(self, slug, control_id, hostname, object_name):
        """The headings of the value-at-fault cells on that row."""
        table = self.table(slug)
        for index, row in enumerate(table.rows):
            cells = dict(zip(table.headers, row))
            if (cells["Control ID"] == control_id
                    and cells["Appliance"] == hostname
                    and cells["Object"] == object_name):
                return sorted(table.headers[c] for (r, c) in table.implicated if r == index)
        self.fail(f"no {control_id} row for {hostname}/{object_name}")

    # ------------------------------------------------------------------ the estate came out
    def test_the_estate_is_the_one_these_assertions_describe(self):
        """A guard on setUp, so a later failure is read as a presentation defect and not a seed."""
        # Four portals on each of the pair's two peers, plus the standalone's one.
        self.assertEqual(9, GlobalProtectPortal.objects.count())
        # `oep-gpp6-a` carries one row and is on both peers, so two; the standalone's portal
        # carries two. The other three portals of the pair carry none, which is deliberate -
        # `oep-gpp6-d` having none is the state no control reports.
        self.assertEqual(4, GlobalProtectPortalClientAuthRow.objects.count())
        self.assertEqual(3, GlobalProtectEnforcementPoint.objects.count())

    # ------------------------------------------------------------------ the HA pair
    def test_an_ha_pair_draws_two_rows_for_one_configuration_on_all_three_models(self):
        """THE OPPOSITE OF THE DOMAIN BEFORE THIS ONE, and nothing below presentation folds it.

        All three models key on `appliance` - `unique(appliance, scope, vsys_name[, name])` - so
        two peers holding one synchronised configuration write two of everything. A vsys-scoped
        model keyed on an enforcement point does not: `integrations.EnforcementPoint` is unique on
        (appliance_group, vsys_name), so an HA pair shares ONE, which is why `decryption-policy`'s
        rule models deduplicated themselves and that run had nothing to do.

        What is asserted is the DUPLICATION, not a fold: a `DeviceSettingSheet` has no fold hook
        and `build_rows` is shared machinery, so the two rows are presented and the Appliance and
        HA role columns are what tell them apart.
        """
        # ONE enforcement point for the pair's one vsys - the model is unique on
        # (appliance_group, vsys_name), which is the deduplication these three models do NOT get.
        self.assertEqual(1, EnforcementPoint.objects.filter(appliance_group=self.pair).count())

        pair_portals = GlobalProtectPortal.objects.filter(appliance__appliance_group=self.pair)
        self.assertEqual(8, pair_portals.count(), "four portals, two peers")
        self.assertEqual({"pan-fw-1085-a", "pan-fw-1085-b"},
                         {p.appliance.hostname for p in pair_portals})
        # The same four names on each peer: one real configuration, two rows each.
        for hostname in ("pan-fw-1085-a", "pan-fw-1085-b"):
            self.assertEqual(
                {"oep-gpp6-a", "oep-gpp6-b", "oep-gpp6-c", "oep-gpp6-d"},
                set(pair_portals.filter(appliance__hostname=hostname)
                    .values_list("name", flat=True)))

        # TWO GP enforcement-point rows for ONE vsys, which is the sharpest case: the generic
        # `integrations.EnforcementPoint` for that same vsys is singular one line above.
        pair_points = GlobalProtectEnforcementPoint.objects.filter(
            appliance__appliance_group=self.pair)
        self.assertEqual(2, pair_points.count())
        self.assertEqual({"vsys4"}, {p.vsys_name for p in pair_points})

        # One portal of the pair carries a client-auth row, so the pair writes two of it.
        self.assertEqual(2, GlobalProtectPortalClientAuthRow.objects.filter(
            appliance__appliance_group=self.pair, name="r1").count())

    def test_both_peers_of_a_pair_draw_a_findings_row_and_the_appliance_cell_separates_them(self):
        table = self.table("globalprotect-portals")
        rows = [dict(zip(table.headers, row)) for row in table.rows]
        pair_rows = [r for r in rows
                     if r["Control ID"] == "PAN-GPP-001" and r["Object"] == "oep-gpp6-d"]
        self.assertEqual(2, len(pair_rows))
        self.assertEqual({"pan-fw-1085-a", "pan-fw-1085-b"},
                         {r["Appliance"] for r in pair_rows})
        # Identical in every other cell, which is the point: without the Appliance column a
        # reader would see one defect twice and could not reconcile the count.
        for key in ("Scope", "No SSL/TLS service profile is bound", "Severity"):
            self.assertEqual(1, len({r[key] for r in pair_rows}), key)

    # ------------------------------------------------------------------ the readers
    def test_the_two_graded_portal_settings_read_as_english_and_not_as_a_choice_key(self):
        """WITHOUT THESE READERS THE PASSING VALUE OF PAN-GPP-004 PRINTS AS `0`.

        `display_value` is choices-unaware: its value branch ends in `str(value)` and it never
        calls `get_<field>_display()`. Both fields are in `GlobalProtectPortal.DERIVED_FIELDS`
        and the normalizer writes neither a `FieldProvenance` row, so the readers cost nothing.
        """
        cells = self.cells("globalprotect-portals", "PAN-GPP-003", "pan-fw-1085-a", "oep-gpp6-a")
        self.assertEqual("Disallow", cells["Allow User to Upgrade GlobalProtect App"])
        self.assertEqual("Yes - username and password", cells["Save User Credentials"])

        lower = self.cells("globalprotect-portals", "PAN-GPP-003", "pan-fw-1085-a", "oep-gpp6-c")
        self.assertEqual("Allow Manually", lower["Allow User to Upgrade GlobalProtect App"])
        self.assertEqual("Only with User Fingerprint", lower["Save User Credentials"])

        bare = self.cells("globalprotect-portals", "PAN-GPP-003", "pan-fw-1085-a", "oep-gpp6-d")
        self.assertEqual("Internal", bare["Allow User to Upgrade GlobalProtect App"])
        self.assertEqual("Save Username Only", bare["Save User Credentials"])

    def test_a_portal_handing_out_no_agent_configuration_says_so_in_a_sentence(self):
        """The materialised default of both graded columns, and the firing side of both.

        The raw token is `no_agent_configuration`, which is the value a customer would read
        without the reader - under a heading that is the vendor's own label for a dropdown, so it
        would look like a setting somebody chose.
        """
        cells = self.cells("globalprotect-portals", "PAN-GPP-004", "pan-fw-7d6e", "oep-gpp6-e")
        self.assertEqual("The portal hands out no agent configuration",
                         cells["Save User Credentials"])
        self.assertEqual("The portal hands out no agent configuration",
                         cells["Allow User to Upgrade GlobalProtect App"])

    def test_the_admission_verdict_reads_as_a_sentence_on_the_client_auth_tab(self):
        """The one derived setting column on that tab, and its raw token is unreadable.

        `password_and_certificate` is the PASSING value; the three that fire are
        `password_only`, `password_or_certificate` and `unknown`.
        """
        cells = self.cells("globalprotect-portal-authentication", "PAN-GPP-002",
                           "pan-fw-7d6e", "r1")
        self.assertEqual("A password OR a client certificate admits an endpoint",
                         cells["What this row demands before admitting an endpoint"])

    def test_the_clientless_verdict_reads_as_a_sentence_on_the_coverage_tab(self):
        table = self.table("globalprotect-coverage")
        values = {dict(zip(table.headers, row))["Clientless VPN surface"] for row in table.rows}
        self.assertEqual({"A portal publishes applications and definitions exist"}, values)

    def test_custom_login_page_keeps_the_devices_own_token_and_has_no_reader(self):
        """THE READER THIS RUN REFUSED, and the assertion is about the provenance it preserves.

        `custom_login_page` is the one STORED field of this domain's eight and the normalizer
        writes it a `FieldProvenance` row by name. A reader would report the field `stored=False`,
        which makes `remediation_accessor` skip that row and walk to `__entry__` - and that row is
        the only thing on the tab that separates a portal whose key was READ from one whose key
        the collector never carried, which is what PAN-GPP-005's third query is about.

        It needs no reader on its own merits either: the field has no `choices`, and
        `factory-default` and `Disable` are the vendor's own two words for this dropdown (help
        11.2 p.1001), not Django's.
        """
        spec = DOMAIN_BY_SLUG["globalprotect-portals"].spec
        self.assertNotIn("custom_login_page", spec.value_readers)
        cells = self.cells("globalprotect-portals", "PAN-GPP-005", "pan-fw-1085-a", "oep-gpp6-a")
        self.assertEqual("factory-default", cells["Portal Login Page"])

    # ------------------------------------------------------------------ provenance, P451
    def test_the_coverage_tab_says_derived_and_not_not_recorded(self):
        """BOARD RECORD P451, and this tab is the ONE of the three that walks into it.

        Every column of `GlobalProtectEnforcementPoint` is in its `DERIVED_FIELDS` and the
        normalizer passes `provenance=()` at the write, so there is no per-field row; and
        `write_node_row` writes no `__entry__` row either, so the remediation walk finds nothing
        and `provenance_cells` lands on its `row is None` arm. The default cell would read "Not
        recorded" - "nothing tracks that field" - about two values this assessment computed.
        """
        table = self.table("globalprotect-coverage")
        values = {dict(zip(table.headers, row))["Provenance"] for row in table.rows}
        self.assertEqual({"Derived"}, values)
        self.assertEqual(
            0,
            GlobalProtectEnforcementPoint.objects.first().field_provenance.count(),
            "the model writes no provenance row at all - if it starts to, this tab's "
            "`provenance_cell` is hiding a real answer rather than a placeholder")

    def test_the_other_two_tabs_need_no_provenance_cell_because_an_entry_row_exists(self):
        """THE ASYMMETRY IS THE MEASUREMENT, and it is why only one of three tabs needs the hook.

        `write_scoped_objects` ALWAYS writes a `FieldProvenance` row under `__entry__`;
        `write_node_row` never does. So a derived field on the portal or the client-auth row
        resolves through `remediation_accessor`'s walk to the object's own entry row and the cell
        says where the OBJECT came from, which is the useful answer - while the same field on the
        enforcement point has nothing to walk to.
        """
        for slug in ("globalprotect-portals", "globalprotect-portal-authentication"):
            self.assertIsNone(DOMAIN_BY_SLUG[slug].spec.provenance_cell, slug)
            table = self.table(slug)
            values = {dict(zip(table.headers, row))["Provenance"] for row in table.rows}
            self.assertNotIn("Not recorded", values, slug)
            self.assertTrue(
                any("Local" in value for value in values),
                f"{slug}: expected the entry row to answer, got {values!r}")
        self.assertTrue(
            GlobalProtectPortal.objects.first().field_provenance.filter(
                field_name="__entry__").exists())

    # ------------------------------------------------------------------ the evidence cells
    def test_the_authentication_rows_count_is_the_only_cell_showing_the_worst_state(self):
        """A portal that demands NOTHING of any endpoint, which no control on this domain reports.

        `portal-config/client-auth` is OPTIONAL at commit, measured, so a portal can carry no row
        at all - weaker than PAN-GPP-002's lowest rank - and it has no child row for that control
        to report on. `oep-gpp6-d` is that portal.
        """
        cells = self.cells("globalprotect-portals", "PAN-GPP-001", "pan-fw-1085-a", "oep-gpp6-d")
        self.assertEqual("0", cells["Authentication rows"])
        # And no row of the client-auth tab names it, which is the silence this cell covers.
        table = self.table("globalprotect-portal-authentication")
        portals = {dict(zip(table.headers, row))["Portal"] for row in table.rows}
        self.assertNotIn("oep-gpp6-d", portals)

    def test_the_tls_profile_name_sits_beside_the_verdict_that_says_none_is_bound(self):
        """The verdict is a boolean; a reader fixing PAN-GPP-001 needs to see what IS bound."""
        failing = self.cells("globalprotect-portals", "PAN-GPP-001",
                             "pan-fw-1085-a", "oep-gpp6-d")
        self.assertEqual("Yes", failing["No SSL/TLS service profile is bound"])
        self.assertEqual("(empty)", failing["SSL/TLS service profile"])
        # A portal that DOES bind one draws no PAN-GPP-001 row at all, so the pair is checked on
        # another control's row over the same subject.
        passing = self.cells("globalprotect-portals", "PAN-GPP-003",
                             "pan-fw-1085-a", "oep-gpp6-a")
        self.assertEqual("No", passing["No SSL/TLS service profile is bound"])
        self.assertEqual("oep-tls", passing["SSL/TLS service profile"])

    def test_the_client_auth_row_carries_both_leaves_its_verdict_is_computed_from(self):
        """ONE DERIVED COLUMN, TWO LEAVES, AND THE POLARITY OF ONE IS INVERTED.

        Help 11.2 p.1003: "Allow Authentication with User Credentials OR Client Certificate - If
        you select No, users must authenticate to the gateway using both ... If you select Yes,
        users can authenticate ... using either." So `no` is the HARDENED answer, which is the
        reverse of nearly every other switch in this report - and `yes` is only a second factor
        at all where the owning portal binds a certificate profile.
        """
        either = self.cells("globalprotect-portal-authentication", "PAN-GPP-002",
                            "pan-fw-7d6e", "r1")
        self.assertEqual("yes", either["Credentials OR certificate"])
        self.assertEqual("Yes", either["Certificate profile bound"])
        self.assertEqual("Any", either["Endpoint class (OS)"])
        self.assertEqual("oep-auth", either["Authentication Profile"])
        self.assertEqual("oep-gpp6-e", either["Portal"])

    def test_two_rows_of_one_portal_report_differently_which_is_why_the_row_is_the_grain(self):
        """The measurement the whole three-tab split rests on.

        `r1` demands either factor and fires; `r2` demands both and draws no row. A portal-grain
        control would have had to print one of those and would have reported the compliant sibling
        as the fault.
        """
        table = self.table("globalprotect-portal-authentication")
        rows = [dict(zip(table.headers, row)) for row in table.rows]
        solo = {r["Object"] for r in rows if r["Portal"] == "oep-gpp6-e"}
        self.assertEqual({"r1"}, solo)
        self.assertEqual(
            1, GlobalProtectPortalClientAuthRow.objects.filter(
                portal_name="oep-gpp6-e", name="r2").count(),
            "r2 must exist and simply draw no row")

    def test_the_coverage_tab_shows_the_counts_that_tell_live_from_latent(self):
        table = self.table("globalprotect-coverage")
        cells = next(dict(zip(table.headers, row)) for row in table.rows
                     if dict(zip(table.headers, row))["Appliance"] == "pan-fw-1085-a")
        self.assertEqual("4", cells["Portals"])
        self.assertEqual("1 app(s), 0 group(s), published by 1 portal(s)",
                         cells["Clientless definitions"])
        # The license cell is what "No" in the applicability column actually covers: this estate
        # was never asked, which is NOT the same as licensed.
        # `no licenses` IS OptivEdgeIntegrations' OWN CHOICES LABEL, which the 2026-11-09
        # spelling sweep did not reach - see `integrations.models.globalprotect`. The second
        # half of the sentence is this repo's and was swept.
        self.assertEqual("The appliance reported no licenses at all, or was never asked "
                         "(0 license entries read)", cells["GlobalProtect license"])
        self.assertEqual("No", cells["Licensing rules GlobalProtect out"])

    # ------------------------------------------------------------------ marks
    def test_the_marked_cell_is_the_one_the_matched_query_asserts_on(self):
        """`implicated` reads `ControlQuery.asserted_fields` over the MATCHED queries.

        Checked rather than assumed, because the fallback to the baseline's clause fields applies
        only where `asserted_fields` is empty - a control whose queries predate the pipeline - and
        this domain's stage 8 wrote them.
        """
        self.assertEqual(["Allow User to Upgrade GlobalProtect App"],
                         self.marked("globalprotect-portals", "PAN-GPP-003",
                                     "pan-fw-1085-a", "oep-gpp6-a"))
        self.assertEqual(["Save User Credentials"],
                         self.marked("globalprotect-portals", "PAN-GPP-004",
                                     "pan-fw-1085-a", "oep-gpp6-a"))
        self.assertEqual(["No SSL/TLS service profile is bound"],
                         self.marked("globalprotect-portals", "PAN-GPP-001",
                                     "pan-fw-1085-a", "oep-gpp6-d"))
        self.assertEqual(["What this row demands before admitting an endpoint"],
                         self.marked("globalprotect-portal-authentication", "PAN-GPP-002",
                                     "pan-fw-7d6e", "r1"))

    def test_every_row_of_every_tab_marks_at_least_one_cell(self):
        """`hidden_fields` is empty on all three, so the gate passed on REAL columns.

        That check counts a field as presented if `hidden_fields` carries it, so a non-empty tuple
        is a CLAIM accepted as proof - and it is the only known cause in this repository of a
        findings row that marks nothing as the thing to fix (P409).
        """
        for slug in ("globalprotect-portals", "globalprotect-portal-authentication",
                     "globalprotect-coverage"):
            self.assertEqual((), DOMAIN_BY_SLUG[slug].spec.hidden_fields, slug)
            table = self.table(slug)
            marked_rows = {r for (r, _c) in table.implicated}
            self.assertEqual(set(range(len(table.rows))), marked_rows,
                             f"{slug}: a row marking nothing as the thing to fix")

    # ------------------------------------------------------------------ headings
    def test_no_heading_on_any_of_the_three_tabs_reads_as_a_raw_django_field_name(self):
        """All eight clause fields of this domain headed one before this stage ran.

        Nothing in either repository says which columns head raw - there was no sheet for any of
        these three control types to inherit a `setting_labels` entry from - so it is found by
        building the table and looking, which is what this does.
        """
        for slug in ("globalprotect-portals", "globalprotect-portal-authentication",
                     "globalprotect-coverage"):
            raw = [h for h in self.table(slug).headers
                   if h == h.lower() and ("_" in h or (" " not in h and h.isalpha()))]
            self.assertEqual([], raw, slug)

    def test_no_tab_repeats_a_heading(self):
        """Nothing checks this and a duplicate header ships a workbook Excel refuses to open:
        xlsxwriter drops the table with a warning and leaves a sheet of stray cells."""
        for slug in ("globalprotect-portals", "globalprotect-portal-authentication",
                     "globalprotect-coverage"):
            headers = self.table(slug).headers
            self.assertEqual(len(headers), len(set(headers)), slug)

    def test_the_setting_column_order_is_the_order_stage_5_emitted_its_clauses(self):
        """THE ONE STRUCTURAL PROPERTY WITH NO GATE BEHIND IT, pinned (P435).

        `tested_fields` returns the baseline's clauses in clause order and then every OTHER active
        query's in alphabetical order of the QUERY'S NAME, so renaming a shipped calibration
        silently reorders a customer-facing column. On this domain it comes out matching stage 5,
        which is a property of the query names and not of the machinery - the only control with
        two clause fields is PAN-GPP-005, whose second arrives from the query "Whether this portal
        serves a login page could not be established", and PAN-GPP-006's two are both in its
        baseline in stage 5's own order.
        """
        headers = self.table("globalprotect-portals").headers
        settings = ["No SSL/TLS service profile is bound",
                    "Allow User to Upgrade GlobalProtect App",
                    "Save User Credentials",
                    "Portal Login Page",
                    "All four keys the device requires were read"]
        self.assertEqual(settings, [h for h in headers if h in set(settings)])

        coverage = self.table("globalprotect-coverage").headers
        pair = ["Licensing rules GlobalProtect out", "Clientless VPN surface"]
        self.assertEqual(pair, [h for h in coverage if h in set(pair)])

    def test_the_workbook_sheet_name_fits_excels_cap_on_all_three_tabs(self):
        """A title over 31 characters is TRUNCATED in the book and kept whole on the live page, so
        the two surfaces disagree about the tab's own name. That is why the authentication tab is
        "Portal Client Authentication" and not "GlobalProtect Portal Client Authentication"."""
        for slug in ("globalprotect-portals", "globalprotect-portal-authentication",
                     "globalprotect-coverage"):
            title = DOMAIN_BY_SLUG[slug].spec.sheet_title
            self.assertLessEqual(len(title), 31, f"{slug}: {title!r} is {len(title)} characters")

    # ------------------------------------------------------------------ the stated condition
    def test_the_stated_condition_renders_in_field_names_and_the_resolving_cells_are_present(self):
        """RECORDED AS IT IS RATHER THAN FIXED: `fires_when` is shared machinery.

        `render_node` consults `setting_labels` nowhere, so the condition reads
        `saved_credentials_posture ≠ 0` directly above a column headed "Save User Credentials"
        whose cell reads "Yes - username and password" - the same value named two ways on one row,
        and the raw `0` that the reader exists to keep out of the cell is printed in the condition
        anyway. What is asserted is that the cells which RESOLVE it are all still on the row.
        """
        cells = self.cells("globalprotect-portals", "PAN-GPP-004", "pan-fw-1085-a", "oep-gpp6-a")
        self.assertEqual("saved_credentials_posture ≠ 0",
                         cells["Fires when (failing condition)"])
        self.assertEqual("Yes - username and password", cells["Save User Credentials"])
        self.assertIn("The user's password is kept on the endpoint", cells["Matched queries"])
        self.assertIn("The user's password is kept on the endpoint", cells["Severity basis"])

    def test_the_severity_basis_announces_an_adjustment_that_moved_nothing(self):
        """RECORDED, NOT FIXED - `severity_basis` is out of this stage's scope.

        18 of this domain's 24 built rows read "Adjusted to <X> by: <query>" where <X> is already
        the control's default severity, so the cell announces a change that did not happen. Five
        rows are genuine adjustments. Pinned on one row of each kind so a later fix is visible as
        a test change rather than as silence.
        """
        noop = self.cells("globalprotect-portals", "PAN-GPP-003", "pan-fw-1085-a", "oep-gpp6-a")
        self.assertEqual("Medium", noop["Severity"])
        self.assertTrue(noop["Severity basis"].startswith("Adjusted to Medium by:"),
                        noop["Severity basis"])

        genuine = self.cells("globalprotect-portals", "PAN-GPP-004",
                             "pan-fw-1085-a", "oep-gpp6-c")
        self.assertEqual("Medium", genuine["Severity"])
        self.assertTrue(genuine["Severity basis"].startswith("Adjusted to Medium by:"))

    def test_a_row_matching_two_calibrations_finds_them_at_the_same_severity(self):
        """BOARD RECORD P450, AND ITS PRECONDITION IS REACHABLE HERE - which is NOT what the
        reasoning that cleared `decryption-policy` would have predicted, and is why this is
        asserted rather than asserted-absent.

        That run established that P450 cannot occur where every calibration of a control is
        mutually exclusive with its siblings, which holds when they all pin ONE column to
        distinct values. FIVE of this domain's six controls are that shape. PAN-GPP-005 IS NOT:
        its two calibrations clause on DIFFERENT fields - "The platform's own login page is
        served" on `custom_login_page`, and "Whether this portal serves a login page could not be
        established" on `mandatory_keys_present` - so one portal can and does match both, which
        this estate's `oep-gpp6-d` does.

        IT IS HARMLESS ONLY BECAUSE BOTH CARRY `medium`, the control's own default, so there is no
        lower grade for the basis cell to name. That is a property of two severities somebody
        chose and not of the machinery, so what is asserted is the condition itself: where a row
        matches more than one calibration, they must agree on the grade. Re-grading either of
        PAN-GPP-005's two calibrations makes P450 bite on this tab, and this test is what says so.
        """
        from assessments.models import ControlQuery

        severities = {}
        for query in ControlQuery.objects.select_related("control").all():
            severities[(query.control.control_id, query.name)] = query.adjusted_severity

        multi = []
        for slug in ("globalprotect-portals", "globalprotect-portal-authentication",
                     "globalprotect-coverage"):
            table = self.table(slug)
            for row in table.rows:
                cells = dict(zip(table.headers, row))
                control_id = cells["Control ID"]
                matched = [q for q in cells["Matched queries"].split("\n")
                           if q and q != "Baseline"]
                if len(matched) < 2:
                    continue
                multi.append((control_id, tuple(matched)))
                grades = {severities.get((control_id, name)) for name in matched}
                self.assertEqual(
                    1, len(grades),
                    f"{slug}: {control_id} matched {matched!r} at grades {grades!r} - P450 is "
                    f"now live on this tab and the basis cell can name the lower one")

        # And the one control where it happens is named, so a change in which control that is
        # shows up here rather than silently.
        self.assertEqual({"PAN-GPP-005"}, {control_id for control_id, _names in multi},
                         f"expected only PAN-GPP-005 to match two calibrations, got {multi!r}")

    # ------------------------------------------------------------------ the rail
    def test_each_of_the_three_models_has_exactly_one_rail_item(self):
        for model, slug in (
                ("integrations.GlobalProtectPortal", "globalprotect-portals"),
                ("integrations.GlobalProtectPortalClientAuthRow",
                 "globalprotect-portal-authentication"),
                ("integrations.GlobalProtectEnforcementPoint", "globalprotect-coverage")):
            items = [o for o in CONFIG_OBJECTS if o.search_model == model]
            self.assertEqual([slug], [o.slug for o in items], model)
            self.assertEqual("Network", items[0].category)
            self.assertEqual("GlobalProtect", items[0].group)
            self.assertTrue(items[0].where.startswith("Network > GlobalProtect"),
                            items[0].where)
            self.assertEqual(items, list(objects_for_model(model)))

    def test_the_prefix_is_out_of_awaiting_presentation(self):
        """An exemption that survives the work it was waiting for is a permanent hole, and while
        it stands `test_configuration_links` passes for the wrong reason: all 24 shipped PAN-GPP
        queries are exempted rather than resolved."""
        self.assertNotIn("PAN-GPP", cr.AWAITING_PRESENTATION)

    def test_each_rail_item_has_a_results_spec_whose_row_matches_its_columns(self):
        """The shipped squareness check cannot see what a cell SAYS, so this exercises the
        lambdas over real rows and reads them."""
        for slug, queryset in (
                ("globalprotect-portals", GlobalProtectPortal.objects.all()),
                ("globalprotect-portal-authentication",
                 GlobalProtectPortalClientAuthRow.objects.all()),
                ("globalprotect-coverage", GlobalProtectEnforcementPoint.objects.all())):
            spec = cr.RESULTS[slug]
            self.assertTrue(queryset.exists(), slug)
            for obj in queryset:
                row = spec.row(obj)
                self.assertEqual(len(spec.columns), len(row), f"{slug}: {obj}")
                self.assertTrue(all(cell is not None for cell in row), f"{slug}: {obj}")

    def test_the_explorer_pages_say_the_same_words_as_the_findings_tabs(self):
        """One column must not read two ways on two surfaces, which nothing checks."""
        portals = cr.RESULTS["globalprotect-portals"]
        row = dict(zip(portals.columns,
                       portals.row(GlobalProtectPortal.objects.get(name="oep-gpp6-a",
                                                                   appliance__hostname=
                                                                   "pan-fw-1085-a"))))
        self.assertEqual("Disallow", row["Allow User to Upgrade GlobalProtect App"])
        self.assertEqual("Yes - username and password", row["Save User Credentials"])
        self.assertEqual("factory-default", row["Portal Login Page"])
        self.assertEqual("1", row["Authentication rows"])

        auth = cr.RESULTS["globalprotect-portal-authentication"]
        auth_row = dict(zip(auth.columns, auth.row(
            GlobalProtectPortalClientAuthRow.objects.get(portal_name="oep-gpp6-e", name="r2"))))
        self.assertEqual("Browser", auth_row["Endpoint class (OS)"])
        self.assertEqual("no", auth_row["Credentials OR certificate"])
        self.assertEqual("Both a password AND a client certificate are required",
                         auth_row["What this row demands before admitting an endpoint"])

    def test_every_query_field_on_each_results_spec_is_registered_with_the_compiler(self):
        """Stored, searchable and registered are three different things, and a heading mapped to
        an unregistered field points the "build a query from these rows" button at a lookup that
        refuses itself or silently matches nothing."""
        from assessments.search.globalprotect_enforcement_point.compiler import (
            FIELD_OPERATOR_REGISTRY as POINT_REGISTRY)
        from assessments.search.globalprotect_portal.compiler import (
            FIELD_OPERATOR_REGISTRY as PORTAL_REGISTRY)
        from assessments.search.globalprotect_portal_client_auth.compiler import (
            FIELD_OPERATOR_REGISTRY as AUTH_REGISTRY)

        for slug, registry in (("globalprotect-portals", PORTAL_REGISTRY),
                               ("globalprotect-portal-authentication", AUTH_REGISTRY),
                               ("globalprotect-coverage", POINT_REGISTRY)):
            spec = cr.RESULTS[slug]
            for heading, field in spec.query_fields.items():
                self.assertIn(field, registry, f"{slug}: {heading!r} -> {field!r}")
                self.assertIn(heading, spec.columns, f"{slug}: {heading!r}")
