"""The two IPSec tabs as a customer reads them: what the columns are called, which cell is
marked, and the cells that say more than a field holds.

WHY THIS FILE EXISTS. The stage 9 run of the `ipsec-crypto` domain built both tabs and read all
64 rows, and the things it could not settle were all report content - what the derived columns are
headed, whether the workbook carries the firing condition, and what a cell should say where the
shared `display_value` has no word for the state. Nothing in this repo held any of those, so each
was a judgement the next change could undo in silence. Two of them were WRONG when first written
and reading a row is what found them, which is the argument for pinning them here:

  - `null` at `esp/encryption` is the CLEARTEXT cipher and the worst member of PAN-IPS-002's
    order. Printed bare it reads as absent data in a column of algorithm names, so the most
    alarming cell on the row looked like the one nobody filled in.
  - `none` at `esp/authentication` is TWO different facts. On a profile whose ciphers only
    encrypt it is integrity declined; on an AEAD profile it is the member the VENDOR MANDATES,
    and PAN-IPS-003 excludes that case by applicability rather than scoring it. The first version
    of the cell called both a declined integrity algorithm, on `Suite-B-GCM-128`, beside a
    finding about something else entirely.

FIVE OF THESE CONTROLS CHANGED SUBJECT ON 2026-11-04. PAN-IPS-001 to -005 are keyed on the IPSEC
TUNNEL PATH now rather than on the crypto profile, so their rows are on a third tab - Jason: *"A
weak profile use on one IPSec tunnel should not receive the same treatment as a weak profile used
on 1000 IPSec tunnels. The best way to accomplish this is to raise a finding per effected
tunnel."* PAN-IPS-009 stays on the profile tab, because a profile nothing references is a fact
about the profile and has no path to sit on, and PAN-IPS-006 to -008 stay on the tunnel tab.

EVERY CELL WORDING PINNED BELOW MOVED WITH ITS CONTROL AND NOT ONE OF THEM CHANGED, which is the
point: the path tab declares the SAME `value_readers` the profile tab does, so `null` is still
named as the cleartext cipher and `none` still reads two ways. A second phrasing on the new tab
would be the same defect this file was written for.

AND EACH PROFILE IS PUT ON A SYNTHETIC PATH so the five moved controls have a row to assert. The
lab's four tunnels name only `oep-ips6-p10`, so without one tunnel per profile five of the six
readback profiles would have no path and no row at all.

THE FIXTURE IS A SUBSET AND SAYS SO. Six of the lab's sixteen crypto profiles and all four of its
tunnels, transcribed from `stage6-ipsec-crypto.json`'s `verified.read_back` blocks - which is what
`type=config&action=show` returned from pan-fw-111 and pan-fw-201 after the commits that created
them, on 2026-10-27. They are the six that exercise a cell whose wording is a judgement; the whole
lab's 108 verdicts are reconciled in OptivEdgeProbe's stage 8 artifact and not here. Everything is
put on ONE appliance, which no assertion below depends on.
"""
from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as config_results
from assessments import ipsec_presentation as ipsec
from assessments.artifacts.domains import DOMAINS
from assessments.artifacts.layout import NONE
from assessments.artifacts.sheets.findings import build_findings_table
from assessments.ipsec_crypto_profile_findings import generate_ipsec_crypto_profile_findings
from assessments.ipsec_tunnel_findings import generate_ipsec_tunnel_findings
from assessments.ipsec_tunnel_path_findings import generate_ipsec_tunnel_path_findings
from assessments.models import AssessmentRun, Control
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.ipsec import (
    normalize_ipsec_crypto_profiles, normalize_ipsec_tunnels, normalize_monitor_profiles)
from optivedge_integrations.integrations.platforms.pan_os.normalization.ipsec_path import (
    normalize_ipsec_tunnel_paths)
from optivedge_integrations.integrations.models import IpsecCryptoProfile, IpsecTunnel

#: The five that moved onto the path, 2026-11-04.
PATH_CONTROLS = ["PAN-IPS-001", "PAN-IPS-002", "PAN-IPS-003", "PAN-IPS-004", "PAN-IPS-005"]
#: What is left on the profile tab: the unreferenced-profile control alone.
PROFILE_CONTROLS = ["PAN-IPS-009"]
TUNNEL_CONTROLS = ["PAN-IPS-006", "PAN-IPS-007", "PAN-IPS-008"]
PATH_SLUG = "ipsec-tunnel-paths"

#: A one-member list is what the read_back blocks record and what `iter_member_values` reads; a
#: bare string is what xmltodict delivers for the same node. Both arrive here, and the normalizer
#: reads them identically.
PROFILES = [
    # The null cipher with md5, re-keying on no-pfs, on a thirty-day lifetime written in DAYS.
    {"@name": "oep-ips6-p01",
     "esp": {"encryption": {"member": ["null"]}, "authentication": {"member": ["md5"]}},
     "dh-group": "no-pfs", "lifetime": {"days": "30"}},
    # THE INTEGRITY-ONLY AH BRANCH. `weakest_encryption_offered` is the EMPTY STRING here and
    # PAN-IPS-002 fires and marks that cell, which is the row the wording pinned below is for.
    {"@name": "oep-ips6-p08",
     "ah": {"authentication": {"member": ["sha256"]}},
     "dh-group": "group14", "lifetime": {"hours": "1"}},
    # NEITHER BRANCH, and committable: the lifetime is the object's only mandatory key.
    {"@name": "oep-ips6-p09", "lifetime": {"hours": "1"}},
    # The one profile a tunnel names, so its reference count is not zero.
    {"@name": "oep-ips6-p10",
     "esp": {"encryption": {"member": ["aes-256-gcm"]}, "authentication": {"member": ["none"]}},
     "dh-group": "group21", "lifetime": {"hours": "1"}},
    # `none` integrity beside a cipher that ONLY ENCRYPTS - integrity declined, at critical.
    {"@name": "oep-ips6-p11",
     "esp": {"encryption": {"member": ["aes-128-cbc"]}, "authentication": {"member": ["none"]}},
     "dh-group": "group14", "lifetime": {"hours": "1"}},
    # `none` integrity beside an AEAD cipher - the member the vendor MANDATES. Same stored value
    # as the row above and the opposite fact.
    {"@name": "Suite-B-GCM-128",
     "esp": {"encryption": {"member": ["aes-128-gcm"]}, "authentication": {"member": ["none"]}},
     "dh-group": "group19", "lifetime": {"hours": "1"}},
]

TUNNELS = [
    # Both switches READ and both off.
    {"@name": "oep-ips6-t01", "tunnel-interface": "tunnel.61", "disabled": "yes",
     "anti-replay": "no", "tunnel-monitor": {"enable": "no"}},
    # NEITHER switch present. A null boolean matches no positive comparison, so what fires is the
    # companion column and that is the cell that has to be marked.
    {"@name": "oep-ips6-t02", "tunnel-interface": "tunnel.61", "disabled": "yes"},
    # Monitoring on, with a target and a profile that RESOLVES - the only route by which a
    # monitor profile's content reaches any row of this report.
    {"@name": "oep-ips6-t03", "tunnel-interface": "tunnel.61", "disabled": "yes",
     "anti-replay": "yes",
     "tunnel-monitor": {"enable": "yes", "destination-ip": "192.0.2.61",
                        "tunnel-monitor-profile": "oep-ips6-m01"}},
    # The one tunnel that WRITES a crypto-profile reference, so the inference below is absent
    # from exactly one row.
    {"@name": "oep-ips6-t04", "tunnel-interface": "tunnel.61", "disabled": "yes",
     "auto-key": {"ike-gateway": {"entry": [{"@name": "oep-ike6-g01"}]},
                  "ipsec-crypto-profile": "oep-ips6-p10"}},
]

MONITOR_PROFILES = [
    {"@name": "oep-ips6-m01", "interval": "2", "threshold": "2", "action": "fail-over"},
]


def merged_payload():
    return {"config": {"devices": {"entry": [{
        "@name": "localhost.localdomain",
        "network": {
            "ike": {"crypto-profiles": {"ipsec-crypto-profiles": {"entry": list(PROFILES)}}},
            "tunnel": {"ipsec": {"entry": list(TUNNELS)}},
            "profiles": {"monitor-profile": {"entry": list(MONITOR_PROFILES)}},
        }}]}}}


class IpsecTabTestCase(TestCase):
    def setUp(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.ips")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-ips",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="6A9C0A9904E7D6E", hostname="pan-fw-111")
        run = AssessmentRun.objects.create(
            name="IPSec", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        seed_controls(PROFILE_CONTROLS, control_type=Control.ControlType.IPSEC_CRYPTO_PROFILE)
        seed_controls(TUNNEL_CONTROLS, control_type=Control.ControlType.IPSEC_TUNNEL)
        seed_controls(PATH_CONTROLS, control_type=Control.ControlType.IPSEC_TUNNEL_PATH)
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload=merged_payload())
        normalize_ipsec_crypto_profiles(appliance)
        normalize_monitor_profiles(appliance)
        normalize_ipsec_tunnels(appliance)
        generate_ipsec_crypto_profile_findings(run)
        generate_ipsec_tunnel_findings(run)
        self._one_tunnel_per_profile(station, group, appliance)
        normalize_ipsec_tunnel_paths(appliance)
        generate_ipsec_tunnel_path_findings(run)

    @staticmethod
    def _one_tunnel_per_profile(station, group, appliance):
        """A tunnel naming each stored profile, so every profile is on exactly one path.

        SCAFFOLDING AND NOT A READING, and prefixed `probe-` so no assertion can mistake one for
        a stage 6 subject. The path normalizer joins stored rows rather than parsing a payload,
        so stored rows are what it is given.
        """
        snapshot = Snapshot.objects.filter(appliance=appliance).latest("collected_at")
        for profile in IpsecCryptoProfile.objects.filter(appliance=appliance):
            IpsecTunnel.objects.create(
                management_station=station, appliance=appliance, appliance_group=group,
                source_snapshot=snapshot, tunnel_name=f"probe-{profile.profile_name}",
                crypto_profile_name=profile.profile_name)

    @staticmethod
    def table(slug):
        return build_findings_table(next(d.spec for d in DOMAINS if d.slug == slug))

    def cell(self, slug, control_id, subject, heading):
        table = self.table(slug)
        row = self.row(table, control_id, subject)
        return row[table.headers.index(heading)]

    @staticmethod
    def row(table, control_id, subject):
        name = table.headers.index("Object")
        found = [r for r in table.rows if r[1] == control_id and r[name] == subject]
        assert len(found) == 1, f"{control_id} / {subject}: {len(found)} rows"
        return found[0]

    def marked(self, slug, control_id, subject):
        table = self.table(slug)
        index = table.rows.index(self.row(table, control_id, subject))
        return sorted(table.headers[c] for (r, c) in table.implicated if r == index)

    @staticmethod
    def path_row(table, control_id, profile_name):
        """One row of the path tab, found by the PROFILE it runs on.

        The path tab's Object column is the TUNNEL - one row is one place traffic crosses - and
        every expectation in this file is a statement about one profile's content.
        """
        named = table.headers.index("IPSec crypto profile named")
        found = [r for r in table.rows if r[1] == control_id and r[named] == profile_name]
        assert len(found) == 1, f"{control_id} / {profile_name}: {len(found)} rows"
        return found[0]

    def path_cell(self, control_id, profile_name, heading):
        table = self.table(PATH_SLUG)
        return self.path_row(table, control_id, profile_name)[table.headers.index(heading)]

    def path_marked(self, control_id, profile_name):
        table = self.table(PATH_SLUG)
        index = table.rows.index(self.path_row(table, control_id, profile_name))
        return sorted(table.headers[c] for (r, c) in table.implicated if r == index)


class NoHeadingIsSilentlyBroken(IpsecTabTestCase):
    """A duplicate header is the silent one: Excel rejects a table that has one, xlsxwriter drops
    the table with a warning, and the sheet comes out as stray cells where the table should be
    (seen 2026-09-18 on two other tabs). Nothing else in the build fails."""

    def test_no_tab_repeats_a_heading(self):
        for slug in ("ipsec-crypto-profiles", "ipsec-tunnels", PATH_SLUG):
            headers = self.table(slug).headers
            repeated = sorted({h for h in headers if headers.count(h) > 1})
            self.assertEqual([], repeated, f"{slug} repeats {repeated}")

    def test_no_tab_heads_a_column_with_a_field_name(self):
        """`setting_columns` falls back to the raw Django field name, which is what 28 of the 33
        findings tabs still head every derived column with."""
        for slug in ("ipsec-crypto-profiles", "ipsec-tunnels", PATH_SLUG):
            for heading in self.table(slug).headers:
                self.assertNotIn("_", heading, f"{slug} heads a column `{heading}`")

    def test_every_tab_carries_the_firing_condition_in_the_workbook(self):
        """`tested_columns` DEFAULTS to `('Provenance',)`, which keeps `Fires when` on the live
        page and drops it from the xlsx - so a row's defects split across the two media and the
        workbook shows the contradicting value under the control's name with no stated condition
        at all. Both specs declare `ALL_TESTED_COLUMNS` instead, deliberately."""
        for slug in ("ipsec-crypto-profiles", "ipsec-tunnels", PATH_SLUG):
            self.assertIn("Fires when (failing condition)", self.table(slug).headers, slug)


class EveryRowPointsAtSomething(IpsecTabTestCase):
    """`hidden_fields` is empty on both specs, which is the only known cause of a row with no
    value-at-fault mark anywhere in this repository - a census of all 33 findings tabs, correlating
    in both directions. `check_every_tested_field_is_presented` would NOT catch it: it accepts a
    field's presence in `hidden_fields` as proof that something shows it."""

    def test_every_row_on_every_tab_marks_at_least_one_cell(self):
        for slug in ("ipsec-crypto-profiles", "ipsec-tunnels", PATH_SLUG):
            table = self.table(slug)
            marked_rows = {r for r, _c in table.implicated}
            unmarked = [i for i in range(len(table.rows)) if i not in marked_rows]
            self.assertEqual([], unmarked, f"{slug}: rows with no mark at all: {unmarked}")
            self.assertTrue(table.rows, f"{slug} drew no rows, so this proves nothing")

    def test_the_applicability_clause_is_never_the_marked_cell(self):
        """`all_offered_ciphers_authenticate` is PAN-IPS-003's applicability clause and no
        control asserts on it. Marked, it would read No with the value-at-fault fill on the rows
        of a control that is only applicable BECAUSE it reads No."""
        table = self.table(PATH_SLUG)
        marked = {table.headers[c] for (_r, c) in table.implicated}
        self.assertNotIn("Every payload cipher authenticates", marked)
        self.assertTrue(marked, "nothing was marked at all, so this proves nothing")

    def test_the_companion_column_is_what_an_unread_switch_marks(self):
        """`anti_replay equals false` does not match a tunnel whose key is ABSENT - a null
        boolean matches no positive comparison - so PAN-IPS-006's firing is moved onto the
        companion column, and the mark has to move with it. The switch itself reads `(none)` on
        that row and must not be offered as the thing to change."""
        self.assertEqual(["Replay protection read?"],
                         self.marked("ipsec-tunnels", "PAN-IPS-006", "oep-ips6-t02"))
        self.assertEqual(["Far-end monitoring read?"],
                         self.marked("ipsec-tunnels", "PAN-IPS-007", "oep-ips6-t02"))
        # And where the key WAS read, the switch itself is the fault.
        self.assertEqual(["Replay protection"],
                         self.marked("ipsec-tunnels", "PAN-IPS-006", "oep-ips6-t01"))


class ACellSaysWhatTheStoredValueCannot(IpsecTabTestCase):
    """The four readings that are judgements rather than fields, each pinned on the row that
    made it one. `display_value` has three answers - a value, `(none)`, `(empty)` - and it is
    shared by every tab, so these go through the spec's own `value_readers`."""

    def test_the_marked_cipher_cell_is_never_empty_on_a_profile_with_no_cipher(self):
        """PAN-IPS-002 fires on the AH-branch profile and MARKS `weakest_encryption_offered`,
        which stores the empty string there. `display_value` prints `(empty)`, so the row offered
        `(empty)` as the value an engineer should change."""
        self.assertEqual(["Weakest payload cipher"],
                         self.path_marked("PAN-IPS-002", "oep-ips6-p08"))
        cell = self.path_cell("PAN-IPS-002", "oep-ips6-p08", "Weakest payload cipher")
        self.assertNotIn("(empty)", cell)
        self.assertIn("AH", cell)

    def test_the_cleartext_cipher_is_named_rather_than_printed_bare(self):
        """`null` is a cipher and the WORST member of the order. Bare, it reads as absent data."""
        for heading in ("Weakest payload cipher", "Encryption offered (ESP)"):
            cell = self.path_cell("PAN-IPS-002", "oep-ips6-p01", heading)
            self.assertIn("cleartext", cell, heading)

    def test_the_two_meanings_of_a_none_integrity_member_read_differently(self):
        """Same stored value, opposite facts: declined integrity beside a cipher that only
        encrypts, against the member the vendor MANDATES for an AEAD cipher."""
        declined = self.path_cell("PAN-IPS-003", "oep-ips6-p11",
                                  "Weakest payload integrity algorithm")
        mandated = self.path_cell("PAN-IPS-002", "Suite-B-GCM-128",
                                  "Weakest payload integrity algorithm")
        self.assertIn("declined", declined)
        self.assertNotIn("declined", mandated)
        self.assertIn("not required", mandated)

    def test_the_branchless_profile_does_not_read_as_a_missing_cell(self):
        """`protocol_branch` stores the token `none` for a COMMITTED state, and `display_value`'s
        word for a NULL is `(none)` - so printed raw a reader cannot tell the two apart."""
        self.assertEqual("Neither branch",
                         self.path_cell("PAN-IPS-001", "oep-ips6-p09",
                                        "Payload protection branch"))

    def test_the_lifetime_carries_the_unit_it_was_written_in(self):
        """The hours are a CONVERSION; the unit is where an engineer goes to change it, and a
        profile written in days holds nothing at all at the hour branch."""
        self.assertEqual("720 h (written in days)",
                         self.path_cell("PAN-IPS-005", "oep-ips6-p01",
                                        "Payload key lifetime (as written)"))

    def test_a_zero_reference_count_says_what_was_counted(self):
        """A bare 0 in a reference column reads as "not counted" exactly where it means
        "counted, and the answer was none" - and here zero is the finding."""
        self.assertIn("Nothing on this firewall names it",
                      self.cell("ipsec-crypto-profiles", "PAN-IPS-009", "oep-ips6-p09",
                                "Named by a tunnel here"))

    def test_the_em_dash_is_the_one_layout_uses(self):
        """U+2014. Four stage 9 artifacts and `ike_presentation` call it an en-dash, so a reader
        grepping for the wrong character finds nothing. Asserted rather than imported, because
        `artifacts.layout` is a workbook module and `ipsec_presentation` is imported at request
        time."""
        self.assertEqual(NONE, ipsec.NOT_APPLICABLE)
        self.assertEqual("—", ipsec.NOT_APPLICABLE)

    def test_a_branch_the_profile_does_not_have_reads_as_inapplicable(self):
        """Not `(empty)`: an absent AH list on an ESP profile is not an unmeasured value, it is
        a branch the profile does not have. The two integrity columns are separate because ONE
        grid column on the device serves both branches."""
        self.assertEqual(NONE,
                         self.path_cell("PAN-IPS-003", "oep-ips6-p11", "Integrity offered (AH)"))
        self.assertEqual(NONE,
                         self.path_cell("PAN-IPS-002", "oep-ips6-p08",
                                        "Encryption offered (ESP)"))


class ThePointerColumnsSayWhatNoOtherCellCan(IpsecTabTestCase):
    def test_an_inferred_crypto_profile_reference_says_it_was_inferred(self):
        """Where the tunnel writes no reference the column holds the literal `default`, which is
        an INFERENCE - stage 4 set `may_materialise: false` on three leads and not one
        measurement. The recorded `assumed_default` reaches no other cell on the row, because the
        Provenance column answers per TESTED field and no clause in this domain reads this one.
        That cell is the only one on either tab that is handed `provenance_of`."""
        inferred = self.cell("ipsec-tunnels", "PAN-IPS-008", "oep-ips6-t01",
                             "IPSec crypto profile named")
        written = self.cell("ipsec-tunnels", "PAN-IPS-008", "oep-ips6-t04",
                            "IPSec crypto profile named")
        self.assertIn("inferred", inferred)
        self.assertIn("default", inferred)
        self.assertEqual("oep-ips6-p10", written)

    def test_the_monitor_profiles_action_reaches_a_row_through_the_tunnel(self):
        """`integrations.MonitorProfile` is stored and normalised and NO shipped query names it,
        so it has no rail item and no findings tab of its own - and this is the only cell in the
        whole report where its content reaches a reader."""
        self.assertEqual("Fail over",
                         self.cell("ipsec-tunnels", "PAN-IPS-008", "oep-ips6-t03",
                                   "Monitor action if probing fails"))
        # And the three states that all store the empty string are told apart rather than blank.
        self.assertEqual(NONE,
                         self.cell("ipsec-tunnels", "PAN-IPS-008", "oep-ips6-t01",
                                   "Monitor action if probing fails"))

    def test_the_unreported_half_of_pan_ips_009_says_so_on_the_row(self):
        """PAN-IPS-009's first stage 5 record asserts on `effective_crypto_profile_chosen` over
        the TUNNEL and its second over the crypto profile; a `Control` is one model per control
        type, so stage 8 could ship only the profile half. The column is on the row, is markable,
        and nothing will ever mark it."""
        cell = self.cell("ipsec-tunnels", "PAN-IPS-008", "oep-ips6-t01",
                         "Running on a chosen profile")
        self.assertIn("not reported by any control", cell)
        table = self.table("ipsec-tunnels")
        marked = {table.headers[c] for (_r, c) in table.implicated}
        self.assertNotIn("Running on a chosen profile", marked)


class TheExplorerPagesLambdasActuallyRun(IpsecTabTestCase):
    """`test_configuration_queries.test_every_row_is_as_wide_as_its_columns` walks every
    `ResultsSpec` but has fixtures for ONE model, so a page whose `row` lambda has never been
    called over a real object is square by vacuity. The `ike-crypto` run found that and closed it
    with a throwaway; this closes it for these two pages with the fixture already seeded here.

    The findings tabs and the explorer pages are two surfaces over the same objects, and the
    reason `ipsec_presentation` is one module is that a cell reading "0" on one page and
    "nothing names it" on the other sends an engineer to argue with their own report."""

    def test_both_result_specs_render_every_row_at_the_right_width(self):
        # The tunnel count includes the one synthetic tunnel per profile that setUp adds so the
        # five moved controls have a path to sit on. The explorer page lists every tunnel the
        # appliance holds and has no reason to hide them.
        for slug, expected in (("ipsec-crypto", len(PROFILES)),
                               ("ipsec-tunnels", len(TUNNELS) + len(PROFILES))):
            spec = config_results.RESULTS[slug]
            rows = list(spec.base_queryset())
            self.assertEqual(expected, len(rows), slug)
            for item in rows:
                cells = spec.row(item)
                self.assertEqual(len(spec.columns), len(cells), f"{slug} / {item}")
                for heading, cell in zip(spec.columns, cells):
                    self.assertTrue(str(cell).strip(), f"{slug} / {item}: {heading} is blank")

    def test_the_two_surfaces_agree_about_one_object(self):
        """The same reading, reached two ways. Not a tautology: the explorer calls
        `crypto_profile_named` WITHOUT `provenance_of`, which it has no index for, so this is
        also the assertion that the optional argument is genuinely optional."""
        spec = config_results.RESULTS["ipsec-tunnels"]
        row = next(spec.row(t) for t in spec.base_queryset()
                   if t.tunnel_name == "oep-ips6-t01")
        page_cell = row[spec.columns.index("IPSec crypto profile")]
        tab_cell = self.cell("ipsec-tunnels", "PAN-IPS-008", "oep-ips6-t01",
                             "IPSec crypto profile named")
        # The page cannot say the reference was inferred and the tab can; both name the profile.
        self.assertEqual("default", page_cell)
        self.assertTrue(tab_cell.startswith("default"))
        self.assertIn("inferred", tab_cell)
