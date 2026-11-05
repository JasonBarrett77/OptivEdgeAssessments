"""The IPSec tunnel path, as a finding count and as a tab. PAN-IKE-002 to -005, PAN-IPS-001 to -005.

WHAT THIS FILE IS FOR. The nine strength controls moved off the two crypto profile models onto the
path on 2026-11-04, for one reason: a profile is a named algorithm set and not an enforcement
point, so keyed on the profile a weak proposal earned ONE finding whether one tunnel ran on it or
a thousand did. Jason: *"A weak profile use on one IPSec tunnel should not receive the same
treatment as a weak profile used on 1000 IPSec tunnels. The best way to accomplish this is to
raise a finding per effected tunnel."* The first class below is that claim as a count, and it is
the assertion the whole change exists to satisfy.

THE REST PIN THE THREE RULINGS THAT CAME WITH IT, each of which a later change could undo in
silence because each one makes a row report where the obvious reading would pass it:

  - an unresolvable binding FAILS - no IKE gateway, no IKE crypto profile named, or an IPSec
    crypto profile left at `default` - and it fails through the baseline queries the nine controls
    already shipped, with nothing added to the catalogue;
  - the `disabled` flag is not read at all, on tunnel or gateway;
  - an orphan IKE gateway is listed with no tunnel against it and is graded on the IKE side only.

THE ESTATE IS BUILT FROM ROWS rather than from a merged snapshot, which is what the path
normalizer itself reads: it joins the four collections' rows and parses no payload.
"""
from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.artifacts.domains import DOMAINS
from assessments.artifacts.sheets.findings import build_findings_table
from assessments.ipsec_tunnel_path_findings import generate_ipsec_tunnel_path_findings
from assessments.models import AssessmentRun, Control, IpsecTunnelPathFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, FieldProvenance, IkeCryptoProfile, IkeGateway,
    IpsecCryptoProfile, IpsecTunnel, ManagementStation, Snapshot)
from django.contrib.contenttypes.models import ContentType
from optivedge_integrations.integrations.platforms.pan_os.normalization.ipsec_path import (
    normalize_ipsec_tunnel_paths)

IKE_CONTROLS = ["PAN-IKE-002", "PAN-IKE-003", "PAN-IKE-004", "PAN-IKE-005"]
IPSEC_CONTROLS = ["PAN-IPS-001", "PAN-IPS-002", "PAN-IPS-003", "PAN-IPS-004", "PAN-IPS-005"]
SLUG = "ipsec-tunnel-paths"

#: A phase 1 proposal that fails all four IKE controls: the 1024-bit group, 3DES, SHA-1 and a key
#: that stands for a month with no re-authentication bound.
WEAK_IKE = {
    "weakest_dh_group": "group2", "dh_group_floor_met": False,
    "weakest_encryption_cipher": "3des", "encryption_floor_met": False,
    "weakest_hash_algorithm": "sha1", "hash_floor_met": False,
    "key_lifetime_hours": 720, "key_lifetime_known": True,
    "reauth_interval_bounded": False,
}

#: A phase 2 proposal that fails all five IPSec controls: the integrity-only AH branch, so no
#: cipher at all, md5 integrity, no per-association key agreement and a 30-day key.
WEAK_IPSEC = {
    "protocol_branch": IpsecCryptoProfile.ProtocolBranch.AH,
    "weakest_encryption_offered": "", "weakest_integrity_offered": "md5",
    "all_offered_ciphers_authenticate": False, "integrity_meets_sha2_floor": False,
    "dh_group": "no-pfs", "dh_group_meets_target": False,
    "lifetime_hours": 720, "lifetime_within_target": False,
}


class IpsecPathTestCase(TestCase):
    """One appliance, and every row built by hand so each test says what its estate is."""

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.path")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-path",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="6A9C0A9904E7D6E", hostname="pan-fw-111")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": [{"@name": "localhost.localdomain"}]}}})
        self.run = AssessmentRun.objects.create(
            name="IPSec paths", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        seed_controls(IKE_CONTROLS + IPSEC_CONTROLS,
                      control_type=Control.ControlType.IPSEC_TUNNEL_PATH)

    def _anchors(self):
        return {"management_station": self.station, "appliance": self.appliance,
                "appliance_group": self.group, "source_snapshot": self.snapshot}

    def tunnel(self, name, *, gateways=None, crypto="", inferred=False, **extra):
        row = IpsecTunnel.objects.create(
            **self._anchors(), tunnel_name=name, ike_gateway_names=gateways,
            crypto_profile_name=crypto, **extra)
        if inferred:
            FieldProvenance.objects.create(
                content_type=ContentType.objects.get_for_model(IpsecTunnel),
                object_id=row.pk, field_name="crypto_profile_name",
                provenance_type=FieldProvenance.ProvenanceType.ASSUMED_DEFAULT,
                raw_value="default")
        return row

    def gateway(self, name, profile="", **extra):
        values = {"ike_version": IkeGateway.IkeVersion.IKEV2,
                  "ikev2_crypto_profile_name": profile}
        values.update(extra)
        return IkeGateway.objects.create(**self._anchors(), entry_name=name, **values)

    def ike_profile(self, name, **values):
        return IkeCryptoProfile.objects.create(**self._anchors(), entry_name=name, **values)

    def ipsec_profile(self, name, **values):
        defaults = {"dh_group": "group14", "lifetime_hours": 1}
        defaults.update(values)
        return IpsecCryptoProfile.objects.create(
            **self._anchors(), profile_name=name, **defaults)

    def generate(self):
        normalize_ipsec_tunnel_paths(self.appliance)
        return generate_ipsec_tunnel_path_findings(self.run)

    @staticmethod
    def findings(control_id):
        return list(IpsecTunnelPathFinding.objects.filter(control__control_id=control_id)
                    .order_by("subject_name"))

    @staticmethod
    def table():
        return build_findings_table(next(d.spec for d in DOMAINS if d.slug == SLUG))


class OneFindingPerTunnelTests(IpsecPathTestCase):
    """THE CLAIM THE WHOLE CHANGE RESTS ON: the finding count is the number of tunnels affected."""

    def test_one_weak_profile_on_three_tunnels_is_three_findings_for_each_control(self):
        """Keyed on the profile, as these nine controls shipped, this estate earned ONE finding
        per control and the count said nothing about reach."""
        self.ike_profile("weak-ike", **WEAK_IKE)
        self.ipsec_profile("weak-ipsec", **WEAK_IPSEC)
        for n in (1, 2, 3):
            self.tunnel(f"t0{n}", gateways=[f"g0{n}"], crypto="weak-ipsec")
            self.gateway(f"g0{n}", profile="weak-ike")
        self.generate()
        for control_id in IKE_CONTROLS + IPSEC_CONTROLS:
            self.assertEqual(len(self.findings(control_id)), 3, control_id)

    def test_each_finding_names_its_own_tunnel_and_gateway(self):
        """So a reader of any one of them knows which path it is about - and so two rows of a
        tunnel that named two gateways could never collide on the subject name."""
        self.ike_profile("weak-ike", **WEAK_IKE)
        self.tunnel("t01", gateways=["g01", "g02"], crypto="p")
        self.gateway("g01", profile="weak-ike")
        self.gateway("g02", profile="weak-ike")
        self.generate()
        self.assertEqual([f.subject_name for f in self.findings("PAN-IKE-002")],
                         ["t01 / g01", "t01 / g02"])

    def test_the_summary_names_the_place_before_the_fault(self):
        self.ike_profile("weak-ike", **WEAK_IKE)
        self.tunnel("t01", gateways=["g01"], crypto="p")
        self.gateway("g01", profile="weak-ike")
        self.generate()
        summary = self.findings("PAN-IKE-002")[0].summary
        self.assertIn("IPSec tunnel t01 on pan-fw-111", summary)
        self.assertIn("through IKE gateway g01", summary)
        self.assertIn("running the IKE crypto profile weak-ike", summary)
        # The algorithm half is the profile generator's own sentence, run on the path row.
        self.assertIn("weakest group2", summary)

    def test_a_hardened_path_reports_nothing(self):
        """The population matters as much as the firing: nine controls that fired on everything
        would also satisfy the count assertions above."""
        self.ike_profile("strong-ike", weakest_dh_group="group20", dh_group_floor_met=True,
                         weakest_encryption_cipher="aes-256-gcm", encryption_floor_met=True,
                         weakest_hash_algorithm="sha384", hash_floor_met=True,
                         key_lifetime_hours=8, key_lifetime_known=True,
                         reauth_interval_bounded=True)
        self.ipsec_profile(
            "strong-ipsec", protocol_branch=IpsecCryptoProfile.ProtocolBranch.ESP,
            weakest_encryption_offered="aes-256-gcm", weakest_integrity_offered="sha256",
            all_offered_ciphers_authenticate=True, integrity_meets_sha2_floor=True,
            dh_group="group20", dh_group_meets_target=True,
            lifetime_hours=1, lifetime_within_target=True)
        self.tunnel("t01", gateways=["g01"], crypto="strong-ipsec")
        self.gateway("g01", profile="strong-ike")
        self.generate()
        self.assertEqual(IpsecTunnelPathFinding.objects.count(), 0)


class AnUnresolvableBindingFailsTests(IpsecPathTestCase):
    """Jason, 2026-11-04: *"IKE Crypto is a required field on IPSec Tunnel. If the value is
    missing, that is an invalid configuration. IPSec Crypto Profile must also be specified, but
    the default value is 'default'. We can't know what the 'default' value means, so we should
    assume that it fails if it is default, unspecified, or otherwise unknown."*

    AND NOTHING WAS ADDED TO THE CATALOGUE TO MAKE IT FAIL, which is checked here rather than
    assumed: every one of the nine baselines is a negated equality or a false verdict boolean, and
    an unresolved path stores a blank in every value column and leaves every verdict false.
    """

    def test_a_tunnel_with_no_ike_gateway_fires_all_four_ike_controls(self):
        """Three of pan-fw-111's four tunnels are stored exactly this way."""
        self.tunnel("t02", crypto="default", inferred=True)
        self.generate()
        for control_id in IKE_CONTROLS:
            self.assertEqual(len(self.findings(control_id)), 1, control_id)

    def test_and_the_finding_says_invalid_rather_than_weak(self):
        """An unresolved path never reports a weak ALGORITHM, because no algorithm was read."""
        self.tunnel("t02", crypto="default", inferred=True)
        self.generate()
        summary = self.findings("PAN-IKE-002")[0].summary
        self.assertIn("names NO IKE GATEWAY", summary)
        self.assertIn("invalid configuration rather than a weak one", summary)
        self.assertNotIn("key agreement offered", summary)
        self.assertNotIn("weakest", summary)

    def test_a_gateway_naming_no_ike_crypto_profile_fires_the_same_four(self):
        self.tunnel("t01", gateways=["g01"], crypto="p")
        self.gateway("g01")
        self.generate()
        for control_id in IKE_CONTROLS:
            self.assertEqual(len(self.findings(control_id)), 1, control_id)
        self.assertIn("names NO IKE CRYPTO PROFILE",
                      self.findings("PAN-IKE-003")[0].summary)

    def test_a_tunnel_left_at_the_default_ipsec_profile_fires_all_five_ipsec_controls(self):
        self.tunnel("t02", crypto="default", inferred=True)
        self.generate()
        for control_id in IPSEC_CONTROLS:
            self.assertEqual(len(self.findings(control_id)), 1, control_id)
        self.assertIn("runs on whatever PAN-OS renders as `default`",
                      self.findings("PAN-IPS-002")[0].summary)

    def test_an_unresolved_path_reports_at_the_controls_default_severity(self):
        """The per-value calibration queries compare against value lists and a blank matches no
        member of one, so "we cannot tell what this tunnel proposes" earns no graded severity.
        PAN-IPS-004 grades `no-pfs` and six groups; an unresolved path matches none of the seven.
        """
        self.tunnel("t02", crypto="default", inferred=True)
        self.generate()
        control = Control.objects.get(control_id="PAN-IPS-004")
        self.assertEqual(self.findings("PAN-IPS-004")[0].severity, control.default_severity)

    def test_a_dangling_profile_name_is_reported_as_dangling(self):
        self.tunnel("t01", crypto="gone")
        self.generate()
        self.assertIn("does NOT EXIST on this appliance",
                      self.findings("PAN-IPS-001")[0].summary)


class TheDisabledFlagIsNotReadTests(IpsecPathTestCase):
    """Jason, 2026-11-04: *"The 'disabled' value is ignored. So give a tunnel/gateway the same
    treatment regardless of the disabled state."* All four of pan-fw-111's tunnels are
    `disabled=yes`, so a suppression anywhere here would silence the only appliance in this lab
    that terminates a tunnel at all."""

    def test_a_switched_off_tunnel_reports_exactly_as_a_live_one_does(self):
        self.ipsec_profile("weak-ipsec", **WEAK_IPSEC)
        self.tunnel("on", crypto="weak-ipsec", is_disabled=False)
        self.tunnel("off", crypto="weak-ipsec", is_disabled=True)
        self.generate()
        self.assertEqual([f.subject_name for f in self.findings("PAN-IPS-001")],
                         ["off / (no gateway)", "on / (no gateway)"])

    def test_an_inactive_gateway_reports_exactly_as_an_active_one_does(self):
        self.ike_profile("weak-ike", **WEAK_IKE)
        self.tunnel("t01", gateways=["live"], crypto="p")
        self.tunnel("t02", gateways=["dead"], crypto="p")
        self.gateway("live", profile="weak-ike")
        self.gateway("dead", profile="weak-ike", disabled=True, gateway_is_active=False)
        self.generate()
        self.assertEqual(len(self.findings("PAN-IKE-004")), 2)


class AnOrphanGatewayIsListedAndGradedOnTheIkeSideTests(IpsecPathTestCase):
    """Jason's keying: *"If there are any IKE Gateway objects present on a firewall that are not
    named by an IPSec Tunnel object on that firewall, then we add that to the list with a blank
    IPSec Tunnel value."*"""

    def setUp(self):
        super().setUp()
        self.ike_profile("weak-ike", **WEAK_IKE)
        self.gateway("orphan", profile="weak-ike")
        self.generate()

    def test_the_ike_controls_fire_on_it(self):
        """A weak phase 1 proposal on a gateway nothing routes through is still a weak proposal,
        and the row says it carries no traffic by holding a blank tunnel name."""
        for control_id in IKE_CONTROLS:
            self.assertEqual(len(self.findings(control_id)), 1, control_id)
        self.assertEqual(self.findings("PAN-IKE-002")[0].subject_name, "(no tunnel) / orphan")

    def test_the_ipsec_payload_controls_do_not(self):
        """There is no tunnel on the path to name an IPSec crypto profile, so every IPSec payload
        column is blank - which is indistinguishable, to a clause, from a tunnel running on a
        profile that offers nothing. Those five controls carry `path_origin eq tunnel`."""
        for control_id in IPSEC_CONTROLS:
            self.assertEqual(self.findings(control_id), [], control_id)

    def test_the_finding_says_no_tunnel_names_it(self):
        self.assertIn("NO IPSEC TUNNEL ON THIS APPLIANCE NAMES",
                      self.findings("PAN-IKE-002")[0].summary)


class TheTabReadsAsOneRowPerPathTests(IpsecPathTestCase):
    """What a customer sees. The tab is built from the same spec the workbook would use."""

    def setUp(self):
        super().setUp()
        self.ike_profile("weak-ike", **WEAK_IKE)
        self.ipsec_profile("weak-ipsec", **WEAK_IPSEC)
        self.tunnel("t01", gateways=["g01"], crypto="weak-ipsec")
        self.gateway("g01", profile="weak-ike")
        self.tunnel("t02", crypto="default", inferred=True)
        self.generate()

    def test_no_heading_is_repeated(self):
        """A duplicate header is the silent failure: Excel rejects a table that has one and
        xlsxwriter drops the table, leaving stray cells where it should be."""
        headers = self.table().headers
        self.assertEqual(len(headers), len(set(headers)), headers)

    def test_no_heading_is_a_raw_field_name(self):
        """Every settings column on this tab is declared in `setting_labels`; a column with no
        label falls back to the Django field name and prints code in a customer table."""
        for header in self.table().headers:
            self.assertNotRegex(header, r"^[a-z][a-z0-9_]*$", header)

    def test_the_object_column_is_the_tunnel_and_the_gateway_is_beside_it(self):
        table = self.table()
        row = next(r for r in table.rows if r[1] == "PAN-IKE-002")
        self.assertEqual(row[table.headers.index("Object")], "t01")
        self.assertEqual(row[table.headers.index("IKE gateway")], "g01")

    def test_the_three_resolution_cells_say_which_object_is_missing(self):
        table = self.table()
        row = next(r for r in table.rows
                   if r[1] == "PAN-IPS-002" and r[table.headers.index("Object")] == "t02")
        self.assertEqual(row[table.headers.index("Gateway resolves here")],
                         "No gateway named - not reachable through the dialog, which requires one")
        self.assertEqual(row[table.headers.index("IKE crypto resolves here")],
                         "No gateway on this path to carry one")
        self.assertIn("Left at `default`",
                      row[table.headers.index("IPSec crypto resolves here")])

    def test_an_orphan_row_says_so_in_the_object_cell(self):
        self.gateway("orphan", profile="weak-ike")
        self.generate()
        table = self.table()
        row = next(r for r in table.rows
                   if r[1] == "PAN-IKE-002"
                   and r[table.headers.index("IKE gateway")] == "orphan")
        self.assertEqual(row[table.headers.index("Object")], "No tunnel names this gateway")
