"""The two User-ID tabs, and the two shared tabs this domain added a column to.

Written by the stage 9 run of OptivEdgeProbe's `user-id` domain, 2026-11-02. What it pins is the
part of those tabs that is a JUDGMENT rather than a derivation: the cell wordings, which cell a
row marks as the thing to fix, and the two readings the shared renderer could not have given.
The squareness checks every spec already gets are in `test_configuration_queries`; nothing here
repeats them.

THE ONE TEST HERE THAT IS NOT ABOUT THIS DOMAIN is
`test_a_zone_field_without_a_value_reader_cannot_resolve_its_provenance`. It pins the reason the
Security Zones tab needs a reader per field rather than per model, which is what made a tab built
for another domain's control unbuildable for this one's.
"""
from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementPoint, ManagementStation, Snapshot, Zone)
from optivedge_integrations.integrations.platforms.pan_os.normalization.management_interfaces \
    import normalize_management_interfaces
from optivedge_integrations.integrations.platforms.pan_os.normalization.user_id import (
    normalize_user_id)
from optivedge_integrations.integrations.platforms.pan_os.normalization.zones import (
    normalize_zones)

from assessments import user_id_presentation as user_id
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets.findings import ALL_TESTED_COLUMNS, build_findings_table
from assessments.management_interface_findings import generate_management_interface_findings
from assessments.models import AssessmentRun
from assessments.tests._seed import seed_controls
from assessments.user_id_collector_findings import generate_user_id_collector_findings
from assessments.user_id_discovery_bound_findings import (
    generate_user_id_discovery_bound_findings)
from assessments.zone_findings import generate_zone_findings


def _setting(**keys):
    return {key.replace("_", "-"): value for key, value in keys.items()}


def _net(name, discovery, address, disabled=None):
    entry = {"@name": name, "discovery": discovery, "network-address": address}
    if disabled is not None:
        entry["disabled"] = disabled
    return entry


def _vsys(name, collector=None, networks=None, zones=None):
    entry = {"@name": name}
    uid = {}
    if collector is not None:
        uid["setting"] = collector
    if networks is not None:
        uid["include-exclude-network"] = {"entry": networks}
    if uid:
        entry["user-id-collector"] = uid
    if zones is not None:
        entry["zone"] = {"entry": zones}
    return entry


#: One appliance carrying every shape these tests read. Transcribed from the stage 6 subjects of
#: the `user-id` domain: the aux-2 plane is PANORAMA'S, which is the only subject in the domain
#: whose provenance a finding can name.
PAYLOAD = {"config": {"devices": {"entry": [{
    "@name": "localhost.localdomain",
    "deviceconfig": {"system": {
        # Both listener keys explicitly `yes` - the vendor's NEGATED spelling, so OFF.
        "service": {"disable-userid-syslog-listener-udp": "yes"},
        "aux-1": {"service": {"disable-http": "yes"}},
        "aux-2": {"@ptpl": "stack_fw-core-tpa",
                  "service": {"disable-http": "yes"}},
    }},
    "vsys": {"entry": [
        # Probing on, and no discovery list at all.
        _vsys("vsys1", collector=_setting(enable_probing="yes")),
        # Expiry in force at ninety minutes: the calibration fires and moves the severity.
        _vsys("vsys2", collector=_setting(enable_mapping_timeout="yes",
                                          ip_user_mapping_timeout="90"),
              networks=[_net("n-ex", "exclude", "10.20.0.0/16")]),
        # An include entry naming public space, and a zone with the User-ID switch on.
        _vsys("vsys3", collector=_setting(enable_mapping_timeout="no"),
              networks=[_net("n-pub", "include", "203.0.113.0/24")],
              zones=[{"@name": "z-on", "enable-user-identification": "yes"}]),
    ]},
}]}}}


class UserIdTabTestCase(TestCase):
    def setUp(self):
        now = timezone.now()
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.uid")
        group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-uid",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=group,
            serial_number="S-UID", hostname="fw-uid")
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=now, payload=PAYLOAD)
        for entry in PAYLOAD["config"]["devices"]["entry"][0]["vsys"]["entry"]:
            EnforcementPoint.objects.create(
                management_station=self.station, appliance=self.appliance,
                vsys_name=entry["@name"], vsys_display_name=entry["@name"])

        # THE OTHER DOMAINS' CONTROLS TOO, on the two shared tabs. Without them those tabs read
        # as this domain's alone, which is the opposite of what the shared-tab tests check.
        seed_controls(["PAN-UID-001", "PAN-UID-002", "PAN-UID-003", "PAN-UID-004",
                       "PAN-UID-005", "PAN-UID-006",
                       "PAN-IOT-002",
                       "PAN-MGT-001", "PAN-MGT-002", "PAN-MGT-003", "PAN-MGT-006"])

        normalize_management_interfaces(self.appliance)
        for point in EnforcementPoint.objects.all():
            normalize_zones(point)
            normalize_user_id(point)

        run = AssessmentRun.objects.create(
            name="User-ID", status=AssessmentRun.Status.RUNNING, started_at=now)
        generate_user_id_collector_findings(run)
        generate_user_id_discovery_bound_findings(run)
        generate_zone_findings(run)
        generate_management_interface_findings(run)

    @staticmethod
    def table(slug):
        return build_findings_table(DOMAIN_BY_SLUG[slug].spec, tested=ALL_TESTED_COLUMNS)

    def rows(self, slug, control_id):
        table = self.table(slug)
        index = table.headers.index("Control ID")
        return [row for row in table.rows if row[index] == control_id]

    def cell(self, slug, control_id, heading, row=0):
        table = self.table(slug)
        return self.rows(slug, control_id)[row][table.headers.index(heading)]

    def marks(self, slug, control_id, row=0):
        table = self.table(slug)
        target = self.rows(slug, control_id)[row]
        position = table.rows.index(target)
        return sorted(table.headers[column] for r, column in table.implicated if r == position)


class NoHeadingIsSilentlyRaw(UserIdTabTestCase):
    """A derived column with no `setting_labels` entry heads with the Django field name."""

    def test_neither_new_tab_heads_a_column_with_a_field_name(self):
        for slug in ("user-id-collector", "user-id-discovery"):
            for header in self.table(slug).headers:
                self.assertNotIn("_", header, f"{slug} heads a column {header!r}")

    def test_the_two_shared_tabs_head_this_domains_column_in_words(self):
        """Both were built by other domains and neither labeled the field this one brings."""
        self.assertIn("Enable User Identification", self.table("security-zones").headers)
        self.assertIn("Listener state measured on this surface",
                      self.table("management-interfaces").headers)

    def test_the_management_interface_tab_no_longer_heads_any_column_raw(self):
        """`is_management_surface` is PAN-MGT-003's field and was raw on a customer tab.

        Pinned here, by the domain that found it rather than the one that owns it, because
        nothing else asserts it and the label is a proposal `management-services` inherits.
        """
        for header in self.table("management-interfaces").headers:
            self.assertNotIn("_", header)

    def test_no_tab_repeats_a_heading(self):
        """A duplicate header is an invalid table and xlsxwriter drops it with a warning."""
        for slug in ("user-id-collector", "user-id-discovery",
                     "security-zones", "management-interfaces"):
            headers = self.table(slug).headers
            self.assertEqual(len(headers), len(set(headers)), slug)


class EveryRowPointsAtSomething(UserIdTabTestCase):
    def test_every_row_on_both_new_tabs_marks_at_least_one_cell(self):
        """`hidden_fields` is empty on both, so the mark rests on real columns."""
        for slug in ("user-id-collector", "user-id-discovery"):
            table = self.table(slug)
            marked_rows = {row for row, _column in table.implicated}
            self.assertEqual(marked_rows, set(range(len(table.rows))), slug)

    def test_the_applicability_clause_is_never_the_marked_cell(self):
        """PAN-UID-006's calibration SCOPES on expiry being on and ASSERTS on the lifetime.

        The mark reads `asserted_fields`, so the scoping column must not carry it: a row whose
        expiry is correctly in force must not name that as the fault. vsys2 is that row - expiry
        on, ninety minutes - and vsys3 is its opposite, expiry off, which the baseline reports.
        """
        self.assertEqual(self.marks("user-id-collector", "PAN-UID-006",
                                    row=self._row_for("PAN-UID-006", "vsys2")),
                         ["Mapping lifetime (minutes)"])
        self.assertEqual(self.marks("user-id-collector", "PAN-UID-006",
                                    row=self._row_for("PAN-UID-006", "vsys3")),
                         ["Mapping entries expire"])

    def _row_for(self, control_id, vsys_name):
        table = self.table("user-id-collector")
        vsys = table.headers.index("Vsys")
        return [row[vsys] for row in self.rows("user-id-collector", control_id)].index(vsys_name)

    def test_a_shared_tab_marks_only_the_asserting_controls_own_field(self):
        """The two `zone` controls draw each other's columns; neither may mark the other's."""
        self.assertEqual(self.marks("security-zones", "PAN-UID-001"),
                         ["Enable User Identification"])


class ACellSaysWhatTheStoredValueCannot(UserIdTabTestCase):
    def test_an_uncomputed_discovery_verdict_does_not_read_as_an_empty_list(self):
        """`display_value` would print `(empty)`, which is a real and DIFFERENT state."""
        from optivedge_integrations.integrations.models import UserIdDiscoveryBound

        row = UserIdDiscoveryBound.objects.first()
        row.list_shape = ""
        row.save(update_fields=["list_shape"])
        self.assertEqual(user_id.list_shape(row), user_id.SHAPE_NOT_COMPUTED)
        self.assertNotEqual(user_id.list_shape(row), "(empty)")

    def test_a_computed_discovery_verdict_prints_the_models_own_label(self):
        from optivedge_integrations.integrations.models import UserIdDiscoveryBound

        row = UserIdDiscoveryBound.objects.get(enforcement_point__vsys_name="vsys1")
        self.assertEqual(row.list_shape, UserIdDiscoveryBound.SHAPE_NO_ENTRIES)
        self.assertEqual(user_id.list_shape(row), "No entries in force")

    def test_an_unmeasured_listener_plane_does_not_read_as_a_device_fault(self):
        """False here means nobody measured this plane, not that the listener is down."""
        value = self.cell("management-interfaces", "PAN-UID-005",
                          "Listener state measured on this surface")
        self.assertEqual(value, user_id.LISTENER_NOT_MEASURED)
        # The point of the reader: NOT the bare Yes/No `display_value` would have produced, which
        # under any scannable heading reads as a fact about the listener rather than about us.
        self.assertNotIn(value, {"No", "Yes"})

    def test_an_empty_included_ranges_cell_distinguishes_its_two_causes(self):
        from optivedge_integrations.integrations.models import UserIdDiscoveryBound

        computed = UserIdDiscoveryBound.objects.get(enforcement_point__vsys_name="vsys1")
        self.assertEqual(user_id.include_networks(computed), "No in-force include entry")
        computed.list_shape = ""
        self.assertEqual(user_id.include_networks(computed), user_id.SHAPE_NOT_COMPUTED)

    def test_the_included_ranges_cell_prints_what_it_was_given(self):
        from optivedge_integrations.integrations.models import UserIdDiscoveryBound

        row = UserIdDiscoveryBound.objects.get(enforcement_point__vsys_name="vsys3")
        self.assertEqual(user_id.include_networks(row), "203.0.113.0/24")


class TheSeverityBasisClaimsAnAdjustmentThatMovedNothing(UserIdTabTestCase):
    """P414, measured on this domain and NOT fixable here: `severity_basis` is shared.

    `severity_basis` puts a matched non-baseline query in its `adjusting` list whenever the query
    carries any `adjusted_severity`, without comparing it to the control default - so a query
    whose tier EQUALS the default still prints "Adjusted to ... by:". The two cases below are the
    same column of the same tab in the same wording, and only one of them moved anything.
    """

    def test_a_calibration_at_the_controls_own_tier_still_claims_an_adjustment(self):
        basis = self.cell("user-id-discovery", "PAN-UID-002",
                          "Severity basis", row=self._row_for("vsys1"))
        self.assertIn("Adjusted to Medium by:", basis)
        self.assertIn("No in-force include or exclude entry", basis)

    def test_a_calibration_that_really_moved_the_tier_reads_identically(self):
        basis = self.cell("user-id-discovery", "PAN-UID-002",
                          "Severity basis", row=self._row_for("vsys3"))
        self.assertIn("Adjusted to High by:", basis)
        self.assertIn("An include entry names a public address range", basis)

    def _row_for(self, vsys_name):
        table = self.table("user-id-discovery")
        control = table.headers.index("Control ID")
        vsys = table.headers.index("Vsys")
        candidates = [row for row in table.rows if row[control] == "PAN-UID-002"]
        return [row[vsys] for row in candidates].index(vsys_name)


class ThePushedSurfaceNamesTheThingThatOwnsIt(UserIdTabTestCase):
    """The one defect this domain could fix where the zone case could only record it.

    `integrations.ManagementInterface` IS a `ProvenancedMixin`, so the aux-2 surface's `@ptpl`
    marker reaches a `FieldProvenance` row and the row can say the configuration is Panorama's -
    which matters because a finding that sends an engineer to edit it sends them to a node the
    firewall will refuse or overwrite.
    """

    def test_a_template_pushed_surface_names_its_template_on_the_row(self):
        table = self.table("management-interfaces")
        control = table.headers.index("Control ID")
        surface = table.headers.index("Surface")
        template = table.headers.index("Template")
        pushed = [row for row in table.rows
                  if row[control] == "PAN-UID-005" and "Aux-2" in str(row[surface])]
        self.assertTrue(pushed, "no aux-2 row was drawn")
        self.assertIn("stack_fw-core-tpa", str(pushed[0][template]))

    def test_a_locally_committed_surface_names_no_template(self):
        table = self.table("management-interfaces")
        control = table.headers.index("Control ID")
        surface = table.headers.index("Surface")
        template = table.headers.index("Template")
        local = [row for row in table.rows
                 if row[control] == "PAN-UID-005" and "Aux-1" in str(row[surface])]
        self.assertTrue(local, "no aux-1 row was drawn")
        self.assertEqual(str(local[0][template]).strip(), "")


class TheZoneTabNeedsAReaderPerFieldAndNotPerModel(UserIdTabTestCase):
    """Why `ZONE_READERS` gained a fourth entry, and what happens to the fifth domain.

    `integrations.Zone` is a `SyncTrackedModel`, so it declares no `DERIVED_FIELDS` and nothing
    writes a `FieldProvenance` row for a zone. A tested field with no `ValueReader` therefore
    reaches the remediation walk, and the walk reads that attribute.
    """

    def test_zone_declares_no_derived_fields_at_all(self):
        self.assertFalse(hasattr(Zone, "DERIVED_FIELDS"))

    # THE READER-PER-FIELD GUARD THAT USED TO BE HERE IS GONE, and both of its problems are
    # worth recording where somebody will meet them.
    #
    # It asserted that every tested field of every active `zone` control appears in
    # `ZONE_READERS`. Two things were wrong with it, found 2026-11-02 while verifying this run:
    #
    # 1. IT COULD NOT SEE THE CONTROL THAT ACTUALLY BROKE. It iterated
    #    `Control.objects.filter(control_type=ZONE, is_active=True)`, which is whatever THIS
    #    file's `setUp` seeded - PAN-UID-001 and PAN-IOT-002, both of which have readers. The
    #    shipped control whose fields have none is PAN-ZON-001 (`zone_protection_unresolved`,
    #    `zone_type`), and it is not seeded here, so the guard passed while the real case was
    #    live on Jason's dev server: "Could not store the security-zones table for run 147".
    #
    # 2. IT MANDATED A WORKAROUND THAT NO LONGER EXISTS. A reader was compulsory only because
    #    `build_rows.provenance_of` read `_model.DERIVED_FIELDS` as a plain attribute and raised
    #    on a model that declares none. That is fixed - it is now
    #    `getattr(_model, "DERIVED_FIELDS", ())` - so a tested field needs no reader to build.
    #    Left in place, this guard would have made the `zone-dos-protection` run add readers
    #    that do nothing, to satisfy a test rather than a requirement.
    #
    # The invariant it was reaching for is real, and it is pinned properly in
    # `tests/test_findings_unprovenanced_subject.py`, which drives PAN-ZON-001 and the real
    # `security-zones` spec through `stored_findings_table` - the exact call that failed for run
    # 147 - and which was watched failing with that `AttributeError` before the fix landed.

    def test_the_zone_tab_builds_with_both_of_its_controls_reporting(self):
        table = self.table("security-zones")
        control = table.headers.index("Control ID")
        self.assertIn("PAN-UID-001", {row[control] for row in table.rows})
