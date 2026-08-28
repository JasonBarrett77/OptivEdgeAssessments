"""MGMT-002 end to end: does the control select the right surfaces, named reportably?"""

from __future__ import annotations

from django.test import TestCase

from assessments.search.compiler import compile_predicate
from optivedge_integrations.integrations.models import (
    Appliance,
    ManagementInterface,
    ManagementStation,
    PermittedSource,
    Snapshot,
)
from django.utils import timezone

# The baseline query for MGMT-002, exactly as it would sit in a catalog.
MGMT_002 = {
    "model": "integrations.ManagementInterface",
    "operator": "or",
    "clauses": [
        {"field": "exposure", "op": "eq", "value": "unrestricted"},
        {"field": "exposure", "op": "eq", "value": "undetermined"},
    ],
}


class ManagementInterfaceControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.test")
        self.appliance = Appliance.objects.create(
            management_station=self.station, serial_number="S-1", hostname="fw-a")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

    def _surface(self, plane, interface_name="", profile_name="", sources=()):
        surface = ManagementInterface.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_snapshot=self.snapshot, plane=plane,
            interface_name=interface_name, profile_name=profile_name)
        for position, (value, family, start, end) in enumerate(sources):
            PermittedSource.objects.create(
                management_interface=surface, position=position, value=value,
                family=family, ipv4_start_int=start, ipv4_end_int=end)
        return surface

    def test_control_selects_exposed_surfaces_and_names_them(self):
        self._surface(ManagementInterface.PLANE_MGT,
                      sources=[("10.0.0.0/8", 4, 167772160, 184549375)])          # restricted
        self._surface(ManagementInterface.PLANE_AUX1)                              # unrestricted
        self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/1", "p1")    # unrestricted
        self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/2", "p2",
                      sources=[("2001:db8::/32", 6, None, None)])                  # undetermined
        self._surface(ManagementInterface.PLANE_DATAPLANE, "loopback.9", "p3",
                      sources=[("192.168.1.1", 4, 3232235777, 3232235777)])        # restricted

        matched = ManagementInterface.objects.filter(
            compile_predicate(ManagementInterface, MGMT_002))
        names = sorted(s.display_name for s in matched)

        # the finding names the surface, which is the whole point
        self.assertEqual(names, ["Aux-1", "ethernet1/1", "ethernet1/2"])
        self.assertNotIn("MGT", names)
        self.assertNotIn("loopback.9", names)

    def test_one_appliance_yields_one_finding_per_surface_not_one_per_appliance(self):
        self._surface(ManagementInterface.PLANE_MGT)
        self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/1", "p1")
        self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/3", "p2")
        matched = ManagementInterface.objects.filter(
            compile_predicate(ManagementInterface, MGMT_002))
        self.assertEqual(matched.count(), 3)
        self.assertEqual({s.appliance_id for s in matched}, {self.appliance.pk})

    def test_an_ipv6_only_list_is_undetermined_not_restricted(self):
        """Whether a v6-only list restricts IPv4 is unmeasured; the ACL keeps the families
        apart and an empty v4 peers list means unrestricted, so this must not read clean."""
        self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/8", "p",
                      sources=[("2001:db8::/32", 6, None, None)])
        matched = ManagementInterface.objects.filter(
            compile_predicate(ManagementInterface, MGMT_002))
        self.assertEqual([s.display_name for s in matched], ["ethernet1/8"])

    def test_an_unparseable_source_is_undetermined_not_restricted(self):
        """The failure this control exists to avoid is a false clean result."""
        self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/7", "p",
                      sources=[("not-an-address", None, None, None)])
        matched = ManagementInterface.objects.filter(
            compile_predicate(ManagementInterface, MGMT_002))
        self.assertEqual([s.display_name for s in matched], ["ethernet1/7"])

    def test_hostname_filter_scopes_to_an_appliance(self):
        self._surface(ManagementInterface.PLANE_MGT)
        q = {"model": "integrations.ManagementInterface", "operator": "and",
             "clauses": [{"field": "hostname", "op": "eq", "value": "fw-a"}]}
        self.assertEqual(
            ManagementInterface.objects.filter(compile_predicate(ManagementInterface, q)).count(), 1)
