"""MGMT-002 end to end: does the control select the right surfaces, named reportably?"""

from __future__ import annotations

from django.test import TestCase

from assessments.management_interface_naming import surface_label

from assessments.search.compiler import compile_predicate
from optivedge_integrations.integrations.models import (
    Appliance,
    ManagementInterface,
    ManagementService,
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
                      sources=[("2001:db8::/32", 6, None, None)])                  # restricted
        self._surface(ManagementInterface.PLANE_DATAPLANE, "loopback.9", "p3",
                      sources=[("192.168.1.1", 4, 3232235777, 3232235777)])        # restricted

        matched = ManagementInterface.objects.filter(
            compile_predicate(ManagementInterface, MGMT_002))
        names = sorted(surface_label(s) for s in matched)

        # the finding names the surface, which is the whole point
        self.assertEqual(names, ["Aux-1", "ethernet1/1"])
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

    def test_an_ipv6_only_list_is_restricted(self):
        """Measured 2026-08-28: a v6-only list denies IPv4 outright, so it genuinely
        restricts. Connecting over IPv4 to an interface carrying only a v6 entry is
        refused, while adding a matching v4 range to the same list opens it."""
        self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/8", "p",
                      sources=[("2001:db8::/32", 6, None, None)])
        matched = ManagementInterface.objects.filter(
            compile_predicate(ManagementInterface, MGMT_002))
        self.assertEqual(list(matched), [])

    def test_an_unparseable_source_is_undetermined_not_restricted(self):
        """The failure this control exists to avoid is a false clean result."""
        self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/7", "p",
                      sources=[("not-an-address", None, None, None)])
        matched = ManagementInterface.objects.filter(
            compile_predicate(ManagementInterface, MGMT_002))
        self.assertEqual([surface_label(s) for s in matched], ["ethernet1/7"])

    def test_hostname_filter_scopes_to_an_appliance(self):
        self._surface(ManagementInterface.PLANE_MGT)
        q = {"model": "integrations.ManagementInterface", "operator": "and",
             "clauses": [{"field": "hostname", "op": "eq", "value": "fw-a"}]}
        self.assertEqual(
            ManagementInterface.objects.filter(compile_predicate(ManagementInterface, q)).count(), 1)


#: The baseline queries for the service controls, exactly as they sit in the catalog.
PAN_MGT_001 = {
    "model": "integrations.ManagementInterface",
    "operator": "or",
    "clauses": [{"field": "service_enabled", "op": "eq", "value": "telnet"}],
}
PAN_MGT_006 = {
    "model": "integrations.ManagementInterface",
    "operator": "or",
    "clauses": [{"operator": "and", "clauses": [
        {"field": "plane", "op": "eq", "value": "dataplane"},
        {"field": "service_enabled", "op": "eq", "value": "administrative"},
    ]}],
}


class ServiceControlTests(TestCase):
    """The service controls select surfaces, and 006 enumerates without judging."""

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.svc")
        self.appliance = Appliance.objects.create(
            management_station=self.station, serial_number="S-SVC", hostname="fw-svc")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

    def _surface(self, plane, services, interface_name="", profile_name=""):
        surface = ManagementInterface.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_snapshot=self.snapshot, plane=plane,
            interface_name=interface_name, profile_name=profile_name)
        for name, enabled in services.items():
            ManagementService.objects.create(
                management_interface=surface, name=name, enabled=enabled)
        return surface

    def _match(self, query):
        return set(ManagementInterface.objects
                   .filter(compile_predicate(ManagementInterface, query))
                   .values_list("pk", flat=True))

    def test_telnet_control_selects_only_surfaces_running_telnet(self):
        on = self._surface(ManagementInterface.PLANE_MGT, {"telnet": True, "ssh": True})
        self._surface(ManagementInterface.PLANE_AUX1, {"telnet": False, "ssh": True})
        self.assertEqual(self._match(PAN_MGT_001), {on.pk})

    def test_a_service_that_is_off_never_matches_even_when_the_row_exists(self):
        """A row exists for every service its plane supports, on or off.

        Matching on the row rather than on `enabled` would flag every surface, which is the
        failure mode of storing all services rather than only the enabled ones.
        """
        self._surface(ManagementInterface.PLANE_MGT, {"telnet": False})
        self.assertEqual(self._match(PAN_MGT_001), set())

    def test_006_enumerates_dataplane_surfaces_with_any_administrative_service(self):
        https_only = self._surface(
            ManagementInterface.PLANE_DATAPLANE, {"https": True, "ping": True},
            "ethernet1/1", "p-https")
        telnet = self._surface(
            ManagementInterface.PLANE_DATAPLANE, {"telnet": True}, "ethernet1/2", "p-telnet")
        self.assertEqual(self._match(PAN_MGT_006), {https_only.pk, telnet.pk},
                         "any administrative service makes it an administration surface")

    def test_006_ignores_a_dataplane_surface_with_only_non_administrative_services(self):
        """The refinement that keeps the list filterable: ping alone is not exposure."""
        self._surface(ManagementInterface.PLANE_DATAPLANE,
                      {"ping": True, "response-pages": True, "http-ocsp": True,
                       "userid-service": True, "https": False},
                      "ethernet1/3", "p-ping")
        self.assertEqual(self._match(PAN_MGT_006), set())

    def test_006_does_not_reach_the_management_plane(self):
        """MGT running https is not a data-plane exposure; 001/002/003 cover that plane."""
        self._surface(ManagementInterface.PLANE_MGT, {"https": True, "ssh": True})
        self.assertEqual(self._match(PAN_MGT_006), set())

    def test_a_surface_matches_once_even_with_several_administrative_services_on(self):
        """The join could duplicate the row; the compiler must not double-report it."""
        surface = self._surface(
            ManagementInterface.PLANE_DATAPLANE,
            {"https": True, "ssh": True, "telnet": True, "snmp": True},
            "ethernet1/4", "p-all")
        matched = list(ManagementInterface.objects
                       .filter(compile_predicate(ManagementInterface, PAN_MGT_006))
                       .values_list("pk", flat=True))
        self.assertEqual(matched, [surface.pk])
