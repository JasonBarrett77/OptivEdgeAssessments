"""The Management Interfaces tab: configuration detail, and a findings-only filter."""

from __future__ import annotations

import re

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments.models import (
    AssessmentRun, Control, ManagementInterfaceFinding)
from optivedge_integrations.integrations.models import (
    Appliance, DeviceConfigurationProfile, ManagementInterface, ManagementService,
    ManagementStation, PermittedSource, Snapshot)


class ManagementInterfaceListViewTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.view")
        self.appliance = Appliance.objects.create(
            management_station=self.station, serial_number="S-V1", hostname="fw-view")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        self.control = Control.objects.create(
            control_id="MGMT-002", name="Permitted IPs configured",
            control_type=Control.ControlType.MANAGEMENT_INTERFACE,
            description="x", default_severity=Control.Severity.HIGH)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(), completed_at=timezone.now())

        self.restricted = self._surface(ManagementInterface.PLANE_AUX1)
        PermittedSource.objects.create(
            management_interface=self.restricted, position=0, value="10.10.10.0/24",
            family=4, ipv4_start_int=168430080, ipv4_end_int=168430335)
        self.exposed = self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/1", "p1")
        ManagementInterfaceFinding.objects.create(
            assessment_run=self.run, control=self.control, management_interface=self.exposed,
            severity=Control.Severity.HIGH, title="t", subject_name="ethernet1/1")

    def _surface(self, plane, interface_name="", profile_name=""):
        return ManagementInterface.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_snapshot=self.snapshot, plane=plane,
            interface_name=interface_name, profile_name=profile_name)

    def test_lists_every_surface_by_default(self):
        response = self.client.get(reverse("assessment_management_interface_list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_count"], 2)
        self.assertEqual(response.context["shown_count"], 2)
        self.assertContains(response, "Aux-1")
        self.assertContains(response, "ethernet1/1")
        self.assertContains(response, "10.10.10.0/24")

    def test_findings_filter_narrows_to_surfaces_with_an_open_finding(self):
        response = self.client.get(
            reverse("assessment_management_interface_list"), {"findings": "1"})
        self.assertTrue(response.context["findings_only"])
        self.assertEqual(response.context["shown_count"], 1)
        self.assertEqual(response.context["total_count"], 2, "the total still counts everything")
        self.assertContains(response, "ethernet1/1")
        self.assertNotContains(response, "10.10.10.0/24")

    def test_an_empty_permitted_list_reads_as_any_source_not_as_blank(self):
        response = self.client.get(reverse("assessment_management_interface_list"))
        self.assertContains(response, "any source")
        self.assertContains(response, "Unrestricted")

    def test_both_tabs_are_present_and_this_one_is_active(self):
        response = self.client.get(reverse("assessment_management_interface_list"))
        self.assertContains(response, "Device Configuration")
        self.assertContains(response, "Management Interfaces")
        self.assertContains(response, reverse("assessment_device_configuration_profile_list"))


class DeviceConfigurationTableShapeTests(TestCase):
    """The permitted-IP columns moved to the other tab; the table must stay square.

    Nothing asserted this before, which is how removing two model fields left the header
    declaring columns the body no longer rendered - every column after them shifted.
    """

    def test_header_and_body_declare_the_same_number_of_columns(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.shape")
        appliance = Appliance.objects.create(
            management_station=station, serial_number="S-S1", hostname="fw-shape")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(), payload={})
        DeviceConfigurationProfile.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            config_source="local")

        html = self.client.get(
            reverse("assessment_device_configuration_profile_list")).content.decode()
        body = re.search(r"<tbody>(.*?)</tbody>", html, re.S).group(1)
        first_row = re.search(r"<tr[^>]*>(.*?)</tr>", body, re.S).group(1)
        header = re.search(r"<thead>(.*?)</thead>", html, re.S).group(1)
        header_rows = re.findall(r"<tr[^>]*>(.*?)</tr>", header, re.S)

        cells = len(re.findall(r"<td", first_row))
        columns = len(re.findall(r"<th", header_rows[-1]))
        spans = sum(int(x) for x in re.findall(r'colspan="(\d+)"', header_rows[0])) \
            + len(re.findall(r'<th(?![^>]*colspan)', header_rows[0]))
        self.assertEqual(cells, columns, "body cells must match the column header row")
        self.assertEqual(spans, columns, "group header spans must cover every column")

    def test_permitted_ip_columns_are_gone_from_this_tab(self):
        response = self.client.get(reverse("assessment_device_configuration_profile_list"))
        self.assertNotContains(response, "Permitted IPs")
        self.assertContains(response, "Management Interfaces")


class ManagementInterfaceTableShapeTests(TestCase):
    """The same squareness assertion, on the tab that just grew five columns.

    The device-configuration table shifted every column when a header row and a body row
    disagreed, and this table now has two group headers to keep aligned rather than one.
    """

    def setUp(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.mishape")
        appliance = Appliance.objects.create(
            management_station=station, serial_number="S-MS1", hostname="fw-mishape")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance, source_type="show_merged_config",
            collected_at=timezone.now(), payload={})
        self.surface = ManagementInterface.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            plane=ManagementInterface.PLANE_MGT)
        for name, enabled in (("http", True), ("https", True), ("ssh", True),
                              ("telnet", False), ("snmp", False), ("icmp", True)):
            ManagementService.objects.create(
                management_interface=self.surface, name=name, enabled=enabled)

    def test_header_and_body_declare_the_same_number_of_columns(self):
        html = self.client.get(
            reverse("assessment_management_interface_list")).content.decode()
        body = re.search(r"<tbody>(.*?)</tbody>", html, re.S).group(1)
        first_row = re.search(r"<tr[^>]*>(.*?)</tr>", body, re.S).group(1)
        header = re.search(r"<thead>(.*?)</thead>", html, re.S).group(1)
        header_rows = re.findall(r"<tr[^>]*>(.*?)</tr>", header, re.S)

        cells = len(re.findall(r"<td", first_row))
        columns = len(re.findall(r"<th", header_rows[-1]))
        spans = sum(int(x) for x in re.findall(r'colspan="(\d+)"', header_rows[0])) \
            + len(re.findall(r'<th(?![^>]*colspan)', header_rows[0]))
        self.assertEqual(cells, columns, "body cells must match the column header row")
        self.assertEqual(spans, columns, "group header spans must cover every column")

    def test_only_administrative_services_get_columns(self):
        """icmp is on, and must not appear as a column - six services have no column."""
        response = self.client.get(reverse("assessment_management_interface_list"))
        cells = response.context["rows"][0]["services"]
        self.assertEqual([c["name"] for c in cells],
                         ["http", "https", "ssh", "telnet", "snmp"])
        self.assertNotContains(response, ">ICMP<")
        self.assertNotContains(response, ">Ping<")
        self.assertNotContains(response, ">Response Pages<")

    def test_an_insecure_service_that_is_on_is_highlighted(self):
        cells = {c["name"]: c for c in self.client.get(
            reverse("assessment_management_interface_list")).context["rows"][0]["services"]}
        self.assertTrue(cells["http"]["enabled"] and cells["http"]["insecure"])
        self.assertTrue(cells["https"]["enabled"])
        self.assertFalse(cells["https"]["insecure"],
                         "https is administrative but not something a control says to disable")
        self.assertFalse(cells["telnet"]["enabled"])
