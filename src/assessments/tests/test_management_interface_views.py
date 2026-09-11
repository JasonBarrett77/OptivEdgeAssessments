"""The Management Interfaces tab: configuration detail, and a findings-only filter."""

from __future__ import annotations

import re

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments.models import (
    AssessmentRun, Control, ManagementInterfaceFinding)
from django.contrib.contenttypes.models import ContentType

from optivedge_integrations.integrations.models import (
    Appliance, FieldProvenance, ManagementInterface,
    ManagementService, ManagementStation, PermittedSource, Snapshot)  # noqa: F401


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


class ProvenanceToggleTests(TestCase):
    """Provenance is off by default, asked for, and does not disturb the findings filter."""

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.prov")
        self.appliance = Appliance.objects.create(
            management_station=self.station, serial_number="S-PROV", hostname="fw-prov")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        self.surface = ManagementInterface.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_snapshot=self.snapshot, plane=ManagementInterface.PLANE_AUX2)
        self._pushed(self.surface)
        # The measured shape: a pushed leaf beside one that was overridden locally.
        pushed = ManagementService.objects.create(
            management_interface=self.surface, name="https", enabled=True)
        self._pushed(pushed)
        overridden = ManagementService.objects.create(
            management_interface=self.surface, name="telnet", enabled=True)
        self._local(overridden)
        source = PermittedSource.objects.create(
            management_interface=self.surface, position=0, value="10.0.0.0/8",
            family=4, ipv4_start_int=167772160, ipv4_end_int=184549375)
        self._pushed(source)

    def _provenance_row(self, instance, provenance_type, raw_key, raw_value):
        FieldProvenance.objects.create(
            content_type=ContentType.objects.get_for_model(type(instance)),
            object_id=instance.pk, field_name="__entry__",
            provenance_type=provenance_type, raw_key=raw_key, raw_value=raw_value)

    def _pushed(self, instance):
        self._provenance_row(instance, FieldProvenance.ProvenanceType.TEMPLATE,
                             "@ptpl", "stack_fw-core-tpa")

    def _local(self, instance):
        """Present in the payload with no marker - written locally, or overridden."""
        self._provenance_row(instance, FieldProvenance.ProvenanceType.LOCAL, "", "")

    def test_provenance_is_off_by_default(self):
        response = self.client.get(reverse("assessment_management_interface_list"))
        self.assertFalse(response.context["show_provenance"])
        self.assertNotContains(response, "stack_fw-core-tpa")

    def test_provenance_on_shows_the_source_beside_the_value(self):
        response = self.client.get(
            reverse("assessment_management_interface_list"), {"provenance": "1"})
        self.assertTrue(response.context["show_provenance"])
        self.assertContains(response, "stack_fw-core-tpa")

    def test_an_overridden_value_reads_differently_from_a_pushed_one(self):
        """The whole point: two services on ONE surface, one pushed and one overridden."""
        cells = {c["name"]: c for c in self.client.get(
            reverse("assessment_management_interface_list"),
            {"provenance": "1"}).context["rows"][0]["services"]}
        self.assertEqual(cells["https"]["provenance"], "stack_fw-core-tpa")
        self.assertEqual(cells["telnet"]["provenance"], "",
                         "a local row has no source name, so it renders blank")

    def test_the_two_toggles_compose(self):
        """Turning one on must not silently turn the other off.

        With findings already on, the provenance link has to carry findings forward -
        otherwise pressing it drops the filter the reader is in the middle of using.
        """
        response = self.client.get(
            reverse("assessment_management_interface_list"), {"findings": "1"})
        self.assertContains(response, "?findings=1&amp;provenance=1", html=False)

        both = self.client.get(
            reverse("assessment_management_interface_list"),
            {"provenance": "1", "findings": "1"})
        self.assertTrue(both.context["show_provenance"])
        self.assertTrue(both.context["findings_only"])
        # Each link now turns its own toggle OFF while preserving the other.
        self.assertContains(both, 'href="?findings=1&amp;"')
        self.assertContains(both, 'href="?provenance=1&amp;"')

    def test_a_local_value_renders_nothing_at_all(self):
        """Local is blank, not the word "Local".

        Roughly four in five cells on a real page are local, so printing the word buried the
        template names that are the only reason to turn the toggle on. Blank also keeps the
        permitted-sources cell from doubling in height for a list that is entirely local.
        """
        response = self.client.get(
            reverse("assessment_management_interface_list"), {"provenance": "1"})
        self.assertContains(response, "stack_fw-core-tpa")
        self.assertNotContains(response, ">Local<")

    def test_the_table_stays_square_with_provenance_on(self):
        html = self.client.get(
            reverse("assessment_management_interface_list"),
            {"provenance": "1"}).content.decode()
        body = re.search(r"<tbody>(.*?)</tbody>", html, re.S).group(1)
        first_row = re.search(r"<tr[^>]*>(.*?)</tr>", body, re.S).group(1)
        header = re.search(r"<thead>(.*?)</thead>", html, re.S).group(1)
        header_rows = re.findall(r"<tr[^>]*>(.*?)</tr>", header, re.S)
        self.assertEqual(len(re.findall(r"<td", first_row)),
                         len(re.findall(r"<th", header_rows[-1])),
                         "provenance adds lines inside cells, never cells")


class AnyAddressExposureTests(TestCase):
    """A list containing 0.0.0.0/0 does not restrict, however non-empty it looks."""

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.any")
        self.appliance = Appliance.objects.create(
            management_station=self.station, serial_number="S-ANY", hostname="fw-any")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

    def test_only_an_all_addresses_entry_is_unrestricted(self):
        """Seen on a real firewall: MGT permitted only 0.0.0.0/0 and read Restricted."""
        from assessments.search.management_interface.fields.exposure import (
            RESTRICTED, UNDETERMINED, UNRESTRICTED, classify)
        self.assertEqual(classify([("0.0.0.0/0", 4)]), UNRESTRICTED)
        self.assertEqual(classify([("::/0", 6)]), UNRESTRICTED)
        self.assertEqual(classify([("0.0.0.0/0", 4), ("::/0", 6)]), UNRESTRICTED)

    def test_alone_it_is_unrestricted_on_every_plane_without_measurement(self):
        """Honoured, it permits everything; stripped, the list is empty, which also does."""
        from assessments.search.management_interface.fields.exposure import (
            UNRESTRICTED, classify)
        for stripped in (True, False):
            self.assertEqual(
                classify([("0.0.0.0/0", 4)], wildcard_is_stripped=stripped), UNRESTRICTED)

    def test_beside_other_entries_the_planes_differ(self):
        """Both planes measured, and they disagree.

        PAN-OS strips the wildcard when compiling a deviceconfig ACL, so [0.0.0.0/0, jump
        host] permits the jump host and nobody else. Reporting that as unrestricted is a
        false positive on a hardened device, which read-device-configuration.md says
        explicitly. A data-plane profile does NOT strip it - measured 2026-09-02 by
        connection, since a profile has no compiled ACL to read - so the same list there
        really does permit everyone.

        The direction matters: these two must not be collapsed to one rule. Assuming the
        deviceconfig behaviour everywhere hides an open surface; assuming the profile
        behaviour everywhere flags a hardened one.
        """
        from assessments.search.management_interface.fields.exposure import (
            RESTRICTED, UNRESTRICTED, classify)
        mixed = [("0.0.0.0/0", 4), ("10.99.99.99/32", 4)]
        self.assertEqual(classify(mixed, wildcard_is_stripped=True), RESTRICTED)
        self.assertEqual(classify(mixed, wildcard_is_stripped=False), UNRESTRICTED)

    def test_the_plane_decides_which_rule_applies(self):
        """exposure_by_interface must pick the rule per surface, not once for the table."""
        from assessments.search.management_interface.fields.exposure import (
            RESTRICTED, UNRESTRICTED, exposure_by_interface)
        for plane, iface, profile in ((ManagementInterface.PLANE_MGT, "", ""),
                                      (ManagementInterface.PLANE_DATAPLANE, "ethernet1/9", "p")):
            surface = ManagementInterface.objects.create(
                management_station=self.station, appliance=self.appliance,
                source_snapshot=self.snapshot, plane=plane,
                interface_name=iface, profile_name=profile)
            for position, value in enumerate(("0.0.0.0/0", "10.99.99.99/32")):
                PermittedSource.objects.create(
                    management_interface=surface, position=position, value=value, family=4)
            setattr(self, f"surface_{plane}", surface)
        exposure = exposure_by_interface()
        self.assertEqual(exposure[getattr(self, "surface_mgt").pk], RESTRICTED)
        self.assertEqual(exposure[getattr(self, "surface_dataplane").pk], UNRESTRICTED)

    def test_ordinary_entries_still_restrict(self):
        from assessments.search.management_interface.fields.exposure import (
            RESTRICTED, classify)
        self.assertEqual(classify([("10.0.0.0/8", 4)]), RESTRICTED)
        self.assertEqual(classify([("10.0.0.0/8", 4), ("192.168.1.1/32", 4)]), RESTRICTED)

    def test_both_new_states_are_matched_by_the_shipped_control(self):
        """PAN-MGT-003's baseline matches unrestricted OR undetermined, so a surface is
        reported either way rather than quietly assumed safe."""
        from assessments.controls_catalog.registry import load_seed_payload
        spec = next(c for c in load_seed_payload()["catalogs"][0]["controls"]
                    if c["control_id"] == "PAN-MGT-003")
        values = {c["value"] for c in spec["queries"][0]["canonical_query"]["clauses"]}
        self.assertEqual(values, {"unrestricted", "undetermined"})
