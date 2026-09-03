"""The Login Banner tab: the banner and its acknowledgement, with both toggles."""

from __future__ import annotations

import re

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments.models import (
    AssessmentRun, Control, DeviceConfigurationFinding)
from optivedge_integrations.integrations.models import (
    Appliance, DeviceConfigurationProfile, FieldProvenance, ManagementStation, Snapshot)


class LoginBannerListViewTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.banner")
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(), completed_at=timezone.now())
        self.control_007 = Control.objects.create(
            control_id="PAN-MGT-007", name="Login Banner Configured",
            control_type=Control.ControlType.DEVICE_CONFIGURATION,
            description="x", default_severity=Control.Severity.LOW)
        self.bare = self._profile("fw-bare", banner="", ack=False)
        self.good = self._profile("fw-good", banner="Authorized users only.", ack=True)
        DeviceConfigurationFinding.objects.create(
            assessment_run=self.run, control=self.control_007,
            device_configuration_profile=self.bare,
            severity=Control.Severity.LOW, title="t")

    def _profile(self, hostname, banner, ack):
        appliance = Appliance.objects.create(
            management_station=self.station, serial_number=f"S-{hostname}", hostname=hostname)
        snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        return DeviceConfigurationProfile.objects.create(
            management_station=self.station, appliance=appliance, source_snapshot=snapshot,
            config_source="local", login_banner=banner, ack_login_banner=ack)

    def test_lists_every_appliance_by_default(self):
        response = self.client.get(reverse("assessment_login_banner_list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_count"], 2)
        self.assertContains(response, "Authorized users only.")

    def test_a_missing_banner_reads_not_set_rather_than_blank(self):
        """A blank cell is indistinguishable from missing data; this row is the finding."""
        response = self.client.get(reverse("assessment_login_banner_list"))
        self.assertContains(response, "Not set")
        self.assertContains(response, "Not required")

    def test_findings_filter_narrows_to_appliances_with_an_open_finding(self):
        response = self.client.get(reverse("assessment_login_banner_list"), {"findings": "1"})
        self.assertEqual(response.context["shown_count"], 1)
        self.assertEqual(response.context["rows"][0]["profile"], self.bare)

    def test_it_shows_only_banner_findings(self):
        """An unrelated device-configuration control must not leak onto this tab."""
        other = Control.objects.create(
            control_id="PAN-MGT-011", name="Log on High DP Load",
            control_type=Control.ControlType.DEVICE_CONFIGURATION,
            description="x", default_severity=Control.Severity.LOW)
        DeviceConfigurationFinding.objects.create(
            assessment_run=self.run, control=other,
            device_configuration_profile=self.good,
            severity=Control.Severity.LOW, title="t")
        rows = {r["profile"].appliance.hostname: r for r in self.client.get(
            reverse("assessment_login_banner_list")).context["rows"]}
        self.assertEqual([f.control.control_id for f in rows["fw-good"]["findings"]], [])
        self.assertEqual([f.control.control_id for f in rows["fw-bare"]["findings"]],
                         ["PAN-MGT-007"])

    def test_provenance_is_off_by_default_and_reads_a_named_field(self):
        """DeviceConfigurationProfile carries many values on one row, so provenance is stored
        per field rather than under "__entry__" as it is on the surfaces and profiles tabs."""
        FieldProvenance.objects.create(
            content_type=ContentType.objects.get_for_model(DeviceConfigurationProfile),
            object_id=self.good.pk, field_name="login_banner",
            provenance_type=FieldProvenance.ProvenanceType.TEMPLATE,
            raw_key="@ptpl", raw_value="stack_fw-core-tpa")

        off = self.client.get(reverse("assessment_login_banner_list"))
        self.assertFalse(off.context["show_provenance"])
        self.assertNotContains(off, "stack_fw-core-tpa")

        on = self.client.get(reverse("assessment_login_banner_list"), {"provenance": "1"})
        rows = {r["profile"].appliance.hostname: r for r in on.context["rows"]}
        self.assertEqual(rows["fw-good"]["banner_provenance"], "stack_fw-core-tpa")
        self.assertEqual(rows["fw-good"]["ack_provenance"], "",
                         "a field with no row renders blank, as everywhere else")
        self.assertContains(on, "stack_fw-core-tpa")

    def test_the_table_stays_square(self):
        html = self.client.get(reverse("assessment_login_banner_list")).content.decode()
        body = re.search(r"<tbody>(.*?)</tbody>", html, re.S).group(1)
        first_row = re.search(r"<tr[^>]*>(.*?)</tr>", body, re.S).group(1)
        header = re.search(r"<thead>(.*?)</thead>", html, re.S).group(1)
        self.assertEqual(len(re.findall(r"<td", first_row)),
                         len(re.findall(r"<th", header)))

    def test_the_page_carries_the_device_nav_with_its_own_section_active(self):
        """Was "all four device tabs are present". Interface Profiles moved to the Network
        section, so it is correctly absent here now. test_navigation pins the full mapping."""
        response = self.client.get(reverse("assessment_login_banner_list"))
        for label in ("Device Configuration", "Management Interfaces", "Login Banner"):
            self.assertContains(response, label)
        self.assertContains(response, "bg-slate-800 text-white\"\n        >\n            Device")

    def test_the_banner_columns_left_device_configuration(self):
        """Moved, not duplicated - the same precedent as permitted IPs moving to the
        surfaces tab. Two places showing one value drift."""
        response = self.client.get(reverse("assessment_device_configuration_profile_list"))
        self.assertNotContains(response, ">Ack Banner</th>")
