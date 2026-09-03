"""The Password Complexity tab: thirteen controls presented on one row per appliance.

The thing worth testing here is that the page contains NO thresholds of its own. Which cell a
finding highlights is derived from the control's own query, and whether it highlights at all
comes from the finding - so the page cannot disagree with the assessment, and cannot go stale
when a threshold moves.

PAN-AUTH-010 is the case that makes this more than tidiness. It is bounded at both ends: a
period of 0 means passwords never expire and 365 means they expire too rarely, while 60 is
fine. A page that re-derived its own highlighting would almost certainly have written "higher
is worse" and got the 365 right by luck and the 0 wrong.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments.models import AssessmentRun, Control, ControlQuery, DeviceConfigurationFinding
from optivedge_integrations.integrations.models import (
    Appliance, DeviceConfigurationProfile, FieldProvenance, ManagementStation, Snapshot)

CONTROLS = [f"PAN-AUTH-{n:03d}" for n in range(1, 14)]
FIELD_BY_CONTROL = {
    "PAN-AUTH-001": ("password_complexity_enabled",),
    "PAN-AUTH-002": ("password_minimum_length",),
    "PAN-AUTH-003": ("password_minimum_uppercase",),
    "PAN-AUTH-004": ("password_minimum_lowercase",),
    "PAN-AUTH-005": ("password_minimum_numeric",),
    "PAN-AUTH-006": ("password_minimum_special",),
    "PAN-AUTH-007": ("password_block_username_inclusion",),
    "PAN-AUTH-008": ("password_new_differs_by_characters",),
    "PAN-AUTH-009": ("password_history_count",),
    "PAN-AUTH-010": ("password_expiration_period",),
    "PAN-AUTH-011": ("password_expiration_warning_period",),
    "PAN-AUTH-012": ("password_post_expiration_admin_login_count",),
    "PAN-AUTH-013": ("password_post_expiration_grace_period",),
}


class PasswordComplexityListViewTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.pwv")
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(), completed_at=timezone.now())
        self.controls = {}
        for control_id, fields in FIELD_BY_CONTROL.items():
            control = Control.objects.create(
                control_id=control_id, name=control_id,
                control_type=Control.ControlType.DEVICE_CONFIGURATION,
                description="x", default_severity=Control.Severity.MEDIUM)
            ControlQuery.objects.create(
                control=control, name="Baseline", is_baseline=True, is_active=True,
                canonical_query={
                    "model": "integrations.DeviceConfigurationProfile", "operator": "or",
                    "clauses": [{"field": f, "op": "lt", "value": 1} for f in fields]})
            self.controls[control_id] = control

    def _profile(self, hostname, **values):
        appliance = Appliance.objects.create(
            management_station=self.station, serial_number=f"S-{hostname}", hostname=hostname)
        snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        return DeviceConfigurationProfile.objects.create(
            management_station=self.station, appliance=appliance, source_snapshot=snapshot,
            config_source="local", **values)

    def _fire(self, profile, *control_ids):
        for control_id in control_ids:
            DeviceConfigurationFinding.objects.create(
                assessment_run=self.run, control=self.controls[control_id],
                device_configuration_profile=profile,
                severity=Control.Severity.MEDIUM, title=control_id)

    def _cells(self, response, hostname):
        """{cell label: cell dict} for one appliance, flattened across groups."""
        row = next(r for r in response.context["rows"]
                   if r["profile"].appliance.hostname == hostname)
        return {cell["label"]: cell for group in row["groups"] for cell in group["cells"]}

    def test_one_row_per_appliance_carrying_every_finding(self):
        """Jason's rule: controls sharing an object are presented together, not split."""
        profile = self._profile("fw-bare")
        self._fire(profile, *[c for c in CONTROLS if c not in ("PAN-AUTH-012", "PAN-AUTH-013")])
        response = self.client.get(reverse("assessment_password_complexity_list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["rows"]), 1)
        self.assertEqual(len(response.context["rows"][0]["findings"]), 11)

    def test_a_cell_is_weak_only_when_its_own_control_fired(self):
        profile = self._profile("fw-one", password_minimum_length=8, password_history_count=2)
        self._fire(profile, "PAN-AUTH-002")
        cells = self._cells(self.client.get(
            reverse("assessment_password_complexity_list")), "fw-one")
        self.assertTrue(cells["Length"]["weak"])
        self.assertFalse(cells["History"]["weak"])

    def test_the_bounded_control_marks_both_ends_and_not_the_middle(self):
        """PAN-AUTH-010. The test that a re-derived "higher is worse" rule would fail.

        Never-expires and expires-too-rarely are both findings; sixty days is not. The page
        gets all three right without knowing the threshold, because the highlight follows the
        finding.
        """
        never = self._profile("fw-never", password_expiration_period=0)
        rarely = self._profile("fw-rarely", password_expiration_period=365)
        fine = self._profile("fw-fine", password_expiration_period=60)
        self._fire(never, "PAN-AUTH-010")
        self._fire(rarely, "PAN-AUTH-010")
        response = self.client.get(reverse("assessment_password_complexity_list"))
        self.assertTrue(self._cells(response, "fw-never")["Period"]["weak"])
        self.assertTrue(self._cells(response, "fw-rarely")["Period"]["weak"])
        self.assertFalse(self._cells(response, "fw-fine")["Period"]["weak"])
        self.assertContains(response, "never")

    def test_unassessed_values_are_shown_and_never_marked_weak(self):
        """Three keys PAN-OS accepts that no control reads. Shown, so the page does not imply
        the assessed subset is the whole object; never amber, so nobody reads one as a pass."""
        profile = self._profile("fw-unassessed", password_block_repeated_characters=0)
        self._fire(profile, *CONTROLS)
        cells = self._cells(self.client.get(
            reverse("assessment_password_complexity_list")), "fw-unassessed")
        for label in ("Repeated chars", "On first login", "Period block"):
            self.assertEqual(cells[label]["kind"].split("_")[0], "unassessed")
            self.assertFalse(cells[label]["weak"])

    def test_provenance_renders_a_pushed_value_and_stays_blank_for_a_local_one(self):
        profile = self._profile("fw-prov", password_minimum_length=8, password_history_count=2)
        content_type = ContentType.objects.get_for_model(DeviceConfigurationProfile)
        FieldProvenance.objects.create(
            content_type=content_type, object_id=profile.pk,
            field_name="password_minimum_length", provenance_type="template",
            raw_value="ptpl_fw-core-tpa")
        FieldProvenance.objects.create(
            content_type=content_type, object_id=profile.pk,
            field_name="password_history_count", provenance_type="local", raw_value="")
        url = reverse("assessment_password_complexity_list")
        cells = self._cells(self.client.get(url + "?provenance=1"), "fw-prov")
        self.assertEqual(cells["Length"]["provenance"], "ptpl_fw-core-tpa")
        self.assertEqual(cells["History"]["provenance"], "")
        self.assertContains(self.client.get(url + "?provenance=1"), "ptpl_fw-core-tpa")
        self.assertNotContains(self.client.get(url), "ptpl_fw-core-tpa")

    def test_the_findings_filter_hides_clean_appliances(self):
        dirty = self._profile("fw-dirty")
        self._profile("fw-clean", password_minimum_length=15)
        self._fire(dirty, "PAN-AUTH-002")
        response = self.client.get(
            reverse("assessment_password_complexity_list") + "?findings=1")
        self.assertEqual(response.context["shown_count"], 1)
        self.assertEqual(response.context["total_count"], 2)
