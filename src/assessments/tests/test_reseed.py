"""Refresh Seed does the whole job: refresh, discard, apply.

It used to only rewrite the stored payload and tell the user to apply it separately - which
fails outright once a live control references a search field that no longer exists, with no
way out of the UI.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments.controls_catalog.io.importers import reseed_from_bundled_catalog
from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import (
    AssessmentRun, Catalog, Control, ControlQuery, DeviceConfigurationFinding)
from optivedge_integrations.integrations.models import (
    Appliance, DeviceConfigurationProfile, ManagementStation, Snapshot)

DEAD_QUERY = {
    "model": "integrations.DeviceConfigurationProfile",
    "operator": "or",
    "clauses": [{"field": "http_disabled", "op": "eq", "value": False}],
}


class ReseedTests(TestCase):
    def setUp(self):
        payload = next(c for c in load_seed_payload()["catalogs"]
                       if c["catalog"]["key"] == "base")
        meta = payload["catalog"]
        # A STALE stored payload, as an environment seeded before the seed file changed.
        self.catalog = Catalog.objects.create(
            key=meta["key"], label=meta["label"], version=meta["version"],
            description=meta["description"],
            payload={**payload, "controls": []}, is_seeded=True)
        self.old_snapshot_catalog = Catalog.objects.create(
            key="snap", label="Snapshot 1", version="snapshot", description="",
            payload={**payload, "controls": []}, is_snapshot=True)

        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.rs")
        appliance = Appliance.objects.create(
            management_station=self.station, serial_number="S-RS", hostname="fw-rs")
        self.config_snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        profile = DeviceConfigurationProfile.objects.create(
            management_station=self.station, appliance=appliance,
            source_snapshot=self.config_snapshot, config_source="local")

        stale = Control.objects.create(
            control_id="MGMT-001", name="Insecure services",
            control_type=Control.ControlType.DEVICE_CONFIGURATION,
            description="x", default_severity=Control.Severity.HIGH)
        ControlQuery.objects.create(
            control=stale, name="Baseline", canonical_query=DEAD_QUERY, is_baseline=True)
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(), completed_at=timezone.now())
        DeviceConfigurationFinding.objects.create(
            assessment_run=run, control=stale, device_configuration_profile=profile,
            severity=Control.Severity.HIGH, title="t")

    def test_one_call_refreshes_discards_and_applies(self):
        result = reseed_from_bundled_catalog(application_environment=None)
        live = set(Control.objects.values_list("control_id", flat=True))
        self.assertNotIn("MGMT-001", live)
        self.assertIn("PAN-MGT-013", live)
        self.assertEqual(result.controls_created, len(live))
        self.assertEqual(AssessmentRun.objects.count(), 0)
        self.assertEqual(DeviceConfigurationFinding.objects.count(), 0)

    def test_it_works_when_a_live_control_uses_a_removed_field(self):
        """The case that made the UI a dead end: the stale control blocks apply_catalog's
        snapshot, and refreshing alone does not clear it."""
        reseed_from_bundled_catalog(application_environment=None)
        self.assertTrue(Control.objects.filter(control_id="PAN-MGT-001").exists())

    def test_snapshot_catalogs_are_deleted_and_none_is_created(self):
        """A snapshot taken before a stale apply cannot be applied either - it captured the
        same dead field - so it reads as a rollback point and is not one."""
        reseed_from_bundled_catalog(application_environment=None)
        self.assertEqual(Catalog.objects.filter(is_snapshot=True).count(), 0)
        self.assertFalse(Catalog.objects.filter(pk=self.old_snapshot_catalog.pk).exists())

    def test_collected_configuration_is_untouched(self):
        """`Snapshot` in OptivEdgeIntegrations is a different model with the same word in
        its name. Deleting it would mean re-collecting from every device."""
        reseed_from_bundled_catalog(application_environment=None)
        self.assertTrue(Snapshot.objects.filter(pk=self.config_snapshot.pk).exists())
        self.assertEqual(DeviceConfigurationProfile.objects.count(), 1)

    def test_it_is_idempotent(self):
        first = reseed_from_bundled_catalog(application_environment=None)
        second = reseed_from_bundled_catalog(application_environment=None)
        self.assertEqual(second.controls_created, first.controls_created)
        self.assertEqual(second.snapshot_catalogs_deleted, 0,
                         "a clean run leaves no snapshot catalog to delete next time")

    def test_the_view_reseeds_and_reports_what_it_discarded(self):
        response = self.client.post(reverse("assessment_catalog_refresh_seed"), follow=True)
        self.assertEqual(response.status_code, 200)
        text = " ".join(str(m) for m in response.context["messages"])
        self.assertIn("Reseeded", text)
        self.assertIn("Discarded", text)
        self.assertIn("Collected configuration is untouched", text)
        self.assertTrue(Control.objects.filter(control_id="PAN-MGT-013").exists())


class ReseedButtonCopyTests(TestCase):
    """The button destroys findings and runs, so the page has to say so before it is pressed."""

    def test_the_system_page_warns_what_the_button_discards(self):
        response = self.client.get(reverse("assessment_system"))
        self.assertContains(response, "Reseed")
        self.assertContains(response, "Discards every control")
        self.assertContains(response, "Collected configuration is untouched")

    def test_it_no_longer_tells_the_user_to_apply_separately(self):
        response = self.client.get(reverse("assessment_system"))
        self.assertNotContains(response, "use Apply on the Catalogs tab afterward")
