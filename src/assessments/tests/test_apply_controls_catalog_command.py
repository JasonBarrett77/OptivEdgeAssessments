"""The recovery path for a catalog that can no longer be applied from the UI.

Removing a search field invalidates every stored query that named it. `apply_catalog`
snapshots the LIVE controls before replacing them and validates that snapshot, so a single
stale control blocks the apply that would have fixed it - and the UI has no way out. This
happened for real when the six *_disabled fields were dropped from
DeviceConfigurationProfile, and recovery required a database shell.
"""

from __future__ import annotations

from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import (
    AssessmentRun,
    Catalog,
    Control,
    ControlQuery,
    DeviceConfigurationFinding,
)
from optivedge_integrations.integrations.models import (
    Appliance,
    DeviceConfigurationProfile,
    ManagementStation,
    Snapshot,
)

#: The exact query that broke the real environment: a field that no longer exists.
DEAD_QUERY = {
    "model": "integrations.DeviceConfigurationProfile",
    "operator": "or",
    "clauses": [{"field": "http_disabled", "op": "eq", "value": False}],
}


class ApplyControlsCatalogCommandTests(TestCase):
    def setUp(self):
        payload = next(c for c in load_seed_payload()["catalogs"]
                       if c["catalog"]["key"] == "base")
        meta = payload["catalog"]
        self.catalog = Catalog.objects.create(
            key=meta["key"], label=meta["label"], version=meta["version"],
            description=meta["description"], payload=payload, is_seeded=True)

        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.cmd")
        appliance = Appliance.objects.create(
            management_station=station, serial_number="S-CMD", hostname="fw-cmd")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        self.profile = DeviceConfigurationProfile.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            config_source="local")

        # A live control whose stored query names a removed field, with a finding holding a
        # PROTECT reference to it - which is what makes the naive delete fail.
        self.stale = Control.objects.create(
            control_id="MGMT-001", name="Insecure services",
            control_type=Control.ControlType.DEVICE_CONFIGURATION,
            description="x", default_severity=Control.Severity.HIGH)
        ControlQuery.objects.create(
            control=self.stale, name="Baseline", canonical_query=DEAD_QUERY, is_baseline=True)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(), completed_at=timezone.now())
        DeviceConfigurationFinding.objects.create(
            assessment_run=self.run, control=self.stale,
            device_configuration_profile=self.profile,
            severity=Control.Severity.HIGH, title="t")

    def _run(self, *args):
        out = StringIO()
        call_command("apply_controls_catalog", *args, stdout=out, stderr=out)
        return out.getvalue()

    def test_dry_run_reports_the_blocker_and_changes_nothing(self):
        output = self._run()
        self.assertIn("MGMT-001", output)
        self.assertIn("http_disabled", output)
        self.assertIn("Dry run", output)
        self.assertTrue(Control.objects.filter(control_id="MGMT-001").exists())
        self.assertFalse(Control.objects.filter(control_id="PAN-MGT-001").exists())

    def test_dry_run_predicts_against_the_seed_not_the_stored_payload(self):
        """The environments that need this command are exactly the ones whose stored payload
        is stale, so reading it would report no changes in the case that matters."""
        self.catalog.payload = {**self.catalog.payload, "controls": []}
        self.catalog.save(update_fields=["payload"])
        output = self._run()
        self.assertIn("the bundled seed file", output)
        self.assertIn("+ PAN-MGT-001", output)

    def test_apply_clears_the_blocker_and_installs_the_new_controls(self):
        self._run("--apply")
        live = set(Control.objects.values_list("control_id", flat=True))
        self.assertNotIn("MGMT-001", live)
        self.assertIn("PAN-MGT-001", live)
        self.assertIn("PAN-MGT-006", live)
        self.assertEqual(DeviceConfigurationFinding.objects.count(), 0)

    def test_apply_succeeds_despite_the_protected_finding(self):
        """The naive fix - delete the control - raises ProtectedError. The findings must go
        first, and the error names only the first protecting model it hits."""
        self._run("--apply")
        self.assertTrue(Control.objects.filter(control_id="PAN-MGT-003").exists())

    def test_apply_is_idempotent(self):
        self._run("--apply")
        first = sorted(Control.objects.values_list("control_id", flat=True))
        output = self._run("--apply")
        self.assertIn("No stale controls", output)
        self.assertEqual(sorted(Control.objects.values_list("control_id", flat=True)), first)
