"""MGMT-002 producing findings: one per exposed surface, each naming its own door."""

from __future__ import annotations

from django.test import TestCase

from assessments.management_interface_naming import surface_label
from django.utils import timezone

from assessments.management_interface_findings import regenerate_management_interface_findings
from assessments.models import (
    AssessmentRun,
    Control,
    ControlQuery,
    ManagementInterfaceFinding,
)
from optivedge_integrations.integrations.models import (
    Appliance,
    ManagementInterface,
    ManagementStation,
    PermittedSource,
    Snapshot,
)

MGMT_002_QUERY = {
    "model": "integrations.ManagementInterface",
    "operator": "or",
    "clauses": [
        {"field": "exposure", "op": "eq", "value": "unrestricted"},
        {"field": "exposure", "op": "eq", "value": "undetermined"},
    ],
}


class ManagementInterfaceFindingTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.findings")
        self.appliance = Appliance.objects.create(
            management_station=self.station, serial_number="S-F1", hostname="fw-findings")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        self.control = Control.objects.create(
            control_id="MGMT-002",
            name="Ensure management interface permitted IP addresses are configured",
            control_type=Control.ControlType.MANAGEMENT_INTERFACE,
            description="Management access should be restricted to approved networks.",
            default_severity=Control.Severity.HIGH,
        )
        self.query = ControlQuery.objects.create(
            control=self.control, name="Baseline", canonical_query=MGMT_002_QUERY,
            is_baseline=True)

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

    def test_one_finding_per_exposed_surface_naming_the_surface(self):
        self._surface(ManagementInterface.PLANE_MGT,
                      sources=[("10.0.0.0/8", 4, 167772160, 184549375)])       # restricted
        self._surface(ManagementInterface.PLANE_AUX1)                           # unrestricted
        self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/1", "p")  # unrestricted
        self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/4", "p",
                      sources=[("not-an-address", None, None, None)])           # undetermined

        result = regenerate_management_interface_findings()

        self.assertEqual(result.controls_evaluated, 1)
        self.assertEqual(result.findings_created, 3)
        self.assertEqual(result.skipped_queries, 0)
        self.assertEqual(result.assessment_run.status, AssessmentRun.Status.COMPLETED)

        findings = ManagementInterfaceFinding.objects.all()
        self.assertEqual(sorted(f.subject_name for f in findings),
                         ["Aux-1", "ethernet1/1", "ethernet1/4"])
        # the whole point: the summary names the door, not just the value
        summary = findings.get(subject_name="ethernet1/1").summary
        self.assertIn("ethernet1/1", summary)
        self.assertIn("fw-findings", summary)
        self.assertIn("Baseline", summary)
        self.assertEqual(findings.get(subject_name="Aux-1").matched_query_names, ["Baseline"])
        self.assertEqual(findings.first().severity, Control.Severity.HIGH)

    def test_one_appliance_can_produce_several_findings_for_one_control(self):
        """Not duplicates - separate doors with separate exposure."""
        for name in ("ethernet1/1", "ethernet1/2", "ethernet1/3"):
            self._surface(ManagementInterface.PLANE_DATAPLANE, name, "p")
        result = regenerate_management_interface_findings()
        self.assertEqual(result.findings_created, 3)
        self.assertEqual(
            {f.management_interface.appliance_id for f in ManagementInterfaceFinding.objects.all()},
            {self.appliance.pk})

    def test_subject_name_is_frozen_against_a_later_rename(self):
        surface = self._surface(ManagementInterface.PLANE_DATAPLANE, "ethernet1/9", "p")
        regenerate_management_interface_findings()
        surface.interface_name = "ethernet1/9-renamed"
        surface.save(update_fields=["interface_name"])
        self.assertEqual(ManagementInterfaceFinding.objects.get().subject_name, "ethernet1/9")

    def test_a_run_replaces_the_previous_one(self):
        self._surface(ManagementInterface.PLANE_AUX1)
        regenerate_management_interface_findings()
        regenerate_management_interface_findings()
        self.assertEqual(ManagementInterfaceFinding.objects.count(), 1)

    def test_a_fully_restricted_estate_produces_nothing(self):
        self._surface(ManagementInterface.PLANE_MGT,
                      sources=[("10.0.0.0/8", 4, 167772160, 184549375)])
        result = regenerate_management_interface_findings()
        self.assertEqual(result.findings_created, 0)
        self.assertEqual(result.assessment_run.status, AssessmentRun.Status.COMPLETED)
