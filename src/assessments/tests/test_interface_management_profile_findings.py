"""PAN-MGT-013 end to end: does an unused profile become a finding, and a bound one not?"""

from __future__ import annotations

import re

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments.controls_catalog.registry import load_seed_payload
from assessments.interface_management_profile_findings import (
    generate_interface_management_profile_findings,
)
from assessments.models import (
    AssessmentRun, Control, ControlQuery, InterfaceManagementProfileFinding)
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, InterfaceManagementProfile, ManagementStation, Snapshot)


class UnusedProfileControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.imp")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="pair",
            group_type=ApplianceGroup.TYPE_HA_PAIR)
        # The control ships in the seed; take its real query rather than inventing one, so
        # the test fails if the catalog and the compiler drift apart.
        spec = next(c for c in load_seed_payload()["catalogs"][0]["controls"]
                    if c["control_id"] == "PAN-MGT-013")
        self.control = Control.objects.create(
            control_id=spec["control_id"], name=spec["name"],
            control_type=Control.ControlType.INTERFACE_MANAGEMENT_PROFILE,
            description=spec["description"], default_severity=spec["default_severity"],
            target_model=spec["target_model"])
        for query in spec["queries"]:
            ControlQuery.objects.create(
                control=self.control, name=query["name"],
                canonical_query=query["canonical_query"],
                is_baseline=query["is_baseline"], is_active=query["is_active"])
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _profile(self, hostname, name, bound=()):
        appliance, _ = Appliance.objects.get_or_create(
            management_station=self.station, serial_number=f"S-{hostname}",
            defaults={"hostname": hostname, "appliance_group": self.group})
        snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        return InterfaceManagementProfile.objects.create(
            management_station=self.station, appliance=appliance,
            appliance_group=self.group, source_snapshot=snapshot, name=name,
            bound_interface_names=list(bound), bound_interface_count=len(bound))

    def test_only_unbound_profiles_produce_a_finding(self):
        self._profile("fw-a", "bound", bound=["ethernet1/1"])
        unused = self._profile("fw-a", "unused")
        controls, findings, links, skipped = generate_interface_management_profile_findings(self.run)
        self.assertEqual((controls, findings, skipped), (1, 1, 0))
        finding = InterfaceManagementProfileFinding.objects.get()
        self.assertEqual(finding.interface_management_profile, unused)
        self.assertEqual(finding.subject_name, "unused")
        self.assertEqual(finding.severity, Control.Severity.LOW)

    def test_the_same_template_profile_unused_on_two_peers_is_two_findings(self):
        """Per appliance, deliberately: each device's binding state is its own fact."""
        self._profile("fw-a", "from-template")
        self._profile("fw-b", "from-template")
        generate_interface_management_profile_findings(self.run)
        self.assertEqual(
            sorted(InterfaceManagementProfileFinding.objects
                   .values_list("interface_management_profile__appliance__hostname", flat=True)),
            ["fw-a", "fw-b"])

    def test_the_summary_says_it_is_bound_to_nothing_not_that_it_is_exposed(self):
        self._profile("fw-a", "unused")
        generate_interface_management_profile_findings(self.run)
        summary = InterfaceManagementProfileFinding.objects.get().summary
        self.assertIn("bound to no interface", summary)
        self.assertNotIn("exposed", summary)

    def test_a_profile_bound_only_to_a_subinterface_is_not_unused(self):
        self._profile("fw-a", "sub-only", bound=["ethernet1/1.10"])
        _, findings, _, _ = generate_interface_management_profile_findings(self.run)
        self.assertEqual(findings, 0)

