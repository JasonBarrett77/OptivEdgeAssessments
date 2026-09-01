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


class InterfaceManagementProfileListViewTests(TestCase):
    """The Management Profiles tab: every profile, with a findings-only filter."""

    def setUp(self):
        from optivedge_integrations.integrations.models import FieldProvenance
        from django.contrib.contenttypes.models import ContentType

        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.tab")
        self.appliance = Appliance.objects.create(
            management_station=self.station, serial_number="S-TAB", hostname="fw-tab")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        self.control = Control.objects.create(
            control_id="PAN-MGT-013", name="Unused Interface Management Profiles",
            control_type=Control.ControlType.INTERFACE_MANAGEMENT_PROFILE,
            description="x", default_severity=Control.Severity.LOW)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(), completed_at=timezone.now())

        self.bound = self._profile("bound-one", ["ethernet1/1"])
        self.unused = self._profile("unused-one", [])
        InterfaceManagementProfileFinding.objects.create(
            assessment_run=self.run, control=self.control,
            interface_management_profile=self.unused,
            severity=Control.Severity.LOW, title="t", subject_name="unused-one")

        # A template-sourced profile records provenance; a local one records none.
        FieldProvenance.objects.create(
            content_type=ContentType.objects.get_for_model(InterfaceManagementProfile),
            object_id=self.bound.pk, field_name="__entry__",
            provenance_type=FieldProvenance.ProvenanceType.TEMPLATE,
            raw_key="@ptpl", raw_value="ptpl_fw-core-tpa")

    def _profile(self, name, bound):
        return InterfaceManagementProfile.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_snapshot=self.snapshot, name=name,
            bound_interface_names=bound, bound_interface_count=len(bound))

    def test_lists_every_profile_by_default(self):
        response = self.client.get(reverse("assessment_interface_management_profile_list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_count"], 2)
        self.assertContains(response, "bound-one")
        self.assertContains(response, "unused-one")

    def test_findings_filter_narrows_to_profiles_with_an_open_finding(self):
        response = self.client.get(
            reverse("assessment_interface_management_profile_list"), {"findings": "1"})
        self.assertEqual(response.context["shown_count"], 1)
        self.assertEqual(response.context["rows"][0]["profile"], self.unused)

    def test_an_unbound_profile_reads_as_nothing_not_as_blank(self):
        """A blank cell is ambiguous; the whole point of the row is that nothing uses it."""
        response = self.client.get(reverse("assessment_interface_management_profile_list"))
        self.assertContains(response, "Nothing")

    def test_provenance_shows_the_template_and_defaults_to_local(self):
        rows = {r["profile"].name: r for r in self.client.get(
            reverse("assessment_interface_management_profile_list")).context["rows"]}
        self.assertEqual(rows["bound-one"]["origin"].raw_value, "ptpl_fw-core-tpa")
        self.assertIsNone(rows["unused-one"]["origin"],
                          "local is the absence of a provenance row")

    def test_the_table_stays_square(self):
        html = self.client.get(
            reverse("assessment_interface_management_profile_list")).content.decode()
        body = re.search(r"<tbody>(.*?)</tbody>", html, re.S).group(1)
        first_row = re.search(r"<tr[^>]*>(.*?)</tr>", body, re.S).group(1)
        header = re.search(r"<thead>(.*?)</thead>", html, re.S).group(1)
        self.assertEqual(len(re.findall(r"<td", first_row)),
                         len(re.findall(r"<th", header)))

    def test_all_three_device_tabs_are_present(self):
        response = self.client.get(reverse("assessment_interface_management_profile_list"))
        self.assertContains(response, "Device Configuration")
        self.assertContains(response, "Management Interfaces")
        self.assertContains(response, "Management Profiles")


class EmptyStateGuidanceTests(TestCase):
    """The empty state has to name the right action.

    Both of these said "run a sync", which contacts every device. Surfaces and profiles are
    both built from the stored snapshot, so Renormalize is enough - and on an estate where
    collection is slow or a device is unreachable, the difference is the whole afternoon.
    """

    def test_the_profiles_tab_asks_for_a_renormalize_not_a_sync(self):
        response = self.client.get(reverse("assessment_interface_management_profile_list"))
        self.assertEqual(response.context["total_count"], 0)
        self.assertContains(response, "Renormalize")
        self.assertContains(response, "stored snapshot")

    def test_the_surfaces_tab_asks_for_a_renormalize_not_a_sync(self):
        response = self.client.get(reverse("assessment_management_interface_list"))
        self.assertEqual(response.context["total_count"], 0)
        self.assertContains(response, "Renormalize")
        self.assertContains(response, "stored snapshot")
