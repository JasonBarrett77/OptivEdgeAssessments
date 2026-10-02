"""PAN-COV-001 and PAN-COV-002 — what the assessment could not establish.

The case these tests exist for is the one that is easy to get wrong: an object with no size
looks identical whether NOBODY ASKED or the DEVICE ANSWERED AND FAILED, and only the first is
a gap in this assessment. The second is a defect in the customer's configuration and reports
elsewhere. Both have `num_hosts` NULL, and the only thing telling them apart is whether the
device ever reported its own total.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.coverage_findings import generate_coverage_findings
from assessments.models import AssessmentRun, Control, CoverageFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    AddressObject,
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    SecurityRule,
    SecurityRuleDestinationAddressRef,
    Snapshot,
)

CONTROL_IDS = ["PAN-COV-001", "PAN-COV-002"]


class CoverageControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.cov")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-cov",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-COV", hostname="fw-cov")
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group, vsys_name="vsys1")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        seed_controls(CONTROL_IDS, control_type=Control.ControlType.COVERAGE)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _edl(self, name, *, num_hosts=None, truncated=False, source_total=None):
        return AddressObject.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            name=name, namespace_type="local_vsys", namespace_value="vsys1",
            precedence_rank=10, address_type=AddressObject.TYPE_EDL, is_edl=True,
            edl_list_type="ip", value="ip", normalized_value="ip",
            num_hosts=num_hosts, resolved_content_truncated=truncated,
            resolved_content_source_total=source_total,
        )

    def _reference(self, obj):
        rule = SecurityRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=1, rule_position=0, name=f"rule-{obj.name}", action="allow")
        SecurityRuleDestinationAddressRef.objects.create(
            security_rule=rule, raw_value=obj.name, position=0,
            ref_type=SecurityRuleDestinationAddressRef.RefType.ADDRESS_OBJECT,
            address_object=obj)
        return rule

    def _findings(self):
        generate_coverage_findings(self.run)
        return {(f.control.control_id, f.subject_name): f for f in
                CoverageFinding.objects.select_related("control")}

    def test_an_uncollected_referenced_edl_reports(self):
        self._reference(self._edl("never-collected"))

        findings = self._findings()

        self.assertIn(("PAN-COV-001", "never-collected"), findings)
        self.assertEqual(findings[("PAN-COV-001", "never-collected")].severity, "medium")

    def test_an_edl_nothing_references_does_not_report(self):
        """Collection follows normalized rule refs, so an unreferenced list is EXPECTED to be
        unsized. Reporting it would make a full address book look like a broken assessment."""
        self._edl("unused-and-unsized")

        self.assertEqual(self._findings(), {})

    def test_an_edl_the_DEVICE_failed_to_resolve_is_not_our_gap(self):
        """The distinction the whole domain rests on. `prod_west_edl` on the lab answers
        total-valid 0 with a cURL error: the device was asked, it tried, and it failed. That is
        a defect in the customer's configuration - the rule enforces against an empty list - and
        reporting it as an assessment gap would both excuse the device and bury the real
        finding. num_hosts is NULL in both cases; the device having answered at all is what
        separates them."""
        self._reference(self._edl("device-could-not-fetch", source_total=0))

        findings = self._findings()

        self.assertNotIn(("PAN-COV-001", "device-could-not-fetch"), findings)
        self.assertEqual(findings, {})

    def test_a_truncated_edl_reports_with_both_numbers(self):
        self._reference(self._edl("too-big", num_hosts=500, truncated=True, source_total=4000))

        findings = self._findings()

        finding = findings[("PAN-COV-002", "too-big")]
        self.assertEqual(finding.severity, "medium")
        # Both numbers, because the shortfall is the point - a reader needs to know how much of
        # the list is missing, not merely that some is.
        self.assertIn("500", finding.summary)
        self.assertIn("4,000", finding.summary.replace("4000", "4,000"))

    def test_a_truncated_edl_does_not_also_report_as_uncollected(self):
        """It has content, just not all of it. Firing both would report one object twice for
        one condition, and the remedies differ - one is to run a refresh, the other is to
        reconsider the ceiling."""
        self._reference(self._edl("too-big", num_hosts=500, truncated=True, source_total=4000))

        findings = self._findings()

        self.assertNotIn(("PAN-COV-001", "too-big"), findings)
        self.assertEqual(len(findings), 1)

    def test_a_fully_collected_edl_reports_nothing(self):
        self._reference(self._edl("all-good", num_hosts=2776, source_total=2776))

        self.assertEqual(self._findings(), {})
