"""Generating findings costs the same number of queries for one subject as for three.

Run Findings ran out of memory on the lab on 2026-10-14, and when that was fixed it still issued
about 40,000 queries for 13,162 security-rule findings, three per finding:

* the subject sentence prints the rule's enforcement point, whose `__str__` reads
  `appliance_group or appliance` - a lazy fetch per finding
* each finding was its own INSERT
* each finding's query links were their own INSERT

and every control re-fetched the rules it matched, with their prefetched verdicts, so a rule
matched by eighteen controls was built eighteen times. None of that raised anything and none of
it shows on a fixture of one rule. It shows as a query count that grows with the estate, which
is what this pins. Measured on the lab: 9.0s to 2.1s, identical findings.
"""

from __future__ import annotations

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from assessments.findings import generate_rule_findings
from assessments.models import AssessmentRun, Control, RuleFinding
from assessments.tests._seed import seed_controls, seed_specs
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    SecurityRule,
    SecurityRuleProfileVerdict,
    Snapshot,
)


class RuleFindingGenerationCostTests(TestCase):
    def setUp(self):
        seed_controls([cid for cid, spec in seed_specs().items()
                       if spec["control_type"] == Control.ControlType.SECURITY_RULE])
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.cost")
        # Owned by a GROUP: the point's `__str__` reads the group first, which is the lazy
        # fetch the sentence used to pay per finding.
        group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-cost",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=group,
            serial_number="S-cost", hostname="fw-cost")
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=group,
            vsys_name="vsys1", vsys_display_name="vsys1")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})

    def add_rules(self, count):
        """Allow rules carrying no profile: every verdict NULL, so every threat-profile control
        fires on each, and each rule is a subject of many controls at once."""
        start = SecurityRule.objects.count()
        for order in range(start + 1, start + count + 1):
            rule = SecurityRule.objects.create(
                management_station=self.station, enforcement_point=self.point,
                source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
                effective_order=order, rule_position=order, name=f"bare-{order}",
                action="allow", rule_type="universal")
            for assertion, _label in SecurityRuleProfileVerdict.ASSERTION_CHOICES:
                SecurityRuleProfileVerdict.objects.create(
                    security_rule=rule, assertion=assertion, profile_name="",
                    satisfied=None, detail="no profile is in force on this rule")

    def generate(self):
        # Outside the measured window: replacing the previous run's findings costs a delete
        # that the first run, with nothing to replace, does not - a constant, not a per-row cost.
        RuleFinding.objects.all().delete()
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        with CaptureQueriesContext(connection) as captured:
            generate_rule_findings(run)
        return len(captured), RuleFinding.objects.filter(assessment_run=run).count()

    def test_query_count_does_not_grow_with_findings(self):
        self.add_rules(1)
        one_queries, one_findings = self.generate()
        self.add_rules(2)
        three_queries, three_findings = self.generate()

        # Guards the comparison: a run that found nothing would agree on any code.
        self.assertGreaterEqual(one_findings, 11)
        self.assertEqual(three_findings, 3 * one_findings)
        self.assertEqual(three_queries, one_queries,
                         "generating rule findings costs a query per finding or per rule")

    def test_every_finding_is_linked_to_the_queries_it_matched(self):
        """The links are now written by key read back after a batch INSERT, so a mismatch
        would attach a finding's queries to another finding rather than fail."""
        self.add_rules(3)
        self.generate()

        for finding in RuleFinding.objects.prefetch_related("query_links__control_query"):
            with self.subTest(finding.reference):
                linked = sorted(link.control_query.name
                                for link in finding.query_links.all())
                self.assertEqual(linked, sorted(finding.matched_query_names))
                self.assertTrue(all(link.control_query.control_id == finding.control_id
                                    for link in finding.query_links.all()))
