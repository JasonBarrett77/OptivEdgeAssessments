"""Severity assignment: one mechanism, and how it behaves.

A control has ONE baseline query, and `Control.default_severity` is the severity a finding
reports when only that matched. A non-baseline query carrying `adjusted_severity` is an operator
statement about a condition; when several match, the WORST wins, and it overrides the baseline
tier - including downward, which is how a consultant relaxes a finding.

A second mechanism - declarative severity bands on the Control - existed until 2026-09-09 and
was removed. It was seed-only, reachable from no form, capped so it could never escalate, and
produced every severity defect this project had: a null band on a firing value reporting at the
default, a query threshold disagreeing with its bands, a measure field of the wrong type, and
the bands silently outranking an operator query. The ten scaled controls were converted to the
queries below by `OptivEdgeProbe/scratch/convert_severity_scales.py`, which refused to write
until the before/after severity of every value in every control's domain was identical.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.admin_user_findings import generate_admin_user_findings
from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import AdminUserFinding, AssessmentRun, Control, ControlQuery
from optivedge_integrations.integrations.models import (
    AdminUser, Appliance, ApplianceGroup, ManagementStation, Snapshot)


class SeededSeverityTests(TestCase):
    def test_no_control_carries_a_severity_scale(self):
        """The removed mechanism must not come back in a seed - nothing reads it any more, so
        a scale in the catalog would be silently ignored rather than rejected."""
        for cat in load_seed_payload()["catalogs"]:
            for control in cat["controls"]:
                with self.subTest(control=control["control_id"]):
                    self.assertNotIn("severity_scale", control)
                    self.assertNotIn("measure_field", control)

    def test_every_control_has_exactly_one_baseline_query(self):
        """The single-baseline rule is what lets `default_severity` be the baseline-tier
        severity: with one baseline, "severity on the query" and "severity on the control" are
        the same number."""
        for cat in load_seed_payload()["catalogs"]:
            for control in cat["controls"]:
                with self.subTest(control=control["control_id"]):
                    baselines = [q for q in control["queries"] if q["is_baseline"]]
                    self.assertEqual(len(baselines), 1)

    def test_a_baseline_query_never_carries_a_severity(self):
        for cat in load_seed_payload()["catalogs"]:
            for control in cat["controls"]:
                for query in control["queries"]:
                    if not query["is_baseline"]:
                        continue
                    with self.subTest(control=control["control_id"]):
                        self.assertIn(query["adjusted_severity"], (None, ""))

    def test_every_non_baseline_query_carries_one(self):
        """A non-baseline query with no severity would match, contribute nothing, and leave the
        finding at the default - indistinguishable from the query not existing."""
        for cat in load_seed_payload()["catalogs"]:
            for control in cat["controls"]:
                for query in control["queries"]:
                    if query["is_baseline"]:
                        continue
                    with self.subTest(control=control["control_id"], query=query["name"]):
                        self.assertIn(query["adjusted_severity"],
                                      [s for s, _ in Control.Severity.choices])


class CalibrationQueryTests(TestCase):
    """Jason, 2026-09-09: "One query may say value < 5 is high severity, and a second query may
    say value < 3 is critical severity. In this case, the object with a value of 2 would
    technically generate 2 findings, but the code should only keep the more critical of the two."

    That is the design, and nothing exercised it until this: every seeded control carried a
    baseline query alone, so the removed scale had been deciding graded severities unopposed.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.cal")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-cal",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-CAL", hostname="fw-cal")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _control(self, baseline_above=1):
        control = Control.objects.create(
            control_id="PAN-TEST-CAL", name="Superuser count",
            control_type=Control.ControlType.ADMIN_USER,
            description="d", default_severity="high",
            target_model="integrations.AdminUser")

        def query(name, value, severity, baseline=False):
            ControlQuery.objects.create(
                control=control, name=name, is_baseline=baseline, is_active=True,
                adjusted_severity=severity,
                canonical_query={"model": "integrations.AdminUser", "operator": "or",
                                 "clauses": [{"field": "superuser_cohort_size",
                                              "op": "gt", "value": value}]})

        query("Baseline", baseline_above, None, baseline=True)
        query("Operator: above 1", 1, "high")
        query("Operator: above 3", 3, "critical")
        return control

    def _user(self, cohort):
        return AdminUser.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot,
            name=f"u{cohort}", is_superuser=True, superuser_cohort_size=cohort)

    def _findings(self):
        generate_admin_user_findings(self.run)
        return AdminUserFinding.objects.filter(control__control_id="PAN-TEST-CAL")

    def test_matching_two_queries_makes_ONE_finding(self):
        self._control()
        self._user(4)
        self.assertEqual(self._findings().count(), 1)

    def test_the_worse_severity_wins(self):
        """4 matches both "> 1" (high) and "> 3" (critical). Critical is kept."""
        self._control()
        self._user(4)
        self.assertEqual(self._findings().get().severity, "critical")

    def test_matching_only_the_gentler_query_keeps_its_severity(self):
        self._control()
        self._user(2)
        self.assertEqual(self._findings().get().severity, "high")

    def test_an_operator_query_overrides_the_baseline_tier_DOWNWARD_too(self):
        """The consultant relaxing a finding - the direction that matters most in the field,
        and the one a capped mechanism could not express."""
        control = self._control()
        control.queries.filter(is_baseline=False).delete()
        ControlQuery.objects.create(
            control=control, name="Operator: acceptable here", is_baseline=False,
            is_active=True, adjusted_severity="low",
            canonical_query={"model": "integrations.AdminUser", "operator": "or",
                             "clauses": [{"field": "superuser_cohort_size",
                                          "op": "gt", "value": 1}]})
        self._user(4)
        self.assertEqual(self._findings().get().severity, "low")

    def test_an_operator_query_can_fire_outside_the_baseline(self):
        """An operator captures findings we do not, at their own severity.

        Cohort 3 is below the baseline's `> 5`, so nothing we ship reports it. The operator's
        `> 1` query does, and its severity is the one recorded.
        """
        control = self._control(baseline_above=5)
        control.queries.filter(name="Operator: above 3").delete()
        self._user(3)
        finding = self._findings().get()
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.matched_query_names, ["Operator: above 1"])

    def test_only_the_baseline_matching_reports_the_control_default(self):
        control = self._control(baseline_above=1)
        control.queries.filter(is_baseline=False).delete()
        self._user(4)
        self.assertEqual(self._findings().get().severity, "high")
