"""Security-rule findings on the shared object path, and saying which rule they are about.

Until 2026-09-16 a policy finding read "Matched control query: Baseline." and nothing more:
`RuleFinding` was built on `FindingBase`, so it had no `subject_name`, and this module's
generator was a hand-rolled copy of `object_findings` that wrote no subject sentence. These
tests hold the converged path in place - the sentence, the frozen name, and the scope that
keeps two same-named rules in different vsys apart.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.findings import generate_rule_findings, regenerate_rule_findings
from assessments.models import AssessmentRun, Control, ControlQuery, RuleFinding
from optivedge_integrations.integrations.models import (
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    SecurityRule,
    Snapshot,
)

ALLOW_QUERY = {
    "model": "integrations.SecurityRule",
    "operator": "or",
    "clauses": [{"field": "action", "op": "eq", "value": "allow"}],
}


class RuleFindingTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="pano.rule-findings")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="fw-rule-findings")
        self.control = Control.objects.create(
            control_id="PAN-POL-TEST-001",
            name="Ensure security rules are not overly permissive",
            control_type=Control.ControlType.SECURITY_RULE,
            description="Prototype control for finding generation.",
            default_severity=Control.Severity.MEDIUM,
        )
        self.query = ControlQuery.objects.create(
            control=self.control, name="Baseline", canonical_query=ALLOW_QUERY, is_baseline=True)

    def _point(self, vsys_name):
        """Cached by name: a vsys is unique per appliance group, and two rules in the same vsys
        are the normal case."""
        point, _ = EnforcementPoint.objects.get_or_create(
            management_station=self.station, appliance_group=self.group,
            vsys_name=vsys_name, defaults={"vsys_display_name": vsys_name})
        return point

    def _rule(self, name, *, point=None, config_source=SecurityRule.SOURCE_LOCAL,
              order=1, action="allow", disabled=False):
        point = point or self._point("vsys1")
        snapshot = Snapshot.objects.create(
            management_station=self.station, enforcement_point=point,
            source_type="test", collected_at=timezone.now())
        return SecurityRule.objects.create(
            management_station=self.station, enforcement_point=point,
            source_snapshot=snapshot, config_source=config_source,
            effective_order=order, rule_position=order, name=name,
            action=action, disabled=disabled, rule_type="universal")

    def _run(self):
        run = AssessmentRun.objects.create(
            name="Rule findings", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_rule_findings(run)
        return run

    def test_the_summary_names_the_rule_its_position_rulebase_and_point(self):
        rule = self._rule("allow-any-any", point=self._point("vsys3"), order=7)
        self._run()
        finding = RuleFinding.objects.get()
        self.assertIn("Rule allow-any-any", finding.summary)
        self.assertIn("position 7", finding.summary)
        self.assertIn("local rulebase", finding.summary)
        self.assertIn(str(rule.enforcement_point), finding.summary)
        self.assertIn("action allow", finding.summary)
        self.assertTrue(finding.summary.endswith("Matched control query: Baseline."))

    def test_a_disabled_rule_says_so(self):
        """The finding is real - the rule is one click from enforcing - but a reader must not
        be left to assume it is live."""
        self._rule("staged-allow", disabled=True)
        self._run()
        self.assertIn("DISABLED", RuleFinding.objects.get().summary)

    def test_a_pushed_rule_names_the_panorama_rulebase(self):
        self._rule("pre-allow", config_source=SecurityRule.SOURCE_PUSHED_PRE)
        self._run()
        self.assertIn("Panorama pre-rulebase", RuleFinding.objects.get().summary)

    def test_the_subject_name_is_frozen_onto_the_finding(self):
        """So the finding still says what it found after the rule is renamed or collected away."""
        rule = self._rule("allow-any-any")
        self._run()
        finding = RuleFinding.objects.get()
        self.assertEqual(finding.subject_name, "allow-any-any")
        rule.delete()
        self.assertEqual(RuleFinding.objects.count(), 0)  # cascades, as the FK says

    def test_the_scope_separates_two_rules_with_the_same_name(self):
        """A rule name is unique only per enforcement point, so the same name legitimately
        exists in several vsys. Without a scope the two findings are indistinguishable."""
        self._rule("allow-any-any", point=self._point("vsys1"))
        self._rule("allow-any-any", point=self._point("vsys2"))
        self._run()
        scopes = sorted(f.subject_scope for f in RuleFinding.objects.all())
        self.assertEqual(scopes, ["local:vsys1", "local:vsys2"])

    def test_the_scope_separates_a_local_rule_from_a_pushed_one(self):
        point = self._point("vsys1")
        self._rule("allow-any-any", point=point)
        self._rule("allow-any-any", point=self._point("vsys2"),
                   config_source=SecurityRule.SOURCE_PUSHED_PRE)
        self._run()
        self.assertEqual(
            sorted(f.subject_scope for f in RuleFinding.objects.all()),
            ["local:vsys1", "pushed_pre:vsys2"])

    def test_findings_are_created_in_subject_order_not_pk_order(self):
        """Findings are numbered in creation order, so the order must be the one a reader of a
        list sorted by object expects - not whichever rule was collected first."""
        self._rule("zz-last")
        self._rule("aa-first")
        self._run()
        self.assertEqual([f.subject_name for f in RuleFinding.objects.order_by("id")],
                         ["aa-first", "zz-last"])

    def test_regenerate_runs_security_rule_controls_alone(self):
        """Every other finding kind had a per-kind regenerate; this one did not."""
        self._rule("allow-any-any")
        result = regenerate_rule_findings()
        self.assertEqual(result.controls_evaluated, 1)
        self.assertEqual(result.findings_created, 1)
        self.assertEqual(result.query_links_created, 1)
        self.assertEqual(result.assessment_run.status, AssessmentRun.Status.COMPLETED)
        self.assertIn("Security rule", result.assessment_run.name)
