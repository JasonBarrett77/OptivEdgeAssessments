"""PAN-POL-004 - application-default on allow rules, and what it deliberately leaves alone.

The control asserts the corpus's preferred value, so BOTH ways of missing it fire: `any`, which
allows every permitted application on every port, and an explicit service object, which pins the
rule to ports the configuration cannot say were intended. An assessor holding that documentation
clears the second; nothing in the config can.

Two device facts measured on fw-core-tpa-a, 2026-09-16, are why the query is one clause over a
member list rather than a shape test:

  - `service` is REQUIRED. A rule without it writes cleanly and fails the COMMIT - "is missing
    'service'" - so a committed rule always carries one, and the only rules with none are the two
    predefined defaults, which is why they are excluded rather than reported.
  - `application-default` is EXCLUSIVE. Writing it beside another member is refused at the write:
    code=12, "'application-default' should not be used with another service". So "has an
    application-default member" is the same question as "is application-default".
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.findings import generate_rule_findings
from assessments.models import AssessmentRun, Control, RuleFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    SecurityRule,
    SecurityRuleService,
    Snapshot,
)


class ApplicationDefaultServiceTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.pol004")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-pol004",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group,
            vsys_name="vsys1", vsys_display_name="vsys1")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_type="test", collected_at=timezone.now())
        self.control = seed_controls(
            ["PAN-POL-004"], control_type=Control.ControlType.SECURITY_RULE)[0]
        self.order = 0

    def _rule(self, name, *, services, action="allow",
              config_source=SecurityRule.SOURCE_LOCAL, disabled=False):
        self.order += 1
        rule = SecurityRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=config_source,
            effective_order=self.order, rule_position=self.order, name=name,
            action=action, disabled=disabled, rule_type="universal")
        for position, value in enumerate(services, start=1):
            SecurityRuleService.objects.create(
                security_rule=rule, value=value, prov="test", position=position)
        return rule

    def _fired(self):
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_rule_findings(run)
        return {finding.security_rule.name for finding in
                RuleFinding.objects.select_related("security_rule")}

    def test_an_allow_rule_on_service_any_fires(self):
        self._rule("allow-any-service", services=["any"])
        self.assertEqual(self._fired(), {"allow-any-service"})

    def test_an_allow_rule_pinned_to_an_explicit_service_fires(self):
        """The corpus names application-default as the PREFERRED value and the control asserts
        it. A documented nonstandard port is the assessor's call, not the query's."""
        self._rule("allow-tcp-8443", services=["tcp-8443"])
        self.assertEqual(self._fired(), {"allow-tcp-8443"})

    def test_an_allow_rule_on_application_default_is_silent(self):
        self._rule("allow-app-default", services=["application-default"])
        self.assertEqual(self._fired(), set())

    def test_a_deny_rule_is_silent_whatever_its_service(self):
        """The vendor recommends application-default FOR ALLOW POLICIES (Help p.131), and a deny
        restricted to a port is a narrower deny rather than a weaker one."""
        self._rule("deny-any-service", services=["any"], action="deny")
        self._rule("deny-tcp-22", services=["tcp-22"], action="drop")
        self.assertEqual(self._fired(), set())

    def test_the_predefined_default_rules_are_silent(self):
        """`intrazone-default` allows, exists in no rulebase and carries no service - and has
        none to set, so reporting it would be a finding nobody can clear."""
        self._rule("intrazone-default", services=[], config_source=SecurityRule.SOURCE_DEFAULT)
        self._rule("interzone-default", services=[], action="deny",
                   config_source=SecurityRule.SOURCE_DEFAULT)
        self.assertEqual(self._fired(), set())

    def test_a_pushed_rule_fires_like_a_local_one(self):
        """Most of the lab's policy arrives from Panorama; a control that only saw local rules
        would report a fraction of the estate and look correct doing it."""
        self._rule("pushed-allow-any", services=["any"],
                   config_source=SecurityRule.SOURCE_PUSHED_PRE)
        self.assertEqual(self._fired(), {"pushed-allow-any"})

    def test_a_disabled_rule_still_fires_and_the_finding_says_so(self):
        """It enforces nothing today and is one click from enforcing tomorrow. The summary
        carries the qualifier so a reader is not left to assume it is live."""
        self._rule("staged-allow-any", services=["any"], disabled=True)
        self.assertEqual(self._fired(), {"staged-allow-any"})
        self.assertIn("DISABLED", RuleFinding.objects.get().summary)

    def test_the_finding_names_the_rule_and_reports_at_the_corpus_severity(self):
        self._rule("allow-any-service", services=["any"])
        self._fired()
        finding = RuleFinding.objects.get()
        self.assertEqual(finding.subject_name, "allow-any-service")
        self.assertEqual(finding.subject_scope, "local:vsys1")
        self.assertEqual(finding.severity, Control.Severity.HIGH)
        self.assertIn("Rule allow-any-service", finding.summary)
