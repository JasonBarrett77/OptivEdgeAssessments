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
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    SecurityRule,
    SecurityRuleService,
    Snapshot,
)
from optivedge_integrations.integrations.platforms.pan_os.normalization import (
    normalize_enforcement_point_addresses,
    normalize_enforcement_point_security_rules,
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


class MatchTupleBreadthTests(TestCase):
    """PAN-POL-005 - every allow rule names its applications - and the ground PAN-POL-001 held
    before it was dropped on 2026-10-06.

    **These were PAN-POL-001's tests.** It asserted that no allow rule leaves BOTH its source
    and its destination covering the whole address space, and it was dropped into PAN-POL-002's
    critical band: measured on the lab, 45 of its 46 findings already reported there at
    critical. The cases are kept and re-pointed at PAN-POL-002 rather than deleted, because
    what has to stay true is that the dropped assertion is still covered - a drop justified by
    "another control covers it" is worth exactly as much as the test that says so.

    One of them is gone with it. `test_the_include_any_flag_is_what_makes_the_address_clauses_work`
    held a flag in 001's seeded query: the semantic address compiler EXCLUDES `any` members
    unless a clause asks for them, so 001 written without `include_any` matched nothing and
    reported a clean estate - a control failing in the direction of its own answer. PAN-POL-002
    reads host-count COLUMNS and not that compiler, so it cannot fail that way and there is no
    flag to hold. 001 was the only control in the catalog using `include_any`; the capability
    remains and this is the note saying why it mattered.

    PAN-POL-005 reads the corpus's PREFERRED value rather than its minimum, which applies only
    to rules "crossing an untrust boundary" - something no configuration states.

    Built through the REAL normalizers rather than by hand. An address clause resolves through a
    normalized `AddressObject` and its resolved entries, so a hand-made ref matches nothing - and
    a test that built one would pass while asserting the control cannot work.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.breadth")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-breadth",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-BREADTH", hostname="fw-breadth")
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group,
            vsys_name="vsys1", vsys_display_name="vsys1")
        self.controls = {c.control_id: c for c in seed_controls(
            ["PAN-POL-002", "PAN-POL-005"], control_type=Control.ControlType.SECURITY_RULE)}

    @staticmethod
    def _entry(name, *, source, destination, application, action="allow"):
        return {
            "@name": name,
            "from": {"member": "trust"}, "to": {"member": "untrust"},
            "source": {"member": source}, "destination": {"member": destination},
            "source-user": {"member": "any"}, "application": {"member": application},
            "service": {"member": "application-default"}, "action": action,
        }

    def _normalize(self, *entries, defaults=()):
        """One merged-config snapshot, through address and rule normalization."""
        Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            enforcement_point=self.point, source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {"devices": {"entry": {"vsys": {"entry": {
                "@name": "vsys1",
                "address": {"entry": [
                    {"@name": "net-10", "ip-netmask": "10.0.0.0/8"},
                    {"@name": "net-10-1", "ip-netmask": "10.1.0.0/16"},
                    # Narrow enough that PAN-POL-002 says nothing about it: its floor is 8,192
                    # addresses, and a /16 is 65,536 - so net-10-1 is NOT the object to reach
                    # for when a test needs a rule 002 ignores.
                    {"@name": "host-10-1-1-1", "ip-netmask": "10.1.1.1/32"},
                    # An object that covers the whole address space without saying `any`.
                    {"@name": "everything", "ip-netmask": "0.0.0.0/0"},
                ]},
                "rulebase": {"security": {"rules": {"entry": list(entries)}}},
            }}}}}})
        # Panorama-managed points require BOTH pushed reads to exist before normalization will
        # run: the group-wide shared policy and the per-vsys one. Empty, but present.
        Snapshot.objects.create(
            management_station=self.station, appliance_group=self.group,
            source_type="show_pushed_shared_policy", collected_at=timezone.now(),
            payload={"policy": {"panorama": {
                "pre-rulebase": {"security": {"rules": {"entry": []}}},
                "post-rulebase": {"security": {"rules": {"entry": []}}},
            }}})
        Snapshot.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_type="show_pushed_shared_policy_vsys", collected_at=timezone.now(),
            payload={"policy": {"panorama": {
                "pre-rulebase": {"security": {"rules": {"entry": []}}},
                "post-rulebase": {
                    "security": {"rules": {"entry": []}},
                    "default-security-rules": {"rules": {"entry": []}},
                },
            }}})
        normalize_enforcement_point_addresses(self.point)
        normalize_enforcement_point_security_rules(self.point)
        for name in defaults:
            SecurityRule.objects.filter(name=name).update(
                config_source=SecurityRule.SOURCE_DEFAULT)

    def _fired(self, control_id):
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_rule_findings(run)
        return {f.security_rule.name for f in
                RuleFinding.objects.select_related("security_rule", "control")
                .filter(control__control_id=control_id)}

    def _severity(self, control_id, rule_name):
        """The severity already generated by the last `_fired` call, not a second run."""
        return RuleFinding.objects.get(
            control__control_id=control_id, security_rule__name=rule_name).severity

    def test_one_unbounded_side_now_reports_where_001_said_nothing(self):
        """The substantive change from the drop. 001 fired only when BOTH sides were the whole
        space; 002's bands are per side with `or`, so a rule unbounded on ONE end is critical.
        Nothing new started reporting on 2026-10-06 - 002 was already live and already saying
        this - but the assertion the estate is measured against is now the broader one."""
        self._normalize(
            self._entry("dst-only", source="net-10", destination="any", application="ssl"),
            self._entry("src-only", source="any", destination="net-10-1", application="ssl"),
            self._entry("app-only", source="net-10", destination="net-10-1", application="any"))

        fired = self._fired("PAN-POL-002")

        self.assertEqual(fired, {"dst-only", "src-only", "app-only"})
        # `app-only` is in there on its ADDRESSES, not its application: net-10 is a /8, which is
        # 16,777,216 addresses and lands in 002's high band. The application axis is 005's.
        self.assertEqual(self._severity("PAN-POL-002", "app-only"), Control.Severity.HIGH)
        self.assertEqual(self._severity("PAN-POL-002", "dst-only"), Control.Severity.CRITICAL)

    def test_both_sides_any_still_reports_critical(self):
        """001's own case, which is why the drop was accepted."""
        self._normalize(
            self._entry("src-and-dst", source="any", destination="any", application="ssl"))

        self.assertEqual(self._fired("PAN-POL-002"), {"src-and-dst"})
        self.assertEqual(
            self._severity("PAN-POL-002", "src-and-dst"), Control.Severity.CRITICAL)

    def test_an_address_object_covering_everything_still_counts(self):
        """001 read addresses SEMANTICALLY, so a rule whose source is 0.0.0.0/0 counted as
        `any` even though no member says so. That was the subtlest thing it did, and losing it
        in the drop would have been a silent regression. 002 gets there differently - the
        normalizer resolves the object to 4,294,967,296 addresses - and arrives at critical."""
        self._normalize(
            self._entry("all-of-v4", source="everything", destination="net-10-1",
                        application="ssl"))

        self.assertEqual(self._fired("PAN-POL-002"), {"all-of-v4"})
        self.assertEqual(self._severity("PAN-POL-002", "all-of-v4"), Control.Severity.CRITICAL)

    def test_a_deny_rule_is_not_a_trust_grant(self):
        self._normalize(
            self._entry("deny-any-any", source="any", destination="any", application="any",
                        action="deny"))

        self.assertEqual(self._fired("PAN-POL-002"), set())

    def test_the_predefined_defaults_are_excluded(self):
        self._normalize(
            self._entry("intrazone-default", source="any", destination="any", application="any"),
            defaults=("intrazone-default",))

        self.assertEqual(self._fired("PAN-POL-002"), set())

    def test_a_disabled_any_any_rule_is_reported_by_NOTHING(self):
        """The one case the drop gave up, recorded here so it is a decision rather than a
        surprise. 001 reported this rule - wrongly, at critical, since a disabled rule permits
        nothing - and 002 excludes disabled rules for exactly that reason. Its real home is
        PAN-POL-014, "Disabled Rules Removed After Grace Period", which is not built.

        When 014 ships, this test should assert it fires rather than asserting silence.
        """
        self._normalize(
            self._entry("disabled-any-any", source="any", destination="any", application="ssl"))
        SecurityRule.objects.filter(name="disabled-any-any").update(disabled=True)

        self.assertEqual(self._fired("PAN-POL-002"), set())
        self.assertEqual(
            RuleFinding.objects.filter(security_rule__name="disabled-any-any").count(), 0)

    def test_port_only_rules_fire_on_their_own(self):
        """PAN-POL-005 asserts something different about the same rule: that it identifies
        nothing. A narrow rule with `application any` fires there and not on 002."""
        self._normalize(
            self._entry("narrow-but-port-only", source="host-10-1-1-1",
                        destination="host-10-1-1-1", application="any"))

        self.assertEqual(self._fired("PAN-POL-005"), {"narrow-but-port-only"})
        self.assertEqual(self._fired("PAN-POL-002"), set())

    def test_a_rule_that_is_both_fires_both(self):
        """Two different statements about one rule: unbounded addresses AND identifying
        nothing. Fixing the application clears 005 and leaves 002 standing - which is what
        PAN-POL-005's description now says, having said PAN-POL-001 until the drop."""
        self._normalize(
            self._entry("wide-and-port-only", source="any", destination="any",
                        application="any"))

        self.assertEqual(self._fired("PAN-POL-005"), {"wide-and-port-only"})
        self.assertEqual(self._fired("PAN-POL-002"), {"wide-and-port-only"})

    def test_pan_pol_001_is_gone_from_the_catalog(self):
        """A drop is only done when the control is absent from the seed, which is what
        PAN-MGT-005's entry means by `implemented`. Asserted here rather than trusted, because
        a control left seeded but unreferenced would keep reporting."""
        from assessments.controls_catalog.registry import load_seed_payload

        seeded = {c["control_id"] for cat in load_seed_payload()["catalogs"]
                  for c in cat["controls"]}

        self.assertNotIn("PAN-POL-001", seeded)
        self.assertIn("PAN-POL-002", seeded)
