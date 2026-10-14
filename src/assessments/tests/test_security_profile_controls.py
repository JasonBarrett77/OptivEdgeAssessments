"""The nine anti-spyware and vulnerability-protection controls, which report PER RULE.

Jason, 2026-10-12: "convert the whole domain now." Until then all nine were profile-based -
one finding per SecurityProfile - and PAN-AVW-003 was the only control in these domains that
named a rule. The reason it did is the reason they all do now: a profile nothing uses endangers
nothing, and a rule is what carries traffic.

So this file is in two halves, and the split is the design:

**The rule half** is the controls. One verdict row per rule per assertion, resolved in
normalization from the profile in force on that rule after its profile group is resolved. These
tests pin what the conversion changed and would be easy to get wrong:

- one profile behind two rules is TWO findings, because it is two pieces of traffic;
- a profile NO rule uses is no finding at all, where the profile-based version reported it;
- a rule with no profile of that kind fires EVERY control - reversed 2026-10-12, see
  `test_a_rule_with_no_profile_fires_EVERY_control`;
- only ALLOW rules that are not the predefined defaults are subjects - a rule that blocks
  passes nothing to inspect - while a DISABLED allow rule still is (Jason, 2026-10-14);
- the finding has to name the PROFILE, because that is the thing to go and fix, and a rule
  finding naming only the rule would send a reader somewhere with nothing to change.

**The profile half** is the search fields over SecurityProfile. No control reads them any more,
and they are not dead: they are what the anti-spyware and vulnerability-protection
configuration pages filter on, so an engineer can still ask which profiles look a certain way.
They keep their tests for that reason.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments import configuration_navigation as config_nav
from assessments.findings import generate_rule_findings
from assessments.models import AssessmentRun, Control, RuleFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    PolicyObjectNamespace,
    SecurityProfile,
    SecurityProfileCategoryVerdict,
    SecurityProfileDnsSignatureSource,
    SecurityProfileSeverityVerdict,
    SecurityRule,
    SecurityRuleProfileVerdict,
    Snapshot,
)

SPY = SecurityProfile.KIND_SPYWARE
VLN = SecurityProfile.KIND_VULNERABILITY

V = SecurityRuleProfileVerdict
THREAT_CONTROLS = ["PAN-SPY-001", "PAN-SPY-002", "PAN-SPY-003", "PAN-SPY-004", "PAN-SPY-005",
                   "PAN-VLN-001", "PAN-VLN-002", "PAN-VLN-003", "PAN-VLN-004"]


class _LabFixture(TestCase):
    """A station, a group, an appliance, an enforcement point and a snapshot."""

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.sp")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-sp",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-SP", hostname="fw-sp")
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group,
            vsys_name="vsys1", vsys_display_name="vsys1")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            enforcement_point=self.point, source_type="show_merged_config",
            collected_at=timezone.now(), payload={})
        self.order = 0

    def _profile(self, name, kind=SPY, critical=True, high=True, medium=True,
                 predefined=False, used=False):
        """A profile with its severity verdicts. Owned by the group whatever the namespace."""
        profile = SecurityProfile.objects.create(
            management_station=self.station, appliance_group=self.group,
            source_snapshot=self.snapshot, config_source="local", name=name,
            namespace_type=(PolicyObjectNamespace.PREDEFINED if predefined
                            else PolicyObjectNamespace.LOCAL_VSYS),
            namespace_value="vsys1", precedence_rank=1, kind=kind,
            is_predefined=predefined, is_used=used,
            referrer_count=1 if used else 0)
        for severity, blocked, detail in (
                ("critical", critical, "reset-both" if critical else "alert by rule a"),
                ("high", high, "reset-both" if high else "alert by rule alert-high"),
                ("medium", medium, "reset-both" if medium else "no catch-all rule")):
            SecurityProfileSeverityVerdict.objects.create(
                security_profile=profile, severity=severity, blocked=blocked, detail=detail)
        return profile

    def _bare_rule(self, name, *, action="allow", disabled=False,
                   config_source=SecurityRule.SOURCE_LOCAL):
        self.order += 1
        return SecurityRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=config_source,
            effective_order=self.order, rule_position=self.order, name=name, action=action,
            rule_type="universal", disabled=disabled)


# ---------------------------------------------------------------------------- the rule half


class ThreatProfileRuleControlTests(_LabFixture):
    """The nine controls, each asserting something about the profile in force on a rule."""

    def setUp(self):
        super().setUp()
        seed_controls(THREAT_CONTROLS, control_type=Control.ControlType.SECURITY_RULE)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _rule(self, name, verdicts, **kwargs):
        """A rule plus one verdict row per assertion.

        `verdicts` maps an assertion to (satisfied, detail, profile_name). Any assertion left
        out gets a SATISFIED row, so a test is about the one assertion it names.

        It defaulted to NULL until 2026-10-12, when absence became a finding - after which
        every test here fired all eleven controls and none was about what it said.
        `_rule_with_no_profiles` is the NULL case, which now has to be asked for explicitly.
        """
        rule = self._bare_rule(name, **kwargs)
        for assertion in dict(V.ASSERTION_CHOICES):
            satisfied, detail, profile_name = verdicts.get(
                assertion, (True, "", "a-satisfying-profile"))
            SecurityRuleProfileVerdict.objects.create(
                security_rule=rule, assertion=assertion, profile_name=profile_name,
                satisfied=satisfied, detail=detail)
        return rule

    def _rule_with_no_profiles(self, name, **kwargs):
        """A rule carrying NO profile of any kind - every verdict NULL.

        What most rules on a real estate look like, and what all eleven controls now report.
        """
        rule = self._bare_rule(name, **kwargs)
        for assertion, _label in V.ASSERTION_CHOICES:
            kind = ("antivirus" if assertion in V.ANTIVIRUS_ASSERTIONS else
                    "spyware" if assertion in V.SPYWARE_ASSERTIONS else "vulnerability")
            SecurityRuleProfileVerdict.objects.create(
                security_rule=rule, assertion=assertion, profile_name="",
                satisfied=None, detail=f"no {kind} profile is in force on this rule")
        return rule

    def _fired(self):
        generate_rule_findings(self.run)
        return sorted((f.control.control_id, f.security_rule.name)
                      for f in RuleFinding.objects.select_related("control", "security_rule"))

    def test_a_failing_profile_fires_its_own_control_only(self):
        self._rule("weak-spy", {V.SPYWARE_SEVERITIES: (False, "alert by rule a", "spy-weak")})
        self.assertEqual(self._fired(), [("PAN-SPY-001", "weak-spy")])

    def test_a_satisfying_profile_fires_nothing(self):
        self._rule("good-spy", {V.SPYWARE_SEVERITIES: (True, "", "spy-good")})
        self.assertEqual(self._fired(), [])

    def test_a_rule_with_no_profile_fires_EVERY_control(self):
        """REVERSED 2026-10-12. Jason: "The absence of a profile should create the finding for
        that profile. This is a rule across all rule security profiles."

        It fired nothing until then, on the argument that eleven controls reporting every
        unprotected rule would bury PAN-POL-008. That argued volume rather than correctness: a
        rule with no anti-spyware profile is not getting anti-spyware inspection, so the absence
        IS each control's finding. PAN-AVW-003 had it this way from the day it was built.
        """
        self._rule_with_no_profiles("bare")
        self.assertEqual({control_id for control_id, _name in self._fired()},
                         set(THREAT_CONTROLS))

    def test_the_finding_for_an_absent_profile_says_so_rather_than_naming_one(self):
        """"is protected by X" reads wrong when there is no X, and the two cases need different
        fixes - attach a profile, or repair the one that is there."""
        self._rule_with_no_profiles("bare")
        generate_rule_findings(self.run)
        summary = RuleFinding.objects.get(control__control_id="PAN-SPY-002").summary
        self.assertIn("no spyware profile is in force", summary)
        self.assertNotIn("is protected by", summary)
    def test_ONE_profile_behind_TWO_rules_is_TWO_findings(self):
        """The whole point of the conversion: each rule is a distinct piece of traffic."""
        shared = {V.SPYWARE_DNS_SINKHOLE: (False, "action is alert", "spy-shared")}
        self._rule("rule-a", shared)
        self._rule("rule-b", shared)
        self.assertEqual(self._fired(),
                         [("PAN-SPY-002", "rule-a"), ("PAN-SPY-002", "rule-b")])

    def test_a_profile_no_rule_uses_is_NOT_a_finding(self):
        """The other half of the same change. The profile-based version reported it."""
        self._profile("orphan-spy", critical=False)
        self.assertEqual(self._fired(), [])

    def test_the_finding_names_the_profile_and_the_gap(self):
        self._rule("named", {V.SPYWARE_DNS_SINKHOLE: (False, "action is block", "spy-dns")})
        generate_rule_findings(self.run)
        summary = RuleFinding.objects.get(control__control_id="PAN-SPY-002").summary
        self.assertIn("Rule named", summary)
        self.assertIn("spy-dns", summary)
        self.assertIn("action is block", summary)

    def test_a_POL_control_sentence_is_unchanged_by_the_new_clause(self):
        """The subject sentence is shared with twenty-odd PAN-POL controls."""
        seed_controls(["PAN-POL-008"], control_type=Control.ControlType.SECURITY_RULE)
        rule = self._rule("pol-only", {})
        rule.has_spyware_profile = False
        rule.save(update_fields=["has_spyware_profile"])
        generate_rule_findings(self.run)
        summary = RuleFinding.objects.get(control__control_id="PAN-POL-008").summary
        self.assertIn("Rule pol-only", summary)
        self.assertNotIn("is protected by", summary)

    def test_each_assertion_fires_only_its_own_control(self):
        cases = {
            V.SPYWARE_SEVERITIES: "PAN-SPY-001",
            V.SPYWARE_DNS_SINKHOLE: "PAN-SPY-002",
            V.SPYWARE_DNS_CATEGORIES: "PAN-SPY-003",
            V.SPYWARE_INLINE: "PAN-SPY-004",
            V.SPYWARE_EXCEPTIONS: "PAN-SPY-005",
            V.VULNERABILITY_SEVERITIES: "PAN-VLN-001",
            V.VULNERABILITY_BRUTE_FORCE: "PAN-VLN-002",
            V.VULNERABILITY_INLINE: "PAN-VLN-003",
            V.VULNERABILITY_EXCEPTIONS: "PAN-VLN-004",
        }
        for assertion in cases:
            self._rule(f"r-{assertion}", {assertion: (False, "because", "p")})
        fired = self._fired()
        for assertion, control_id in cases.items():
            with self.subTest(assertion=assertion):
                self.assertIn((control_id, f"r-{assertion}"), fired)
                others = {cid for cid, name in fired if name == f"r-{assertion}"}
                self.assertEqual(others, {control_id})

    def test_a_spyware_gap_does_not_fire_a_vulnerability_control(self):
        self._rule("spy-side", {V.SPYWARE_INLINE: (False, "detectors alert", "spy-p")})
        self.assertNotIn("PAN-VLN-003", [cid for cid, _ in self._fired()])

    def test_the_finding_carries_the_control_severity(self):
        self._rule("sev", {V.SPYWARE_DNS_SINKHOLE: (False, "action is alert", "p")})
        generate_rule_findings(self.run)
        self.assertEqual(
            RuleFinding.objects.get(control__control_id="PAN-SPY-002").severity, "high")

    def test_a_disabled_rule_still_reports_and_says_so(self):
        """A disabled rule is one click from live, so the finding is real - and must say it."""
        rule = self._bare_rule("off", disabled=True)
        SecurityRuleProfileVerdict.objects.create(
            security_rule=rule, assertion=V.SPYWARE_DNS_SINKHOLE, profile_name="p",
            satisfied=False, detail="action is alert")
        generate_rule_findings(self.run)
        summary = RuleFinding.objects.get(control__control_id="PAN-SPY-002").summary
        self.assertIn("DISABLED", summary)

    def test_a_rule_that_does_not_allow_is_not_a_subject(self):
        """Added 2026-10-14. The baselines tested only the verdict, so every deny rule on the
        lab - 42 of them - fired all eleven controls for a profile that could inspect nothing.
        Every non-allow action is checked, because PAN-OS has five and `allow` is the one
        that passes traffic."""
        for action in ("deny", "drop", "reset-client", "reset-server", "reset-both"):
            self._rule_with_no_profiles(f"blocks-{action}", action=action)
            self._rule(f"weak-{action}", {V.SPYWARE_SEVERITIES: (False, "alert", "p")},
                       action=action)
        self.assertEqual(self._fired(), [])

    def test_the_predefined_default_rules_are_not_subjects(self):
        """The same exclusion PAN-AVW-003 and PAN-POL-008 make. `intrazone-default` is an
        allow rule, so the action clause alone would not keep it out."""
        self._rule_with_no_profiles("intrazone-default", config_source=SecurityRule.SOURCE_DEFAULT)
        self.assertEqual(self._fired(), [])

    def test_a_disabled_allow_rule_with_no_profile_fires_every_control(self):
        """Scoped like PAN-AVW-003 in all but this, on purpose (Jason, 2026-10-14): a
        disabled rule is one click from live. The scope must not drift into excluding it."""
        self._rule_with_no_profiles("off", disabled=True)
        self.assertEqual({control_id for control_id, _name in self._fired()},
                         set(THREAT_CONTROLS))

    def test_a_pushed_rule_is_a_subject_and_says_which_rulebase(self):
        """The scope PAN-SPY-002 had never fired on while it was profile-based."""
        rule = self._bare_rule("pushed", config_source=SecurityRule.SOURCE_PUSHED_PRE)
        SecurityRuleProfileVerdict.objects.create(
            security_rule=rule, assertion=V.SPYWARE_DNS_SINKHOLE, profile_name="dg-profile",
            satisfied=False, detail="action is alert")
        generate_rule_findings(self.run)
        summary = RuleFinding.objects.get(control__control_id="PAN-SPY-002").summary
        self.assertIn("Panorama pre-rulebase", summary)
        self.assertIn("dg-profile", summary)

    def test_a_rule_failing_two_assertions_gets_two_findings_naming_each_profile(self):
        self._rule("two-gaps", {
            V.SPYWARE_DNS_SINKHOLE: (False, "action is alert", "spy-p"),
            V.VULNERABILITY_BRUTE_FORCE: (False, "reset-both by rule rb", "vln-p")})
        fired = self._fired()
        self.assertIn(("PAN-SPY-002", "two-gaps"), fired)
        self.assertIn(("PAN-VLN-002", "two-gaps"), fired)
        spy = RuleFinding.objects.get(control__control_id="PAN-SPY-002").summary
        vln = RuleFinding.objects.get(control__control_id="PAN-VLN-002").summary
        self.assertIn("spy-p", spy)
        self.assertNotIn("vln-p", spy)
        self.assertIn("vln-p", vln)

    def test_an_unresolvable_profile_name_FIRES(self):
        """A group naming a profile that is not in scope protects nothing, so it reports - the
        same reading as no profile at all, which is what it amounts to. The detail says which,
        because "attach a profile" and "repair the dangling reference" are different jobs."""
        self._rule("dangling", {V.SPYWARE_DNS_SINKHOLE: (
            None, "names spyware profile 'ghost', which resolves to nothing", "ghost")})
        self.assertEqual(self._fired(), [("PAN-SPY-002", "dangling")])
    def _rule_with(self, name, assertion, satisfied):
        rule = self._bare_rule(name)
        SecurityRuleProfileVerdict.objects.create(
            security_rule=rule, assertion=assertion, profile_name="p",
            satisfied=satisfied, detail="" if satisfied else "because")
        return rule

    def test_a_null_verdict_is_on_the_FALSE_side(self):
        """REVERSED 2026-10-12: absence is a finding, so `false` matches NULL as well.

        The two values still must not both match a row - `true` requires a profile that
        satisfies the assertion rather than being the complement of `false`.
        """
        from assessments.search.security_rules.compiler import FIELD_COMPILERS

        fails = self._rule_with("fails", V.SPYWARE_DNS_SINKHOLE, False)
        passes = self._rule_with("passes", V.SPYWARE_DNS_SINKHOLE, True)
        absent = self._rule_with("absent", V.SPYWARE_DNS_SINKHOLE, None)

        compile_field = FIELD_COMPILERS["spyware_dns_sinkholes"]
        false_match = {r["pk"] for r in compile_field(
            {"op": "eq", "value": False, "case_sensitive": False})}
        true_match = {r["pk"] for r in compile_field(
            {"op": "eq", "value": True, "case_sensitive": False})}

        self.assertEqual(false_match, {fails.pk, absent.pk})
        self.assertEqual(true_match, {passes.pk})
        self.assertEqual(false_match & true_match, set())

    def test_the_detail_is_searchable(self):
        from assessments.search.security_rules.compiler import FIELD_COMPILERS

        rule = self._rule_with("detailed", V.VULNERABILITY_BRUTE_FORCE, False)
        matched = {r["pk"] for r in FIELD_COMPILERS["vulnerability_blocks_brute_force_detail"](
            {"op": "contains", "value": "because", "case_sensitive": False})}
        self.assertEqual(matched, {rule.pk})

    def test_the_properties_read_the_satellite(self):
        """The artifact layer resolves a tested field against the model, so these must exist."""
        rule = self._rule_with("props", V.SPYWARE_EXCEPTIONS, False)
        self.assertIs(rule.spyware_exceptions_minimal, False)
        self.assertEqual(rule.spyware_exceptions_minimal_detail, "because")
        self.assertIsNone(rule.spyware_dns_sinkholes)
        self.assertEqual(rule.spyware_dns_sinkholes_detail, "")


# ------------------------------------------------------------------------- the profile half


class SecurityProfilePageTests(_LabFixture):
    def test_each_explorer_page_lists_only_its_own_kind(self):
        self._profile("only-spyware")
        self._profile("only-vulnerability", kind=VLN)
        for slug, shown, hidden in (
                ("anti-spyware", "only-spyware", "only-vulnerability"),
                ("vulnerability-protection", "only-vulnerability", "only-spyware")):
            with self.subTest(slug=slug):
                response = self.client.get(reverse(
                    "assessment_configuration_object",
                    args=[config_nav.category_slug("Objects"), slug]))
                self.assertContains(response, shown)
                self.assertNotContains(response, hidden)


class SecurityProfileSearchFieldTests(_LabFixture):
    """The profile-side search fields.

    No control reads these since the conversion. They are what the two configuration pages
    filter on, so an engineer can ask which profiles look a certain way - which is why they are
    tested rather than deleted.
    """

    def _dns_source(self, profile, action, *, name="default-paloalto-dns", content=True,
                    implicit=False, source_type=None):
        src = SecurityProfileDnsSignatureSource
        return src.objects.create(
            security_profile=profile, name=name, is_paloalto_content=content,
            source_type=source_type or (src.TYPE_PALOALTO_CONTENT if content else src.TYPE_EDL),
            configured_action="" if implicit else action, effective_action=action,
            sinkholes=action == "sinkhole", enforces=action in src.ENFORCING_ACTIONS,
            action_is_implicit=implicit)

    def test_a_profile_with_no_verdicts_matches_neither_severity_value(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        answers = self._profile("answers", critical=False)
        silent = SecurityProfile.objects.create(
            management_station=self.station, appliance_group=self.group,
            source_snapshot=self.snapshot, config_source="local", name="silent",
            namespace_type=PolicyObjectNamespace.LOCAL_SHARED, namespace_value="shared",
            precedence_rank=21, kind=SPY)

        compile_blocked = FIELD_COMPILERS["critical_blocked"]
        false_match = {r["pk"] for r in compile_blocked(
            {"op": "eq", "value": False, "case_sensitive": False})}
        self.assertIn(answers.pk, false_match)
        self.assertNotIn(silent.pk, false_match,
                         "a profile that makes no claim must not read as failing")

    def test_the_severity_detail_is_searchable_through_the_satellite(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        weak = self._profile("weak-detail", critical=False)
        matched = {r["pk"] for r in FIELD_COMPILERS["critical_detail"](
            {"op": "contains", "value": "alert by rule", "case_sensitive": False})}
        self.assertIn(weak.pk, matched)

    def test_the_dns_sinkhole_field_scopes_to_the_paloalto_content_row(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        edl_only = self._profile("edl-only")
        self._dns_source(edl_only, "sinkhole")
        self._dns_source(edl_only, "allow", name="corp-allow", content=False)
        alerting = self._profile("alerting")
        self._dns_source(alerting, "alert")

        false_match = {r["pk"] for r in FIELD_COMPILERS["dns_sinkholes_malicious_queries"](
            {"op": "eq", "value": False, "case_sensitive": False})}
        self.assertIn(alerting.pk, false_match)
        self.assertNotIn(edl_only.pk, false_match,
                         "an EDL allow-list beside a sinkholing content row is not a failure")

    def test_the_implicit_dns_action_is_listable(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        bare = self._profile("bare")
        self._dns_source(bare, "sinkhole", implicit=True)
        explicit = self._profile("explicit")
        self._dns_source(explicit, "sinkhole")

        matched = {r["pk"] for r in FIELD_COMPILERS["dns_sinkhole_action_is_implicit"](
            {"op": "eq", "value": True, "case_sensitive": False})}
        self.assertEqual(matched, {bare.pk})

    def test_the_category_field_needs_every_asserted_category(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        src = SecurityProfileDnsSignatureSource
        mixed = self._profile("mixed")
        for name, action in (("pan-dns-sec-cc", "sinkhole"),
                             ("pan-dns-sec-malware", "default"),
                             ("pan-dns-sec-phishing", "sinkhole")):
            self._dns_source(mixed, action, name=name, content=False,
                             source_type=src.TYPE_DNS_SECURITY)

        true_match = {r["pk"] for r in FIELD_COMPILERS["dns_security_categories_enforced"](
            {"op": "eq", "value": True, "case_sensitive": False})}
        self.assertNotIn(mixed.pk, true_match,
                         "one sinkholing category must not make the profile read as enforced")

    def test_the_brute_force_field_reads_the_category_verdict(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        profile = self._profile("bf", kind=VLN)
        SecurityProfileCategoryVerdict.objects.create(
            security_profile=profile,
            category=SecurityProfileCategoryVerdict.BRUTE_FORCE,
            blocks_source=False, weakest_action="reset-both",
            detail="reset-both by rule rb (critical)")

        false_match = {r["pk"] for r in FIELD_COMPILERS["brute_force_blocked_by_source"](
            {"op": "eq", "value": False, "case_sensitive": False})}
        self.assertEqual(false_match, {profile.pk})
