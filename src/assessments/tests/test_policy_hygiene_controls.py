"""PAN-POL-014 - disabled rules, graded by what they would permit - and PAN-POL-024 - zones
named on both sides.

Both were built on 2026-10-07 out of PAN-POL-001's drop: 014 is the only home for the disabled
any/any rule that drop gave up, and 024 is the one piece of 001's ground nothing else covered.

**014's severities are PAN-POL-002's, unshifted, and that is a decision rather than a
shortcut.** I proposed landing them two steps lower on the grounds that a disabled rule permits
nothing today. Jason, 2026-10-07: "A highly permissive but disabled rule could be worse then an
operational-permissive rule. The disabled rule could be intentionally dangerous, previously used
for testing purposes." 002 excludes disabled rules because breadth-scoring an INACTIVE rule
measures nothing about current exposure, which is not a claim that such rules are less serious.
The two tests at the bottom hold that: one rule, disabled, reports 014 and not 002 - at the same
severity 002 would have given it.

**014 does not trigger on age.** The corpus states it as "no rule has been disabled longer than
90 days", which needs config-history correlation this assessment does not have. The trigger is
presence; a test asserts a disabled rule fires with no notion of when it was disabled.
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
    SecurityRuleFromZone,
    SecurityRuleToZone,
    Snapshot,
)

ANY = 4_294_967_296
SLASH_8 = 16_777_216
SLASH_11 = 2_097_152
SLASH_12 = 1_048_576
SLASH_14 = 262_144
SLASH_15 = 131_072
SLASH_32 = 1


class PolicyHygieneTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.hygiene")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-hygiene",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group,
            vsys_name="vsys1", vsys_display_name="vsys1")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_type="test", collected_at=timezone.now())
        seed_controls(["PAN-POL-002", "PAN-POL-008", "PAN-POL-014", "PAN-POL-024",
                       "PAN-AVW-003"],
                      control_type=Control.ControlType.SECURITY_RULE)
        self.order = 0

    def _rule(self, name, *, source=SLASH_32, destination=SLASH_32, disabled=False,
              action="allow", config_source=SecurityRule.SOURCE_LOCAL,
              from_zone="trust", to_zone="untrust", rule_type="universal",
              antivirus=True, spyware=True, vulnerability=True,
              wildfire=True, wildfire_detail=""):
        self.order += 1
        rule = SecurityRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=config_source,
            effective_order=self.order, rule_position=self.order, name=name,
            action=action, disabled=disabled, rule_type=rule_type,
            source_num_hosts=source, destination_num_hosts=destination,
            has_antivirus_profile=antivirus, has_spyware_profile=spyware,
            has_vulnerability_profile=vulnerability,
            # THREE STATES. True covers everything; False is a profile that is too narrow;
            # None is no profile reaching the rule at all - which is the common real case and
            # also what an un-renormalized row holds.
            wildfire_analysis_submits_all=wildfire,
            wildfire_analysis_detail=wildfire_detail)
        if from_zone is not None:
            SecurityRuleFromZone.objects.create(
                security_rule=rule, value=from_zone, prov="test", position=1)
        if to_zone is not None:
            SecurityRuleToZone.objects.create(
                security_rule=rule, value=to_zone, prov="test", position=1)
        return rule

    def _severities(self, control_id):
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_rule_findings(run)
        return {f.security_rule.name: f.severity for f in
                RuleFinding.objects.filter(control__control_id=control_id, assessment_run=run)
                .select_related("security_rule")}

    # --- PAN-AVW-003 -------------------------------------------------------------------------

    def test_a_rule_whose_profile_submits_everything_is_silent(self):
        """The predefined `default` WildFire analysis profile is this case - file-type any,
        application any, direction both. The shipped profile PASSES here, which is the reverse
        of PAN-AVW-001 and 002."""
        self._rule("fully-analysed")

        self.assertEqual(self._severities("PAN-AVW-003"), {})

    def test_a_rule_no_profile_reaches_fires(self):
        """NULL, not False. The lab's own case: 113 rules name a profile group called
        `default` that lists no profiles at all, so nothing is sent for analysis while the
        rule looks configured."""
        self._rule("no-profile", wildfire=None,
                   wildfire_detail="no WildFire analysis profile is in force on this rule")

        self.assertEqual(self._severities("PAN-AVW-003"), {"no-profile": "high"})

    def test_a_rule_whose_profile_is_too_narrow_fires(self):
        self._rule("narrow", wildfire=False, wildfire_detail="wf-pe-only: no rule covers every file type")

        self.assertEqual(self._severities("PAN-AVW-003"), {"narrow": "high"})

    def test_an_un_renormalized_row_fires_rather_than_passing(self):
        """A new nullable column on an already-populated model holds NULL until something
        re-normalizes. Null fires, so the window between migrating and re-normalizing
        announces itself instead of reporting a clean estate - which is the failure measured
        on PAN-MCR-001/002/003."""
        self._rule("stale", wildfire=None, wildfire_detail="")

        self.assertEqual(self._severities("PAN-AVW-003"), {"stale": "high"})

    def test_a_disabled_rule_is_out_of_scope(self):
        """Same scope as PAN-POL-008: the question is what inspection is in force on traffic
        the rule permits, and a disabled rule permits none."""
        self._rule("disabled-no-wf", disabled=True, wildfire=None)

        self.assertEqual(self._severities("PAN-AVW-003"), {})

    def test_a_deny_rule_is_out_of_scope(self):
        self._rule("deny-no-wf", action="deny", wildfire=None)

        self.assertEqual(self._severities("PAN-AVW-003"), {})

    def test_the_implicit_defaults_are_out_of_scope(self):
        self._rule("intrazone-default", config_source=SecurityRule.SOURCE_DEFAULT,
                   wildfire=None)

        self.assertEqual(self._severities("PAN-AVW-003"), {})

    # --- PAN-POL-014 -------------------------------------------------------------------------

    def test_a_disabled_rule_fires_at_the_baseline_whatever_its_size(self):
        """The trigger is PRESENCE. No part of this depends on how long it has been disabled,
        which is the corpus assertion we cannot evaluate."""
        self._rule("disabled-narrow", source=SLASH_32, disabled=True)

        self.assertEqual(self._severities("PAN-POL-014"), {"disabled-narrow": "low"})

    def test_the_bands_are_002s_thresholds_and_002s_severities(self):
        self._rule("d-medium", source=SLASH_14, disabled=True)
        self._rule("d-high", source=SLASH_11, disabled=True)
        self._rule("d-critical", source=ANY, disabled=True)

        self.assertEqual(self._severities("PAN-POL-014"), {
            "d-medium": "medium", "d-high": "high", "d-critical": "critical"})

    def test_each_band_edge_lands_the_way_002s_do(self):
        """Every threshold is `gt` against a power of two, so one `gte` moves a class of rules
        by a severity. 002's own boundary tests make the same argument."""
        self._rule("at-15", source=SLASH_15, disabled=True)
        self._rule("over-15", source=SLASH_15 + 1, disabled=True)
        self._rule("at-12", source=SLASH_12, disabled=True)
        self._rule("over-12", source=SLASH_12 + 1, disabled=True)
        self._rule("at-8", source=SLASH_8, disabled=True)
        self._rule("over-8", source=SLASH_8 + 1, disabled=True)

        self.assertEqual(self._severities("PAN-POL-014"), {
            "at-15": "low", "over-15": "medium",
            "at-12": "medium", "over-12": "high",
            "at-8": "high", "over-8": "critical"})

    def test_an_enabled_rule_is_not_014s_business(self):
        self._rule("enabled-any", source=ANY, disabled=False)

        self.assertEqual(self._severities("PAN-POL-014"), {})

    def test_an_indeterminate_side_reports_at_the_baseline_only(self):
        """002 raises an unmeasurable side to medium because it might permit anything. On a
        disabled rule it permits nothing either way, so that argument does not carry over."""
        self._rule("disabled-unknown", source=None, disabled=True)

        self.assertEqual(self._severities("PAN-POL-014"), {"disabled-unknown": "low"})

    def test_a_disabled_deny_rule_is_out_of_scope(self):
        """A disabled DENY is protection that was turned off - a different defect, and one
        nothing covers yet."""
        self._rule("disabled-deny", source=ANY, disabled=True, action="deny")

        self.assertEqual(self._severities("PAN-POL-014"), {})

    def test_the_predefined_defaults_are_out_of_scope(self):
        self._rule("intrazone-default", source=ANY, disabled=True,
                   config_source=SecurityRule.SOURCE_DEFAULT)

        self.assertEqual(self._severities("PAN-POL-014"), {})

    def test_014_and_002_divide_the_rulebase_rather_than_overlapping(self):
        """The whole point of the split. One rule, disabled and wide open: 014 reports it,
        002 does not, and 014 gives it the severity 002 would have."""
        self._rule("wide-and-disabled", source=ANY, destination=ANY, disabled=True)

        self.assertEqual(self._severities("PAN-POL-014"), {"wide-and-disabled": "critical"})
        self.assertEqual(self._severities("PAN-POL-002"), {})

    # --- PAN-POL-024 -------------------------------------------------------------------------

    def test_one_any_zone_side_is_medium(self):
        self._rule("src-zone-any", from_zone="any", to_zone="untrust")
        self._rule("dst-zone-any", from_zone="trust", to_zone="any")

        self.assertEqual(self._severities("PAN-POL-024"),
                         {"src-zone-any": "medium", "dst-zone-any": "medium"})

    def test_both_any_zone_sides_is_high(self):
        self._rule("both-zones-any", from_zone="any", to_zone="any")

        self.assertEqual(self._severities("PAN-POL-024"), {"both-zones-any": "high"})

    def test_both_zones_named_is_silent(self):
        self._rule("fully-named", from_zone="trust", to_zone="untrust")

        self.assertEqual(self._severities("PAN-POL-024"), {})

    def test_a_deny_rule_is_out_of_scope(self):
        self._rule("deny-any-zones", from_zone="any", to_zone="any", action="deny")

        self.assertEqual(self._severities("PAN-POL-024"), {})

    def test_a_disabled_rule_is_014s_business_not_024s(self):
        """Excluded so one rule does not report twice for two readings of the same slackness.
        A disabled rule's zones are part of what 014 already reports on."""
        self._rule("disabled-any-zones", from_zone="any", to_zone="any", disabled=True)

        self.assertEqual(self._severities("PAN-POL-024"), {})
        self.assertEqual(self._severities("PAN-POL-014"), {"disabled-any-zones": "low"})

    def test_the_predefined_defaults_are_out_of_scope(self):
        """They carry no zone elements at all, and their match tuple cannot be edited."""
        self._rule("interzone-default", from_zone=None, to_zone=None,
                   config_source=SecurityRule.SOURCE_DEFAULT)

        self.assertEqual(self._severities("PAN-POL-024"), {})

    def test_an_intrazone_rule_is_in_scope_and_can_satisfy_the_control(self):
        """Measured, not assumed. PAN-OS refuses an intrazone rule whose source and destination
        zones DIFFER - code=12, "Intrazone rule has different set of source and destination
        zones", pan-fw-111 2026-10-07 - so naming the same zone twice is the only shape such a
        rule takes, and it satisfies this control rather than being impossible for it.
        """
        self._rule("intrazone-named", rule_type="intrazone",
                   from_zone="trust", to_zone="trust")
        self._rule("intrazone-any", rule_type="intrazone", from_zone="any", to_zone="any")

        self.assertEqual(self._severities("PAN-POL-024"), {"intrazone-any": "high"})

    # --- PAN-POL-008 ---------------------------------------------------------------------------

    def test_a_rule_with_all_three_profiles_is_silent(self):
        self._rule("protected")

        self.assertEqual(self._severities("PAN-POL-008"), {})

    def test_a_rule_missing_one_profile_reports_high(self):
        self._rule("no-av", antivirus=False)
        self._rule("no-as", spyware=False)
        self._rule("no-vp", vulnerability=False)

        self.assertEqual(self._severities("PAN-POL-008"),
                         {"no-av": "high", "no-as": "high", "no-vp": "high"})

    def test_a_rule_with_no_inspection_at_all_is_critical(self):
        """The lab's own case: 113 rules name a profile group that names nothing, so all three
        columns are False and the rule passes traffic uninspected."""
        self._rule("uninspected", antivirus=False, spyware=False, vulnerability=False)

        self.assertEqual(self._severities("PAN-POL-008"), {"uninspected": "critical"})

    def test_a_deny_rule_needs_no_profiles(self):
        self._rule("deny-bare", action="deny",
                   antivirus=False, spyware=False, vulnerability=False)

        self.assertEqual(self._severities("PAN-POL-008"), {})

    def test_a_disabled_rule_is_out_of_scope(self):
        """It inspects nothing because it permits nothing. PAN-POL-014 is where it reports."""
        self._rule("disabled-bare", disabled=True,
                   antivirus=False, spyware=False, vulnerability=False)

        self.assertEqual(self._severities("PAN-POL-008"), {})
        self.assertEqual(self._severities("PAN-POL-014"), {"disabled-bare": "low"})

    def test_the_predefined_defaults_are_out_of_scope(self):
        self._rule("intrazone-default", config_source=SecurityRule.SOURCE_DEFAULT,
                   antivirus=False, spyware=False, vulnerability=False)

        self.assertEqual(self._severities("PAN-POL-008"), {})
