"""PAN-POL-002 - the address-breadth bands, at their boundaries.

Every threshold in this control is an off-by-one waiting to happen: the queries are `gt`, the
bands are stated in the description as PREFIXES, and a prefix is a count of addresses that is
exactly a power of two. So /8 is 16,777,216 addresses and belongs to HIGH, while critical starts
one address above it - and a `gte` anywhere in the chain, or a band floor written as the prefix
rather than the prefix's size, moves a whole class of rules by one severity without failing any
test that only checks a midpoint. Each band is therefore tested at both of its edges.

The lab could not have found these. Its address objects are 490 /32s and nine `any`, so until
the band subjects were written to pan-fw-111 on 2026-10-05 the only bands with any subject at
all were critical and indeterminate. Boundaries are what tests are for.

The counts are set directly on the rule here. They are COLUMNS, written by normalization from
the merged member intervals of each side, and `test_address_breadth_normalization` in
OptivEdgeIntegrations is what tests the arithmetic that produces them. What is under test here
is the mapping from a count to a severity.
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
    Snapshot,
)

#: Each band's floor is `gt`, so the band's own broadest prefix sits one BELOW the next floor.
ANY = 4_294_967_296
SLASH_8 = 16_777_216
SLASH_11 = 2_097_152
SLASH_12 = 1_048_576
SLASH_14 = 262_144
SLASH_15 = 131_072
SLASH_16 = 65_536
SLASH_18 = 16_384
SLASH_19 = 8_192
SLASH_32 = 1


class AddressBreadthBandTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.pol002")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-pol002",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group,
            vsys_name="vsys1", vsys_display_name="vsys1")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_type="test", collected_at=timezone.now())
        seed_controls(["PAN-POL-002"], control_type=Control.ControlType.SECURITY_RULE)
        self.order = 0

    def _rule(self, name, *, source, destination=SLASH_32, action="allow",
              config_source=SecurityRule.SOURCE_LOCAL, disabled=False):
        self.order += 1
        return SecurityRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=config_source,
            effective_order=self.order, rule_position=self.order, name=name,
            action=action, disabled=disabled, rule_type="universal",
            source_num_hosts=source, destination_num_hosts=destination)

    def _severities(self):
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_rule_findings(run)
        return {finding.security_rule.name: finding.severity for finding in
                RuleFinding.objects.filter(control__control_id="PAN-POL-002")
                .select_related("security_rule")}

    # --- the five bands, each at both edges -------------------------------------------------

    def test_narrower_than_the_baseline_floor_is_silent(self):
        """/19 is the widest side this control says nothing about."""
        self._rule("slash-19", source=SLASH_19)
        self.assertEqual(self._severities(), {})

    def test_informational_runs_from_one_above_the_floor_to_a_slash_17(self):
        self._rule("one-over", source=SLASH_19 + 1)
        self._rule("slash-18", source=SLASH_18)
        self._rule("slash-17", source=SLASH_16 // 2)
        self.assertEqual(self._severities(), {
            "one-over": "informational", "slash-18": "informational",
            "slash-17": "informational"})

    def test_low_starts_one_address_above_a_slash_17(self):
        self._rule("slash-17", source=SLASH_16 // 2)
        self._rule("one-over-17", source=SLASH_16 // 2 + 1)
        self._rule("slash-16", source=SLASH_16)
        self._rule("slash-15", source=SLASH_15)
        self.assertEqual(self._severities(), {
            "slash-17": "informational", "one-over-17": "low",
            "slash-16": "low", "slash-15": "low"})

    def test_medium_starts_one_address_above_a_slash_15(self):
        self._rule("slash-15", source=SLASH_15)
        self._rule("one-over-15", source=SLASH_15 + 1)
        self._rule("slash-14", source=SLASH_14)
        self._rule("slash-12", source=SLASH_12)
        self.assertEqual(self._severities(), {
            "slash-15": "low", "one-over-15": "medium",
            "slash-14": "medium", "slash-12": "medium"})

    def test_high_starts_one_address_above_a_slash_12(self):
        self._rule("slash-12", source=SLASH_12)
        self._rule("one-over-12", source=SLASH_12 + 1)
        self._rule("slash-11", source=SLASH_11)
        self._rule("slash-8", source=SLASH_8)
        self.assertEqual(self._severities(), {
            "slash-12": "medium", "one-over-12": "high",
            "slash-11": "high", "slash-8": "high"})

    def test_critical_starts_one_address_above_a_slash_8(self):
        """The edge the description argues for explicitly: the RFC1918 aggregate is 17,891,328
        addresses, above a /8 and therefore critical, which is the whole reason the conversion
        rounds the prefix UP."""
        self._rule("slash-8", source=SLASH_8)
        self._rule("one-over-8", source=SLASH_8 + 1)
        self._rule("rfc1918-aggregate", source=16_777_216 + 1_048_576 + 65_536)
        self._rule("any", source=ANY)
        self.assertEqual(self._severities(), {
            "slash-8": "high", "one-over-8": "critical",
            "rfc1918-aggregate": "critical", "any": "critical"})

    # --- the side that decides ---------------------------------------------------------------

    def test_the_destination_side_scores_the_same_as_the_source(self):
        self._rule("broad-destination", source=SLASH_32, destination=ANY)
        self.assertEqual(self._severities(), {"broad-destination": "critical"})

    def test_the_broader_side_decides_and_a_narrow_side_does_not_soften_it(self):
        """The bands are per-side with `or`, so one critical side is a critical rule - Jason,
        2026-09-30, asked for exactly this. A rule tight on one end is not a tight rule."""
        self._rule("one-end-tight", source=ANY, destination=SLASH_32)
        self.assertEqual(self._severities(), {"one-end-tight": "critical"})

    # --- indeterminate -----------------------------------------------------------------------

    def test_an_unmeasurable_side_reports_medium_rather_than_nothing(self):
        """NULL is not 0. A dynamic address group, a region, an unresolved EDL - the rule might
        permit everything, and scoring it as the narrowest rule on the device is the one failure
        this control must not have."""
        self._rule("unknown-source", source=None, destination=SLASH_32)
        self.assertEqual(self._severities(), {"unknown-source": "medium"})

    def test_an_unmeasurable_side_does_not_cap_a_measurable_critical_one(self):
        """Worst-wins across queries, so the indeterminate query's medium must not pull a rule
        DOWN from a severity another side already established."""
        self._rule("unknown-and-any", source=None, destination=ANY)
        self.assertEqual(self._severities(), {"unknown-and-any": "critical"})

    def test_both_sides_unmeasurable_reports_once_at_medium(self):
        self._rule("both-unknown", source=None, destination=None)
        severities = self._severities()
        self.assertEqual(severities, {"both-unknown": "medium"})
        self.assertEqual(
            RuleFinding.objects.filter(control__control_id="PAN-POL-002").count(), 1)

    # --- scope -------------------------------------------------------------------------------

    def test_a_deny_rule_is_out_of_scope(self):
        self._rule("deny-any-any", source=ANY, destination=ANY, action="deny")
        self.assertEqual(self._severities(), {})

    def test_a_disabled_rule_is_out_of_scope(self):
        """It permits nothing, so its breadth is not a finding."""
        self._rule("disabled-any", source=ANY, disabled=True)
        self.assertEqual(self._severities(), {})

    def test_the_predefined_default_rules_are_out_of_scope(self):
        """Their match tuple cannot be edited, so there is no remediation to report."""
        self._rule("intrazone-default", source=ANY, destination=ANY,
                   config_source=SecurityRule.SOURCE_DEFAULT)
        self.assertEqual(self._severities(), {})

    def test_a_rule_narrow_on_both_sides_is_silent(self):
        self._rule("host-to-host", source=SLASH_32, destination=SLASH_32)
        self.assertEqual(self._severities(), {})
