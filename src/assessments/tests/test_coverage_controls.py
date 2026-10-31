"""PAN-COV-001 and PAN-COV-002 — what the assessment could not establish.

The case these tests exist for is the one that is easy to get wrong: an object with no size
looks identical whether NOBODY ASKED, the DEVICE ANSWERED AND FAILED, or the firewall answered
with a PLACEHOLDER that is a syntactically valid address. All three leave a breadth score
something it will believe, and only `content_was_fetched` tells them apart.

WHAT CHANGED ON 2026-10-31, because two of these tests used to assert the opposite.

The shipped baseline rested on `size_known`, `collection_attempted` and
`resolved_content_truncated`, and all three are satisfied by a list the firewall has never read
a byte of: it answers `total-valid 1` with the single member `0.0.0.0/32`, so the recorded total
becomes 1, `num_hosts` becomes 1, and 1 < 1 is false. Three of the five shipped clauses failed
on exactly the estate the control exists to find, and the row was reported by nothing while a
rule naming that list scored its side as ONE HOST - the narrowest value there is. Measured on
pan-fw-111, 2026-10-26 and again 2026-10-29.

The second change is a decision rather than a measurement. A fetch the device ATTEMPTED AND
FAILED used to be held out of this control on the ground that it is the customer's fault and
reports as PAN-POL-023. PAN-POL-023 is an allocated name with no description, no severity and
no generator, so that state reported NOWHERE - a silence that reads as "collected and fine".
The standing decision is to report the worst case and let the engineer reduce it, so it reports
here, and the remediation says which case a reader is looking at.
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

    def _edl(self, name, *, num_hosts=None, truncated=False, source_total=None,
             member_count=None, fetched=False, band=None):
        """One EDL row.

        `band` defaults to whatever the IFF constraint allows for `fetched`, so a caller that
        cares only about the fetch verdict does not have to restate the band - and a caller
        passing an inconsistent pair is refused by the database rather than silently stored,
        which is what `integrations_shortfall_band_matches_content_was_fetched` is for.
        """
        if band is None:
            band = (AddressObject.BAND_EQUAL if fetched
                    else AddressObject.BAND_CONTENT_NOT_FETCHED)
        return AddressObject.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            name=name, namespace_type="local_vsys", namespace_value="vsys1",
            precedence_rank=10, address_type=AddressObject.TYPE_EDL, is_edl=True,
            edl_list_type="ip", value="ip", normalized_value="ip",
            num_hosts=num_hosts, resolved_content_truncated=truncated,
            resolved_content_source_total=source_total,
            resolved_member_count=member_count,
            content_was_fetched=fetched, content_shortfall_band=band,
        )

    def _fqdn(self, name, *, resolution_was_read=False, num_hosts=None):
        return AddressObject.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            name=name, namespace_type="local_vsys", namespace_value="vsys1",
            precedence_rank=10, address_type=AddressObject.TYPE_FQDN,
            value=f"{name}.invalid", normalized_value=f"{name}.invalid",
            num_hosts=num_hosts, resolution_was_read=resolution_was_read,
        )

    def _netmask(self, name):
        return AddressObject.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            name=name, namespace_type="local_vsys", namespace_value="vsys1",
            precedence_rank=10, address_type=AddressObject.TYPE_IP_NETMASK,
            value="198.51.100.7/32", normalized_value="198.51.100.7/32", num_hosts=1)

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

    # ------------------------------------------------------------------ PAN-COV-001, EDL half

    def test_an_uncollected_referenced_edl_reports(self):
        self._reference(self._edl("never-collected"))

        findings = self._findings()

        self.assertIn(("PAN-COV-001", "never-collected"), findings)
        self.assertEqual(findings[("PAN-COV-001", "never-collected")].severity, "medium")

    def test_the_never_fetched_placeholder_still_reports(self):
        """THE MEASURED TRAP, and the reason the baseline moved off `size_known`. A list the
        firewall has never fetched answers one valid member - 0.0.0.0/32 - so the device gives
        a non-zero total and the collection stores a size of one host. `size_known` and
        `collection_attempted` are both TRUE here. The row must still report, because what the
        rule naming it admits is entirely unknown."""
        obj = self._edl("placeholder-only", num_hosts=1, source_total=1, member_count=1,
                        fetched=False)
        self._reference(obj)

        self.assertTrue(obj.size_known)
        self.assertTrue(obj.collection_attempted)

        findings = self._findings()

        self.assertIn(("PAN-COV-001", "placeholder-only"), findings)

    def test_an_edl_nothing_references_does_not_report(self):
        """Collection follows normalized rule refs, so an unreferenced list is EXPECTED to be
        unsized. Reporting it would make a full address book look like a broken assessment."""
        self._edl("unused-and-unsized")

        self.assertEqual(self._findings(), {})

    def test_an_edl_the_DEVICE_failed_to_resolve_reports_here_too(self):
        """`prod_west_edl` on the lab answers total-valid 0 / total-invalid 1 with a cURL
        error: the device was asked, it tried, and it failed. That is a defect in the
        customer's configuration - the rule enforces against an empty list - and it is
        PAN-POL-023's subject. PAN-POL-023 has no generator, so holding this row out of this
        control reported it nowhere at all. The worst case is reported and the engineer reduces
        it; the remediation names the device as the fault for a row that survives a refresh."""
        self._reference(self._edl("device-could-not-fetch", source_total=0, member_count=0))

        findings = self._findings()

        self.assertIn(("PAN-COV-001", "device-could-not-fetch"), findings)
        self.assertEqual(findings[("PAN-COV-001", "device-could-not-fetch")].severity, "medium")

    def test_a_fully_collected_edl_reports_nothing(self):
        self._reference(self._edl("all-good", num_hosts=2776, source_total=2776,
                                  member_count=2776, fetched=True))

        self.assertEqual(self._findings(), {})

    # ---------------------------------------------------------- PAN-COV-001, name-based half

    def test_a_referenced_fqdn_object_with_no_resolution_read_reports(self):
        """THE HALF THAT WAS REPORTED BY NOTHING. The shipped baseline claused on
        `is_edl eq true`, so every FQDN object was excluded outright - measured at stage 0: an
        FQDN referenced by policy whose content was never collected matched four of the five
        clauses and did not fire."""
        self._reference(self._fqdn("unresolved"))

        findings = self._findings()

        self.assertIn(("PAN-COV-001", "unresolved"), findings)
        self.assertEqual(findings[("PAN-COV-001", "unresolved")].severity, "medium")

    def test_an_fqdn_object_whose_resolution_was_read_reports_nothing(self):
        self._reference(self._fqdn("resolved", resolution_was_read=True, num_hosts=2))

        self.assertEqual(self._findings(), {})

    def test_an_fqdn_object_nothing_references_does_not_report(self):
        self._fqdn("unreferenced-name")

        self.assertEqual(self._findings(), {})

    def test_resolution_read_with_no_v4_answer_is_not_a_coverage_gap(self):
        """The distinction `resolution_was_read` exists for and `size_known` cannot make. A
        stanza answering only AAAA, or carrying the `::  unknown` sentinel, resolves to no IPv4
        interval and leaves `num_hosts` NULL - and it is still a stanza, so the table WAS read.
        A correctly configured IPv6-only name must not be reported as an assessment gap."""
        self._reference(self._fqdn("v6-only", resolution_was_read=True, num_hosts=None))

        self.assertEqual(self._findings(), {})

    def test_neither_half_reports_an_address_object_of_another_kind(self):
        """The kind clause is the only thing holding this control off the address book. Without
        it the name-based half would fire on every ip-netmask object in the vsys - fifty of them
        on the lab appliance - because none of them carries a resolution either."""
        self._reference(self._netmask("a-host"))

        self.assertEqual(self._findings(), {})

    # -------------------------------------------------------------------------- PAN-COV-002

    def test_a_truncated_edl_reports_with_both_numbers(self):
        self._reference(self._edl("too-big", num_hosts=500, truncated=True, source_total=4000,
                                  member_count=500, fetched=True,
                                  band=AddressObject.BAND_TWO_TO_TEN_TIMES))

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
        reconsider the ceiling. The partition is explicit in the queries rather than a property
        a reader has to work out: PAN-COV-001 asserts `content_was_fetched eq false` and
        PAN-COV-002 carries `content_was_fetched eq true` as applicability."""
        self._reference(self._edl("too-big", num_hosts=500, truncated=True, source_total=4000,
                                  member_count=500, fetched=True,
                                  band=AddressObject.BAND_TWO_TO_TEN_TIMES))

        findings = self._findings()

        self.assertNotIn(("PAN-COV-001", "too-big"), findings)
        self.assertEqual(len(findings), 1)

    def test_a_list_nobody_fetched_is_not_graded_as_part_kept(self):
        """The band's own default is `content_not_fetched`, and the applicability clause is what
        keeps it out of the grading. Without it, the never-fetched reply's ratio of exactly 1.0
        would land on `equal` and report the most incomplete object on the device as the most
        compliant."""
        obj = self._edl("placeholder-only", num_hosts=1, source_total=1, member_count=1,
                        fetched=False)
        self._reference(obj)

        findings = self._findings()

        self.assertNotIn(("PAN-COV-002", "placeholder-only"), findings)
        self.assertIn(("PAN-COV-001", "placeholder-only"), findings)

    def test_a_small_shortfall_is_reported_below_the_control_default(self):
        """The calibration the grading asks for. A kept part that already fixes the order of
        magnitude is worth recording and not worth alarming anyone, so it reports at low rather
        than at the control's medium."""
        self._reference(self._edl("slightly-short", num_hosts=600, truncated=True,
                                  source_total=900, member_count=600, fetched=True,
                                  band=AddressObject.BAND_UP_TO_TWO_TIMES))

        finding = self._findings()[("PAN-COV-002", "slightly-short")]

        self.assertEqual(finding.severity, "low")

    def test_a_large_shortfall_is_reported_above_the_control_default(self):
        self._reference(self._edl("mostly-missing", num_hosts=100, truncated=True,
                                  source_total=50000, member_count=100, fetched=True,
                                  band=AddressObject.BAND_MORE_THAN_TEN_TIMES))

        finding = self._findings()[("PAN-COV-002", "mostly-missing")]

        self.assertEqual(finding.severity, "high")

    def test_a_middling_shortfall_keeps_the_control_default(self):
        """The placement at the baseline's own tier, which gets no query of its own. It is safe
        only because the lower-severity query is an EQUALITY on a closed set of bands and so
        cannot also match this row - `derive_control_query_severity_value` discards the baseline
        tier the moment any calibration query matches, so a threshold operator here would
        report this row at low."""
        self._reference(self._edl("middling", num_hosts=400, truncated=True, source_total=2000,
                                  member_count=400, fetched=True,
                                  band=AddressObject.BAND_TWO_TO_TEN_TIMES))

        finding = self._findings()[("PAN-COV-002", "middling")]

        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.matched_query_names, ["Baseline"])
