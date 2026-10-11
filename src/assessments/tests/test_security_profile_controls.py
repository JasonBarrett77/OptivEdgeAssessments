"""PAN-SPY-001 and PAN-VLN-001 - anti-spyware and vulnerability profiles that do not block critical
and high severity threats.

The verdict itself is computed in normalization and tested there (OEI tests_security_profiles).
What these pin is the SCOPING the seed queries apply on top of it, which is where a control like
this goes wrong quietly:

- a custom profile is a subject whether or not anything uses it;
- a predefined profile is a subject ONLY when a rule or profile group uses it (Jason,
  2026-09-11) - an unused `default` is on every vsys and protects nothing;
- medium is the corpus PREFERRED value, so a medium-only gap fires nothing;
- the two controls share a model and must not fire on each other's kind.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments import configuration_navigation as config_nav
from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import AssessmentRun, Control, ControlQuery, SecurityProfileFinding
from assessments.security_profile_findings import generate_security_profile_findings
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, ManagementStation, PolicyObjectNamespace, SecurityProfile, SecurityProfileCategoryVerdict,
    SecurityProfileDnsSignatureSource,
    SecurityProfileSeverityVerdict, Snapshot)

SPY = SecurityProfile.KIND_SPYWARE
VLN = SecurityProfile.KIND_VULNERABILITY


class SecurityProfileControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.sp")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-sp", group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-SP", hostname="fw-sp")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        specs = {c["control_id"]: c for c in load_seed_payload()["catalogs"][0]["controls"]}
        for control_id in ("PAN-SPY-001", "PAN-VLN-001"):
            spec = specs[control_id]
            control = Control.objects.create(
                control_id=control_id, name=spec["name"],
                control_type=Control.ControlType.SECURITY_PROFILE,
                description=spec["description"], default_severity=spec["default_severity"],
                target_model=spec["target_model"])
            for query in spec["queries"]:
                ControlQuery.objects.create(
                    control=control, name=query["name"], canonical_query=query["canonical_query"],
                    is_baseline=query["is_baseline"], is_active=query["is_active"])
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _profile(self, name, kind=SPY, critical=True, high=True, medium=True, predefined=False, used=False):
        # Owned by the group here whatever the namespace: these tests are about the QUERY, and the
        # owner rules are ScopedPolicyObject.clean()'s business, pinned in OEI.
        namespace = PolicyObjectNamespace.PREDEFINED if predefined else PolicyObjectNamespace.LOCAL_SHARED
        profile = SecurityProfile.objects.create(
            management_station=self.station, appliance_group=self.group, source_snapshot=self.snapshot,
            config_source="local", name=name, namespace_type=namespace,
            namespace_value="predefined" if predefined else "shared", precedence_rank=20, kind=kind,
            is_predefined=predefined, is_used=used, referrer_count=1 if used else 0,
            referrers=["vsys1 profile-group/g"] if used else [])
        # The verdicts are rows now, one per severity the profile answers for. A kind with no
        # severity rules - antivirus - writes none, and then matches neither true nor false.
        for severity, blocked, detail in (
                ("critical", critical, "reset-both" if critical else "alert by rule a"),
                ("high", high, "reset-both" if high else "alert by rule alert-high"),
                ("medium", medium, "reset-both" if medium else "no catch-all rule")):
            SecurityProfileSeverityVerdict.objects.create(
                security_profile=profile, severity=severity, blocked=blocked, detail=detail)
        return profile

    def _fired(self):
        generate_security_profile_findings(self.run)
        return sorted((f.control.control_id, f.security_profile.name)
                      for f in SecurityProfileFinding.objects.select_related("control", "security_profile"))

    def test_a_custom_profile_failing_high_fires_its_own_control_only(self):
        self._profile("weak-spy", high=False)
        self._profile("weak-vln", kind=VLN, critical=False)
        self.assertEqual(self._fired(), [("PAN-SPY-001", "weak-spy"), ("PAN-VLN-001", "weak-vln")])

    def test_an_unused_custom_profile_is_still_a_subject(self):
        self._profile("unused-weak", critical=False, used=False)
        self.assertEqual(self._fired(), [("PAN-SPY-001", "unused-weak")])

    def test_a_blocking_profile_does_not_fire(self):
        self._profile("strong")
        self.assertEqual(self._fired(), [])

    def test_a_medium_only_gap_fires_nothing(self):
        self._profile("medium-gap", medium=False)
        self.assertEqual(self._fired(), [])

    def test_an_unused_predefined_profile_is_not_a_subject(self):
        self._profile("default", critical=False, high=False, predefined=True, used=False)
        self.assertEqual(self._fired(), [])

    def test_a_used_predefined_profile_fires_and_says_it_is_predefined_and_used(self):
        self._profile("default", kind=VLN, critical=False, high=False, predefined=True, used=True)
        self.assertEqual(self._fired(), [("PAN-VLN-001", "default")])
        summary = SecurityProfileFinding.objects.get().summary
        self.assertIn("predefined Vulnerability Protection profile default", summary)
        self.assertIn("used by 1 rule or profile group", summary)
        self.assertIn("high: alert by rule alert-high", summary)


class SecurityProfilePageTests(TestCase):
    def setUp(self):
        SecurityProfileControlTests.setUp(self)

    _profile = SecurityProfileControlTests._profile

    def test_each_explorer_page_lists_only_its_own_kind(self):
        self._profile("only-spyware")
        self._profile("only-vulnerability", kind=VLN)
        for slug, shown, hidden in (("anti-spyware", "only-spyware", "only-vulnerability"),
                                    ("vulnerability-protection", "only-vulnerability", "only-spyware")):
            with self.subTest(slug=slug):
                response = self.client.get(reverse(
                    "assessment_configuration_object", args=[config_nav.category_slug("Objects"), slug]))
                self.assertContains(response, shown)
                self.assertNotContains(response, hidden)


class VerdictSatelliteSearchTests(SecurityProfileControlTests):
    """A profile that answers no severity question matches NEITHER true nor false.

    This is what the satellite bought. While the verdicts were columns the only way to store
    "does not answer" was `False`, which a query for `critical_blocked = false` would have
    returned as though the profile failed to block critical threats.
    """

    def test_a_profile_with_no_verdicts_matches_neither_value(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        answers = self._profile("answers", critical=False)
        silent = SecurityProfile.objects.create(
            management_station=self.station, appliance_group=self.group,
            source_snapshot=self.snapshot, config_source="local", name="silent",
            namespace_type=PolicyObjectNamespace.LOCAL_SHARED, namespace_value="shared",
            precedence_rank=21, kind=SPY)

        compile_blocked = FIELD_COMPILERS["critical_blocked"]
        false_match = {row["pk"] for row in compile_blocked(
            {"op": "eq", "value": False, "case_sensitive": False})}
        true_match = {row["pk"] for row in compile_blocked(
            {"op": "eq", "value": True, "case_sensitive": False})}

        self.assertIn(answers.pk, false_match)
        self.assertNotIn(silent.pk, false_match,
                         "a profile that makes no claim must not read as failing")
        self.assertNotIn(silent.pk, true_match)

    def test_the_detail_is_searchable_through_the_satellite(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        weak = self._profile("weak-detail", critical=False)

        matched = {row["pk"] for row in FIELD_COMPILERS["critical_detail"](
            {"op": "contains", "value": "alert by rule", "case_sensitive": False})}

        self.assertIn(weak.pk, matched)


class BruteForceSourceBlockingTests(SecurityProfileControlTests):
    """PAN-VLN-002: blocking the THREAT and blocking its SOURCE are different questions."""

    def setUp(self):
        super().setUp()
        spec = {c["control_id"]: c
                for c in load_seed_payload()["catalogs"][0]["controls"]}["PAN-VLN-002"]
        control = Control.objects.create(
            control_id="PAN-VLN-002", name=spec["name"],
            control_type=Control.ControlType.SECURITY_PROFILE,
            description=spec["description"], default_severity=spec["default_severity"],
            target_model=spec["target_model"])
        for query in spec["queries"]:
            ControlQuery.objects.create(
                control=control, name=query["name"], canonical_query=query["canonical_query"],
                is_baseline=query["is_baseline"], is_active=query["is_active"])

    def _verdict(self, profile, blocks_source, *, weakest="", track_by="", duration=None,
                 detail=""):
        return SecurityProfileCategoryVerdict.objects.create(
            security_profile=profile,
            category=SecurityProfileCategoryVerdict.BRUTE_FORCE,
            blocks_source=blocks_source, weakest_action=weakest, track_by=track_by,
            duration=duration, detail=detail)

    def test_a_profile_blocking_the_source_does_not_fire(self):
        profile = self._profile("bf-blocked", kind=VLN)
        self._verdict(profile, True, weakest="block-ip", track_by="source", duration=300)
        self.assertNotIn(("PAN-VLN-002", "bf-blocked"), self._fired())

    def test_a_reset_both_profile_passes_vln_001_and_fires_vln_002(self):
        # The whole point of the control, as one assertion.
        profile = self._profile("bf-reset", kind=VLN)
        self._verdict(profile, False, weakest="reset-both",
                      detail="reset-both by rule rb (critical)")
        fired = self._fired()
        self.assertIn(("PAN-VLN-002", "bf-reset"), fired)
        self.assertNotIn(("PAN-VLN-001", "bf-reset"), fired)

    def test_a_profile_with_no_category_row_matches_neither_value(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        answers = self._profile("vln-answers", kind=VLN)
        self._verdict(answers, False, detail="no rule covers brute-force for critical")
        silent = self._profile("spy-silent", kind=SPY)

        compile_blocked = FIELD_COMPILERS["brute_force_blocked_by_source"]
        false_match = {row["pk"] for row in compile_blocked(
            {"op": "eq", "value": False, "case_sensitive": False})}
        true_match = {row["pk"] for row in compile_blocked(
            {"op": "eq", "value": True, "case_sensitive": False})}

        self.assertIn(answers.pk, false_match)
        self.assertNotIn(silent.pk, false_match,
                         "an anti-spyware profile makes no claim about brute-force source "
                         "blocking and must not read as failing it")
        self.assertNotIn(silent.pk, true_match)

    def test_an_anti_spyware_profile_never_fires_this_control(self):
        self._profile("spy-anything", kind=SPY, critical=False)
        self.assertNotIn("PAN-VLN-002", [cid for cid, _ in self._fired()])

    def test_the_detail_is_searchable(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        profile = self._profile("bf-detail", kind=VLN)
        self._verdict(profile, False, detail="alert by rule bf (high, server side)")

        matched = {row["pk"] for row in FIELD_COMPILERS["brute_force_detail"](
            {"op": "contains", "value": "server side", "case_sensitive": False})}
        self.assertIn(profile.pk, matched)

    def test_the_subject_says_the_source_is_not_blocked(self):
        # Without this clause the finding read "blocks critical and high threats" - the
        # reassuring sentence on a failing profile.
        profile = self._profile("bf-subject", kind=VLN)
        self._verdict(profile, False, weakest="reset-both",
                      detail="reset-both by rule rb (critical)")
        generate_security_profile_findings(self.run)
        finding = SecurityProfileFinding.objects.get(
            control__control_id="PAN-VLN-002", security_profile=profile)
        self.assertIn("does not block the source of brute-force attempts", finding.summary)
        self.assertNotIn("blocks critical and high threats", finding.summary)

    def test_a_profile_failing_both_questions_says_both(self):
        profile = self._profile("bf-both", kind=VLN, critical=False)
        self._verdict(profile, False, weakest="alert", detail="alert by rule a (critical)")
        generate_security_profile_findings(self.run)
        summary = SecurityProfileFinding.objects.get(
            control__control_id="PAN-VLN-002", security_profile=profile).summary
        self.assertIn("does not block every critical and high threat", summary)
        self.assertIn("does not block the source of brute-force attempts", summary)

    def test_the_finding_carries_the_CONTROL_severity_not_the_preferred_gap(self):
        # controls.json carries `preferred_gap_severity: low`, and the checklist is explicit
        # that it is not something to implement: the control asserts the preferred value and
        # the finding reports the control's own severity. Seeded at low first, which is the
        # defect five shipped controls had at the other end.
        profile = self._profile("bf-sev", kind=VLN)
        self._verdict(profile, False, detail="no rule covers brute-force for critical")
        generate_security_profile_findings(self.run)
        finding = SecurityProfileFinding.objects.get(
            control__control_id="PAN-VLN-002", security_profile=profile)
        self.assertEqual(finding.severity, "medium")


class DnsSinkholeControlTests(SecurityProfileControlTests):
    """PAN-SPY-002, including the case the Help says is passing: nothing configured."""

    def setUp(self):
        super().setUp()
        spec = {c["control_id"]: c
                for c in load_seed_payload()["catalogs"][0]["controls"]}["PAN-SPY-002"]
        control = Control.objects.create(
            control_id="PAN-SPY-002", name=spec["name"],
            control_type=Control.ControlType.SECURITY_PROFILE,
            description=spec["description"], default_severity=spec["default_severity"],
            target_model=spec["target_model"])
        for query in spec["queries"]:
            ControlQuery.objects.create(
                control=control, name=query["name"], canonical_query=query["canonical_query"],
                is_baseline=query["is_baseline"], is_active=query["is_active"])

    def _source(self, profile, action, *, name="default-paloalto-dns", content=True,
                implicit=False):
        return SecurityProfileDnsSignatureSource.objects.create(
            security_profile=profile, name=name, is_paloalto_content=content,
            configured_action="" if implicit else action,
            effective_action=action, sinkholes=action == "sinkhole",
            action_is_implicit=implicit)

    def test_a_sinkholing_profile_does_not_fire(self):
        profile = self._profile("spy-sink", kind=SPY)
        self._source(profile, "sinkhole")
        self.assertNotIn(("PAN-SPY-002", "spy-sink"), self._fired())

    def test_an_alerting_profile_fires(self):
        # The shape the predefined `default` profile actually ships with.
        profile = self._profile("spy-alert", kind=SPY)
        self._source(profile, "alert")
        self.assertIn(("PAN-SPY-002", "spy-alert"), self._fired())

    def test_block_fires_because_it_loses_the_infected_client(self):
        profile = self._profile("spy-block", kind=SPY)
        self._source(profile, "block")
        self.assertIn(("PAN-SPY-002", "spy-block"), self._fired())

    def test_an_unconfigured_profile_does_NOT_fire(self):
        # Help p.284 says an unconfigured Palo Alto Networks Content list sinkholes. Firing
        # here would report every profile that never opened the DNS Policies tab.
        profile = self._profile("spy-bare", kind=SPY)
        self._source(profile, "sinkhole", implicit=True)
        self.assertNotIn(("PAN-SPY-002", "spy-bare"), self._fired())

    def test_an_allow_EDL_does_not_fire_the_control(self):
        # An EDL with allow is the documented way to express a DNS exception. Only the Palo
        # Alto Networks Content row is asserted.
        profile = self._profile("spy-edl", kind=SPY)
        self._source(profile, "sinkhole")
        self._source(profile, "allow", name="corp-dns-allow", content=False)
        self.assertNotIn(("PAN-SPY-002", "spy-edl"), self._fired())

    def test_a_vulnerability_profile_matches_neither_value(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        answers = self._profile("spy-answers", kind=SPY)
        self._source(answers, "alert")
        silent = self._profile("vln-silent", kind=VLN)

        compile_sink = FIELD_COMPILERS["dns_sinkholes_malicious_queries"]
        false_match = {row["pk"] for row in compile_sink(
            {"op": "eq", "value": False, "case_sensitive": False})}
        true_match = {row["pk"] for row in compile_sink(
            {"op": "eq", "value": True, "case_sensitive": False})}

        self.assertIn(answers.pk, false_match)
        self.assertNotIn(silent.pk, false_match,
                         "a vulnerability profile has no DNS tree and makes no claim")
        self.assertNotIn(silent.pk, true_match)

    def test_the_implicit_case_is_listable_without_being_asserted(self):
        from assessments.search.security_profile.compiler import FIELD_COMPILERS

        bare = self._profile("spy-implicit", kind=SPY)
        self._source(bare, "sinkhole", implicit=True)
        explicit = self._profile("spy-explicit", kind=SPY)
        self._source(explicit, "sinkhole")

        matched = {row["pk"] for row in FIELD_COMPILERS["dns_sinkhole_action_is_implicit"](
            {"op": "eq", "value": True, "case_sensitive": False})}
        self.assertEqual(matched, {bare.pk})

    def test_the_subject_names_the_dns_gap_and_not_only_the_severities(self):
        profile = self._profile("spy-dns-subject", kind=SPY)
        self._source(profile, "alert")
        generate_security_profile_findings(self.run)
        summary = SecurityProfileFinding.objects.get(
            control__control_id="PAN-SPY-002", security_profile=profile).summary
        self.assertIn("does not sinkhole malicious DNS queries", summary)
        self.assertIn("action is alert", summary)
        self.assertNotIn("blocks critical and high threats", summary)

    def test_the_finding_carries_the_control_severity(self):
        profile = self._profile("spy-dns-sev", kind=SPY)
        self._source(profile, "alert")
        generate_security_profile_findings(self.run)
        self.assertEqual(SecurityProfileFinding.objects.get(
            control__control_id="PAN-SPY-002", security_profile=profile).severity, "high")
