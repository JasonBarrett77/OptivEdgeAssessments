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
    Appliance, ApplianceGroup, ManagementStation, PolicyObjectNamespace, SecurityProfile, Snapshot)

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
        return SecurityProfile.objects.create(
            management_station=self.station, appliance_group=self.group, source_snapshot=self.snapshot,
            config_source="local", name=name, namespace_type=namespace,
            namespace_value="predefined" if predefined else "shared", precedence_rank=20, kind=kind,
            is_predefined=predefined, is_used=used, referrer_count=1 if used else 0,
            referrers=["vsys1 profile-group/g"] if used else [],
            critical_blocked=critical, critical_detail="reset-both" if critical else "alert by rule a",
            high_blocked=high, high_detail="reset-both" if high else "alert by rule alert-high",
            medium_blocked=medium, medium_detail="reset-both" if medium else "no catch-all rule")

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

    def test_the_tab_hides_unused_predefined_profiles(self):
        self._profile("custom-spy", high=False)
        self._profile("used-default", kind=VLN, predefined=True, used=True, critical=False)
        self._profile("unused-default", predefined=True, used=False, critical=False)
        response = self.client.get(reverse("assessment_security_profile_list"))
        self.assertContains(response, "custom-spy")
        self.assertContains(response, "used-default")
        self.assertNotContains(response, "unused-default")

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
