"""A finding's reference - F-0001 - is unique within its run across EVERY finding model.

Jason, 2026-09-16: "A consistent, human readable, unique identifier used at presentation layers in
the app and all related artifacts. Re-runs should reset the identifier."

No database constraint can span 23 tables, so the cross-model guarantee rests on one allocator per
run (`AssessmentRun.next_reference_number`) and on this file. The per-model half IS a constraint,
declared once on `FindingBase` - and lost silently by any subclass whose Meta REPLACES
`constraints` instead of concatenating them, which is what the first test is for.
"""

from __future__ import annotations

from django.db import models
from django.test import TestCase
from django.utils import timezone

from assessments.finding_registry import FINDING_KINDS, FINDING_MODELS
from assessments.finding_run import regenerate_findings
from assessments.models import AssessmentRun, Control, FindingBase, LoginBannerFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, LoginBanner, ManagementStation, PasswordComplexityPolicy, Snapshot)


def _all_references(run):
    return [(kind.model.__name__, finding.reference)
            for kind in FINDING_KINDS
            for finding in kind.model.objects.filter(assessment_run=run)]


class FindingReferenceConstraintTests(TestCase):
    def test_every_finding_model_keeps_the_per_run_reference_constraint(self):
        for model in FINDING_MODELS:
            with self.subTest(model.__name__):
                self.assertTrue(issubclass(model, FindingBase))
                self.assertIn(
                    ("assessment_run", "reference_number"),
                    [tuple(c.fields) for c in model._meta.constraints
                     if isinstance(c, models.UniqueConstraint)],
                    f"{model.__name__}.Meta replaced FindingBase's constraints instead of "
                    f"concatenating them")


class FindingReferenceAllocationTests(TestCase):
    def setUp(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.ref")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-ref", group_type=ApplianceGroup.TYPE_STANDALONE)
        # Created b-then-a, so a numbering that followed insertion order would be caught.
        for hostname in ("fw-b", "fw-a"):
            appliance = Appliance.objects.create(
                management_station=station, appliance_group=group,
                serial_number=f"S-{hostname}", hostname=hostname)
            snapshot = Snapshot.objects.create(
                management_station=station, appliance=appliance,
                source_type="show_merged_config", collected_at=timezone.now(), payload={})
            # Every value at its insecure default: PAN-AUTH-002 fires on both appliances.
            PasswordComplexityPolicy.objects.create(
                management_station=station, appliance=appliance, source_snapshot=snapshot)
            LoginBanner.objects.create(
                management_station=station, appliance=appliance, source_snapshot=snapshot, text="")
        seed_controls(["PAN-AUTH-002"], control_type=Control.ControlType.PASSWORD_COMPLEXITY)
        seed_controls(["PAN-MGT-007"], control_type=Control.ControlType.LOGIN_BANNER)

    def test_one_run_numbers_every_model_from_one_sequence_in_generator_order(self):
        run = regenerate_findings().assessment_run
        references = _all_references(run)

        self.assertEqual(sorted(ref for _, ref in references),
                         ["F-0001", "F-0002", "F-0003", "F-0004"])
        by_reference = {ref: model for model, ref in references}
        # Password complexity precedes login banner in GENERATORS, so it takes the low numbers.
        self.assertEqual(by_reference["F-0001"], "PasswordComplexityFinding")
        self.assertEqual(by_reference["F-0002"], "PasswordComplexityFinding")
        self.assertEqual(by_reference["F-0003"], "LoginBannerFinding")
        self.assertEqual(by_reference["F-0004"], "LoginBannerFinding")

    def test_within_a_control_findings_are_numbered_by_subject_not_insertion(self):
        run = regenerate_findings().assessment_run
        banners = LoginBannerFinding.objects.filter(assessment_run=run).order_by("reference_number")
        self.assertEqual([f.subject_name for f in banners], ["fw-a", "fw-b"])

    def test_a_new_run_starts_again_at_one(self):
        regenerate_findings()
        second = regenerate_findings().assessment_run
        self.assertEqual(sorted(ref for _, ref in _all_references(second)),
                         ["F-0001", "F-0002", "F-0003", "F-0004"])

    def test_a_finding_saved_outside_a_generator_continues_the_run_sequence(self):
        """A fresh run instance seeds its counter from what the run already holds, so a
        finding created directly - as tests and fixtures do - cannot reuse a number."""
        run = regenerate_findings().assessment_run
        control = Control.objects.get(control_id="PAN-MGT-007")
        existing = LoginBanner.objects.first()
        appliance = Appliance.objects.create(
            management_station=existing.management_station,
            appliance_group=existing.appliance.appliance_group,
            serial_number="S-fw-c", hostname="fw-c")
        banner = LoginBanner.objects.create(
            management_station=existing.management_station, appliance=appliance,
            source_snapshot=existing.source_snapshot, text="")

        fresh_instance = AssessmentRun.objects.get(pk=run.pk)
        finding = LoginBannerFinding.objects.create(
            assessment_run=fresh_instance, control=control, login_banner=banner,
            severity=Control.Severity.LOW, title="direct")
        self.assertEqual(finding.reference, "F-0005")

    def test_reference_widens_rather_than_wrapping(self):
        finding = LoginBannerFinding(reference_number=12345)
        self.assertEqual(finding.reference, "F-12345")
