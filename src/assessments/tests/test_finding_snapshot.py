"""What configuration a finding was computed from.

`FindingBase.snapshot` is copied off the subject when the generator writes the finding. The
subject's own `source_snapshot` answers a different question - what that object is CURRENTLY
parsed from - and normalization repoints it in place on the next collection. So a surface
reading the date through the subject reports the config the estate holds NOW, not the config
the assessment was derived from, and the two diverge in exactly the case a reader needs to
notice: findings that have gone stale against a newer collection.

`test_the_date_does_not_follow_a_later_collection` is the whole point of the field. Everything
else here guards the ways it could quietly stop being true.
"""

from __future__ import annotations

from django.db.models import ProtectedError
from django.test import TestCase
from django.utils import timezone

from datetime import timedelta

from assessments.finding_registry import FINDING_KINDS
from assessments.finding_run import regenerate_findings
from assessments.models import Control, LoginBannerFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, LoginBanner, ManagementStation, Snapshot)


def build_estate(*, collected_at=None):
    station = ManagementStation.objects.create(
        station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.snap")
    group = ApplianceGroup.objects.create(
        management_station=station, name="g-snap", group_type=ApplianceGroup.TYPE_STANDALONE)
    appliance = Appliance.objects.create(
        management_station=station, appliance_group=group,
        serial_number="S-SNAP", hostname="fw-snap")
    snapshot = Snapshot.objects.create(
        management_station=station, appliance=appliance, source_type="show_merged_config",
        collected_at=collected_at or timezone.now(), payload={})
    banner = LoginBanner.objects.create(
        management_station=station, appliance=appliance, source_snapshot=snapshot, text="")
    seed_controls(["PAN-MGT-007"], control_type=Control.ControlType.LOGIN_BANNER)
    return station, appliance, snapshot, banner


class FindingSnapshotTests(TestCase):
    def setUp(self):
        self.collected = timezone.now() - timedelta(days=3)
        self.station, self.appliance, self.snapshot, self.banner = build_estate(
            collected_at=self.collected)

    def test_a_generated_finding_records_the_configuration_it_came_from(self):
        regenerate_findings()

        finding = LoginBannerFinding.objects.get()
        self.assertEqual(finding.snapshot, self.snapshot)
        self.assertEqual(finding.snapshot.collected_at, self.collected)

    def test_the_date_does_not_follow_a_later_collection(self):
        """The reason this field exists. Collect again, normalize in place, do NOT re-run: the
        finding must still name the configuration it was computed from. Read through the
        subject it would now report the newer date, and claim an assessment of config it never
        saw."""
        regenerate_findings()
        finding = LoginBannerFinding.objects.get()

        later = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.filter(pk=self.banner.pk).update(source_snapshot=later)

        finding.refresh_from_db()
        self.assertEqual(finding.snapshot, self.snapshot)
        self.assertEqual(finding.snapshot.collected_at, self.collected)
        # And the subject now says something different, which is the divergence being pinned.
        self.assertEqual(LoginBanner.objects.get(pk=self.banner.pk).source_snapshot, later)

    def test_a_rerun_picks_up_the_newer_collection(self):
        """Pinned, not frozen. A run states what IT assessed, so the next run states what it
        assessed - otherwise the date would go stale in the other direction."""
        regenerate_findings()
        later = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.filter(pk=self.banner.pk).update(source_snapshot=later)

        regenerate_findings()

        self.assertEqual(LoginBannerFinding.objects.get().snapshot, later)

    def test_configuration_an_assessment_depends_on_cannot_be_deleted(self):
        """`on_delete=PROTECT`. A pruned snapshot must not take findings with it, and must not
        silently turn a recorded date into "not recorded"."""
        regenerate_findings()

        with self.assertRaises(ProtectedError):
            self.snapshot.delete()

        self.assertEqual(LoginBannerFinding.objects.count(), 1)

    def test_a_finding_with_no_snapshot_is_allowed(self):
        """Nullable on purpose: a run predating the field, or a subject normalization left
        without a snapshot, is a real state and not worth refusing a finding over."""
        regenerate_findings()
        finding = LoginBannerFinding.objects.get()
        finding.snapshot = None
        finding.save()

        self.assertIsNone(LoginBannerFinding.objects.get().snapshot)


class EveryFindingModelCarriesItTests(TestCase):
    def test_the_field_is_on_every_finding_model(self):
        """It is declared once, on the abstract base. This fails for a finding model that stops
        inheriting from it - the same drift `test_finding_reference` guards for the reference."""
        for kind in FINDING_KINDS:
            with self.subTest(kind.model.__name__):
                field = kind.model._meta.get_field("snapshot")
                self.assertTrue(field.null)
                self.assertEqual(field.remote_field.on_delete.__name__, "PROTECT")

    def test_it_declines_a_reverse_accessor(self):
        """Why this field CAN sit on the abstract base where `assessment_run` and `control`
        cannot: `related_name="+"` means there is no name to interpolate, so `Snapshot` does not
        grow twenty-four accessors named after lowercased class names."""
        accessors = [f.name for f in Snapshot._meta.get_fields()
                     if f.is_relation and f.auto_created and "finding" in f.name.lower()]

        self.assertEqual(accessors, [])

    def test_every_subject_model_can_supply_one(self):
        """The copy reads `source_snapshot` off the subject. A subject model without it would
        silently record None for every finding of that kind."""
        for kind in FINDING_KINDS:
            with self.subTest(kind.model.__name__):
                subject = kind.model._meta.get_field(kind.subject_field).related_model
                self.assertTrue(
                    any(f.name == "source_snapshot" for f in subject._meta.get_fields()),
                    f"{subject.__name__} has no source_snapshot to copy")
