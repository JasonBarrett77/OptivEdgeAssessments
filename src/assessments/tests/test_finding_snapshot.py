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

    def test_recording_it_does_not_load_the_configuration(self):
        """The ID is copied, never the relation. Reading `obj.source_snapshot` fetches the
        Snapshot with its `payload` - the raw merged config, decoded on fetch - once per
        FINDING, because nothing shares the instance. On the lab, 2026-10-14, that was 194s and
        3.6 GB for security rules alone and a MemoryError from Run Findings; copying the ID
        made it 9s and 144 MB. A test estate's `payload={}` costs nothing, so the timing would
        never show it here: the query is the signal."""
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        with CaptureQueriesContext(connection) as captured:
            regenerate_findings()

        payload_reads = [q["sql"] for q in captured.captured_queries
                         if '"integrations_snapshot"."payload"' in q["sql"]]
        self.assertEqual(payload_reads, [])
        self.assertEqual(LoginBannerFinding.objects.get().snapshot_id, self.snapshot.pk)


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

    #: Subject models with no `source_snapshot`, each with the reason the field's purpose
    #: cannot apply to it. The field exists to catch ONE thing - see the module docstring - a
    #: finding that has gone stale against a newer collection. An exemption has to show that
    #: divergence is impossible for the subject, not merely inconvenient to record.
    SUBJECTS_WITH_NO_SNAPSHOT_TO_COPY = {
        "NormalizationIssue": (
            "It is not normalized FROM a snapshot - it is the normalizer's record of what it "
            "could not normalize, and `models/normalization.py` says it 'records what is "
            "currently wrong, and is replaced on every run exactly like the objects it "
            "describes'. So a row cannot survive into a newer collection, which is the "
            "divergence this field detects. And NormalizationFinding's subject FK is CASCADE, "
            "so a fault that gets fixed takes its finding with the row rather than leaving a "
            "stale one behind. Both halves are needed: replace-per-run alone would leave an "
            "orphaned finding, and CASCADE alone would not stop a row being rewritten in "
            "place. Added 2026-10-28 with the normalization coverage framework."
        ),
    }

    def test_every_subject_model_can_supply_one(self):
        """The copy reads `source_snapshot` off the subject. A subject model without it would
        silently record None for every finding of that kind - unless the staleness this field
        detects cannot arise for that subject, which is what the exemption above has to argue."""
        for kind in FINDING_KINDS:
            with self.subTest(kind.model.__name__):
                subject = kind.model._meta.get_field(kind.subject_field).related_model
                if subject.__name__ in self.SUBJECTS_WITH_NO_SNAPSHOT_TO_COPY:
                    self.assertFalse(
                        any(f.name == "source_snapshot" for f in subject._meta.get_fields()),
                        f"{subject.__name__} now HAS source_snapshot - drop its exemption "
                        f"rather than leaving a stale reason in this file")
                    continue
                self.assertTrue(
                    any(f.name == "source_snapshot" for f in subject._meta.get_fields()),
                    f"{subject.__name__} has no source_snapshot to copy")

    def test_the_exemptions_name_a_registered_subject_and_carry_a_reason(self):
        """An exemption for a model nobody registers is a reason nobody can check, and the
        mechanism would then hide the next real gap instead of documenting this one."""
        subjects = {kind.model._meta.get_field(kind.subject_field).related_model.__name__
                    for kind in FINDING_KINDS}
        for name, reason in self.SUBJECTS_WITH_NO_SNAPSHOT_TO_COPY.items():
            with self.subTest(name):
                self.assertIn(name, subjects)
                self.assertGreater(len(reason), 120)
