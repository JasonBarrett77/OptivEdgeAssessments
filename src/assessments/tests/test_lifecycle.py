"""A findings run lives as long as the normalization it was computed from - see lifecycle.py.

Jason, 2026-10-15: normalization is all or nothing, and never deletes a collection. A run
computed before it no longer describes the configuration in the database, so it is discarded -
the rule a catalog reseed already follows. Neither may start while the other is in progress,
and a workbook build holds normalization off too.
"""

from __future__ import annotations

import shutil
import tempfile

from django.test import TestCase, override_settings
from django.urls import reverse

from assessments import artifact_store
from assessments.finding_run import open_findings_run, regenerate_findings
from assessments.models import AssessmentRun, GeneratedArtifact
from assessments.tests._seed import seed_controls
from assessments.tests.test_findings_views import build_estate
from optivedge_integrations.integrations.lifecycle import (
    NormalizationRefused, begin_normalization)
from optivedge_integrations.integrations.models import ManagementStation


class _Estate(TestCase):
    def setUp(self):
        media = tempfile.mkdtemp(prefix="oea-lifecycle-")
        self.addCleanup(shutil.rmtree, media, ignore_errors=True)
        override = override_settings(MEDIA_ROOT=media)
        override.enable()
        self.addCleanup(override.disable)
        build_estate()
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()
        self.station = ManagementStation.objects.first()

    def finding_count(self):
        from assessments.finding_registry import FINDING_KINDS

        return sum(kind.model.objects.count() for kind in FINDING_KINDS)


class NormalizationDiscardsRunsTests(_Estate):
    def test_normalization_discards_every_run_and_its_findings(self):
        self.assertGreater(self.finding_count(), 0, "the estate must have findings to lose")

        begin_normalization(self.station)

        self.assertFalse(AssessmentRun.objects.exists())
        self.assertEqual(self.finding_count(), 0)

    def test_a_kept_build_survives_it_marked_stale(self):
        """A deliverable is the engineer's to delete (2026-10-14)."""
        artifact = artifact_store.fill_workbook(artifact_store.open_workbook_build())

        begin_normalization(self.station)

        artifact.refresh_from_db()
        self.assertIsNone(artifact.assessment_run)
        response = self.client.get(reverse("assessment_downloads"))
        self.assertTrue(response.context["rows"][0]["stale"])

    def test_normalization_is_refused_while_findings_are_being_run(self):
        """The run would compute against objects being deleted under it."""
        running = open_findings_run()

        with self.assertRaisesRegex(NormalizationRefused, "findings run is in progress"):
            begin_normalization(self.station)

        self.assertTrue(AssessmentRun.objects.filter(pk=running.pk).exists())
        self.assertGreater(self.finding_count(), 0)

    def test_normalization_is_refused_while_a_workbook_is_being_built(self):
        artifact_store.open_workbook_build()

        with self.assertRaisesRegex(NormalizationRefused, "workbook is being built"):
            begin_normalization(self.station)

        self.assertTrue(AssessmentRun.objects.exists())

    def test_the_operator_is_told_why_on_the_station_page(self):
        """The refusal reaches Integrations' own view as its message - nothing written there."""
        from unittest import mock

        from optivedge_integrations.integrations.models import IntegrationRun

        open_findings_run()

        with mock.patch("optivedge_integrations.integrations.views.threading.Thread") as thread:
            response = self.client.post(
                reverse("management_station_renormalize", kwargs={"pk": self.station.pk}),
                follow=True)

        thread.assert_not_called()
        self.assertFalse(IntegrationRun.objects.exists())
        self.assertIn("findings run is in progress",
                      " ".join(m.message for m in response.context["messages"]))


class NoRunIsNotACleanEstateTests(_Estate):
    """With no run, the findings pages are a grid of dashes and a total of 0 - which reads as
    nothing wrong. They have to say that nothing was assessed."""

    def test_the_findings_pages_say_nothing_was_assessed(self):
        begin_normalization(self.station)

        for url in (reverse("assessment_findings_summary"),
                    reverse("assessment_findings_domain", args=["login-banner"])):
            with self.subTest(url):
                response = self.client.get(url)
                self.assertContains(response, "data-no-findings-run")
                self.assertContains(response, "nothing here has been assessed")

    def test_a_run_removes_the_warning(self):
        response = self.client.get(reverse("assessment_findings_summary"))

        self.assertNotContains(response, "data-no-findings-run")


class RestartTests(_Estate):
    def test_a_restart_fails_what_was_running_and_leaves_the_rest(self):
        from optivedge.lifecycle import server_started

        finished = AssessmentRun.objects.get()
        running = open_findings_run()
        building = artifact_store.open_workbook_build()

        server_started.send(sender=None)

        running.refresh_from_db()
        building.refresh_from_db()
        finished.refresh_from_db()
        self.assertEqual(running.status, AssessmentRun.Status.FAILED)
        self.assertEqual(building.status, GeneratedArtifact.Status.FAILED)
        self.assertEqual(finished.status, AssessmentRun.Status.COMPLETED)
