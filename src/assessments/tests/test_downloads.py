"""The workbook, built in the background and collected from Downloads.

It was built on the request until 2026-10-14. Jason: make it a background process, and retrieve
the file from a view that lists what is available for download. Three decisions came with it, and
each has a test here because each is easy to undo by accident:

* builds are KEPT until somebody deletes them - nothing prunes, and a reseed discarding the run
  a build came from must not take the file with it
* a build from an older findings run is FLAGGED stale, never refused
* a build and a findings run REFUSE each other, both ways - see `artifact_store`

The thread itself is mocked in the view tests and `fill_workbook` is called directly, the same
split `test_control_views` uses for Run Findings: what runs on the thread is tested as a function,
and the view is tested for starting it.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.messages import get_messages
from django.test import TestCase, override_settings
from django.urls import reverse

from assessments import artifact_store
from assessments.artifacts import ArtifactBuildError
from assessments.finding_run import open_findings_run, regenerate_findings
from assessments.models import AssessmentRun, GeneratedArtifact
from assessments.tests._seed import seed_controls
from assessments.tests.test_findings_views import build_estate
from optivedge.models import ApplicationEnvironment

XLSX_MAGIC = b"PK"


class _MediaRoot(TestCase):
    """A throwaway MEDIA_ROOT per test, so a stored workbook never lands in the repo."""

    def setUp(self):
        self.media = tempfile.mkdtemp(prefix="oea-downloads-")
        self.addCleanup(shutil.rmtree, self.media, ignore_errors=True)
        override = override_settings(MEDIA_ROOT=self.media)
        override.enable()
        self.addCleanup(override.disable)
        build_estate()
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()

    def built(self) -> GeneratedArtifact:
        """A workbook built the way the thread builds it."""
        return artifact_store.fill_workbook(artifact_store.open_workbook_build())


class BuildingTests(_MediaRoot):
    def test_a_build_stores_a_workbook_and_records_its_run(self):
        artifact = self.built()

        self.assertEqual(artifact.status, GeneratedArtifact.Status.READY)
        self.assertEqual(artifact.assessment_run, AssessmentRun.objects.get())
        self.assertTrue(Path(artifact.file.path).is_relative_to(self.media))
        content = Path(artifact.file.path).read_bytes()
        self.assertEqual(content[:2], XLSX_MAGIC)
        self.assertEqual(artifact.size, len(content))
        self.assertIsNotNone(artifact.completed_at)

    def test_the_file_is_named_for_the_engagement(self):
        ApplicationEnvironment.objects.create(
            client_name="Acme Corporation", client_short_name="Acme",
            opportunity_number="OP-1234567")

        artifact = self.built()

        self.assertTrue(artifact.filename.startswith("acme-op-1234567-assessment-"))

    def test_a_refused_build_says_which_guard_and_why(self):
        """What `ArtifactBuildError` deriving from Exception is FOR. On a thread there is no
        request to raise into, so the guard's sentence has to land on the row the reader sees."""
        with mock.patch("assessments.artifact_store.build_workbook",
                        side_effect=ArtifactBuildError("PAN-MGT-007 reached no tab")):
            artifact = self.built()

        self.assertEqual(artifact.status, GeneratedArtifact.Status.FAILED)
        self.assertIn("PAN-MGT-007 reached no tab", artifact.error)
        self.assertFalse(artifact.file)
        self.assertContains(self.client.get(reverse("assessment_downloads")),
                            "PAN-MGT-007 reached no tab")

    def test_an_unexpected_error_fails_the_build_rather_than_leaving_it_building(self):
        """A row left BUILDING would block every later build until the age limit expired."""
        with mock.patch("assessments.artifact_store.build_workbook",
                        side_effect=RuntimeError("disk full")):
            with self.assertLogs("assessments.artifact_store", level="ERROR"):
                artifact = self.built()

        self.assertEqual(artifact.status, GeneratedArtifact.Status.FAILED)
        self.assertIn("RuntimeError: disk full", artifact.error)


class BuildViewTests(_MediaRoot):
    def post(self):
        with mock.patch("assessments.views.threading.Thread") as thread:
            response = self.client.post(reverse("assessment_workbook_build"), follow=True)
        return response, thread

    def last_message(self, response):
        return str(list(get_messages(response.wsgi_request))[-1])

    def test_it_opens_the_row_and_hands_the_build_to_a_thread(self):
        response, thread = self.post()

        self.assertRedirects(response, reverse("assessment_downloads"))
        artifact = GeneratedArtifact.objects.get()
        self.assertEqual(artifact.status, GeneratedArtifact.Status.BUILDING)
        thread.assert_called_once()
        self.assertEqual(thread.call_args.kwargs["args"], (artifact.pk,))
        self.assertTrue(thread.call_args.kwargs["daemon"])
        thread.return_value.start.assert_called_once()

    def test_a_second_build_is_refused_while_one_runs(self):
        """A second click used to start a second build."""
        self.post()

        response, thread = self.post()

        thread.assert_not_called()
        self.assertEqual(GeneratedArtifact.objects.count(), 1)
        self.assertIn("already being built", self.last_message(response))

    def test_a_build_is_refused_while_findings_are_being_run(self):
        """Its tabs would come from two runs: every generator replaces its whole table."""
        open_findings_run()

        response, thread = self.post()

        thread.assert_not_called()
        self.assertFalse(GeneratedArtifact.objects.exists())
        self.assertIn("findings run is in progress", self.last_message(response))

    def test_findings_are_refused_while_a_workbook_is_being_built(self):
        """The other half of the same rule."""
        self.post()

        with mock.patch("assessments.views.threading.Thread") as thread:
            response = self.client.post(reverse("assessment_control_run_findings"), follow=True)

        thread.assert_not_called()
        self.assertEqual(AssessmentRun.objects.filter(
            status=AssessmentRun.Status.RUNNING).count(), 0)
        self.assertIn("workbook is being built", self.last_message(response))

    def test_a_restart_closes_the_build_it_killed(self):
        """A restart kills the daemon thread and leaves the row BUILDING, which would disable
        both buttons for good. The next server process closes it, and says why on the row."""
        from optivedge.lifecycle import server_started

        self.post()
        server_started.send(sender=None)

        orphan = GeneratedArtifact.objects.get()
        self.assertEqual(orphan.status, GeneratedArtifact.Status.FAILED)
        self.assertIn("server restarted", orphan.error)
        self.assertIsNone(artifact_store.build_in_progress())
        _response, thread = self.post()
        thread.assert_called_once()

    def test_a_build_is_refused_while_the_configuration_is_being_replaced(self):
        with mock.patch("assessments.views.integration_work_in_progress", return_value=True):
            response, thread = self.post()

        thread.assert_not_called()
        self.assertFalse(GeneratedArtifact.objects.exists())
        self.assertIn("collection or normalization is running", self.last_message(response))

    def test_without_a_findings_run_nothing_is_built(self):
        """Every tab would be empty: a clean estate, on a deliverable, that nothing assessed."""
        AssessmentRun.objects.all().delete()

        response, thread = self.post()

        thread.assert_not_called()
        self.assertFalse(GeneratedArtifact.objects.exists())
        self.assertIn("No findings run", self.last_message(response))

    @override_settings(MEDIA_ROOT="")
    def test_without_a_media_root_nothing_is_built(self):
        """Unset, storage writes to the server's working directory - wherever manage.py was
        started. A client deliverable must not land somewhere nobody chose."""
        response, thread = self.post()

        thread.assert_not_called()
        self.assertFalse(GeneratedArtifact.objects.exists())
        self.assertIn("MEDIA_ROOT is not set", self.last_message(response))


class DownloadTests(_MediaRoot):
    def test_a_ready_build_downloads_under_its_name(self):
        artifact = self.built()

        response = self.client.get(reverse("assessment_artifact_download", args=[artifact.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertIn(f'filename="{artifact.filename}"', response["Content-Disposition"])
        self.assertTrue(response["Content-Disposition"].startswith("attachment"))
        self.assertEqual(b"".join(response.streaming_content)[:2], XLSX_MAGIC)

    def test_a_build_that_is_not_ready_has_nothing_to_download(self):
        artifact = artifact_store.open_workbook_build()

        response = self.client.get(reverse("assessment_artifact_download", args=[artifact.pk]))

        self.assertEqual(response.status_code, 404)

    def test_a_file_gone_from_disk_is_a_404_not_a_500(self):
        artifact = self.built()
        Path(artifact.file.path).unlink()

        response = self.client.get(reverse("assessment_artifact_download", args=[artifact.pk]))

        self.assertEqual(response.status_code, 404)


class KeepingTests(_MediaRoot):
    """Kept until deleted, and deleting takes the file too."""

    def test_deleting_a_build_deletes_its_file(self):
        artifact = self.built()
        path = Path(artifact.file.path)

        self.client.post(reverse("assessment_artifact_delete", args=[artifact.pk]))

        self.assertFalse(GeneratedArtifact.objects.exists())
        self.assertFalse(path.exists(), "the row went and left a client file on disk")

    def test_a_build_still_running_cannot_be_deleted(self):
        """Its thread would write the file after the row was gone, and nothing would list it."""
        artifact = artifact_store.open_workbook_build()

        self.client.post(reverse("assessment_artifact_delete", args=[artifact.pk]))

        self.assertTrue(GeneratedArtifact.objects.filter(pk=artifact.pk).exists())

    def test_an_interrupted_build_can_be_deleted(self):
        from optivedge.lifecycle import server_started

        artifact = artifact_store.open_workbook_build()
        server_started.send(sender=None)

        self.client.post(reverse("assessment_artifact_delete", args=[artifact.pk]))

        self.assertFalse(GeneratedArtifact.objects.exists())

    def test_discarding_its_run_keeps_the_build(self):
        """A reseed discards every run. A kept deliverable becomes stale; it does not vanish."""
        artifact = self.built()
        path = Path(artifact.file.path)

        AssessmentRun.objects.all().delete()

        artifact.refresh_from_db()
        self.assertIsNone(artifact.assessment_run)
        self.assertTrue(path.exists())


class StaleTests(_MediaRoot):
    def rows(self):
        return self.client.get(reverse("assessment_downloads")).context["rows"]

    def test_a_build_from_the_latest_run_is_not_stale(self):
        self.built()

        self.assertFalse(self.rows()[0]["stale"])

    def test_a_newer_run_flags_it_and_still_offers_it(self):
        """Flagged, not refused (Jason, 2026-10-14)."""
        artifact = self.built()
        regenerate_findings()

        response = self.client.get(reverse("assessment_downloads"))

        self.assertTrue(response.context["rows"][0]["stale"])
        self.assertContains(response, "data-artifact-stale")
        self.assertContains(response, reverse("assessment_artifact_download", args=[artifact.pk]))

    def test_a_build_whose_run_was_discarded_is_stale(self):
        self.built()
        AssessmentRun.objects.all().delete()

        self.assertTrue(self.rows()[0]["stale"])


class PageTests(_MediaRoot):
    def test_the_findings_summary_offers_a_build_and_the_downloads_page(self):
        response = self.client.get(reverse("assessment_findings_summary"))

        self.assertContains(response, reverse("assessment_workbook_build"))
        self.assertContains(response, reverse("assessment_downloads"))
        self.assertContains(response, "Build Workbook")

    def test_a_build_in_progress_is_polled_with_retries(self):
        """Static, because nothing here runs JavaScript - the same check as the controls page:
        a failed poll schedules the next one, and nothing reloads on a timer."""
        artifact = artifact_store.open_workbook_build()

        content = self.client.get(reverse("assessment_downloads")).content.decode()

        self.assertIn(f'data-artifact-build-in-progress="{artifact.pk}"', content)
        script = content[content.index("var shownBuild"):]
        script = script[:script.index("</script>")]
        self.assertRegex(script, r"\.catch\(function \(\) \{ setTimeout\(poll, 3000\); \}\)")
        self.assertNotRegex(script, r"setTimeout\(function \(\) \{ window\.location\.reload")

    def test_an_idle_page_does_not_poll(self):
        self.built()

        response = self.client.get(reverse("assessment_downloads"))

        self.assertNotContains(response, "data-artifact-build-in-progress")
        self.assertNotContains(response, reverse("assessment_downloads_status"))

    def test_the_status_names_the_build_in_progress(self):
        url = reverse("assessment_downloads_status")
        self.assertEqual(self.client.get(url).json(), {"building": None})

        artifact = artifact_store.open_workbook_build()
        self.assertEqual(self.client.get(url).json(), {"building": artifact.pk})

        artifact_store.fill_workbook(artifact)
        self.assertEqual(self.client.get(url).json(), {"building": None})
