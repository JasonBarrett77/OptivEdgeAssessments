"""`profile_assessment_workbook`: the measurements from an environment reached only by pip.

Production took about three minutes to build what the lab builds in 7.6s (2026-10-14), and the
only way in is `pip install`. So the command has to run anywhere the package does and leave a
file behind - these pin that it does, that it writes nothing else, and that a refused build is
reported in the file rather than lost to a traceback.
"""

from __future__ import annotations

import io
import shutil
import tempfile
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.test import TestCase

from assessments.artifacts import ArtifactBuildError
from assessments.finding_run import regenerate_findings
from assessments.models import GeneratedArtifact
from assessments.tests._seed import seed_controls
from assessments.tests.test_findings_views import build_estate


class ProfileWorkbookCommandTests(TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="oea-profile-"))
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        self.report = self.directory / "profile.txt"
        build_estate()
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()

    def run_command(self, *args):
        call_command("profile_assessment_workbook", str(self.report), *args, stdout=io.StringIO())
        return self.report.read_text(encoding="utf-8")

    def test_it_writes_a_line_per_sheet_and_a_total(self):
        text = self.run_command()

        self.assertIn("Login Banner", text)
        self.assertRegex(text, r"\nTOTAL\s+\d+\.\d\d")
        self.assertIn("findings=", text)
        self.assertNotIn("STOPPED", text)

    def test_it_stores_nothing(self):
        """Safe on a live engagement: no build row, no file but the report."""
        self.run_command()

        self.assertFalse(GeneratedArtifact.objects.exists())
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()), ["profile.txt"])

    def test_the_profile_lists_where_the_time_went(self):
        text = self.run_command("--profile")

        self.assertIn("slowest in themselves", text)
        self.assertRegex(text, r"assessments/artifacts/sheets/findings\.py:\d+\(")
        self.assertNotIn("List reduced", text)

    def test_a_refused_build_is_reported_in_the_file(self):
        with mock.patch("assessments.artifacts.workbook.check_every_finding_reached_a_tab",
                        side_effect=ArtifactBuildError("3 findings are on a tab but 4 exist")):
            text = self.run_command()

        self.assertIn("STOPPED  ArtifactBuildError: 3 findings are on a tab but 4 exist", text)
        self.assertIn("TOTAL", text)
