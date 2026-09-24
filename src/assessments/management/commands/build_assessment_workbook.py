"""Write the engineer-detail workbook to a path.

The build itself returns bytes and knows nothing about the filesystem - see
`assessments.artifacts`. This is the way to run it without a browser, which is what a
consultant checking an estate before a delivery actually wants.
"""

from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from assessments.artifacts import ArtifactBuildError, build_workbook


class Command(BaseCommand):
    help = "Build the engineer-detail assessment workbook."

    def add_arguments(self, parser):
        parser.add_argument("path", help="where to write the .xlsx")
        parser.add_argument(
            "--quiet-report",
            action="store_true",
            help="write the file without printing what each sheet reported.",
        )

    def handle(self, *args, **options):
        try:
            content, reports = build_workbook()
        except ArtifactBuildError as exc:
            # A guard refused. The message names what did not add up; a traceback would bury it.
            raise CommandError(str(exc)) from exc

        path = Path(options["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

        self.stdout.write(self.style.SUCCESS(f"{path} ({len(content):,} bytes)"))
        if not options["quiet_report"]:
            for line in reports:
                self.stdout.write(f"  {line}")
