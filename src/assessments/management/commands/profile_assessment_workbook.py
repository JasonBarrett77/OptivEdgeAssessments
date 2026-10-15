"""Time the workbook build, sheet by sheet, and write what was measured to a text file.

Built for an environment nobody can attach a profiler to: production, reached only through
`pip install`, where Build Workbook took about three minutes against 7.6s on the lab
(2026-10-14). The file is meant to be read off a screen, so it is short and fixed-width.

It builds the workbook exactly as Build Workbook does, and keeps nothing: no file is stored, no
row is written, so it is safe to run against a live engagement. Run it while nothing else is
writing - a findings run mid-way would hand later sheets a different run's findings, which is
what `artifact_store` refuses to let a real build do.

`--profile` adds the functions the time went to. It slows the build two or three times over, so
its sheet timings are inflated; run once without it for the timings, once with it for where.
"""

from __future__ import annotations

import cProfile
import io
import json
import os
import platform
import pstats
import sqlite3
import sys
import time
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

import django
import xlsxwriter
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection

PACKAGES = ("optivedge", "optivedge-integrations", "optivedge-assessments")


def package_line(name: str) -> str:
    """Version, and the commit when pip recorded one - which is what says the code is current."""
    try:
        dist = metadata.distribution(name)
    except metadata.PackageNotFoundError:
        return f"{name}: not installed"
    detail = ""
    try:
        direct = json.loads(dist.read_text("direct_url.json") or "{}")
        commit = direct.get("vcs_info", {}).get("commit_id")
        if commit:
            detail = f" @ {commit[:7]}"
        elif direct.get("dir_info", {}).get("editable"):
            detail = " (editable)"
    except (ValueError, OSError):
        pass
    return f"{name} {dist.version}{detail}"


def tail(value, width: int = 64) -> str:
    """The END of a path, which is the part that says where it is."""
    text = str(value)
    return text if len(text) <= width else "..." + text[-(width - 3):]


def short_where(where: str) -> str:
    for marker in ("site-packages", "src"):
        separator = f"{os.sep}{marker}{os.sep}"
        if separator in where:
            return where.split(separator, 1)[1]
    return where


def peak_memory_mb() -> str:
    try:
        import resource
    except ImportError:  # Windows
        return "n/a"
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return f"{peak / (1024 * 1024 if sys.platform == 'darwin' else 1024):.0f} MB"


class Command(BaseCommand):
    help = "Time the assessment workbook build per sheet and write the measurements to a file."

    def add_arguments(self, parser):
        parser.add_argument(
            "path", nargs="?",
            help="where to write the report (default: workbook-profile-<UTC time>.txt here)")
        parser.add_argument(
            "--profile", action="store_true",
            help="also list the functions the time went to (slows the build 2-3x)")

    def handle(self, *args, **options):
        from assessments import finding_registry
        from assessments.artifacts import workbook as wb
        from assessments.artifacts.context import WorkbookBuild
        from assessments.artifacts.layout import SUMMARY_TITLE
        from assessments.models import AssessmentRun
        from optivedge_integrations.integrations.models import (
            Appliance, EnforcementPoint, SecurityRule)

        now = datetime.now(timezone.utc)
        path = Path(options["path"] or f"workbook-profile-{now:%Y%m%d-%H%M%S}.txt")
        lines = []
        out = lines.append

        out(f"WORKBOOK PROFILE  {now:%Y-%m-%d %H:%M:%S} UTC"
            + ("  (--profile: timings inflated)" if options["profile"] else ""))
        out(f"host     {platform.platform()[:60]}  cpus={os.cpu_count()}")
        out(f"python   {platform.python_version()}  django {django.get_version()}"
            f"  sqlite {sqlite3.sqlite_version}")
        for name in PACKAGES:
            out(f"package  {package_line(name)}")

        db = connection.settings_dict
        out(f"database {db['ENGINE'].rsplit('.', 1)[-1]}  {tail(db['NAME'])}")
        if connection.vendor == "sqlite":
            size = Path(db["NAME"]).stat().st_size if Path(str(db["NAME"])).exists() else 0
            with connection.cursor() as cursor:
                pragmas = {}
                for pragma in ("journal_mode", "synchronous", "busy_timeout", "cache_size"):
                    cursor.execute(f"PRAGMA {pragma}")
                    pragmas[pragma] = cursor.fetchone()[0]
            out(f"         {size / 1048576:.0f} MB  " + "  ".join(f"{k}={v}" for k, v in pragmas.items()))
        out(f"media    {tail(settings.MEDIA_ROOT) if settings.MEDIA_ROOT else '(MEDIA_ROOT not set)'}")

        by_kind = sorted(((kind.model.objects.count(), kind.model.__name__)
                          for kind in finding_registry.FINDING_KINDS), reverse=True)
        run = AssessmentRun.objects.order_by("-pk").first()
        out(f"estate   findings={sum(c for c, _ in by_kind):,}  rules={SecurityRule.objects.count():,}"
            f"  appliances={Appliance.objects.count():,}"
            f"  points={EnforcementPoint.objects.count():,}")
        out("         largest: " + ", ".join(f"{name.removesuffix('Finding')} {count:,}"
                                             for count, name in by_kind[:4] if count))
        if run is not None:
            finished = f"{run.completed_at:%Y-%m-%d %H:%M} UTC" if run.completed_at else "-"
            out(f"run      {run.pk} {run.status}, finished {finished}")
        out("")
        out(f"{'sheet':38s} {'seconds':>8s} {'queries':>8s} {'rows':>7s}")

        queries = [0]

        def count(execute, sql, params, many, context):
            queries[0] += 1
            return execute(sql, params, many, context)

        profiler = cProfile.Profile() if options["profile"] else None
        book = xlsxwriter.Workbook(io.BytesIO(), {"in_memory": True})
        build = WorkbookBuild(workbook=book)
        summary = book.add_worksheet(SUMMARY_TITLE)
        infos = []
        started = time.perf_counter()
        error = None
        try:
            with connection.execute_wrapper(count):
                if profiler:
                    profiler.enable()
                for sheet in wb.SHEETS:
                    queries[0] = 0
                    t = time.perf_counter()
                    info = getattr(sheet, "write_sheet", sheet)(build)
                    infos.append(info)
                    rows = (sum(info.by_severity.values()) if info.by_severity
                            else info.count.split(" ")[0])
                    out(f"{info.title[:38]:38s} {time.perf_counter() - t:8.2f} {queries[0]:8,d}"
                        f" {rows:>7}")
                queries[0] = 0
                t = time.perf_counter()
                wb.check_every_finding_reached_a_tab(infos)
                wb.check_tabs_follow_the_summary(infos)
                wb.summary_sheet.write_sheet(build, summary, infos)
                out(f"{'(checks and Summary)':38s} {time.perf_counter() - t:8.2f} {queries[0]:8,d}")
                t = time.perf_counter()
                book.close()
                out(f"{'(write file)':38s} {time.perf_counter() - t:8.2f}")
        except Exception as exc:
            # The point is the measurements; a refusal part-way is one more of them.
            error = f"{type(exc).__name__}: {exc}"
        finally:
            if profiler:
                profiler.disable()

        out(f"{'TOTAL':38s} {time.perf_counter() - started:8.2f}   peak memory {peak_memory_mb()}")
        if error:
            out(f"STOPPED  {error[:200]}")

        if profiler:
            out("")
            out("slowest in themselves (tottime)")
            for seconds, calls, where in self.top(profiler, "tottime", 10):
                out(f"  {seconds:7.2f}s {calls:>12s} calls  {where[:52]}")
            out("")
            out("slowest including what they call (cumtime), this stack's own code")
            for seconds, calls, where in self.top(profiler, "cumulative", 12,
                                                  r"assessments|optivedge"):
                out(f"  {seconds:7.2f}s {calls:>12s} calls  {where[:52]}")

        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.stdout.write("\n".join(lines))
        self.stdout.write(self.style.SUCCESS(f"\nWritten to {path.resolve()}"))

    @staticmethod
    def top(profiler, key: str, limit: int, restrict: str | None = None):
        """(seconds, calls, where) for the top entries, read off `pstats`' own table."""
        stream = io.StringIO()
        stats = pstats.Stats(profiler, stream=stream).sort_stats(key)
        stats.print_stats(*([restrict] if restrict else []), limit)
        column = 3 if key == "cumulative" else 1
        rows = []
        for raw in stream.getvalue().splitlines():
            parts = raw.split(None, 5)
            # A row starts with its call count. "List reduced from ..." and the summary line
            # above the header also split into six words, and would parse as one.
            if len(parts) != 6 or not parts[0][0].isdigit():
                continue
            try:
                seconds = float(parts[column])
            except ValueError:  # the header, and the summary line above it
                continue
            rows.append((seconds, parts[0], short_where(parts[5])))
        return rows
