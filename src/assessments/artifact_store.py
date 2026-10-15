"""Building client deliverables in the background, and keeping them.

`artifacts.build_workbook()` returns bytes and knows nothing about the filesystem, on purpose:
"the caller decides whether that is a download, a stored artifact or a test." This module is
the stored-artifact caller. It opens a `GeneratedArtifact` row, builds on a thread, writes the
file under MEDIA_ROOT, and records what happened on the row - which is the only place a
background build can report to.

Jason, 2026-10-14, on the three decisions this rests on:

* KEPT until somebody deletes it - nothing is pruned
* a workbook built from an older findings run is FLAGGED stale, not refused
* a build and a findings run REFUSE each other, both ways

The last is not caution for its own sake. `build_workbook` reads some thirty tables one after
another, not as one snapshot, and every findings generator deletes and recreates its whole
table. A run that lands mid-build hands the later tabs a different run's findings than the
earlier ones, and the workbook's own guards either refuse it or - worse - pass a file whose tabs
disagree. A single read transaction would give the build a snapshot, but the engagement settings
use `transaction_mode: IMMEDIATE`, under which every transaction takes the WRITE lock, so the
build would hold Run Findings off for its whole length instead. Refusing is the honest version.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.files.base import ContentFile
from django.db import connections
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.utils import timezone

from assessments.artifacts import ArtifactBuildError, build_workbook
from assessments.artifacts.naming import workbook_filename
from assessments.environment import get_application_environment
from assessments.models import AssessmentRun, GeneratedArtifact

logger = logging.getLogger(__name__)

#: A BUILDING row younger than this blocks another build, and a findings run. Older ones are
#: orphans: the worker is a daemon thread, so a server restart mid-build kills it and leaves the
#: row BUILDING for ever. Same reasoning and figure as `finding_run.FINDINGS_LOCK_MAX_AGE`.
BUILD_LOCK_MAX_AGE = timedelta(hours=2)


def require_media_root() -> None:
    """Refuse rather than write a client deliverable somewhere nobody chose.

    MEDIA_ROOT belongs to the host project and defaults to the empty string, which
    FileSystemStorage reads as the server process's working directory - a client file would
    land wherever `manage.py` happened to be started.
    """
    if not settings.MEDIA_ROOT:
        raise ImproperlyConfigured(
            "MEDIA_ROOT is not set, so there is nowhere to keep a built workbook. Set it in the "
            "host project's settings.py - see DEPLOYMENT.md.")


def build_in_progress() -> GeneratedArtifact | None:
    """The build currently running, or None. Orphans are ignored, not resumed."""
    return (GeneratedArtifact.objects
            .filter(status=GeneratedArtifact.Status.BUILDING,
                    requested_at__gte=timezone.now() - BUILD_LOCK_MAX_AGE)
            .first())


def is_orphaned(artifact: GeneratedArtifact) -> bool:
    """A BUILDING row its worker will never finish - see BUILD_LOCK_MAX_AGE."""
    return (artifact.status == GeneratedArtifact.Status.BUILDING
            and artifact.requested_at < timezone.now() - BUILD_LOCK_MAX_AGE)


def findings_run_of_record() -> AssessmentRun | None:
    """The run the stored findings belong to - what a workbook built now is built FROM.

    Read off the findings, not assumed to be the newest run: a run that failed part-way leaves
    the earlier generators' findings in place, and the newest COMPLETED run is only the right
    answer when nothing contradicts it. Several runs means the tables are mixed, and the
    workbook's own guard refuses that; it is recorded as the newest of them meanwhile.
    """
    from assessments.finding_registry import FINDING_KINDS

    run_ids = set()
    for kind in FINDING_KINDS:
        run_ids.update(kind.model.objects.values_list("assessment_run_id", flat=True).distinct())
    if run_ids:
        return AssessmentRun.objects.filter(pk__in=run_ids).order_by("-pk").first()
    return (AssessmentRun.objects.filter(status=AssessmentRun.Status.COMPLETED)
            .order_by("-pk").first())


def open_workbook_build() -> GeneratedArtifact:
    """The row, BUILDING, before the thread starts - so the page it redirects to can show it."""
    return GeneratedArtifact.objects.create(
        kind=GeneratedArtifact.Kind.WORKBOOK,
        status=GeneratedArtifact.Status.BUILDING,
        assessment_run=findings_run_of_record(),
        filename=workbook_filename(get_application_environment()),
    )


def fill_workbook(artifact: GeneratedArtifact) -> GeneratedArtifact:
    """Build the workbook and store it on `artifact`, or record why it was not built.

    A guard refusing is a FAILED row carrying the guard's sentence, not an exception: a
    background build has no request to raise into, and "the workbook would have been wrong,
    because X" is precisely what the reader needs to see on the downloads page.
    """
    try:
        content, _reports = build_workbook()
    except ArtifactBuildError as exc:
        return _fail(artifact, f"The workbook was not built: {exc}")
    except Exception as exc:
        logger.exception("Workbook build %s failed", artifact.pk)
        return _fail(artifact, f"The workbook build failed: {type(exc).__name__}: {exc}")

    artifact.file.save(artifact.filename, ContentFile(content), save=False)
    artifact.size = len(content)
    artifact.status = GeneratedArtifact.Status.READY
    artifact.completed_at = timezone.now()
    artifact.save(update_fields=["file", "size", "status", "completed_at"])
    return artifact


def _fail(artifact: GeneratedArtifact, message: str) -> GeneratedArtifact:
    artifact.status = GeneratedArtifact.Status.FAILED
    artifact.error = message[:2000]
    artifact.completed_at = timezone.now()
    artifact.save(update_fields=["status", "error", "completed_at"])
    return artifact


def build_workbook_in_background(artifact_pk: int) -> None:
    """Thread entry point. Takes a pk, not the instance: the thread has its own connection.

    Mirrors `views._run_findings_in_background`, down to closing the connection: a thread that
    leaves one open holds it for the life of the process.
    """
    try:
        fill_workbook(GeneratedArtifact.objects.get(pk=artifact_pk))
    except Exception:
        logger.exception("Background workbook build %s failed", artifact_pk)
    finally:
        connections.close_all()


@receiver(post_delete, sender=GeneratedArtifact)
def delete_the_file_with_the_row(sender, instance, **kwargs):
    """Django deletes the row and leaves the file. For a client deliverable that is the one
    outcome worse than either keeping or deleting it: a file nothing lists any more."""
    if instance.file:
        instance.file.delete(save=False)
