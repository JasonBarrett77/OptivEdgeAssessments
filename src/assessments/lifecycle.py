"""What a findings run's lifetime is tied to, beyond the run itself.

**A run describes one normalization of the configuration, and dies with it** (Jason,
2026-10-15). Normalization deletes and recreates what it owns: rules cascade their findings
away, while device-wide settings are updated in place and keep findings that no longer describe
them. Either way the run is no longer about the configuration in the database. So when
OptivEdgeIntegrations announces a normalization, every run is discarded - the same rule a
catalog reseed already follows, which makes it symmetric: change either input to a run, the
catalog or the configuration, and the run goes. Builds on Downloads are kept, marked Stale,
because a deliverable is the engineer's to delete.

**A normalization is refused while a run or a build is in progress.** The run would compute
against objects being deleted under it, and the build would read tabs from two configurations.
The reverse - a run or a build refused while normalization runs - is in the views, through
`integration_work_in_progress`.

**A restart closes what it killed.** Runs and builds work on daemon threads, which die with the
server and leave their rows RUNNING or BUILDING. A two-hour age limit used to tell the dead from
the live, which locked Run Findings and Build Workbook for up to two hours after a crash, and
would have mistaken a genuine build longer than that - plausible on an engagement VDI - for a
dead one. An engagement runs ONE server process, so OptivEdge's `server_started`, sent on a new
process's first request, can close everything still marked as running.
"""

from __future__ import annotations

from django.db import transaction
from django.dispatch import receiver
from django.utils import timezone

from optivedge.lifecycle import server_started
from optivedge_integrations.integrations.lifecycle import (
    NormalizationRefused, normalization_starting)

from assessments.models import AssessmentRun, GeneratedArtifact

INTERRUPTED = "Interrupted: the server restarted before this finished."

#: Shown wherever there is no run to show. Without it an empty findings page reads as a clean
#: estate, which is the one wrong answer that looks like a right one.
NO_FINDINGS_RUN = (
    "No findings run since the configuration was last normalized or the catalog last applied, "
    "so nothing here has been assessed. Run Findings from Assessments > Controls.")


@receiver(server_started)
def close_interrupted_work(**kwargs) -> None:
    now = timezone.now()
    with transaction.atomic():
        AssessmentRun.objects.filter(status=AssessmentRun.Status.RUNNING).update(
            status=AssessmentRun.Status.FAILED, completed_at=now,
            notes=f"{INTERRUPTED} Run Findings again.")
        GeneratedArtifact.objects.filter(status=GeneratedArtifact.Status.BUILDING).update(
            status=GeneratedArtifact.Status.FAILED, completed_at=now,
            error=f"{INTERRUPTED} Build it again.")


@receiver(normalization_starting)
def discard_runs_before_normalization(management_station=None, **kwargs) -> None:
    from assessments.artifact_store import build_in_progress
    from assessments.finding_run import findings_run_in_progress

    # One transaction: under the engagement settings' IMMEDIATE mode it holds the write lock
    # from the check to the delete, so a run cannot open in between.
    with transaction.atomic():
        if findings_run_in_progress() is not None:
            raise NormalizationRefused(
                "A findings run is in progress. Normalize once it finishes - it is reading the "
                "configuration normalization would replace.")
        if build_in_progress() is not None:
            raise NormalizationRefused(
                "A workbook is being built. Normalize once it finishes - see Assessments > "
                "Downloads.")
        AssessmentRun.objects.all().delete()
