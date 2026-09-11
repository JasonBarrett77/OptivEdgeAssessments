"""Refresh the bundled seed into the stored catalog and apply it, in one step.

Why this exists as a command rather than the two buttons in the UI: removing a search field
makes every stored query that used it invalid, and `apply_catalog` snapshots the LIVE
controls before replacing them - a snapshot it validates. So the moment a control goes
stale, applying the catalog that would fix it fails on the snapshot, and the UI offers no
way out. Recovery needed a database shell, which is the wrong place for a routine seed
update to end up.

The order matters and is not obvious:

    1. refresh   the stored Catalog payload is a COPY taken when the database was first
                 seeded. `seed_catalogs_if_empty()` is a permanent no-op afterwards, so an
                 edited seed.json never reaches an already-seeded database without this.
    2. unblock   delete the stale controls, and the findings that reference them - the
                 finding FK to Control is PROTECT, so the findings must go first.
    3. apply     now the snapshot builds from the controls that remain, and succeeds.

Reports and changes nothing unless --apply is given.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from assessments.controls_catalog.io.importers import (
    reseed_from_bundled_catalog,
    seed_catalogs_if_empty,
)
from assessments.controls_catalog.registry import load_seed_payload
from assessments.environment import get_application_environment
from assessments.models import (
    AssessmentRun,
    Catalog,
    Control,
)
from assessments.finding_registry import FINDING_MODELS as REGISTERED_FINDING_MODELS
from assessments.search.syntax import validate_search_payload

#: Every model whose FK to Control is PROTECT. A stale control cannot be deleted while any
#: of these reference it, and the error names only the first one it hits, so they are all
#: cleared rather than discovered one failed delete at a time.
#:
#: FROM THE REGISTRY, not listed. The hand-kept tuple named three of eighteen, so replacing a
#: control with a certificate, authentication or administrator finding would have failed on
#: the PROTECT this list exists to get past - the drift `finding_registry` was built to stop.
FINDING_MODELS = REGISTERED_FINDING_MODELS


def stale_controls() -> dict[str, list[str]]:
    """{control_id: [reasons]} for every live control whose stored query no longer validates.

    A query goes stale when a search field it names is removed. Nothing detects this at
    removal time, because the queries live in the database rather than in code.
    """
    stale: dict[str, list[str]] = {}
    for control in Control.objects.prefetch_related("queries").order_by("control_id"):
        for query in control.queries.all():
            try:
                validate_search_payload(query.canonical_query)
            except Exception as exc:  # noqa: BLE001 - any validation failure blocks the apply
                stale.setdefault(control.control_id, []).append(f"{query.name}: {exc}")
    return stale


class Command(BaseCommand):
    help = (
        "Refresh the stored controls catalog from the bundled seed file and apply it, "
        "clearing controls whose stored queries reference fields that no longer exist."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply", action="store_true",
            help="Actually make the changes. Without this the command only reports.")
        parser.add_argument(
            "--catalog-key", default="base",
            help="Key of the catalog to apply (default: base).")
        parser.add_argument(
            "--regenerate-findings", action="store_true",
            help="Regenerate configuration findings after applying.")

    def handle(self, *args, **options):
        apply_changes = options["apply"]
        key = options["catalog_key"]

        seed_catalogs_if_empty()

        try:
            catalog = Catalog.objects.get(key=key)
        except Catalog.DoesNotExist as exc:
            raise CommandError(
                f"No catalog with key {key!r}. Available: "
                f"{sorted(Catalog.objects.values_list('key', flat=True)) or 'none'}") from exc

        blocked = stale_controls()
        if blocked:
            self.stdout.write(self.style.WARNING(
                f"\n{len(blocked)} live control(s) reference fields that no longer exist. "
                f"These block the pre-apply snapshot:"))
            for control_id, reasons in blocked.items():
                for reason in reasons:
                    self.stdout.write(f"    {control_id}  {reason}")
        else:
            self.stdout.write("\nNo stale controls; the pre-apply snapshot will build cleanly.")

        # Compare against what --apply WOULD install, not what is stored. The stored payload
        # is a copy taken at first seed and is only replaced by the refresh step above, so a
        # dry run reading it would report "no changes" in exactly the environments that most
        # need this command - ones seeded before the seed file was edited.
        # Always compare against the bundled seed file, never the stored payload: the stored
        # one is a copy taken at first seed, so reading it would report "no changes" in
        # exactly the environments this exists for.
        source = "the bundled seed file"
        payload = next(
            (c for c in load_seed_payload()["catalogs"] if c["catalog"]["key"] == key), None)
        if payload is None:
            raise CommandError(f"The bundled seed file defines no catalog with key {key!r}.")
        payload_ids = [c["control_id"] for c in payload.get("controls", [])]
        live_ids = sorted(Control.objects.values_list("control_id", flat=True))
        self.stdout.write(
            f"\n{source} defines {len(payload_ids)} control(s); {len(live_ids)} are live.")
        for control_id in sorted(set(payload_ids) - set(live_ids)):
            self.stdout.write(self.style.SUCCESS(f"    + {control_id}"))
        for control_id in sorted(set(live_ids) - set(payload_ids)):
            self.stdout.write(self.style.WARNING(f"    - {control_id}"))

        runs = AssessmentRun.objects.count()
        if not apply_changes:
            self.stdout.write(self.style.WARNING(
                f"\nDry run. Re-run with --apply to refresh and apply. Applying deletes all "
                f"{runs} assessment run(s) and their findings - that is what apply_catalog "
                f"does, not something this command adds."))
            return

        outcome = reseed_from_bundled_catalog(
            application_environment=(environment := get_application_environment()))
        self.stdout.write(self.style.SUCCESS(
            f"Reseeded {outcome.catalog.key} ({outcome.catalog.version}): "
            f"{outcome.controls_created} controls, {outcome.queries_created} queries. "
            f"Discarded {outcome.controls_deleted} control(s), "
            f"{outcome.assessment_runs_deleted} assessment run(s) and "
            f"{outcome.snapshot_catalogs_deleted} snapshot catalog(s)."))
        if environment is None:
            self.stdout.write(self.style.WARNING(
                "No application environment configured, so the catalog was applied but not "
                "recorded as current."))

        if options["regenerate_findings"]:
            from assessments.configuration_findings import regenerate_configuration_findings
            findings = regenerate_configuration_findings()
            self.stdout.write(self.style.SUCCESS(
                f"Regenerated findings: {findings.controls_evaluated} controls evaluated, "
                f"{findings.findings_created} findings, {findings.skipped_queries} skipped."))
