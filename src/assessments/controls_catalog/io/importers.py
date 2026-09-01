"""Catalog creation, seeding, and apply helpers."""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from assessments.controls_catalog.io.exporters import export_control_catalog
from assessments.controls_catalog.io.results import (
    CatalogApplyResult,
    CatalogRefreshResult,
    CatalogReseedResult,
    CatalogSeedResult,
)
from assessments.controls_catalog.registry import load_seed_payload
from assessments.controls_catalog.schemas import validate_catalog_payload
from assessments.models import (
    ApplicationEnvironmentCatalogState,
    AssessmentRun,
    Catalog,
    Control,
    ControlQuery,
)


def seed_catalogs_if_empty() -> CatalogSeedResult:
    if Catalog.objects.exists():
        return CatalogSeedResult(catalogs_created=0)

    seed_payload = load_seed_payload()
    created_count = 0
    for catalog_payload in seed_payload["catalogs"]:
        create_catalog_from_payload(
            catalog_payload,
            is_seeded=True,
            is_snapshot=False,
        )
        created_count += 1
    return CatalogSeedResult(catalogs_created=created_count)


def refresh_seeded_catalogs() -> CatalogRefreshResult:
    """Re-read the bundled catalog seed file from disk (same CATALOG_SEED_PATH used by
    seed_catalogs_if_empty()) and update the matching seeded Catalog row(s) in place.

    Unlike seed_catalogs_if_empty(), this runs regardless of whether catalogs already exist -
    it's the only way an edited seed.json ever reaches a database that's already been seeded
    once, since seed_catalogs_if_empty() is a permanent no-op after that first run.

    Updates the existing Catalog row in place (matched by key, e.g. "base") rather than
    delete-and-recreate, so its pk - and anything referencing it, such as
    ApplicationEnvironmentCatalogState.current_catalog - stays valid. Deliberately does not
    touch live Control/ControlQuery rows; use apply_catalog() on the refreshed catalog
    afterward to push its updated queries into live controls.
    """
    seed_payload = load_seed_payload()
    created_count = 0
    updated_count = 0
    for catalog_payload in seed_payload["catalogs"]:
        normalized_payload = validate_catalog_payload(catalog_payload)
        metadata = normalized_payload["catalog"]
        _catalog, created = Catalog.objects.update_or_create(
            key=metadata["key"],
            defaults={
                "label": metadata["label"],
                "version": metadata["version"],
                "description": metadata["description"],
                "payload": normalized_payload,
                "is_seeded": True,
            },
        )
        if created:
            created_count += 1
        else:
            updated_count += 1
    return CatalogRefreshResult(catalogs_created=created_count, catalogs_updated=updated_count)


def create_catalog_from_payload(
    payload: dict,
    *,
    is_seeded: bool = False,
    is_snapshot: bool = False,
) -> Catalog:
    normalized_payload = validate_catalog_payload(payload)
    metadata = normalized_payload["catalog"]
    return Catalog.objects.create(
        key=metadata["key"],
        label=metadata["label"],
        version=metadata["version"],
        description=metadata["description"],
        payload=normalized_payload,
        is_seeded=is_seeded,
        is_snapshot=is_snapshot,
    )


def create_catalog_from_current_controls(
    *,
    label: str,
    version: str,
    description: str,
    is_seeded: bool = False,
    is_snapshot: bool = False,
) -> Catalog:
    key = Catalog.generate_unique_key(label)
    payload = export_control_catalog(
        key=key,
        label=label,
        version=version,
        description=description,
    )
    return Catalog.objects.create(
        key=key,
        label=label,
        version=version,
        description=description,
        payload=payload,
        is_seeded=is_seeded,
        is_snapshot=is_snapshot,
    )


def apply_catalog(*, catalog: Catalog, application_environment) -> CatalogApplyResult:
    normalized_payload = validate_catalog_payload(catalog.payload)
    snapshot_catalog = None

    with transaction.atomic():
        if Control.objects.exists():
            snapshot_catalog = create_catalog_from_current_controls(
                label=f"Snapshot {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
                version="snapshot",
                description=f"Automatic snapshot created before applying catalog {catalog.label}.",
                is_snapshot=True,
            )

        assessment_runs_deleted = AssessmentRun.objects.count()
        if assessment_runs_deleted:
            AssessmentRun.objects.all().delete()

        Control.objects.all().delete()

        controls_created = 0
        queries_created = 0
        for control_payload in normalized_payload["controls"]:
            control = Control.objects.create(
                control_id=control_payload["control_id"],
                name=control_payload["name"],
                control_type=control_payload["control_type"],
                description=control_payload["description"],
                rationale=control_payload["rationale"],
                audit=control_payload["audit"],
                remediation=control_payload["remediation"],
                default_severity=control_payload["default_severity"],
                implementation_version=control_payload["implementation_version"],
                target_model=control_payload.get("target_model", ""),
                is_active=control_payload["is_active"],
            )
            controls_created += 1

            for query_payload in control_payload["queries"]:
                ControlQuery.objects.create(
                    control=control,
                    name=query_payload["name"],
                    short_description=query_payload["short_description"],
                    canonical_query=query_payload["canonical_query"],
                    is_baseline=query_payload["is_baseline"],
                    adjusted_severity=query_payload["adjusted_severity"],
                    is_active=query_payload["is_active"],
                )
                queries_created += 1

        if application_environment is not None:
            state, _created = ApplicationEnvironmentCatalogState.objects.get_or_create(
                application_environment=application_environment,
            )
            state.current_catalog = catalog
            state.save(update_fields=["current_catalog", "updated_at"])

    return CatalogApplyResult(
        catalog=catalog,
        snapshot_catalog=snapshot_catalog,
        controls_created=controls_created,
        queries_created=queries_created,
        assessment_runs_deleted=assessment_runs_deleted,
    )


def reseed_from_bundled_catalog(*, application_environment) -> CatalogReseedResult:
    """Re-read the bundled seed file and make the live controls match it, in one step.

    Refresh alone only rewrites the stored Catalog payload; the live controls keep whatever
    they had, and applying them separately fails outright once any of them references a
    search field that no longer exists - `apply_catalog` snapshots the live controls first
    and validates that snapshot. Recovering from that needed a database shell, which is the
    wrong place for a routine seed update to end up.

    So this deletes rather than preserves, deliberately:

        assessment runs      every finding with them, by cascade. They are derived from the
                             controls being replaced, so keeping them would leave findings
                             citing controls that no longer exist.
        controls             all of them. `apply_catalog` recreates every one from the
                             catalog, so the ones deleted here were about to be replaced -
                             and with none left, the pre-apply snapshot is skipped rather
                             than built from controls nobody wants.
        snapshot catalogs    a snapshot taken before a stale apply cannot be applied either,
                             since it captured the same dead field. They read as rollback
                             points and are not.

    Nothing here touches the collected configuration. `Snapshot` in OptivEdgeIntegrations -
    the merged-config payloads - is a different model with the same word in its name, and
    losing it would mean re-collecting from every device.
    """
    refresh = refresh_seeded_catalogs()

    seeded = list(Catalog.objects.filter(is_seeded=True, is_snapshot=False))
    if not seeded:
        raise ValueError("the bundled seed file defines no catalog to apply")
    if len(seeded) > 1:
        raise ValueError(
            "the bundled seed file defines more than one catalog "
            f"({', '.join(c.key for c in seeded)}); applying one would discard the others, "
            "so this must be done per catalog rather than as a reseed")
    catalog = seeded[0]

    with transaction.atomic():
        runs_deleted = AssessmentRun.objects.count()
        AssessmentRun.objects.all().delete()

        controls_deleted = Control.objects.count()
        Control.objects.all().delete()

        snapshots_deleted = Catalog.objects.filter(is_snapshot=True).count()
        Catalog.objects.filter(is_snapshot=True).delete()

        applied = apply_catalog(
            catalog=catalog, application_environment=application_environment)

    return CatalogReseedResult(
        catalog=catalog,
        catalogs_refreshed=refresh.catalogs_updated,
        catalogs_created=refresh.catalogs_created,
        snapshot_catalogs_deleted=snapshots_deleted,
        assessment_runs_deleted=runs_deleted,
        controls_deleted=controls_deleted,
        controls_created=applied.controls_created,
        queries_created=applied.queries_created,
    )
