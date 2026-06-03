"""Catalog creation, seeding, and apply helpers."""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from assessments.controls_catalog.io.exporters import export_control_catalog
from assessments.controls_catalog.io.results import CatalogApplyResult, CatalogSeedResult
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
