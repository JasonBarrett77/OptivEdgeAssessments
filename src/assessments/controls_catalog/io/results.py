"""Result objects for catalog seeding and apply workflows."""

from __future__ import annotations

from dataclasses import dataclass

from assessments.models import Catalog


@dataclass(frozen=True)
class CatalogSeedResult:
    catalogs_created: int


@dataclass(frozen=True)
class CatalogRefreshResult:
    catalogs_created: int
    catalogs_updated: int


@dataclass(frozen=True)
class CatalogApplyResult:
    catalog: Catalog
    snapshot_catalog: Catalog | None
    controls_created: int
    queries_created: int
    assessment_runs_deleted: int


@dataclass(frozen=True)
class CatalogReseedResult:
    """What a full reseed did. Every number is a deletion except the last two."""

    catalog: Catalog
    catalogs_refreshed: int
    catalogs_created: int
    snapshot_catalogs_deleted: int
    assessment_runs_deleted: int
    controls_deleted: int
    controls_created: int
    queries_created: int
