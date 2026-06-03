# Controls Catalog

## Overview

The controls catalog subsystem stores reusable assessment control sets as local `Catalog` records.

For the MVP, `Catalog` is the authoritative source for reusable control content inside the app.

Live `Control` and `ControlQuery` rows remain the active working assessment data.

Applying a catalog replaces the live control set from the selected catalog payload.

## Current Shape

Current package:

```text
assessments/controls_catalog/
├── catalogs/
│   └── seed.json
├── io/
│   ├── exporters.py
│   ├── importers.py
│   ├── loaders.py
│   └── results.py
├── registry.py
└── schemas.py
```

Current local models:

```text
Catalog
ApplicationEnvironmentCatalogState
```

`Catalog` stores:

* stable `key`
* human-readable `label`
* `version`
* `description`
* portable catalog `payload`
* seeded/snapshot flags

`ApplicationEnvironmentCatalogState` stores the current catalog selection for the single deployment-scoped `ApplicationEnvironment` record without modifying framework-owned OptivEdge models in this repository.

## Seed Artifact

The repo-managed seed artifact is:

```text
assessments/controls_catalog/catalogs/seed.json
```

The seed artifact is developer-managed source data.

On first catalog access, if the local `Catalog` table is empty, the app loads all catalogs from this file into the database.

The seed artifact supports multiple catalogs:

```json
{
  "type": "optivedge.assessments.catalog_seed",
  "schema_version": "1.0",
  "catalogs": []
}
```

## Catalog Payload

Each `Catalog.payload` stores one portable catalog document:

```json
{
  "type": "optivedge.assessments.catalog",
  "schema_version": "1.0",
  "catalog": {
    "key": "base",
    "label": "Base Controls",
    "version": "1.0.0",
    "description": "Baseline controls."
  },
  "controls": []
}
```

Control identity:

```text
control_id
```

Control-query identity:

```text
control_id + query name
```

Canonical query payloads continue using Django model labels such as:

```text
integrations.SecurityRule
integrations.ManagementPlaneProfile
```

## Apply Behavior

Applying a catalog does the following:

1. Creates a snapshot catalog from the current live controls if any exist.
2. Deletes current assessment runs so stale findings do not survive a control reset.
3. Replaces live `Control` and `ControlQuery` rows from the selected catalog payload.
4. Updates the current catalog selection for the active `ApplicationEnvironment`.

The MVP uses full replace semantics, not merge semantics.

That means controls or queries not present in the selected catalog are removed from the live assessment state.

## Management Flow

Current management surfaces:

```text
/
/assessments/catalogs/
```

Current supported actions:

* view available catalogs
* apply a catalog
* create a new catalog from the current live controls
* download an individual catalog JSON payload
* download the multi-catalog seed JSON artifact shape

## Validation

Catalog validation checks:

* top-level type
* schema version
* catalog metadata
* duplicate catalog keys in the seed artifact
* duplicate control ids
* duplicate query names within a control
* valid control types
* valid severity values
* valid baseline severity behavior
* canonical query syntax using the existing assessment search validator

Invalid catalog payloads fail explicitly.

## Boundaries

This subsystem is local to `OptivEdgeAssessments`.

It does not move normalized integration models or framework settings into the downstream repo.

The only environment linkage added here is a local state model pointing to the framework-owned `ApplicationEnvironment`.
