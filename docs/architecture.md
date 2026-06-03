# Architecture

## Overview

`OptivEdgeAssessments` is a downstream Django project built on the `OptivEdge` framework.

The project provides assessment workflows on top of normalized firewall integration data. It does not own vendor collection, vendor API communication, or normalized firewall data models. Those responsibilities belong to the installed OptivEdge framework package.

The primary architectural split is:

```text
OptivEdge
├── framework shell
├── shared templates and template tags
├── integration app
├── normalized firewall data models
├── PAN-OS collection
└── PAN-OS normalization

OptivEdgeAssessments
├── assessment controls
├── control queries
├── finding generation
├── assessment search and filtering
├── report exports
├── control catalogs
└── assessment-specific UI
```

## Dependency Boundary

`OptivEdgeAssessments` consumes OptivEdge as an installed Python dependency.

Typical dependency declaration:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.0#egg=optivedge
```

During active development, `@main` may be used temporarily, but repeatable installs should use a tag or commit SHA.

The downstream project should not assume the OptivEdge source repository is present locally. A local editable install may be used for framework development, but it should not be committed to `requirements.txt`.

## Application Boundaries

### OptivEdge

OptivEdge owns framework and integration concerns:

* Django framework composition
* shared shell layout
* shared templates
* shared template tags
* shared integration-facing routes and views
* vendor API session handling
* PAN-OS XML API collection
* raw integration persistence
* normalized firewall data models
* normalized security rule data
* normalized address object and address group data
* normalized management-plane data
* future vendor integrations

Changes to these areas should normally be made in the `OptivEdge` repository.

### OptivEdgeAssessments

`OptivEdgeAssessments` owns assessment workflow concerns:

* assessment controls
* control queries
* canonical query evaluation
* security-rule findings
* management-plane findings
* assessment runs
* assessment search/filtering UX
* report context shaping
* Word and Excel report generation
* control catalog import/export
* assessment-specific views
* assessment-specific templates

The local app is:

```text
assessments/
```

## Core Rule

Assessment code should consume normalized OptivEdge data.

It should not call vendor APIs directly.

Correct pattern:

```text
PAN-OS API
  → OptivEdge collection
  → OptivEdge persistence
  → OptivEdge normalization
  → normalized OptivEdge models
  → OptivEdgeAssessments controls/findings/reports
```

Incorrect pattern:

```text
OptivEdgeAssessments
  → PAN-OS API
```

## Data Flow

### 1. Collection

Collection is owned by OptivEdge.

Examples:

* PAN-OS API session handling
* Panorama inventory collection
* merged configuration retrieval
* pushed policy retrieval
* future vendor collection endpoints

Assessment modules should not implement collection logic.

### 2. Persistence

Raw integration persistence is owned by OptivEdge.

Examples:

* source snapshots
* collected response payloads
* collection metadata
* sync run records

Assessment modules may reference persisted normalized records but should not own raw vendor persistence.

### 3. Normalization

Normalization is owned by OptivEdge.

Examples:

* management stations
* appliances
* appliance groups
* enforcement points
* security rules
* address objects
* address groups
* management-plane profiles

Assessment code should treat these as authoritative source data.

### 4. Assessment

Assessment behavior is owned by `OptivEdgeAssessments`.

Examples:

* defining controls
* defining control queries
* applying canonical queries
* generating findings
* rendering assessment views
* exporting reports
* importing/exporting control catalogs

## Canonical Query Boundary

Assessment search and control-query payloads use stable Django model labels.

Correct canonical model labels:

```text
integrations.SecurityRule
integrations.ManagementPlaneProfile
```

These are not Python import paths.

Correct Python imports use the installed OptivEdge package:

```python
from optivedge.integrations.models import SecurityRule
from optivedge.integrations.models import ManagementPlaneProfile
```

Do not convert canonical model labels to `optivedge.integrations...`.

The stable model-label boundary allows assessment query payloads, saved control queries, and exported catalogs to remain portable even though the Python package path is `optivedge.integrations`.

## Assessment Models

The local `assessments` app owns assessment-specific models, including:

* `Control`
* `ControlQuery`
* `AssessmentRun`
* `SecurityRuleSearchState`
* `RuleFinding`
* `RuleFindingControlQuery`
* `ManagementPlaneFinding`
* `ManagementPlaneFindingControlQuery`

These models represent assessment workflow state, not raw integration data.

## Controls and Control Queries

A `Control` defines the assessment requirement.

A `ControlQuery` defines one canonical query used to identify matching normalized data.

A control may have multiple queries.

Common query types:

```text
security rule query
management-plane query
```

Default identity rules:

```text
Control identity: control_id
ControlQuery identity: control_id + query name
```

These identity rules should also be used by import/export workflows.

## Finding Generation

Finding generation is local to `OptivEdgeAssessments`.

Current finding families:

```text
RuleFinding
ManagementPlaneFinding
```

Finding generation should:

* read active controls
* evaluate active control queries
* match against normalized OptivEdge data
* create assessment runs
* create finding records
* preserve links between findings and matched control queries

Finding generation should not mutate normalized OptivEdge integration data.

## Reporting

Reporting is local to `OptivEdgeAssessments`.

Reporting modules own:

* finding rollups
* report context shaping
* Word document rendering
* Excel workbook rendering
* report export views

Reporting should consume:

* assessment findings
* assessment runs
* controls
* normalized OptivEdge records needed for report context

Reporting should not perform vendor collection or normalization.

## Control Catalogs

Control catalog functionality belongs under:

```text
assessments/controls_catalog/
```

Recommended structure:

```text
assessments/controls_catalog/
├── catalogs/
├── io/
├── registry.py
└── schemas.py
```

The control catalog subsystem owns:

* exporting existing controls and control queries
* importing catalog payloads
* loading bundled catalogs
* validating catalog shape
* supporting multiple catalog variants
* supporting future industry-specific catalogs

Potential catalog examples:

```text
base
banking
health_insurance
```

Catalog files should use stable application-level identifiers, not database primary keys.

Default import behavior should be idempotent:

* create missing controls
* update existing controls
* create missing queries
* update existing queries
* do not delete missing records

Pruning, deactivation, or destructive synchronization should require explicit design and user confirmation.

## UI Architecture

The UI uses the OptivEdge shell and shared template system.

Assessment templates should extend the shared shell rather than creating a second shell.

Assessment UI owns:

* controls list/detail workflows
* control-query CRUD workflows
* security-rule assessment views
* plain-language query workflows
* findings views
* report export actions
* future control catalog views

Shared UI rules are documented separately:

* `docs/style-standard.md`
* `docs/ux-decision-rules.md`
* `docs/design-tokens.md`
* `docs/component-spec.md`
* `docs/ui-open-questions.md`

## URL Composition

The downstream project root URL configuration includes OptivEdge URLs:

```python
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("", include("optivedge.urls")),
    path("admin/", admin.site.urls),
]
```

The `assessments` app is mounted through its app metadata:

```python
URL_MOUNT = {
    "prefix": "assessments/",
    "module": "assessments.urls",
}
```

This keeps app-local routes owned by the app while allowing OptivEdge to compose installed app navigation and URL mounts.

## App Metadata

`assessments/app_meta.py` exposes optional app metadata consumed by OptivEdge.

Current responsibilities:

* mount assessment URLs
* expose assessment sidebar navigation

This metadata should remain small and declarative.

Do not put business logic in `app_meta.py`.

## Package Layout

Expected project structure:

```text
OptivEdgeAssessments/
├── AGENTS.md
├── README.md
├── requirements.txt
├── manage.py
├── config/
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
├── assessments/
│   ├── app_meta.py
│   ├── apps.py
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── control_queries.py
│   ├── findings.py
│   ├── management_findings.py
│   ├── search/
│   ├── reporting/
│   ├── plain_language/
│   └── controls_catalog/
└── templates/
    └── assessments/
```

## Module Responsibilities

### `assessments/models.py`

Owns assessment workflow persistence.

### `assessments/control_queries.py`

Owns shared control-query evaluation helpers.

### `assessments/findings.py`

Owns security-rule finding regeneration.

### `assessments/management_findings.py`

Owns management-plane finding regeneration.

### `assessments/search/`

Owns canonical query parsing, validation, compilation, and model-specific field behavior.

### `assessments/plain_language/`

Owns plain-language-to-canonical-query workflows.

### `assessments/reporting/`

Owns report context shaping and artifact rendering.

### `assessments/controls_catalog/`

Owns control catalog import, export, validation, loading, and bundled catalog data.

### `assessments/views.py`

Owns request/response coordination for assessment views.

Views should remain thin. Move reusable behavior into focused modules.

## Development Guidance

Prefer simple, explicit module boundaries.

Avoid abstractions that are not yet justified by multiple real use cases.

When adding new behavior:

1. identify whether it belongs in OptivEdge or OptivEdgeAssessments
2. keep vendor/integration concerns in OptivEdge
3. keep assessment workflow concerns in `assessments`
4. keep UI behavior aligned with documented patterns
5. keep import/export behavior explicit and idempotent

## Known Architectural Risks

### OptivEdge version drift

If the dependency points to `@main`, behavior may change whenever OptivEdge changes.

Use tags or commit SHAs for repeatable installs.

### Query payload portability

Saved control queries and catalog exports rely on stable canonical model labels.

Changing model labels would affect persisted JSON and catalog portability.

### Framework leakage

Assessment code should not accumulate framework responsibilities.

If an assessment feature needs missing normalized data, add the collection/normalization capability to OptivEdge instead of working around it in `assessments`.

### Catalog overwrite risk

Control catalogs can update existing controls and queries.

Import UX should make updates visible before destructive or broad changes are applied.

### Reporting artifact sensitivity

Generated Word and Excel reports may contain client-sensitive data.

They should not be committed unless intentionally used as fixtures or templates.
