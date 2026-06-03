# Current State

## Overview

`OptivEdgeAssessments` is a downstream Django project that consumes the installed `OptivEdge` framework package.

The project is currently focused on assessment workflows built on top of normalized firewall integration data exposed by OptivEdge.

Current local app:

```text
assessments
```

Current framework dependency:

```text
OptivEdge
```

## Repository Status

This repository has been split out from the original combined AegisGo project.

The previous combined structure was:

```text
AegisGo
├── integrations
├── assessments
├── demo_policy
└── base
```

The new target structure is:

```text
OptivEdge
└── optivedge.integrations

OptivEdgeAssessments
└── assessments

Future / separate
└── demo_policy
```

`OptivEdgeAssessments` has been validated as a downstream Django project using OptivEdge as an installed dependency.

## What Currently Works

The project currently supports:

* installation of OptivEdge from GitHub
* Django project setup through local `config/`
* loading OptivEdge apps through `OPTIVEDGE_APPS`
* loading OptivEdge templates and template tags
* mounting OptivEdge framework URLs
* mounting the local `assessments` app through `assessments/app_meta.py`
* applying OptivEdge `integrations` migrations
* applying local `assessments` migrations
* rendering the OptivEdge home page
* rendering the assessment controls page

Validated commands:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

Validated pages:

```text
/
 /assessments/controls/
```

## Current Dependency Model

`OptivEdgeAssessments` depends on OptivEdge through `requirements.txt`.

Current development dependency pattern:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@main#egg=optivedge
```

This is acceptable during active development.

For repeatable installs, use a tag or commit SHA:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.0#egg=optivedge
```

## Current Django Apps

Expected installed apps include:

```text
django.contrib.admin
django.contrib.auth
django.contrib.contenttypes
django.contrib.sessions
django.contrib.messages
django.contrib.staticfiles
optivedge.apps.OptivEdgeConfig
optivedge.integrations.apps.IntegrationsConfig
assessments.apps.AssessmentsConfig
```

`optivedge.apps.OptivEdgeConfig` is required so Django can discover shared OptivEdge templates.

`optivedge.integrations.apps.IntegrationsConfig` provides normalized firewall integration models.

`assessments.apps.AssessmentsConfig` provides the local assessment workflow models and views.

## Current URL Composition

The downstream project root URL configuration includes OptivEdge URLs:

```python
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("", include("optivedge.urls")),
    path("admin/", admin.site.urls),
]
```

The `assessments` app is mounted by OptivEdge through app metadata:

```python
URL_MOUNT = {
    "prefix": "assessments/",
    "module": "assessments.urls",
}
```

This currently enables assessment routes such as:

```text
/assessments/controls/
/assessments/security-rules/
/assessments/findings/
/assessments/management-findings/
```

## Current Assessment Features

The `assessments` app currently includes:

* assessment controls
* control queries
* control-query CRUD views
* canonical query parsing and evaluation
* security-rule assessment search
* plain-language security-rule query translation
* security-rule finding generation
* management-plane finding generation
* findings list views
* Word report rendering
* Excel workbook rendering
* assessment-specific templates

## Current Models

The local `assessments` app currently owns these assessment workflow models:

```text
AssessmentRun
Control
ControlQuery
SecurityRuleSearchState
RuleFinding
RuleFindingControlQuery
ManagementPlaneFinding
ManagementPlaneFindingControlQuery
```

These models represent assessment workflow state.

They should not be treated as raw integration data.

## Current OptivEdge Data Dependency

Assessment workflows currently depend on normalized data from OptivEdge, including:

```text
integrations.SecurityRule
integrations.ManagementPlaneProfile
integrations.ManagementStation
integrations.ApplicationEnvironment
```

Python imports should use the installed package path:

```python
from optivedge.integrations.models import SecurityRule
```

Canonical query payloads should continue using model labels:

```text
integrations.SecurityRule
integrations.ManagementPlaneProfile
```

## Current Search and Query Behavior

The assessment search system currently supports canonical JSON query payloads.

Current model targets:

```text
integrations.SecurityRule
integrations.ManagementPlaneProfile
```

Control queries store canonical JSON and are evaluated against normalized OptivEdge querysets.

The current design supports:

* saved control queries
* baseline control queries
* adjusted severity on non-baseline queries
* server-side search state
* rule filtering from saved control queries
* control-based filtering
* plain-language query generation into canonical JSON

## Current Finding Behavior

Current finding families:

```text
RuleFinding
ManagementPlaneFinding
```

Current finding generation behavior:

* reads active controls
* evaluates active control queries
* matches against normalized OptivEdge data
* creates an `AssessmentRun`
* creates finding records
* links findings back to matched `ControlQuery` records

Finding generation is local to `OptivEdgeAssessments`.

It should not mutate normalized OptivEdge data.

## Current Reporting Behavior

The assessment app currently includes report export support.

Current report formats:

```text
.docx
.xlsx
```

Current reporting dependencies:

```text
python-docx
docxtpl
xlsxwriter
```

Current report-related modules:

```text
assessments/reporting/context.py
assessments/reporting/docx.py
assessments/reporting/workbook_data.py
assessments/reporting/xlsx.py
```

The repository currently contains report template material copied from the original project.

Generated client deliverables should not be committed unless intentionally used as fixtures or templates.

## Current Control Catalog Status

Control catalog import/export is now implemented as a local `Catalog` subsystem.

The target package location is:

```text
assessments/controls_catalog/
```

Current structure:

```text
assessments/controls_catalog/
├── catalogs/
├── io/
├── registry.py
└── schemas.py
```

Current responsibilities:

* export current `Control` and `ControlQuery` records
* load repo-seeded catalogs into local `Catalog` rows
* validate catalog schema
* apply catalogs into live `Control` and `ControlQuery` tables
* export the current live control state into local catalogs
* export local catalogs back into the seed artifact shape

Current catalog behavior:

```text
seed artifact
local catalogs
automatic snapshots before apply
```

Current apply behavior:

* create a snapshot catalog if live controls already exist
* delete current assessment runs
* fully replace live controls and control queries from the selected catalog
* update the local current-catalog state tied to the deployment environment

## Current UI State

The project uses the shared OptivEdge shell.

Assessment templates should extend the shared shell rather than creating a second shell.

Current UI patterns include:

* left-rail navigation
* app-local assessment subnavigation
* dense analytical tables
* right-side overlays for CRUD
* table-based list views
* detail views
* severity displays
* report action links

UI standards still need to be rebranded from the original AegisGo docs, but most of the substance remains valid.

## Current Documentation State

The original AegisGo documentation is partially stale.

Docs that should be rewritten for `OptivEdgeAssessments`:

```text
README.md
AGENTS.md
docs/architecture.md
docs/current-state.md
docs/data-handling.md
```

Docs that can mostly be retained with rebranding and light edits:

```text
docs/style-standard.md
docs/ux-decision-rules.md
docs/design-tokens.md
docs/component-spec.md
docs/ui-open-questions.md
```

A new document now exists:

```text
docs/controls-catalog.md
```

A deployment document should also exist:

```text
docs/deployment.md
```

## Active Transitions

Current active transitions:

* AegisGo has been split into OptivEdge and OptivEdgeAssessments.
* `integrations` now belongs to OptivEdge.
* `assessments` now belongs to OptivEdgeAssessments.
* `demo_policy` should remain separate and should not be pulled into OptivEdgeAssessments by default.
* Assessment imports have been rewritten from local `integrations` imports to `optivedge.integrations` imports.
* Canonical query model labels intentionally remain `integrations.*`.
* Control catalog import/export is now a local implemented subsystem.

## Near-Term Work

Near-term tasks include:

* finalize documentation for the new downstream project structure
* export current control data from the original project
* import exported controls as the starting base catalog
* replace `@main` OptivEdge dependency with a tag once the framework stabilizes
* run the full assessment test suite after import-path cleanup
* verify report generation after the split
* remove or ignore Windows `Zone.Identifier` artifacts
* confirm all copied report template files are intentional

## Known Gaps

Current known gaps:

* no bundled base catalog yet
* no explicit deployment doc finalized for this repo
* original docs still reference AegisGo concepts in places
* report template paths may need review after the project split
* plain-language OpenAI integration may still depend on development-only key handling
* generated reports and local exports need clear ignore/output conventions

## Known Risks

### OptivEdge version drift

Using `@main` means downstream behavior can change when OptivEdge changes.

Use tags or commit SHAs for repeatable installs.

### Import path confusion

Python imports should use:

```python
from optivedge.integrations.models import SecurityRule
```

Canonical query payloads should use:

```text
integrations.SecurityRule
```

Changing canonical labels would affect saved control queries and future catalogs.

### Framework leakage

Assessment code should not accumulate framework responsibilities.

If an assessment requires missing normalized integration data, the normalization should usually be added to OptivEdge.

### Catalog overwrite risk

Future catalog imports can update existing controls and queries.

Import behavior should be explicit, previewable where practical, and non-destructive by default.

### Reporting sensitivity

Generated reports may contain client-sensitive data.

Do not commit generated deliverables unless intentionally versioned as templates or fixtures.

## Baseline Validation

Minimum validation for the current project:

```bash
source .venv/bin/activate
python manage.py check
python manage.py migrate
python manage.py runserver
```

Recommended smoke-test pages:

```text
/
 /assessments/controls/
 /assessments/security-rules/
 /assessments/findings/
 /assessments/management-findings/
```

## Current Rule of Thumb

If the change concerns vendor collection, PAN-OS parsing, normalization, framework shell behavior, shared templates, or normalized integration models, it probably belongs in `OptivEdge`.

If the change concerns controls, queries, findings, reporting, assessment views, or control catalogs, it probably belongs in `OptivEdgeAssessments`.
