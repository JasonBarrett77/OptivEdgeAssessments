# AGENTS.md

## Purpose

`OptivEdgeAssessments` is a downstream Django project built on the `OptivEdge` framework.

This repository owns assessment workflows that consume normalized firewall integration data provided by the installed OptivEdge package.

OptivEdge provides the shared framework layer:

* `optivedge.integrations`
* normalized firewall data models
* PAN-OS collection and normalization logic
* shared shell, templates, template tags, and framework URLs

This repository owns the local `assessments` app:

* assessment controls
* control queries
* canonical query evaluation
* rule findings
* management-plane findings
* assessment views
* reporting exports
* control catalog import/export workflows
* assessment-specific templates

Framework-level integration work belongs in the separate `OptivEdge` repository.

## Authoritative Documents

General guidance:

* `README.md`
* `docs/architecture.md`
* `docs/current-state.md`
* `docs/data-handling.md`
* `docs/controls-catalog.md`

UI guidance:

* `docs/style-standard.md`
* `docs/ux-decision-rules.md`
* `docs/design-tokens.md`
* `docs/component-spec.md`
* `docs/ui-open-questions.md`

Deployment guidance:

* `requirements.txt`
* `docs/deployment.md`

## Development Posture

* Prefer simplicity over cleverness.
* Prefer maintainability over abstraction unless a pattern is already proving reusable.
* Optimize for future maintainers who may be stronger in network security than in Python application design.
* Keep packages and modules narrowly scoped.
* Call out ambiguity, scope drift, conflicting instructions, and unnecessary complexity.
* Treat `OptivEdge` as the framework dependency and `assessments` as the downstream consumer app.
* Do not re-embed vendor API collection, normalization, or persistence logic inside `assessments`.

## Repository Boundaries

### OptivEdge dependency

This repository should consume OptivEdge through `requirements.txt`.

Use a tag or commit SHA for repeatable installs:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.0#egg=optivedge
```

Using `@main` is acceptable during active development, but it creates version drift.

### Local assessment app

The local `assessments` app should build on normalized OptivEdge integration data.

Assessment code may import OptivEdge models:

```python
from optivedge.integrations.models import SecurityRule
```

Canonical query payloads should continue using Django model labels:

```text
integrations.SecurityRule
integrations.ManagementPlaneProfile
```

Do not change canonical model labels to Python import paths.

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

Use this package for:

* exporting current `Control` and `ControlQuery` records
* importing catalog payloads
* loading bundled catalogs
* validating catalog shape and schema version
* supporting future industry-specific catalogs such as base, banking, and health insurance

Views should call the `controls_catalog` service layer. Do not put import/export business logic directly in views.

Control catalog imports should be explicit and idempotent.

Identity rules:

* `Control`: `control_id`
* `ControlQuery`: `control_id + query name`
* catalog: catalog id and version

Default import behavior:

* create missing controls
* update existing controls
* create missing queries
* update existing queries
* do not delete missing controls or queries

Avoid pruning or deactivation unless explicitly requested.

## Environment and Workflow

This repository assumes a local virtual environment.

Typical setup:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python manage.py migrate
```

Common commands:

```bash
source .venv/bin/activate
python manage.py check
python manage.py migrate
python manage.py runserver
```

During active OptivEdge framework development, a local editable install may be used temporarily:

```bash
python -m pip install -e ~/PythonProjects/OptivEdge
```

Do not commit local editable paths into `requirements.txt`.

To force-refresh OptivEdge from GitHub during development:

```bash
python -m pip install --force-reinstall --no-deps "git+https://github.com/JasonBarrett77/OptivEdge.git@main#egg=optivedge"
```

## Core Behavior Rules

### Preserve the framework boundary

Do not move OptivEdge framework concerns into this repository.

Framework concerns include:

* vendor collection logic
* PAN-OS session handling
* normalized integration models
* shared framework templates
* shared framework navigation composition
* shared integration views

Assessment concerns belong here.

### Consume normalized data

Assessment workflows should use normalized OptivEdge models such as:

* security rules
* management-plane profiles
* address objects
* enforcement scopes

Do not add vendor-specific API calls to assessment views, reporting modules, catalog modules, or control-query evaluation code.

### Keep views thin

Views should coordinate request/response behavior only.

Move reusable logic into focused modules, for example:

* `assessments/search/`
* `assessments/reporting/`
* `assessments/controls_catalog/`
* `assessments/findings.py`
* `assessments/management_findings.py`

### Preserve working behavior

Existing implemented behavior is the minimum expected behavior unless explicitly changed.

When extending incomplete flows, preserve current behavior first, then layer new behavior carefully.

## UI Rules

Use the OptivEdge shell and existing template patterns.

Do not create a second application shell inside assessment templates.

Reuse documented patterns for:

* dense analytical tables
* right-side overlays
* list views
* detail views
* CRUD forms
* delete confirmations
* severity badges
* buttons
* app-local subnavigation

Respect density and overflow rules:

* avoid body-level scrolling
* local data regions own scrolling
* structural flex containers should use `min-h-0`
* dense tables should use local `overflow-auto` regions
* use `table-auto` by default
* use `table-fixed` only for specific constrained-column layouts

Tailwind utility classes are preferred. Avoid custom CSS unless utility-only implementation is brittle or harms alignment, scrolling, or table behavior.

Use the existing Lucide template tag pattern:

```django
{% load lucide %}
{% lucide "icon-name" class="h-4 w-4" %}
```

Do not inline duplicate SVGs when a Lucide icon already exists.

## Code Shaping

Prefer durable production names over temporary explanatory names.

Good examples:

* `controls_catalog`
* `importers`
* `exporters`
* `registry`
* `schemas`

Keep modules scoped around one responsibility.

Examples:

* `controls_catalog/io/importers.py` imports catalog payloads
* `controls_catalog/io/exporters.py` exports current database state
* `controls_catalog/registry.py` lists and loads bundled catalogs
* `controls_catalog/schemas.py` validates payload structure

Avoid generalized plugin systems or broad framework abstractions unless multiple real use cases already justify them.

## Data and Security

* Assessment data may be engagement-specific.
* Report exports may include client-sensitive information.
* Do not casually commit generated client artifacts, exported reports, databases, or environment files.
* Keep `.env`, SQLite databases, generated exports, and local artifacts ignored unless explicitly intended as versioned fixtures or catalogs.
* Credential and secret handling belongs primarily in OptivEdge integration configuration. Do not spread credential handling into assessment modules unless explicitly required.

## Testing and Validation

Testing should be pragmatic and protect working behavior.

Minimum validation after meaningful changes:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

Smoke-test relevant pages when touched:

```text
/
/assessments/controls/
/assessments/security-rules/
/assessments/findings/
/assessments/management-findings/
```

Add tests when they materially protect:

* control catalog import/export behavior
* canonical query parsing/evaluation
* finding regeneration
* reporting output behavior
* view behavior that has broken before or is likely to regress

Do not impose a heavy testing regime unless requested.

## Documentation Expectations

Documentation should stay concise and durable.

Update docs when a change materially affects:

* repo setup
* OptivEdge dependency behavior
* assessment architecture
* control catalog workflows
* UI patterns
* data handling
* deployment steps

Keep `AGENTS.md` focused on operating guidance. Put deeper architecture and workflow detail in dedicated docs.

## Known Pitfalls

### OptivEdge version drift

If `requirements.txt` uses `@main`, downstream installs may change as OptivEdge changes. Prefer tags or commit SHAs for repeatable installs.

### Python imports versus model labels

Use Python imports for code:

```python
from optivedge.integrations.models import SecurityRule
```

Use Django model labels in canonical query payloads:

```text
integrations.SecurityRule
```

Do not confuse the two.

### Missing OptivEdge route or template

If a framework route, template, or shared shell behavior is missing, check OptivEdge first. The issue may belong in the framework repo, not in `OptivEdgeAssessments`.

### Windows artifacts

Do not commit files such as:

```text
*:Zone.Identifier
```

Keep `.gitattributes` and `.gitignore` aligned with WSL/Windows development.
