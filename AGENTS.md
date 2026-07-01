# AGENTS.md

## Purpose

`OptivEdgeAssessments` is a reusable Django assessment app package built on the `OptivEdge` framework. It is installed into downstream Django host projects; it is not a standalone Django project.

This repository owns only the installable `assessments` app under `src/assessments`. Downstream host projects own `manage.py`, root settings, root URLs, databases, environment variables, and deployment configuration.

## Authoritative Documents

* `README.md`
* `DEPLOYMENT.md`
* `pyproject.toml`

Package-local workflow notes that are used by the app live under `src/assessments/docs/`.

## Repository Boundaries

OptivEdge owns framework concerns:

* vendor collection logic
* PAN-OS session handling
* normalized integration models
* shared framework templates
* shared framework navigation composition
* shared integration views

OptivEdgeAssessments owns assessment concerns:

* assessment controls
* control queries
* canonical query evaluation
* rule findings
* management-plane findings
* assessment views
* reporting exports
* control catalog import/export workflows
* assessment-specific templates

Do not move OptivEdge framework concerns into this repository.

## Package Layout

Expected top-level layout:

```text
OptivEdgeAssessments/
├── AGENTS.md
├── DEPLOYMENT.md
├── README.md
├── pyproject.toml
└── src/
    └── assessments/
```

Do not add root-level Django project scaffolding such as `manage.py`, `config/settings.py`, root `templates/`, SQLite databases, or root deployment settings.

## Development Workflow

Use a local virtual environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Run package-level validation here:

```bash
python -m pip wheel --no-deps . -w /tmp/optivedge-assessments-wheel
python - <<'PY'
import assessments
import assessments.apps
import assessments.settings.components

print("OptivEdgeAssessments import check passed")
PY
```

Run Django checks, migrations, and UI smoke tests from a downstream host Django project that installs this package.

## Core Behavior Rules

* Consume normalized OptivEdge data models such as security rules, management-plane profiles, address objects, and enforcement scopes.
* Do not add vendor-specific API calls to assessment views, reporting modules, catalog modules, or control-query evaluation code.
* Keep views thin; put reusable logic in focused modules such as `controls_catalog`, `search`, `reporting`, `findings.py`, and `management_findings.py`.
* Preserve canonical query model labels such as `integrations.SecurityRule`; do not replace them with Python import paths.

## UI Rules

Use the OptivEdge shell and existing template patterns. Do not create a second application shell inside assessment templates.

Use the existing Lucide template tag pattern:

```django
{% load lucide %}
{% lucide "icon-name" class="h-4 w-4" %}
```

Do not inline duplicate SVGs when a Lucide icon exists.

## Data And Security

Assessment data and report exports may be client-sensitive. Do not commit generated client reports, local exports, databases, `.env` files, or other local runtime artifacts unless they are intentionally versioned fixtures or bundled catalogs.

## Known Pitfalls

* `pyproject.toml` currently depends on OptivEdge from `@main`; prefer tags or commit SHAs for repeatable deployments.
* Use Python imports in code, for example `from optivedge.integrations.models import SecurityRule`.
* Use Django model labels in canonical query payloads, for example `integrations.SecurityRule`.
* If a framework route, shared shell behavior, template, or template tag is missing, check OptivEdge first.
