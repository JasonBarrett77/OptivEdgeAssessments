# OptivEdgeAssessments

`OptivEdgeAssessments` is a reusable Django assessment app package built on the `OptivEdge` framework. It is not intended to be deployed directly as a standalone Django project. Host Django projects install this package and include its app, URLs, templates, migrations, and assessment workflows.

This package owns firewall assessment workflows that consume normalized firewall integration data provided by OptivEdge.

OptivEdge provides the framework layer:

* `optivedge.integrations`
* normalized firewall data models
* PAN-OS collection and normalization logic
* shared shell, templates, template tags, and framework URLs

`OptivEdgeAssessments` provides the assessment layer:

* controls
* control queries
* canonical query evaluation
* security-rule findings
* management-plane findings
* assessment views
* report exports
* control catalog import/export workflows

## Repository Structure

```text
OptivEdgeAssessments/
├── pyproject.toml
├── README.md
├── DEPLOYMENT.md
└── src/
    └── assessments/          # installable Django app
        ├── __init__.py
        ├── app_meta.py
        ├── apps.py
        ├── models.py
        ├── urls.py
        ├── migrations/
        ├── templates/
        ├── templatetags/
        ├── settings/
        ├── controls_catalog/
        ├── search/
        ├── reporting/
        └── plain_language/
```

Only `src/assessments` is packaged for installation. Downstream host projects remain responsible for `manage.py`, root settings, URL configuration, database, environment variables, and deployment configuration.

## Dependency Model

This repository is packaged as the `optivedge-assessments` Python distribution, which installs the local `assessments` Django app. The app depends on OptivEdge through `pyproject.toml`:

```text
optivedge @ git+https://github.com/JasonBarrett77/OptivEdge.git@main
```

A downstream project can install this assessment app from GitHub in the same style:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdgeAssessments.git@main#egg=optivedge-assessments"
```

For repeatable installs, prefer a tag or commit SHA instead of `@main`:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdgeAssessments.git@v0.1.0#egg=optivedge-assessments"
```

## Requirements

* Python 3.12+
* Django 6.0.x
* OptivEdge installed from GitHub
* SQLite for local development unless another database is configured

## Local Development

Create and activate a virtual environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Install the assessment package in editable mode:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

Run a package import check:

```bash
python - <<'PY'
import assessments
import assessments.apps
import assessments.settings.components

print("OptivEdgeAssessments import check passed")
PY
```

Build a wheel to verify distributable package contents:

```bash
python -m pip wheel --no-deps . -w /tmp/optivedge-assessments-wheel
```

Full Django checks, migrations, and browser smoke tests should be run from a downstream host Django project that installs this package.

## Application Boundaries

### OptivEdge

OptivEdge owns framework and integration concerns:

* vendor collection logic
* PAN-OS session handling
* raw integration persistence
* normalized firewall data models
* framework shell
* shared templates
* shared template tags
* integration-facing routes and views

Framework-level changes should be made in the `OptivEdge` repository.

### OptivEdgeAssessments

This repository owns assessment concerns:

* assessment controls
* control queries
* control-query evaluation
* security-rule findings
* management-plane findings
* report rendering
* control catalog workflows
* assessment-specific views and templates

Assessment code should consume normalized OptivEdge data. It should not call vendor APIs directly.

## Canonical Query Model Labels

Assessment search payloads use Django model labels, not Python import paths.

Correct canonical query model labels:

```text
integrations.SecurityRule
integrations.ManagementPlaneProfile
```

Correct Python imports:

```python
from optivedge.integrations.models import SecurityRule
```

Do not replace canonical query model labels with `optivedge.integrations...` paths.

## Control Catalogs

Control catalog work belongs under:

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

The control catalog subsystem is intended to support:

* exporting existing `Control` and `ControlQuery` objects
* importing catalog payloads
* loading bundled catalogs
* validating catalog shape and schema version
* maintaining base and industry-specific catalogs

Potential catalog examples:

```text
base
banking
health_insurance
```

Catalog imports should be explicit and idempotent.

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

## Development Validation

This repository does not include a root Django project. Run package-local validation here:

```bash
python -m pip install -e .
python -m pip wheel --no-deps . -w /tmp/optivedge-assessments-wheel
```

Run Django checks, migrations, and browser smoke tests from a downstream host project that installs this package.

## Reporting

The assessment app includes report export support for Word and Excel outputs.

Reporting dependencies are declared in `pyproject.toml`, including:

```text
python-docx
docxtpl
xlsxwriter
```

Report templates and generated report artifacts may contain client-sensitive data. Do not commit generated client reports unless explicitly intended.

## Documentation

Repository guidance lives in:

* `README.md`
* `DEPLOYMENT.md`
* `AGENTS.md`

Package-local workflow notes that are used by the app live under `src/assessments/docs/`.

## Git Notes

Do not commit local runtime artifacts:

```text
.venv/
.env
*.sqlite3
__pycache__/
*.pyc
generated reports
local exports
```

Do not commit Windows alternate data stream artifacts:

```text
*:Zone.Identifier
```

## Known Pitfalls

### OptivEdge version drift

`pyproject.toml` currently depends on OptivEdge from `@main`. Use tags or commit SHAs for repeatable deployments.

### Wrong import style

Use Python imports for code:

```python
from optivedge.integrations.models import SecurityRule
```

Use Django model labels in canonical query payloads:

```text
integrations.SecurityRule
```

### Missing framework routes or templates

If a shared shell route, integration route, template, or template tag is missing, check the OptivEdge framework first. The fix may belong in the `OptivEdge` repository, not in `OptivEdgeAssessments`.

### Generated files

Do not commit generated client deliverables, local exports, or local databases unless they are intentionally versioned fixtures or catalog data.
