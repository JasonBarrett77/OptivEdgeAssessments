# OptivEdgeAssessments

`OptivEdgeAssessments` is a downstream Django project built on the `OptivEdge` framework.

This project owns firewall assessment workflows that consume normalized firewall integration data provided by the installed OptivEdge package.

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
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── search/
│   ├── reporting/
│   ├── plain_language/
│   └── controls_catalog/
└── templates/
    └── assessments/
```

## Dependency Model

This project depends on OptivEdge through `requirements.txt`.

During active development, `@main` may be used:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@main#egg=optivedge
```

For repeatable installs, prefer a tag or commit SHA:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.0#egg=optivedge
```

## Requirements

* Python 3.12+
* Django 6.0.x
* OptivEdge installed from GitHub
* SQLite for local development unless another database is configured

## Local Setup

Create and activate a virtual environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run migrations:

```bash
python manage.py migrate
```

Run validation:

```bash
python manage.py check
```

Start the development server:

```bash
python manage.py runserver
```

Open:

```text
http://127.0.0.1:8000/
```

## Common Development Commands

```bash
source .venv/bin/activate
python manage.py check
python manage.py migrate
python manage.py runserver
```

Force-refresh OptivEdge from GitHub during development:

```bash
python -m pip install --force-reinstall --no-deps "git+https://github.com/JasonBarrett77/OptivEdge.git@main#egg=optivedge"
```

Inspect installed package versions:

```bash
python -m pip freeze
```

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

After meaningful changes, run:

```bash
python manage.py check
python manage.py migrate
```

For UI or view changes, also run the development server and smoke-test relevant pages:

```text
/
/assessments/controls/
/assessments/security-rules/
/assessments/findings/
/assessments/management-findings/
```

## Reporting

The assessment app includes report export support for Word and Excel outputs.

Reporting dependencies are installed through `requirements.txt`, including:

```text
python-docx
docxtpl
xlsxwriter
```

Report templates and generated report artifacts may contain client-sensitive data. Do not commit generated client reports unless explicitly intended.

## Documentation

General guidance:

* `AGENTS.md`
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

## Git Notes

Do not commit local runtime artifacts:

```text
.venv/
db.sqlite3
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

If `requirements.txt` uses `@main`, installs may change whenever OptivEdge changes. Use tags or commit SHAs for repeatable deployments.

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
