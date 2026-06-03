# Deployment

## Overview

`OptivEdgeAssessments` is a downstream Django project that depends on the installed `OptivEdge` framework package.

This project is deployed as a normal Django project.

OptivEdge is installed as a Python dependency and provides:

* shared framework shell
* shared templates and template tags
* `optivedge.integrations`
* normalized firewall integration models
* PAN-OS collection and normalization logic
* integration-facing views and URLs

`OptivEdgeAssessments` provides:

* assessment controls
* control queries
* finding generation
* report exports
* assessment-specific UI
* control catalog workflows

## Requirements

Minimum expected runtime:

```text
Python >= 3.12
Django >= 6.0, < 6.1
```

Development defaults:

```text
SQLite
local virtual environment
OptivEdge installed from GitHub
```

Production or engagement deployments may use a different database and hosting model.

## Repository Layout

Expected project layout:

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
└── templates/
    └── assessments/
```

## Dependency Pinning

OptivEdge is installed from GitHub through `requirements.txt`.

During active development, `@main` may be used:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@main#egg=optivedge
```

For repeatable deployments, use a tag or commit SHA:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.0#egg=optivedge
```

Avoid floating `@main` for repeatable or production-like deployments.

## Example `requirements.txt`

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.0#egg=optivedge
python-docx
docxtpl
xlsxwriter
```

During active development, this may temporarily use:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@main#egg=optivedge
```

## Local Development Setup

Create and activate a virtual environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run migrations:

```bash
python manage.py migrate
```

Validate the project:

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

## Local Editable OptivEdge Development

When actively changing the OptivEdge framework locally, install it editable:

```bash
python -m pip install -e ~/PythonProjects/OptivEdge
```

Do not commit local editable paths to `requirements.txt`.

To return to the GitHub dependency:

```bash
python -m pip uninstall -y optivedge
python -m pip install -r requirements.txt
```

To force-refresh OptivEdge from GitHub:

```bash
python -m pip install --force-reinstall --no-deps "git+https://github.com/JasonBarrett77/OptivEdge.git@main#egg=optivedge"
```

## Django Settings Requirements

`config/settings.py` must import OptivEdge settings components:

```python
from optivedge.settings.components import (
    OPTIVEDGE_APPS,
    OPTIVEDGE_CONTEXT_PROCESSORS,
    OPTIVEDGE_TEMPLATE_LIBRARIES,
)
```

`INSTALLED_APPS` must include OptivEdge apps before `assessments`:

```python
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    *OPTIVEDGE_APPS,

    "assessments.apps.AssessmentsConfig",
]
```

`TEMPLATES` must include project templates and OptivEdge template libraries/context processors:

```python
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "libraries": {
                **OPTIVEDGE_TEMPLATE_LIBRARIES,
            },
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                *OPTIVEDGE_CONTEXT_PROCESSORS,
            ],
        },
    },
]
```

## URL Configuration

`config/urls.py` should include OptivEdge URLs:

```python
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("", include("optivedge.urls")),
    path("admin/", admin.site.urls),
]
```

The `assessments` app is mounted through `assessments/app_meta.py`:

```python
URL_MOUNT = {
    "prefix": "assessments/",
    "module": "assessments.urls",
}
```

## Database Setup

Run migrations after installing dependencies:

```bash
python manage.py migrate
```

Expected migration apps include:

```text
admin
auth
contenttypes
integrations
assessments
sessions
```

The `integrations` migrations come from the installed OptivEdge package.

The `assessments` migrations come from this repository.

## Control Catalog Initialization

Control catalog import/export is intended to provide reusable baseline control data.

After the catalog subsystem is implemented, a typical new-environment flow should be:

```bash
python manage.py migrate
```

Then import a control catalog through the UI.

Potential future catalog pages:

```text
/assessments/control-catalogs/
/assessments/controls/import/
/assessments/controls/export/
```

Control catalog imports should be explicit and idempotent.

Default behavior should be:

```text
create missing controls
update existing controls
create missing queries
update existing queries
do not delete missing controls or queries
```

## Development Validation

After meaningful changes, run:

```bash
python manage.py check
python manage.py migrate
```

For UI or routing changes, also run:

```bash
python manage.py runserver
```

Smoke-test:

```text
/
/assessments/controls/
/assessments/security-rules/
/assessments/findings/
/assessments/management-findings/
```

## Report Export Dependencies

Report generation depends on:

```text
python-docx
docxtpl
xlsxwriter
```

These should be installed through `requirements.txt`.

Report templates may be committed if they are generic reusable templates.

Generated client reports should not be committed.

## GitHub Installation Test

To validate a clean install from GitHub in a temporary test project:

```bash
mkdir ~/PythonProjects/TEST_OptivEdgeAssessments
cd ~/PythonProjects/TEST_OptivEdgeAssessments

python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.0#egg=optivedge"
```

For this repository itself:

```bash
python -m pip install -r requirements.txt
python manage.py check
python manage.py migrate
```

## Updating OptivEdge Version

To move to a newer OptivEdge tag:

1. Update `requirements.txt`:

```text
git+https://github.com/JasonBarrett77/OptivEdge.git@v0.1.1#egg=optivedge
```

2. Reinstall:

```bash
python -m pip install --force-reinstall --no-deps -r requirements.txt
```

3. Validate:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

4. Commit the requirements change:

```bash
git add requirements.txt
git commit -m "Update OptivEdge dependency"
```

## Deployment Checklist

Before treating a build as usable:

```text
dependencies installed
OptivEdge pinned to intended tag or commit
python manage.py check passes
python manage.py migrate passes
home page renders
assessment controls page renders
security-rule page renders if normalized data exists
findings pages render
report export paths are reviewed
generated/client-sensitive files are not committed
```

## Files Not to Commit

Do not commit local runtime artifacts:

```text
.venv/
db.sqlite3
*.sqlite3
.env
.env.*
__pycache__/
*.pyc
generated reports
local exports
temporary uploads
*:Zone.Identifier
```

Generic reusable report templates may be committed intentionally.

Generated client deliverables should not be committed unless explicitly intended as fixtures.

## Environment Variables

No production environment variable contract is finalized yet.

Expected future environment variables may include:

```text
SECRET_KEY
DEBUG
ALLOWED_HOSTS
DATABASE_URL or database-specific settings
OPENAI_API_KEY
```

Do not commit `.env` files.

If environment variables become part of the standard deployment flow, document them here.

## Static Files

Static file handling is not finalized for production deployment.

For local development:

```text
STATIC_URL = "static/"
```

For production-like deployment, define:

```python
STATIC_ROOT = BASE_DIR / "staticfiles"
```

Then run:

```bash
python manage.py collectstatic
```

Only add this once the deployment target requires it.

## Production Notes

This project has not yet been hardened for production deployment.

Before production use, review:

```text
SECRET_KEY handling
DEBUG = False
ALLOWED_HOSTS
database configuration
static file serving
TLS termination
authentication and authorization
credential storage
logging
backup/restore
report export storage
client-sensitive data handling
```

Credential storage and vendor integration hardening primarily belong in the OptivEdge framework.

Assessment-specific sensitive data handling belongs in this repository.

## WSL / Windows Notes

This project may be edited from WSL and Windows tools.

Use `.gitattributes` to normalize text files to LF.

Do not commit Windows alternate data stream artifacts:

```text
*:Zone.Identifier
```

Recommended `.gitattributes` pattern:

```text
* text=auto eol=lf

*.py text eol=lf
*.toml text eol=lf
*.html text eol=lf
*.svg text eol=lf
*.md text eol=lf
*.txt text eol=lf
*.json text eol=lf
*.yml text eol=lf
*.yaml text eol=lf

*.docx binary
*.xlsx binary
*.png binary
*.jpg binary
*.jpeg binary
*.webp binary
*.ico binary
```

## Troubleshooting

### `ModuleNotFoundError: optivedge`

OptivEdge is not installed in the active virtual environment.

Run:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### `TemplateDoesNotExist: workspace.html`

The root OptivEdge app is likely missing from `INSTALLED_APPS`.

Confirm `OPTIVEDGE_APPS` includes:

```python
"optivedge.apps.OptivEdgeConfig"
```

Then confirm settings include:

```python
*OPTIVEDGE_APPS
```

### `NoReverseMatch` for assessment routes

Confirm `assessments` is installed:

```python
"assessments.apps.AssessmentsConfig"
```

Confirm `assessments/app_meta.py` includes:

```python
URL_MOUNT = {
    "prefix": "assessments/",
    "module": "assessments.urls",
}
```

Confirm root URLs include:

```python
path("", include("optivedge.urls"))
```

### `NoReverseMatch` for OptivEdge integration routes

The issue may belong in OptivEdge.

Update/reinstall OptivEdge and confirm its URL modules include the required named route.

### Migrations do not include `integrations`

Confirm `OPTIVEDGE_APPS` is included in `INSTALLED_APPS`.

Confirm OptivEdge is installed:

```bash
python -m pip show optivedge
```

### Canonical query model errors

Canonical query payloads should use:

```text
integrations.SecurityRule
integrations.ManagementPlaneProfile
```

They should not use:

```text
optivedge.integrations.SecurityRule
optivedge.integrations.ManagementPlaneProfile
```

## Release / Tagging

To tag a stable project state:

```bash
git status
git tag v0.1.0
git push origin v0.1.0
```

To push the current branch:

```bash
git push -u origin main
```

Pushing the branch does not push tags.

Push a specific tag separately:

```bash
git push origin v0.1.0
```

Avoid moving published tags. Use a new tag for the next release:

```bash
git tag v0.1.1
git push origin v0.1.1
```
