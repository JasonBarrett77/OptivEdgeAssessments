# OptivEdgeAssessments Deployment Instructions

OptivEdgeAssessments is a reusable Django assessment app package. It is not intended to be deployed directly as a standalone Django project. Downstream Django projects install OptivEdgeAssessments as a dependency and include its Django app, URLs, templates, migrations, and assessment workflows.

## Repository Purpose

This repository provides the assessment application layer for OptivEdgeIntegrations, including:

* assessment controls
* control queries
* canonical query evaluation
* security-rule findings
* management-plane findings
* assessment views
* report exports
* control catalog import/export workflows
* assessment templates and template tags

OptivEdgeIntegrations remains responsible for the shared framework layer, including:

* normalized firewall integration models
* PAN-OS collection and normalization logic
* framework shell, templates, and template tags
* framework URL composition
* framework settings components

Downstream projects remain responsible for:

* `manage.py`
* root Django settings
* root URL configuration
* environment variables
* database configuration
* deployment configuration
* project-specific apps and workflows

## Package Layout

Expected repository structure:

```text
OptivEdgeAssessments/
├── pyproject.toml
├── README.md
├── DEPLOYMENT.md
└── src/
    └── assessments/
        ├── __init__.py
        ├── app_meta.py
        ├── apps.py
        ├── urls.py
        ├── models.py
        ├── migrations/
        ├── templates/
        ├── templatetags/
        ├── controls_catalog/
        ├── search/
        ├── reporting/
        └── plain_language/
```

Only `src/assessments` is packaged for installation. Downstream host projects own `manage.py`, root settings, URL configuration, database, environment variables, and deployment configuration.

## Version Requirements

OptivEdgeAssessments currently targets:

```text
Python >= 3.12
OptivEdgeIntegrations installed from GitHub
Django >= 6.0, < 6.1 through OptivEdgeIntegrations
```

The OptivEdgeIntegrations dependency is declared in `pyproject.toml`:

```toml
[project]
requires-python = ">=3.12"
dependencies = [
    "optivedge-integrations @ git+https://github.com/JasonBarrett77/OptivEdgeIntegrations.git@main",
    "python-docx",
    "docxtpl",
    "XlsxWriter",
]
```

## Installing OptivEdgeAssessments In A Downstream Project

Create and activate a virtual environment in the downstream project:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

Install OptivEdgeAssessments from GitHub:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdgeAssessments.git@main#egg=optivedge-assessments"
```

For repeatable installs, prefer a tag:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdgeAssessments.git@v0.1.0#egg=optivedge-assessments"
```

For local development against a checked-out copy:

```bash
python -m pip install -e ~/PythonProjects/OptivEdgeAssessments
```

### Co-development with a local OptivEdgeIntegrations checkout

When a downstream project is developing against local checkouts of both `OptivEdgeIntegrations` and `OptivEdgeAssessments` simultaneously, installing them together with a single `pip install` command will fail. `optivedge-assessments` declares its `optivedge` dependency as a GitHub URL, which pip treats as a different distribution from a local editable install. pip raises a `ResolutionImpossible` conflict.

Install them in three steps instead:

```bash
# 1. Install the local OptivEdgeIntegrations editable first.
python -m pip install -e ~/PythonProjects/OptivEdgeIntegrations

# 2. Install OptivEdgeAssessments editable without resolving its declared
#    optivedge-integrations dependency — the editable from step 1 satisfies it.
python -m pip install -e ~/PythonProjects/OptivEdgeAssessments --no-deps

# 3. Install the remaining OptivEdgeAssessments dependencies that --no-deps skipped.
python -m pip install python-docx docxtpl XlsxWriter
```

The result is the same as a normal install: both packages are editable, and changes to files in either `src/` directory take effect immediately without reinstalling.

## Configuring A Downstream Django Project

Create or use a normal Django project:

```bash
django-admin startproject config .
```

Edit `config/settings.py`.

Import OptivEdgeIntegrations settings components:

```python
from assessments.settings.components import OPTIVEDGE_ASSESSMENTS_APPS
from optivedge_integrations.settings.components import (
    OPTIVEDGE_APPS,
    OPTIVEDGE_CONTEXT_PROCESSORS,
    OPTIVEDGE_TEMPLATE_LIBRARIES,
)
```

Add OptivEdgeAssessments and OptivEdgeIntegrations apps to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    *OPTIVEDGE_ASSESSMENTS_APPS,
    *OPTIVEDGE_APPS,
]
```

Place `OPTIVEDGE_ASSESSMENTS_APPS` before `OPTIVEDGE_APPS` so assessment-owned template overrides win.

Configure templates:

```python
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
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

Edit `config/urls.py`:

```python
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("", include("optivedge_integrations.urls")),
    path("admin/", admin.site.urls),
]
```

OptivEdgeIntegrations composes registered app navigation and routes. The assessment app publishes its mount metadata in `assessments.app_meta`.

## Running Django Checks And Migrations

From the downstream project root:

```bash
python manage.py check
python manage.py migrate
```

Expected migrations include the OptivEdgeIntegrations `integrations` app and the OptivEdgeAssessments `assessments` app.

## Running The Development Server

```bash
python manage.py runserver
```

Open:

```text
http://127.0.0.1:8000/
```

If the OptivEdgeIntegrations shell renders and the Assessments navigation/routes are available, the framework package, assessment app, templates, URLs, and migrations are working.

## Development Workflow For OptivEdgeAssessments

When changing OptivEdgeAssessments itself:

```bash
cd ~/PythonProjects/OptivEdgeAssessments
source .venv/bin/activate
```

Install the assessment app editable for local validation:

```bash
python -m pip install -e .
```

Run a basic non-Django import check:

```bash
python - <<'PY'
import assessments
import assessments.apps
import assessments.settings.components

print("OptivEdgeAssessments import check passed")
PY
```

Django URL, view, and model imports require a configured Django settings module. Validate full Django behavior from a downstream host project that installs this package:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

## URL Organization Convention

OptivEdgeAssessments should keep URL ownership in the assessment app:

```text
src/assessments/urls.py
```

The downstream project's root URL configuration should include `optivedge_integrations.urls`. OptivEdgeIntegrations handles framework-level URL composition and app-local mounts.

## Packaging Rules

Package data required at runtime must stay under `src/assessments/`, including:

* templates
* bundled control catalog JSON
* report document templates
* package-local documentation used by workflows

Do not rely on root-level `templates/` or project-relative file paths for package runtime behavior.
