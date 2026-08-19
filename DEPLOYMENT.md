# OptivEdgeAssessments Deployment Instructions

**Host-project wiring is documented in OptivEdge, not here.** `OptivEdge/DEPLOYMENT.md` is the single
authority for standing up a deployment: creating an engagement project from `deployment_template/`, building
the offline wheel bundle, and configuring `INSTALLED_APPS` / `TEMPLATES` / root urls for the whole stack. Read
it first. This file covers only what is specific to *this* package.

OptivEdgeAssessments is a reusable Django domain package — assessment controls, control queries, findings and
report exports. It is not deployable on its own: it has no `manage.py` and no host settings, and it requires
both **OptivEdge** (the shared app shell) and **OptivEdgeIntegrations** (the normalized firewall models it
assesses) installed alongside it. A downstream host project owns `manage.py`, root settings, root URLs, and the
database.

## What this package contributes to a host project

| | |
|---|---|
| Django app | `assessments`, label `assessments` |
| Settings component | `OPTIVEDGE_ASSESSMENTS_APPS` (from `assessments.settings.components`) |
| Routes | mounted at `/assessments/` by OptivEdge's plugin registry, via `assessments/app_meta.py` |
| Navigation | the "Assessments" and "Experimental" sidebar sections, via the same `app_meta.py` |
| Migrations | the `assessments` app's own |

It contributes **no** shell, base templates, context processors, template libraries, or root URL patterns —
those come from OptivEdge, and this package's templates `{% extends "base.html" %}` and `{% load lucide %}`
out of it. Splice `OPTIVEDGE_ASSESSMENTS_APPS` **after** `OPTIVEDGE_APPS` and `OPTIVEDGE_INTEGRATIONS_APPS`, as
`deployment_template` does; see the ordering note in `OptivEdge/DEPLOYMENT.md` before changing that.

## Version requirements and dependencies

```text
Python >= 3.12
Django >= 6.0, < 6.1   (via OptivEdge)
```

Declared in `pyproject.toml`:

```toml
dependencies = [
    "optivedge @ git+https://github.com/JasonBarrett77/OptivEdge.git@main",
    "optivedge-integrations @ git+https://github.com/JasonBarrett77/OptivEdgeIntegrations.git@main",
    "python-docx",
    "docxtpl",
    "XlsxWriter",
]
```

Both OptivEdge dependencies float on `@main`; prefer tags or commit SHAs for repeatable deployments.

## Installing

From GitHub — pip resolves both OptivEdge dependencies automatically:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdgeAssessments.git@main#egg=optivedge-assessments"
```

For repeatable installs, prefer a tag:

```bash
python -m pip install "git+https://github.com/JasonBarrett77/OptivEdgeAssessments.git@v0.1.0#egg=optivedge-assessments"
```

Working on this package alongside local checkouts of the other two is **not** a single `pip install -e` — the
git-URL dependencies conflict with local editables of the same packages, and pip raises `ResolutionImpossible`.
Follow "Co-development with local checkouts of the whole stack" in `OptivEdge/DEPLOYMENT.md`; the short form
is:

```bash
python -m pip install -e ~/PythonProjects/OptivEdge
python -m pip install -e ~/PythonProjects/OptivEdgeIntegrations --no-deps
python -m pip install -e ~/PythonProjects/OptivEdgeAssessments --no-deps
python -m pip install requests xmltodict python-docx docxtpl XlsxWriter
```

## Local development settings and CLI

`assessments.settings.default` is a local-dev settings module committed inside the package — a SQLite database
in the current working directory, `ROOT_URLCONF = "assessments.urls_root"` (admin plus `optivedge.urls`), and
all three apps installed. It is **not** a downstream integration example; a host project writes its own
settings from `OptivEdge/DEPLOYMENT.md`.

The `optivedge-assessments` console script is a `manage.py` shim over it, so management commands work from
this repo without a host project:

```bash
optivedge-assessments migrate
optivedge-assessments runserver
```

## Packaging rules

Runtime package data must stay under `src/assessments/` and be declared in `pyproject.toml`:

```toml
[tool.setuptools.package-data]
assessments = [
    "controls_catalog/catalogs/*.json",
    "docs/*.md",
    "reporting/docx/*.docx",
    "templates/**/*.html",
]
```

That covers templates, the bundled control catalog JSON, the report document templates, and the package-local
workflow docs. Do not rely on root-level `templates/` or project-relative file paths — they will not survive
being installed as a wheel.

## Validating a change to this package

```bash
DJANGO_SETTINGS_MODULE=assessments.settings.default python -m django test assessments
```

Full Django behavior against real collected data — migrations, report exports, the rendered shell — can only
be validated from a host project:

```bash
python manage.py check
python manage.py migrate
python manage.py runserver
```

## Publishing a version

Only tag a release after a host project can successfully run `check`, `migrate` and `runserver` against it:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Troubleshooting

**`ImportError: cannot import name 'OPTIVEDGE_APPS' from 'optivedge_integrations.settings.components'`** — the
host project is wired for the pre-split layout. `OPTIVEDGE_APPS`, `OPTIVEDGE_CONTEXT_PROCESSORS` and
`OPTIVEDGE_TEMPLATE_LIBRARIES` come from `optivedge.settings.components` now; `optivedge_integrations` exports
only `OPTIVEDGE_INTEGRATIONS_APPS`.

**`TemplateDoesNotExist: base.html`** — `optivedge` is missing from `INSTALLED_APPS`.

**`LookupError: No installed app with label 'integrations'`** — `OPTIVEDGE_INTEGRATIONS_APPS` was left out of
`INSTALLED_APPS`. Controls store their targets as Django model labels (`integrations.SecurityRule`), so this
package cannot resolve a single control target without it.

**`NoReverseMatch` for an `assessment_*` URL name** — `assessments` is missing from `INSTALLED_APPS`, so
OptivEdge's registry never found its `app_meta.py` and never mounted `/assessments/`.

**Sidebar item stops highlighting on a page** — a route name was added to `assessments/urls.py` without being
added to the matching `active_names` set in `assessments/app_meta.py`.
