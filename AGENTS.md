# AGENTS.md

## Purpose

`OptivEdgeAssessments` is a reusable Django assessment app package. It plugs into the `OptivEdge` app shell and assesses the normalized firewall data owned by `OptivEdgeIntegrations`. It is installed into downstream Django host projects; it is not a standalone Django project.

`CLAUDE.md` is a symlink to this file — Claude Code and Codex read the same guidance. Edit `AGENTS.md`.

This repository owns only the installable `assessments` app under `src/assessments`. Downstream host projects own `manage.py`, root settings, root URLs, databases, environment variables, and deployment configuration.

## Before You Build A Control

**Read `src/assessments/docs/building-a-control.md` first, and again before calling a control
done.** It is a checklist of everything that has been missed on a control someone believed was
finished — implicit values assumed rather than measured, key sets hard-coded from a sample,
controls that returned zero findings and were never made to fire, tables that stopped being
square. Each item names the incident behind it.

When a control turns out to need work after it looked done, **add the item to that file.**

## Authoritative Documents

* `README.md`
* `DEPLOYMENT.md`
* `pyproject.toml`

Package-local workflow notes that are used by the app live under `src/assessments/docs/`.

## Repository Boundaries

The stack is three peer packages, and shell concerns were extracted out of OptivEdgeIntegrations into OptivEdge —
older notes that credit OptivEdgeIntegrations with the shell are stale.

OptivEdge owns the shared shell:

* `base.html` / `workspace.html` and the shared `components/` templates
* the `app_registry` plugin convention (`URL_MOUNT` / `SIDEBAR_SECTION`) and the root URL namespace
* the `lucide` template tag and its icon SVGs
* shared UI primitives (`optivedge.views.RightOverlayMixin`, the input-class constants in `optivedge.forms`)
* `ApplicationEnvironment` — client/engagement metadata, consumed here by `environment.py`, `models.py`,
  `views.py` and `reporting/workbook_data.py`

OptivEdgeIntegrations owns firewall-domain concerns:

* vendor collection logic
* PAN-OS session handling
* normalized integration models
* integration views for management stations, appliances and enforcement points

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

Do not move OptivEdge shell concerns or OptivEdgeIntegrations firewall concerns into this repository.

## Package Layout

Expected top-level layout:

```text
OptivEdgeAssessments/
├── AGENTS.md
├── CLAUDE.md -> AGENTS.md
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

When the sibling packages are being worked on together, install all three editable from their checkouts rather
than letting pip pull the `@main` git dependencies. This cannot be one `pip install` — the git-URL dependencies
conflict with local editables and pip raises `ResolutionImpossible`. Stage it (see `DEPLOYMENT.md`):

```bash
python -m pip install -e ~/PythonProjects/OptivEdge
python -m pip install -e ~/PythonProjects/OptivEdgeIntegrations --no-deps
python -m pip install -e ~/PythonProjects/OptivEdgeAssessments --no-deps
python -m pip install requests xmltodict python-docx docxtpl XlsxWriter
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

Run this repo's own test suite (`src/assessments/tests/`) via the existing local-dev settings module,
`assessments.settings.default` (not a downstream integration example - see `DEPLOYMENT.md` for that):

```bash
DJANGO_SETTINGS_MODULE=assessments.settings.default python -m django test assessments
```

Run Django checks, migrations, and UI smoke tests beyond the test suite from a downstream host Django
project that installs this package.

## Core Behavior Rules

* Consume normalized OptivEdgeIntegrations data models such as security rules, management-plane profiles, address objects, and enforcement scopes.
* Do not add vendor-specific API calls to assessment views, reporting modules, catalog modules, or control-query evaluation code.
* Keep views thin; put reusable logic in focused modules such as `controls_catalog`, `search`, `reporting`, `findings.py`, and `management_findings.py`.
* Preserve canonical query model labels such as `integrations.SecurityRule`; do not replace them with Python import paths.

## UI Rules

Use the OptivEdge shell and existing template patterns — `{% extends "base.html" %}` and the shared
`components/` includes resolve through Django's app-directories loader with no import. Do not create a second
application shell inside assessment templates.

Use the existing Lucide template tag pattern (the tag library and its icon SVGs live in OptivEdge):

```django
{% load lucide %}
{% lucide "icon-name" class="h-4 w-4" %}
```

Do not inline duplicate SVGs when a Lucide icon exists.

## Data And Security

Assessment data and report exports may be client-sensitive. Do not commit generated client reports, local exports, databases, `.env` files, or other local runtime artifacts unless they are intentionally versioned fixtures or bundled catalogs.

## Inherited Integrations Data Model

This app assesses models it does not own. Four properties of those models are not obvious
from their field names, and each has bitten someone. The authoritative account is
OptivEdgeIntegrations `CLAUDE.md`, sections "Topology model hierarchy" and "Object scope
resolution (PAN-OS)"; read it before writing anything that reasons about scope, precedence
or topology.

* **`precedence_rank` is derived, not chosen.** PAN-OS resolves on two scopes —
  vsys-specific beats shared — with local-vs-pushed being provenance rather than a
  precedence level. Integrations now derives the rank from the namespace via
  `precedence_for()`: vsys-scoped namespaces are 10, shared-scoped 20, vendor 90/95. The
  fixtures here hardcode `precedence_rank=10` and `=90`, which remain correct under the
  collapsed scheme, but prefer `precedence_for()` in new fixtures. Equal ranks are now
  *meaningful*: two objects sharing a name and a rank occupy one scope, which PAN-OS
  rejects, so it signals a collection fault rather than a tie to break.

* **`ApplianceGroup` is an HA/multi-appliance relationship, not a Panorama marker.** Views
  and reporting here `select_related` through `enforcement_point__appliance_group` and
  render its name. Do not infer Panorama-management from it — Integrations used to, which
  was a latent bug, and now reads `ManagementStation.station_type` (`is_panorama_managed()`).
  That is the explicit discriminant; use it here too.

* **`DeviceConfigurationProfile` is one row per Appliance, so an HA pair produces two.**
  Most of its fields (NTP, banner, idle timeout, permitted-IPs, service enablement) are
  synchronized across the pair, so a control targeting them yields two identical findings
  for what is one configuration. HA fields genuinely differ per node and should not be
  collapsed. There is currently nothing comparing the two profiles, so a pair that has
  *drifted* where it should be synced produces no finding at all.

* **An enforcement point is a vsys, and a single-vsys firewall is still a vsys.** There is
  no "device-level" assessment target for policy or objects; `Control.target_model` picks
  between `integrations.SecurityRule` / `integrations.DeviceConfigurationProfile` and that
  is the whole vocabulary.

## Surfaces pending replacement

Two surfaces are known-incomplete and are NOT to be extended or "fixed" opportunistically.

**The Findings pages** (`FindingListView`, `templates/assessments/finding_list.html`) and
**the client report** (`reporting/context.py`, `reporting/workbook_data.py`) both enumerate
exactly two finding models — `RuleFinding` and `DeviceConfigurationFinding`. Seven exist. The
other five are invisible in both: 22 of the lab's 72 findings, including every certificate
finding.

It is worse than an omission on the report side: `build_report_context()` raises
`ValueError("No assessment run with rule findings exists.")` when there are no `RuleFinding`
rows, so both downloads return **500** rather than a report. The lab has 72 findings and zero
of them are rule findings, so the client deliverable currently crashes on an estate that has
plenty to report. Pre-existing, and left alone with the rest of this surface.

Leave it that way for now. Jason, 2026-09-03: the enumeration is expected to change as the
remaining domains land, and the Findings menu item "is not anchored to anything permanent right
now" — so wiring five models into surfaces that are being replaced is work done twice.

What is expected to replace them: per-object browsing moves to the object tabs, which already
do it better; "everything wrong on one appliance, across every object type" becomes a
per-appliance rollup, which no object tab can answer because each tab is one model by
construction; and the report is rebuilt against whatever finding-model set exists by then.

**When adding a new finding model, do not wire it into either surface.** Add it to this list
instead, so the gap stays counted rather than forgotten. That is how five models drifted out of
view without a single test failing.

Whatever replaces them must DERIVE its finding-model set from the registry rather than naming
models — the same self-extending pattern the enforcement guards use.

## Known Pitfalls

* `pyproject.toml` depends on both OptivEdge and OptivEdgeIntegrations from `@main`; prefer tags or commit SHAs for repeatable deployments.
* Use Python imports in code, for example `from optivedge_integrations.integrations.models import SecurityRule`.
* Use Django model labels in canonical query payloads, for example `integrations.SecurityRule`.
* If a shell behavior, base template, shared component or template tag is missing, check OptivEdge first; if a
  firewall model, collector or integration view is missing, check OptivEdgeIntegrations.

## Git hooks

`.githooks/` is committed and enabled per clone with:

    git config core.hooksPath .githooks

**Each clone must run that once.** Hooks live outside the tree by default, so a committed hook
directory does nothing until git is pointed at it, and git has no way to make that automatic.

`pre-commit` runs the structural guards only - `test_findings_rest_on_columns`,
`test_query_service_boundary` and `test_reseed` - because those are the checks whose
regressions fail SILENTLY: a control query
reaching a JSON column stops matching instead of erroring, and a control type with no target
model makes a freshly applied catalog report MODIFIED. `pre-push` runs the whole suite.

Both fail rather than skip when they cannot find a Python that imports django. A check you
believe ran but did not is worse than no check. `OPTIVEDGE_PYTHON` overrides the interpreter;
otherwise it tries the repo venv then the OptivEdgeLab venv.

These are a REMINDER, not a gate: `git commit --no-verify` skips them, and github.com does not
support server-side hooks, which are the only unbypassable git-native enforcement. A real gate
needs a GitHub Actions workflow with a required status check.

## Everything an assertion rests on must be normalized

The rule behind `test_query_service_boundary`, which is worth stating as intent rather than as
three assertions:

**A control may only assert something that normalization has already interpreted.** Not because
layering is tidy, but because a normalized field has been through the discovery process - the
shape was measured on hardware, the implicit value was established, and the payload contract
records both. A module that reaches around that to a raw payload, or writes its own filter over
a normalized model, is implementing a special case: it decides what the configuration means
privately, where nothing measured it and no test pins it.

Three boundaries enforce it:

- filtering an **asserted** model happens only in `assessments/search/`. Elsewhere a queryset
  may be built and narrowed by primary key - that is how a generator turns the service's answer
  back into objects - but never by a field lookup
- nothing reads `Snapshot.payload` or a `raw_*` field. That is normalization's input
- no lookup reaches into a JSONField, statically or at runtime

"Asserted" is derived, not listed: a model is covered when a control query can target it or a
finding is recorded against it. The set extends itself as domains land.

**Why there is no JSON field NAMING convention.** It was considered and rejected: detecting a
JSON field by its name would need nineteen renames across thirteen models and would still miss
the twentieth, while `_meta` already knows which fields are JSONFields. The checks ask the model
rather than trusting a prefix. The one naming rule that does hold - `raw_*` for verbatim vendor
data - is enforced by the second boundary rather than by a linter.

## Git hooks: enable them, never bypass them

**First thing in a fresh clone, before any other work:**

    git config core.hooksPath .githooks

Hooks live outside the tree by default, so the committed `.githooks/` directory does NOTHING
until git is pointed at it. Git cannot automate this. A clone without it looks identical to a
clone with it and enforces nothing — that silence is the whole risk.

**Never use `git commit --no-verify` or `git push --no-verify`.** There is no CI gate behind
these hooks: github.com does not support server-side hooks, and by decision this project does
not run GitHub Actions. The hooks are therefore the ONLY enforcement, and bypassing one is not
deferring a check, it is removing it. If a hook fails, fix what it found or say why it is wrong
— do not step around it.
