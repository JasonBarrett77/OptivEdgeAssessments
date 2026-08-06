# AGENTS.md

## Purpose

`OptivEdgeAssessments` is a reusable Django assessment app package built on the `OptivEdgeIntegrations` framework. It is installed into downstream Django host projects; it is not a standalone Django project.

This repository owns only the installable `assessments` app under `src/assessments`. Downstream host projects own `manage.py`, root settings, root URLs, databases, environment variables, and deployment configuration.

## Authoritative Documents

* `README.md`
* `DEPLOYMENT.md`
* `pyproject.toml`

Package-local workflow notes that are used by the app live under `src/assessments/docs/`.

## Repository Boundaries

OptivEdgeIntegrations owns framework concerns:

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

Do not move OptivEdgeIntegrations framework concerns into this repository.

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

Use the OptivEdgeIntegrations shell and existing template patterns. Do not create a second application shell inside assessment templates.

Use the existing Lucide template tag pattern:

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

* **`precedence_rank` values are known wrong and will change.** `PolicyObjectPrecedence`
  encodes a four-level ladder that device measurement refuted; PAN-OS resolves on two
  scopes (vsys-specific beats shared), with local-vs-pushed being provenance rather than a
  precedence level. Test fixtures here hardcode ranks (`precedence_rank=10`, `=90` in
  `tests/test_security_rule_search.py`). They will need updating when Integrations
  collapses the ladder. Do not build assessment logic that reads `precedence_rank` as a
  stable ordering.

* **`ApplianceGroup` is an HA/multi-appliance relationship, not a Panorama marker.** Views
  and reporting here `select_related` through `enforcement_point__appliance_group` and
  render its name. Integrations currently uses "has a group" as a proxy for
  "Panorama-managed", which is a known latent bug there — do not copy that inference.
  `ManagementStation.station_type` is the explicit discriminant.

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

## Known Pitfalls

* `pyproject.toml` currently depends on OptivEdgeIntegrations from `@main`; prefer tags or commit SHAs for repeatable deployments.
* Use Python imports in code, for example `from optivedge_integrations.integrations.models import SecurityRule`.
* Use Django model labels in canonical query payloads, for example `integrations.SecurityRule`.
* If a framework route, shared shell behavior, template, or template tag is missing, check OptivEdgeIntegrations first.
