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
* `ApplicationEnvironment` — client/engagement metadata, consumed here by `environment.py`, `models.py`
  and `views.py`

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
python -m pip install requests xmltodict
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
* Do not add vendor-specific API calls to assessment views, catalog modules, or control-query evaluation code.
* Keep views thin; put reusable logic in focused modules such as `controls_catalog`, `search`, `findings.py`, and `management_findings.py`.
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
  here `select_related` through `enforcement_point__appliance_group` and
  render its name. Do not infer Panorama-management from it — Integrations used to, which
  was a latent bug, and now reads `ManagementStation.station_type` (`is_panorama_managed()`).
  That is the explicit discriminant; use it here too.

* **The device-wide models are one row per Appliance, so an HA pair produces two.**
  `PasswordComplexityPolicy`, `AuthenticationSettings`, `LoginBanner`, `ManagementTlsBinding`,
  `MasterKey`, `UpdateServerSettings` and `LoggingSettings` hold settings that are mostly
  synchronized across the pair, so a control targeting them yields two identical findings for
  what is one configuration. HA state, when it is modelled, genuinely differs per node and
  should not be collapsed. There is currently nothing comparing the peers, so a pair that has
  *drifted* where it should be synced produces no finding at all.

* **An enforcement point is a vsys, and a single-vsys firewall is still a vsys.** There is
  no "device-level" assessment target for policy or objects. Device-wide settings are
  appliance-scoped models of their own, and `Control._CONTROL_TYPE_TARGET_MODEL` is the whole
  vocabulary: one model per control type.

## Operating modes are not assessed, deliberately

PAN-OS implicit values differ by operating mode. `admin-lockout/failed-attempts` defaults to
**0 in normal mode and 10 in FIPS-CC mode** (Web Interface Help p.707), and that is one field on
one screen — the pattern almost certainly repeats.

Nothing here detects the mode, and no control accounts for it. **Do not fix this piecemeal.**
Jason, 2026-09-04: a half-implemented FIPS assessment would lie — a device in FIPS-CC mode
would be judged against normal-mode defaults, and would be reported as failing controls it
satisfies and passing ones it does not. Silence about a mode is honest; a wrong verdict about
one is not.

What a real implementation needs, before any of it is worth starting: detect the mode, carry it
on the appliance, resolve implicit values per mode rather than per key, and decide what every
existing control reports on a device whose mode is unknown. That is a scoped piece of work, not
a field.

Until then: the estate is assumed to be in normal operational mode, which is true of every lab
device and stated here so it is a known assumption rather than an accident.

## Severity

**One mechanism: queries.** A control has exactly one baseline query saying what fires, and
`Control.default_severity` is the severity a finding reports when only that matched. A
non-baseline query carrying `adjusted_severity` states a severity for a specific condition;
where several match, the worst wins — `control_queries.derive_control_query_severity_value` —
and it overrides the baseline tier in either direction. Downward is the important one: it is how
an assessor relaxes a finding in the field.

**The most severe matching adjustment wins, deliberately — even over one written to relax.** An
operator who writes a query for critical assets and later a broader one for normal assets that
overlaps it gets the critical severity on the overlap, whichever was written first. Relaxing a
finding therefore works only where no more severe adjustment also matches. Jason, 2026-09-11:
"Yes that was intentional."

One finding per (assessment run, control, object), guaranteed by a unique constraint, however
many queries match. `matched_query_names` on the finding records which ones did.

**A baseline query must not carry a severity** — `ControlQuery.clean()` and the catalog schema
both refuse it, because the baseline tier's severity lives on the control. **A non-baseline
query must**, or it matches and contributes nothing.

**A severity query fires on its own**, so it has to repeat whatever else the baseline required.
A query scoped only to the measured field widens the control.

A second mechanism — declarative `severity_scale` bands on the control — existed until
2026-09-09 and was removed. It was seed-only and reachable from no form, so operators could not
touch it; it was capped and could never escalate; and it produced every severity defect this
project had. The ten scaled controls became eight operator queries with a proven-zero behaviour
diff — most bands equalled the control default and needed no query at all. Do not reintroduce
it; `tests/test_severity_assignment.py` asserts no seed carries one.

**Sentinels need their own query.** PAN-OS overloads 0 — `failed-attempts 0` is lockout off,
`idle-timeout 0` is sessions never expiring — and it sorts as the gentlest value on any range
comparison. Write `eq 0` separately at the severity the meaning deserves.

## Shared machinery for findings

Do not copy a neighbouring module when adding an object type. Four pieces carry the shape:

* **`models.FindingBase` / `ObjectFindingBase`** — status, severity, title, summary,
  timestamps, the reference number, ordering, the three shared indexes and the reference
  constraint. A concrete finding declares only its own foreign keys, its `through`, its one index
  and its constraint. `assessment_run` and `control` stay concrete on purpose: on an abstract base
  they need `related_name="%(class)ss"`, which would turn `run.certificate_profile_findings` into
  `run.certificateprofilefindings`. Subclass Meta must inherit
  (`class Meta(ObjectFindingBase.Meta)`) and **concatenate** both `indexes` and `constraints` —
  Django replaces rather than merges them, and `test_finding_reference` fails for a model that
  loses the reference constraint.
* **`object_findings.generate_object_findings`** — the generator machinery, driven by an
  `ObjectFindingSpec`. Each object module supplies its subject sentence and nothing else.
* **`finding_registry.FINDING_KINDS`** — every finding model. Consumers iterate this instead of
  naming models. A concrete `FindingBase` subclass missing from it fails `test_finding_registry`.
* **`finding_run.GENERATORS`** — every generator, filling ONE run. There is one "Run Findings"
  action for policy and device findings alike; Jason, 2026-09-16: "The split between policy and
  device findings shouldn't exist." A kind missing from the tuple fails `test_finding_run`.

**A finding's identifier is `finding.reference` — `F-0001` — and nothing else.** Jason, 2026-09-16:
"A consistent, human readable, unique identifier used at presentation layers in the app and all
related artifacts. Re-runs should reset the identifier." It is unique within a run across every
finding model and starts again at 1 in each run. Never show a finding's database id: each model
numbers its own rows, so ids collide across models, and every run recreates findings. The numbers
come from one allocator per run (`AssessmentRun.next_reference_number`), in `GENERATORS` order and
then by subject. No constraint can span 23 tables, so the cross-model half of the guarantee is
`test_finding_reference`, not the database.

## Device tab views

A list view subclasses `views.DeviceTabListView` and declares `subject_model`,
`finding_model`, `finding_subject_field`, its orderings, and a `build_row`. The base reads the
two query parameters, groups findings by subject in one query, filters to rows with findings
and sets the counts.

`finding_controls = ()` means **every** control of that finding model. That is right for a tab
owning an object type outright, and silently wrong for tabs that share a finding model - omit it
there and each tab shows the others' findings. No two tabs have shared one since
`DeviceConfigurationProfile` was split and deleted on 2026-09-11, but `test_device_tab_tables`
still fails when a tab sharing a finding model does not name its controls, or when two tabs
claim the same one.

## Device tab templates

A list page extends `assessments/device_tab_base.html` and supplies three things: a
`{% block description %}`, a `COLUMNS` tuple on its view, and a `{% block rows %}`. The nav,
the provenance/findings toggles, the count, the empty state and the `<thead>` come from the
base. `{% block toolbar %}` and `{% block table %}` are overridable for pages with their own
filter box or table shell.

Cells stay hand-written - a cell is usually a value plus a provenance line plus a weak/normal
decision, and a spec for that would be harder to read than the markup. Two pages with grouped
headers keep hand-written `<thead>`s; `tables.py` records the measurement behind that.

## Surfaces pending replacement

One surface is known-incomplete and is NOT to be extended or "fixed" opportunistically.

**The Findings pages** (`FindingListView`, `templates/assessments/finding_list.html`) enumerate
exactly one finding model — `RuleFinding`. **Twenty-three exist** (`finding_registry.FINDING_KINDS`,
which is the count, not this sentence). The other twenty-two are invisible there, including every
certificate finding, every authentication finding, every administrator finding and every
device-wide setting.

**The client report was the second such surface until 2026-09-14, when it was deleted outright.**
Jason called for artifact generation to be purged entirely rather than repaired, so `reporting/`,
both downloads and the .docx template are gone, and the replacement is being designed from a
separate prototype session. Do not reconstruct the old one from git history as a starting point —
it enumerated the same single model, and `build_report_context()` raised rather than reporting on
what existed, so both downloads returned 500 on an estate with no rule findings. The lab, with 72
findings and none of that kind, was exactly such an estate.

**Until 2026-09-11 the Findings pages enumerated a second model, `DeviceConfigurationFinding`.**
`DeviceConfigurationProfile` was split into seven models, one per control cluster, and then
deleted with its finding model. The 24 controls that wrote `DeviceConfigurationFinding` -
password complexity, authentication settings, login banner, master key, update server, logging,
management TLS - now write seven finding models the page does not enumerate. That follows this
section's rule rather than breaking it, and is recorded here so the loss is counted rather than
discovered.

Leave it that way for now. Jason, 2026-09-03: the enumeration is expected to change as the
remaining domains land, and the Findings menu item "is not anchored to anything permanent right
now" — so wiring five models into a surface that is being replaced is work done twice.

What is expected to replace it: per-object browsing moves to the object tabs, which already
do it better, and "everything wrong on one appliance, across every object type" becomes a
per-appliance rollup, which no object tab can answer because each tab is one model by
construction.

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
