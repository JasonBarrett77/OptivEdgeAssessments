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
  *drifted* where it should be synced produces no finding at all — drafted, not built, under
  "HA peer drift is not assessed" below.

* **An enforcement point is a vsys, and a single-vsys firewall is still a vsys.** There is
  no "device-level" assessment target for policy or objects. Device-wide settings are
  appliance-scoped models of their own, and `Control._CONTROL_TYPE_TARGET_MODEL` is the whole
  vocabulary: one model per control type.

## HA peer drift is not assessed, and the assumption is now load-bearing

**Draft for after controls.json. Nothing here is built.**

An HA pair's configuration is assumed synchronized. Nothing checks it, and as of 2026-10-07 two
pieces of behaviour REST on the assumption rather than merely coexisting with it:

* the device-wide models hold one row per appliance, so a pair reports two findings for one
  configuration and a reader takes them to agree
* OptivEdgeIntegrations' `choose_local_appliance` now reads the PEER's merged config when the
  active member has none, which is correct only if the two are the same

So a drifted pair produces no finding, reports its drift as agreement, and may be assessed
against the wrong node. That is three ways of being wrong about the same thing, and the third
one arrived while fixing something else — which is the reason to write this down now rather
than when the control is built.

**What a real implementation needs, before any of it is worth starting.**

* **A per-field answer to "should this be synchronized?"** This is the whole difficulty and it
  is not a property of the model. `SystemIdentity.hostname` legitimately differs per node, and
  so do the management address and the HA priority; `PasswordComplexityPolicy.minimum_length`
  and `LoginBanner.text` must not. A control that compared whole rows would fire on every pair
  in every estate, which is the same uselessness as one that fires on none. The declaration has
  to sit beside each field, the way `DERIVED_FIELDS` does, so it cannot drift from what it
  describes.
* **A subject that is the PAIR.** Every finding model today is one row per object, and
  `Control._CONTROL_TYPE_TARGET_MODEL` is one model per control type. Drift is a statement
  about an `ApplianceGroup`, which nothing is assessed against — so this needs a finding model
  and a control type of its own, not a query over an existing one.
* **A decision about what it reports on a pair collected once.** The active member's snapshot
  is the only one present in a normal collection, and comparing a node against itself finds
  nothing. Either collection has to read both members, or the control states that it could not
  compare — and saying nothing would be the wrong answer, since "no drift found" and "not
  checked" are what this whole section exists to separate.
* **What it does with an HA pair whose members run different PAN-OS versions.** An upgrade
  takes them through that state deliberately, and defaults differ by release — so a difference
  there is expected and a finding about it is noise.

**Until then: the estate is assumed to have synchronized HA pairs, which is true of the lab and
is stated here so it is a known assumption rather than an accident.** Same reasoning as the
operating-mode note below, and the same refusal to fix it piecemeal: a control that compared a
few fields would report "no drift" on a pair that had drifted in the fields it did not compare,
which is worse than the silence it replaced.

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

## The engineer-detail workbook (`assessments/artifacts/`)

`build_workbook()` returns the .xlsx as BYTES and the line each sheet reports about itself.
Nothing in it knows about the filesystem: the caller decides whether that is a download, a
stored artifact or a test. `python manage.py build_assessment_workbook <path>` is the way to
run it without a browser.

Prototyped in `OptivEdgeProbe/scratch/xlsx_prototype/` from 2026-09-15 and moved here on
2026-09-24 once the layout settled. The move was not a copy - three things were harmless in a
script that builds one workbook and exits, and are not harmless in a long-running process:

* **`ANCHORS` was a module dict.** It maps `(kind, pk)` to a fixed cell range so one sheet can
  link into another's rows. Nothing cleared it, so a second workbook inherited the first's row
  numbers and linked to the WRONG ROW, silently. It lives on `WorkbookBuild` now.
* **The format caches were keyed by `id(workbook)`.** CPython reuses an address once an object
  is freed, so a later workbook could be handed a `Format` belonging to a closed one.
* **Guards raised `SystemExit`.** It derives from `BaseException`, so a caller's
  `except Exception` never sees it and a web worker dies instead of returning an error. They
  raise `ArtifactBuildError` now, and `test_artifacts` fails on the word reappearing.

**The findings pages ARE the workbook's tabs.** `/assessments/findings/` mirrors the Summary -
engagement, totals, then the domains grouped by PAN-OS category with their severity counts -
and `/assessments/findings/<slug>/` renders one domain's table. Jason, 2026-09-25: "The live
findings views and page should closely match the xlsx artifact."

`artifacts/domains.py` is the one ordered list of domains. The workbook builds its findings
tabs from it and the views route on it, so a domain added there appears in both places, in the
same place. Slugs are explicit rather than derived from the title, for the reason
`configuration_navigation` gives: a title is the vendor's word and can be renamed; a slug is a
URL somebody bookmarked.

**The Summary is a grid, not a list of chips** (2026-09-28). It was a table per category with
each domain's severities as a row of chips, so a severity sat in a different place on every row
and the page could not be read DOWN a column - "which domain holds the criticals" was a hunt.
It is now ONE table with the categories as heading rows and a fixed column per severity, which
is the layout the workbook's Summary tab already used, for the reason its own comment gives: a
column exists even where nothing reached that severity.

Two small decisions inside that, so they are not re-litigated: a severity cell with no findings
shows a DASH, because the zeros are most of the grid and a field of noughts hides the counts
that matter; the Findings total shows a real `0`, because a headed numeric column with numbers
above and below it does not read as unfilled - which is what the page's old "No findings" text
was working around.

**Every count box is the same box.** Jason: "All bordered boxes containing the counts are the
same height/width, regardless of the content width." So the box is sized by its CELL -
`flex h-5 w-full` - and never by its digits, and the five columns share one width. A width
class on the box, or padding moved from the box to the cell, reintroduces exactly the variation
this removed; `test_findings_views` refuses both. The last column is headed **Info** because
"INFORMATIONAL" measures 97.6px at that size against "LOW" at 26.7px and was on its own setting
the width of every severity column - shortened in the HEADING only, with the full label on the
cell's `title` and everywhere else untouched. `w-16` is 64px against a 60.8px worst case
("CRITICAL" at 52.8px plus 8px of `px-1`), all measured from the font.

**The Provenance column answers "where do I go and change this"** (2026-10-05), which is a
different question from where a value came from. `read-template-provenance.md` in Integrations
states it that way and adds that separating the three unmarked cases - local, overridden,
actively overriding - "would produce a distinction with no action attached to it", because all
three mean: go to the device.

`remediation_accessor` is the walk: the tested FIELD's provenance, else the OBJECT's
`__entry__`, else nothing. A derived number has no location - `binding_count` on an unused
interface management profile is the case - but the profile is defined somewhere, and that is
where it gets deleted or rescoped.

**A walk, not a per-control declaration.** Jason, 2026-10-05: "do we need that value defined,
or a method? It seems that, for the most important question, we can get the answer from the
provenance value closest to what we're measuring." Measured first: the field answers 81% of the
lab's findings and the object a further 10%, so 71 declarations would have bought nothing a rule
does not - and would need keeping current. A per-control override is deliberately NOT built
until a control needs to contradict the walk.

Four things the walk has to get right, each with a test:

* **DERIVED counts as no answer.** `provenance_of` synthesises a DERIVED row for a declared
  computed column; letting that block the walk means the object is never reached.
* **`pan_os_default` IS an answer** and is not walked past. "Nothing configured this" is the
  reason the finding fired.
* **`stored` only decides the WORDING when nothing answered.** `provenance_cells` returns
  "Derived" on `stored=False` before it looks at the row, so a resolved row has to be passed as
  `stored=True` or the walk's answer is discarded at the last step.
* **Both cells that answer "where" walk.** The Template column read
  `provenance_of(field) if stored else None` and so named no template for a derived field on a
  pushed object; source columns now receive the walking accessor, which is what they were
  documented for.

It costs no query: `provenance_index` already loads the `__entry__` row with the rest.

Effect on the lab, before re-normalizing: 7 domains improved, +57 findings gained a location,
several going from none to all - security profiles 0 of 17 to 17, AAA server profiles 12 of 34
to 34, authentication profiles 7 of 16 to 16. Administrators is 0 to 2 of 32 only because the
lab predates the Integrations fix that writes an explicit `local` entry row.

**The Integrations side of this** was two storage bugs, found by measuring rather than assumed:
a locally defined entry recorded NOTHING in two normalizers, so absence meant both "defined on
the device" and "nothing tracks this" - 25 of 26 administrator accounts and half the interface
management profiles; and three SSH fields were read by raw dict access, discarding their marker.
`@ptpl` can also name a template STACK, which has its own config layer; it is stored as given and
not disambiguated, because an engineer reads stacks and templates alike.

**The Summary counts rather than builds.** `severity_counts()` is one query per finding model;
building all twenty-two tables to total them would do the whole job of every page to draw one.

**The findings pages ask for every tested column.** The workbook's policy tab passes
`tested_columns=()` because its own columns already show what its controls test - a decision
about that tab - so the pages pass `ALL_TESTED_COLUMNS` and carry provenance everywhere.

**"Fires when" no longer raises on an operator it cannot phrase.** It did, and nothing noticed:
the only tabs carrying that column used five of the twelve operators, so `exactly` and
`contains` were 500s waiting for a page that asked. All twelve are phrased now - the
address-set five from the LOCKED MEANINGS in `docs/security-rule-search-spec.md`, because
`equals` is whole-set equality and `exactly` is exact membership and the names do not say which
is which - and an unphrased one prints as it stands. The gap is caught by a TEST against the
search registry, which fires when an operator is added rather than when someone opens the page
that uses it.

**One table, two surfaces.** `build_findings_table(spec, tested=...)` loads a domain's
findings and lays them out - columns, rows, the implicated cells, the severity counts - with no
workbook, no request and no template in sight. `write_sheet` draws it with xlsxwriter; the live
findings pages draw the same table as HTML. They match because they ARE the same table, not
because someone kept two layouts in step.

`tested` is how a surface asks for more than its tab carries. The policy tab passes
`tested_columns=()` because its own columns already show every field its controls test - a
decision about that TAB, not about the data - so a surface passing `ALL_TESTED_COLUMNS` gets
the provenance and the firing condition anyway (Jason, 2026-09-25: "can we add the provenance
data, even if both presentation surfaces don't use it?").

**The workbook is downloadable from the findings summary**, `findings/workbook/`, as of
2026-09-28. It builds ON THE REQUEST - Jason: "synchronously is fine for now" - measured at
10.2s for the lab's 153 KB file. Two things follow from that number rather than from taste: the
browser shows nothing while it builds, so a second click starts a second build, and when this
stops being tolerable the answer is a stored artifact and a job, not a longer timeout.

The route sits BEFORE `findings/<slug:slug>/`, which would otherwise match `workbook` and 404.

**A refused build redirects to the summary carrying the guard's message.** That is the whole
point of `ArtifactBuildError` deriving from `Exception`: a guard refusing means the workbook
would have been wrong, and the reader has to be told which guard and why. `base.html` does not
render messages - each page does its own - so the summary template grew a messages block,
without which the redirect would have said nothing at all.

**The filename is `artifacts/naming.py`**, not the view's: a name is not a path, so it does not
break the "nothing here knows about the filesystem" rule, and the docx will want the same
convention. `acme-op-1234567-assessment-2026-09-28.xlsx` - who, which engagement, when. The
date is the BUILD date, deliberately not a collection window: the Summary tab carries the
window, and a filename that looked like one would be read as authoritative. Each part is
slugified because client names are free text on their way into a `Content-Disposition` header,
and a deployment with no `ApplicationEnvironment` drops those parts rather than refusing the
download.

**A joined row arrives whole, and that is how one timestamp cost 1.75 GB** (2026-10-05). Every
findings tab read its Config collected column through `subject.source_snapshot.collected_at`, so
every spec pulled the snapshot into its `select_related`. That is a JOIN, and a `Snapshot`
carries `payload` - the raw merged config - which Django decodes on fetch whether or not anyone
reads it. 511 rule findings pointing at 8 distinct snapshots fetched 210 MB of JSON text and
turned it into 1.75 GB of Python objects, to render 8 dates. Security Rules took 13.24s; all 23
tabs summed, 25.01s.

Query counts were never the signal - 12 before, 13 after. Memory was: ~5.9 MB per finding row,
and `tracemalloc` put 142 of one tab's 184 MB on `json/decoder.py`.

Three things came out of it, and the order matters:

* **`FindingBase.snapshot`** records the configuration a finding was COMPUTED FROM, copied off
  the subject by the generator. The subject's own `source_snapshot` says what that object is
  CURRENTLY parsed from, and normalization repoints it in place, so a finding read through the
  relationship reports a date later than anything it was derived from. `on_delete=PROTECT`,
  nullable, `related_name="+"` - which is why it can sit on the abstract base where
  `assessment_run` and `control` cannot. One write site: all 22 generators route through
  `object_findings.generate_object_findings`.
* **`collected_at_by_snapshot`** seeds one `{snapshot_id: collected_at}` map per build off
  `snapshot_id`, a column on rows already loaded, so the snapshot table is not joined at all.
  `source_snapshot` is gone from all four specs that named it. Security Rules: 0.83s, 20 MB.
* **`collected_at_by_appliance`** (was `latest_merged_config`) asks the database for
  MAX(collected_at) per appliance instead of building 112 Snapshot instances to keep 3 dates.
  4.60s/558 MB to 9ms/0.36 MB, and the workbook from 11.98s to 2.07s. It returns the DATE, not
  the row - handing back a row is what invites the next caller to read one more field off
  something that cost a megabyte.

**Deferring every JSONField would have been worse than the bug.** Most of them are read -
`ciphers`, `kex`, `macs`, `bound_interface_names`, `exposed_surfaces`,
`unauthenticated_servers` are the newline-separated cells - and a deferred field that IS read is
fetched lazily: right answer, one query per row, nothing raised. `verbatim_payload_paths` defers
only fields that are BOTH a JSONField (asked of `_meta`) and `raw_*` (the one naming rule that
holds here, and already unreadable by the query service boundary). `test_artifacts` builds every
domain both ways and requires identical query counts - warming both paths first, because
`get_for_model` caches per process and unwarmed it reports +1 on all 23 domains. A constant
offset is a cache miss; an N+1 would cost one query per ROW.

**Two structural guards were narrowed by this and are worth re-reading before trusting.** Both
identified a finding's subject as "any FK into integrations", true only while a finding had one.
`FindingBase.snapshot` gives every finding a second, so `test_findings_rest_on_columns` reported
Snapshot as 24 unreachable subjects and `test_query_service_boundary` admitted it to the
asserted set. Both now ask `finding_registry` for the subject it NAMES. Stricter, not looser:
Snapshot is normalization's input, and `payload` is already forbidden outright.

**A member's provenance is bulk-loaded too** (2026-10-05). The subject's always was; its
MEMBERS' was not - `member_provenance` called `member.provenance_for("__entry__")` per member,
so Management Interfaces issued 88 of its 96 queries one service and one permitted source at a
time. `member_provenance_index` builds one index over every child row the spec's value readers
walk to, and `member_provenance` takes it as an argument, which is what stops the per-member
query returning: there is no longer a version of that function able to look one up on its own.
96 queries to 11, rows byte-identical.

It scaled with MEMBERS and not with rows, which is why 15 rows cost 96 queries and why it
stayed invisible - 0.026s on the lab. `test_artifacts` now refuses any `provenance_for` call
under `artifacts/`, parsed with `ast` rather than grepped, because the docstrings there NAME the
call they replaced and a text match cannot tell an explanation from a reintroduction.

**Every layout helper takes the `build`, not the workbook.** A sheet writer is
`write_sheet(build)` and reads `build.workbook` for the xlsxwriter calls. That is what keeps
the state's lifetime equal to the file's.

**The guards are the reason this is worth trusting as a deliverable** and are kept exactly as
they were: a workbook that silently omits a finding is worse than no workbook. The one behaviour
change was a bug the move exposed - the tab's category came from the controls that LOADED, so a
control type whose controls were all inactive raised `IndexError` instead of drawing an empty
tab. It reads the spec's own control type now.

**`utc()` converts rather than formatting as it stands.** Every timestamp column is headed
"(UTC)", which was true only by accident of `USE_TZ`. A naive value is read AS UTC, because
that is where these come from - a `collected_at` Django stored in UTC - and not machine-local,
which is what `astimezone` would assume.

Verified by building the same snapshot with the prototype and with this package: **95 of 97 zip
members byte-identical**, the two that differ being the build timestamp.

## Building a query, and keeping it

**One surface builds queries**: the configuration explorer,
`/assessments/configuration/<category>/<object>/`, and every one of its objects has a real
query view rather than a placeholder.

`/assessments/security-rules/` was the original and was RETIRED on 2026-09-25, once the
explorer matched it item for item: the same 23 fields (hard-coded in that page's template,
derived from the compiler registry here, so they can no longer drift), the same columns and
values, the same `control` / `control_query` / `search_state` / `edit_search` parameters, and
pagination it never had - it rendered all 889 of the lab's rules in one page. Two sidebar
doors into one room is worth removing while it is still a route and a nav entry.

Two things moved with it. The plain-language translator now writes a `ConfigurationSearchState`
and sends its result to `Policies > Security`; `SecurityRuleSearchState`, which only that page
read, is deleted (migration 0029). And "Edit Prompt" is now offered by the explorer whenever
the applied state carries a `query_text` - keyed on the state rather than on the object, so
nothing there needs to know which pages have a plain-language front end.

**Discovery is only half of it.** A query that answered something has to become a control's
query, which is the `load_from_search` POST into `ControlQueryCreateView`: it parses the
payload, checks it against the selected control's `target_model`, and opens the control-query
form on it. That view was always generic. Until 2026-09-25 the BUTTON existed in one template -
the retired page's - so an operator could discover on any of the explorer's objects and could
only keep the result if the object happened to be a security rule. That asymmetry is why the
old page could not simply be deleted first.

**The explorer offers it in two places**: beside Apply Query in the builder, and on the results
bar once a query is applied, so an applied query can be saved without reopening the builder to
press a button. An unqueried page offers neither - a button that saves an empty query is a trap.

**Previewing a control seeds the builder with its baseline.** Calibration means adjusting what
the control already asks against real data; opening the builder empty meant rebuilding that
query by hand first. A query of the reader's own always wins over the seed - what is on screen
is what saves - and the save action CREATES a query rather than editing the baseline, so what
comes out of this loop is the calibration query sitting next to the one it started from.

**The previewed control travels with the query.** `control_preview.pk` goes into the form, so
saving from a preview lands on that control instead of asking the operator to find it in a list.

The risk this added is worth naming: the action now exists on twenty-four object pages, so a
query built on one can be aimed at a control of another type. `ControlQueryCreateView` restores
the control's default and says which model the query targets, rather than storing one that can
never match - `test_configuration_queries.SaveQueryOntoAControlTests` pins that.

## Assessments tables show the value whole

`templates/assessments/partials/table_styles.html`, keyed on the `oea-table` class and pulled
in through `{% block head %}`. Jason, 2026-09-27: "ensure lines do no break on '-', no
truncation, and tables can scroll horizontally." Those are one rule: the cell shows its value
whole and the TABLE scrolls.

**`white-space: nowrap` is what stops a break at a hyphen.** A hyphen is a soft wrap
opportunity per UAX #14, so `aes256-gcm`, `TLSv1.2 - TLSv1.3` and `pushed_pre` were all fair
game for the line breaker. There is no property that suppresses only that break while still
wrapping at spaces - the alternative is wrapping every token in the markup - so a data cell
does not wrap at all and the container scrolls in both directions. A cell holding SEVERAL
values still shows one per line: those are `<br>`, which nowrap honours.

**`table-fixed` was the other half of truncation** and is gone from every table: a fixed layout
hands each column a width and makes the content fit it. `min-w-full` replaces `w-full` so a
table can exceed its container rather than folding to it.

**Prose opts back in** with `oea-prose`: a domain description, a catalog description, a query's
short description. A sentence held on one line scrolls the page for no reason.

**A cell holding several values puts one on each line.** Jason, 2026-09-27: "In fields where
multiple values may exist, the values should be separated by new lines." Eight cells were
comma-joined - the three SSH algorithm cells, unauthenticated NTP servers, exposed SNMP
surfaces, revocation checks, sequence members and the control preview's matched queries - which
read as a paragraph, and read as a very WIDE one once a data cell stopped wrapping. The split
is made as TEXT, on newlines, and the template runs each cell through `linebreaksbr`, so
device-supplied values stay escaped. The workbook already did this, so a page and its tab now
agree. An authentication sequence keeps its `>` marker on the lines after the first: the order
is the fallback order, so losing it with the commas would have cost more than the wrapping did.
`test_table_presentation` fails on a `", ".join` reappearing in either presentation module.

**The stylesheet is assessments-owned.** The shell's
`components/partials/analytical_table_styles.html` is OptivEdge's and shared with every other
app, so it is not the place for this.

`test_table_presentation` checks it statically - every `<table>` carries the class, no template
fixes its layout, no cell truncates - because a page can carry the stylesheet and a table that
ignores it, and nothing at runtime would say so.

## Building a query from the rows you ticked

`configuration_selection.py`. Tick rows on a query page, press the button, and the builder
opens on a query those rows satisfy. Jason, 2026-09-26: "this is a convenience feature, not
particularly intelligent... But having it all filled in is the time saver."

**Only the columns on screen seed it.** `ResultsSpec.query_fields` maps a column heading to the
one queryable field it presents; a composite column - "Character Classes", "Protocol Range",
"Referenced By" - has no entry and contributes nothing, because there is no single value a
clause could carry. **All twenty-four pages are mapped** as of 2026-09-27, and a test refuses a
page with no mapping - a page whose every column really is a composite would have to argue the
case rather than quietly ship without the button.

**Build by reader, verify by compiler.** Reading a field off an object is a second copy of what
the compiler knows about that field, and if the two drift the button produces a query that does
not select the rows it came from - silently, which is the worst way for this to fail. So every
clause is compiled and checked against the selection, and one that would exclude a selected row
is DROPPED. Drift shows up as a missing clause instead of a wrong answer.

That is not hypothetical, and the three cases are worth keeping:

* `binding_count` and `configured_hostname` are query names whose model attributes are
  `bound_interface_count` and `hostname`. Both were mapped, both were unreadable, and both
  produced no clause at all - which looks exactly like a field the rows disagreed on.
* `certificate_name` on a `ManagementTlsBinding` is read BY THE COMPILER through the joined
  profile, deliberately, so the binding's copy of it cannot drift. Reading the copy would
  disagree with the compiler on exactly the rows where the drift matters. Hence
  `MODEL_FIELD_PATHS`: a path that is right for one model and wrong for another.

The test reads every mapped field off a real object rather than checking a list of names: a
path can be right in the map and wrong on the model, and only reading it tells the difference.

**`any` is opt-in, and forgetting it matches nothing.** The semantic address operators exclude
`is_any` members unless a clause sets `include_any` - right for a query about 10.0.0.0/8, where
`any` members would swamp it, and self-defeating for a query about `any` itself, where the gate
excludes exactly the members being asked for. `source_address exactly any` without the flag
returns 0 of 889 rules on the lab; with it, 89.

Three things were wrong with that on 2026-09-27, found from one report - a query built from a
selected rule showed the right row behind the builder and none after "Apply Query":

* the builder had NO control for the flag, so it was a query a person could build and that
  could never match
* `serialise` rebuilt each clause from field/op/value/negated, so a loaded query LOST the flag
  the moment it was re-applied - which is the report
* `configuration_selection.clause()` hardcoded it false, so a clause read off an `any` member
  was dropped by the verify step: correct, and quiet

Now: a "Match any?" toggle on the fields that honour it (derived from the operator set, so a
new semantic address field arrives with it), `serialise` carries it through, and a clause whose
VALUE is `any` sets it - asking for `any` while excluding `any` is never what was meant.

**Each press is its own group, ANDed with what was there.** Refining stacks rather than merges;
flattening two `eq` clauses on one field into one group would ask for a row that is two things
at once. Only the root carries `model` (`search.syntax`), so an existing root is nested as a
plain group.

**Names, not addresses, by default.** A rule's address members are read as the names the rule
references, which take `eq` on `source_address_name`. `includes` belongs to the SEMANTIC field
`source_address` - membership of a name and membership of an address space are different
questions - and the "also match resolved addresses" checkbox is what asks the second one.

**Selection is per page.** No hidden state between pages; refining first makes a cross-page
sweep largely unnecessary.

## The surfaces that were pending replacement, and what replaced them

Nothing is pending here any more. Kept as a record of what was lost and what took its place,
because both were deleted on 2026-09-25 and a deletion with no account of it reads as an
accident.

**The Findings pages** enumerated exactly one finding model of twenty-three - `RuleFinding` -
so every certificate, authentication, administrator and device-wide finding was invisible
there. `/assessments/findings/` replaced them: it renders the workbook's own tables, and its
domain list comes from `artifacts/domains.py` rather than from models named in a view, which
is the self-extending pattern that would have prevented the drift in the first place.

**The twenty device tabs** went with them. They were object-centric - one row per object with
its findings counted, plus a provenance toggle - and the findings pages are finding-centric.
Jason, 2026-09-25: "The query builder views show everything, the findings views show the full
state of control outcomes." So the case those tabs answered, *every object of a type including
the clean ones*, is the configuration explorer's, which does it with a query and provenance of
its own. What did NOT survive: the per-object provenance toggle as a table mode, and the tab
that listed unassessed fields beside assessed ones. Both are answerable on the explorer.

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

Those seven models were never wired into the old page, which was correct at the time and is
moot now: the replacement has a page per domain and the domain list is derived.

**When adding a finding model, add its domain to `artifacts/domains.py`.** That one list gives
it a workbook tab and an app page, in the same position in both.

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
