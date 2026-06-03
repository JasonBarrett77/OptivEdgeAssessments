# UX Decision Rules

## Overview

This document defines when implementation work may proceed without asking and when a decision requires explicit user confirmation.

These rules apply to `OptivEdgeAssessments`.

The project uses the shared OptivEdge shell and assessment-specific workflows inside that shell.

## Default Principle

Proceed without asking when the change clearly reuses an existing documented pattern.

Ask before proceeding when the change:

```text
changes workflow semantics
changes data semantics
changes shell behavior
creates a new reusable UI pattern
adds destructive behavior
moves responsibilities across the OptivEdge / OptivEdgeAssessments boundary
```

## Codex May Decide

Codex may decide without asking when applying or extending existing patterns.

### Shell Usage

Codex may decide when:

```text
using the shared OptivEdge shell
extending normal content inside the shell
keeping the top bar empty
using the existing left rail
adding assessment-local subnavigation inside the existing left rail
using existing route-based active navigation behavior
```

Do not create a second shell.

Do not create a second persistent navigation layer.

### Standard Assessment Pages

Codex may decide when:

```text
using a compact table list for object lists
using a sectioned detail layout for object detail pages
using right-side overlays for create/edit/delete workflows
using dense analytical tables for read-heavy assessment views
using explicit empty states inside the relevant data region
using compact pagination near the table it controls
```

### Existing Assessment Workflows

Codex may decide when extending:

```text
controls list/detail views
control-query create/edit/delete overlays
security-rule analytical views
plain-language query views
rule finding views
management-plane finding views
report export actions
```

as long as the existing workflow semantics are preserved.

### Styling and Layout Adjustments

Codex may decide when making local adjustments to:

```text
spacing
alignment
wrapping
table density
table column sizing
metadata label width
button grouping
empty states
local scroll ownership
```

within documented patterns.

Use `table-auto` by default.

Use `table-fixed` only when a specific table needs constrained column distribution.

### Buttons and Actions

Codex may decide when applying existing button roles:

```text
quiet primary: Create, Add, Save, Run now, Import, Export when primary
secondary: Edit, Cancel, Back, Download, Export when secondary
danger: Delete, Remove, Prune
ghost: Close, Dismiss
```

### Icons

Codex may decide when using Lucide icons in:

```text
primary navigation
app-local subnavigation
approved utility actions
```

Use the existing template tag pattern:

```django
{% load lucide %}
{% lucide "icon-name" class="h-4 w-4" %}
```

Do not add decorative icons by default.

### Control Catalog UI

Codex may decide when building catalog UI that follows the established model:

```text
catalog list as a compact table/list
catalog preview as a dense table or diff-style analytical view
catalog import as explicit create/update behavior
catalog export as a download action
result summary after import/export
```

Codex may decide to show non-destructive import result summaries such as:

```text
controls created
controls updated
queries created
queries updated
warnings
errors
```

### Service-Layer Placement

Codex may decide to move reusable logic out of views into focused modules.

Preferred locations:

```text
assessments/search/
assessments/reporting/
assessments/controls_catalog/
assessments/findings.py
assessments/management_findings.py
```

Views should remain thin.

## Codex Must Ask First

### Framework Boundary

Ask before:

```text
moving OptivEdge framework logic into OptivEdgeAssessments
adding vendor API calls inside assessments
duplicating normalized OptivEdge models locally
changing canonical query model labels
changing how OptivEdge URLs or app metadata are composed
```

Framework/integration changes usually belong in the `OptivEdge` repository.

### Shell and Navigation

Ask before:

```text
changing the shared shell structure
changing the left rail width
changing brand row behavior
changing top bar height
turning the top bar into a major navigation surface
adding a second persistent sidebar
adding a new app-level navigation system outside the existing left rail
```

### Workflow and Overlay

Ask before:

```text
replacing right-side overlay CRUD as the default
introducing modal dialogs as a competing default pattern
moving CRUD workflows to full-page forms by default
changing overlay persistence behavior
changing overlay width globally
```

Local width overrides are acceptable when the documented wide-overlay pattern fits the use case.

### Data Presentation

Ask before:

```text
replacing table-first list screens with cards or another default surface
introducing a new detail-page pattern
changing default table density globally
removing local scroll ownership from dense data views
changing analytical table behavior across multiple screens
```

### Forms

Ask before:

```text
introducing a second form styling system
changing global input styling
changing global label styling
moving away from compact overlay forms
```

### Visual System

Ask before:

```text
changing the slate / blue / red palette
introducing rounded corners globally
changing typography scale globally
changing control heights globally
changing button role styling globally
expanding icon usage into dense tables as a general pattern
```

### Control Catalog Behavior

Ask before adding catalog behavior that:

```text
deletes controls
deletes control queries
deactivates missing controls
deactivates missing queries
silently overwrites large sets without preview or summary
imports industry overlays on top of base catalogs
tracks source catalog ownership on models
adds catalog layering semantics
```

Initial catalog import should be create/update only.

Destructive or broad synchronization behavior requires explicit confirmation.

### Data Semantics

Ask before changing:

```text
Control identity
ControlQuery identity
catalog identity
canonical query JSON shape
baseline query severity behavior
finding regeneration semantics
report export semantics
```

Current identity rules:

```text
Control: control_id
ControlQuery: control_id + query name
Catalog: catalog id + version
```

### Security and Sensitive Data

Ask before:

```text
committing client-specific report outputs
committing exported client catalogs
adding credential-like data to assessment models
adding persistent storage for uploaded files
changing report output storage behavior
```

Generated client artifacts should not be committed by default.

## When Uncertain

Ask when the choice materially affects:

```text
workflow semantics
data semantics
security posture
package boundaries
future catalog compatibility
repeatable deployment behavior
shared UI behavior
```

Do not ask when the task is simply applying an already documented pattern.

## Defensive Behavior Rule

Discuss defensive behavior before implementing it if it would:

```text
silently ignore invalid catalog records
silently coerce malformed query JSON
hide import errors
skip unsupported model labels without reporting them
fall back to broad defaults when data is missing
delete or deactivate records automatically
```

Prefer explicit failure and clear user-visible errors.

## Catalog-Specific Decision Rules

### May Decide

Codex may decide to implement:

```text
non-destructive import preview
create/update-only import
export all controls
download exported catalog JSON
list bundled catalogs
load catalog metadata
validate supported schema versions
show result summaries
```

### Must Ask

Codex must ask before implementing:

```text
delete missing records
deactivate missing records
catalog overlay semantics
partial selected-control export
catalog ownership tracking on models
automatic catalog import during migration
automatic catalog import on first page load
background import jobs
file storage for uploaded catalogs
```

## Reporting-Specific Decision Rules

### May Decide

Codex may decide to:

```text
place report actions near findings
render report downloads as secondary actions
keep generated reports transient
use temporary files during response generation
show explicit errors when report prerequisites are missing
```

### Must Ask

Codex must ask before:

```text
persisting generated reports
adding report history
committing generated report outputs
changing report template format
changing report artifact naming conventions globally
```

## Search and Query Decision Rules

### May Decide

Codex may decide to:

```text
preserve canonical JSON query behavior
reuse existing security-rule search patterns
reuse existing management-plane search patterns
add validation errors near the query editor
keep model labels stable
```

### Must Ask

Codex must ask before:

```text
changing canonical query schema
changing supported model labels
changing operator semantics
changing default include_any behavior
changing saved query identity
changing baseline query severity rules
```

## Documentation Decision Rules

Codex may update documentation when a change affects:

```text
setup
architecture
dependency behavior
control catalogs
data handling
UI patterns
deployment
known pitfalls
```

Codex should keep documentation concise and avoid duplicating detailed implementation notes across multiple files.

Prefer:

```text
AGENTS.md = operating guidance
README.md = project overview and setup
architecture.md = responsibility boundaries
current-state.md = what works and what is incomplete
data-handling.md = data ownership and safety
controls-catalog.md = catalog design
deployment.md = install/deploy instructions
UI docs = visual/workflow standards
```

## Rule of Thumb

Proceed when the decision is local, reversible, and consistent with existing patterns.

Ask when the decision is structural, destructive, security-sensitive, or likely to affect future compatibility.
