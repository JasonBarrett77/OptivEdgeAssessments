# UI Style Standard

## Overview

This document defines the UI style standard for `OptivEdgeAssessments`.

`OptivEdgeAssessments` uses the shared OptivEdge shell and builds assessment-specific workflows inside that shell.

The UI is:

```text id="2wa5gt"
dense
information-first
table-forward
workflow-oriented
low-decoration
```

The goal is fast scanning, predictable layouts, and maintainable Django templates.

## Source of Truth

For shared framework shell behavior, use OptivEdge templates and components.

For assessment-specific screens, use this document together with:

```text id="yos0ix"
docs/design-tokens.md
docs/component-spec.md
docs/ux-decision-rules.md
docs/ui-open-questions.md
```

Do not introduce new visual or workflow patterns when an existing documented pattern fits.

## Core Principles

### 1. Density First

Primary users are expected to review technical data, controls, findings, and report context.

Use compact layouts.

Prefer:

```text id="7yckxb"
tables
small labels
compact action rows
border-separated sections
local scroll regions
```

Avoid:

```text id="29lxjx"
large cards
decorative spacing
marketing-style page blocks
oversized headings
unnecessary helper text
```

Persistent text must earn its space.

### 2. Consistency Over Novelty

Reuse existing patterns for:

```text id="1doogu"
shell layout
left navigation
app-local subnavigation
analytical tables
list views
detail views
right-side overlays
CRUD forms
delete confirmations
buttons
severity badges
pagination
```

If a new screen can use an existing pattern, use the existing pattern.

If a new pattern seems necessary, document why.

### 3. Tailwind First

Use Tailwind utility classes directly in templates by default.

Avoid custom CSS unless:

```text id="0px2r5"
utility-only implementation is brittle
table alignment is materially worse without CSS
scrolling behavior is difficult to express cleanly
row striping/hover behavior is cleaner locally
```

Template-local CSS is acceptable for dense analytical tables when it improves reliability.

### 4. No Decorative UI

Avoid visual decoration that does not improve usability.

Do not add icons, borders, cards, colors, shadows, or explanatory blocks only for visual interest.

Icons should support navigation or action recognition.

### 5. Explicit Empty States

Empty states should be explicit and understated.

Do not leave blank regions where data should appear.

Good empty states:

```text id="kc2syd"
No controls available.
No rule findings available.
No management findings available.
No matching security rules.
```

Avoid verbose explanations unless the user needs to know the next action.

## Shell Usage

`OptivEdgeAssessments` uses the OptivEdge shell.

Assessment templates should extend the shared shell.

Do not create a second shell inside the assessment app.

The shell provides:

```text id="5xzh5x"
left rail
brand area
top bar
content frame
right-side overlay region
shared navigation composition
```

Assessment pages should render inside the shell’s content area.

## Page Layout

### Standard Page Structure

Use a compact content layout:

```text id="bsb92m"
page/header context
primary data region
footer/pagination/status row when needed
```

Do not add a second page-level header unless the page benefits from it.

### Scroll Ownership

Use inner scroll regions.

Rules:

```text id="4bbgso"
body should not become the primary scroll container
content regions should use min-h-0
data regions should use overflow-auto
dense tables should own their own scroll frame
```

Avoid accidental page overflow caused by missing `min-h-0`.

### Width

Use available width for analytical and data-heavy screens.

Do not constrain main data tables to narrow card widths.

Use max-width only for forms, detail panels, and intentionally readable prose.

## Navigation

### Left Rail

Primary navigation should live in the shared OptivEdge left rail.

Assessment navigation may appear as app-local subnavigation inside the left rail.

App-local subnavigation should be visually subordinate to framework-level navigation through:

```text id="sjonef"
indentation
grouping
lighter emphasis
consistent active state
```

Do not create a second persistent sidebar.

### Icons

Use Lucide icons through the existing template tag pattern:

```django id="7dp5oq"
{% load lucide %}
{% lucide "icon-name" class="h-4 w-4" %}
```

Rules:

```text id="t11c13"
use icons consistently in primary navigation
do not mix icon-bearing and iconless primary nav items
do not inline duplicate SVGs when a Lucide icon exists
do not use decorative icons inside dense tables by default
```

## Typography

Use compact typography.

Preferred patterns:

```text id="9q5z1k"
section labels: text-[11px] uppercase tracking-wide text-slate-500
field labels: text-xs font-medium uppercase tracking-wide text-slate-600
primary values: text-sm text-slate-900
secondary values: text-sm text-slate-800
muted values: text-slate-400
technical values: font-mono text-[13px] text-slate-800
```

Use monospace for:

```text id="9za3to"
hostnames
serial numbers
paths
ports
IP/CIDR values
query JSON
rule identifiers
technical labels
```

Avoid large headings unless the page truly benefits from them.

## Color

Use the existing slate / blue / red pattern.

Default palette:

```text id="nyv3sy"
background: white
border: slate
text: slate
primary/active accent: blue
danger/destructive: red
```

Do not introduce a new color palette without a documented reason.

Colors should improve scanning and state recognition, not decoration.

## Spacing

Use compact spacing.

Preferred spacing:

```text id="q4ulud"
compact horizontal padding: px-3
standard horizontal padding: px-4
compact vertical padding: py-2
standard vertical padding: py-3
micro gap: gap-1
compact gap: gap-2
standard gap: gap-3
form gap: gap-4
```

Avoid arbitrary spacing such as:

```text id="cozfe2"
mt-7
px-11
gap-9
```

unless there is a specific documented layout need.

## Buttons and Actions

Buttons should be text-first.

No rounded corners by default.

Use role-based button styling:

```text id="6yc484"
quiet primary: main forward action
secondary: normal non-destructive action
danger: destructive action
ghost: low-emphasis utility action
```

Typical mapping:

```text id="bk4zka"
Create → quiet primary
Add → quiet primary
Save → quiet primary
Run now → quiet primary
Edit → secondary
Cancel → secondary
Back → secondary
Delete → danger
Remove → danger
Close → ghost
Dismiss → ghost
```

Action groups should be horizontal.

Avoid stacking action buttons vertically unless space constraints require it.

## Forms

Use the right-side overlay for CRUD forms by default.

Form structure:

```text id="vdrw5v"
overlay header
scrollable overlay body
vertical field stack
action row
```

Field structure:

```text id="xp0chz"
label
input
help text if useful
errors
```

Forms should use compact inputs and consistent widget styling.

Use monospace inputs for technical values where useful.

Do not introduce a second form styling system.

## Overlays

Use the shared right-side overlay for:

```text id="ij9v57"
create forms
edit forms
delete confirmations
compact contextual workflows
```

Overlay rules:

```text id="1im99i"
underlying page remains rendered
overlay is contextual
overlay body owns scrolling
overlay header contains title and close action
```

Use a wider overlay only when the workflow benefits from more horizontal space.

Do not introduce modal dialogs when the shared overlay fits.

## Lists

Use table-based list views by default.

List view structure:

```text id="el4fao"
compact header/action row
scrollable table region
footer count or pagination row
```

Rows should be compact.

Use explicit empty states inside the table body.

## Detail Views

Use sectioned detail layouts.

Recommended structure:

```text id="q3y4xy"
identity/action row
metadata section
related tables or child sections
```

Rules:

```text id="c0r5d2"
use border-separated sections, not cards
align actions with the identity row
use fixed-width labels for metadata
stack metadata to one column below xl
render missing values as muted "-"
```

Technical values should wrap safely with `break-all`.

Notes/prose should preserve useful line breaks with `whitespace-pre-wrap`.

## Analytical Tables

Use dense full-page analytical tables for read-heavy assessment workflows.

Examples:

```text id="3av39b"
security rule assessment view
findings views
management-plane findings
future catalog preview/diff views
```

Analytical table structure:

```text id="9s1vxa"
compact context/header row
bordered local scroll frame
dense data table
sticky headers where useful
footer/pagination row when needed
```

Rules:

```text id="q59g5w"
use table-auto by default
use table-fixed only for specific column distribution needs
allow multi-row headers when they clarify grouped columns
list-valued cells may render one value per line
prefer local scroll regions
```

Minimal template-local CSS is acceptable for row striping and hover states.

Preferred row treatment:

```text id="u5ldxk"
odd rows: white
even rows: #f8fafc or #f1f5f9
hover: #dbeafe
```

## Severity Display

Severity values should use a consistent compact badge treatment.

Use for:

```text id="at6syq"
Control.default_severity
ControlQuery.adjusted_severity
rule finding severity
management finding severity
control-applied rule severity
```

Default badge structure:

```text id="gajxkl"
inline-flex
h-6
items-center
border
px-2
text-xs
font-medium
whitespace-nowrap
```

Palette:

```text id="0h1d3b"
informational: border-slate-200 bg-slate-200 text-slate-800
low: border-emerald-200 bg-emerald-50 text-emerald-800
medium: border-yellow-200 bg-yellow-50/75 text-yellow-800
high: border-orange-200 bg-orange-100 text-orange-800
critical: border-red-200 bg-red-100 text-red-800
```

If severity is missing or not applicable, render:

```text id="wg70yc"
-
```

Do not render a muted badge for missing severity.

## Catalog UI

Control catalog workflows should follow existing patterns.

Recommended screens:

```text id="dsrnyi"
catalog list → table/list pattern
catalog preview → analytical table/diff pattern
catalog import confirmation → overlay or explicit confirm action
catalog export → secondary/quiet primary action
```

Catalog import can update existing controls and queries.

The UI should make this visible.

Import result summaries should show:

```text id="1udwpo"
controls created
controls updated
queries created
queries updated
warnings
errors
```

Preview before broad writes is preferred.

Do not hide destructive options behind ambiguous button labels.

## Messages and Alerts

Use understated message styling.

Messages should be:

```text id="db69p0"
brief
specific
action-oriented when needed
```

Good:

```text id="orv3yb"
Control catalog imported. Controls created: 4. Controls updated: 2.
```

Avoid:

```text id="qtb9k7"
Success!
Something went wrong.
```

Errors should clearly describe the failing field, catalog, query, or action.

## Loading States

Loading patterns are not fully standardized.

Prefer simple disabled states or skeleton rows over spinners when loading behavior is needed.

Do not add animated loading treatments unless the workflow requires it.

## Empty States

Empty states should stay inside the relevant region.

Examples:

```text id="d639xg"
empty table row
centered placeholder inside dashboard region
compact muted message in a bordered panel
```

Avoid large decorative empty-state illustrations.

## Pagination

Pagination should be compact.

Use:

```text id="9lqvvu"
horizontal controls
current page visibility
row count where useful
secondary button treatment
```

Keep pagination near the table footer or data region it controls.

## Search and Filtering

Search/filter UI should remain close to the data it filters.

Canonical query editors may use wider overlays or full-page regions when the content requires it.

Plain-language query workflows should still land in canonical query behavior, not bypass it.

## Report Export UI

Report export actions should appear where users review findings.

Use secondary or quiet primary actions depending on context:

```text id="aqfqfh"
Generate Report
Download DOCX
Download XLSX
```

Do not make generated reports look like permanent database records unless they are intentionally persisted.

## What Not To Do

Do not:

```text id="nar1x7"
create a second shell
add a second persistent sidebar
replace table-first lists without a clear reason
replace overlay CRUD with modal dialogs
introduce rounded corners globally
introduce a new color palette
add decorative icons
add large cards around every section
use body-level scrolling casually
silently change workflow semantics for visual convenience
```

## When to Ask

Ask before changing:

```text id="xxyzhc"
shell structure
left rail width
top bar role
default CRUD workflow
overlay behavior
default table density
global color palette
global typography scale
global button styling
navigation hierarchy
destructive catalog import behavior
```

Do not ask merely to reuse an existing documented pattern.

## Rule of Thumb

Use the smallest existing pattern that supports the workflow.

For CRUD:

```text id="pne0xg"
right overlay
```

For read-heavy data:

```text id="0ssolw"
dense analytical table
```

For object lists:

```text id="rbp0ek"
compact table list
```

For object details:

```text id="2w5xt7"
sectioned detail layout
```

For catalog import/export:

```text id="zmlpvl"
service-layer logic with table/preview UI
```
