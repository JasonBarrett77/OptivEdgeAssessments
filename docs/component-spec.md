# Component Spec

## Overview

This document defines reusable UI component patterns for `OptivEdgeAssessments`.

`OptivEdgeAssessments` uses the shared OptivEdge shell and builds assessment-specific workflows inside that shell.

Use these component patterns before introducing new markup structures.

## Component Principles

Components should be:

```text id="l57jcw"
compact
predictable
table-forward
low-decoration
Tailwind-first
easy to scan
easy to maintain
```

Avoid new component abstractions unless repeated usage justifies them.

Prefer Django template includes for repeated markup.

Prefer plain class bundles over complex template APIs unless the component needs structured inputs.

## Base Shell

The shared shell is provided by OptivEdge.

Assessment templates should extend the shared shell.

Required shell blocks:

```text id="kq3oxh"
title
content
```

Optional shell blocks may include:

```text id="7urvwk"
head
brand_area
side_nav
top_nav
header_actions
overlay_title
overlay_subtitle
overlay_body
```

Rules:

```text id="vgg8gw"
do not create a second shell inside assessment templates
content should receive full available width and height
child templates own local overflow
body-level scrolling should not become the default
```

## Navigation Components

### Primary Navigation Item

Use for framework-level navigation.

Expected structure:

```html id="begaz7"
<a href="..." class="inline-flex h-8 items-center gap-2 px-3 text-sm transition-colors duration-300 ...">
    {% lucide "icon-name" class="h-4 w-4" %}
    <span>Label</span>
</a>
```

Active state:

```text id="xft65b"
bg-blue-200/75 font-medium text-slate-900
```

Inactive state:

```text id="trhny0"
text-slate-600 hover:bg-blue-100/70 hover:text-slate-900
```

Rules:

```text id="ctjz61"
use icons consistently in primary nav
do not mix icon-bearing and iconless primary nav items
use Lucide through the template tag
do not inline duplicate SVGs
```

### App-Local Subnavigation

Use for assessment-local navigation inside the existing left rail.

Expected structure:

```text id="do9n4y"
section divider
section label row
indented child links
```

Approved classes:

```text id="100vid"
section divider: mt-2 border-t border-slate-200 pt-2
section label row: inline-flex h-8 items-center gap-2 px-3 text-sm
child link: inline-flex h-8 items-center gap-2 px-9 text-sm transition-colors duration-300
```

Rules:

```text id="dxxotk"
subnavigation must remain visually subordinate to primary navigation
do not create a second persistent sidebar
route-based active state is preferred
```

## Button Components

### Base Button

Base structure:

```text id="gptg54"
inline-flex h-8 items-center justify-center px-3 text-sm font-medium whitespace-nowrap focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

Buttons are text-first.

No rounded corners by default.

### Quiet Primary Button

Use for main forward actions.

```text id="v4x0a1"
inline-flex h-8 items-center justify-center border border-blue-300 bg-blue-50 px-3 text-sm font-medium whitespace-nowrap text-blue-700 hover:bg-blue-100 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

Examples:

```text id="venkq5"
Create
Add
Save
Run now
Import
Confirm Import
```

### Secondary Button

Use for normal non-destructive actions.

```text id="qzg1x7"
inline-flex h-8 items-center justify-center border border-slate-200 bg-white px-3 text-sm font-medium whitespace-nowrap text-slate-700 hover:bg-slate-50 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

Examples:

```text id="b8j3w9"
Edit
Cancel
Back
Download
Export
Preview
```

### Danger Button

Use for destructive actions.

```text id="9jzmhd"
inline-flex h-8 items-center justify-center border border-red-200 bg-white px-3 text-sm font-medium whitespace-nowrap text-red-700 hover:bg-red-50 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

Examples:

```text id="ck4rps"
Delete
Remove
Prune
Deactivate
```

### Ghost Button

Use for low-emphasis utility actions.

```text id="ja6ilc"
inline-flex h-8 items-center justify-center px-2 text-sm font-medium whitespace-nowrap text-slate-600 hover:bg-slate-50 hover:text-slate-900 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

Examples:

```text id="lcbmnn"
Close
Dismiss
```

### Button Rules

```text id="j3cjh6"
action groups should be horizontal
avoid decorative icons
use Lucide only when icon use improves recognition
do not introduce a second button system
```

## Overlay Component

Use the right-side overlay for CRUD and contextual workflows.

Typical uses:

```text id="blhqdg"
create forms
edit forms
delete confirmations
catalog import confirmation
compact contextual workflows
```

### Overlay Structure

```text id="6a6muk"
overlay root
overlay backdrop
overlay panel
overlay header
overlay body
```

Approved classes:

```text id="df095s"
overlay root: absolute inset-x-0 bottom-0 top-10 z-30
overlay hidden: pointer-events-none hidden
overlay backdrop: absolute inset-0 bg-slate-900/10 opacity-0
overlay panel: flex h-full w-[32rem] max-w-[calc(100vw-15rem)] translate-x-full flex-col border-l border-slate-200 bg-white shadow-sm
overlay header: flex h-10 shrink-0 items-center justify-between border-b border-slate-200 px-3
overlay body: min-h-0 flex-1 overflow-auto
```

### Wide Overlay Variant

Use when a contextual workflow needs more horizontal room.

```text id="xmjfsd"
w-[56rem] max-w-[calc(100vw-8rem)]
```

Allowed examples:

```text id="7tmc3d"
query editor
catalog preview
wide inspection surface
```

Rules:

```text id="iur09c"
underlying page remains rendered
overlay is contextual, not standalone
overlay body owns scrolling
do not introduce modal dialogs when overlay fits
do not widen the global default without a shell-level reason
```

## Form Component

Use compact overlay forms for CRUD by default.

### Form Structure

```text id="o0m3i6"
form wrapper
field stack
field blocks
action row
```

Field block:

```html id="jld7zm"
<div class="flex flex-col gap-1">
    <label class="text-xs font-medium uppercase tracking-wide text-slate-600">
        Label
    </label>
    {{ field }}
    {% if field.help_text %}
        <p class="text-xs text-slate-500">{{ field.help_text }}</p>
    {% endif %}
    {% for error in field.errors %}
        <p class="text-xs text-red-700">{{ error }}</p>
    {% endfor %}
</div>
```

Action row:

```text id="el6917"
flex items-center justify-end gap-2 border-t border-slate-200 px-3 py-2
```

Rules:

```text id="e7mujk"
label above input
help text below input
errors below field
use compact field spacing
use monospace inputs for technical values
do not introduce a second form styling system
```

## Delete Confirmation Component

Use inside the right-side overlay.

Structure:

```text id="7mnvbs"
confirmation message
object identifier
destructive action
cancel action
```

Recommended classes:

```text id="muojhe"
confirmation block: border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800
action row: flex items-center justify-end gap-2 border-t border-slate-200 px-3 py-2
```

Rules:

```text id="hb83gs"
underlying detail/list page remains visible
destructive action uses danger button
cancel action uses secondary or ghost button
message should name the object being deleted
```

## List View Component

Use compact table lists for object collections.

Examples:

```text id="xtkb0a"
controls list
catalog list
future saved report list
```

### Structure

```text id="8d64ga"
list region
header/action row
scrollable table region
footer row
```

Approved classes:

```text id="5e8i64"
list region: flex h-full min-h-0 flex-col
header row: flex shrink-0 items-center justify-between gap-3 border-b border-slate-200 px-3 py-2
scroll region: min-h-0 flex-1 overflow-auto
footer row: flex shrink-0 items-center justify-between border-t border-slate-200 px-3 py-2
```

### Table

```html id="9b1xuo"
<table class="min-w-full table-auto border-separate border-spacing-0">
    <thead>
        ...
    </thead>
    <tbody>
        ...
    </tbody>
</table>
```

Rules:

```text id="4gkko5"
use table-auto by default
compact row heights
explicit empty state row
footer contains count/pagination when useful
```

## Detail View Component

Use for object detail pages.

Examples:

```text id="nb5dnz"
control detail
management station detail
future catalog detail
```

### Structure

```text id="t7a31o"
identity/action row
metadata section
related table sections
```

Approved classes:

```text id="rw75qy"
detail page: flex h-full min-h-0 flex-col
detail header: flex shrink-0 items-start justify-between gap-3 border-b border-slate-200 px-4 py-3
detail section: border-b border-slate-200 px-4 py-3
metadata grid: grid grid-cols-1 gap-x-8 gap-y-1 xl:grid-cols-2
label/value row: grid grid-cols-[8rem,minmax(0,1fr)] gap-x-3 gap-y-1.5
```

Rules:

```text id="tto50p"
use border-separated sections, not cards
actions align with top identity row
missing values render as muted "-"
technical values use break-all
notes/prose use whitespace-pre-wrap
```

## Analytical Table Component

Use for read-heavy assessment and inspection workflows.

Examples:

```text id="vrvp9q"
security rule assessment list
rule findings
management-plane findings
catalog preview/diff
```

### Structure

```text id="1tiw12"
dense page shell
compact context/header row
local scroll frame
dense table
footer/pagination row
```

Approved classes:

```text id="u49oqe"
page shell: flex h-full min-h-0 min-w-0 flex-col px-3 py-2
header row: flex items-start justify-between gap-3 border-b border-slate-200 pb-2
scroll frame: min-h-0 min-w-0 flex-1 overflow-auto border border-slate-200
footer row: flex shrink-0 items-center justify-between border-t border-slate-200 px-3 py-2
```

### Header

```text id="ibpawj"
label: text-[11px] uppercase tracking-wide text-slate-500
title: text-sm font-semibold text-slate-900
secondary text: text-sm text-slate-600
```

### Table

```text id="ln7n3e"
table: min-w-full table-auto border-separate border-spacing-0
dense header height: h-8
dense row height: h-8
header base: sticky top-0 z-10 border-b border-slate-200 bg-slate-50 px-3 text-left uppercase tracking-wide
dense header text: text-[11px] font-medium text-slate-600
body cell: border-b border-slate-200 px-3 py-1.5
```

Rules:

```text id="l5hdo3"
use for analysis, not CRUD
local region owns scrolling
sticky headers allowed
multi-row headers allowed when they clarify grouped columns
list-valued cells may render one value per line
template-local CSS allowed for striping and hover
```

Preferred striping:

```text id="28l15r"
odd rows: white
even rows: #f8fafc or #f1f5f9
hover: #dbeafe
```

## Severity Badge Component

Use for severity values.

Applies to:

```text id="vnb7o9"
Control.default_severity
ControlQuery.adjusted_severity
RuleFinding.severity
ManagementPlaneFinding.severity
control-applied rule severity
```

### Base Structure

```html id="ej2wca"
<span class="inline-flex h-6 items-center border px-2 text-xs font-medium whitespace-nowrap ...">
    Medium
</span>
```

### Palette

```text id="vmtse2"
informational: border-slate-200 bg-slate-200 text-slate-800
low: border-emerald-200 bg-emerald-50 text-emerald-800
medium: border-yellow-200 bg-yellow-50/75 text-yellow-800
high: border-orange-200 bg-orange-100 text-orange-800
critical: border-red-200 bg-red-100 text-red-800
```

Missing value:

```text id="sdmzba"
-
```

Rules:

```text id="5dm0jb"
do not use saturated alert backgrounds
do not render missing severity as a muted badge
use same palette across all assessment surfaces
```

## Toggle Component

Use the existing shared toggle component.

Expected includes:

```text id="ovrovu"
templates/components/toggle.html
templates/components/partials/toggle_control.html
```

Required input:

```text id="yyx7xd"
field
```

Optional inputs:

```text id="36ydfx"
size
label_prefix
label_on
label_off
text_color
text_weight
text_size
text_tracking
```

Allowed sizes:

```text id="db8uu7"
sm
md
lg
```

Rules:

```text id="vt4f8o"
do not add new toggle sizes
keep peer-driven interaction model
use existing active/inactive text behavior
```

## Message Component

Use for success, warning, and error messages.

### Base

```text id="e5l4d5"
border px-3 py-2 text-sm leading-5
```

### Success / Info

```text id="guzgfn"
border-blue-200 bg-blue-50 text-blue-800
```

### Warning

```text id="htx9dq"
border-yellow-200 bg-yellow-50 text-yellow-800
```

### Error

```text id="c5zwx4"
border-red-200 bg-red-50 text-red-800
```

Rules:

```text id="vc80sp"
message text should be specific
avoid generic "Success" or "Error"
include counts for import/export operations
show validation failures clearly
```

## Empty State Component

Use inside the relevant region.

### Table Empty Row

```html id="c6yzjs"
<tr>
    <td colspan="..." class="px-3 py-8 text-center text-sm text-slate-500">
        No records available.
    </td>
</tr>
```

### Placeholder Block

```html id="egr702"
<div class="flex h-full items-center justify-center text-sm text-slate-500">
    No data available.
</div>
```

Rules:

```text id="ms5sha"
empty states should be explicit
empty states stay inside the current region
avoid large decorative empty states
```

## Pagination Component

Use compact horizontal pagination.

Structure:

```text id="57pzok"
row count
previous/next controls
page range
```

Approved classes:

```text id="w1u8qu"
container: flex items-center gap-2
text: text-sm text-slate-600
buttons: secondary button treatment
```

Rules:

```text id="2sqsq4"
place pagination near the table footer
keep controls compact
show row count where useful
```

## JSON / Code Display Component

Use for canonical query previews and catalog payload previews.

### Inline Technical Text

```text id="3rn0vi"
font-mono text-[13px] text-slate-800
```

### JSON Block

```html id="hxho45"
<pre class="w-full overflow-auto border border-slate-200 bg-slate-50 p-3 font-mono text-[12px] leading-5 text-slate-900">
...
</pre>
```

### JSON Textarea Editor

```text id="bc6mpl"
min-h-72 w-full border border-slate-300 bg-white px-3 py-2 font-mono text-[12px] text-slate-900 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20
```

Rules:

```text id="xhl5w7"
canonical query JSON should be readable
long JSON should scroll locally
do not wrap JSON in decorative cards
```

## File Upload Component

Use for future catalog import.

### Structure

```text id="04zlay"
label
file input region
help text
validation errors
action row
```

Approved classes:

```text id="nj3sgh"
file input wrapper: border border-slate-200 bg-white px-3 py-2
help text: text-xs text-slate-500
upload action row: flex items-center justify-end gap-2 border-t border-slate-200 px-3 py-2
```

Rules:

```text id="zlz4l2"
show accepted file type
show validation errors near upload control
preview before broad writes where practical
```

## Catalog List Component

Use for bundled and uploaded control catalogs.

Recommended columns:

```text id="a2yxab"
Catalog
Version
Industry
Description
Controls
Actions
```

Use compact list view table pattern.

Actions:

```text id="32d6pd"
Preview
Import
Export current controls
```

Rules:

```text id="tyy3t3"
do not make destructive sync actions primary
show catalog id and version
show import result after action
```

## Catalog Preview Component

Use dense analytical table pattern.

Recommended columns:

```text id="xgg6k5"
Action
Control ID
Control Name
Type
Default Severity
Queries
Status / Warning
```

Action values:

```text id="sgfx32"
create
update
skip
warning
error
```

Rules:

```text id="pq71vh"
preview should not write database changes
show updates clearly
show warnings/errors before import
confirm before broad write
```

## Import Result Component

Use after catalog import.

Recommended fields:

```text id="chmwy5"
controls created
controls updated
queries created
queries updated
controls skipped
queries skipped
warnings
errors
```

Use message or compact result box styling.

Base result box:

```text id="bbixyc"
border border-slate-200 bg-white px-3 py-2 text-sm text-slate-800
```

Warning box:

```text id="zblvp3"
border border-yellow-200 bg-yellow-50 px-3 py-2 text-sm text-yellow-800
```

Error box:

```text id="m302j7"
border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800
```

## Report Export Component

Use near finding review surfaces.

Actions:

```text id="aqj6wl"
Download DOCX
Download XLSX
Generate Report
```

Recommended placement:

```text id="fowk3o"
finding list header action group
report-related footer/action row
```

Rules:

```text id="t1jl7m"
do not present generated reports as persisted history unless they are stored
use secondary or quiet primary button style
show explicit prerequisite errors
```

## Search / Filter Component

Use close to the data region it filters.

Canonical query editors may use:

```text id="307t67"
wide overlay
full analytical region
JSON textarea editor
plain-language form paired with canonical query behavior
```

Rules:

```text id="b98wbi"
preserve canonical query JSON behavior
do not bypass saved query/control query flow
show validation errors clearly
```

## Component Extraction Guidance

Extract repeated markup into template includes when:

```text id="xl85w8"
same markup appears in multiple templates
same visual pattern needs consistent behavior
same component has stable inputs
```

Avoid extraction when:

```text id="75mlot"
the component has only one use
the abstraction hides page-specific semantics
the include API becomes more complex than the markup
```

## Approved Include Candidates

Good candidates:

```text id="n844jp"
severity badge
pagination controls
empty table row
catalog import result summary
metadata label/value row
button/action row
```

Avoid premature includes for:

```text id="dwquzw"
entire analytical tables
large page-specific table rows
complex query builder sections
one-off report actions
```

## What Not To Build

Do not build these without explicit need:

```text id="b1at5b"
second shell
modal system competing with overlay
generic UI component framework
global card system
global toast system
decorative icon library
custom form framework
general-purpose catalog framework beyond controls
```

## Rule of Thumb

Use these defaults:

```text id="ci6i1o"
CRUD → right overlay
read-heavy data → dense analytical table
object list → compact table list
object detail → sectioned detail view
catalog preview → dense analytical table
catalog import/export → thin view + controls_catalog service layer
severity → compact badge
technical values → monospace
actions → role-based buttons
```
