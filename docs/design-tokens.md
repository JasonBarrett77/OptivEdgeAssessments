# Design Tokens

## Overview

This document defines the design tokens and approved class patterns for `OptivEdgeAssessments`.

`OptivEdgeAssessments` uses the shared OptivEdge shell and Tailwind-first templates.

The UI should remain:

```text
dense
technical
compact
table-forward
low-decoration
```

Use these tokens before inventing new one-off classes.

## Layout Tokens

### Page Shell

The shared shell is provided by OptivEdge.

Expected shell structure:

```text
app root
├── left rail
└── workspace column
    ├── top bar
    ├── content frame
    └── overlay region
```

Approved class patterns:

```text
body: h-full overflow-hidden bg-white text-slate-800
app root: flex h-full min-h-0
left rail: flex h-full min-h-0 w-60 shrink-0 flex-col border-r border-slate-200
brand row: flex h-10 shrink-0 items-center border-b border-slate-200 px-4
side nav: min-h-0 flex-1 overflow-auto px-3 py-3
workspace column: relative flex min-h-0 flex-1 flex-col
top bar: flex h-10 shrink-0 items-center border-b border-slate-200 px-3
content frame: flex h-full w-full min-h-0 min-w-0
```

### Dense Analytical Page

Use for read-heavy assessment views.

```text
dense analytical page shell: flex h-full min-h-0 min-w-0 flex-col px-3 py-2
dense analytical header row: flex items-start justify-between gap-3 border-b border-slate-200 pb-2
dense analytical scroll frame: min-h-0 min-w-0 flex-1 overflow-auto border border-slate-200
```

### Detail Layout

Use for object detail surfaces.

```text
outer detail metadata layout: grid grid-cols-1 gap-x-8 gap-y-1 xl:grid-cols-2
inner metadata grid: grid grid-cols-[8rem,minmax(0,1fr)] gap-x-3 gap-y-1.5
technical wrapping: break-all
notes wrapping: whitespace-pre-wrap break-words
```

## Color Tokens

### Base Palette

```text
background: bg-white
muted surface: bg-slate-50
border: border-slate-200
primary text: text-slate-900
body text: text-slate-800
secondary text: text-slate-600
muted text: text-slate-500
de-emphasized text: text-slate-400
primary accent: bg-blue-600
quiet primary accent: border-blue-300 bg-blue-50 text-blue-700 hover:bg-blue-100
active accent: bg-blue-200/75
hover accent: bg-blue-100/70
danger accent: border-red-200 text-red-700 hover:bg-red-50
```

### Usage Rules

Use slate for structure and normal content.

Use blue for active state, primary emphasis, and focus.

Use red only for destructive or error states.

Do not introduce a new color palette without a specific documented need.

## Severity Tokens

Severity values should use quiet, readable badge styling.

### Informational

```text
border-slate-200 bg-slate-200 text-slate-800
```

### Low

```text
border-emerald-200 bg-emerald-50 text-emerald-800
```

### Medium

```text
border-yellow-200 bg-yellow-50/75 text-yellow-800
```

### High

```text
border-orange-200 bg-orange-100 text-orange-800
```

### Critical

```text
border-red-200 bg-red-100 text-red-800
```

### Badge Base

```text
inline-flex h-6 items-center border px-2 text-xs font-medium whitespace-nowrap
```

### Missing Severity

Render missing or not-applicable severity as:

```text
-
```

Do not render missing severity as a muted badge.

## Typography Tokens

### Text Hierarchy

```text
brand title: text-lg font-semibold text-slate-900
overlay title: text-sm font-semibold text-slate-900
section title: text-sm font-semibold text-slate-900
compact label: text-[11px] font-medium uppercase tracking-wide text-slate-500
field label: text-xs font-medium uppercase tracking-wide text-slate-600
primary value: text-sm text-slate-900
secondary value: text-sm text-slate-800
help text: text-xs text-slate-500
muted value: text-slate-400
technical value: font-mono text-[13px] text-slate-800
```

### Technical Values

Use monospace for:

```text
hostnames
serial numbers
paths
ports
IP addresses
CIDRs
rule names
model labels
query JSON
technical identifiers
```

Preferred token:

```text
font-mono text-[13px] text-slate-800
```

## Spacing Tokens

### Padding

```text
compact x padding: px-3
standard x padding: px-4
compact y padding: py-2
standard y padding: py-3
table cell compact: px-3 py-1.5
table cell standard: px-3 py-2
```

### Gaps

```text
micro gap: gap-1
compact gap: gap-2
standard gap: gap-3
form gap: gap-4
metadata row gap: gap-y-1 or gap-y-1.5
```

### Avoid

Avoid arbitrary spacing such as:

```text
mt-7
px-11
gap-9
py-11
```

unless there is a documented layout reason.

## Control Tokens

### Base Input

```text
h-8 rounded-md border border-slate-200 bg-white px-3 text-sm text-slate-800 placeholder:text-slate-400 focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20
```

### Monospace Input

```text
h-8 rounded-md border border-slate-200 bg-white px-3 text-sm text-slate-800 placeholder:text-slate-400 focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20 font-mono
```

### Textarea

```text
min-h-24 rounded-md border border-slate-200 bg-white px-3 py-2 text-sm text-slate-800 placeholder:text-slate-400 focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20
```

### Select

```text
h-8 rounded-md border border-slate-200 bg-white px-3 text-sm text-slate-800 focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20
```

### Field Label

```text
text-xs font-medium uppercase tracking-wide text-slate-600
```

### Help Text

```text
text-xs text-slate-500
```

### Error Text

```text
text-xs text-red-700
```

## Button Tokens

### Button Base

```text
inline-flex h-8 items-center justify-center px-3 text-sm font-medium whitespace-nowrap focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

### Quiet Primary Button

Use for main forward actions.

```text
inline-flex h-8 items-center justify-center border border-blue-300 bg-blue-50 px-3 text-sm font-medium whitespace-nowrap text-blue-700 hover:bg-blue-100 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

Examples:

```text
Create
Add
Save
Run now
Import
```

### Secondary Button

Use for contextual non-destructive actions.

```text
inline-flex h-8 items-center justify-center border border-slate-200 bg-white px-3 text-sm font-medium whitespace-nowrap text-slate-700 hover:bg-slate-50 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

Examples:

```text
Edit
Cancel
Back
Download
Export
```

### Danger Button

Use for destructive actions.

```text
inline-flex h-8 items-center justify-center border border-red-200 bg-white px-3 text-sm font-medium whitespace-nowrap text-red-700 hover:bg-red-50 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

Examples:

```text
Delete
Remove
Prune
```

### Ghost Button

Use for low-emphasis utility actions.

```text
inline-flex h-8 items-center justify-center px-2 text-sm font-medium whitespace-nowrap text-slate-600 hover:bg-slate-50 hover:text-slate-900 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

Examples:

```text
Close
Dismiss
```

## Navigation Tokens

### Primary Nav Item Base

```text
inline-flex h-8 items-center px-3 text-sm transition-colors duration-300
```

### Primary Nav Active

```text
bg-blue-200/75 font-medium text-slate-900
```

### Primary Nav Inactive

```text
text-slate-600 hover:bg-blue-100/70 hover:text-slate-900
```

### Nav Item With Icon

```text
inline-flex h-8 items-center gap-2 px-3 text-sm transition-colors duration-300
```

### Subnav Section Divider

```text
mt-2 border-t border-slate-200 pt-2
```

### Subnav Section Label Row

```text
inline-flex h-8 items-center gap-2 px-3 text-sm
```

### Subnav Child Link

```text
inline-flex h-8 items-center gap-2 px-9 text-sm transition-colors duration-300
```

## Icon Tokens

Use Lucide through the shared template tag.

```django
{% load lucide %}
{% lucide "icon-name" class="h-4 w-4" %}
```

### Common Sizes

```text
standard nav icon: h-4 w-4
compact utility icon: h-4 w-4
larger empty-state icon, if needed: h-5 w-5
```

Do not introduce decorative icons by default.

Use color through classes only.

## Overlay Tokens

### Overlay Root

```text
absolute inset-x-0 bottom-0 top-10 z-30
```

### Overlay Hidden

```text
pointer-events-none hidden
```

### Overlay Backdrop

```text
absolute inset-0 bg-slate-900/10 opacity-0
```

### Overlay Panel

```text
flex h-full w-[32rem] max-w-[calc(100vw-15rem)] translate-x-full flex-col border-l border-slate-200 bg-white shadow-sm
```

### Wide Overlay Panel

Use only for workflows that need more horizontal space.

```text
w-[56rem] max-w-[calc(100vw-8rem)]
```

### Overlay Header

```text
flex h-10 shrink-0 items-center justify-between border-b border-slate-200 px-3
```

### Overlay Body

```text
min-h-0 flex-1 overflow-auto
```

## Table Tokens

### Base Table

```text
min-w-full table-auto border-separate border-spacing-0
```

### Header Heights

```text
standard header height: h-9
dense header height: h-8
```

### Row Heights

```text
standard row height: h-9
dense row height: h-8
```

### Header Base

```text
sticky top-0 z-10 border-b border-slate-200 bg-slate-50 px-3 text-left uppercase tracking-wide
```

### Header Text

```text
standard header text: text-xs font-medium text-slate-600
dense header text: text-[11px] font-medium text-slate-600
```

### Body Cell Border

```text
border-b border-slate-200
```

### Body Cell Padding

```text
px-3 py-1.5
px-3 py-2
```

### Analytical Scroll Region

```text
overflow-auto border border-slate-200
```

### Row Striping

```text
odd rows: bg-white
even rows: #f8fafc or #f1f5f9
hover row: #dbeafe
```

Template-local CSS is acceptable for analytical table striping and hover if utility-only classes are brittle.

## List View Tokens

### List Region

```text
flex h-full min-h-0 flex-col
```

### List Header Row

```text
flex shrink-0 items-center justify-between gap-3 border-b border-slate-200 px-3 py-2
```

### List Scroll Region

```text
min-h-0 flex-1 overflow-auto
```

### List Footer Row

```text
flex shrink-0 items-center justify-between border-t border-slate-200 px-3 py-2
```

## Detail View Tokens

### Detail Page

```text
flex h-full min-h-0 flex-col
```

### Detail Header

```text
flex shrink-0 items-start justify-between gap-3 border-b border-slate-200 px-4 py-3
```

### Detail Section

```text
border-b border-slate-200 px-4 py-3
```

### Detail Metadata Grid

```text
grid grid-cols-1 gap-x-8 gap-y-1 xl:grid-cols-2
```

### Detail Label/Value Row

```text
grid grid-cols-[8rem,minmax(0,1fr)] gap-x-3 gap-y-1.5
```

### Missing Value

```text
text-slate-400
```

## Analytical View Tokens

### Page Shell

```text
flex h-full min-h-0 min-w-0 flex-col px-3 py-2
```

### Header Row

```text
flex items-start justify-between gap-3 border-b border-slate-200 pb-2
```

### Header Label

```text
text-[11px] uppercase tracking-wide text-slate-500
```

### Header Title

```text
text-sm font-semibold text-slate-900
```

### Header Secondary Text

```text
text-sm text-slate-600
```

### Scroll Frame

```text
min-h-0 min-w-0 flex-1 overflow-auto border border-slate-200
```

### Footer Row

```text
flex shrink-0 items-center justify-between border-t border-slate-200 px-3 py-2
```

## Toggle Tokens

### Track Defaults

```text
default track: bg-slate-300
active track: peer-checked:bg-blue-600
knob: after:bg-white after:shadow-sm
track transition: transition-colors duration-200
label transition: transition-all duration-200
```

### Small Toggle

```text
h-4 w-7
after:h-3 after:w-3
peer-checked:after:translate-x-3
```

### Medium Toggle

```text
h-5 w-9
after:h-4 after:w-4
peer-checked:after:translate-x-4
```

### Large Toggle

```text
h-6 w-11
after:h-5 after:w-5
peer-checked:after:translate-x-5
```

Do not add additional toggle sizes.

## Message Tokens

### Success / Informational

```text
border-blue-200 bg-blue-50 text-blue-800
```

### Error

```text
border-red-200 bg-red-50 text-red-800
```

### Warning

```text
border-yellow-200 bg-yellow-50 text-yellow-800
```

### Message Box

```text
border px-3 py-2 text-sm leading-5
```

Messages should be specific and brief.

## Empty State Tokens

### Table Empty Row

```text
px-3 py-8 text-center text-sm text-slate-500
```

### Placeholder Block

```text
flex h-full items-center justify-center text-sm text-slate-500
```

### Empty Value

```text
text-slate-400
```

Render missing scalar values as:

```text
-
```

## Pagination Tokens

### Pagination Container

```text
flex items-center gap-2
```

### Pagination Button

Use secondary button styling.

### Pagination Text

```text
text-sm text-slate-600
```

## Catalog UI Tokens

### Catalog List

Use standard compact table list tokens.

### Catalog Preview

Use dense analytical table tokens.

### Import Result Box

```text
border border-slate-200 bg-white px-3 py-2 text-sm text-slate-800
```

### Import Warning Box

```text
border border-yellow-200 bg-yellow-50 px-3 py-2 text-sm text-yellow-800
```

### Import Error Box

```text
border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800
```

## Code / JSON Display Tokens

### Inline Technical Text

```text
font-mono text-[13px] text-slate-800
```

### JSON Block

```text
w-full overflow-auto border border-slate-200 bg-slate-50 p-3 font-mono text-[12px] leading-5 text-slate-900
```

### Textarea JSON Editor

```text
min-h-72 w-full border border-slate-300 bg-white px-3 py-2 font-mono text-[12px] text-slate-900 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20
```

## File / Upload Tokens

### File Input Wrapper

```text
border border-slate-200 bg-white px-3 py-2
```

### File Help Text

```text
text-xs text-slate-500
```

### Upload Action Row

```text
flex items-center justify-end gap-2 border-t border-slate-200 px-3 py-2
```

## Approved Pattern Bundles

### Quiet Primary Action

```text
inline-flex h-8 items-center justify-center border border-blue-300 bg-blue-50 px-3 text-sm font-medium whitespace-nowrap text-blue-700 hover:bg-blue-100 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

### Secondary Action

```text
inline-flex h-8 items-center justify-center border border-slate-200 bg-white px-3 text-sm font-medium whitespace-nowrap text-slate-700 hover:bg-slate-50 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

### Danger Action

```text
inline-flex h-8 items-center justify-center border border-red-200 bg-white px-3 text-sm font-medium whitespace-nowrap text-red-700 hover:bg-red-50 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

### Ghost Action

```text
inline-flex h-8 items-center justify-center px-2 text-sm font-medium whitespace-nowrap text-slate-600 hover:bg-slate-50 hover:text-slate-900 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500/20 disabled:cursor-not-allowed disabled:opacity-50
```

### Dense Analytical Page

```text
flex h-full min-h-0 min-w-0 flex-col px-3 py-2
```

### Dense Analytical Header

```text
flex items-start justify-between gap-3 border-b border-slate-200 pb-2
```

### Dense Analytical Scroll Frame

```text
min-h-0 min-w-0 flex-1 overflow-auto border border-slate-200
```

### Overlay Panel

```text
flex h-full w-[32rem] max-w-[calc(100vw-15rem)] translate-x-full flex-col border-l border-slate-200 bg-white shadow-sm
```

### Wide Overlay Panel

```text
w-[56rem] max-w-[calc(100vw-8rem)]
```

## Avoided Patterns

Avoid these unless explicitly approved:

```text
rounded corners as a global default
large card grids
body-level scrolling
decorative icons
custom color palettes
large marketing-style headers
modal dialogs competing with overlays
custom form control systems
global table density changes
silent overflow clipping
```

## Rule of Thumb

Start with these default tokens:

```text
layout: compact flex with min-h-0
lists: table-auto compact tables
analytics: dense table in local scroll frame
CRUD: right overlay
buttons: quiet primary / secondary / danger / ghost
colors: slate / blue / red
icons: Lucide through template tag
technical text: monospace
severity: compact quiet badge
```
