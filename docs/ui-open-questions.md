# UI Open Questions

## Overview

This document tracks UI areas that are intentionally unsettled in `OptivEdgeAssessments`.

It is not authoritative.

Use it to capture decisions that should not be overbuilt before the workflow proves itself.

Authoritative UI guidance lives in:

```text
docs/style-standard.md
docs/ux-decision-rules.md
docs/design-tokens.md
docs/component-spec.md
```

## 1. Control Catalog Import Workflow

The control catalog subsystem is planned but not yet implemented.

Open questions:

```text
Should all catalog imports require preview before commit?
Should small imports allow direct import?
Should imported updates show field-level diffs?
Should imports distinguish created, updated, unchanged, skipped, warning, and error rows?
Should catalog import be a full-page workflow or a wide overlay workflow?
```

Current leaning:

```text
Use preview before broad writes.
Use create/update only by default.
Avoid destructive sync behavior initially.
```

Do not implement pruning or deactivation until the workflow is explicitly designed.

## 2. Catalog List and Registry UI

Bundled catalogs may eventually include:

```text
base
banking
health_insurance
```

Open questions:

```text
Should bundled catalogs be shown in a dedicated catalog list page?
Should uploaded catalogs appear in the same UI as bundled catalogs?
Should catalog metadata include control/query counts before import?
Should catalog metadata be loaded from files only or cached in the database?
Should catalogs have a detail page?
```

Current leaning:

```text
Start with a simple catalog list.
Keep catalog metadata file-based.
Do not add database-backed catalog registry until needed.
```

## 3. Catalog Export Scope

Initial export can include all controls and queries.

Open questions:

```text
Should export support selected controls?
Should export support active-controls-only?
Should export support control type filtering?
Should export support industry/catalog tagging?
Should export include disabled controls?
Should export include inactive queries?
```

Current leaning:

```text
Start with all controls and queries.
Add filters only after a real use case appears.
```

## 4. Catalog Ownership Tracking

A future system may track whether a control came from a catalog.

Open questions:

```text
Should Control store source catalog id/version?
Should ControlQuery store source catalog id/version?
Should locally modified catalog records be marked as changed?
Should imported records be protected from accidental overwrite?
Should catalog import show drift between installed records and bundled catalog records?
```

Current leaning:

```text
Do not add model fields yet.
Keep catalog identity in payloads first.
Add ownership tracking only if catalog lifecycle management becomes necessary.
```

## 5. Catalog Layering

Industry catalogs may either be standalone or overlays on the base catalog.

Open questions:

```text
Should banking import require base import first?
Should health insurance import layer on top of base?
Should industry catalogs override base controls?
Should industry catalogs add additional queries to existing controls?
Should import order be recorded?
```

Current leaning:

```text
Treat early catalogs as standalone complete catalogs.
Avoid overlay semantics until there is enough catalog content to justify them.
```

## 6. Catalog Diff Display

Catalog preview may need to show what will change.

Open questions:

```text
Should preview show only summary counts?
Should preview show one row per control?
Should preview show one row per query?
Should preview show field-level changes?
Should unchanged records be hidden by default?
```

Current leaning:

```text
Start with summary counts and control/query rows.
Add field-level diffs later if users need them.
```

## 7. Import Result Presentation

Catalog imports should return structured results.

Open questions:

```text
Should results appear as messages, a detail panel, or a dedicated result page?
Should warnings and errors be grouped separately?
Should successful imports link to affected controls?
Should results be persisted?
```

Current leaning:

```text
Use a compact result panel or message region.
Do not persist import history yet.
```

## 8. Control Authoring Workflow

Controls are currently normal database records edited through the app.

Open questions:

```text
Should controls be authored primarily in the UI and exported to catalogs?
Should controls be edited directly in JSON catalog files?
Should the UI expose all catalog-related metadata?
Should control query JSON remain manually editable?
Should there be a higher-level query builder for catalog authors?
```

Current leaning:

```text
Author controls in the UI.
Export reviewed controls into catalog JSON.
Keep canonical query JSON visible and editable for now.
```

## 9. Query Builder Reuse

The security-rule search workflow is richer than a simple filter form.

Open questions:

```text
Should the security-rule query builder become a reusable component?
Should management-plane queries get the same builder UI?
Should control query editing reuse the same builder instead of raw JSON?
Should catalog preview validate and display query behavior?
```

Current leaning:

```text
Reuse behavior carefully, but do not create a generic query-builder framework yet.
```

## 10. Plain-Language Query UI

Plain-language security-rule query translation exists as an assessment workflow.

Open questions:

```text
Should plain-language query creation be available inside control-query authoring?
Should translated queries be saved directly as ControlQuery records?
Should plain-language prompts be stored with ControlQuery records?
Should translated query output show a confidence or validation summary?
```

Current leaning:

```text
Keep plain-language query flow separate until control catalog authoring needs it.
```

## 11. Top Bar Role

The shell top bar is intentionally minimal.

Open questions:

```text
Should assessment pages use the top bar for context?
Should catalog import/export actions appear in the top bar?
Should environment/client context appear in the top bar?
Should report actions appear in the top bar or page header?
```

Current leaning:

```text
Keep the top bar sparse.
Place actions close to the relevant page/data region.
```

## 12. App-Local Subnavigation

Assessment navigation currently fits inside the existing left rail.

Open questions:

```text
Should control catalogs appear under the Assessments subnavigation?
Should reports get their own subnavigation item?
Should security-rule search, findings, and controls stay as separate nav items?
Should catalog import/export appear as pages or actions inside Controls?
```

Current leaning:

```text
Add catalog navigation only when catalog views exist.
Keep catalog actions near Controls unless the catalog system becomes large.
```

## 13. Status and Outcome Indicators

Success, warning, error, and skipped states are still lightweight.

Open questions:

```text
Should import statuses use badges?
Should finding statuses use the same badge family?
Should run statuses get a standardized status component?
Should warnings use yellow consistently, or stay mostly text-based?
```

Current leaning:

```text
Use understated text/border treatments.
Standardize only after repeated status displays justify it.
```

## 14. Severity Rendering

Severity badge styling is documented.

Open questions:

```text
Should severity badges be extracted into a shared include?
Should severity display use the same component in reports preview, controls, queries, and findings?
Should adjusted severity visually differ from default severity?
Should inherited/default severity be labeled differently from explicitly adjusted severity?
```

Current leaning:

```text
Use one quiet severity badge pattern.
Add a shared include once duplicated markup becomes noticeable.
```

## 15. Report Export UX

Report exports currently behave as downloads.

Open questions:

```text
Should report generation remain transient?
Should generated reports be stored?
Should there be report history?
Should export prerequisites be checked before showing download actions?
Should Word and Excel export buttons be grouped or separated?
```

Current leaning:

```text
Keep reports transient.
Do not add report history until explicitly needed.
```

## 16. Report Template Management

Report templates are currently generic files in the project.

Open questions:

```text
Should report templates be managed through the UI?
Should templates be versioned by client/industry?
Should template selection be configurable per deployment?
Should report template paths move into settings?
```

Current leaning:

```text
Keep templates as versioned project files.
Review paths after the project split.
Do not add UI template management yet.
```

## 17. Generated Artifact Handling

Generated reports and exports may include client-sensitive data.

Open questions:

```text
Should generated exports use a standard local output directory?
Should generated reports ever be stored under MEDIA_ROOT?
Should downloads stream from temporary files only?
Should local generated files be auto-cleaned?
```

Current leaning:

```text
Use temporary files for downloads.
Do not persist generated client artifacts by default.
```

## 18. Analytical Table Reuse

Dense analytical table patterns are used across assessment screens.

Open questions:

```text
Should analytical table structure be extracted into reusable includes?
Should row rendering remain page-specific?
Should table header rendering be shared?
Should pagination become a shared include?
```

Current leaning:

```text
Extract small repeated pieces first.
Avoid abstracting entire analytical tables too early.
```

## 19. Pagination Standard

Pagination exists but is not fully standardized.

Open questions:

```text
Should every paginated table use the same footer include?
Should pagination show total rows, page range, or both?
Should page size be user-selectable?
Should page size be remembered?
```

Current leaning:

```text
Use compact pagination near the data table.
Do not add page-size controls yet.
```

## 20. Search and Filtering Convergence

Security-rule search and control-based filtering are more advanced than other pages.

Open questions:

```text
Should findings pages get comparable filtering?
Should controls list get filtering?
Should catalog preview get filtering?
Should management-plane findings use the same search interaction model?
```

Current leaning:

```text
Add filtering only where data volume or workflow pressure requires it.
```

## 21. Forms and Overlay Width

CRUD forms use the standard overlay.

Open questions:

```text
Should control-query editing use the wide overlay by default?
Should catalog preview use a wide overlay or full-page workflow?
Should control forms stay standard width?
Should JSON editors always use wide overlays?
```

Current leaning:

```text
Use standard overlay for normal CRUD.
Use wide overlay for JSON-heavy or preview-heavy workflows.
```

## 22. Catalog Upload Storage

Uploaded catalog files may be used for import.

Open questions:

```text
Should uploaded catalog files be stored?
Should uploaded files be discarded after import?
Should uploaded catalog content be persisted as import history?
Should uploads be limited to JSON only?
```

Current leaning:

```text
Do not persist uploaded files initially.
Parse, preview/import, then discard.
```

## 23. Error Handling UX

Catalog and query validation can produce detailed errors.

Open questions:

```text
Should errors appear inline per row?
Should errors appear in a summary panel?
Should invalid queries be expandable?
Should validation errors include JSON paths?
```

Current leaning:

```text
Show summary errors first.
Use row-level errors when preview tables exist.
Add JSON-path detail if validation complexity grows.
```

## 24. Accessibility and Keyboard Flow

The UI is dense and keyboard-heavy usage may matter.

Open questions:

```text
Should overlays trap focus?
Should table actions have keyboard shortcuts?
Should query editor support keyboard submit?
Should catalog import confirmation be keyboard optimized?
```

Current leaning:

```text
Keep focus behavior sane and visible.
Do not add keyboard shortcuts until a workflow clearly needs them.
```

## 25. Open Design Decisions Summary

Unresolved but important:

```text
catalog preview depth
catalog import confirmation behavior
catalog layering semantics
catalog ownership tracking
report persistence
query builder reuse
management-plane query UI parity
pagination standardization
status badge standardization
top bar role
```

## Rule of Thumb

If a workflow is not repeated yet, keep it simple and page-local.

If a behavior affects data safety, catalog compatibility, package boundaries, or destructive updates, decide explicitly before implementation.
