# Data Handling

## Overview

`OptivEdgeAssessments` handles assessment workflow data.

It does not own vendor collection, raw vendor persistence, or normalized firewall integration models. Those responsibilities belong to the installed `OptivEdge` framework package.

The main data boundary is:

```text
OptivEdge
├── vendor collection
├── raw integration persistence
├── normalization
└── normalized firewall data models

OptivEdgeAssessments
├── assessment controls
├── control queries
├── assessment runs
├── findings
├── report exports
└── control catalogs
```

## Responsibility Boundary

### OptivEdge-owned data

OptivEdge owns integration data, including:

* management stations
* appliances
* appliance groups
* enforcement points
* snapshots
* security rules
* address objects
* address groups
* management-plane profiles
* future normalized vendor data

OptivEdgeAssessments may read this data but should not redefine or duplicate it.

### OptivEdgeAssessments-owned data

OptivEdgeAssessments owns assessment workflow data, including:

* `Control`
* `ControlQuery`
* `AssessmentRun`
* `SecurityRuleSearchState`
* `RuleFinding`
* `RuleFindingControlQuery`
* `ManagementPlaneFinding`
* `ManagementPlaneFindingControlQuery`
* control catalog payloads
* report export context
* assessment-specific local state

## Data Flow

Current intended flow:

```text
Vendor API
  → OptivEdge collection
  → OptivEdge raw persistence
  → OptivEdge normalization
  → normalized OptivEdge models
  → OptivEdgeAssessments queries
  → OptivEdgeAssessments findings
  → OptivEdgeAssessments reports
```

Assessment modules should not call vendor APIs directly.

If assessment functionality needs data that is not currently normalized, prefer adding collection and normalization support in OptivEdge rather than adding vendor-specific workarounds in OptivEdgeAssessments.

## Normalized Integration Data

Assessment features consume normalized integration data through OptivEdge models.

Python imports should use the installed package path:

```python
from optivedge.integrations.models import SecurityRule
from optivedge.integrations.models import ManagementPlaneProfile
```

Canonical query payloads should use stable Django model labels:

```text
integrations.SecurityRule
integrations.ManagementPlaneProfile
```

Do not convert canonical query labels to Python import paths.

## Assessment Data

Assessment data is local to this project.

### Controls

`Control` records define assessment requirements.

A control includes:

* stable `control_id`
* name
* control type
* description
* rationale
* audit guidance
* remediation guidance
* default severity
* implementation version
* active state

`control_id` should be treated as the durable identity for import/export and catalog operations.

### Control Queries

`ControlQuery` records define canonical query logic associated with controls.

A control query includes:

* parent control
* query name
* short description
* canonical JSON query
* baseline flag
* optional adjusted severity
* active state

`ControlQuery` identity should be treated as:

```text
control_id + query name
```

Baseline queries should not define adjusted severity.

Non-baseline queries may define adjusted severity when they calibrate severity for more specific matches.

### Assessment Runs

`AssessmentRun` records represent a finding-generation run.

They should capture:

* run name
* status
* start time
* completion time
* notes

Assessment runs provide historical context for generated findings.

### Findings

Current finding families:

```text
RuleFinding
ManagementPlaneFinding
```

Findings should be generated from normalized OptivEdge data and assessment control queries.

Finding records should preserve:

* assessment run
* matched control
* matched normalized object
* severity
* status
* summary
* links to matched control queries

Finding generation should not mutate normalized OptivEdge integration records.

## Search State

`SecurityRuleSearchState` stores server-side search state for security-rule assessment workflows.

It may contain:

* user-entered query text
* canonical query JSON
* generated plain-language query state

This is workflow state, not catalog data.

Search state may be short-lived and should not be treated as durable assessment evidence unless explicitly promoted into a control query or finding run.

## Canonical Query JSON

Canonical query JSON is durable application data.

It appears in:

* saved control queries
* search state
* future control catalog exports
* tests
* import/export payloads

Canonical queries should remain portable across environments.

Stable model labels are required:

```text
integrations.SecurityRule
integrations.ManagementPlaneProfile
```

Payloads should avoid database primary keys.

Use stable names, field names, operators, and query values.

## Control Catalog Data

Control catalogs are planned as versioned import/export payloads for controls and control queries.

Catalog functionality belongs under:

```text
assessments/controls_catalog/
```

Recommended structure:

```text
assessments/controls_catalog/
├── catalogs/
├── io/
├── registry.py
└── schemas.py
```

Catalog data should support:

* base controls
* industry-specific controls
* future versioned variants
* exported control sets from development environments
* import into new downstream installs

Potential catalog examples:

```text
base
banking
health_insurance
```

## Catalog Identity Rules

Catalog payloads should use stable application-level identifiers, not database primary keys.

Recommended identity rules:

```text
Catalog: catalog id + version
Control: control_id
ControlQuery: control_id + query name
```

These identities allow catalogs to be exported from one environment and imported into another without relying on matching database IDs.

## Catalog Import Behavior

Catalog imports should be explicit and idempotent.

Default behavior:

* create missing controls
* update existing controls
* create missing control queries
* update existing control queries
* do not delete missing controls
* do not delete missing control queries
* do not deactivate missing controls
* do not deactivate missing queries

Pruning or deactivation should be separate, explicit behavior.

Import previews should be preferred before broad updates through the UI.

## Catalog Export Behavior

Catalog exports should serialize current `Control` and `ControlQuery` records into a portable JSON payload.

Exports should include:

* catalog metadata
* schema version
* controls
* control queries nested under controls
* canonical query JSON
* severity values
* active states
* implementation versions

Exports should exclude:

* database primary keys
* timestamps unless explicitly needed
* assessment runs
* generated findings
* search state
* client-specific report artifacts

## Recommended Catalog Payload Shape

Use a versioned JSON object.

Example:

```json
{
  "type": "optivedge.assessments.control_catalog",
  "schema_version": "1.0",
  "catalog": {
    "id": "base",
    "name": "Base Assessment Controls",
    "version": "1.0.0",
    "industry": "general",
    "description": "Baseline controls for general firewall assessment use."
  },
  "controls": [
    {
      "control_id": "FW-RULE-ANY-SOURCE-001",
      "name": "Review rules with any source",
      "control_type": "security_rule",
      "description": "Identifies security rules that allow traffic from any source.",
      "rationale": "Rules with any source may expose more systems than intended.",
      "audit": "Review matching rules and confirm that any source is required.",
      "remediation": "Replace any source with specific address objects or groups where feasible.",
      "default_severity": "medium",
      "implementation_version": "v1",
      "is_active": true,
      "queries": [
        {
          "name": "Baseline",
          "short_description": "Source address is any.",
          "canonical_query": {
            "model": "integrations.SecurityRule",
            "operator": "and",
            "clauses": [
              {
                "field": "source_address_name",
                "op": "eq",
                "value": "any",
                "negated": false,
                "case_sensitive": false,
                "include_any": false
              }
            ]
          },
          "is_baseline": true,
          "adjusted_severity": null,
          "is_active": true
        }
      ]
    }
  ]
}
```

## Data Validation

Import/export logic should validate catalog payloads before writing database changes.

Validation should check:

* expected top-level type
* supported schema version
* catalog id and version
* required control fields
* valid control types
* valid severity values
* query list shape
* valid baseline severity behavior
* canonical query object shape
* supported canonical query model labels

Validation should fail explicitly when payloads are malformed.

Avoid silent fallback or coercion unless the behavior is intentionally defined.

## UI Import/Export Handling

Future catalog views should call the control catalog service layer.

Views should not contain import/export business logic.

Preferred view responsibilities:

```text
receive request
load selected bundled catalog or uploaded JSON
call controls_catalog service function
render preview/result
confirm import
return downloadable export
```

Preferred workflow:

```text
select/upload catalog
preview changes
confirm import
show result summary
```

Result summaries should include:

* controls created
* controls updated
* queries created
* queries updated
* skipped records
* validation errors

## Report Data

Reports are generated from assessment data and normalized OptivEdge data.

Current report formats:

```text
.docx
.xlsx
```

Report generation may use:

* controls
* control queries
* assessment runs
* findings
* application environment metadata
* normalized security rules
* normalized management-plane profiles

Generated reports may contain client-sensitive data.

Do not commit generated reports unless they are intentionally versioned fixtures or templates.

## Report Templates

Report templates may be committed if they are generic reusable templates.

Report templates should be clearly separated from generated client deliverables.

Recommended handling:

```text
commit reusable templates
ignore generated outputs
ignore local/client-specific exports unless intentionally retained
```

## Local Databases

Local SQLite databases are development artifacts.

They should not be committed.

Ignored examples:

```text
db.sqlite3
*.sqlite3
```

Database state should be recreated from:

* migrations
* OptivEdge normalized data collection
* imported control catalogs
* intentionally versioned fixtures if needed

## Generated Exports

Generated exports should not be committed by default.

Examples:

```text
generated reports
exported catalogs
temporary import files
local test artifacts
```

If a catalog export is promoted to a versioned bundled catalog, place it intentionally under:

```text
assessments/controls_catalog/catalogs/
```

and review it as source data.

## Sensitive Data

Assessment environments may include client-sensitive information.

Sensitive data may appear in:

* normalized firewall rules
* address object names
* management station metadata
* assessment findings
* report exports
* uploaded/exported control catalogs if customized for a client
* local SQLite databases

Do not commit sensitive client data.

Do not commit `.env` files, local databases, generated reports, or client-specific exports unless explicitly intended and reviewed.

## Credentials and Secrets

Credential and secret handling primarily belongs to OptivEdge integration configuration.

OptivEdgeAssessments should not spread credential handling into assessment modules.

If assessment features require credential-like values, document the reason and keep handling localized.

Plaintext credential handling should be treated as transitional development behavior, not a final pattern.

## File Handling

Keep repository file handling predictable.

Commit:

```text
source code
generic templates
documentation
generic bundled control catalogs
tests
small generic fixtures when intentional
```

Do not commit by default:

```text
.venv/
db.sqlite3
*.sqlite3
.env
generated reports
client exports
temporary uploads
__pycache__/
*.pyc
*:Zone.Identifier
```

## Windows and WSL Artifacts

This project may be edited from Windows and WSL.

Do not commit Windows alternate data stream artifacts:

```text
*:Zone.Identifier
```

Use `.gitattributes` to keep text files normalized to LF and binary files treated as binary.

## Destructive Operations

Destructive data behavior should be explicit.

Avoid default behaviors that:

* delete controls
* delete queries
* deactivate missing catalog records
* overwrite generated findings without clear user action
* silently coerce invalid catalog data
* silently ignore unsupported query shapes

Finding regeneration may intentionally replace prior generated findings if that behavior is part of the existing workflow.

Catalog imports should not delete or deactivate records unless a deliberate option or UI flow exists.

## Testing Data Handling

Data handling tests should focus on behavior that protects portability and prevents data loss.

Useful test areas:

* export excludes database primary keys
* import creates missing controls
* import updates existing controls
* import creates missing queries
* import updates existing queries
* import does not delete extra local records by default
* invalid catalog schema fails clearly
* baseline queries reject adjusted severity
* canonical query labels remain stable
* generated report exports return valid binary files

## Current Gaps

Current data-handling gaps:

* no bundled base control catalog yet
* no catalog preview/confirm workflow yet
* no finalized export location convention
* no documented report output directory convention
* plain-language OpenAI key handling may still be development-oriented
* report template paths should be reviewed after the project split

## Rule of Thumb

If the data represents vendor collection, raw vendor payloads, normalized firewall objects, or normalized management-plane configuration, it belongs in OptivEdge.

If the data represents controls, control queries, assessment runs, findings, reports, or control catalogs, it belongs in OptivEdgeAssessments.
