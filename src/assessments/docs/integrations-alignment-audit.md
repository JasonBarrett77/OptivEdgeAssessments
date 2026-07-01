# Assessments / Integrations Alignment Audit

## Purpose

This note captures the concrete breakpoints between the current `assessments`
app and the refactored `integrations` normalization layer. It is the step-1
audit artifact for re-enabling `assessments` in `INSTALLED_APPS`.

## Current App State

- `assessments` is currently enabled in `base/settings.py`
- the app boots and its focused security-rule/control tests are passing against
  the ref-based `integrations` contract

## Authoritative Integrations Contract

`assessments` should now treat these as authoritative:

- `SecurityRuleSourceAddressRef`
- `SecurityRuleDestinationAddressRef`
- `AddressObject`
- `AddressGroup`

Address-like rule semantics now include:

- direct realized objects
- static group expansion
- dynamic groups
- built-in `any`
- synthetic literal IPv4 values
- EDL-backed objects marked with `is_edl`

`assessments` should consume that normalized layer and should not recreate
PAN-OS resolution rules independently.

## Breakpoints

### 1. Security rule list rendering still uses removed related names

The security-rule view still renders source and destination members using the
old removed related names:

- `securityrulesourceaddresss`
- `securityruledestinationaddresss`

Locations:

- [assessments/views.py](/home/jason/PythonProjects/AegisGo/assessments/views.py:86)
- [assessments/views.py](/home/jason/PythonProjects/AegisGo/assessments/views.py:87)
- [assessments/views.py](/home/jason/PythonProjects/AegisGo/assessments/views.py:520)
- [assessments/views.py](/home/jason/PythonProjects/AegisGo/assessments/views.py:521)

These must move to the ref layer:

- `security_rule.source_address_refs`
- `security_rule.destination_address_refs`

### 2. Search semantics for source/destination need a second phase

The current search compiler for `source_address_name` and `destination_address_name`
now owns the existing name/token-oriented behavior for source/destination
search.

Locations:

- [assessments/search/security_rules/fields/source_address.py](/home/jason/PythonProjects/AegisGo/assessments/search/security_rules/fields/source_address.py:1)
- [assessments/search/security_rules/fields/destination_address.py](/home/jason/PythonProjects/AegisGo/assessments/search/security_rules/fields/destination_address.py:1)

That is acceptable as the current name-oriented mode. Semantic
`source_address` / `destination_address` fields are now implemented alongside
it and use these operators:

- `matches`
- `includes`
- `exactly`
- `intersects`
- `equals`

Locked clarification:

- `matches` for IPv4 hosts, CIDRs, and ranges means every address in the
  queried value must be matched by the rule's effective address scope
- `includes` operates on effective resolved address members, not only the
  literal direct tokens configured on the rule
- `exactly` is reserved for exact effective-member equality
- `equals` is reserved for full effective-set equality
- `any` remains a query value, not a special operator
- by default, semantic `*_address` clauses ignore `any`
- assume `any` stands alone in a rule source/destination field
- semantic `*_address` clauses now support an `include_any` boolean option to
  allow `any` to participate in semantic evaluation
- unsupported object types should be skipped by future semantic `*_address`
  query evaluation rather than causing the whole query to fail
- semantic `*_address` query inputs are limited to IPv4 host, IPv4 CIDR, IPv4
  range, and `any`
- FQDN is currently treated as unsupported for semantic `*_address` queries
- `equals` should normalize and merge effective IPv4 member intervals first,
  and non-contiguous effective sets should not match a single queried value

The current name-oriented fields still intentionally cover:

- raw ref token matching
- effective resolved `AddressObject` matching
- `AddressGroup` matching where relevant

The semantic fields now add:

- IPv4 interval-based matching using `ipv4_start_int` / `ipv4_end_int`
- explicit traffic-match, inclusion, exactness, and overlap semantics

### 3. Security rule search semantics are split intentionally

The backend now implements both:

- name/token-oriented `*_address_name`
- semantic `*_address`

Location:

- [assessments/docs/security-rule-search-spec.md](/home/jason/PythonProjects/AegisGo/assessments/docs/security-rule-search-spec.md:310)

The next search-design work is refinement, not initial implementation.

### 4. Address analytical view removed

The assessment-specific address analytical surface has been removed for now.

That keeps `assessments` aligned with current scope instead of carrying a
second address-oriented UI while the app is being redesigned. If an
assessment-specific address view is needed later, it should be rebuilt against
the current normalized policy-object model rather than restored from the
previous implementation.

### 5. Control/query execution is still rule-row centric

Current control application logic operates on `SecurityRule` query matches and
derives severity, but it does not yet take advantage of the richer ref/object
distinctions now available in `integrations`.

Location:

- [assessments/views.py](/home/jason/PythonProjects/AegisGo/assessments/views.py:173)

This is expected for the current prototype, but future control logic should be
rebased on helper functions that understand the normalized ref/object layer.

## Implementation Order

1. build ref-based helper functions in `assessments`
2. switch security-rule list rendering to those helpers
3. keep existing name/token search under `*_address_name`
4. refine the implemented semantic `*_address` operators
5. update control application paths and live-validate
