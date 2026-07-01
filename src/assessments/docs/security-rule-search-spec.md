# Security Rule Search Spec

This document defines canonical structured search behavior for security-rule
search. It is intended to be durable reference material for:

- backend query compilation
- future help and guidance screens
- AI-driven plain-language-to-structured-search translation

The canonical search shape is the source of truth. Plain-language input may be
translated into this shape, but execution semantics are defined here.

## Root Query Shape

Security-rule queries must use the app-qualified root model:

```json
{
  "model": "integrations.SecurityRule",
  "operator": "and",
  "clauses": [
    {
      "field": "from_zone",
      "op": "eq",
      "value": "trust"
    }
  ]
}
```

The root `model` is required for security-rule search queries. Nested groups do
not repeat it.

## Scope

This document currently defines these security-rule fields:

- `config_source`
- `management_station`
- `vsys_name`
- `vsys_display_name`
- `name`
- `provenance`
- `action`
- `disabled`
- `rule_type`
- `description`
- `log_start`
- `log_end`
- `log_setting`
- `from_zone`
- `to_zone`
- `source_address`
- `source_address_name`
- `destination_address`
- `destination_address_name`
- `application`
- `service`

The repeated-value fields still use shared repeated-value semantics.

The address fields are split intentionally:

- `source_address` / `destination_address`
  - semantic IPv4 matching behavior
- `source_address_name` / `destination_address_name`
  - object, group, and raw token name matching behavior

## Canonical Clause Shape

```json
{
  "field": "from_zone",
  "op": "eq",
  "value": "trust",
  "negated": false,
  "case_sensitive": false,
  "include_any": false
}
```

Fields:

- `field`: required string
- `op`: required string operator
- `value`: required operator-specific value
- `negated`: optional boolean, defaults to `false`
- `case_sensitive`: optional boolean, defaults to `false`
- `include_any`: optional boolean, defaults to `false`
  - only meaningful for semantic `source_address` / `destination_address`
    clauses

## Field Definitions

### `config_source`

Field name:

- `config_source`

Authoritative source:

- `integrations.models.SecurityRule.config_source`

Meaning:

- search against the rule config source
- friendly matching is allowed against either the stored value or the display
  label

Examples:

- `local`
- `pushed_pre`
- `Pushed Pre-Rulebase`

### `management_station`

Field name:

- `management_station`

Authoritative source:

- `integrations.models.SecurityRule.management_station`

Meaning:

- friendly search against the related management station
- matches either station `name` or `hostname`

### `vsys_name`

Field name:

- `vsys_name`

Authoritative source:

- `integrations.models.SecurityRule.enforcement_point.vsys_name`

Meaning:

- search against the related enforcement point VSYS identifier

### `vsys_display_name`

Field name:

- `vsys_display_name`

Authoritative source:

- `integrations.models.SecurityRule.enforcement_point.vsys_display_name`

Meaning:

- search against the related enforcement point VSYS display name

### `name`

Field name:

- `name`

Authoritative source:

- `integrations.models.SecurityRule.name`

Meaning:

- search against the rule name

### `provenance`

Field name:

- `provenance`

Authoritative source:

- `integrations.models.SecurityRule.provenance`

Meaning:

- search against the rule provenance / device-group label

### `action`

Field name:

- `action`

Authoritative source:

- `integrations.models.SecurityRule.action`

Meaning:

- search against the rule action

### `disabled`

Field name:

- `disabled`

Authoritative source:

- `integrations.models.SecurityRule.disabled`

Meaning:

- search against the rule disabled state
- accepts boolean-friendly values such as `true`, `false`, `yes`, `no`, `on`,
  `off`, `1`, and `0`

### `rule_type`

Field name:

- `rule_type`

Authoritative source:

- `integrations.models.SecurityRule.rule_type`

Meaning:

- search against the rule type

### `description`

Field name:

- `description`

Authoritative source:

- `integrations.models.SecurityRule.description`

Meaning:

- search against the rule description text

### `log_start`

Field name:

- `log_start`

Authoritative source:

- `integrations.models.SecurityRule.log_start`

Meaning:

- search against the start-of-session logging flag
- accepts boolean-friendly values such as `true`, `false`, `yes`, `no`, `on`,
  `off`, `1`, and `0`

### `log_end`

Field name:

- `log_end`

Authoritative source:

- `integrations.models.SecurityRule.log_end`

Meaning:

- search against the end-of-session logging flag
- accepts boolean-friendly values such as `true`, `false`, `yes`, `no`, `on`,
  `off`, `1`, and `0`

### `log_setting`

Field name:

- `log_setting`

Authoritative source:

- `integrations.models.SecurityRule.log_setting`

Meaning:

- search against the logging profile / setting name

### `from_zone`

Field name:

- `from_zone`

Authoritative source:

- `integrations.models.SecurityRuleFromZone`

Meaning:

- search against related `from` zone values for a `SecurityRule`

### `to_zone`

Field name:

- `to_zone`

Authoritative source:

- `integrations.models.SecurityRuleToZone`

Meaning:

- search against related `to` zone values for a `SecurityRule`

### `source_address_name`

Field name:

- `source_address_name`

Authoritative source:

- `integrations.models.SecurityRuleSourceAddressRef`

Meaning:

- search against normalized source address refs for a `SecurityRule`
- matches any of:
  - the raw ref token
  - the resolved `AddressObject.name`
  - the resolved `AddressGroup.name`

Notes:

- `source_address_name` is the name/token-oriented field
- `source_address` is reserved for future IP/address-semantic matching

### `destination_address_name`

Field name:

- `destination_address_name`

Authoritative source:

- `integrations.models.SecurityRuleDestinationAddressRef`

Meaning:

- search against normalized destination address refs for a `SecurityRule`
- matches any of:
  - the raw ref token
  - the resolved `AddressObject.name`
  - the resolved `AddressGroup.name`

Notes:

- `destination_address_name` is the name/token-oriented field
- `destination_address` is reserved for future IP/address-semantic matching

### `*_address`

Field names:

- `source_address`
- `destination_address`

Authoritative sources:

- `integrations.models.SecurityRuleSourceAddressRef`
- `integrations.models.SecurityRuleDestinationAddressRef`

Meaning:

- semantic IP/address querying against effective resolved source/destination
  address members

Locked operator set for those future fields:

- `matches`
- `includes`
- `exactly`
- `intersects`
- `equals`

Locked meanings:

- `matches`
  - runtime traffic-match semantics
  - asks whether traffic using the queried value would match the rule
  - for IPv4 hosts, CIDRs, and ranges, every address in the queried value must
    be matched by the rule's effective address scope
- `includes`
  - configured/effective member semantics
  - asks whether the rule includes the queried value in its effective
    source/destination address set
  - for static groups, this operates on the effective resolved address members,
    not only the literal direct tokens configured on the rule
- `exactly`
  - strict/exclusive member-equality semantics
  - asks whether the queried value is present as an exact effective member
- `intersects`
  - overlap semantics
  - asks whether the rule's effective address space overlaps the queried value
- `equals`
  - whole-set equality semantics
  - asks whether the rule's full effective address set equals the queried value

Implementation basis for IPv4 semantics:

- use `AddressObject.ipv4_start_int`
- use `AddressObject.ipv4_end_int`
- treat IPv4 addresses, CIDRs, ranges, and built-in `any` as interval-based
  comparisons

Value conventions:

- `any` remains a value, not an operator
- `source_address matches any` means the rule matches the full IPv4 space
- `source_address includes any` means `any` is present as an effective member
- by default, `any` is ignored for semantic `*_address` evaluation unless
  `include_any` is enabled on the clause
- no separate `is_any` operator is planned for the core query language
- assume `any` stands alone in a rule source/destination field rather than
  appearing alongside other members
- `include_any: true` means semantic `*_address` evaluation should allow `any`
  members to satisfy the clause

Allowed semantic `*_address` query values:

- IPv4 host
- IPv4 CIDR
- IPv4 range
- `any`

Excluded for now:

- FQDN

Unsupported object-type behavior:

- when a future semantic `*_address` query encounters an address object or
  group type that is not supported by the operator implementation, that object
  should be skipped for query evaluation
- unsupported object types should not cause the whole rule query to fail
- unsupported object types should be documented as follow-on remediation work
- FQDN is currently treated as unsupported for semantic `*_address` operators,
  the same way dynamic groups are unsupported

Currently unsupported semantic `*_address` object types:

- dynamic groups
- FQDN address objects
- future normalized object families not yet implemented

`equals` set behavior:

- normalize and merge effective IPv4 member intervals before comparison
- if the effective IPv4 set remains non-contiguous after normalization, it does
  not match a single queried IPv4 host/CIDR/range/`any`

### `application`

Field name:

- `application`

Authoritative source:

- `integrations.models.SecurityRuleApplication`

Meaning:

- search against related application names for a `SecurityRule`

### `service`

Field name:

- `service`

Authoritative source:

- `integrations.models.SecurityRuleService`

Meaning:

- search against related service names for a `SecurityRule`

## Supported Operators

Supported by text and choice fields:

- `eq`
- `contains`

Supported by boolean fields:

- `eq`

Not permitted:

- `in`

The `in` operator is intentionally not supported for these fields in this spec.
If multi-value matching is needed later, it should be introduced explicitly as a
new, documented capability rather than implied through ad hoc behavior.

## Semantics

### `eq`

Matches a rule when at least one related value for the field exactly matches
the input value, or when a scalar field exactly matches the normalized search
value.

Example:

```json
{
  "field": "from_zone",
  "op": "eq",
  "value": "trust"
}
```

### `contains`

Matches a rule when at least one related value for the field contains the input
value as a substring, or when a text/choice scalar field contains the input
value as a substring.

Example:

```json
{
  "field": "from_zone",
  "op": "contains",
  "value": "corp"
}
```

### Negation

When `negated` is `true`, the clause matches a rule when no related field value
matches the positive predicate.

Example:

```json
{
  "field": "from_zone",
  "op": "eq",
  "value": "trust",
  "negated": true
}
```

Meaning:

- include rules where no related field value exactly equals `trust`

## Repeated-Field Rule

These fields are repeated related fields. Negation semantics must be based on
match existence, not on the existence of non-matching rows.

Required model:

- positive clause: `EXISTS(match)`
- negated clause: `NOT EXISTS(match)`

Example rule values:

- `trust`
- `dmz`

Expected results:

- `eq trust` => `true`
- `negated eq trust` => `false`
- `negated eq untrust` => `true`

This behavior is required for correctness.

## Case Sensitivity

`case_sensitive` is optional and defaults to `false`.

### `eq`

- `case_sensitive: false` => case-insensitive exact match
- `case_sensitive: true` => case-sensitive exact match

### `contains`

- `case_sensitive: false` => case-insensitive substring match
- `case_sensitive: true` => case-sensitive substring match

Boolean fields do not support `case_sensitive`; it must remain `false`.

Example:

```json
{
  "field": "from_zone",
  "op": "contains",
  "value": "Prod",
  "case_sensitive": true
}
```

## Value Validation

For these fields:

- `eq`: `value` must be a non-empty string
- `contains`: `value` must be a non-empty string

Validation rules:

- trim leading and trailing whitespace before compile
- reject empty string after trimming
- reject non-string values
- reject unknown operators
- reject non-boolean `negated`
- reject non-boolean `case_sensitive`
- reject non-boolean `include_any`

## Empty-Relation Behavior

If a rule has no related values for the selected field:

- `eq ...` => `false`
- `contains ...` => `false`
- negated variants => `true`

## Compiler Contract

Structured search should compile these fields into a predicate against
`SecurityRule`, not into Python-side filtering.

Recommended implementation shape:

1. build a field-specific related-value subquery scoped to the outer rule id
2. apply operator-specific predicate against `value`
3. wrap the result in `Exists(...)`
4. invert with `~Exists(...)` when `negated` is `true`

Conceptual pseudocode:

```python
base = SecurityRuleFromZone.objects.filter(security_rule_id=OuterRef("pk"))

if op == "eq":
    lookup = "value__exact" if case_sensitive else "value__iexact"
    match = base.filter(**{lookup: value})
elif op == "contains":
    lookup = "value__contains" if case_sensitive else "value__icontains"
    match = base.filter(**{lookup: value})
else:
    raise UnsupportedOperator(...)

predicate = Exists(match)
if negated:
    predicate = ~predicate
```

## Index Recommendation

For `SecurityRuleFromZone`, add or preserve:

- index on `security_rule`
- index on `value`
- composite index on `(value, security_rule)`

The composite index is the most important for exact-match search because the
search pattern filters on `value` and needs the related rule id efficiently.

Normal btree indexes are less useful for arbitrary substring `contains`
searches, but exact search still benefits from proper indexing and this spec
intentionally supports both exact and substring semantics.

## Future Extension Guidance

Additional repeated-value fields such as:

- `to_zone`
- `source_address_name`
- `destination_address_name`
- `application`
- `service`

should use the same clause shape and the same `EXISTS` / `NOT EXISTS` model
unless a field requires domain-specific semantics that justify deviation.
