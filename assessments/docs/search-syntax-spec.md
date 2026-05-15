# Search Syntax Spec

This document defines the canonical structured search syntax for assessment
search. It is the general syntax contract that field-specific search specs build
on top of.

This syntax is intended to support:

- backend query compilation
- UI query builders
- saved searches
- help and guidance screens
- AI translation from plain language into canonical search syntax

Field-specific semantics such as supported operators, value types, and matching
behavior belong in separate field specs. This document defines the general shape
and boolean composition rules.

## Design Goals

The canonical search syntax must be:

- explicit
- composable
- nestable
- deterministic
- durable enough to store in saved searches

The canonical syntax is the source of truth. Plain-language search should be
translated into this syntax before execution.

## Root Shape

A search document must be a root group.

The root group must include:

- `model`
- `operator`
- `clauses`

Example:

```json
{
  "model": "integrations.SecurityRule",
  "operator": "and",
  "clauses": [
    {"field": "from_zone", "op": "eq", "value": "trust"},
    {"field": "to_zone", "op": "eq", "value": "dmz"}
  ]
}
```

Rules:

- `model` is required on the root group
- `model` must be an app-qualified Django model name
- nested groups must not declare `model`
- clauses must not declare `model`

## Clause Shape

A clause is the smallest executable search unit.

Canonical clause shape:

```json
{
  "field": "from_zone",
  "op": "eq",
  "value": "trust",
  "negated": false,
  "case_sensitive": false
}
```

Clause fields:

- `field`: required string
- `op`: required string
- `value`: required, operator-specific
- `negated`: optional boolean, defaults to `false`
- `case_sensitive`: optional boolean, defaults to `false`

Notes:

- `field` selects the searchable field definition
- `op` is interpreted in the context of that field
- `value` must be validated according to the field/operator contract
- `negated` applies to the whole clause
- `case_sensitive` is optional and only meaningful for fields/operators that support it

## Group Shape

A group combines clauses and nested groups with a boolean operator.

Canonical root-group shape:

```json
{
  "model": "integrations.SecurityRule",
  "operator": "and",
  "clauses": [
    {"field": "from_zone", "op": "eq", "value": "trust"},
    {"field": "to_zone", "op": "eq", "value": "dmz"}
  ]
}
```

Group fields:

- `model`: required string on the root group only
- `operator`: required string
- `clauses`: required non-empty array

Supported group operators:

- `and`
- `or`

Each item in `clauses` may be:

- a clause
- or another group

Nested group shape:

```json
{
  "operator": "or",
  "clauses": [
    {"field": "from_zone", "op": "eq", "value": "trust"},
    {"field": "from_zone", "op": "eq", "value": "dmz"}
  ]
}
```

## Boolean Operators

### `and`

All child clauses/groups must match.

Example:

```json
{
  "model": "integrations.SecurityRule",
  "operator": "and",
  "clauses": [
    {"field": "from_zone", "op": "eq", "value": "trust"},
    {"field": "action", "op": "eq", "value": "allow"}
  ]
}
```

Meaning:

- rules must match both conditions

### `or`

At least one child clause/group must match.

Example:

```json
{
  "operator": "or",
  "clauses": [
    {"field": "from_zone", "op": "eq", "value": "trust"},
    {"field": "from_zone", "op": "eq", "value": "dmz"}
  ]
}
```

Meaning:

- rules may match either condition

## Grouping and Nesting

Groups can be nested arbitrarily.

Example:

```json
{
  "operator": "and",
  "clauses": [
    {"field": "action", "op": "eq", "value": "allow"},
    {
      "operator": "or",
      "clauses": [
        {"field": "from_zone", "op": "eq", "value": "trust"},
        {"field": "from_zone", "op": "eq", "value": "dmz"}
      ]
    }
  ]
}
```

Meaning:

- action must equal `allow`
- and at least one of the nested `from_zone` clauses must match

Nested groups are the canonical representation for parentheses-like logical
grouping.

## Negation

Negation is clause-level in the current syntax.

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

- the clause matches when the positive predicate does not match

Current rule:

- `negated` is supported on clauses
- group-level negation is not part of this spec

## Model Scope

The root `model` determines:

- which field names are valid
- which operators are valid for those fields
- which compiler backend executes the query

Example root model:

- `integrations.SecurityRule`

Nested groups and clauses inherit model scope from the root group.

If group-level negation is needed later, it should be added explicitly and
documented as a separate extension.

## Case Sensitivity

`case_sensitive` is optional and defaults to `false`.

Current rule:

- include it only when the referenced field/operator supports it
- unsupported use should be rejected during validation

This field remains part of the canonical clause shape so translators and saved
searches have a stable place for it.

## Validation Rules

General validation rules:

- a search document must be either a valid clause or a valid group
- groups must contain a non-empty `clauses` array
- groups must use a supported `operator`
- clauses must include `field`, `op`, and `value`
- `negated`, if present, must be boolean
- `case_sensitive`, if present, must be boolean
- unknown top-level keys may be rejected or ignored, but behavior should be consistent

Recommended strictness:

- reject invalid syntax rather than coercing it silently

## Execution Model

The compiler should process the syntax recursively.

Recommended model:

1. detect whether the current node is a clause or group
2. compile clauses using field-specific compilers
3. compile groups by recursively compiling children
4. combine child predicates according to `operator`

Conceptual shape:

```python
def compile_node(node):
    if is_clause(node):
        return compile_clause(node)
    if is_group(node):
        compiled = [compile_node(child) for child in node["clauses"]]
        if node["operator"] == "and":
            return combine_and(compiled)
        if node["operator"] == "or":
            return combine_or(compiled)
    raise InvalidSearchSyntax(...)
```

Field-specific compilers are responsible for:

- validating operator compatibility
- validating value shape
- applying case-sensitivity rules
- implementing negation correctly

## Saved Search Guidance

Saved searches should store the canonical structured form, not only a user-typed
string.

Recommended saved artifacts:

- display name
- canonical search syntax
- optional human-readable description

The canonical syntax is the durable executable form.

## Plain-Language Translation Guidance

Plain-language search is not executed directly.

Recommended flow:

1. plain-language input is translated into canonical syntax
2. canonical syntax is validated
3. canonical syntax is executed

This keeps execution deterministic and keeps AI output constrained to a durable
contract.

## Future Extensions

Potential future extensions may include:

- additional field-specific operators
- group-level negation
- explicit ordering syntax
- reusable named subgroups
- field aliases for help/UI convenience

Any extension should preserve backward compatibility for existing saved search
documents where practical.
