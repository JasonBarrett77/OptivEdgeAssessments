# Plain Language Security Rule Query

This feature provides a separate plain-language entry point for the existing
security-rule query builder.

Workflow:

- user submits a plain-language request
- OpenAI Responses translates it into canonical security-rule query JSON
- the canonical query is validated locally against the existing search syntax
- the app stores the query in `SecurityRuleSearchState`
- the user is redirected to:
  - `/assessments/security-rules/?edit_search=1&search_state=<token>`

Implementation notes:

- the OpenAI call uses the Responses API
- `model = gpt-5.5`
- `service_tier = flex`
- structured outputs are enforced with a JSON schema derived from the live
  security-rule field/operator registry
- translation retries up to three times when the model returns schema-valid but
  locally invalid canonical search JSON

Important semantics:

- object/group name lookups should target:
  - `source_address_name`
  - `destination_address_name`
- IPv4 traffic-meaning queries should target:
  - `source_address`
  - `destination_address`
- `include_any` stays false by default and should only be enabled when the user
  explicitly wants `any`-valued source/destination members to count
