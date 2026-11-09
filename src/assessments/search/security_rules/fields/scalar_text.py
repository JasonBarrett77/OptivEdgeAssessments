"""Shared compiler helpers for scalar text security-rule fields.

`is_empty` WAS MISSING FROM THIS SET AND TWO SHIPPING CONTROLS ASK FOR IT. Added by stage 8 of
`security-policy`, 2026-11-01. Before this the set was `{"eq", "contains"}`, and a clause written
as an `eq` against `""` raised `SearchSyntaxError` from the guard below - which
`control_queries.evaluate_queryset_control_queries` CATCHES and counts as a SKIPPED query. So a
control asserting "this text leaf is empty" did not fail loudly; it vanished, and the control
reported nothing while reading as shipped.

WHAT ASKED FOR IT, measured against `pipeline/artifacts/stage5-security-policy.json`:

  * PAN-POL-021's baseline is `description is empty` - a rule carrying no documentation.
  * PAN-POL-009's second record's baseline is `log_setting is empty` - a rule naming no
    log-forwarding profile. Stage 5's own note on that record says "`log_setting` is searchable
    today with `is_empty`, so this restatement needs nothing built", and that was WRONG: the
    operator did not exist on this model at all.
  * Nine controls of that domain name `action is empty` in their records' `undetermined` prose
    as the companion that stops a rule whose action could not be read from leaving the candidate
    set in silence. Stage 5 says there too that "`action` is searchable with `is_empty`
    already". Also wrong, and the same cause.

THE BARE `filter(field="")` SHAPE IS RIGHT HERE AND IT IS NOT RIGHT EVERYWHERE. The operator
widens SEVEN fields at once, because seven of this package's field modules share this helper -
`action`, `description`, `log_setting`, `name`, `rule_type`, `vsys_name` and
`vsys_display_name` - and EVERY ONE of those columns is NON-NULLABLE (`CharField`/`TextField`
with no `null=True`; `vsys_name` and `vsys_display_name` reach `EnforcementPoint`'s own
non-nullable columns). So `""` is the only absent value any of them can hold and an `__isnull`
branch beside it would match nothing extra. Where a column is `null=True` and the
normalizer writes NULL for the absent case, this shape compiles, passes every gate and matches
nothing on the exact population it was written for - so a nullable column needs the
`__isnull`-OR form instead. The operator set is imported from `device_configuration` rather than
restated so that the query builder offers the same three everywhere.
"""

from __future__ import annotations

from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS,
)
from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import SecurityRule


def compile_scalar_text_clause(clause, *, field_name, lookup_field):
    op = clause["op"]
    value = clause["value"]
    case_sensitive = clause["case_sensitive"]

    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")

    base_query = SecurityRule.objects.all()
    if op == "is_empty":
        # The value is carried for shape only. A non-empty one is a clause whose author meant
        # `eq`, and accepting it silently would answer a different question.
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        return base_query.filter(**{lookup_field: ""}).values("pk")

    if not isinstance(value, str):
        raise SearchSyntaxError(f"{field_name} search value must be a string.")

    trimmed_value = value.strip()
    if not trimmed_value:
        raise SearchSyntaxError(f"{field_name} search value must not be empty.")

    if op == "eq":
        lookup = f"{lookup_field}__exact" if case_sensitive else f"{lookup_field}__iexact"
        return base_query.filter(**{lookup: trimmed_value}).values("pk")

    lookup = f"{lookup_field}__contains" if case_sensitive else f"{lookup_field}__icontains"
    return base_query.filter(**{lookup: trimmed_value}).values("pk")
