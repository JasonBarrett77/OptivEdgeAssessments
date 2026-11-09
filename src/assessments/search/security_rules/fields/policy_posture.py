"""The security-policy domain's per-rule posture fields. Stage 8 of `security-policy`.

SIXTEEN FIELDS OVER THIRTEEN STAGE 5 COLUMNS PLUS THREE COMPANIONS, and the three companions are
the half that keeps an unknown from reading as a clean rule. Registered 2026-11-01 for
PAN-POL-003, -006, -011, -012, -013, -015, -020, -022 and -024, plus the two shipped controls
whose stage 5 grading axis had no field (PAN-POL-008's threat-profile count and PAN-POL-024's
open-zone count).

WHAT IS NOT HERE, DELIBERATELY. Stage 5 marks 36 of this domain's 69 columns
`needs_compiler_field` and only 22 of them are read by a clause or a grading - the compiler's
rule in this repository is that a field earns its place by a control needing it. So
`effective_order`, `group_tag`, `schedule`, `category` and `tag` get nothing: nothing asserts on
them. `shadow_relation_computed` gets nothing either, and that one is worth a sentence: it is
the declared companion of `is_shadowed_by_earlier_rule`, and the record that would clause on it
is PAN-POL-011's SecurityRule half, which this domain does not build - the control reaches the
appliance-grained `PolicyRuleSettings` instead. A field for a clause nobody can write is a
search surface with no owner.

THREE COLUMNS WHERE NULL CARRIES ITS OWN MEANING, and each one is handled rather than hoped
about. The failure mode is specific: SQL answers a positive comparison on NULL as "no match", so
a bare threshold or a bare `eq false` passes the exact rows the control was written to catch, and
that reads from outside like a compliant estate.

  * `permitted_port_count` is `null=True` and OEI's docstring is explicit that NULL MEANS
    INDETERMINATE AND NEVER ZERO - "zero ports is the narrowest rule there is, so a rule whose
    services could not be expanded must not score as the tightest on the device". It is NULL for
    `any`, for `application-default`, for a name resolving to nothing and for a group this pass
    could not walk. A threshold therefore reaches none of those rows, which is correct, and
    `permitted_port_count_known` below is what reaches them - an INVERTED `__isnull` on the count
    itself, which is the shape `source_breadth_known` already uses on `source_num_hosts` and the
    shape OEI's own `permitted_port_count_known` property docstring prescribes: "the search layer
    filters it with an inverted `__isnull` on the column because a property cannot appear in a
    WHERE clause".
  * `permits_high_risk_application` is `null=True` where FALSE WOULD MEAN CHECKED AND CLEAN, and
    the normalizer writes NULL on every row in the estate - `/config/predefined/application` is a
    read no collector issues. `eq true` therefore matches nothing today, which is honest and is
    PAN-POL-006's whole condition; `eq false` would ALSO match nothing, and a reader who expects
    it to mean "checked and found clean" would be reading a column that has never been checked.
  * `is_shadowed_by_earlier_rule` is `null=True` where "NULL IS NOT `NOT SHADOWED`: a false here
    is a claim that the whole rulebase was compared". `eq true` reaches only rows the shadow pass
    has answered for.
  * `busy_rule_placed_late` and `schedule_window_expired` are `null=True` for the same reason -
    "NOT ESTABLISHED" rather than a verdict - and both take the plain boolean form, so a NULL row
    matches neither `eq true` nor `eq false`. A NEGATED `eq` reaches them, because negation here
    is the complement of a `pk__in` subquery and a row absent from the subquery is in the
    complement whether its column is NULL or False. That is how PAN-POL-011's and PAN-POL-013's
    `is not` clauses reach a NULL on the appliance model, and it is worth knowing that the same
    mechanism is available on these.

THE THREE TEXT COLUMNS TAKE THE TEXT COMPILER and not a closed-choice form, for the reason the
NTP and DNS compilers record: the closed form accepts none of the shared probe values, so it
would put this domain's vocabulary into a shared test of every other model. All three are
non-nullable `CharField`s with a `""` default, so the `is_empty` the text set now carries reaches
their absent value with the bare `filter(field="")` and needs no `__isnull` branch.
"""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.security_rules.fields.scalar_boolean import (
    SUPPORTED_OPERATORS as BOOLEAN_OPERATORS,
)
from assessments.search.security_rules.fields.scalar_boolean import (
    compile_scalar_boolean_clause,
    parse_boolean_value,
)
from assessments.search.security_rules.fields.scalar_text import (
    compile_scalar_text_clause,
)
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import SecurityRule

NUMBER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def _build_number_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in NUMBER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return SecurityRule.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = NUMBER_OPERATORS
    return compiler


def _build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        return compile_scalar_boolean_clause(
            clause, field_name=field_name, lookup_field=lookup_field)
    compiler.SUPPORTED_OPERATORS = BOOLEAN_OPERATORS
    return compiler


def _build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        return compile_scalar_text_clause(
            clause, field_name=field_name, lookup_field=lookup_field)
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def _build_established_compiler(field_name, lookup_field):
    """A `_known` flag over a NULLABLE column, as an INVERTED `__isnull` on the column itself.

    The column's NULL *is* this flag's false, and a second stored copy could disagree with it -
    which is the argument `permitted_port_count_known`'s own property docstring in OEI makes. The
    shipped `source_breadth_known` on `source_num_hosts` is the precedent and this is the same
    three lines.
    """
    def compiler(clause):
        op = clause["op"]
        if op not in BOOLEAN_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        known = parse_boolean_value(clause["value"], field_name=field_name)
        return SecurityRule.objects.filter(
            **{f"{lookup_field}__isnull": not known}).values("pk")
    compiler.SUPPORTED_OPERATORS = BOOLEAN_OPERATORS
    return compiler


#: PAN-POL-003's assertion and grading axis. NULL IS INDETERMINATE - see the module docstring.
compile_permitted_port_count_clause = _build_number_compiler(
    "permitted_port_count", "permitted_port_count")
#: PAN-POL-003's companion, and the only thing that reports a service list nobody could expand.
compile_permitted_port_count_known_clause = _build_established_compiler(
    "permitted_port_count_known", "permitted_port_count")
#: PAN-POL-024's assertion and grading axis. A COUNT of open zone sides, 0 to 2, non-null with a
#: default of 2 - the worst band on an unrecomputed row, which fires rather than passing.
compile_open_zone_side_count_clause = _build_number_compiler(
    "open_zone_side_count", "open_zone_side_count")
#: PAN-POL-008's grading axis, and the column that supersedes the three `has_*_profile` booleans
#: the shipped baseline ORs. A COUNT and not a set, despite the plural name:
#: `PositiveSmallIntegerField(default=0)` holding 0 to 3.
compile_threat_profile_kinds_in_force_clause = _build_number_compiler(
    "threat_profile_kinds_in_force", "threat_profile_kinds_in_force")
#: PAN-POL-013's assertion and grading axis. NULL IS `NOT ESTABLISHED` AND NEVER ZERO: the read
#: answers `last-hit-timestamp: 0` for a rule that has never matched, which is parsed as NULL
#: rather than as 1970.
compile_days_since_last_hit_clause = _build_number_compiler(
    "days_since_last_hit", "days_since_last_hit")
#: PAN-POL-013's and PAN-POL-015's companion. A STORED boolean here and not an inverted isnull -
#: it is false wherever the appliance's hit-count switch is not TRUE, wherever no reading was
#: taken and wherever the counter was reset inside the window, and only the second of those three
#: shows up as a NULL age.
compile_hit_count_reading_known_clause = _build_boolean_compiler(
    "hit_count_reading_known", "hit_count_reading_known")
#: PAN-POL-015's assertion. NULL IS `NOT ESTABLISHED`: false would claim the ranking ran over the
#: whole rulebase and found nothing out of place.
compile_busy_rule_placed_late_clause = _build_boolean_compiler(
    "busy_rule_placed_late", "busy_rule_placed_late")
#: PAN-POL-020's assertion.
compile_has_url_filtering_profile_clause = _build_boolean_compiler(
    "has_url_filtering_profile", "has_url_filtering_profile")
#: PAN-POL-020's grading axis.
compile_url_inspection_posture_clause = _build_text_compiler(
    "url_inspection_posture", "url_inspection_posture")
#: PAN-POL-006's assertion. NULL ON EVERY ROW IN THE ESTATE - see the module docstring.
compile_permits_high_risk_application_clause = _build_boolean_compiler(
    "permits_high_risk_application", "permits_high_risk_application")
#: PAN-POL-006's grading axis. One characteristic, the vendor's own leaf name, not a joined set -
#: so its twelve placements are mutually exclusive equalities and no two can match one row.
compile_high_risk_application_characteristic_clause = _build_text_compiler(
    "high_risk_application_characteristic", "high_risk_application_characteristic")
#: PAN-POL-011's SecurityRule half, which this domain does not build - registered because stage 5
#: names the column in an `expression` record and the owed-field check is computed over those.
compile_is_shadowed_by_earlier_rule_clause = _build_boolean_compiler(
    "is_shadowed_by_earlier_rule", "is_shadowed_by_earlier_rule")
#: PAN-POL-012's assertion.
compile_has_exact_duplicate_clause = _build_boolean_compiler(
    "has_exact_duplicate", "has_exact_duplicate")
#: PAN-POL-012's companion, and it is the WHOLE mechanism rather than a nicety: the column above
#: is a non-nullable boolean whose false means both "compared and no duplicate" and "never
#: compared", and a boolean cannot hold a third state.
compile_duplicate_comparison_computed_clause = _build_boolean_compiler(
    "duplicate_comparison_computed", "duplicate_comparison_computed")
#: PAN-POL-022's applicability, and the declared companion of the assertion beside it.
compile_schedule_kind_clause = _build_text_compiler("schedule_kind", "schedule_kind")
#: PAN-POL-022's assertion. NULL IS `NO WINDOW, OR NOT COMPARED`, and a RECURRING schedule is
#: null here on purpose - which is the false pass to watch for.
compile_schedule_window_expired_clause = _build_boolean_compiler(
    "schedule_window_expired", "schedule_window_expired")


POLICY_POSTURE_COMPILERS = {
    "permitted_port_count": compile_permitted_port_count_clause,
    "permitted_port_count_known": compile_permitted_port_count_known_clause,
    "open_zone_side_count": compile_open_zone_side_count_clause,
    "threat_profile_kinds_in_force": compile_threat_profile_kinds_in_force_clause,
    "days_since_last_hit": compile_days_since_last_hit_clause,
    "hit_count_reading_known": compile_hit_count_reading_known_clause,
    "busy_rule_placed_late": compile_busy_rule_placed_late_clause,
    "has_url_filtering_profile": compile_has_url_filtering_profile_clause,
    "url_inspection_posture": compile_url_inspection_posture_clause,
    "permits_high_risk_application": compile_permits_high_risk_application_clause,
    "high_risk_application_characteristic": compile_high_risk_application_characteristic_clause,
    "is_shadowed_by_earlier_rule": compile_is_shadowed_by_earlier_rule_clause,
    "has_exact_duplicate": compile_has_exact_duplicate_clause,
    "duplicate_comparison_computed": compile_duplicate_comparison_computed_clause,
    "schedule_kind": compile_schedule_kind_clause,
    "schedule_window_expired": compile_schedule_window_expired_clause,
}
