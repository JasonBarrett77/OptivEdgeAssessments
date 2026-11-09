"""Canonical search compiler for one appliance's device-wide policy-rule switches.

PAN-POL-011. Minted by stage 8 of `security-policy`, 2026-11-01.

ONE ROW PER APPLIANCE, read from `deviceconfig/setting/management`, which on an HA pair is TWO
ROWS FOR ONE REAL CONFIGURATION with nothing downstream deduplicating them. The two peers'
management containers have been measured differing while config sync reported synchronized, so a
difference between peers is DATA and not a normalization fault.

BOTH ASSESSED COLUMNS ARE `BooleanField(null=True)` AND NULL IS THE FIRING SIDE, which is the
whole reason both controls that rest on them are written as NEGATED equalities rather than
positive ones:

  * PAN-POL-011 asks `disable_shadow_rule_check is not false`. The leaf is a NEGATIVE whose being
    set SUPPRESSES the evidence the control's other half rests on, and stage 4 left its implicit
    UNMEASURED - so NULL means nobody has established what an absent key does, and NULL must
    report rather than pass. Inferring `no` from the key's name would hand the reassuring answer
    to a control whose whole evidence the key suppresses.
  * PAN-POL-013's first record asks `rule_hit_count_enabled is not true`. That implicit HAS since
    been measured - an absent key asserts counting is ON, read off the Policy Rule Hit Count
    checkbox on two appliances in opposite key states - so the normalizer now stores TRUE for an
    absent key and the clause passes it correctly. That record is not built as a control by this
    domain: PAN-POL-013 reaches the per-rule age instead, and this column is registered because
    stage 5 names it in an `expression` record and the owed-field check is computed over those.

HOW A NEGATED CLAUSE REACHES A NULL, because it is not obvious and it is the only reason either
control works. `compile_search_clause` wraps every field's queryset as `Q(pk__in=Subquery(...))`
and applies `~` to the WHOLE predicate. So `is not false` compiles to the COMPLEMENT of the set
of rows whose column is False - and a row whose column is NULL is absent from that set, so it is
in the complement. The negation is set-complement over primary keys rather than a SQL `!=`, which
is what makes it NULL-safe; a bare `eq false` with no negation would miss every NULL, and that is
the shape to avoid here.

FOUR FIELDS. `rule_hit_count_enabled` and `disable_shadow_rule_check` are the two assessed
columns; `hostname` and `serial_number` serve stage 5's `management_station` and `appliance`
identity columns, which stage 5 marks `needs_compiler_field` and which nothing clauses on - a
reader of an appliance-grained finding has nothing else to name the appliance by, and this is
what most shipped compilers do for that column.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import PolicyRuleSettings

POLICY_RULE_SETTINGS_MODEL = "integrations.PolicyRuleSettings"
BOOLEAN_OPERATORS = {"eq"}
TRUE_VALUES = {"true", "yes", "on", "1"}
FALSE_VALUES = {"false", "no", "off", "0"}


def _parse_boolean(value, *, field_name):
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        raise SearchSyntaxError(
            f"{field_name} search value must be a boolean or boolean-like string.")
    normalized = value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise SearchSyntaxError(
        f"{field_name} search value must be true/false, yes/no, on/off, or 1/0.")


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            # Both lookups are non-nullable CharFields on `Appliance`.
            return PolicyRuleSettings.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return PolicyRuleSettings.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    """A NULLABLE boolean, filtered positively. See the module docstring on negation."""
    def compiler(clause):
        op = clause["op"]
        if op not in BOOLEAN_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        parsed = _parse_boolean(clause["value"], field_name=field_name)
        return PolicyRuleSettings.objects.filter(**{lookup_field: parsed}).values("pk")
    compiler.SUPPORTED_OPERATORS = BOOLEAN_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    #: PAN-POL-011's assertion. The device's own key, WITH THE DEVICE'S OWN POLARITY KEPT: TRUE
    #: means the check has been SUPPRESSED, and a device with it set reports zero shadow warnings
    #: for exactly the same reason a clean device does.
    "disable_shadow_rule_check": build_boolean_compiler(
        "disable_shadow_rule_check", "disable_shadow_rule_check"),
    #: PAN-POL-013's first record - not built as a control by this domain. See the docstring.
    "rule_hit_count_enabled": build_boolean_compiler(
        "rule_hit_count_enabled", "rule_hit_count_enabled"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_policy_rule_settings_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_policy_rule_settings_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def compile_search_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause["negated"] else predicate
