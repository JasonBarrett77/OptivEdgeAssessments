"""Canonical search compiler for anti-spyware and vulnerability profiles.

The verdict fields - `critical_blocked`, `high_blocked`, `medium_blocked` - are stored
CONCLUSIONS, computed in normalization from the profile's whole rule list, because the question
"is every critical threat blocked" spans rules and the search layer compares one field to a
literal. The reason sits beside each verdict (`critical_detail`) so a row can be checked rather
than taken.

THEY LIVE ON A SATELLITE TABLE, one row per severity the profile answers for, and these
compilers reach into it. The field NAMES are unchanged because they are the control contract -
PAN-SPY-001 and PAN-VLN-001 name them in their queries - while where the value is stored is not.

A profile with no row for a severity MAKES NO CLAIM about it, and matches neither
`critical_blocked = true` nor `critical_blocked = false`. That is the point of the split: an
antivirus profile has no severity rules, and a column that could only say yes or no had to say
"critical is not blocked" about a profile that does not answer the question.

A profile belongs to an enforcement point (vsys and predefined scope) or to an appliance group
(shared scope), so `appliance_group` matches either path.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import SecurityProfile

SECURITY_PROFILE_MODEL = "integrations.SecurityProfile"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        # EVERY path empty or missing. A profile has one owner, so the other owner's path is
        # always NULL - OR-ing the null branches would call every row empty.
        q = Q()
        for lookup in lookups:
            q &= Q(**{lookup: ""}) | Q(**{f"{lookup}__isnull": True})
        return q
    if not isinstance(value, str) or not value.strip():
        raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
    suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
    q = Q()
    for lookup in lookups:
        q |= Q(**{f"{lookup}__{suffix}": value.strip()})
    return q


def build_text_compiler(field_name, *lookups):
    """One field over one or more lookup paths - several when the owner can be either model."""
    def compiler(clause):
        return SecurityProfile.objects.filter(_text_filter(field_name, lookups, clause)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return SecurityProfile.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in INTEGER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return SecurityProfile.objects.filter(**{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


def build_ml_model_compiler(field_name, column):
    """Does this antivirus profile leave any WildFire Inline ML model off, or alert-only?

    `mlav-policy-action` has THREE values, enumerated from the device with action=complete:
    `enable`, `enable(alert-only)` and `disable`. A model on alert-only RUNS and does not STOP
    the file, so `enabled` and `blocks` are different questions and the control asks the
    second - which is the literal the corpus names for its minimum and its preferred alike.

    Answered from the model rows, which carry one entry per model the CONTENT release knows
    about - catalogued from the predefined profile rather than from a hardcoded list, because
    controls.json says those names come from content and must be enumerated per version.

    A model the profile's config never mentions is DISABLED, and has a row saying so. Without
    that, a profile with no ML node at all would have no rows and would read as having nothing
    switched off, when in fact it runs no inline ML whatever.
    """
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        if value:
            return SecurityProfile.objects.filter(**{
                f"ml_models__{column}": False}).distinct().values("pk")
        return (SecurityProfile.objects.filter(ml_models__isnull=False)
                .exclude(**{f"ml_models__{column}": False}).distinct().values("pk"))
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_non_blocking_decoder_compiler(field_name):
    """Does this antivirus profile leave any protocol decoder not blocking malware?

    Answered from the decoder rows, where `default` has already been resolved to what it means
    on each protocol - reset-both on http/http2/ftp/smb, alert on smtp/imap/pop3. The
    configuration says `default` on every decoder of every unedited profile, including the
    shipped one, so a compiler reading the configured literal would find nothing wrong with any
    of them.

    `false` requires at least one decoder row. A profile with none is not an antivirus profile
    that blocks everywhere; it is a kind that has no decoders, and it must not read as passing.
    """
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        if value:
            return SecurityProfile.objects.filter(
                decoders__blocks=False).distinct().values("pk")
        return (SecurityProfile.objects.filter(decoders__isnull=False)
                .exclude(decoders__blocks=False).distinct().values("pk"))
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_verdict_compiler(field_name, severity):
    """`critical_blocked = true/false`, answered from the severity-verdict rows.

    A profile with no row for this severity matches NEITHER value. It is not a profile that
    fails to block the severity; it is a profile that does not answer the question.
    """
    def compiler(clause):
        op = clause["op"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        value = clause["value"]
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return SecurityProfile.objects.filter(
            severity_verdicts__severity=severity,
            severity_verdicts__blocked=value).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_verdict_detail_compiler(field_name, severity):
    """The reason beside a verdict - why a severity is not blocked."""
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, str):
            raise SearchSyntaxError(f"{field_name} search value must be a string.")
        lookup = "iexact" if op == "eq" else "icontains"
        return SecurityProfile.objects.filter(**{
            "severity_verdicts__severity": severity,
            f"severity_verdicts__detail__{lookup}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "name": build_text_compiler("name", "name"),
    "kind": build_text_compiler("kind", "kind"),
    "namespace_type": build_text_compiler("namespace_type", "namespace_type"),
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    "appliance_group": build_text_compiler(
        "appliance_group", "appliance_group__name", "enforcement_point__appliance_group__name"),
    # The firewalls holding the definition: every appliance of the owning group, or the vsys's.
    "hostname": build_text_compiler(
        "hostname", "appliance_group__appliances__hostname",
        "enforcement_point__appliance_group__appliances__hostname", "enforcement_point__appliance__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "appliance_group__appliances__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number",
        "enforcement_point__appliance__serial_number"),
    "description": build_text_compiler("description", "description"),
    "is_predefined": build_boolean_compiler("is_predefined", "is_predefined"),
    "is_used": build_boolean_compiler("is_used", "is_used"),
    "critical_blocked": build_verdict_compiler("critical_blocked", "critical"),
    "critical_detail": build_verdict_detail_compiler("critical_detail", "critical"),
    "high_blocked": build_verdict_compiler("high_blocked", "high"),
    "high_detail": build_verdict_detail_compiler("high_detail", "high"),
    "medium_blocked": build_verdict_compiler("medium_blocked", "medium"),
    "medium_detail": build_verdict_detail_compiler("medium_detail", "medium"),
    "has_non_blocking_decoder": build_non_blocking_decoder_compiler("has_non_blocking_decoder"),
    "has_disabled_ml_model": build_ml_model_compiler("has_disabled_ml_model", "enabled"),
    "has_non_blocking_ml_model": build_ml_model_compiler(
        "has_non_blocking_ml_model", "blocks"),
    "rule_count": build_integer_compiler("rule_count", "rule_count"),
    "referrer_count": build_integer_compiler("referrer_count", "referrer_count"),
    "threat_exception_count": build_integer_compiler("threat_exception_count", "threat_exception_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_security_profile_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_security_profile_search_node(c) for c in group["clauses"]]
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
