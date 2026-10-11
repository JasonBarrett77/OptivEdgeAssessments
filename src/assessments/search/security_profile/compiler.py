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
from optivedge_integrations.integrations.models import (
    SecurityProfile,
    SecurityProfileApplicationOverride,
    SecurityProfileDecoder,
    SecurityProfileInlineDetector,
)

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


def build_non_blocking_decoder_compiler(field_name, column="blocks", nullable=False):
    """Does this antivirus profile leave any protocol decoder not blocking malware?

    Answered from the decoder rows, where `default` has already been resolved to what it means
    on each protocol - reset-both on http/http2/ftp/smb, alert on smtp/imap/pop3. The
    configuration says `default` on every decoder of every unedited profile, including the
    shipped one, so a compiler reading the configured literal would find nothing wrong with any
    of them.

    `false` requires at least one decoder row. A profile with none is not an antivirus profile
    that blocks everywhere; it is a kind that has no decoders, and it must not read as passing.

    THREE COLUMNS, ONE COMPILER. A decoder carries SIGNATURE ACTION, WILDFIRE SIGNATURE ACTION
    and WILDFIRE INLINE ML ACTION, and they are independent verdict sources - a profile can be
    hard on one and open on another. Each gets its own field so an assessor can ask about them
    separately, and PAN-AVW-001 ORs all three.

    `nullable` is for `mlav_blocks`, where a null means NOT COMPUTED - a decoder row written
    before the column existed. Those must report, not pass, so the filter asks for
    `!= True` rather than `== False`.
    """
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        # Row-level on the DECODER, for the same reason the override compiler is: a spanning
        # `exclude(decoders__blocks=False)` on the profile asks "has no open decoder", which is
        # the right question only for the `false` branch.
        open_decoders = Q(**{f"{column}": False})
        if nullable:
            open_decoders |= Q(**{f"{column}__isnull": True})
        permissive = (SecurityProfileDecoder.objects.filter(open_decoders)
                      .values("security_profile"))
        if value:
            return SecurityProfile.objects.filter(pk__in=permissive).values("pk")
        return (SecurityProfile.objects.filter(decoders__isnull=False)
                .exclude(pk__in=permissive).distinct().values("pk"))
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_non_blocking_application_override_compiler(field_name):
    """Does this antivirus profile override a decoder's action for a named application?

    A per-application override defeats the decoder action - a profile can read `reset-both` on
    all seven decoders and still allow malware over a named application. Found 2026-10-08 by
    enumerating the profile's key set rather than reading a sample.

    `blocks=True` is the only passing state, so the filter is `blocks != True` and NOT
    `blocks=False`: a null means the literal `default`, whose resolution is not established for
    an override, and a null excluded from the filter would pass silently. The control fails
    toward firing there.

    UNLIKE the decoder compiler, `false` does NOT require a row. No override rows is the normal
    and correct state - an override is an operator-added exception, and almost every profile
    has none - so requiring one would make every ordinary profile match neither value. The
    cost is that a profile row written before the override model existed also reads as clean;
    the control's record names the re-normalize that fixes that.
    """
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        # ROW-LEVEL on the override model, NOT `exclude(application_overrides__blocks=True)`
        # on the profile. That spanning exclude asks "has no blocking override" and so drops a
        # profile for HAVING one - a profile with gmail-base=allow beside
        # dropbox-base=reset-both would not be reported, which is the common real shape: an
        # exception list holds several entries and only some of them are permissive.
        #
        # `Q(blocks=False) | Q(blocks__isnull=True)` rather than `exclude(blocks=True)`,
        # because SQL's `NOT (blocks = TRUE)` is NULL for a NULL and the row would be dropped -
        # and NULL is the unresolved `default`, which must be reported.
        permissive = (SecurityProfileApplicationOverride.objects
                      .filter(Q(blocks=False) | Q(blocks__isnull=True))
                      .values("security_profile"))
        if value:
            return SecurityProfile.objects.filter(pk__in=permissive).values("pk")
        return SecurityProfile.objects.exclude(pk__in=permissive).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_inline_detector_compiler(field_name):
    """Does this profile leave an inline cloud-analysis detector not blocking?

    PAN-SPY-004 and PAN-VLN-003. Covers both ways of not blocking - a detector the profile
    never mentions, which does not run, and one set to `alert`, which runs and lets the
    traffic through. The second is `enable(alert-only)` from PAN-AVW-002 under another name,
    and reading it as "enabled" would pass a profile that only watches.

    `false` requires at least one detector row. A profile with none is not a profile whose
    inline analysis blocks everything; it is a kind that has no such engine - antivirus and
    wildfire-analysis - and it must not read as passing.
    """
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        # Row-level, for the reason the override compiler is: a spanning exclude on the
        # PROFILE would drop a profile for HAVING one blocking detector.
        permissive = (SecurityProfileInlineDetector.objects.filter(blocks=False)
                      .values("security_profile"))
        if value:
            return SecurityProfile.objects.filter(pk__in=permissive).values("pk")
        return (SecurityProfile.objects.filter(inline_detectors__isnull=False)
                .exclude(pk__in=permissive).distinct().values("pk"))
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


def build_category_verdict_compiler(field_name, category):
    """`brute_force_blocked_by_source = true/false`, from the category-verdict rows.

    The same no-row-no-claim rule as the severity verdict, and it matters MORE here: only
    vulnerability profiles get a row, so an antivirus or anti-spyware profile matches neither
    value rather than reading as a profile that fails to block brute force.

    This is a different question from `critical_blocked`, not a stricter version of it. A rule
    with `reset-both` satisfies that one and fails this one, because resetting a connection
    stops the attempt and leaves the source free to make the next.
    """
    def compiler(clause):
        op = clause["op"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        value = clause["value"]
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return SecurityProfile.objects.filter(
            category_verdicts__category=category,
            category_verdicts__blocks_source=value).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_category_verdict_detail_compiler(field_name, category):
    """The reason beside a category verdict - what has to change."""
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, str):
            raise SearchSyntaxError(f"{field_name} search value must be a string.")
        lookup = "iexact" if op == "eq" else "icontains"
        return SecurityProfile.objects.filter(**{
            "category_verdicts__category": category,
            f"category_verdicts__detail__{lookup}": value}).values("pk")
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
    "has_non_blocking_wildfire_decoder": build_non_blocking_decoder_compiler(
        "has_non_blocking_wildfire_decoder", "wildfire_blocks"),
    "has_non_blocking_mlav_decoder": build_non_blocking_decoder_compiler(
        "has_non_blocking_mlav_decoder", "mlav_blocks", nullable=True),
    "has_non_blocking_application_override": build_non_blocking_application_override_compiler(
        "has_non_blocking_application_override"),
    "has_inline_detector_not_blocking": build_inline_detector_compiler(
        "has_inline_detector_not_blocking"),
    "has_disabled_ml_model": build_ml_model_compiler("has_disabled_ml_model", "enabled"),
    "has_non_blocking_ml_model": build_ml_model_compiler(
        "has_non_blocking_ml_model", "blocks"),
    "brute_force_blocked_by_source": build_category_verdict_compiler(
        "brute_force_blocked_by_source", "brute-force"),
    "brute_force_detail": build_category_verdict_detail_compiler(
        "brute_force_detail", "brute-force"),
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
