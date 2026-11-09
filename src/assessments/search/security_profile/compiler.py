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
    SecurityProfileDnsSignatureSource,
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
    about - catalogd from the predefined profile rather than from a hardcoded list, because
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


def build_dns_sinkhole_compiler(field_name):
    """`dns_sinkholes_malicious_queries = true/false`, from the Palo Alto Networks Content row.

    PAN-SPY-002. SCOPED TO THAT ONE SOURCE: `is_paloalto_content` filters out External Dynamic
    Lists, because Help p.284 makes an EDL with an allow or alert action the documented way to
    express a DNS exception, and reporting one would call a deliberate allow-list a failure.
    DNS Security categories are a different node, a different action enum and PAN-SPY-003.

    Every anti-spyware profile has such a row - synthesized when the config is silent - so this
    does not silently skip a profile that never configured DNS. Every OTHER kind has no row and
    matches neither value, the same no-claim rule as the verdict fields.
    """
    def compiler(clause):
        op = clause["op"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        value = clause["value"]
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return SecurityProfile.objects.filter(
            dns_signature_sources__is_paloalto_content=True,
            dns_signature_sources__sinkholes=value).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_dns_implicit_compiler(field_name):
    """`dns_sinkhole_action_is_implicit = true/false` - is the verdict resting on the Help?

    Not asserted by any control. It exists so the undecided case can be LISTED: the implicit
    action is documented (p.284, twice) and not measured, and if that measurement comes out the
    other way this field is how the affected profiles are found without a schema change.
    """
    def compiler(clause):
        op = clause["op"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        value = clause["value"]
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return SecurityProfile.objects.filter(
            dns_signature_sources__is_paloalto_content=True,
            dns_signature_sources__action_is_implicit=value).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_dns_category_compiler(field_name):
    """`dns_security_categories_enforced = true/false`, over the asserted malicious categories.

    PAN-SPY-003. `false` means AT LEAST ONE of the asserted categories does not block or
    sinkhole; `true` means every one of them does. Those are not each other's complement over
    rows - a profile has three rows and they can disagree - so `true` is expressed as "has a
    row and has no failing row" rather than as a plain match.

    THE ASSERTED SET IS THREE of ten: C2, malware and phishing. controls.json leaves
    newly-registered, parked and DGA to "risk tolerance", two of the categories it names do
    not exist on this content release, and sinkholing `pan-dns-sec-benign` would be a defect
    rather than a finding. The set lives on the model beside its measurement date.

    `block` PASSES here and reports under PAN-SPY-002, because the two corpus entries differ:
    this one says "must sinkhole/block", that one asks for sinkhole alone.
    """
    def compiler(clause):
        op = clause["op"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        value = clause["value"]
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        source = SecurityProfileDnsSignatureSource
        failing = Q(
            dns_signature_sources__source_type=source.TYPE_DNS_SECURITY,
            dns_signature_sources__name__in=source.ASSERTED_MALICIOUS_CATEGORIES,
            dns_signature_sources__enforces=False)
        if not value:
            return SecurityProfile.objects.filter(failing).values("pk")
        # Has the rows at all, and none of them failing. A profile with no rows makes no
        # claim and must match neither value.
        return SecurityProfile.objects.filter(
            dns_signature_sources__source_type=source.TYPE_DNS_SECURITY,
            dns_signature_sources__name__in=source.ASSERTED_MALICIOUS_CATEGORIES,
        ).exclude(failing).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
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
    "dns_sinkholes_malicious_queries": build_dns_sinkhole_compiler(
        "dns_sinkholes_malicious_queries"),
    "dns_sinkhole_action_is_implicit": build_dns_implicit_compiler(
        "dns_sinkhole_action_is_implicit"),
    "dns_security_categories_enforced": build_dns_category_compiler(
        "dns_security_categories_enforced"),
    "dns_sinkhole_ipv4": build_text_compiler("dns_sinkhole_ipv4", "dns_sinkhole_ipv4"),
    "rule_count": build_integer_compiler("rule_count", "rule_count"),
    "referrer_count": build_integer_compiler("referrer_count", "referrer_count"),
    "threat_exception_count": build_integer_compiler("threat_exception_count", "threat_exception_count"),
    # ---------------------------------------------------------------- `file-data-filtering`
    # PAN-FIL-001, -002 and -004, over the `file-blocking` and `data-filtering` kinds of this
    # model. Every one of these columns is stored as a CONCLUSION over the profile's rule list,
    # for the reason the module docstring gives about the severity verdicts: the questions span
    # rules and a predicate compares one field to one literal.
    #
    # THE SPELLINGS BEHIND THEM ARE CASE-SENSITIVE AND MEASURED, which is why no clause here
    # names a file type. Stage 4 wrote the lower-case `pe` and the device REFUSED it -
    # "file-type 'pe' is not an allowed keyword", code=12 - while `PE` committed; the same for
    # `multi-level-encoding` against `Multi-Level-Encoding`. A query comparing against the
    # lower-case member sits in no stored row anywhere and would report a finding on the one
    # profile in the estate that actually blocks the type. The member set also MOVES between
    # content releases - 242 members on 11.2.5 against 225 on 11.1.13-h3 - so the floor is a
    # named set resolved at normalization, not a list in a query.
    "stops_floor_file_types": build_boolean_compiler(
        "stops_floor_file_types", "stops_floor_file_types"),
    "stops_nested_encoding": build_boolean_compiler(
        "stops_nested_encoding", "stops_nested_encoding"),
    "expresses_unopenable_file_decision": build_boolean_compiler(
        "expresses_unopenable_file_decision", "expresses_unopenable_file_decision"),
    "confirm_rule_beyond_web_browsing": build_boolean_compiler(
        "confirm_rule_beyond_web_browsing", "confirm_rule_beyond_web_browsing"),
    "every_rule_carries_both_counts": build_boolean_compiler(
        "every_rule_carries_both_counts", "every_rule_carries_both_counts"),
    # The two graded columns. TEXT AND NOT A CHOICE COMPILER, deliberately: each stores the
    # WEAKEST action in force on its file types across the profile's rules, over the three
    # measured values (block, continue, alert) - and an EMPTY STRING for the fourth case, which
    # is not a value of the field at all. An action key ABSENT from a committed rule is legal,
    # measured on `oep-fdf6-07`, and must NOT be scored as the schema default `alert`: that
    # would report a rule taking an unknown action as one known to deliver the file and log it.
    # The baseline reports the empty case through the verdict boolean beside it, and `is_empty`
    # reaches it here for a reader who wants the row.
    "floor_file_type_action": build_text_compiler(
        "floor_file_type_action", "floor_file_type_action"),
    "nested_encoding_action": build_text_compiler(
        "nested_encoding_action", "nested_encoding_action"),
    # THE TWO-HOP REFERENCE WALK, and the pair exists because a boolean cannot hold the fourth
    # value. The shipped `is_used` and `referrer_count` above are ONE hop and are measured wrong
    # in this lab in BOTH directions: all eight standing file-blocking profiles on pan-fw-201 are
    # named by a profile group and not one of those groups is named by any rule, so a one-hop
    # predicate passes five profiles nothing enforces - while a rules-only audit calls a
    # group-mediated profile unused, because a rule's profile setting is a CHOICE NODE,
    # `group` XOR `profiles`, never both.
    #
    # `reference_reach` IS NON-NULLABLE AND DEFAULTS TO `undetermined`, which is stage 7
    # departing from stage 5's declared `null` and saying so in its own `spec_gaps`. The
    # consequence is asymmetric across this domain's clauses and worth stating where a query
    # author reads it: an unresolved row satisfies `is not unreferenced`, so PAN-FIL-001 and -002
    # do NOT suppress themselves on it and fall through to their assertion columns - but it does
    # NOT satisfy `equals unreferenced`, so PAN-FIL-004 still reports nothing about a profile
    # nobody could resolve. `reference_reach_resolved` is the companion stage 5 names for exactly
    # that, false on the firing side, and all four controls carry a query on it.
    "reference_reach": build_text_compiler("reference_reach", "reference_reach"),
    "reference_reach_resolved": build_boolean_compiler(
        "reference_reach_resolved", "reference_reach_resolved"),
    # ------------------------------------------------------------------------- `url-filtering`
    # PAN-URL-001 to -006, over the `url-filtering` kind of this model. ADDITIVE ONLY: not one
    # line above this block was renamed, retyped or re-scoped, because PAN-AVW-006 and the three
    # PAN-FIL controls compile their queries through this same table and a changed field changes
    # their results silently.
    #
    # EVERY VERDICT HERE IS A STORED CONCLUSION over the device's own category catalogue MINUS
    # the profile's member lists, for the reason the module docstring gives about the severity
    # verdicts: the question spans a catalogue of 88-to-90 names and a predicate compares one
    # field to one literal. The catalogue is NOT in the profile, which is why none of these can
    # be expressed as a clause over a member list.
    "all_hostile_categories_blocked": build_boolean_compiler(
        "all_hostile_categories_blocked", "all_hostile_categories_blocked"),
    "all_reachable_categories_logged": build_boolean_compiler(
        "all_reachable_categories_logged", "all_reachable_categories_logged"),
    "credential_submission_blocked_for_every_category": build_boolean_compiler(
        "credential_submission_blocked_for_every_category",
        "credential_submission_blocked_for_every_category"),
    "all_reachable_categories_credential_restricted": build_boolean_compiler(
        "all_reachable_categories_credential_restricted",
        "all_reachable_categories_credential_restricted"),
    "records_all_request_headers": build_boolean_compiler(
        "records_all_request_headers", "records_all_request_headers"),
    "cloud_inline_categorization": build_boolean_compiler(
        "cloud_inline_categorization", "cloud_inline_categorization"),
    "local_inline_categorization_on": build_boolean_compiler(
        "local_inline_categorization_on", "local_inline_categorization_on"),
    # THE FOUR GRADED COLUMNS, TEXT AND NOT CHOICE COMPILERS, deliberately and for the reason
    # the file-data-filtering block above gives: each stores the WEAKEST or WORST member in
    # force and is `null=True, default=None`, where a null means the reading was never
    # established - either the row predates the recompute or the device's category catalogue was
    # not collected for it. A null is NOT a value of the column's domain, so a closed-choice
    # builder could express no query for it; `is_empty` reaches it here, because this module's
    # `_text_filter` ORs an `__isnull` branch beside `field=""`.
    #
    # NO `values` LIST EXISTS FOR TWO OF THEM AND THAT IS STAGE 5's DECISION, not an omission:
    # the member set of `worst_reachable_unlogged_category` and
    # `worst_credential_permissive_category` is the device's own catalogue, 88-to-90 names moving
    # with the content release, of which stage 3 placed six and three respectively and said the
    # remainder take the baseline. An unplaced member is returned as the device gave it and
    # matches no calibration query, which is what makes the baseline the right answer for it.
    "weakest_hostile_category_action": build_text_compiler(
        "weakest_hostile_category_action", "weakest_hostile_category_action"),
    "worst_reachable_unlogged_category": build_text_compiler(
        "worst_reachable_unlogged_category", "worst_reachable_unlogged_category"),
    "worst_credential_permissive_category": build_text_compiler(
        "worst_credential_permissive_category", "worst_credential_permissive_category"),
    "broadest_inline_analysis_exemption_type": build_text_compiler(
        "broadest_inline_analysis_exemption_type", "broadest_inline_analysis_exemption_type"),
    "weakest_permitted_custom_category_action": build_text_compiler(
        "weakest_permitted_custom_category_action", "weakest_permitted_custom_category_action"),
    # `worst_unrecorded_request_header` IS A DIFFERENT SHAPE FROM THE FIVE ABOVE and the
    # difference is load-bearing: it is `null=False, blank=True, default=""` and the EMPTY STRING
    # IS ITS PASSING VALUE - no header is missing - where the five above use null for "not
    # established". So `is_empty` here reaches the COMPLIANT rows and not the unread ones, which
    # is why no query of this domain uses it: all three of its values are placed and the verdict
    # boolean beside it carries the passing case.
    "worst_unrecorded_request_header": build_text_compiler(
        "worst_unrecorded_request_header", "worst_unrecorded_request_header"),
    # `credential_detection_mode` is `null=False, blank=True, default="disabled"` and the default
    # FIRES: `disabled` is the value PAN-URL-003's first half reports on, materialised on a
    # committed profile carrying no credential-enforcement node at all - measured on three
    # appliances across two major versions. It is one record's assertion and the next record's
    # applicability, which is why both arms of it are queried.
    "credential_detection_mode": build_text_compiler(
        "credential_detection_mode", "credential_detection_mode"),
    # THE TWO COUNTS, whose unknown READS AS COMPLIANT. `gt 0` returns no row for the migration's
    # own 0, so between the migration that adds the column and the pass that recomputes it an
    # estate reports no exemptions and no carve-outs at all. The companion boolean beside each is
    # what makes that visible and both are registered below for exactly that query.
    "inline_analysis_exemption_count": build_integer_compiler(
        "inline_analysis_exemption_count", "inline_analysis_exemption_count"),
    "permitted_custom_category_count": build_integer_compiler(
        "permitted_custom_category_count", "permitted_custom_category_count"),
    # THE THREE COMPANIONS, each false-or-true on exactly the rows whose verdict rests on
    # nothing. Stage 5 names the first two in `when_unknown.companion_column` for the two counts
    # above; the third is named in PAN-URL-005's `undetermined` as the column that is TRUE on
    # exactly the rows where that restatement may be a false positive.
    "category_catalogue_collected": build_boolean_compiler(
        "category_catalogue_collected", "category_catalogue_collected"),
    "inline_analysis_exemptions_computed": build_boolean_compiler(
        "inline_analysis_exemptions_computed", "inline_analysis_exemptions_computed"),
    "local_inline_categorization_undetermined": build_boolean_compiler(
        "local_inline_categorization_undetermined", "local_inline_categorization_undetermined"),
    # THE TWO REQUEST-HEADER SOURCE BOOLEANS stage 5 names BY NAME in PAN-URL-004's
    # `undetermined`, because both rest on an `assumed_default` rather than on a measurement and
    # a reader of the finding has to be told which of the three defaults is an inference. ONE
    # WRITE PER KEY closes that. `log_http_header_user_agent` is deliberately NOT registered: it
    # is the one of the three stage 5 does not name in any clause, grading or `undetermined`, and
    # the contract's own rule for this list is the narrow one - a field earns its place by a
    # control needing it. The asymmetry is recorded rather than tidied away.
    "log_http_header_xff": build_boolean_compiler("log_http_header_xff", "log_http_header_xff"),
    "log_http_header_referer": build_boolean_compiler(
        "log_http_header_referer", "log_http_header_referer"),
    # `reachable_unlogged_categories`, `credential_permissive_categories`,
    # `unblocked_hostile_categories`, `unrecorded_request_headers` and
    # `inline_analysis_exemptions` are NOT registered, and the reason is a convention rather than
    # an oversight: every one is a JSONField, stage 5 marks each `not_searchable`, and a
    # JSONField must not be registered here. What carries each reading for a QUERY is the scalar
    # beside it - the verdict boolean and the `worst`/`weakest` member - and what carries it for
    # a READER is stage 9's business. Likewise `reference_surfaces_searched` on the custom
    # category, whose scalar neighbour is `referrer_count`.
    # `has_rules` and `lowest_block_threshold` are NOT registered. Stage 5 marks both
    # `needs_compiler_field` and no clause and no grading in this domain names either: stage 5's
    # own `spec_surplus` records that "no clause in this domain reads `has_rules` at all", and
    # `lowest_block_threshold` is "the number an assessor reads beside the verdict, not a column
    # any clause here compares". Both are `presented: true`, which is stage 9's business.
    # Registering them would ship a search surface no control asks for.
    # ---------------------------------------------------------------------------- `decryption`
    # PAN-DCP-001 to -005 and -007, over the `decryption` kind of this model. ADDITIVE ONLY: not
    # one line above this block was renamed, retyped or re-scoped, because PAN-AVW-006, the three
    # PAN-FIL controls and the five PAN-URL controls compile their queries through this same table
    # and a changed field changes their results silently.
    #
    # EVERY QUERY OF THIS DOMAIN CARRIES `kind eq decryption` AND THE REASON IS IN THE MODEL's
    # OWN WORDS. `SecurityProfile.DECRYPTION_KINDS` says this family is the loudest case of the
    # shared-model hazard: the permitted-primitive columns default TRUE and
    # `weakest_broken_primitive_permitted` defaults `rc4`, so a `virus` row reads as permitting
    # RC4 and a clause written without the kind fires on every antivirus profile in the estate.
    # Nothing downstream enforces the clause - not this compiler, not the catalogue schema, not a
    # test - so it is a convention held by the query author alone.
    #
    # THE TWO POLARITIES MEET HERE AND THE COLUMN NAMES DO NOT ANNOUNCE IT. The twelve `*_block_*`
    # columns are BLOCK switches where FALSE is the weak side (the check is not performed); the
    # three verdicts and `rule_destination_unrestricted` are written in the FIRING direction where
    # TRUE is the defect. A query author reading this list top to bottom meets both.
    "ssl_min_version_below_tls12": build_boolean_compiler(
        "ssl_min_version_below_tls12", "ssl_min_version_below_tls12"),
    "ssl_max_version_restrictive": build_boolean_compiler(
        "ssl_max_version_restrictive", "ssl_max_version_restrictive"),
    # PAN-DCP-001 AND -002's APPLICABILITY CLAUSE, and the one column of this domain whose
    # QUANTIFIER is disputed in writing. The shipped docstring is "TRUE where every rule naming it
    # leaves the destination open", which the normaliser spells `not any(narrows)` - so ONE
    # narrowed rule among ten wide-open ones makes this FALSE and SUPPRESSES both controls on a
    # profile nine rules still expose. Stage 7's `spec_gaps` for this domain records the
    # disagreement and a pinned OEI test asserts the declared behaviour so it cannot be flipped
    # quietly. Registered to match what is stored, not what either side wishes were stored.
    "rule_destination_unrestricted": build_boolean_compiler(
        "rule_destination_unrestricted", "rule_destination_unrestricted"),
    # THE TWO GRADED PROTOCOL COLUMNS, TEXT AND NOT CHOICE COMPILERS, and NOT because the empty
    # string is reachable - both are `blank=True` with a non-empty measured default. The reason is
    # that a closed-choice builder would have to carry a value set the two leaves DO NOT SHARE:
    # `max` is a member of the ceiling and the device refuses it at the floor with code=12. Each
    # query is an `eq` on one member, so no ordering is asked of either column - which is the
    # model's own instruction, since lexicographic order is right for the floor by coincidence and
    # INVERTED for the ceiling, where `max` sorts first while meaning the strongest setting.
    #
    # `ssl_max_version_resolved` IS DELIBERATELY NOT REGISTERED. Stage 5 marks it
    # `needs_compiler_field` and `presented: true`, and no clause, no grading column and no
    # `undetermined` of this domain names it - stage 7's own `spec_surplus` says so in terms:
    # "PAN-DCP-001 clauses on `ssl_max_version_restrictive`, the verdict. NOTHING clauses on
    # either of the other two." It is the number a reader is shown beside the verdict, which is
    # stage 9's business, and registering it would ship a search surface no control asks for.
    "ssl_min_version": build_text_compiler("ssl_min_version", "ssl_min_version"),
    "ssl_max_version": build_text_compiler("ssl_max_version", "ssl_max_version"),
    # THE TWO COMPOSED PRIMITIVE VERDICTS, each one token naming the WORST primitive its class
    # still leaves negotiable, with `none` as the only compliant member. Text for the same reason
    # as the two above: every query is an `eq` on one member and the severity varies with WHICH
    # member it is, which is what a grading over the values of one column needs. The member sets
    # are `BROKEN_PRIMITIVE_ORDER` and `NON_PFS_OR_UNAUTHENTICATED_ORDER` on the model, plus
    # `PRIMITIVE_NONE` - composed by the normaliser out of seven booleans rather than read off any
    # single device key, which is why no closed choice set the device offers could back them.
    "weakest_broken_primitive_permitted": build_text_compiler(
        "weakest_broken_primitive_permitted", "weakest_broken_primitive_permitted"),
    "weakest_non_pfs_or_unauthenticated_permitted": build_text_compiler(
        "weakest_non_pfs_or_unauthenticated_permitted",
        "weakest_non_pfs_or_unauthenticated_permitted"),
    # THE FOUR CERTIFICATE AND VERSION BLOCK SWITCHES PAN-DCP-003, -004 AND -005[0] ASSERT ON.
    # FALSE means the profile does not perform the check, which is the finding, and false is also
    # what an absent key asserts - measured on the dialog's own checkboxes - so the materialised
    # default, the measured absent value and the firing side are one answer. `fwd_` is
    # `ssl-forward-proxy` and `inb_` is `ssl-inbound-proxy`; the two containers are NOT symmetric,
    # which is why `block-expired-certificate` and `block-untrusted-issuer` have no `inb_` twin.
    "fwd_block_expired_certificate": build_boolean_compiler(
        "fwd_block_expired_certificate", "fwd_block_expired_certificate"),
    "fwd_block_untrusted_issuer": build_boolean_compiler(
        "fwd_block_untrusted_issuer", "fwd_block_untrusted_issuer"),
    "fwd_block_unsupported_version": build_boolean_compiler(
        "fwd_block_unsupported_version", "fwd_block_unsupported_version"),
    "fwd_block_unsupported_cipher": build_boolean_compiler(
        "fwd_block_unsupported_cipher", "fwd_block_unsupported_cipher"),
    "inb_block_unsupported_version": build_boolean_compiler(
        "inb_block_unsupported_version", "inb_block_unsupported_version"),
    "inb_block_unsupported_cipher": build_boolean_compiler(
        "inb_block_unsupported_cipher", "inb_block_unsupported_cipher"),
    # THE SIX RESOURCE, DOWNGRADE AND HSM BLOCK SWITCHES, PAN-DCP-005[1] and [2]. Both records
    # are INVERTED - `finding_when_clauses_fail` over four and two clauses - so their baselines
    # fire on the DISJUNCTION of the negations and are written as `or` groups of negated
    # equalities. A negated `eq true` on a non-nullable boolean is exactly `= false`, so no
    # `is_empty` member is needed and none is offered: the boolean builder takes `eq` alone.
    "fwd_block_if_no_resource": build_boolean_compiler(
        "fwd_block_if_no_resource", "fwd_block_if_no_resource"),
    "fwd_block_tls13_downgrade_no_resource": build_boolean_compiler(
        "fwd_block_tls13_downgrade_no_resource", "fwd_block_tls13_downgrade_no_resource"),
    "inb_block_if_no_resource": build_boolean_compiler(
        "inb_block_if_no_resource", "inb_block_if_no_resource"),
    "inb_block_tls13_downgrade_no_resource": build_boolean_compiler(
        "inb_block_tls13_downgrade_no_resource", "inb_block_tls13_downgrade_no_resource"),
    "fwd_block_if_hsm_unavailable": build_boolean_compiler(
        "fwd_block_if_hsm_unavailable", "fwd_block_if_hsm_unavailable"),
    "inb_block_if_hsm_unavailable": build_boolean_compiler(
        "inb_block_if_hsm_unavailable", "inb_block_if_hsm_unavailable"),
    # THE COMPANION THAT TELLS A REFERRER COUNT OF ZERO FROM A COUNT NOBODY TOOK. PAN-DCP-007
    # carries it BOTH WAYS: `eq true` as an applicability clause on the baseline, which suppresses
    # the control where no decryption rulebase was collected, and `eq false` on a second query
    # that picks the suppressed rows up and reports them as not assessed rather than as unused.
    # Without the pair, `is_used eq false` reports every profile on an uncollected appliance as
    # unreferenced with a deletion remediation attached. The model's own docstring says the
    # pairing is stage 8's to write and that this column only makes it possible.
    "decryption_rulebase_collected": build_boolean_compiler(
        "decryption_rulebase_collected", "decryption_rulebase_collected"),
    # THE SEVEN PER-PRIMITIVE ALLOW SWITCHES - `enc_algo_rc4`, `enc_algo_3des`, `auth_algo_sha1`,
    # `auth_algo_md5`, `keyxchg_algo_rsa`, `enc_algo_aes_128_cbc`, `enc_algo_aes_256_cbc` - ARE
    # NOT REGISTERED, and that is the same narrow rule the `has_rules` note above applies. Stage 5
    # marks all seven `needs_compiler_field` and `presented: true`, and no clause and no grading
    # of this domain names one: PAN-DCP-002's two records each clause on the COMPOSED verdict
    # instead, because `clauses` is one conjunction with no OR and the assertion is a disjunction
    # over four and three booleans. They are what a READER is shown so a report naming RC4 is not
    # silent about SHA-1 on the same profile, which is stage 9's business.
    #
    # `namespace_value`, `precedence_rank` and `vsys_name` are not registered for this domain
    # either. `vsys_name` already ships above; the other two are `presented` only, and stage 7
    # recorded `vsys_name` in `columns_not_built` on its own model spec because every shared and
    # predefined row reaches an EMPTY vsys name through the traversal, so a clause on it silently
    # drops every shared-scoped row.
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
