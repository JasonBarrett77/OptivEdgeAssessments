"""Compilers for the twelve per-rule threat-profile assertions, and one graded value beside them.

PAN-AVW-001, PAN-AVW-002, PAN-SPY-001..005 and PAN-VLN-001..004.

These controls were profile-based until 2026-10-12 - one finding per SecurityProfile. Jason
asked for the whole domain to report per rule, as PAN-AVW-003 does, because a profile nothing
uses endangers nothing and a rule is what carries traffic.

THE VERDICTS LIVE ON A SATELLITE, one row per rule per assertion, and these compilers reach
into it. The same shape as the security-profile severity and category verdicts.

**`false` MATCHES NULL**, so a rule with no profile of that kind reports. Jason, 2026-10-12:
"The absence of a profile should create the finding for that profile. This is a rule across all
rule security profiles."

These compilers shipped the other way for a few hours, on the argument that nine controls
matching NULL would raise roughly 8,600 findings on the lab and duplicate PAN-POL-008. That
argued VOLUME, which is not the same thing as correctness: a rule with no anti-spyware profile
is not getting anti-spyware inspection, so the absence is this control's finding and not merely
PAN-POL-008's. PAN-AVW-003 had it right from the day it was built.

So the two overlap deliberately. PAN-POL-008 says "this allow rule carries no security profiles
at all", once; each of these says "this rule gets no antivirus / anti-spyware / vulnerability
inspection", and the `detail` on the row says which of the two it is - `no <kind> profile is in
force on this rule`, or the specific gap in the profile that IS there.

`true` still requires a profile that satisfies the assertion, so the two values are not each
other's complement and a row is never matched by both.
"""

from __future__ import annotations

from django.db.models import Q

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.security_rules.fields.scalar_boolean import parse_boolean_value
from optivedge_integrations.integrations.models import (
    SecurityRule,
    SecurityRuleProfileVerdict,
)

SUPPORTED_OPERATORS = {"eq"}


def build_profile_verdict_compiler(field_name, assertion):
    """`<field> = true/false` against one assertion's verdict rows.

    `true` is expressed as "has the row and it is satisfied" rather than as the complement of
    `false`, because NULL is on the FALSE side here and the two must not both match a row.
    """
    def compiler(clause):
        op = clause["op"]
        if op not in SUPPORTED_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        value = parse_boolean_value(clause["value"], field_name=field_name)
        if value:
            return SecurityRule.objects.filter(
                profile_verdicts__assertion=assertion,
                profile_verdicts__satisfied=True).values("pk")
        # NULL FIRES: no profile of this kind reaches the rule, so the rule gets none of this
        # inspection. The row's `detail` distinguishes that from a profile that is present and
        # misconfigured, which is a different fix.
        return SecurityRule.objects.filter(
            Q(profile_verdicts__assertion=assertion)
            & (Q(profile_verdicts__satisfied=False)
               | Q(profile_verdicts__satisfied__isnull=True))).values("pk")
    compiler.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
    return compiler


def build_profile_verdict_detail_compiler(field_name, assertion):
    """The reason beside a verdict - which profile, and what is wrong with it."""
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in {"eq", "contains"}:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, str):
            raise SearchSyntaxError(f"{field_name} search value must be a string.")
        lookup = "iexact" if op == "eq" else "icontains"
        return SecurityRule.objects.filter(**{
            "profile_verdicts__assertion": assertion,
            f"profile_verdicts__detail__{lookup}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq", "contains"}
    return compiler


_V = SecurityRuleProfileVerdict

#: field name -> assertion. The field names are what control queries say, so they are a
#: contract; the assertion constants are what the satellite stores.
VERDICT_FIELDS = {
    "antivirus_blocks_malware": _V.ANTIVIRUS_BLOCKS_MALWARE,
    "antivirus_inline_ml_blocks": _V.ANTIVIRUS_INLINE_ML,
    "spyware_blocks_critical_high": _V.SPYWARE_SEVERITIES,
    "spyware_dns_sinkholes": _V.SPYWARE_DNS_SINKHOLE,
    "spyware_dns_categories_enforced": _V.SPYWARE_DNS_CATEGORIES,
    "spyware_inline_analysis_blocks": _V.SPYWARE_INLINE,
    "spyware_exceptions_minimal": _V.SPYWARE_EXCEPTIONS,
    "vulnerability_blocks_critical_high": _V.VULNERABILITY_SEVERITIES,
    "vulnerability_blocks_brute_force": _V.VULNERABILITY_BRUTE_FORCE,
    "vulnerability_inline_analysis_blocks": _V.VULNERABILITY_INLINE,
    "vulnerability_exceptions_minimal": _V.VULNERABILITY_EXCEPTIONS,
    # PAN-VLN-003's FIRST HALF, and the twelfth assertion. `VULNERABILITY_INLINE` above answers
    # only the second half - it reads `mica-engine-vulnerability-enabled` and not
    # `cloud-inline-analysis` - so a profile with every detector at reset-both and the
    # profile-wide switch OFF satisfied that assertion and inspected nothing in real time.
    # Stage 3 states the control as two halves and standing ruling 6 makes it one control with
    # an OR, so this field is clausedon by a second active query rather than a new control id.
    "vulnerability_inline_analysis_enabled": _V.VULNERABILITY_INLINE_ENABLED,
}

PROFILE_VERDICT_COMPILERS = {
    field: build_profile_verdict_compiler(field, assertion)
    for field, assertion in VERDICT_FIELDS.items()
}
PROFILE_VERDICT_COMPILERS.update({
    f"{field}_detail": build_profile_verdict_detail_compiler(f"{field}_detail", assertion)
    for field, assertion in VERDICT_FIELDS.items()
})


def build_profile_verdict_grading_compiler(field_name, assertion):
    """The GRADED VALUE beside one assertion's verdict - what the severity varies with.

    A verdict says WHETHER and a severity grading needs WHICH, and the value it needs is
    `SecurityRuleProfileVerdict.grading_value`: ONE column with a different vocabulary per
    assertion, which is why the field name says which axis it is and the assertion is bound in.

    **BLANK IS NOT A MATCHABLE VALUE AND THAT IS THE POINT.** `grading_value` is
    `blank=True` rather than nullable, and it is blank on every assertion that has no grading,
    on a verdict whose profile could not be resolved, and on a rule that has no verdict row at
    all. A positive `eq` reaches none of those, so a rule nobody graded matches no calibration
    query and reports at its control's BASELINE severity - which is the direction a missing
    grading has to point. An empty search value is refused rather than compiled, because
    `eq ""` would quietly match every ungraded row and hand the whole estate a calibration.
    """
    def compiler(clause):
        op = clause["op"]
        if op not in GRADING_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        value = clause["value"]
        if not isinstance(value, str):
            raise SearchSyntaxError(f"{field_name} search value must be a string.")
        if not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must not be empty.")
        return SecurityRule.objects.filter(
            profile_verdicts__assertion=assertion,
            profile_verdicts__grading_value=value).values("pk")
    compiler.SUPPORTED_OPERATORS = GRADING_OPERATORS
    return compiler


GRADING_OPERATORS = {"eq"}

#: field name -> the assertion whose `grading_value` it reads. ONE ENTRY PER GRADED AXIS A
#: CONTROL QUERY NAMES, and not one per axis that exists: the two vulnerability weakest-action
#: axes are stored and graded, but every one of their placements sits at its control's own
#: baseline severity, so no calibration query names them and registering them would ship a
#: search surface no control asks for.
GRADING_FIELDS = {
    # PAN-VLN-004's grading. Three firing members - `signature-scoped` (low),
    # `signature-unscoped` (medium, the baseline tier and so queryless) and
    # `inline-analysis-population` (high) - and the blank passing state.
    "vulnerability_widest_exemption_surface": _V.VULNERABILITY_EXCEPTIONS,
    # PAN-SPY-001's grading: WHICH severity band the anti-spyware profile leaves un-stopped.
    # `critical` and `high` both sit at the control's own baseline tier and are queried anyway,
    # because the band is what a reader of the row needs and stage 6 names this column as the
    # clause those subjects violate. `medium` is UNREACHABLE and deliberately has no query:
    # `SecurityProfile.worst_unstopped_severity` returns `medium` only when critical and high
    # are both stopped, which makes `spyware_blocks_critical_high` TRUE - and every query on
    # this control carries that assertion as `eq false`, so no row can hold both.
    "spyware_worst_unstopped_severity": _V.SPYWARE_SEVERITIES,
    # PAN-SPY-002's grading: what the profile does with a lookup on the vendor's own downloaded
    # malicious-domain list. Four members, `sinkhole` passing, the other three all queried.
    "spyware_dns_content_list_action": _V.SPYWARE_DNS_SINKHOLE,
    # PAN-SPY-004's grading: the weakest action any inline analysis engine holds. `allow` (high)
    # and `alert` (medium, the baseline tier) fire; the four stopping actions pass.
    "spyware_worst_engine_action": _V.SPYWARE_INLINE,
}

PROFILE_VERDICT_GRADING_COMPILERS = {
    field: build_profile_verdict_grading_compiler(field, assertion)
    for field, assertion in GRADING_FIELDS.items()
}
