"""Compilers for the nine per-rule threat-profile assertions. PAN-SPY-001..005, PAN-VLN-001..004.

These controls were profile-based until 2026-10-12 - one finding per SecurityProfile. Jason
asked for the whole domain to report per rule, as PAN-AVW-003 does, because a profile nothing
uses endangers nothing and a rule is what carries traffic.

THE VERDICTS LIVE ON A SATELLITE, one row per rule per assertion, and these compilers reach
into it. The same shape as the security-profile severity and category verdicts.

**`false` DOES NOT MATCH NULL HERE, and that is a deliberate break from PAN-AVW-003.** Its
compiler matches NULL on `false` so a rule with no WildFire profile reports, which is right for
one control. For nine it is not: 962 of the lab's 966 allow rules have no anti-spyware profile
in force, so matching NULL would raise nine findings on each - roughly 8,600 - and bury the one
finding that describes the actual problem.

PAN-POL-008 owns "this allow rule has no security profile" and says it once. These own "the
profile that IS attached is configured correctly". A rule with no profile therefore matches
neither `true` nor `false` here, which is the same no-claim rule the profile-side verdict
fields already use.
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
    `false`, because a rule can hold a NULL row for this assertion and NULL is neither.
    """
    def compiler(clause):
        op = clause["op"]
        if op not in SUPPORTED_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        value = parse_boolean_value(clause["value"], field_name=field_name)
        return SecurityRule.objects.filter(
            profile_verdicts__assertion=assertion,
            profile_verdicts__satisfied=value).values("pk")
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
    "spyware_blocks_critical_high": _V.SPYWARE_SEVERITIES,
    "spyware_dns_sinkholes": _V.SPYWARE_DNS_SINKHOLE,
    "spyware_dns_categories_enforced": _V.SPYWARE_DNS_CATEGORIES,
    "spyware_inline_analysis_blocks": _V.SPYWARE_INLINE,
    "spyware_exceptions_minimal": _V.SPYWARE_EXCEPTIONS,
    "vulnerability_blocks_critical_high": _V.VULNERABILITY_SEVERITIES,
    "vulnerability_blocks_brute_force": _V.VULNERABILITY_BRUTE_FORCE,
    "vulnerability_inline_analysis_blocks": _V.VULNERABILITY_INLINE,
    "vulnerability_exceptions_minimal": _V.VULNERABILITY_EXCEPTIONS,
}

PROFILE_VERDICT_COMPILERS = {
    field: build_profile_verdict_compiler(field, assertion)
    for field, assertion in VERDICT_FIELDS.items()
}
PROFILE_VERDICT_COMPILERS.update({
    f"{field}_detail": build_profile_verdict_detail_compiler(f"{field}_detail", assertion)
    for field, assertion in VERDICT_FIELDS.items()
})
