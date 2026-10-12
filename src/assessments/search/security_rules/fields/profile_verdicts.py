"""Compilers for the eleven per-rule threat-profile assertions.

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
}

PROFILE_VERDICT_COMPILERS = {
    field: build_profile_verdict_compiler(field, assertion)
    for field, assertion in VERDICT_FIELDS.items()
}
PROFILE_VERDICT_COMPILERS.update({
    f"{field}_detail": build_profile_verdict_detail_compiler(f"{field}_detail", assertion)
    for field, assertion in VERDICT_FIELDS.items()
})
