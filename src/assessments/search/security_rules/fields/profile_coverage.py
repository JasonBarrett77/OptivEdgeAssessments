"""Compilers for the threat-profile coverage fields. PAN-POL-008.

Whether a rule is actually protected by an antivirus, anti-spyware or vulnerability profile -
after resolving its profile group, not merely after noting that it names one.

That distinction is the control. On the lab 113 rules name a profile group called `default`
and that group names no profiles at all, so every one of them inspects nothing while appearing
configured. The resolution happens in normalization, which walks the reference, resolves the
group name by scope and reads its member list; the search layer compares a field to a literal
and cannot do any of that.
"""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.security_rules.fields.scalar_boolean import parse_boolean_value
from optivedge_integrations.integrations.models import SecurityRule

SUPPORTED_OPERATORS = {"eq"}


def _build(field_name, column):
    def compiler(clause):
        op = clause["op"]
        if op not in SUPPORTED_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        value = parse_boolean_value(clause["value"], field_name=field_name)
        return SecurityRule.objects.filter(**{column: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
    return compiler


compile_has_antivirus_profile_clause = _build(
    "has_antivirus_profile", "has_antivirus_profile")
compile_has_spyware_profile_clause = _build(
    "has_spyware_profile", "has_spyware_profile")
compile_has_vulnerability_profile_clause = _build(
    "has_vulnerability_profile", "has_vulnerability_profile")

#: PAN-VLN-004's applicability. THE RESOLVED HALF, and it is not `has_vulnerability_profile`:
#: the two differ on a rule naming a vulnerability profile that does not exist. The name is in
#: force, so `has_vulnerability_profile` is true, while nothing resolves - and saying "this
#: profile carries exemptions" about a profile that does not exist is a false finding.
#:
#: The column is `BooleanField(default=False)` and is set by the coverage pass from the
#: generalised `profile_is_resolved`, which walks the rule's profile-setting, resolves a group
#: name by scope and reads its member list. The search layer compares a field to a literal and
#: cannot do any of that, which is why the resolution happens in normalisation.
compile_vulnerability_profile_resolved_clause = _build(
    "vulnerability_profile_resolved", "vulnerability_profile_resolved")


def compile_wildfire_analysis_submits_all_clause(clause):
    """Does the WildFire analysis profile in force on this rule send EVERY file type?

    THREE STATES, TWO SEARCH VALUES. The column is nullable and null means "no profile
    reaches this rule", which is a different fix from "a profile does and it is too narrow" -
    so the detail column carries the distinction and this field carries the verdict.

    `false` matches NULL as well as False, because the question a control asks is "is this
    rule's traffic fully analysed", and the answer is no in both cases. Matching only False
    would pass every rule with no profile at all, which is the larger of the two problems and
    the one PAN-AVW-003 was built to find.
    """
    field_name = "wildfire_analysis_submits_all"
    op = clause["op"]
    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    value = parse_boolean_value(clause["value"], field_name=field_name)
    if value:
        return SecurityRule.objects.filter(
            wildfire_analysis_submits_all=True).values("pk")
    return SecurityRule.objects.exclude(
        wildfire_analysis_submits_all=True).values("pk")


compile_wildfire_analysis_submits_all_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
