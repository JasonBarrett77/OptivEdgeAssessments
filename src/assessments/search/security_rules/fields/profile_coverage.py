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
