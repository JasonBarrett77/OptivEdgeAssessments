"""Canonical search compiler for one enforcement point's SaaS URL-filtering verdict.

PAN-SAS-002 and PAN-SAS-004. Two questions off one object: whether any profile reachable from
the partition inserts a tenant-restriction header into traffic a rule of that partition actually
carries, and how the partition treats the web categories that carry consumer file storage and
personal publishing.

NO PROFILE ROW EXISTS TO HANG EITHER ON, which is why the grain is the partition and every field
here is a derived verdict. `normalization/security_profiles.py::PROFILE_KINDS` holds four kinds
and `url-filtering` is not one of them, so nothing writes a url-filtering profile row at all -
and a naive control over "a profile carrying header insertion" would have been written against
rows that do not exist.

THE TWO VERDICT BOOLEANS ARE WRITTEN IN THE DIRECTION THAT PASSES, so FALSE is the finding on
both, and false is the migration default on both. That is deliberate rather than convenient: an
`eq false` clause on a NULLABLE boolean behaves differently per model in this consumer, so both
columns are non-nullable with a materialised default and the polarity is fixed where it is
declared.

`consumer_storage_category_treatment` IS A RANK AND `in-no-restricting-list` IS A MEMBER OF IT,
not a sentinel on it. A predefined category explicitly set to permit is NEVER WRITTEN, so the
reading is an enumeration over the category namespace rather than a membership test over the
stored members - which is why the column holds the LEAST restrictive treatment any covered
category gets, and why a partition nobody enumerated grades at the weak end rather than falling
out of the table.

TWO COUNTS HERE FIRE ON NOTHING BY THEMSELVES and both are registered anyway, because a reader
of a finding needs them. `header_insertion_type_entry_count` is the unit of COVERAGE - a second
`type` entry under one `http-header-insertion` entry is refused by the device, so covering N
applications takes N sibling entries - and `rule_bound_tenant_list_count` counts the native
route, whose absence is EXPECTED on an unlicensed estate and is information rather than a
finding. A control clausing on either alone would report every partition in the estate.

`url_filtering_profiles_read` IS THE MOST IMPORTANT FIELD HERE. In the collected payload "no
header insertion" and "url-filtering was never collected" are the same absence, so a control
firing on the first fires on every appliance in every estate until normalization changes. This
column separates them, and it is clausable in its own right.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import SaasUrlFilteringPosture

SAAS_URL_FILTERING_POSTURE_MODEL = "integrations.SaasUrlFilteringPosture"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        predicate = Q()
        for lookup in lookups:
            predicate &= Q(**{lookup: ""}) | Q(**{f"{lookup}__isnull": True})
        return predicate
    if not isinstance(value, str) or not value.strip():
        raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
    suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
    predicate = Q()
    for lookup in lookups:
        predicate |= Q(**{f"{lookup}__{suffix}": value.strip()})
    return predicate


def build_text_compiler(field_name, *lookups):
    def compiler(clause):
        return SaasUrlFilteringPosture.objects.filter(
            _text_filter(field_name, lookups, clause)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return SaasUrlFilteringPosture.objects.filter(**{lookup_field: value}).values("pk")
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
        return SaasUrlFilteringPosture.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler(
        "hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # The companion that answers "did anybody look". False means nobody looked, not that the
    # partition holds no profile.
    "url_filtering_profiles_read": build_boolean_compiler(
        "url_filtering_profiles_read", "url_filtering_profiles_read"),
    # PAN-SAS-002's assertion. FALSE is the finding.
    "tenant_restriction_in_force": build_boolean_compiler(
        "tenant_restriction_in_force", "tenant_restriction_in_force"),
    # PAN-SAS-004's assertion over the web-category surface. FALSE is the finding.
    "consumer_storage_categories_are_restricted": build_boolean_compiler(
        "consumer_storage_categories_are_restricted",
        "consumer_storage_categories_are_restricted"),
    # The GRADED column. A calibration query compares on this; the assertion never does. The
    # placements are EQUALITIES on mutually exclusive tokens and must stay that way: a threshold
    # or a `contains` here would let the low-severity query match a row the grading places at
    # medium, and `derive_control_query_severity_value` would then discard the baseline tier.
    "consumer_storage_category_treatment": build_text_compiler(
        "consumer_storage_category_treatment", "consumer_storage_category_treatment"),
    # Counts a finding reads and no clause of this domain rests on. See the module docstring.
    "header_insertion_type_entry_count": build_integer_compiler(
        "header_insertion_type_entry_count", "header_insertion_type_entry_count"),
    "tenant_header_without_value_count": build_integer_compiler(
        "tenant_header_without_value_count", "tenant_header_without_value_count"),
    "rule_bound_tenant_list_count": build_integer_compiler(
        "rule_bound_tenant_list_count", "rule_bound_tenant_list_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_saas_url_filtering_posture_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_saas_url_filtering_posture_search_node(c) for c in group["clauses"]]
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
