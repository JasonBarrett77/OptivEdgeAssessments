"""Model-specific canonical search compilation for security rules."""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.security_rules.fields.action import compile_action_clause
from assessments.search.security_rules.fields.application import compile_application_clause
from assessments.search.security_rules.fields.config_source import compile_config_source_clause
from assessments.search.security_rules.fields.description import compile_description_clause
from assessments.search.security_rules.fields.disabled import compile_disabled_clause
from assessments.search.security_rules.fields.destination_address import (
    compile_destination_address_clause,
)
from assessments.search.security_rules.fields.destination_address_semantic import (
    compile_destination_address_semantic_clause,
)
from assessments.search.security_rules.fields.from_zone import compile_from_zone_clause
from assessments.search.security_rules.fields.log_end import compile_log_end_clause
from assessments.search.security_rules.fields.log_setting import compile_log_setting_clause
from assessments.search.security_rules.fields.log_start import compile_log_start_clause
from assessments.search.security_rules.fields.management_station import (
    compile_management_station_clause,
)
from assessments.search.security_rules.fields.name import compile_name_clause
from assessments.search.security_rules.fields.negate_destination import compile_negate_destination_clause
from assessments.search.security_rules.fields.negate_source import compile_negate_source_clause
from assessments.search.security_rules.fields.provenance import compile_provenance_clause
from assessments.search.security_rules.fields.rule_type import compile_rule_type_clause
from assessments.search.security_rules.fields.service import compile_service_clause
from assessments.search.security_rules.fields.source_address import compile_source_address_clause
from assessments.search.security_rules.fields.source_address_semantic import (
    compile_source_address_semantic_clause,
)
from assessments.search.security_rules.fields.to_zone import compile_to_zone_clause
from assessments.search.security_rules.fields.vsys_display_name import (
    compile_vsys_display_name_clause,
)
from assessments.search.security_rules.fields.vsys_name import compile_vsys_name_clause


SECURITY_RULE_MODEL = "integrations.SecurityRule"


FIELD_COMPILERS = {
    "action": compile_action_clause,
    "application": compile_application_clause,
    "config_source": compile_config_source_clause,
    "description": compile_description_clause,
    "disabled": compile_disabled_clause,
    "destination_address": compile_destination_address_semantic_clause,
    "destination_address_name": compile_destination_address_clause,
    "from_zone": compile_from_zone_clause,
    "log_end": compile_log_end_clause,
    "log_setting": compile_log_setting_clause,
    "log_start": compile_log_start_clause,
    "management_station": compile_management_station_clause,
    "name": compile_name_clause,
    "negate_destination": compile_negate_destination_clause,
    "negate_source": compile_negate_source_clause,
    "provenance": compile_provenance_clause,
    "rule_type": compile_rule_type_clause,
    "service": compile_service_clause,
    "source_address": compile_source_address_semantic_clause,
    "source_address_name": compile_source_address_clause,
    "to_zone": compile_to_zone_clause,
    "vsys_display_name": compile_vsys_display_name_clause,
    "vsys_name": compile_vsys_name_clause,
}
FIELD_OPERATOR_REGISTRY = {
    "action": compile_action_clause.SUPPORTED_OPERATORS,
    "application": compile_application_clause.SUPPORTED_OPERATORS,
    "config_source": compile_config_source_clause.SUPPORTED_OPERATORS,
    "description": compile_description_clause.SUPPORTED_OPERATORS,
    "disabled": compile_disabled_clause.SUPPORTED_OPERATORS,
    "destination_address": compile_destination_address_semantic_clause.SUPPORTED_OPERATORS,
    "destination_address_name": compile_destination_address_clause.SUPPORTED_OPERATORS,
    "from_zone": compile_from_zone_clause.SUPPORTED_OPERATORS,
    "log_end": compile_log_end_clause.SUPPORTED_OPERATORS,
    "log_setting": compile_log_setting_clause.SUPPORTED_OPERATORS,
    "log_start": compile_log_start_clause.SUPPORTED_OPERATORS,
    "management_station": compile_management_station_clause.SUPPORTED_OPERATORS,
    "name": compile_name_clause.SUPPORTED_OPERATORS,
    "negate_destination": compile_negate_destination_clause.SUPPORTED_OPERATORS,
    "negate_source": compile_negate_source_clause.SUPPORTED_OPERATORS,
    "provenance": compile_provenance_clause.SUPPORTED_OPERATORS,
    "rule_type": compile_rule_type_clause.SUPPORTED_OPERATORS,
    "service": compile_service_clause.SUPPORTED_OPERATORS,
    "source_address": compile_source_address_semantic_clause.SUPPORTED_OPERATORS,
    "source_address_name": compile_source_address_clause.SUPPORTED_OPERATORS,
    "to_zone": compile_to_zone_clause.SUPPORTED_OPERATORS,
    "vsys_display_name": compile_vsys_display_name_clause.SUPPORTED_OPERATORS,
    "vsys_name": compile_vsys_name_clause.SUPPORTED_OPERATORS,
}

def compile_security_rule_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled_clauses = [compile_security_rule_search_node(clause) for clause in group["clauses"]]
    predicate = compiled_clauses[0]
    for compiled_clause in compiled_clauses[1:]:
        if group["operator"] == "and":
            predicate &= compiled_clause
        else:
            predicate |= compiled_clause
    return predicate


def compile_search_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    subquery = compiler(clause)
    predicate = Q(pk__in=Subquery(subquery))
    if clause["negated"]:
        predicate = ~predicate
    return predicate
