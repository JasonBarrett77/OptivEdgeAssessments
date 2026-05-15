"""Canonical search model and field registry."""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.management_plane.compiler import (
    FIELD_OPERATOR_REGISTRY as MANAGEMENT_PLANE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.management_plane.compiler import (
    MANAGEMENT_PLANE_MODEL,
    compile_management_plane_search_node,
)
from assessments.search.security_rules.compiler import (
    FIELD_OPERATOR_REGISTRY as SECURITY_RULE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.security_rules.compiler import (
    SECURITY_RULE_MODEL,
    compile_security_rule_search_node,
)
from optivedge.integrations.models import ManagementPlaneProfile, SecurityRule


MODEL_REGISTRY = {
    SECURITY_RULE_MODEL: {
        "model_class": SecurityRule,
        "field_operators": SECURITY_RULE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_security_rule_search_node,
    },
    MANAGEMENT_PLANE_MODEL: {
        "model_class": ManagementPlaneProfile,
        "field_operators": MANAGEMENT_PLANE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_management_plane_search_node,
    },
}


def get_model_label(model_class):
    return f"{model_class._meta.app_label}.{model_class.__name__}"


def get_model_entry(model_name):
    entry = MODEL_REGISTRY.get(model_name)
    if entry is None:
        raise SearchSyntaxError(f"Unsupported search model: {model_name}.")
    return entry
