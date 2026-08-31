"""Canonical search model and field registry."""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.compiler import (
    FIELD_OPERATOR_REGISTRY as DEVICE_CONFIGURATION_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.device_configuration.compiler import (
    DEVICE_CONFIGURATION_MODEL,
    compile_device_configuration_search_node,
)
from assessments.search.security_rules.compiler import (
    FIELD_OPERATOR_REGISTRY as SECURITY_RULE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.security_rules.compiler import (
    SECURITY_RULE_MODEL,
    compile_security_rule_search_node,
)
from assessments.search.management_interface.compiler import (
    FIELD_OPERATOR_REGISTRY as MANAGEMENT_INTERFACE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.management_interface.compiler import (
    MANAGEMENT_INTERFACE_MODEL,
    compile_management_interface_search_node,
)
from assessments.search.interface_management_profile.compiler import (
    FIELD_OPERATOR_REGISTRY as INTERFACE_MANAGEMENT_PROFILE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.interface_management_profile.compiler import (
    INTERFACE_MANAGEMENT_PROFILE_MODEL,
    compile_interface_management_profile_search_node,
)
from optivedge_integrations.integrations.models import (
    InterfaceManagementProfile,
    DeviceConfigurationProfile,
    ManagementInterface,
    SecurityRule,
)


MODEL_REGISTRY = {
    SECURITY_RULE_MODEL: {
        "model_class": SecurityRule,
        "field_operators": SECURITY_RULE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_security_rule_search_node,
    },
    DEVICE_CONFIGURATION_MODEL: {
        "model_class": DeviceConfigurationProfile,
        "field_operators": DEVICE_CONFIGURATION_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_device_configuration_search_node,
    },
    MANAGEMENT_INTERFACE_MODEL: {
        "model_class": ManagementInterface,
        "field_operators": MANAGEMENT_INTERFACE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_management_interface_search_node,
    },
    INTERFACE_MANAGEMENT_PROFILE_MODEL: {
        "model_class": InterfaceManagementProfile,
        "field_operators": INTERFACE_MANAGEMENT_PROFILE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_interface_management_profile_search_node,
    },
}


def get_model_label(model_class):
    return f"{model_class._meta.app_label}.{model_class.__name__}"


def get_model_entry(model_name):
    entry = MODEL_REGISTRY.get(model_name)
    if entry is None:
        raise SearchSyntaxError(f"Unsupported search model: {model_name}.")
    return entry
