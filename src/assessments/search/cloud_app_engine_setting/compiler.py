"""Canonical search compiler for one appliance's App-ID Cloud Engine. PAN-SAS-005.

ONE ROW PER APPLIANCE, because `deviceconfig/setting/cloudapp` is a device-wide singleton with
no entry name and no vsys - so the owner is the appliance directly and there is no enforcement
point in the lookup path. On an HA pair the setting is synchronised and this produces two rows
for one real configuration, which nothing downstream deduplicates.

THE CONFIGURATION AND THE ENGINE POINT OPPOSITE WAYS FROM ONE NODE AND THE CONFIGURATION IS THE
REASSURING ONE. `ace_disabled` is absent on every lab appliance, so a control reading it alone
passes all four - while `show cloud-appid connection-to-cloud` answers "ACE Error: License check
failed", "Cloud connection: failed" and "Device cert status: Not installed, Invalid or Not pushed
to daemons" on every one of them. PAN-SAS-005 therefore asserts on `ace_not_operational`, which
is the operational verdict, and on nothing in the configuration.

`ace_disabled` IS NULLABLE AND NO OPERATOR HERE REACHES A NULL. It is null in exactly one state -
the merged snapshot carried no `deviceconfig/setting` subtree, so the key is neither present nor
absent but UNREAD - and SQL answers every positive comparison over a null with no match, so an
appliance nobody collected would PASS `ace_disabled eq true`. That is why `cloudapp_node_read`
exists and is registered beside it: a control over the value clauses on the companion, never on
the value alone. There is no is-null operator in this query language and this module does not
invent one. No clause in `saas-security` names `ace_disabled` at all.

`ace_failure_reason` IS A GATE AND NOT A GRADE, and the distinction is the decision on
PAN-SAS-005's second record. Stage 3's applicability is the subscription, and the only column
that can read the subscription is the same verdict the assertion fires on - so a clause on
`ace_not_operational` would have excluded exactly the rows the assertion is about. The gate is on
the reason instead, as a NEGATED equality against `license_check_failed`, which separates "no
subscription, so the control was never about this device" from "subscribed and not working". The
negation rides as a clause FLAG rather than an operator, so this needs no `or` and no second
group.

`unread` IS A REAL TOKEN AND THE GATE ADMITS IT. A text column defaulting to the empty string
makes a negated equality fire for free, so the migration default is the token and an appliance
nobody asked stays inside the control and reports.

`cloudapp_server_address` IS DELIBERATELY NOT REACHABLE FROM HERE. Stage 5 marks it
`not_searchable` and `presented: false`: it stores NOTHING for the absent key, because stage 4
recorded the implicit as unmeasured, and nothing in this domain asserts it.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import CloudAppEngineSetting

CLOUD_APP_ENGINE_SETTING_MODEL = "integrations.CloudAppEngineSetting"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return CloudAppEngineSetting.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return CloudAppEngineSetting.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return CloudAppEngineSetting.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column. The owner is the appliance itself here, not an enforcement
    # point, so there is one lookup path per field and no either-owner branch.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # PAN-SAS-005's assertion. TRUE fires, and true is the stored default: an appliance whose
    # engine nobody has asked about has no working engine anybody has established.
    "ace_not_operational": build_boolean_compiler(
        "ace_not_operational", "ace_not_operational"),
    # The applicability gate, read as a negated equality. See the module docstring.
    "ace_failure_reason": build_text_compiler("ace_failure_reason", "ace_failure_reason"),
    # The companion that answers "is this unknown", for the nullable column beside it.
    "cloudapp_node_read": build_boolean_compiler("cloudapp_node_read", "cloudapp_node_read"),
    # NULLABLE. Clause on `cloudapp_node_read` beside any comparison written here, and read the
    # module docstring first: nothing in `saas-security` clauses on this.
    "ace_disabled": build_boolean_compiler("ace_disabled", "ace_disabled"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_cloud_app_engine_setting_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_cloud_app_engine_setting_search_node(c) for c in group["clauses"]]
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
