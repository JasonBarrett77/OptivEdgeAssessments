"""Canonical search compiler for one appliance's high-availability configuration.

PAN-HAP-001 to 004. ONE ROW PER APPLIANCE: `deviceconfig/high-availability` is device-wide, so
there is no vsys axis and no shared-versus-vsys precedence. On an HA pair the same real
relationship yields TWO rows and they are NOT expected to agree - `group/mode` is present on one
member of this lab's pair and absent on the other, measured by stage 4 of the `ha-panorama`
pipeline domain - so a query here reports per appliance and never per pair.

WHAT IS REACHABLE FROM HERE IS THE VERDICT AND THE BAND, NEVER THE RAW KEY. Every one of this
model's four controls rests on a derived boolean whose TRUE is both the finding side and the
migration default, plus a classification column for the severity. That is not a workaround for a
missing operator in three of the four cases, it is the only correct reading:

* `no_live_redundant_peer` spans a configuration switch and an operational reply
  (`show high-availability all`), and no clause can join those.
* `ha_monitors_nothing` needs a COUNT over a child collection - and the two monitoring enables
  it replaces read `yes` when their keys are ABSENT, so a query over `link_monitoring_enabled`
  would pass every unconfigured appliance in an estate. Stage 4 measured that default directly.
* `no_independent_second_keepalive_path` compares the backup link's port and subnet AGAINST the
  primary's, which is a field-to-field comparison this query language does not have.

THE NULLABLE COLUMNS ARE DELIBERATELY NOT REGISTERED, and the omission is the point. Five
booleans on this model are `null=True` - `cluster_participation_enabled`, `config_sync_enabled`,
`state_sync_enabled`, `ha1_encryption_enabled`, `ha1_encryption_key_imported` - and there is no
is-null operator in this language, so a clause over one of them PASSES every appliance nobody
read. The verdicts above fold them in at normalization with the firing direction preserved, and
`ha_config_collected` / `ha_runtime_state_collected` are the registered booleans that answer
"nobody looked". A later run that wants one of those five reachable owes a `*_known` companion
first.

`monitored_link_groups` IS A JSONField and is absent from here for the rule's own sake:
`tests/test_findings_rest_on_columns.py` walks every registered field and refuses one that
reaches a JSON column. `monitored_link_group_count` is not registered either, because stage 4
measured that a link group carrying NO interface is valid configuration `validate full` accepts -
so a positive count does not mean anything is monitored, and `ha_monitors_nothing` is the column
that already knows that.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import HighAvailabilityConfig

HIGH_AVAILABILITY_CONFIG_MODEL = "integrations.HighAvailabilityConfig"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return HighAvailabilityConfig.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return HighAvailabilityConfig.objects.filter(
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
        return HighAvailabilityConfig.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # The appliance a finding names. One stage 5 column - `appliance` - and TWO fields, which is
    # what every shipped compiler does: a reader recognises the hostname and only the serial is
    # unique across an estate that renames its appliances.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # THE COLUMNS THAT ANSWER "NOBODY LOOKED". False is the firing side and the migration
    # default, so a row nobody has recomputed reports itself as uncollected rather than as
    # collected-and-fine. These carry the companion query every HA control needs, because the
    # applicability clause `ha_enabled eq true` cannot match an uncollected row.
    "ha_config_collected": build_boolean_compiler(
        "ha_config_collected", "ha_config_collected"),
    "ha_runtime_state_collected": build_boolean_compiler(
        "ha_runtime_state_collected", "ha_runtime_state_collected"),
    # The applicability column for PAN-HAP-002, 003 and 004. Non-nullable with default False, so
    # `eq true` narrows the three controls to appliances the configuration says are in a pair.
    "ha_enabled": build_boolean_compiler("ha_enabled", "ha_enabled"),
    # The four verdicts. TRUE is the finding side AND the migration default on every one.
    "no_live_redundant_peer": build_boolean_compiler(
        "no_live_redundant_peer", "no_live_redundant_peer"),
    "ha_monitors_nothing": build_boolean_compiler(
        "ha_monitors_nothing", "ha_monitors_nothing"),
    "no_independent_second_keepalive_path": build_boolean_compiler(
        "no_independent_second_keepalive_path", "no_independent_second_keepalive_path"),
    "ha1_control_link_not_encrypted": build_boolean_compiler(
        "ha1_control_link_not_encrypted", "ha1_control_link_not_encrypted"),
    # The three classification columns a CALIBRATION query compares on; an assertion never does.
    # Each one's members are mutually exclusive by construction, so two band queries cannot match
    # one row - which is what makes a band at the baseline tier safely queryless.
    "ha_monitoring_state": build_text_compiler("ha_monitoring_state", "ha_monitoring_state"),
    "second_keepalive_path_state": build_text_compiler(
        "second_keepalive_path_state", "second_keepalive_path_state"),
    "ha1_control_link_exposure": build_text_compiler(
        "ha1_control_link_exposure", "ha1_control_link_exposure"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_high_availability_config_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_high_availability_config_search_node(c) for c in group["clauses"]]
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
