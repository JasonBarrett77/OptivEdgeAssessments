"""Canonical search compiler for one named IPSec crypto profile. PAN-IPS-001 to 005, and 009.

PHASE 2. The sibling `search/ike_crypto_profile` is phase 1, at the adjacent xpath
`network/ike/crypto-profiles/ike-crypto-profiles`, and this one is
`network/ike/crypto-profiles/ipsec-crypto-profiles`. Four near-identical class names span the
two phases and registering a field against the wrong model is the trap - checked here against
`integrations.IpsecCryptoProfile` and nothing else.

One row per named entry per appliance, device-wide: the collection sits under `network`, so it
is neither vsys nor shared and there is exactly one of it for the whole appliance even on the
multi-vsys PA-5220 - measured by stage 4 of the `ipsec-crypto` domain. So there is no vsys axis,
no shared-versus-vsys precedence, and no `scope` or `vsys_name` field to register.

ONLY THE COLUMNS A CONTROL ASKS FOR ARE HERE, which is the repo's rule and is why the list is
shorter than the model. `lifetime_unit` is a stored, searchable column that NO clause and NO
grading of this domain names - a reader is told the unit by the finding's own sentence, which is
stage 9's business - so registering it would ship a search surface no control asks for.

THE THREE ALGORITHM LISTS ARE DELIBERATELY UNREACHABLE FROM HERE. `esp_encryption`,
`esp_authentication` and `ah_authentication` are JSONFields, stage 5 marks them
`not_searchable`, and `test_findings_rest_on_columns` refuses a registered JSONField outright.
What a control reads is the `weakest_*` member beside each list and the verdict column over the
whole set - which is also the right reading rather than a workaround, because the profile OFFERS
every member and a peer can negotiate down to the weakest one however the list is ordered.

`is_empty` IS THE BARE `field=""` SHAPE HERE AND THAT IS CORRECT, not the majority defect.
Measured across all 58 shipped compilers, 35 compile `is_empty` to `filter(field="")` alone and
22 OR an `__isnull=True` branch beside it; the bare shape silently matches nothing wherever the
absent case is stored as NULL. It is safe here because EVERY text column registered below is
`null=False` with an empty-string default or an always-written value - `protocol_branch`,
`weakest_encryption_offered` and `weakest_integrity_offered` carry `default=""`, and `dh_group`
is written on every row - so there is no NULL for the bare filter to miss. No clause in this
domain reaches for it anyway: not one placement anywhere in the five gradings is the empty
string.

ONE NULLABLE INTEGER, AND NO OPERATOR HERE REACHES A NULL. `lifetime_hours` is
`null=True`, and SQL answers every positive comparison over a NULL with no match, so a band
written over it cannot reach a row whose lifetime was never recomputed. That is safe for a
reason stage 4 measured rather than assumed: `lifetime` is the ONE unconditionally mandatory key
of this object - commit job 496 refused a key-less profile - so a committed profile always
carries it, and stage 5 declares the column `cannot_be_unknown` on that ground. The column is
nullable and the configuration cannot omit it; the two facts are not in conflict. And a row
nobody recomputed is still REPORTED rather than silent, because `lifetime_within_target` is
`default=False` and the baseline clause rests on that.

AND THE HOURS ARE ROUNDED UP. Stage 7 settled the direction nothing in stage 5 stated: a
90-minute lifetime is 2 hours and not 1, which `minimum: 1` forces for the sub-hour case and
which is the firing direction. Every band below assumes it.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import IpsecCryptoProfile

IPSEC_CRYPTO_PROFILE_MODEL = "integrations.IpsecCryptoProfile"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return IpsecCryptoProfile.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return IpsecCryptoProfile.objects.filter(
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
        return IpsecCryptoProfile.objects.filter(**{lookup_field: value}).values("pk")
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
        return IpsecCryptoProfile.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # The identity surface. `hostname` AND `serial_number` both serve stage 5's single
    # `appliance` column, which is what every shipped compiler does: a reader recognises the
    # hostname and only the serial is guaranteed unique across an estate.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "profile_name": build_text_compiler("profile_name", "profile_name"),
    # The graded columns. A severity query compares on these; an assertion never does.
    # `protocol_branch` is the one exception and is BOTH - PAN-IPS-001 clauses on it and grades
    # on it, because which branch a profile carries is the whole of what that control asserts.
    "protocol_branch": build_text_compiler("protocol_branch", "protocol_branch"),
    "weakest_encryption_offered": build_text_compiler(
        "weakest_encryption_offered", "weakest_encryption_offered"),
    # PAN-IPS-003 GRADES ON THIS AND CLAUSES ON NEITHER OF ITS OWN CLAUSE COLUMNS, so it is
    # registered on grading grounds alone. Its `when_unknown.reads_as` is `passes`, and that is
    # safe only because the assertion sits on `integrity_meets_sha2_floor` beside it: a row
    # nobody recomputed holds "" here, matches no band, and reports at the baseline severity.
    "weakest_integrity_offered": build_text_compiler(
        "weakest_integrity_offered", "weakest_integrity_offered"),
    "dh_group": build_text_compiler("dh_group", "dh_group"),
    # The verdict columns. Each one's FALSE is the finding side and is also the migration
    # default, so a profile nobody has recomputed is reported rather than passing.
    #
    # `all_offered_ciphers_authenticate` IS THE ODD ONE AND ITS FALSE IS THE APPLICABLE SIDE
    # rather than the finding side: PAN-IPS-003 clauses on it as APPLICABILITY, so false keeps
    # the control applicable and lets the assertion decide. An unread value reading `true` would
    # exclude every row from the control and the report would say nothing at all.
    "all_offered_ciphers_authenticate": build_boolean_compiler(
        "all_offered_ciphers_authenticate", "all_offered_ciphers_authenticate"),
    "integrity_meets_sha2_floor": build_boolean_compiler(
        "integrity_meets_sha2_floor", "integrity_meets_sha2_floor"),
    "dh_group_meets_target": build_boolean_compiler(
        "dh_group_meets_target", "dh_group_meets_target"),
    "lifetime_within_target": build_boolean_compiler(
        "lifetime_within_target", "lifetime_within_target"),
    # The nullable integer, and the integer that is not. `referencing_tunnel_count` is
    # `default=0` and non-nullable, so `eq 0` reaches every row it should; `lifetime_hours` is
    # nullable and the module docstring says why that is safe here.
    "lifetime_hours": build_integer_compiler("lifetime_hours", "lifetime_hours"),
    "referencing_tunnel_count": build_integer_compiler(
        "referencing_tunnel_count", "referencing_tunnel_count"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_ipsec_crypto_profile_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_ipsec_crypto_profile_search_node(c) for c in group["clauses"]]
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
