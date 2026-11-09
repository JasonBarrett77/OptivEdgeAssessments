"""Canonical search compiler for one agent client-settings row of one GlobalProtect gateway.
PAN-GPG-003, PAN-GPG-004.

TWO CONTROLS, ONE MODEL, ONE TYPE. PAN-GPG-003 asserts over the reconnection cookie - how long it
is accepted for, and whether the certificate that encrypts it is named - and PAN-GPG-004 over the
inventory of paths leaving the tunnel uninspected. They share a `control_type`, a finding model and
a generator, and their findings are told apart by the `control` foreign key alone. That is what
`finding_registry.KIND_BY_MODEL` requires: a finding model may appear in `FINDING_KINDS` exactly
once.

NO ROW OF THIS MODEL EXISTS IN THE MEASURED ESTATE, and this is the model where that costs most.
The collection exists only nested inside a gateway entry and no gateway exists anywhere, so stage 7
proved all eighteen content columns against constructed shapes - nineteen tests asserting VALUES,
then a five-break mutation pass of which four were caught - and nothing here has a device reading.
Stage 7's own sentence for this stage is the one to carry: **the two columns that SUPPRESS on their
default, `accept_cookie_configured` and `authentication_override_configured`, have no device
instance of either branch.**

AND THAT MATTERS BECAUSE BOTH ARE APPLICABILITY CLAUSES. An applicability clause that is false
drops the row out of its control SILENTLY - no finding, no message, nothing distinguishing it from
a compliant row - so the two switches that decide whether PAN-GPG-003 looks at a row at all are
exactly the two whose behavior no device reading confirms. A reader of a PAN-GPG-003 finding
should know that the control's population rests on them.

THE COOKIE LIFETIME IS ONE INTEGER CONVERTED FROM THREE UNIT BRANCHES, and the conversion is the
reason the clause can be a comparison at all. The device accepts minutes, hours or days;
`cookie_lifetime_hours` is the single converted span the grading compares, `cookie_lifetime_unit`
and `cookie_lifetime_as_entered` carry what the administrator actually typed, and a remediation
names those rather than the converted number. The unit column is 24 characters and not stage 5's
declared 16: two of its own three declared values are 17 and 19 characters long, and at the
declared width SQLite truncated them with no error. Stage 7 found that and widened the column.

`cookie_lifetime_hours` IS `null=True` AND FOR AN INTEGER THAT IS SAFE IN A WAY IT IS NOT FOR
TEXT. The integer builder offers comparisons only, so there is no operator a NULL could have
satisfied and then stopped satisfying. What the null MEANS is that a row accepting a reconnection
cookie with no lifetime in any of the three branches PASSES `gt 24` in silence, which stage 3 calls
out in terms: an absent value in all three branches "reads as nobody having looked and fires, and
it must not be graded as acceptable". `cookie_lifetime_known` is the only thing in this language
that reaches those rows.

`cookie_encrypt_decrypt_cert` IS `CharField(null=True, blank=True)` AND PAN-GPG-003[1] CLAUSES
`is empty` ON IT - WHICH IS WHY THE `is_empty` ARM BELOW ORS AN `__isnull` TERM. This is the single
decision in this file a later reader is most likely to get wrong, so it is argued rather than
stated. Two shapes of that arm exist side by side in this repository:

* `search/management_ssh/compiler.py` and twelve others compile `is_empty` to
  `filter(field="")` and nothing else, so a `null=True` column is UNREACHABLE by the one operator
  written for absence.
* `search/security_profile/compiler.py` and the sibling portal client-auth compiler OR an
  `__isnull` term beside `field=""`, per lookup path.

The absent certificate on this column stores NULL and not `""` - stage 7 wrote every optional key
absent as NULL rather than a guess, and tested it. With the first shape, stage 5's `is empty`
clause would compile, pass every gate, and match NOTHING on the exact population it was written
for: a gateway accepting a cookie it cannot prove it can decrypt would report as compliant. So this
compiler takes the second shape. The generalisation worth keeping is narrower than either: READ THE
ARM IN THE COMPILER YOU ARE REGISTERING INTO, because both shapes ship here.

`uninspected_egress_path_count` IS THE ONE QUERYABLE READING OF SIX JSON COLUMNS, and none of the
six is registered. A JSONField may not be registered at all -
`test_findings_rest_on_columns` compiles every registered field and walks the resulting query tree
for a JSONField reference, failing rather than skipping - so the shipped instruction is to register
the scalar column that carries the reading beside it and say which JSON columns were left out. They
are `split_tunnel_exclude_access_routes`, `split_tunnel_include_access_routes`,
`split_tunnel_exclude_applications`, `split_tunnel_include_applications`,
`split_tunnel_exclude_domains` and `split_tunnel_include_domains`, and the integer aggregate over
them is what PAN-GPG-004 asserts on. The finding's own sentence prints the count.

AND THE COUNT'S HONEST EMPTY VALUE IS ZERO, WHICH IS ALSO ITS BEST VALUE. `default=0`,
`null=False`: a full tunnel with nothing excluded and a row the normalization pass never reached
store the same number, and zero is the most compliant state the field can hold. So without
`egress_inventory_computed` beside it an unprocessed row would report as the best configuration in
the estate. The two are different facts with different remediations - one says the posture is
documented, the other says no record of the decision exists - and stage 3 requires the finding's
wording to carry that distinction, which no column can.

TWO AXES OF THAT COUNT WERE NOT DECIDABLE FROM STAGE 5'S DECLARATION and stage 7 decided them,
which a reader of a PAN-GPG-004 finding is entitled to know: an include list of exactly `any` is
NOT counted, because it routes everything into the tunnel; and a NULL
`no_direct_access_to_local_network` IS counted, because the key's name is the negation of what it
permits, so an absence most likely leaves the endpoint's own network open - the firing direction
that column's `fires` reading requires. Both are in the normalizer's docstring and both are tested;
the second is mutation-confirmed.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import GlobalProtectGatewayAgentConfig

GLOBALPROTECT_GATEWAY_AGENT_CONFIG_MODEL = "integrations.GlobalProtectGatewayAgentConfig"

INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        # THE `__isnull` TERM IS LOAD-BEARING ON THIS MODEL, not decoration. See the module
        # docstring: `cookie_encrypt_decrypt_cert` is `null=True`, the absent certificate stores
        # NULL rather than `""`, and PAN-GPG-003[1]'s assertion clause is `is empty` on it.
        # Without this term that clause would match no row of the population it exists for.
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
        return GlobalProtectGatewayAgentConfig.objects.filter(
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
        return GlobalProtectGatewayAgentConfig.objects.filter(
            **{lookup_field: value}).values("pk")
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
        return GlobalProtectGatewayAgentConfig.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column as two fields. ON AN HA PAIR THE SAME ROW ARRIVES ON BOTH PEERS
    # and nothing deduplicates it; the serial is what tells the two apart.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    # The owning gateway's name, a path element from the xpath this row was read at rather than a
    # key on the row. Part of the row's identity: the row's own name is operator-chosen.
    "gateway_name": build_text_compiler("gateway_name", "gateway_name"),
    "row_name": build_text_compiler("row_name", "name"),

    # ------------------------------------------- PAN-GPG-003[0]: the cookie's accepted lifetime
    # PAN-GPG-003[0]'s APPLICABILITY clause, and it must appear in every query that record's
    # grading produces or a calibration fires on rows the baseline excluded. A gateway that never
    # accepts a reconnection cookie has nothing to bound, and stage 4 measured that absence as
    # SATISFYING the assertion. `default=False`, so this clause SUPPRESSES - and no device
    # instance of either branch exists; see the module docstring.
    "accept_cookie_configured": build_boolean_compiler(
        "accept_cookie_configured", "accept_cookie_configured"),
    # PAN-GPG-003[0]'s ASSERTION AND ITS GRADING COLUMN - the same column in both roles, which is
    # why the calibrations are bounded RANGES rather than open thresholds. The worst MATCHED
    # calibration wins and the baseline tier is discarded the moment one matches, so an open
    # `gt 24` carrying the gentler tier would capture every row the harsher band is for. Stage 5
    # states that requirement on the grading itself.
    "cookie_lifetime_hours": build_integer_compiler(
        "cookie_lifetime_hours", "cookie_lifetime_hours"),
    # What the administrator actually typed, and in which unit. Registered so a remediation names
    # the number on the screen rather than the converted one; no clause rests on either. The unit
    # column is 24 characters and not stage 5's declared 16 - see the module docstring.
    "cookie_lifetime_unit": build_text_compiler(
        "cookie_lifetime_unit", "cookie_lifetime_unit"),
    "cookie_lifetime_as_entered": build_integer_compiler(
        "cookie_lifetime_as_entered", "cookie_lifetime_as_entered"),
    # THE ONLY THING THAT REACHES A ROW WITH NO LIFETIME IN ANY OF THE THREE BRANCHES. There is no
    # is-null operator in this language and every integer operator compiles to a comparison a NULL
    # fails, so a row accepting a cookie it never bounded passes `gt 24` in silence without this.
    # Claused on by one query of PAN-GPG-003, at that record's own severity, alongside the
    # applicability clause above - stage 5's `undetermined` spells the pair out as a group.
    "cookie_lifetime_known": build_boolean_compiler(
        "cookie_lifetime_known", "cookie_lifetime_known"),

    # ------------------------------------------- PAN-GPG-003[1]: the certificate on the cookie
    # PAN-GPG-003[1]'s APPLICABILITY clause, and the WIDER of the two on purpose: the certificate
    # is a sibling of accept-cookie and serves both the generating and the accepting side, so a
    # row that only GENERATES a cookie still needs one. `default=False`, so this suppresses too.
    "authentication_override_configured": build_boolean_compiler(
        "authentication_override_configured", "authentication_override_configured"),
    # PAN-GPG-003[1]'s ASSERTION, claused `is empty`. `null=True`, the absent certificate stores
    # NULL, and the `is_empty` arm above ORs an `__isnull` term for exactly this - the single
    # decision in this file worth reading the docstring for.
    "cookie_encrypt_decrypt_cert": build_text_compiler(
        "cookie_encrypt_decrypt_cert", "cookie_encrypt_decrypt_cert"),
    # Whether this row generates a cookie as against merely accepting one. Registered for the
    # reader: the two sides share one certificate, so a finding that does not say which side this
    # row is on sends an engineer to the wrong half of the dialog.
    "generate_cookie": build_boolean_compiler("generate_cookie", "generate_cookie"),

    # ------------------------------------------ PAN-GPG-004: the uninspected egress inventory
    # PAN-GPG-004's ASSERTION, and the one queryable reading of six JSON columns none of which may
    # be registered. The aggregate counts PATHS and not entries; see the module docstring for the
    # two axes stage 7 had to decide and how it decided them.
    "uninspected_egress_path_count": build_integer_compiler(
        "uninspected_egress_path_count", "uninspected_egress_path_count"),
    # WHAT TELLS A COUNT OF ZERO THAT NOBODY COMPUTED FROM A FULL TUNNEL WITH NOTHING EXCLUDED.
    # The count's honest empty value is ZERO, which is also its best value, so an unprocessed row
    # would otherwise report the most compliant state available. Claused on by one query of
    # PAN-GPG-004 at that record's own severity.
    "egress_inventory_computed": build_boolean_compiler(
        "egress_inventory_computed", "egress_inventory_computed"),
    # The endpoint's OWN local network, which is one of the eight axes the count rolls up and the
    # one whose absence stage 7 had to rule on. Registered so a finding can name it: it is a
    # screen of its own rather than a member of any exclusion list, and an inventory built from
    # the lists alone reports a clean posture on a gateway leaving it wide open - which is stage
    # 3's own reason for this control existing.
    "no_direct_access_to_local_network": build_boolean_compiler(
        "no_direct_access_to_local_network", "no_direct_access_to_local_network"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_globalprotect_gateway_agent_config_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_globalprotect_gateway_agent_config_search_node(c)
                for c in group["clauses"]]
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
