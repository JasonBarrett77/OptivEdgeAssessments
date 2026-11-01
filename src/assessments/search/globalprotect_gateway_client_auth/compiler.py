"""Canonical search compiler for one row of one GlobalProtect gateway's client-authentication
table. PAN-GPG-002.

NOT THE PORTAL'S CLIENT-AUTH TABLE, and the check is for the NODE rather than the leaf name.
`client-auth` is a leaf both GlobalProtect objects carry under different parents:
`search/globalprotect_portal_client_auth/compiler.py` beside this one reads
`global-protect-portal/entry/portal-config/client-auth`, and this one reads the collection nested
inside a GATEWAY entry. The two models are not interchangeable and neither are their normalisers.

NO ROW OF THIS MODEL EXISTS IN THE MEASURED ESTATE. The collection exists only nested inside a
gateway entry and no gateway exists anywhere - the merged payload carries no
`global-protect-gateway` key under any of the twelve virtual systems of the four appliances, and
`action=show` raises `No such node` at that xpath on all twelve. So every field below compiles and
not one has been shown to match.

THE ROW IS THE SUBJECT AND THE GATEWAY IS NOT. The table is keyed by the client OPERATING SYSTEM -
eleven measured values, `Any` among them as a real value rather than a wildcard the store invents -
so one gateway can point a Windows row at a strong identity service and an `Any` row at the
firewall's own local database. A gateway-grain verdict would fire the parent for one child's fault,
could not say which platform to repoint, and would show the compliant row beside the failing one.
That is exactly the to-many DOWNWARD walk standing ruling 6 refuses.

THE WALK RULING 6 DOES PERMIT IS THE ONE THIS MODEL CARRIES, AND IT IS NULLABLE - WHICH IS THE
THING TO KNOW ABOUT THIS FILE. PAN-GPG-002 has TWO assertion records over TWO models: the row's own
`backend_can_deliver_a_second_factor`, and the gateway-wide
`client_certificate_is_a_second_factor`. A control has ONE `target_model` and `ControlQuery.clean()`
refuses a query on any other, so one of the two halves has to be reached by a relation or go
silent. Measured 2026-11-01 with `probe.relation_between GlobalProtectGatewayClientAuth
GlobalProtectGateway`:

    integrations.GlobalProtectGatewayClientAuth -one-> gateway[forward null=True]
    integrations.GlobalProtectGateway

To-ONE and UPWARD, which is the shape ruling 6 describes and all three of its own examples take,
with the same five scope fields on both sides. So the gateway half IS reachable, as
`gateway_client_certificate_is_a_second_factor` below, and the row's grain survives the join.

**BUT THE FK IS `null=True`, SO THE WALK CANNOT REACH A ROW WHOSE GATEWAY DID NOT RESOLVE.** On
those rows the gateway half is SILENT - not on the population, on exactly those rows - and nothing
in this repository will say so. A positive clause through a null join matches nothing, the control
goes on reporting its other half, and the row reads as though the gateway question had been asked
and answered. The stage 8 artifact names it and `needs_human` carries it, because no count
anywhere says it. The honest reading of `gateway_name` beside it is that a row has the parent's NAME
even where the FK is null - the name is a path element from the xpath this row was read at - so the
name is present and the join is not, which is a distinction a reader of a finding needs.

THE VENDOR'S OWN SWITCH IS REGISTERED AND READS BACKWARDS, the same trap the portal's table carries.
`user_credential_or_client_cert_required` true means a password OR a client certificate will do,
which is the PERMISSIVE state. No control clauses on it here - the derived
`backend_can_deliver_a_second_factor` is what PAN-GPG-002 asserts - and it is registered so a
finding can colour the cell that actually failed.

`client_os` IS AN APPLICABILITY CLAUSE AND NOT AN ASSERTION, which is why asserting on it would
colour the wrong cell. Stage 5 gives it `role: applicability` with the value `X-Auth` negated: rows
serving third-party clients through extended authentication are a different admission path the
vendor documents separately. It appears in EVERY query of this control - a rank query missing an
applicability clause widens the control onto objects that never qualified - and it appears in
`asserted_fields` of none of them.

AND A QUERY HERE CANNOT SAY WHETHER THE IDENTITY SERVICE ENFORCES A SECOND FACTOR. The firewall
records WHICH service it asks and never what that service demands, so stage 3's acceptable minimum
is not a value of any column and stage 5 placed no rank for it. `authentication_backend_method` is
resolved through the row's own `authentication-profile` name onto another model's row - and note
that the shipped column there is `method` and NOT the `backend_method` stage 5's `columns` dict
names; stage 7 declined that second column as `column_should_not_exist` and the resolution reads
`method`. It also cannot tell a profile from a SEQUENCE, whose last member may be the firewall's
own local user database.

NO JSONField IS REGISTERED AND NONE EXISTS ON THIS MODEL. `test_findings_rest_on_columns` compiles
every registered field with every operator it advertises, walks the query tree for a JSONField
reference, and treats a field accepting none of its probe values as a failure rather than a skip -
which the two builders below satisfy.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import GlobalProtectGatewayClientAuth

GLOBALPROTECT_GATEWAY_CLIENT_AUTH_MODEL = "integrations.GlobalProtectGatewayClientAuth"


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
        return GlobalProtectGatewayClientAuth.objects.filter(
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
        return GlobalProtectGatewayClientAuth.objects.filter(
            **{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column as two fields. ON AN HA PAIR THE SAME ROW ARRIVES ON BOTH
    # PEERS, so this subject yields two rows for one real configuration and the serial is what
    # tells them apart.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    # The owning gateway's name, from the xpath this row was read at - A PATH ELEMENT AND NOT A
    # KEY ON THIS ROW, so a predicate has no edge to walk a subtree up for it. PART OF THE ROW'S
    # IDENTITY: the row's own name is free text and two gateways of one vsys may use the same one.
    # It is present even where the `gateway` FK is NULL, which is the distinction the module
    # docstring ends on.
    "gateway_name": build_text_compiler("gateway_name", "gateway_name"),
    # The row's own entry name, which is what an engineer opens. Free text and NOT the operating
    # system - `client_os` below is what a reader goes by, and the finding's sentence names it.
    "row_name": build_text_compiler("row_name", "name"),

    # ------------------------------------------------------- PAN-GPG-002[0]: the row's own half
    # PAN-GPG-002's APPLICABILITY clause, carried in every query this control produces. `X-Auth`
    # is the third-party extended-authentication platform the control's own `applies_when`
    # excludes; the clause is written as a NEGATED equality on it. `cannot_be_unknown`, measured:
    # the device refuses to commit a row without this key, so a collected row always carries it.
    "client_os": build_text_compiler("client_os", "client_os"),
    # PAN-GPG-002[0]'s ASSERTION, and the only member of its baseline's `asserted_fields`.
    # Resolved at normalisation through the row's authentication-profile name onto that profile's
    # `method`, because the query grammar has no edge to walk. `default=False` is the FIRING side,
    # so a row nobody recomputed reports itself.
    "backend_can_deliver_a_second_factor": build_boolean_compiler(
        "backend_can_deliver_a_second_factor", "backend_can_deliver_a_second_factor"),
    # The name an engineer repoints and what it resolved to. Registered for the reader, not for a
    # clause. `authentication_backend_method` resolves through the shipped `method` column of
    # `integrations.AuthenticationProfile` - stage 7 declined stage 5's `backend_method` as a
    # SECOND column over one key - and it cannot tell a profile from a SEQUENCE.
    "authentication_profile_name": build_text_compiler(
        "authentication_profile_name", "authentication_profile_name"),
    "authentication_backend_method": build_text_compiler(
        "authentication_backend_method", "authentication_backend_method"),
    # THE VENDOR'S POLARITY, KEPT, AND IT READS BACKWARDS: true means a password OR a client
    # certificate will do, which is the permissive state. Registered so a finding can colour the
    # cell that failed; no control clauses on it. A reviewer who selects `true` believing they
    # have the hardened rows has selected exactly the permissive ones.
    "user_credential_or_client_cert_required": build_boolean_compiler(
        "user_credential_or_client_cert_required", "user_credential_or_client_cert_required"),

    # ------------------------------------- PAN-GPG-002[1]: the GATEWAY's half, reached by a walk
    # THE RELATION WALK STANDING RULING 6 PERMITS, AND THE ONLY REASON PAN-GPG-002'S SECOND
    # RECORD IS NOT SILENT. The column belongs to `integrations.GlobalProtectGateway`; the lookup
    # traverses the row's own `gateway` foreign key, which is to-ONE and UPWARD with the same five
    # scope fields on both sides. A walked lookup path is the same mechanism `hostname` above uses
    # for `appliance__hostname`, so this is a shipped convention rather than an invention here.
    #
    # IT IS `null=True` AND THAT IS THE LIMIT. A row whose gateway did not resolve is unreachable
    # by this field: the join yields nothing, a positive clause matches nothing, and the row reads
    # as though the gateway question had been asked. The stage 8 artifact records the half as
    # reached-but-partial and `needs_human` carries the per-row silence, because nothing in either
    # repository counts it.
    #
    # AND A STAGE 9 OBLIGATION RIDES ON THIS NAME. `artifacts/sheets/findings.py::tested_fields`
    # resolves every clause field against the SUBJECT model and raises `ValueError` for a name
    # that model "neither stores nor computes" - which takes the whole stored-table build down,
    # not one cell. This name is neither a field nor a property of
    # `GlobalProtectGatewayClientAuth`, so the findings sheet for this subject owes a
    # `value_readers` entry for it. That is stage 9's to add and it is named in the stage 8
    # artifact's `needs_human` so it is not discovered as a build failure.
    "gateway_client_certificate_is_a_second_factor": build_boolean_compiler(
        "gateway_client_certificate_is_a_second_factor",
        "gateway__client_certificate_is_a_second_factor"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_globalprotect_gateway_client_auth_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_globalprotect_gateway_client_auth_search_node(c)
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
