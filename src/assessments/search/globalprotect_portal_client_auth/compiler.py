"""Canonical search compiler for one row of one GlobalProtect portal's client-authentication
table. PAN-GPP-002.

THE ROW IS THE SUBJECT AND THE PORTAL IS NOT, and this is the compiler that makes that grain
queryable. The table is KEYED BY THE ENDPOINT CLASS it serves - `Any`, `Browser`, `Satellite`, or
one of eleven per-platform names the leaf also references - so one portal can demand both factors
of one class and neither of another. Measured on this estate: two rows of ONE portal on pan-fw-111
sit at `high` and at `no_finding`. A control at the portal grain would fire the parent for one
child's fault, could not say which class was weak, and would report the compliant sibling beside
it - which is exactly the to-many DOWNWARD relation walk standing ruling 6 refuses.

THE WALK THAT RULING 6 DOES PERMIT IS THE ONE THIS MODEL ALREADY CARRIES, and it is why one
severity separates two rows whose own switch value is identical. `certificate_profile_bound` is
the PARENT PORTAL'S fact - whether `portal-config/certificate-profile` binds anything at all -
written onto the row at normalization. The row's `portal` FK is to-ONE and UPWARD, so the row's
grain survives the join; the reverse accessor `client_auth_rows` is the direction that does not.

`admission_demand` IS ONE COLUMN AND NOT A PREDICATE OVER TWO, which is a stage 5 decision this
compiler only has to respect. The failing condition is a DISJUNCTION - no certificate profile
bound, OR one bound with a permissive and/or switch - and a control query's clause list is one
conjunction with no OR, so two clauses would fire only where both held. The derived column is that
disjunction, resolved from the pair together, and it is both PAN-GPP-002's assertion and its
grading column.

THE VENDOR'S POLARITY IS KEPT ON `user_credential_or_client_cert_required` AND IT READS BACKWARDS.
`yes` means a password OR a client certificate will do, which is the PERMISSIVE state; `no` means
both are required, which is the hardened one - the device's own help string spells it `No (User
Credentials AND Client Certificate Required)`. A reviewer who clauses `equals yes` believing they
have selected the hardened rows has selected exactly the permissive ones. No control clauses on it
here; it is registered so the finding can color the cell that actually failed, which is the same
reason `data_filtering_posture` registers the two parts of its conjunction.

WHAT NO QUERY ON THIS MODEL CAN REACH. Whether the first factor is an authentication PROFILE or an
authentication SEQUENCE - two different objects, both shipped downstream - and stage 5's
`not_stored` says this column cannot tell them apart. A sequence is tried member by member until
one succeeds, so a portal bound to one whose last member is the firewall's own local user database
accepts a locally held password whenever the identity service is unreachable. That is stage 3's
fallback-path assertion and it is unexpressed rather than satisfied.

AND THE WEAKEST ADMISSION STATE THE DEVICE PERMITS PRODUCES NO ROW HERE AT ALL: a portal with an
empty authentication table demands nothing of anybody. `GlobalProtectPortal.client_auth_row_count`
is the only column anywhere that can see it, and a control's queries all compile against ONE
model, so no query of PAN-GPP-002 can reach it. Stage 7 recorded that as surplus and built the
column anyway; stage 5's reason for carrying it stands.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import GlobalProtectPortalClientAuthRow

GLOBALPROTECT_PORTAL_CLIENT_AUTH_MODEL = "integrations.GlobalProtectPortalClientAuthRow"


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
        return GlobalProtectPortalClientAuthRow.objects.filter(
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
        return GlobalProtectPortalClientAuthRow.objects.filter(
            **{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column, as two fields. `appliance` is non-nullable on this model, so
    # there is no appliance-group fallback. ON AN HA PAIR THE SAME ROW ARRIVES ON BOTH PEERS, so
    # this subject yields two rows for one real configuration and nothing deduplicates them -
    # stage 5 records it and the serial is what tells the two apart.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    # The owning portal's name. PART OF THE ROW'S IDENTITY and not only a convenience: `name`
    # alone is not unique within a vsys, because two portals of one vsys routinely use the same
    # row name - measured, four portals of vsys4 each carrying a row called `r1`.
    "portal_name": build_text_compiler("portal_name", "portal_name"),
    # The row's own name, which is what an engineer opens. OPERATOR-CHOSEN and carrying no
    # meaning, measured - `os` below is what a reader goes by.
    "row_name": build_text_compiler("row_name", "name"),
    # Which class of endpoint this row applies to. Registered because it is what the finding has
    # to print for a reader to know WHICH class is weak - the whole reason this grain exists. No
    # `choices` on the column: the leaf also references a predefined list of eleven per-platform
    # names, so it can hold a value the three generic buckets do not list.
    "os": build_text_compiler("os", "os"),
    # PAN-GPP-002's assertion AND its grading column. Four placements; `password_and_certificate`
    # is the only compliant one in this estate.
    "admission_demand": build_text_compiler("admission_demand", "admission_demand"),
    # The two inputs the derived verdict above resolves from, registered so a finding can colour
    # the cell that failed rather than the verdict alone - a reader cannot otherwise tell "no
    # certificate profile is bound at all" from "one is bound and the switch is permissive", and
    # those are two different remediations on two different objects.
    "certificate_profile_bound": build_boolean_compiler(
        "certificate_profile_bound", "certificate_profile_bound"),
    # NULLABLE, because the key is OPTIONAL on a committed row and its MEANING when absent is not
    # measured - the two candidate answers are the two ENDS of the grading. The text compiler's
    # `is_empty` arm ORs an `__isnull` term, which is the only way this language reaches a null.
    "user_credential_or_client_cert_required": build_text_compiler(
        "user_credential_or_client_cert_required", "user_credential_or_client_cert_required"),
    # The NAME this row binds as its first factor - what an engineer repoints. It cannot say
    # whether that name is a profile or a sequence; see the module docstring.
    "authentication_profile": build_text_compiler(
        "authentication_profile", "authentication_profile"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_globalprotect_portal_client_auth_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_globalprotect_portal_client_auth_search_node(c)
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
