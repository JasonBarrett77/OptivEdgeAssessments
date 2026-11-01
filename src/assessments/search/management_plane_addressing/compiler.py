"""Canonical search compiler for one appliance's management-plane addressing. PAN-MGT-004.

Minted by stage 8 of `management-services` on 2026-11-01. One row per appliance; on an HA pair
two rows for two peers, which the integrations model records as a real difference rather than
duplication - the peers have different management addresses and are separately reachable.

ONE COLUMN IS REGISTERED AND FOUR ARE DELIBERATELY NOT, which is the whole of this file's
judgement. Stage 5 marks five of this subject's six columns `needs_compiler_field`:

    exposure_posture              PAN-MGT-004's assertion clause AND its grading axis  -> HERE
    allocation_mode               named by no clause, no grading and no undetermined    -> not
    management_ip_address         named by nothing, and see the paragraph below          -> not
    static_default_gateway        named by nothing                                       -> not
    address_is_globally_routable  named by nothing                                       -> not

A field earns its place by a control needing it - this repository's own compiler rule - and
registering the other four would ship a search surface no control asks for. They are accounted
for in the stage 8 artifact with `registered: false` rather than silently skipped.

AND TWO OF THE FOUR WOULD HAVE CARRIED THE NULL TRAP HAD THEY BEEN REGISTERED, which is the
reason not to register them casually. `management_ip_address` and `static_default_gateway` are
`CharField(null=True)`, and the integrations model says in terms that an `is_empty` clause
compiling to `filter(field="")` alone "would match nothing on exactly the appliances this column
is null on" - the two DHCP-addressed PA-VMs in this estate. A compiler written for them needs the
`__isnull=True` branch beside the empty-string one. Nothing needs them today, so the trap is
avoided by not building rather than by getting it right.

`exposure_posture` IS NOT NULLABLE AND HAS NO EMPTY STATE. It is
`CharField(max_length=32, choices=POSTURE_CHOICES, default=POSTURE_ROUTABLE)` - the default being
the WORST class, so a row nobody has recomputed fires - so `eq` over the four posture tokens
reaches every state the column can hold and `is_empty` would reach none of them. The text
compiler's `is_empty` arm is therefore registered and unreachable rather than absent, which is
the same shape every other scalar-text field in this repository carries.

PAN-MGT-004's CLAUSE IS A NEGATED EQUALITY, not a three-way OR. Stage 5 writes the assertion as
`exposure_posture is not private_no_default_route`, and `_compile_clause` below applies the
clause's own `negated` flag as `~predicate` - so one clause reaches the three firing classes and
stays correct if a fifth posture class is ever added. A stored OR over the three would silently
stop covering a new class, which is the defect shape `SslTlsServiceProfile.min_version_rank`
exists to prevent one model over.

THIS MODEL IS NOT A REMEDIATION TARGET and this compiler does not make it one. Jason's standing
restriction: no change to a management IP address or to management-plane routing is to be
proposed or implied. The columns exist so a finding can PRINT the value an assessor goes and
looks at; `hostname` and `serial_number` are registered so they can find the appliance.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import ManagementPlaneAddressing

MANAGEMENT_PLANE_ADDRESSING_MODEL = "integrations.ManagementPlaneAddressing"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return ManagementPlaneAddressing.objects.filter(
                **{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains",
                  "starts_with": "istartswith", "ends_with": "iendswith"}.get(op, "iexact")
        return ManagementPlaneAddressing.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    #: PAN-MGT-004's assertion clause and its grading axis. The configuration's CONTRIBUTION to
    #: the management plane's exposure, as one of four classes - not a statement that the plane
    #: is reachable, which the firewall holds nothing about.
    "exposure_posture": build_text_compiler("exposure_posture", "exposure_posture"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_management_plane_addressing_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_management_plane_addressing_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(
            f"Unsupported search field for {MANAGEMENT_PLANE_ADDRESSING_MODEL}: "
            f"{clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause.get("negated") else predicate
