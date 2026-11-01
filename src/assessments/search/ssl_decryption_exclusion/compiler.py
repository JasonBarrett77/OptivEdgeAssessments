"""Canonical search compiler for one SSL decryption exclusion the organisation added. PAN-DEC-004.

ONE ROW PER NAMED EXCLUSION WITHIN ONE SCOPE OF ONE APPLIANCE. The model inherits
`ApplianceScopedObject`, so the appliance is a DIRECT foreign key and the lookups need no
either-owner branch - unlike the two enforcement-point-owned compilers beside this one. The vsys is
a property of where the definition sits rather than a second owner, which is why `vsys_name` is a
string here and is blank on a shared-scoped entry.

BOTH WRITABLE SCOPES ARE ONE MODEL AND TWO ROWS, and the uniqueness constraint says so:
`(appliance, scope, vsys_name, name)`. A collector reading only the vsys scope would report no
exclusions on a firewall whose operator added them through the interface, because PAN-OS puts that
screen at the appliance's own shared container. Stage 6 built one entry at each scope on one
appliance for exactly that reason, and both fire.

WHAT THIS MODEL DOES NOT HOLD IS THE VENDOR'S 330 OR 385 ENTRIES. They live at
`/config/predefined/ssl-exclude-cert`, are a separate object, and are invisible to the read this
model normalizes - while the web interface renders BOTH collections in ONE grid distinguished only
by a Location column. So a query here reaches the organisation's own exclusions and nothing else,
which is what PAN-DEC-004's first record asserts over and is the reason `locally added` needs no
clause: it is what the subject IS.

`exclusion_name` IS THE FIELD NAME AND `name` IS THE COLUMN. Stage 5 calls the identity column
`exclusion_name` and OEI carries it as a `@property` over the base class's `name` for the stated
reason that `artifacts/sheets/findings.py::tested_fields` resolves a tested field against the
subject model and raises for a name the model can neither store nor compute. Registering stage 5's
spelling keeps the two vocabularies in step; the lookup underneath is the stored column.

`exclude` IS STORED, IS MARKED `needs_compiler_field` BY STAGE 5, AND IS DELIBERATELY NOT
REGISTERED. No clause, grading or `undetermined` of this domain names it, and stage 5 says in terms
why: an entry somebody switched off is still an entry somebody should be able to account for, so the
assertion rests on the reason text and not on the enable switch. Registering it would make the
narrowing one clause away - and that narrowing is live rather than hypothetical, because
`oep-dec6-x02` on the lab is switched OFF and carries no reason, and stage 6 expects it to fire.

`is_empty` IS THE BARE `field=""` SHAPE AND IT IS CORRECT. `description` is
`TextField(blank=True, default="")` and never nullable, which OEI's own model docstring records as
chosen because the search layer has no is-null operator; the absent key is stored as the empty
string, so the bare filter reaches exactly the population PAN-DEC-004's clause was written for. The
`hostname` and `serial_number` paths are through a NON-NULLABLE appliance FK, so they need no
`__isnull` branch either - the one place in this domain where that is true.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import SslDecryptionExclusion

SSL_DECRYPTION_EXCLUSION_MODEL = "integrations.SslDecryptionExclusion"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return SslDecryptionExclusion.objects.filter(
                **{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return SslDecryptionExclusion.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column: one column, two fields. The appliance FK is direct here.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # Stage 5's remaining identity columns. `scope` and `vsys_name` together say WHERE an operator
    # removes the entry, and the constraint keys on both: the same server name may be excluded in a
    # vsys and in the appliance's own shared container, and those are two different entries.
    "scope": build_text_compiler("scope", "scope"),
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    # Stage 5's `exclusion_name`, over the base class's stored `name`. See the module docstring.
    "exclusion_name": build_text_compiler("exclusion_name", "name"),
    # PAN-DEC-004's ONE CLAUSE, written on the firing side because `is_empty` exists and its
    # negation does not - which happens to be the side the assertion wants. The only place on the
    # entry that can say which application it protects and when it is next due to be rechecked, and
    # the device checks neither.
    "description": build_text_compiler("description", "description"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_ssl_decryption_exclusion_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_ssl_decryption_exclusion_search_node(c) for c in group["clauses"]]
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
