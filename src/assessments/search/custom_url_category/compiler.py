"""Canonical search compiler for custom URL categories. PAN-URL-006.

A custom URL category is the named list a URL filtering profile's action list, a profile's
inline-analysis exemption list or a policy rule's category member points at. This control asserts
REFERENCE HYGIENE over it: a category nothing points at is a permissive configuration already
written, already reviewed and no longer watched.

`is_used` IS THE ASSERTION AND `category_type` IS THE GRADING, and the two answer different
questions about the same row. The reference walk decides whether anything points at the category;
the stored type decides how much reach an unreferenced one already has. Stage 3 grades the second
because a `Category Match` target needs no entries added to it to have reach, while a `URL List`
is as broad as whoever last typed into it and no broader.

`category_type` IS A TEXT COMPILER AND NOT A CHOICE COMPILER, and that is the one decision in
this module worth reading. The column is `CharField(blank=True, default="", choices=["URL List",
"Category Match"])` - so the EMPTY STRING is a reachable value that the column's own `choices` do
not list, which is exactly the shape a closed-choice builder cannot serve: it rejects every value
its choices omit, so it could express no query at all for the unread state. The empty string is
reachable because the type key is MANDATORY AT COMMIT VALIDATION on the device - three commits on
two platforms established that, `Validation Error: ... is missing 'type'` - so a row holding "" is
never a device state; it is a row written before the recompute, or one whose entry came from a
view that carried no type leaf. The cost of the text builder has to be stated rather than
discovered: a MISSPELLED value in a catalog payload compiles against a text field and matches
nothing, where the raising form would have refused it. What limits the damage here is the shape
the control takes anyway - the baseline asserts `is_used eq false` and carries no type clause, so
a misspelled calibration loses a RANK and never a finding.

THE REFERENCE WALK'S OWN DENOMINATOR IS NOT A QUERYABLE COLUMN, and a reader of these fields has
to know it. `reference_surfaces_searched` records which surfaces the walk actually read, and it is
a JSONField: stage 5 marks it `not_searchable` and the convention in this repository is that a
JSONField is not registered. What carries the reading for a QUERY is `referrer_count` - the scalar
beside it - and what carries it for a READER is stage 9's business. The gap it records is real and
measured: the vendor documents four rulebases that can match on a URL category, the project's
normalizer collects two, and stage 2's uncapped referrer enumeration found 39 referrer fields
where a capped ask gives 8. So every error this control makes is in the direction of calling a
LIVE category unreferenced, which is why its deliverable is a list of candidates for review and
never a removal instruction.

A category belongs to an enforcement point (vsys scope) or to an appliance group (shared scope),
so `appliance_group` matches either path - the same shape as the security profile compiler, and
for the same reason.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import CustomUrlCategory

CUSTOM_URL_CATEGORY_MODEL = "integrations.CustomUrlCategory"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        # EVERY path empty or missing. A category has one owner, so the other owner's path is
        # always NULL - OR-ing the null branches would call every row empty.
        q = Q()
        for lookup in lookups:
            q &= Q(**{lookup: ""}) | Q(**{f"{lookup}__isnull": True})
        return q
    if not isinstance(value, str) or not value.strip():
        raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
    suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
    q = Q()
    for lookup in lookups:
        q |= Q(**{f"{lookup}__{suffix}": value.strip()})
    return q


def build_text_compiler(field_name, *lookups):
    """One field over one or more lookup paths - several when the owner can be either model."""
    def compiler(clause):
        return CustomUrlCategory.objects.filter(
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
        return CustomUrlCategory.objects.filter(**{lookup_field: value}).values("pk")
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
        return CustomUrlCategory.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "name": build_text_compiler("name", "name"),
    "namespace_type": build_text_compiler("namespace_type", "namespace_type"),
    "namespace_value": build_text_compiler("namespace_value", "namespace_value"),
    "appliance_group": build_text_compiler(
        "appliance_group", "appliance_group__name", "enforcement_point__appliance_group__name"),
    # The firewalls holding the definition: every appliance of the owning group, or the vsys's.
    "hostname": build_text_compiler(
        "hostname", "appliance_group__appliances__hostname",
        "enforcement_point__appliance_group__appliances__hostname",
        "enforcement_point__appliance__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "appliance_group__appliances__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number",
        "enforcement_point__appliance__serial_number"),
    # ONE STAGE 5 COLUMN, TWO FIELDS, which is this repository's convention rather than an
    # exception: stage 5's `appliance` is `hostname` AND `serial_number` in every shipped
    # compiler. A finding names the category and its scope because the remediation is per
    # object, and an assessor asks by whichever of the two they have in front of them.
    #
    # ---------------------------------------------------------------------- PAN-URL-006
    # THE ASSERTION. `is_used` is a non-null boolean defaulting to FALSE, and false is the
    # REPORTING side - so a row whose reference walk never ran over-reports rather than passing.
    # That is the direction stage 3 chose and bounded, and it is why the deliverable is a
    # candidate list: every error is in the direction of calling a live category unreferenced.
    "is_used": build_boolean_compiler("is_used", "is_used"),
    # THE GRADING. See the module docstring for why this is a text compiler.
    "category_type": build_text_compiler("category_type", "category_type"),
    # `referrer_count` IS THE SCALAR THAT STANDS IN FOR THE JSONField, and it is registered for
    # that reason rather than because a clause names it: it is how a query reaches the reference
    # walk's result at all, now that `reference_surfaces_searched` cannot be registered.
    "referrer_count": build_integer_compiler("referrer_count", "referrer_count"),
    # THE MEMBERSHIP COUNT AND ITS COMPANION. `match_entry_count` is `null=True` - a null means
    # the `list` key was ABSENT and nothing is assumed, which is NOT the same as an empty list -
    # and `match_entry_count_computed` is false on exactly the rows where the count is a
    # migration default rather than a reading. Stage 5 names both on this control and both are
    # `presented`, so a reader of a finding is told the membership and whether it was measured.
    "match_entry_count": build_integer_compiler("match_entry_count", "match_entry_count"),
    "match_entry_count_computed": build_boolean_compiler(
        "match_entry_count_computed", "match_entry_count_computed"),
    # `match_entries` and `reference_surfaces_searched` are NOT registered: both are JSONFields,
    # stage 5 marks both `not_searchable`, and a JSONField must not be registered here. Their
    # scalar neighbours are `match_entry_count` and `referrer_count` above.
    #
    # `precedence_rank` and `enforcement_point` are NOT registered either, and the reason is the
    # narrow rule this list is kept to rather than an oversight: stage 5 marks both
    # `needs_compiler_field`, but no clause, no grading and no `undetermined` of this domain
    # names either, and both carry `asserted_by: null` and `presented: false`. A field earns its
    # place here by a control needing it; registering these would ship a search surface no
    # control asks for. `namespace_type` and `namespace_value` ARE here because they are the
    # scope half of the subject a finding has to name.
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_custom_url_category_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_custom_url_category_search_node(c) for c in group["clauses"]]
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
