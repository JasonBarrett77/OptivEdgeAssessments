"""Search over `NormalizationIssue` - the record of an object this assessment could not build.

The subject here is OUR OWN RECORD rather than a device object, and that is the whole point: a
`NormalizationIssue` row exists when the object does not, so it is the only thing a finding can
point at for a class of gap nothing could previously report. Every other search package in this
directory compiles clauses over normalized device configuration; this one compiles clauses over
the normalizer's own account of what it could not normalize.

`raw_entry` IS DELIBERATELY NOT REGISTERED. It is a JSONField holding the verbatim payload entry
that failed, which is what `raw_*` means throughout both repos - evidence a human reads when
locating a fault by hand, never something a control clauses on. Registering it would make a
control's verdict depend on a vendor payload shape nothing has contracted.

`build_choice_compiler` RAISES ON A VALUE OUTSIDE THE COLUMN'S CHOICES rather than matching
nothing. The existing `search/security_rules/fields/scalar_choice.py` resolves the query's value
against the choice map and, on no match, returns `.none()` silently - so a clause naming a value
that is not a member is indistinguishable from a clause that matched no rows, and an operator who
mistypes `sever` for `severity`'s value gets a clean estate. Measured 2026-10-28: that compiler
has exactly one call site (`config_source`), so the behaviour is narrow, but it is the wrong
default for a package whose entire subject is "something we could not interpret".
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import NormalizationIssue

NORMALIZATION_ISSUE_MODEL = "integrations.NormalizationIssue"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return NormalizationIssue.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return NormalizationIssue.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_choice_compiler(field_name, lookup_field, choices):
    """`eq` against a closed set, refusing a value the column cannot hold.

    See the module docstring for why this raises where the other choice compiler returns an
    empty queryset. The members are read off the model's own `choices` rather than restated, so
    a member added to the column cannot go missing here.
    """
    members = {str(stored) for stored, _label in choices}

    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        candidate = value.strip()
        if candidate not in members:
            raise SearchSyntaxError(
                f"{field_name} has no value {candidate!r}. It is one of: "
                f"{', '.join(sorted(members))}.")
        return NormalizationIssue.objects.filter(
            **{lookup_field: candidate}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_boolean_compiler(field_name, lookup_field, *, invert=False):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return NormalizationIssue.objects.filter(
            **{lookup_field: (not value) if invert else value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    #: What kind of object failed - "security rule", "address object", "region". Free text in
    #: the model on purpose, so a new kind of failure costs no migration, which is why this is
    #: a text compiler and not a choice one: there is no closed set to validate against.
    "kind": build_text_compiler("kind", "kind"),
    #: The object's name on the device. CAN BE EMPTY, and the model says why: "Empty when the
    #: entry had no @name; that is itself the problem." So `is_empty` is a meaningful clause
    #: here rather than a degenerate one.
    "name": build_text_compiler("name", "name"),
    #: Whether the state should be possible at all.
    "severity": build_choice_compiler(
        "severity", "severity", NormalizationIssue.Severity.choices),
    #: What was actually DONE - whether the object exists downstream or not. This is the column
    #: that separates "we could not build it" from "we built it on data we do not trust", and
    #: those are two different findings with two different remediations.
    "disposition": build_choice_compiler(
        "disposition", "disposition", NormalizationIssue.Disposition.choices),
    #: True when this row is a CONSEQUENCE of another row in the same run - a rule that failed
    #: because an object it references failed. Computed at write time by Integrations, which is
    #: what lets a control report the cause separately from its symptoms instead of reporting
    #: 1,301 findings for one fault.
    "is_consequent": build_boolean_compiler("is_consequent", "is_consequent"),
    #: For a consequent row, the object it could not resolve. This is how a finding about an
    #: affected rule names the object that took it down.
    "related_object_name": build_text_compiler(
        "related_object_name", "related_object_name"),
    #: Which payload node and which read it came from, for locating the fault by hand.
    "node": build_text_compiler("node", "node"),
    "source": build_text_compiler("source", "source"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_normalization_issue_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_normalization_issue_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause.get("negated") else predicate
