"""Build a query from the rows a person ticked.

The convenience half of the query builder: select rows, press the button, and the builder
opens on a query those rows satisfy. Jason, 2026-09-26: "this is a convenience feature, not
particularly intelligent. The user will likely adjust the parameters to get what they want.
But having it all filled in is the time saver."

HOW IT WORKS. For each column the page shows that presents one queryable field, read that
field from every selected object. Where they all agree, that agreement becomes a clause.
Clauses go in a GROUP, and refining adds a second group ANDed with the first - which is why
the first one is a group at all.

THE HAZARD, AND WHAT IS DONE ABOUT IT. Reading a field's value is a second copy of what the
compiler knows about that field. If the two drift, the button produces a query that does not
select the rows it came from - silently, which is the worst way for this to fail. So the
query is BUILT BY THE READER AND VERIFIED BY THE COMPILER: every clause is compiled and
checked against the selection, and one that would exclude a selected row is dropped rather
than shipped. Drift shows up as a missing clause, not as a wrong answer.

`query_fields` on each `ResultsSpec` says which column presents which field. A column with no
entry - "Character Classes", "Protocol Range", "Referenced By" - presents a composite or a
verdict rather than a field, and contributes nothing here.
"""

from __future__ import annotations

from assessments.search.compiler import apply_search_node
from assessments.search.exceptions import SearchSyntaxError
from assessments.search.registry import get_model_entry

#: Fields whose value is not an attribute of the object. Each names the path to read instead,
#: and a path is only ever a chain of attributes - anything cleverer belongs in the compiler,
#: which is the thing this must not become a second copy of.
FIELD_PATHS = {
    "hostname": "appliance.hostname",
    "serial_number": "appliance.serial_number",
    "management_station": "management_station",
    "vsys_name": "enforcement_point.vsys_name",
    "vsys_display_name": "enforcement_point.vsys_display_name",
    # Query name and column name differ from the attribute. Both were silently unreadable
    # until a test asked for them - a field that cannot be read produces no clause, which
    # looks exactly like a field the rows disagreed on.
    "binding_count": "bound_interface_count",
    "configured_hostname": "hostname",
}

#: Fields holding a SET of members rather than one value: the shared members become one clause
#: each. The relation is named here because reading it is presentation, not assessment - the
#: same relations `configuration_results` already renders in those columns.
MEMBER_RELATIONS = {
    "from_zone": ("securityrulefromzones", "value"),
    "to_zone": ("securityruletozones", "value"),
    "application": ("securityruleapplications", "value"),
    "service": ("securityruleservices", "value"),
    "source_address_name": ("source_address_refs", "raw_value"),
    "destination_address_name": ("destination_address_refs", "raw_value"),
}

#: The resolved side of an address field, for the "include resolved addresses" option. These
#: are the only fields that take `includes` - a name field takes `eq`, because membership of a
#: name and membership of an address space are different questions.
RESOLVED_ADDRESS_FIELDS = {
    "source_address_name": "source_address",
    "destination_address_name": "destination_address",
}


def read_value(obj, field):
    """The value of a queryable field on one object, or `_MISSING` when it cannot be read."""
    path = FIELD_PATHS.get(field, field)
    value = obj
    for part in path.split("."):
        value = getattr(value, part, _MISSING)
        if value is _MISSING:
            return _MISSING
    return value


def read_members(obj, field):
    """The members of a multi-valued field, as a set of strings."""
    relation, attribute = MEMBER_RELATIONS[field]
    manager = getattr(obj, relation, None)
    if manager is None:
        return set()
    return {str(getattr(row, attribute)) for row in manager.all()
            if getattr(row, attribute, None)}


class _Missing:
    def __repr__(self):
        return "<unreadable>"


_MISSING = _Missing()


def clause(field, op, value):
    return {"field": field, "op": op, "value": value,
            "negated": False, "case_sensitive": False, "include_any": False}


def shared_clauses(objects, fields, *, resolved_addresses=False):
    """One clause per field the selected objects AGREE on, in `fields` order.

    A field they disagree on is left out rather than turned into an OR: the button is
    answering "what do these rows have in common", and a clause listing alternatives says
    something the reader did not ask for. With one row selected everything agrees, which is
    the point - the whole row becomes the query.
    """
    built = []
    for field in fields:
        if field in MEMBER_RELATIONS:
            shared = set.intersection(*(read_members(obj, field) for obj in objects))
            for member in sorted(shared):
                built.append(clause(field, "eq", member))
                if resolved_addresses and field in RESOLVED_ADDRESS_FIELDS:
                    # The same member asked as an address space rather than as a name.
                    built.append(clause(RESOLVED_ADDRESS_FIELDS[field], "includes", member))
            continue

        values = [read_value(obj, field) for obj in objects]
        if any(value is _MISSING for value in values):
            continue
        first = values[0]
        if any(value != first for value in values[1:]):
            continue
        if first is None or first == "":
            # Absent is a real state, but `eq ""` is not how every field spells it and this is
            # not the place to decide which do. Left out; the reader can add it.
            continue
        if not isinstance(first, (str, int, bool)):
            first = str(first)
        built.append(clause(field, "eq", first))
    return built


def keep_clauses_that_hold(model_label, clauses, objects):
    """Drop any clause the compiler does not agree with - the guard described in the module
    docstring. A clause that excludes a row it was READ FROM is a reader/compiler disagreement,
    and shipping it would produce a query that answers a different question than the one the
    selection asked."""
    entry = get_model_entry(model_label)
    selected = {obj.pk for obj in objects}
    kept = []
    for one in clauses:
        node = {"model": model_label, "operator": "and", "clauses": [one]}
        try:
            matched = set(apply_search_node(
                entry["model_class"].objects.all(), node).values_list("pk", flat=True))
        except (SearchSyntaxError, Exception):  # noqa: BLE001 - a bad clause is dropped, not raised
            continue
        if selected <= matched:
            kept.append(one)
    return kept


def selection_group(model_label, objects, fields, *, resolved_addresses=False):
    """The group of clauses a selection produces, verified, or None when nothing survived."""
    clauses = keep_clauses_that_hold(
        model_label,
        shared_clauses(objects, fields, resolved_addresses=resolved_addresses),
        objects)
    if not clauses:
        return None
    return {"operator": "and", "clauses": clauses}


def combine(model_label, existing, group):
    """The refined query: each press of the button is its own group, ANDed with what was there.

    Only the ROOT may carry `model` (see `search.syntax`), so an existing root is nested as a
    plain group. Groups rather than a flat clause list because a refinement is a separate
    thought - and because flattening two `eq` clauses on one field into one group would ask
    for a row that is two things at once.
    """
    if not existing:
        return {"model": model_label, "operator": "and", "clauses": group["clauses"]} \
            if len(group["clauses"]) == 1 else {"model": model_label, **group}
    nested = {key: value for key, value in existing.items() if key != "model"}
    return {"model": model_label, "operator": "and", "clauses": [nested, group]}
