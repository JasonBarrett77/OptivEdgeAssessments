"""What the configuration explorer holds: objects, the controls over them, and their queries.

`/assessments/configuration/` used to redirect straight to an object, on the reasoning that a
category index would be "a fourth thing to design and would be passed through without being
read". That reasoning was about a CATEGORY INDEX - a page whose only content is the four links
already in the bar above it. This is a different page: it answers questions the object pages
cannot, because each of them sees one object and these are all comparisons.

  - Which objects can be queried, and how much is normalized behind each.
  - How many controls read each object, and how many queries they carry.
  - Which rail items no control reads yet - Jason's rule, 2026-09-10, is that an object no
    completed control relates to comes out of the view, so the page that shows the rail should
    be able to show when that rule is being broken.
  - Which controls have nowhere to be previewed, which is the drift the destination resolver
    exists to prevent and worth stating rather than trusting.

Counts come from the same resolver the "view query results" links use, so a control counted
against an object here is a control whose link lands there. Two implementations of "which page
does this control belong to" would disagree eventually, and the disagreement would be invisible.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from django.db.models import Count

from assessments import configuration_navigation as config_nav
from assessments import configuration_results as config_results
from assessments.models import ConfigurationSearchState, Control, ControlQuery
from assessments.search.compiler import apply_search_node

#: Built queries shown on the dashboard. Enough to pick up yesterday's work, not a history.
RECENT_QUERIES = 8


@dataclass
class ObjectSummary:
    config_object: config_nav.ConfigObject
    href: str
    #: Rows normalized for this object, after the page's own scope.
    row_count: int
    controls: list[Control] = field(default_factory=list)
    query_count: int = 0

    @property
    def control_count(self) -> int:
        return len(self.controls)


def _controls_by_object():
    """{(category, slug): [Control]}, routed exactly the way a link would route.

    A control lands on the page its BASELINE query resolves to, which is what disambiguates the
    two pages over `SecurityProfile`. A control whose baseline resolves nowhere is not counted
    against an object - it appears in `unplaced_controls` instead, where it can be seen.
    """
    placed: dict[tuple[str, str], list[Control]] = {}
    unplaced: list[Control] = []
    controls = (Control.objects.filter(is_active=True)
                .prefetch_related("queries").order_by("control_id"))
    for control in controls:
        baseline = next((q for q in control.queries.all() if q.is_baseline), None)
        obj = config_results.object_for_canonical_query(
            baseline.canonical_query if baseline else None)
        if obj is None or not control.target_model:
            unplaced.append(control)
            continue
        placed.setdefault((obj.category, obj.slug), []).append(control)
    return placed, unplaced


def _row_count(obj) -> int:
    spec = config_results.RESULTS[obj.slug]
    rows = spec.base_queryset()
    if spec.scope:
        rows = apply_search_node(rows, spec.scope)
    return rows.count()


def _recent_queries(href):
    """The last few queries someone BUILT here, with a link back to each.

    A built query is parked server-side and addressed by a token, so it survives a reload and a
    paste to a colleague - and is then unfindable, because the token was only ever in one
    address bar. These are the rows that already exist; listing them costs nothing and turns a
    disposable token into something you can get back to.
    """
    by_model = {}
    for obj in config_nav.CONFIG_OBJECTS:
        if obj.search_model:
            by_model.setdefault(obj.search_model, obj)
    recent = []
    for state in ConfigurationSearchState.objects.all()[:RECENT_QUERIES]:
        obj = by_model.get(state.model_label)
        if obj is None:
            # The object it was built on is no longer in the rail. Shown, not hidden: the query
            # is still a thing someone wrote, and a silent drop reads as it never existing.
            recent.append({"label": state.model_label, "href": "", "text": state.query_text,
                           "created_at": state.created_at})
            continue
        recent.append({
            "label": obj.label,
            "href": f"{href(obj)}?search_state={state.token}",
            "text": state.query_text,
            "created_at": state.created_at,
        })
    return recent


def build(href) -> dict:
    """The whole dashboard. `href` builds an object's URL, and is passed in so this module
    stays free of `reverse` and of the view's own idea of routing."""
    placed, unplaced = _controls_by_object()
    query_counts = dict(
        ControlQuery.objects.filter(is_active=True)
        .values_list("control_id")
        .annotate(total=Count("id"))
    )

    categories = []
    for category in config_nav.CATEGORIES:
        summaries = []
        for obj in config_nav.objects_in(category):
            controls = placed.get((category, obj.slug), [])
            summaries.append(ObjectSummary(
                config_object=obj,
                href=href(obj),
                row_count=_row_count(obj) if obj.search_model else 0,
                controls=controls,
                query_count=sum(query_counts.get(c.pk, 0) for c in controls),
            ))
        categories.append({"name": category, "objects": summaries})

    return {
        "categories_detail": categories,
        "recent_queries": _recent_queries(href),
        "unplaced_controls": unplaced,
        #: Rail items no control reads. Not an error - an object can be wired for querying
        #: before a control exists - but it is the state Jason's rule says to look at.
        "objects_without_controls": [
            summary for entry in categories for summary in entry["objects"]
            if not summary.controls],
        #: Rendered as a row of cards. A list of pairs rather than four context keys, so the
        #: template loops instead of repeating the same markup four times.
        "totals": [
            ("Objects", sum(len(entry["objects"]) for entry in categories)),
            ("Controls", sum(len(v) for v in placed.values())),
            ("Active queries", sum(s.query_count for e in categories for s in e["objects"])),
            ("Rows normalized", sum(s.row_count for e in categories for s in e["objects"])),
        ],
    }
