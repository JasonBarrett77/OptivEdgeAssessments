"""One finding generator, parameterised, instead of five near-identical copies.

The five object generators were 111 of 122 lines IDENTICAL after renaming. The only content
that differed was the sentence describing the subject - which is the part that carries meaning
and stays hand-written per object, in each module, where it can be read next to the control it
describes.

What is shared is the machinery: load the active controls of a type, evaluate each control's
queries, delete the previous findings, create one finding per matched object, and bulk-create
the query links. None of that is object-specific and copying it five times meant five places to
fix when the shape changed.

The spec deliberately takes CALLABLES for the queryset and the evaluator rather than importing
them here. Importing every object's model and evaluator into one module makes this file the
thing that must change whenever a new object appears - which is the coupling the registry
pattern exists to avoid.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from django.db import transaction
from django.db.models import QuerySet
from django.utils import timezone

from assessments.models import AssessmentRun, Control


@dataclass(frozen=True)
class ObjectFindingSpec:
    #: Singular and lowercase, for the run name and prose: "certificate profile".
    label: str
    control_type: str
    finding_model: type
    link_model: type
    #: Field on the finding holding the object, and on the link holding the finding.
    subject_fk: str
    link_fk: str
    #: Deferred so this module imports no object models. Called with no arguments.
    queryset: Callable[[], QuerySet]
    #: (base_queryset, control) -> (qs, active, skipped, matched_by_object, severity_by_id)
    evaluate: Callable
    #: (obj, matched_queries) -> the summary sentence. The part worth writing by hand.
    summary: Callable
    #: (obj) -> the name frozen onto the finding.
    subject_name: Callable = lambda obj: obj.name
    #: (obj) -> scope, for objects whose names collide across scopes. None when they cannot.
    subject_scope: Callable | None = None


def matched_query_sentence(subject: str, matched_queries) -> str:
    """The trailing "Matched control query/queries: ..." clause every summary ends with."""
    names = [query.name for query in matched_queries]
    if not names:
        return subject + "."
    if len(names) == 1:
        return f"{subject}. Matched control query: {names[0]}."
    return f"{subject}. Matched control queries: {', '.join(names)}."


@dataclass
class ObjectFindingRunResult:
    assessment_run: AssessmentRun
    controls_evaluated: int
    findings_created: int
    query_links_created: int
    skipped_queries: int


def generate_object_findings(spec: ObjectFindingSpec, assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    controls = list(
        Control.objects.filter(control_type=spec.control_type, is_active=True)
        .order_by("control_id")
    )
    base_queryset = spec.queryset()
    findings_created = query_links_created = skipped_queries = 0

    with transaction.atomic():
        spec.finding_model.objects.all().delete()

        for control in controls:
            (
                _matched_queryset,
                _active_queries,
                control_skipped_queries,
                matched_by_object,
                severity_by_object_id,
            ) = spec.evaluate(base_queryset, control)
            skipped_queries += control_skipped_queries

            objects = {obj.pk: obj for obj in base_queryset.filter(pk__in=matched_by_object)}

            # Findings are created - and so numbered - in a stable order: by subject, as a reader
            # of any presentation sorted by control then object would expect.
            def by_subject(object_id):
                obj = objects[object_id]
                scope = spec.subject_scope(obj) if spec.subject_scope is not None else ""
                return (spec.subject_name(obj), scope, object_id)

            for object_id in sorted(matched_by_object, key=by_subject):
                matched_queries = matched_by_object[object_id]
                obj = objects[object_id]
                fields = {
                    "assessment_run": assessment_run,
                    "control": control,
                    spec.subject_fk: obj,
                    "severity": severity_by_object_id[object_id],
                    "title": control.name,
                    "subject_name": spec.subject_name(obj),
                    "summary": spec.summary(obj, matched_queries),
                    "matched_query_names": [q.name for q in matched_queries],
                    # The configuration this finding was computed from, PINNED HERE rather than
                    # read back through the subject later. The subject's own `source_snapshot`
                    # answers a different question - what that object is currently parsed from -
                    # and normalization repoints it in place on the next collection, so a
                    # finding reading through the relationship would report a date later than
                    # anything it was derived from. See `FindingBase.snapshot`.
                    #
                    # Every subject model carries `source_snapshot`, checked across all 24
                    # finding kinds, so `getattr` is for the one that eventually does not
                    # rather than for the ones that do.
                    "snapshot": getattr(obj, "source_snapshot", None),
                }
                if spec.subject_scope is not None:
                    fields["subject_scope"] = spec.subject_scope(obj)
                finding = spec.finding_model.objects.create(**fields)
                findings_created += 1
                links = [
                    spec.link_model(**{spec.link_fk: finding, "control_query": control_query})
                    for control_query in matched_queries
                ]
                spec.link_model.objects.bulk_create(links)
                query_links_created += len(links)

    return len(controls), findings_created, query_links_created, skipped_queries


def regenerate_object_findings(spec: ObjectFindingSpec) -> ObjectFindingRunResult:
    """Create a run, fill it, and mark it - failing the run rather than leaving it RUNNING."""
    assessment_run = AssessmentRun.objects.create(
        name=f"{spec.label.capitalize()} Findings "
             f"{timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        status=AssessmentRun.Status.RUNNING,
        started_at=timezone.now(),
    )
    try:
        controls, findings, links, skipped = generate_object_findings(spec, assessment_run)
    except Exception:
        assessment_run.mark_failed()
        assessment_run.save(update_fields=["status", "completed_at"])
        raise
    assessment_run.mark_completed()
    assessment_run.save(update_fields=["status", "completed_at"])
    return ObjectFindingRunResult(
        assessment_run=assessment_run, controls_evaluated=controls,
        findings_created=findings, query_links_created=links, skipped_queries=skipped)
