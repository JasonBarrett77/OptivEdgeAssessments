"""Graded severity for one finding, from the corpus scale on its control.

Split out because both finding generators need it and neither should own it. The scale lives on
the Control; the value it grades lives on the subject; the field connecting them is read from
the control's own query rather than declared anywhere.

`Control.severity_for_measure` returns None whenever it cannot say - no scale, no matching band,
a value that will not parse - and the caller keeps whatever severity the query produced. That
fallback is the whole safety story: grading can only ever refine a severity the system was
already going to report, never invent or lose one.
"""

from __future__ import annotations


def graded_severity(control, subject, fallback: str) -> str:
    """The finding's severity: the corpus band if there is one, else what the query decided."""
    if not control.severity_scale:
        return fallback
    field = control.measured_field()
    if not field:
        return fallback
    measure = getattr(subject, field, None)
    return control.severity_for_measure(measure) or fallback
