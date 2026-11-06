"""What to call the file, for a caller that has to invent a name.

`build_workbook()` returns bytes and no name - the module docstring is explicit that nothing
here knows about the filesystem, and that stands: a NAME is not a path. The management command
takes its path from the operator, but a browser download has to put something in
`Content-Disposition`, and a stored artifact would want the same string, so the convention
lives here rather than in the one view that needs it first.

Three parts, in the order a consultant sorting a directory wants them: who it is about, which
engagement, and when it was built. The date is the BUILD date and not a collection window -
the workbook's Summary tab carries the window, and a filename that looked like one would be
read as authoritative.
"""

from __future__ import annotations

import datetime as dt

from django.utils.text import slugify


def workbook_filename(environment=None, *, today: dt.date | None = None) -> str:
    """`acme-op-1234567-assessment-2026-09-28.xlsx`, or the dated stem alone with no
    environment configured.

    A deployment without an `ApplicationEnvironment` is a real state - the lab spends its
    first minutes in it - and it is not worth refusing a download over, so the client and
    opportunity parts are simply dropped. Each part is slugified because it is client-supplied
    free text on its way into a header.
    """
    parts = []
    if environment is not None:
        name = environment.client_short_name or environment.client_name
        parts.extend(part for part in (slugify(name),
                                       slugify(environment.opportunity_number)) if part)
    parts.append("assessment")
    parts.append((today or dt.date.today()).isoformat())
    return "-".join(parts) + ".xlsx"


def remediation_workbook_filename(environment=None, *, today: dt.date | None = None) -> str:
    """`acme-op-1234567-remediation-2026-11-05.xlsx`, the same three parts with its own word.

    Named for what it answers rather than for the first file plus a suffix: a consultant with
    both in a directory is choosing between "what did we find" and "where do I go", and
    `-assessment-remediation` would sort them together and read as a variant of one.
    """
    parts = []
    if environment is not None:
        name = environment.client_short_name or environment.client_name
        parts.extend(part for part in (slugify(name),
                                       slugify(environment.opportunity_number)) if part)
    parts.append("remediation")
    parts.append((today or dt.date.today()).isoformat())
    return "-".join(parts) + ".xlsx"


def health_check_filename(environment=None, *, today: dt.date | None = None) -> str:
    """`acme-op-1234567-health-check-2026-11-05.docx`, the same three parts and a new extension.

    `health-check` and not `report`: the two workbooks and this are all reports, and the thing a
    consultant is choosing between in a directory is the engineer's detail, the list of edits,
    and the document that goes to the client. The hyphen is kept inside the word so the name
    reads as the deliverable Optiv's template is called after.
    """
    parts = []
    if environment is not None:
        name = environment.client_short_name or environment.client_name
        parts.extend(part for part in (slugify(name),
                                       slugify(environment.opportunity_number)) if part)
    parts.append("health-check")
    parts.append((today or dt.date.today()).isoformat())
    return "-".join(parts) + ".docx"
