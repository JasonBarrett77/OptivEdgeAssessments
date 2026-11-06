"""The partials a generated .docx is built out of, and the scaffold they are inserted into.

Jason, 2026-11-05: *"I'd rather copy the style visually, build our own partials that can easily
be generated from the data, and create a new .docx file every time."* These are those partials.
They are deliberately small and style-driven - `paragraph(STYLE, text)`, `table(rows, grid)`,
`CaptionCounters.table(...)`, `rating_cell(...)` - because every visual decision in this
deliverable belongs to Optiv's own `styles.xml` and none of it belongs here. A partial that set a
font would be a second source of truth for the look of the page, and the first reissue of the
template would leave it behind.

`scaffold` opens the committed style donor READ-ONLY and hands back new bytes; `partials` builds
the WordprocessingML that goes into it. Nothing here knows what a health check SAYS - see
`artifacts.health_check` for that, the same split the workbooks keep between `layout` and their
sheet writers.

Imported as modules rather than re-exported name by name: `partials` is forty short names, most
of them style ids, and a caller reads better saying `partials.TABLE_TEXT` than importing it.
"""

from __future__ import annotations

from . import partials, scaffold

__all__ = ["partials", "scaffold"]
