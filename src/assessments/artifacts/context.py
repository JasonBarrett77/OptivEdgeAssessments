"""Per-build state, which used to be module-level globals.

Two of them, and both are bugs the prototype could not hit because the process exited after
one workbook:

* **`ANCHORS`** mapped `(kind, pk)` to a fixed cell range like `internal:'Controls'!A6:H6`.
  Nothing cleared it between builds, so a second workbook in the same process inherited the
  first one's rows: a control that had moved, or gone, still had an anchor, and its link
  opened the WRONG ROW with no error.

* **The format caches were keyed by `id(workbook)`.** CPython reuses an address once an
  object is freed, so a later workbook could land on a freed earlier one's id and be handed a
  `Format` belonging to a closed workbook.

Both live on the build instead. A sheet writer takes a `WorkbookBuild` and reads
`build.workbook` for everything xlsxwriter needs, so the lifetime of the state is exactly the
lifetime of the file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkbookBuild:
    """One workbook being written."""

    workbook: Any

    #: (kind, pk) -> (link target, sheet name). A sheet registers its rows as it is written,
    #: and a sheet linking to them must be written AFTER it - see `workbook.SHEETS`. The
    #: target is a fixed cell range, so re-sorting the target table sends links to the wrong
    #: row.
    anchors: dict[tuple[str, int], tuple[str, str]] = field(default_factory=dict)

    #: Formats are registered with one workbook and cannot be used with another.
    formats: dict[Any, Any] = field(default_factory=dict)

    def format(self, key, properties):
        """A format made once per workbook, by key."""
        if key not in self.formats:
            self.formats[key] = self.workbook.add_format(properties)
        return self.formats[key]
