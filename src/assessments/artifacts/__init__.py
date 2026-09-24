"""Client-deliverable artifacts built from an assessment run.

`build_workbook()` returns the engineer-detail workbook as bytes, together with the line each
sheet reports about itself. It raises `ArtifactBuildError` rather than producing a file it
cannot vouch for: a workbook that silently omits a finding is worse than no workbook, and the
guards that say so are the reason this is worth trusting as a deliverable.

The docx report will sit beside this, sharing the run and the engagement metadata.
"""

from __future__ import annotations

from .errors import ArtifactBuildError
from .workbook import build_workbook

__all__ = ["ArtifactBuildError", "build_workbook"]
