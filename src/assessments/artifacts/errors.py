"""What a workbook build raises when it refuses to produce a file.

The prototype raised `SystemExit` - correct for a script, wrong here twice over: it derives
from `BaseException`, so a `except Exception` around a build will not catch it, and under a
web server it takes the worker down rather than returning an error.

The guards themselves are the point and are kept exactly as they were. A workbook that
silently omits a finding is worse than no workbook, so a failed check stops the build.
"""

from __future__ import annotations


class ArtifactBuildError(Exception):
    """A build guard refused: the workbook would have been wrong."""
