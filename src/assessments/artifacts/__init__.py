"""Client-deliverable artifacts built from an assessment run.

`build_workbook()` returns the engineer-detail workbook as bytes, together with the line each
sheet reports about itself, `build_remediation_workbook()` returns the remediation workbook the
same way, and `build_health_check_document()` returns Optiv's PAN Health Check as a .docx -
three deliverables answering three questions. The two workbooks share `layout` and nothing else;
the document shares `errors`, `naming` and the engagement metadata with them and nothing else
again.

Each raises `ArtifactBuildError` rather than producing a file it cannot vouch for: a workbook
that silently omits a finding is worse than no workbook, and the guards that say so are the
reason this is worth trusting as a deliverable. For the document the same bargain covers a
scaffold missing a style the report names, and a finding against a control the Area mapping does
not place.
"""

from __future__ import annotations

from .errors import ArtifactBuildError
from .health_check import build_health_check_document
from .naming import health_check_filename, remediation_workbook_filename, workbook_filename
from .sheets.findings import ALL_TESTED_COLUMNS, FindingsTable, build_findings_table
from .remediation_workbook import build_remediation_workbook
from .stored import stored_findings_table
from .workbook import build_workbook

__all__ = [
    "ALL_TESTED_COLUMNS",
    "ArtifactBuildError",
    "FindingsTable",
    "build_findings_table",
    "build_health_check_document",
    "build_remediation_workbook",
    "build_workbook",
    "health_check_filename",
    "remediation_workbook_filename",
    "stored_findings_table",
    "workbook_filename",
]
