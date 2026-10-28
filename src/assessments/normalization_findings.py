"""Finding generation for NORMALIZATION COVERAGE controls — objects we could not build.

A sibling of `coverage_findings.py` and the same kind of statement: these say something about
us, not about the customer's device. The difference is which gap they can reach.
`coverage_findings` reports an object that normalized and whose content we never collected.
This reports the object that did not normalize at all — which has no downstream row, so until
now nothing in the assessment could name it.

WHAT THE SUBJECT IS. `NormalizationIssue`, our own record, written by Integrations when an
object could not be normalized cleanly. Its `disposition` says whether the object exists
downstream: `skipped` means it does not, and that is the case no other finding model can
represent. See `models.NormalizationFinding` for why the record rather than the object.

WHY THE PROSE IS HAND-WRITTEN. The remediation differs by what failed and how, and for a
finding whose whole content is "we could not see this", the sentence IS the finding — there is
no device setting to point at. So `_subject` says what was not built, what it took down with
it, and where to look, in the terms of the record rather than in the terms of a device object
that may not exist.

WHAT IS NOT HERE. No control is seeded by this module and none is seeded by this change at
all: the catalog entries are control work and belong to the process that writes control prose.
This is the plumbing those controls will run on, exercised by tests rather than by shipped
catalog rows.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_normalization_control_queries
from assessments.models import (
    Control,
    NormalizationFinding,
    NormalizationFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import NormalizationIssue

#: `ObjectFindingBase.subject_name` is 64 characters and `NormalizationIssue.name` is 255. That
#: mismatch is harmless for every other finding model and is not harmless here: the rows that
#: exist at all are the ones whose payload was malformed, so an over-long name is exactly the
#: shape to expect. Truncating is right rather than widening the base column, because the base
#: column is shared by twenty-odd models that do not have this problem and the frozen name is a
#: label, not an identifier — the foreign key identifies the row.
SUBJECT_NAME_MAX = 64


def _where(issue) -> str:
    """The owner, in the terms a reader can act on.

    Three owners are possible because the objects have three scopes, and the model's docstring
    says `appliance` was added last, when interfaces began normalizing for both members of an
    HA pair. Reported in the order most-specific-first, since an enforcement point names the
    vsys and an appliance names only the box.
    """
    owner = issue.enforcement_point or issue.appliance_group or issue.appliance
    return f" on {owner}" if owner else ""


def subject_name_for(issue) -> str:
    """The name frozen onto the finding, which must survive an empty `name`.

    `NormalizationIssue.name` is "Empty when the entry had no @name; that is itself the
    problem", so a blank subject is not a defect in the data — it is the finding. A blank
    `subject_name` would put an empty cell on the tab for precisely the worst rows, so the
    fallback says what the row is instead of leaving the reader nothing.
    """
    name = (issue.name or "").strip()
    if not name:
        kind = (issue.kind or "object").strip() or "object"
        name = f"<unnamed {kind}>"
    return name[:SUBJECT_NAME_MAX]


def _subject(issue) -> str:
    """The one sentence this finding contributes.

    Says what was not built, whether anything was kept, and what else fell with it — because
    those three decide the remediation, and none of them is a device setting.
    """
    subject = f"{issue.kind or 'object'} {subject_name_for(issue)}{_where(issue)}"

    if issue.disposition == NormalizationIssue.Disposition.SKIPPED:
        head = (f"{subject} could not be normalized and does not exist downstream, so no "
                f"control in this assessment has looked at it")
    else:
        head = (f"{subject} was normalized and kept, but on data the normalizer could not "
                f"read in full, so anything asserted about it rests on that")

    if issue.is_consequent and issue.related_object_name:
        head += (f". It failed as a consequence of {issue.related_object_name}, which is the "
                 f"object to fix first")
    elif issue.is_consequent:
        head += ". It failed as a consequence of another object in the same run"

    reason = (issue.reason or "").strip()
    if reason:
        head += f". The normalizer reported: {reason}"

    locator = " / ".join(part for part in ((issue.source or "").strip(),
                                           (issue.node or "").strip()) if part)
    if locator:
        head += f". Read from {locator}"

    return head


def build_normalization_finding_summary(issue, matched_queries) -> str:
    return matched_query_sentence(_subject(issue).rstrip("."), matched_queries)


SPEC = ObjectFindingSpec(
    label="normalization",
    control_type=Control.ControlType.NORMALIZATION,
    finding_model=NormalizationFinding,
    link_model=NormalizationFindingControlQuery,
    subject_fk="normalization_issue",
    link_fk="normalization_finding",
    queryset=lambda: NormalizationIssue.objects.select_related(
        "enforcement_point", "appliance_group", "appliance"),
    evaluate=evaluate_normalization_control_queries,
    summary=build_normalization_finding_summary,
    subject_name=subject_name_for,
)

#: Kept so importers do not have to know the generator is shared.
NormalizationFindingRunResult = ObjectFindingRunResult


def generate_normalization_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_normalization_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
