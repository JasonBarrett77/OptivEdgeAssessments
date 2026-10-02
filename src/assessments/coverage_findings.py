"""Finding generation for COVERAGE controls — what this assessment could not see.

Every other finding family says something about the customer's device. These say something
about us: an external dynamic list nobody collected, one truncated at our own ceiling, a count
we could not resolve. They exist because the alternative is silence, and silence here is worse
than a finding — an unsized object falls through a breadth score as NARROW, which is a false
negative on the control whose whole job is finding broad rules.

NOT the same thing as a device fault, and the two must not share a control. An EDL the FIREWALL
cannot fetch is a real defect in the customer's configuration — the rule is live and the list
behind it is empty — and that belongs in the policy domain with the rest of the client's
findings. What is here is only our own blind spots. The two are distinguishable in the data:
a device that tried and failed leaves a snapshot with `resolved_content_source_total` set,
where a list nobody collected has no snapshot at all.

Generic where it matters - its own tab, and a summary that explains in prose what is unknown
and why - and structured where the codebase requires it. See `CoverageFinding` for why the
foreign key stayed.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_coverage_control_queries
from assessments.models import (
    Control,
    CoverageFinding,
    CoverageFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import AddressObject


def _where(obj) -> str:
    """The object's location, in the terms a reader can act on."""
    point = obj.enforcement_point or obj.appliance_group
    return f" on {point}" if point else ""


def _subject(obj) -> str:
    """The one sentence a coverage finding contributes.

    Says what is unknown and WHY it is unknown, because the remediation differs: a list nobody
    collected needs the EDL/FQDN cache refresh run, while one truncated at our ceiling needs a
    decision about the ceiling. Neither is something to change on the firewall.
    """
    subject = f"{obj.get_address_type_display()} {obj.name}{_where(obj)}"

    if obj.resolved_content_truncated:
        kept = obj.num_hosts if obj.num_hosts is not None else "an unknown number of"
        reported = obj.resolved_content_source_total
        return matched_query_sentence(
            f"{subject} was collected only in part - {kept} addresses kept of "
            f"{reported if reported is not None else 'an unreported total'} the device "
            f"reported, so its size is a known under-count and any breadth scored from it is "
            f"a floor rather than a figure",
            [],
        )

    return matched_query_sentence(
        f"{subject} has no resolved content, so the number of addresses it permits is unknown. "
        f"It is referenced by policy and has never been collected, or the collection returned "
        f"nothing. Run the EDL/FQDN cache refresh; until then any rule referencing it cannot "
        f"be scored for breadth",
        [],
    )


def build_coverage_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj).rstrip("."), matched_queries)


SPEC = ObjectFindingSpec(
    label="coverage",
    control_type=Control.ControlType.COVERAGE,
    finding_model=CoverageFinding,
    link_model=CoverageFindingControlQuery,
    subject_fk="address_object",
    link_fk="coverage_finding",
    queryset=lambda: AddressObject.objects.select_related(
        "enforcement_point", "appliance_group"),
    evaluate=evaluate_coverage_control_queries,
    summary=build_coverage_finding_summary,
    subject_name=lambda obj: obj.name,
)

#: Kept so importers do not have to know the generator is shared.
CoverageFindingRunResult = ObjectFindingRunResult


def generate_coverage_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_coverage_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
