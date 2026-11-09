"""Finding generation for the cryptographic operational mode an appliance reports. PAN-MGT-012.

Minted by stage 8 of `management-services` on 2026-11-01.

THE VALUE IS IN NO CONFIGURATION NODE AT ANY SCOPE. The mode is set from maintenance mode and is
reported at `/response/result/system/operational-mode` in the `show system info` reply. `show
fips-mode` - the command a reader reaches for - answers code=17 on all four lab appliances and
the CLI grammar carries no node for it. So this finding rests on a runtime reading, which is why
neither assessed column carries a provenance row.

WHAT THE SENTENCE MUST SAY, AND WHY IT IS NOT A VERDICT. Nothing on the device records whether
the approved mode is REQUIRED of this appliance. Stage 3 had a contractual obligation in its
`applies_when`; stage 5's restatement carries one clause and NO applicability, so that obligation
did not become a clause and every appliance in any estate reports this whether the obligation
exists or not. The honest sentence is therefore "the mode is not the approved one and nobody has
confirmed whether it must be" - an item an assessor is owed - and stage 5 defends that direction
in the integrations column's own words. Writing it as a plain failure would assert an obligation
this project has never established for any customer.

THE OTHER MODE'S SPELLING IS UNMEASURED and the sentence never claims it. The device answered
lowercase `normal` on all four lab appliances through both operational reads;
`ApplianceOperationalMode.APPROVED_MODE` is the catalog's `FIPS-CC`, no appliance in this
estate runs it, and neither available instrument can enumerate it - `action=complete` needs an
xpath and there is none. No query rests on that spelling, because stage 5 grades the approved
mode `no_finding`, which compiles to no query.

AN EMPTY MODE MEANS THE READ WAS NOT TAKEN, which is a different state from any value the device
can report: the field cannot be absent from a reply that arrived, there being no xpath at which
it could be missing, but the READ can be missing. That row still fires, because the verdict
column defaults to the firing side - and the sentence says which of the two it is looking at
rather than reporting a blank as a mode.

THE DISPATCH DEFAULTS TO `()`, for the reason the repository has repaired twice elsewhere: a
default that is this control's arms is how the next control on the type gets described with this
control's claim.

AND NOTHING HERE LICENSES REINTERPRETING ANOTHER DOMAIN'S DEFAULTS. Jason decided 2026-09-04
that a half-implemented assessment of this mode "would lie - a device in FIPS-CC mode would be
judged against normal-mode defaults, and would be reported as failing controls it satisfies and
passing ones it does not". Implicit values differ by mode, so an unanswered mode propagates
outwards into every other domain's findings wherever a control reasons from an absent key.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_appliance_operational_mode_control_queries)
from assessments.models import (
    ApplianceOperationalModeFinding,
    ApplianceOperationalModeFindingControlQuery,
    Control,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import ApplianceOperationalMode


def _owner(obj) -> str:
    return str(obj.appliance)


def _mode(obj) -> list[str]:
    """PAN-MGT-012's assertion: the appliance is not in the approved cryptography mode."""
    reported = str(obj.operational_mode or "")
    approved = ApplianceOperationalMode.APPROVED_MODE
    if not reported:
        return [
            f"NO OPERATIONAL-MODE READING WAS TAKEN FROM {_owner(obj)}, so nothing here "
            f"establishes which cryptographic mode it runs in - this is an unread appliance "
            f"rather than one reported as running the unapproved mode, and it is raised because "
            f"an appliance nobody read has not been shown to be in the approved mode",
        ]
    return [
        f"{_owner(obj)} REPORTS OPERATIONAL MODE {reported!r}, which is not the approved "
        f"cryptography mode ({approved}), so the appliance is not restricted to an approved "
        f"algorithm list",
    ]


def _obligation(obj) -> list[str]:
    """The half no configuration field holds, on every row this control reports."""
    return [
        "WHAT THIS DOES NOT ESTABLISH: nothing on the device records whether the approved mode "
        "is REQUIRED of this appliance, and this control carries no clause that asks - so what "
        "this finding says is that the mode is not the approved one and nobody has confirmed "
        "whether it must be, which is a question for an assessor rather than a verdict. Running "
        "in the approved mode is a design choice with real operational costs where no "
        "obligation exists"
    ]


#: Keyed by control id, defaulting to `()`. See the module docstring.
PARTS_BY_CONTROL = {
    "PAN-MGT-012": (_mode, _obligation),
}


def _subject(obj, control_id: str = "") -> str:
    parts: list[str] = []
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    if not parts:
        return f"the operational mode of {_owner(obj)}"
    return "; ".join(parts)


def build_appliance_operational_mode_finding_summary(obj, matched_queries) -> str:
    # The control id comes off the first matched query, which is safe because
    # `object_findings.generate_object_findings` iterates `for control in controls` and creates
    # the finding with that same control, so `matched_queries` holds one control's queries.
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="appliance operational mode",
    control_type=Control.ControlType.APPLIANCE_OPERATIONAL_MODE,
    finding_model=ApplianceOperationalModeFinding,
    link_model=ApplianceOperationalModeFindingControlQuery,
    subject_fk="appliance_operational_mode",
    link_fk="appliance_operational_mode_finding",
    queryset=lambda: ApplianceOperationalMode.objects.select_related("appliance"),
    evaluate=evaluate_appliance_operational_mode_control_queries,
    summary=build_appliance_operational_mode_finding_summary,
    # The appliance. This model has no `name`, which the `ObjectFindingSpec.subject_name`
    # default would reach for and raise on inside generation rather than at import.
    subject_name=lambda obj: _owner(obj),
)

ApplianceOperationalModeFindingRunResult = ObjectFindingRunResult


def generate_appliance_operational_mode_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_appliance_operational_mode_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
