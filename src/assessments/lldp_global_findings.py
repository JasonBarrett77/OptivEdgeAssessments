"""Finding generation for the device-wide LLDP enable.

NO SHIPPED CONTROL PRODUCES ONE OF THESE, so this generator writes nothing today, and that is a
recorded state rather than dead code left behind. PAN-NET-003's assertions name two subjects -
the per-interface announcement and this device-wide enable - and `Control` maps one type to one
model while `ControlQuery.clean()` refuses a query whose model differs from its control's target,
so one catalog control cannot hold both halves. The per-interface half took the id, because
seven of the ten expectations stage 6 wrote are on it and all of its graded severities are.
Splitting PAN-NET-003 into two catalog ids changes what a customer's report contains and is
Jason's decision.

The generator is registered anyway, for the reason `finding_run.GENERATORS` exists at all: the
tuple has fallen behind `finding_registry` twice without anything failing, and a finding model
whose generator is added later is exactly the shape that slipped. Registering it now means the
half Jason may decide to build reports the moment a control exists, rather than producing a
model with rows nothing reads.

WHAT THE SENTENCE WOULD SAY, and it is not "LLDP is on firewall-wide". `network/lldp` is ABSENT
on every appliance measured and what the absence MEANS is unestablished in BOTH directions: it
could mean the protocol is globally enabled by default, in which case the preferred value is
unmet everywhere, or globally disabled, in which case the per-interface keys are moot. The one
piece of evidence - zero frames transmitted on three interfaces - is consistent with either,
because those interfaces also store `enable: no` individually, so the counters are explained
without the global key. What would turn it into an answer is one write and one commit on one
appliance: set `network/lldp/enable` to `no`, commit, and see whether `show lldp config all`'s
per-interface entries change or vanish.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_lldp_global_control_queries
from assessments.models import Control, LldpGlobalFinding, LldpGlobalFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import PanOsLldpGlobalSettings


def _global_enable(obj) -> list[str]:
    if obj.lldp_global_enable is False:
        return []
    if obj.lldp_global_enable is None:
        return ["the firewall-wide LLDP state was never established on this appliance - the "
                "`network/lldp` node is absent and what its absence means is unmeasured in both "
                "directions, so this reports a reading nobody has taken rather than a protocol "
                "known to be running"]
    return ["link-layer discovery is enabled firewall-wide, so the protocol is one per-interface "
            "checkbox away from announcing on any port anyone adds later"]


def _documented_need(obj) -> list[str]:
    return ["whether a documented operational need exists for the protocol is not recorded on "
            "the firewall and is not asserted here - where no need is produced, the preferred "
            "state is unmet"]


PARTS_BY_CONTROL: dict[str, tuple] = {}


def _subject(obj, control_id: str) -> str:
    parts = [f"Global LLDP on {obj.appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, (_global_enable, _documented_need)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_lldp_global_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="global LLDP setting",
    control_type=Control.ControlType.LLDP_GLOBAL,
    finding_model=LldpGlobalFinding,
    link_model=LldpGlobalFindingControlQuery,
    subject_fk="lldp_global_settings",
    link_fk="lldp_global_finding",
    queryset=lambda: PanOsLldpGlobalSettings.objects.select_related("appliance"),
    evaluate=evaluate_lldp_global_control_queries,
    summary=build_lldp_global_finding_summary,
    subject_name=lambda obj: obj.appliance.hostname or obj.appliance.serial_number,
)


def generate_lldp_global_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_lldp_global_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
