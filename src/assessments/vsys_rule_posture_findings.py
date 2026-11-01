"""Finding generation for one virtual system's whole-policy posture.

PAN-POL-007, -010, -017, -018 and -019. Minted by stage 8 of `security-policy`, 2026-11-01.

THE VSYS IS THE SUBJECT AND NOT THE RULE, because every one of these five controls reports a
rule that DOES NOT EXIST - no catch-all refusal with its sessions recorded, no refusal of named
applications evaluated above the permits it covers, no standing block of the vendor's own hostile
address lists, no rule naming a region on either address side, no refusal matched on a port. A
rule-keyed row cannot report an absence, and a missing row cannot either: a vsys with no
`rulebase/security/rules` node at all still enforces the two rules PAN-OS ships, which is why
the integrations model writes a row with `rules_collected` false rather than no row.

THE DISPATCH DEFAULTS TO `()`. Five controls share this type today and each one's finding has to
name its own absence, so a default that is any one control's arms is how the next control on the
type gets described with the wrong claim. `()` falls through to the bare subject sentence.

WHAT NO FINDING HERE CAN SAY, and both are gaps rather than style:

- WHICH OF THE THREE RULEBASES THE ABSENCE SPANS. A rule set is the firewall-local vsys rulebase
  plus the Panorama pre- and post-rulebases pushed to it, and this model stores no scope column -
  so an estate whose policy is pushed from Panorama is told to add a rule to a vsys rulebase the
  firewall will not accept rules into. The distinction IS stored, on `SecurityRule.config_source`;
  joining back to it is stage 9's question.
- WHICH HOSTILE LIST TO REFERENCE. Stage 3 forbade carrying the vendor's ten predefined
  hostile-list names downstream - they came from one appliance of three, the Help prints no slug
  for any of them, and the configurable list object has five type branches of which none is the
  predefined kind - so the count stage 7 built tests whether a blocking rule names an EXTERNAL
  LIST on each side, which is strictly wider than the control asks. A customer's own EDL
  satisfies it. The sentence below says so rather than implying the vendor's list was checked.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_vsys_rule_posture_control_queries
from assessments.models import (
    Control, VsysRulePostureFinding, VsysRulePostureFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import VsysRulePosture


def _where(obj) -> str:
    """`vsys6 on fw-core-tpa-a`. The vsys name alone is not unique in an estate."""
    return f"{obj.enforcement_point.vsys_name} on {obj.enforcement_point}"


def _uncollected(obj) -> list[str]:
    """The one sentence that has to come first wherever it applies.

    `rules_collected` false means no rulebase read answered for this vsys at all, so every
    absence below it is an absence nobody measured. Every shipped query on this model clauses
    `rules_collected eq true`, so this arm should be unreachable from a generated finding - it is
    written because a control added later without that clause would otherwise describe an
    unmeasured vsys as a vsys with no rules.
    """
    if obj.rules_collected:
        return []
    return [f"NO RULEBASE READ HAS ANSWERED FOR {_where(obj)}, so nothing below is a statement "
            f"about its policy"]


def _catch_all(obj) -> list[str]:
    """PAN-POL-010's two assertions, which are one finding and two different absences."""
    parts = []
    if not obj.has_logged_catch_all_deny:
        parts.append(
            f"NO RULE IN {_where(obj)} REFUSES WHAT IS LEFT OVER AND RECORDS DOING SO - there is "
            f"no blocking rule with an open match tuple on every side, evaluated after every "
            f"permitting rule, carrying session-end logging. An unlogged catch-all refuses the "
            f"traffic and leaves no evidence it did, so logging is half the assertion and not a "
            f"refinement of it")
    if not obj.default_rules_log_session_end:
        parts.append(
            f"and the two rules PAN-OS ships into {_where(obj)} do not record the sessions they "
            f"refuse: their session-end logging is off, which is the vendor's own shipped value "
            f"wherever no override node exists - so traffic matching neither a permit nor a "
            f"written refusal is dropped with nothing written down")
    return parts


def _application_block(obj) -> list[str]:
    """PAN-POL-007."""
    if obj.has_application_block_rule_above_permits:
        return []
    return [f"NO RULE IN {_where(obj)} REFUSES TRAFFIC BY APPLICATION ABOVE THE PERMITS IT "
            f"COVERS - every blocking rule here either matches on `any` application, which is a "
            f"catch-all rather than an application decision, or sits below a permitting rule "
            f"whose application set it intersects, in which case the permit gets there first. A "
            f"disabled blocking rule does not count: it is in the configuration and not in the "
            f"evaluation"]


def _hostile_lists(obj) -> list[str]:
    """PAN-POL-017. A count of the two directions, so the sentence names which."""
    missing = int(obj.vendor_hostile_list_block_directions_missing or 0)
    if not missing:
        return []
    direction = ("both directions - traffic TO those addresses and traffic FROM them"
                 if missing >= 2 else "one of the two directions")
    return [f"{_where(obj)} HAS NO STANDING RULE BLOCKING KNOWN-HOSTILE ADDRESS LISTS in "
            f"{direction}. WHAT THIS CHECKED is whether a blocking rule above the permits names "
            f"an EXTERNAL DYNAMIC LIST on that side, which is WIDER than the control asks: the "
            f"vendor's own predefined lists cannot be recognised from configuration today - no "
            f"slug is published for any of them and the configurable list object has no "
            f"predefined branch - so a list the customer maintains satisfies this and the "
            f"vendor's is not distinguished"]


def _geographic(obj) -> list[str]:
    """PAN-POL-018."""
    if obj.expresses_geographic_boundary:
        return []
    return [f"THE POLICY OF {_where(obj)} SAYS NOTHING ABOUT GEOGRAPHY - no rule names a region "
            f"on either address side, with either polarity of action. Nothing in a configuration "
            f"distinguishes a deliberate decision not to geo-block from nobody having considered "
            f"it, so this is reported rather than assumed settled"]


def _port_matched_block(obj) -> list[str]:
    """PAN-POL-019."""
    if obj.has_port_matched_block_rule:
        return []
    return [f"NO RULE IN {_where(obj)} REFUSES TRAFFIC BY PORT - no blocking rule names a "
            f"service object or group rather than `any` or `application-default`, so the "
            f"mechanism for refusing a port outright is not present at all. WHICH ports must be "
            f"blocked is this estate's decision and this control does not take it; the device "
            f"ships service objects for HTTP and HTTPS and for nothing else, so every other port "
            f"needs an object somebody builds"]


#: Keyed by control id, defaulting to `()`. See the module docstring.
PARTS_BY_CONTROL = {
    "PAN-POL-007": (_uncollected, _application_block),
    "PAN-POL-010": (_uncollected, _catch_all),
    "PAN-POL-017": (_uncollected, _hostile_lists),
    "PAN-POL-018": (_uncollected, _geographic),
    "PAN-POL-019": (_uncollected, _port_matched_block),
}


def _subject(obj, control_id: str = "") -> str:
    parts: list[str] = []
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    if not parts:
        return f"the rule posture of {_where(obj)}"
    return "; ".join(parts)


def build_vsys_rule_posture_finding_summary(obj, matched_queries) -> str:
    # The control id comes off the first matched query, which is safe because
    # `object_findings.generate_object_findings` iterates `for control in controls`, takes
    # `matched_by_object` from `spec.evaluate(base_queryset, control)` and creates the finding
    # with that same control - so `matched_queries` can only ever hold one control's queries.
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="virtual system rule posture",
    control_type=Control.ControlType.VSYS_RULE_POSTURE,
    finding_model=VsysRulePostureFinding,
    link_model=VsysRulePostureFindingControlQuery,
    subject_fk="vsys_rule_posture",
    link_fk="vsys_rule_posture_finding",
    # The point's owner is joined because every sentence prints it, and `EnforcementPoint.__str__`
    # reads `appliance_group or appliance` - a query per finding otherwise.
    queryset=lambda: VsysRulePosture.objects.select_related(
        "enforcement_point__appliance_group", "enforcement_point__appliance"),
    evaluate=evaluate_vsys_rule_posture_control_queries,
    summary=build_vsys_rule_posture_finding_summary,
    # The vsys's own name. NOT `obj.name`, which this model does not have.
    subject_name=lambda obj: obj.enforcement_point.vsys_name,
    # The appliance that owns the virtual system - `vsys6` is not unique in an estate.
    subject_scope=lambda obj: str(obj.enforcement_point.appliance or
                                  obj.enforcement_point)[:128],
)

VsysRulePostureFindingRunResult = ObjectFindingRunResult


def generate_vsys_rule_posture_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_vsys_rule_posture_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
