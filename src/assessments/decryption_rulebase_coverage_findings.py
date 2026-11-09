"""Finding generation for one enforcement point's decryption rulebase. PAN-DEC-001 and PAN-DEC-009.

THE GRAIN THAT CAN REPORT AN ABSENCE, which is the whole reason this module exists beside
`decryption_policy_rule_findings`. Stage 4 measured the commonest state of this domain as NO
DECRYPTION RULEBASE AT ALL - all four lab appliances, all twenty virtual systems, both Panorama
Shared rulebases and all ten device groups, twice - and a predicate cannot compare against a row
that is not there. So the two controls whose finding is that NO rule does something name the
enforcement point, where every column's uncollected and unrecomputed value is the FIRING one, and
the remediation is to ADD a rule rather than to edit one.

THE DISPATCH DEFAULTS TO `()` for the reason the sibling module states at length: a default that is
another control's arms is how a control sharing a type gets described with somebody else's claims,
and this type carries two controls whose claims are about different traffic in opposite directions.

WHAT THIS GENERATOR CANNOT SAY, AND EVERY FINDING IT WRITES CARRIES IT. The verdict is right and
UNATTRIBUTABLE: a decryption rule pushed from a device-group or Shared pre/post-rulebase CONTRIBUTES
to these counts because it is in force on this enforcement point, and the verdict row has no scope
column - so "this enforcement point opens no outbound web session" cannot say whether the gap is in
the firewall's own rulebase or in the device group above it. The per-rule model answers that with
`config_source`; this one cannot, and a reader sent to the wrong rulebase does not find the problem.

AND THE POPULATION THESE CONTROLS ARE REALLY ABOUT IS THE ENGINEER'S, not the firewall's. Which of
an appliance's egress paths carry user web traffic, in which jurisdictions opening it is lawful, and
which published TLS services are business-critical are all facts the firewall does not hold. Stage 3
records both controls as deliverable without them - as the inventory of what the policy as written
does - and a finding here says what the configuration says rather than that a particular path is
uninspected.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_decryption_rulebase_coverage_control_queries,
)
from assessments.models import (
    Control,
    DecryptionRulebaseCoverageFinding,
    DecryptionRulebaseCoverageFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import (
    DecryptionRulebaseVerdict,
)


def _nothing_opens_outbound_web(obj) -> list[str]:
    """PAN-DEC-001: outbound web traffic reaches no rule that opens the session."""
    disposition = obj.outbound_web_disposition
    if disposition == DecryptionRulebaseVerdict.OUTBOUND_NO_RULE:
        found = (
            "THERE IS NO FORWARD-PROXY DECRYPTION RULE IN FORCE ON THIS ENFORCEMENT POINT AT ALL. "
            f"It holds {obj.rule_count} in-force decryption rule(s) and none of them is on the "
            "ssl-forward-proxy branch, so no outbound web session is opened for inspection on the "
            "client's behalf. The remediation is to ADD a rule, which is why this finding names "
            "the virtual system rather than any rule")
    elif disposition == DecryptionRulebaseVerdict.OUTBOUND_NO_DECRYPT:
        found = (
            "EVERY FORWARD-PROXY RULE IN FORCE HERE LEAVES THE SESSION ENCRYPTED. The enforcement "
            f"point holds {obj.rule_count} in-force decryption rule(s), the rules match the "
            "traffic, and all of them pass it through unopened - so nothing downstream inspects "
            "anything. This is the failure a reviewer who counts rules reads as coverage, and the "
            "remediation is to EDIT a rule that already exists rather than to add one")
    else:
        found = (
            "THE OUTBOUND WEB DISPOSITION OF THIS ENFORCEMENT POINT READS "
            f"`{disposition or 'as nothing this reader could resolve'}` while its "
            "session-opening verdict is false, which is a combination the normalizer does not "
            "produce - read the rulebase itself before acting on this row")
    return [
        found,
        "EVERY CONTENT INSPECTION THE FIREWALL IS CONFIGURED TO PERFORM RUNS INSIDE A SESSION "
        "SOMEBODY OPENED. Malware, exploit, command-and-control, web-category and file-type "
        "inspection all read the inside of a TLS session, so where nothing opens one the whole "
        "inspection stack reports clean about traffic it never saw - and the organization is told "
        "it is protected on the strength of nothing",
        "WHICH EGRESS PATHS THIS APPLIANCE CARRIES AND WHERE OPENING THEM IS LAWFUL IS NOT A FACT "
        "THE FIREWALL HOLDS. An appliance that only fronts services the organization publishes, "
        "or only terminates site-to-site tunnels, has no outbound web traffic to open and this "
        "row is not a defect on it. What is delivered is what the policy as written does; the "
        "path list and the jurisdictions are the engineer's answer",
        "AND THIS ROW CANNOT SAY WHOSE RULEBASE THE GAP IS IN. A rule pushed from a device-group "
        "or Shared pre/post-rulebase is in force here and contributes to the verdict, and this "
        "model has no scope column - so check the firewall's own rulebase AND the device group "
        "above it before concluding either is empty",
        "`decrypt-and-forward` IS DELIBERATELY NOT A FAILING STATE HERE. That action opens the "
        "session, so it meets this assertion; that it also copies the opened session to an "
        "external chain is a separate exposure the catalog asserts nowhere, and stage 3 put it "
        "in its own uncovered list rather than reporting it as a coverage failure of this control",
    ]


def _no_inbound_inspection(obj) -> list[str]:
    """PAN-DEC-009: nothing inspects inbound TLS toward the organization's own servers."""
    return [
        "NO SSL INBOUND INSPECTION RULE IS IN FORCE ON THIS ENFORCEMENT POINT. It holds "
        f"{obj.rule_count} in-force decryption rule(s) and none of them is on the "
        "ssl-inbound-inspection branch, so exploit attempts arriving inside TLS toward the "
        "organization's own published servers are not visible to threat prevention at all",
        "THE COMMONEST FAILING STATE IS THAT NO SUCH RULE EXISTS, which is why this finding names "
        "the virtual system: a comparison over rule rows cannot report a row that is not there. "
        "The remediation is to add a rule and import the server's certificate and private key",
        "WHICH PUBLISHED SERVICES ARE BUSINESS-CRITICAL IS THE ENGINEER'S ANSWER AND NOT THE "
        "FIREWALL'S. A compensating arrangement - TLS terminated at a load balancer or a web "
        "application firewall in front of these servers - is a legitimate answer to this finding "
        "and the firewall holds no record of it, so this row is the start of that conversation "
        "rather than a defect on its own",
        "WHETHER A BOUND CERTIFICATE IS STILL VALID IS NOT ASSERTED HERE. Stage 3 reaches for the "
        "state where a rule covers the service with NO certificate bound and stage 4 measured "
        "that state UNREACHABLE - `certificates` is mandatory at commit validation when the "
        "inbound-inspection branch is the one present, so no committed rule can be in it. The "
        "state stage 3 was reaching for is real and arrives by a different mechanism, an EXPIRED "
        "bound certificate, which PAN-CRT-001 owns",
        "AND THIS ROW CANNOT SAY WHOSE RULEBASE THE GAP IS IN, the same limit PAN-DEC-001 carries: "
        "a pushed rule is in force here and this model has no scope column",
    ]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. The default is `()`.
PARTS_BY_CONTROL = {
    "PAN-DEC-001": (_nothing_opens_outbound_web,),
    "PAN-DEC-009": (_no_inbound_inspection,),
}


def _owner(obj) -> str:
    point = obj.enforcement_point
    appliance = point.appliance
    return str(appliance.hostname if appliance is not None else point.appliance_group)


def _subject(obj, control_id: str) -> str:
    parts = [f"the decryption rulebase of {obj.enforcement_point.vsys_name} on {_owner(obj)}"]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_decryption_rulebase_coverage_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="decryption rulebase coverage",
    control_type=Control.ControlType.DECRYPTION_RULEBASE_COVERAGE,
    finding_model=DecryptionRulebaseCoverageFinding,
    link_model=DecryptionRulebaseCoverageFindingControlQuery,
    subject_fk="decryption_rulebase_verdict",
    link_fk="decryption_rulebase_coverage_finding",
    queryset=lambda: DecryptionRulebaseVerdict.objects.select_related(
        "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group"),
    evaluate=evaluate_decryption_rulebase_coverage_control_queries,
    summary=build_decryption_rulebase_coverage_finding_summary,
    # The virtual system. NOT `obj.name`, which this model does not have - the dataclass default
    # would raise `AttributeError` inside generation rather than at import.
    subject_name=lambda obj: obj.enforcement_point.vsys_name,
    # REQUIRED ON A VERDICT GRAIN. `subject_name` above is a partition name like `vsys1`, which is
    # not unique in an estate and is not unique on one Panorama either, so without this a reader
    # cannot tell which appliance the row is about.
    subject_scope=lambda obj: _owner(obj)[:128],
)


def generate_decryption_rulebase_coverage_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_decryption_rulebase_coverage_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
