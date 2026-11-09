"""Finding generation for one decryption policy rule. PAN-DEC-002, -003, -005 to -008 and -010.

SEVEN CONTROLS AND ONE SUBJECT. The entry grain is the exemption grain: every one of these controls
is about a rule that EXISTS and is wrong - it leaves traffic encrypted with a criterion at `any`, or
with no written reason, or with no profile attached, or with the source match inverted, or with a
log switch turned off - and what an engineer opens to close the finding is that rule. The three
coverage assertions in this domain are the opposite shape and are written by
`decryption_rulebase_coverage_findings`, because the state they report is that NO rule does
something and a row per rule has nothing to report it on.

THE DISPATCH DEFAULTS TO `()`, which is the safe convention and is a deliberate choice rather than
a default. Measured across all 28 shipped generators that key a dispatch by control id: EIGHTEEN
default to a non-empty arm tuple, five to `()` and five to `None` with a comment saying why. A
default that is another control's arms is how a control sharing a type gets described with somebody
else's claims - `zone_findings` was measured doing exactly that, returning PAN-IOT-002's sentence
for PAN-UID-001 - and with seven controls on this type the hazard would be six of them.

AND THERE IS NO REASSURING FALLBACK SENTENCE HERE. `_subject` below opens with what the rule IS and
then adds only the arms its own control owns; a control id with no entry gets the rule's identity
and nothing else, which states no compliance at all. That is the defect
`security_profile_findings._subject` carries in the other direction - a closing fall-through to
"blocks critical and high threats", reached by every kind that writes no severity-verdict row, so a
FAILING profile gets a reassuring sentence - and it is checked for rather than assumed absent here.

WHAT NO SENTENCE ON THIS SUBJECT CAN SAY, and it is the half a reader should be told about:
whether an exemption belongs to one of the organization's declared classes. Nothing on the firewall
records that - a rule holds its match criteria and its own free text, and the class is a fact about
the organization's policy - so PAN-DEC-002's second half is delivered as the INVENTORY of what each
exempting rule is keyed on, which is what lets a reader do the classification, rather than as a
judgment that a particular rule belongs to no class.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_decryption_policy_rule_control_queries
from assessments.models import (
    Control,
    DecryptionPolicyRuleFinding,
    DecryptionPolicyRuleFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import DecryptionPolicyRule


def _members(obj, accessor: str) -> str:
    """One criterion's members, in the device's own order, or the word for holding none.

    A ROW SET AND NOT A COLUMN: each of the five criteria is stored as rows of its own child
    model, so this reads a related manager rather than a field. Holding NO rows is a real state
    and it is not the same as holding `any` - a criterion nobody collected has no rows, while an
    absent key on a collected rule has `any` MATERIALISED for it where the vendor's default is
    measured. The two read identically on the device and differently here, which is why the
    normalizer also records the list NODE's own provenance on the rule.
    """
    values = [m.value for m in getattr(obj, accessor).all()]
    return ", ".join(f"`{v}`" for v in values) if values else "nothing this reader could resolve"


def _unbounded_content_criterion(obj) -> list[str]:
    """PAN-DEC-002's first half: the risky content classes are not among the traffic left
    encrypted."""
    return [
        "THIS RULE LEAVES TRAFFIC ENCRYPTED AND ITS CONTENT CRITERION IS UNBOUNDED - it names "
        f"{_members(obj, 'decryptionpolicyrulecategorys')}, which includes the keyword `any` - so "
        "every content class it reaches is left unopened, the classes most used to deliver "
        "attacks among them. An ABSENT key means every URL category here, measured, so a rule "
        "nobody bounded reads the same way as one somebody set to `any` on purpose",
        "THE INSPECTION STACK REPORTS CLEAN ABOUT WHAT THIS RULE PASSES. Malware, exploit, "
        "command-and-control, web-category and file-type inspection all run on the inside of a "
        "session, so for the traffic this rule matches none of them sees anything and the threat "
        "reports stay clean because the attack was never visible to them",
        "AND A NAMED MEMBER MAY BE NARROWER THAN IT READS. A content class a rule names may be a "
        "custom category object whose own members are other classes, and that object is an "
        "INTERSECTION rather than a union - the vendor's own worked procedure blocks the combined "
        "object while leaving each constituent class at a permitting action. So coverage read off "
        "the member names OVERSTATES what is opened, and an inventory of what is exempt is a "
        "LOWER BOUND",
    ]


def _keyed_on_nothing(obj) -> list[str]:
    """PAN-DEC-002's second half: an exemption keyed on no criterion at all."""
    return [
        "EVERY ONE OF THIS RULE'S FIVE MATCH CRITERIA IS UNBOUNDED - content "
        f"{_members(obj, 'decryptionpolicyrulecategorys')}, source "
        f"{_members(obj, 'decryptionpolicyrulesources')}, destination "
        f"{_members(obj, 'decryptionpolicyruledestinations')}, user "
        f"{_members(obj, 'decryptionpolicyrulesourceusers')} and service "
        f"{_members(obj, 'decryptionpolicyruleservices')} - so it is an exemption keyed on "
        "nothing at all and belongs to no class of exemption anybody could declare",
        "WHAT THIS CONTROL CANNOT TELL YOU IS WHETHER IT BELONGS TO A DECLARED CLASS. Nothing on "
        "the firewall records that: a rule holds its criteria and its own free text, and the "
        "class is a fact about the organization's written policy. What is delivered is the "
        "inventory of what each exempting rule is keyed on, which is what lets a reader do the "
        "classification - the judgment that a particular rule belongs to no class should wait "
        "for the class list",
        "THE FIVE SIBLING CONTROLS EACH OWN ONE DECLARED CLASS and defer to this one only for the "
        "wider claim that there is no undeclared sixth: a throughput exemption is PAN-DEC-003's, "
        "a compatibility one PAN-DEC-004's, a privacy one PAN-DEC-005's, a people-keyed one "
        "PAN-DEC-006's and a segment-keyed one PAN-DEC-007's",
    ]


def _no_written_reason(obj) -> list[str]:
    """PAN-DEC-003: a throughput exemption carries no justification and no review date."""
    return [
        "THIS RULE LEAVES TRAFFIC ENCRYPTED AND CARRIES NO DESCRIPTION, so nothing on it says why "
        "the exemption exists, which application or path it was granted for, or when anybody is "
        "due to look at it again. The device checks neither, and the description is the only "
        "place on a decryption rule that can hold either",
        "AN EXEMPTION WITH NO STATED REASON CANNOT BE RETIRED, which is the harm rather than the "
        "untidiness: nobody who did not create it can tell whether the throughput problem that "
        "justified it still exists, so an accommodation granted for one appliance generation "
        "survives every upgrade that would have let it be removed",
        "WHETHER THE EXEMPTION IS BOUNDED TIGHTLY ENOUGH IS NOT ASSERTED HERE. Stage 3 grades a "
        "destination aggregate of /8 or wider above a narrow named object, and NOTHING IN THE "
        "CONFIGURATION MEASURES HOW LARGE AN ADDRESS OBJECT IS - an eight-bit prefix and a "
        "thirty-bit prefix are the same field with the same shape. That arithmetic belongs to "
        "PAN-POL-002, which is not built, so two of this control's graded bands carry no severity "
        "at all",
    ]


def _privacy_carve_out_keyed_on_addresses(obj) -> list[str]:
    """PAN-DEC-005: a privacy carve-out keyed on addresses rather than on content classes."""
    return [
        "THIS RULE IS A CARVE-OUT KEYED ON ADDRESSES AND NOT ON CONTENT - its content criterion "
        f"names {_members(obj, 'decryptionpolicyrulecategorys')}, which includes `any`, while its "
        f"source names {_members(obj, 'decryptionpolicyrulesources')}, which does not. A privacy "
        "exemption that names a network rather than a content class exempts everything those "
        "hosts do, not the sensitive traffic the written policy meant to protect",
        "A CATEGORY-KEYED CARVE-OUT IS CHECKABLE AGAINST COUNSEL'S OWN LIST and an address-keyed "
        "one is not: the jurisdictions and the content classes are what a written privacy policy "
        "names, and an address list has to be re-derived from an inventory every time anybody "
        "asks what is exempt",
        "THE DESTINATION-KEYED FORM OF THE SAME DEFECT IS NOT REPORTED BY THIS CONTROL. A rule "
        "whose content criterion is unbounded and whose DESTINATION is a named object is the same "
        "carve-out written the other way round, and expressing both in one query would need an OR "
        "between two clause groups that the query grammar does not have. The configuration stands "
        "on the lab as `oep-dec6-r12` and is recorded in the stage 8 artifact rather than "
        "silently read as compliance",
    ]


def _exempt_population_is_a_keyword(obj) -> list[str]:
    """PAN-DEC-006: the exempt user population is a device keyword rather than a reviewable
    group."""
    return [
        "THE PEOPLE THIS RULE EXEMPTS ARE NAMED BY A DEVICE KEYWORD AND NOT BY A GROUP - its user "
        f"criterion names {_members(obj, 'decryptionpolicyrulesourceusers')}, every member of "
        "which is one of the four keywords the platform offers - so there is no membership list "
        "anybody can audit, recertify or hand to a reviewer. `any` exempts everyone the rule "
        "otherwise matches, `known-user` is the whole authenticated workforce by the vendor's own "
        "description, `unknown` is whoever identity mapping missed and cannot be enumerated at "
        "all, and `pre-logon` is a machine state rather than a set of people",
        "AN ATTACKER LANDING IN AN EXEMPT POPULATION INHERITS INSPECTION-FREE EGRESS, which is "
        "what makes the membership list the control rather than the rule",
        "AND THIS FINDING CANNOT TELL A DIRECTORY GROUP FROM ONE INDIVIDUAL. A member outside the "
        "four keywords is a free principal string of unknown kind: the device's own reference for "
        "this field points at the LOCAL user database rather than at the directory, and the read "
        "that would resolve it is PAN-UID-001's `show user group list`, which is not built. A "
        "rule naming such a member is NOT reported by this control, and that silence is a gap "
        "rather than a pass",
    ]


def _inverted_source_match(obj) -> list[str]:
    """PAN-DEC-007: the source match is inverted, so the named segment is the only one
    inspected."""
    return [
        "THIS RULE'S SOURCE MATCH IS INVERTED. It names "
        f"{_members(obj, 'decryptionpolicyrulesources')} and the negate switch is set, so the "
        "addresses it names are the ONLY ones NOT exempted - every other host the rule reaches "
        "has its sessions left encrypted. A reader of the grid sees a narrow address list and the "
        "device applies its complement",
        "A SEGMENT CARVE-OUT IS SUPPOSED TO BE THE NAMED SEGMENT AND NOTHING ELSE, which is what "
        "the inversion reverses: the exemption stops being a bounded list of OT, IoT, guest or "
        "medical-device networks and becomes everything except them",
        "THE POLARITY IS STORED AS THE VENDOR WRITES IT AND THE ABSENT STATE IS ASSUMED RATHER "
        "THAN MEASURED. No oracle stage 4 reached rendered this key, so `no` is inferred from the "
        "security rulebase's measured absent-means-no plus the commit-validation refusal "
        "\"Negate cannot be enabled ... with source address as 'any'\" - which only makes sense if "
        "absence means no. The report prints the value as not measured for that reason. Stage 7 "
        "later measured that `show running decryption-policy` DOES render it, as a `(negate)` "
        "suffix on the source member, and that promotion is a person's call between domains",
        "AND THAT SAME REFUSAL IS WHY THE `any` BAND OF THIS CONTROL'S GRADING MATCHES NOTHING ON "
        "A COMMITTED DEVICE: the firewall will not accept an inverted match beside the keyword "
        "`any`, so the two states cannot co-occur in a running configuration. The query is "
        "shipped rather than dropped because the read behind this row is candidate-derived and a "
        "STAGED rule can reach the combination",
    ]


def _no_profile_on_an_exempt_rule(obj) -> list[str]:
    """PAN-DEC-008: an exempt rule attaches no decryption profile, so no certificate check runs."""
    return [
        "THIS RULE LEAVES TRAFFIC ENCRYPTED AND ATTACHES NO DECRYPTION PROFILE, so the baseline "
        "TLS checks that survive an exemption do not run on it: nothing refuses a session "
        "presenting an expired certificate or one from an untrusted issuer. Traffic exempted from "
        "DECRYPTION can still be VALIDATED, and on this rule it is not",
        "EMPTY DOES NOT MEAN NOTHING IS APPLIED IN GENERAL, which is why this control confines "
        "itself to rules that leave traffic encrypted: stage 4 measured the device resolving an "
        "absent profile to the predefined profile named `default` once the action moved to "
        "`decrypt` on the inbound branch, and to nothing on an exempting rule. The applicability "
        "clause is that condition",
        "WHAT THIS CANNOT SAY IS WHETHER AN ATTACHED PROFILE ACTUALLY REFUSES ANYTHING. The two "
        "refusals are children of the decryption profile's own no-decryption container, there is "
        "no decryption-profile object in this domain's model at all, and an attachment with no "
        "effect is indistinguishable in outcome from having no profile attached - while reading "
        "as COMPLIANT on this half. Stage 3 grades both missing refusals and neither band has a "
        "column to rest on; the profile's own content is PAN-DCP-005's",
    ]


def _failed_handshake_record_off(obj) -> list[str]:
    """PAN-DEC-010's first half: the failed-handshake record is switched off on this rule."""
    return [
        "THE FAILED-HANDSHAKE RECORD IS SWITCHED OFF ON THIS RULE. Somebody wrote `log-fail: no` "
        "and committed it, which is a decision rather than a default: an ABSENT key means YES "
        "here, measured on the grid in both directions and confirmed by the vendor on two pages, "
        "so an unedited rule keeps the record and does not appear in this finding",
        "FAILED HANDSHAKES ARE WHERE COVERAGE GAPS SURFACE. A rule whose decryption is failing "
        "quietly looks identical, from every other dataset, to one whose traffic nothing matched "
        "- so turning this off removes the one signal that distinguishes a broken exemption from "
        "an absent one",
        "THIS HALF COVERS EVERY RULE IN THE RULEBASE AND NOT ONLY THE EXEMPTING ONES, which is "
        "stage 3's own scope: the record matters on a rule that opens the session and on one that "
        "does not",
    ]


def _successful_session_record(obj) -> list[str]:
    """PAN-DEC-010's second half: the record of a successful session, and whether anything carries
    it off the firewall."""
    disposition = obj.success_record_disposition
    if disposition == DecryptionPolicyRule.RECORD_NONE:
        found = (
            "THIS RULE OPENS SESSIONS AND KEEPS NO RECORD OF THE ONES THAT SUCCEED. "
            "`log-success` is off - which is what the vendor documents as the default, so this is "
            "the state of an unedited rule rather than somebody's decision - so the dataset that "
            "would carry TLS version, cipher, SNI and certificate details for this traffic does "
            "not exist at all. There is nothing to forward and nothing to search")
    elif disposition == DecryptionPolicyRule.RECORD_KEPT_NOT_FORWARDED:
        found = (
            "THIS RULE KEEPS THE RECORD OF A SUCCESSFUL SESSION AND NAMES NOTHING TO CARRY IT OFF "
            "THE FIREWALL. `log-success` is on and `log-setting` is empty, so the observation "
            "exists and is readable on the appliance - what is lost is retention and central "
            "search, which is why this is graded below the rule that keeps no record at all. The "
            "estate's log forwarding generally is PAN-LOG-005's and PAN-LOG-009's")
    else:
        found = (
            "THIS RULE OPENS SESSIONS AND ITS SUCCESSFUL-SESSION RECORD READS "
            f"`{disposition or 'as nothing this reader could resolve'}`, which is neither of the "
            "two states this control asserts over")
    return [
        found,
        "THE ATTACHMENT IS NOT THE DELIVERY, and this row can only ever answer the first. Whether "
        "a log-forwarding profile named on an ordinary decryption rule forwards anything at all "
        "is unsettled in the vendor's own documentation, and that contradiction is on file - so "
        "even the compliant state here is CONFIGURATIONALLY compliant rather than demonstrated",
        "THE POPULATION IS RULES THAT OPEN THE SESSION, which is both of the actions that do. "
        "That is a disjunction the query grammar cannot write - there is no `or` inside a clause "
        "and no `in` operator - so it is read from a derived column whose default is the "
        "INCLUSIVE side: a rule nobody recomputed is assessed rather than silently excluded",
    ]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE, keyed by control id. THE DEFAULT IS `()` - see the
#: module docstring for the measurement behind that choice and for the two hazards a non-empty
#: default carries.
PARTS_BY_CONTROL = {
    "PAN-DEC-002": (_unbounded_content_criterion, _keyed_on_nothing),
    "PAN-DEC-003": (_no_written_reason,),
    "PAN-DEC-005": (_privacy_carve_out_keyed_on_addresses,),
    "PAN-DEC-006": (_exempt_population_is_a_keyword,),
    "PAN-DEC-007": (_inverted_source_match,),
    "PAN-DEC-008": (_no_profile_on_an_exempt_rule,),
    "PAN-DEC-010": (_failed_handshake_record_off, _successful_session_record),
}


def _owner(obj) -> str:
    point = obj.enforcement_point
    appliance = point.appliance
    owner = str(appliance.hostname if appliance is not None else point.appliance_group)
    return f"{owner} / {point.vsys_name}"


def _subject(obj, control_id: str) -> str:
    parts = [
        f"decryption rule {obj.rule_name} in {_owner(obj)}, rule {obj.rule_position} of the "
        f"{obj.get_config_source_display().lower()} decryption rulebase with "
        f"`action: {obj.action or 'no value this reader could resolve'}` on the "
        f"`{obj.type_branch or 'no'}` branch"
    ]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_decryption_policy_rule_finding_summary(obj, matched_queries) -> str:
    """The control id comes from `control.control_id` by way of the matched queries, which can
    only ever be one control's: `generate_object_findings` runs one control at a time and creates
    the finding with that same control. The loop is a redundant spelling of it and is left alone
    because the shipped siblings all carry it."""
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="decryption policy rule",
    control_type=Control.ControlType.DECRYPTION_POLICY_RULE,
    finding_model=DecryptionPolicyRuleFinding,
    link_model=DecryptionPolicyRuleFindingControlQuery,
    subject_fk="decryption_policy_rule",
    link_fk="decryption_policy_rule_finding",
    # The five member criteria are prefetched because every control's sentence reads at least one
    # of them, and `generate_object_findings` loads each matched object once across controls.
    queryset=lambda: DecryptionPolicyRule.objects.select_related(
        "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group",
    ).prefetch_related(
        "decryptionpolicyrulecategorys", "decryptionpolicyrulesources",
        "decryptionpolicyruledestinations", "decryptionpolicyrulesourceusers",
        "decryptionpolicyruleservices"),
    evaluate=evaluate_decryption_policy_rule_control_queries,
    summary=build_decryption_policy_rule_finding_summary,
    # The rule's own entry name. NOT `obj.name`, which this model does not have - the dataclass
    # default would import cleanly, pass every registry check and raise `AttributeError` inside
    # `generate_object_findings` the first time a query matched a row.
    subject_name=lambda obj: obj.rule_name,
    # The appliance, the vsys AND the rulebase. A rule name is unique only per point and rulebase -
    # the shipped constraint is `(enforcement_point, config_source, rule_name)` - so a local rule
    # and a Panorama pre-rule of the same name are different objects a reader must tell apart.
    subject_scope=lambda obj: f"{_owner(obj)} / {obj.config_source}"[:128],
)


def generate_decryption_policy_rule_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_decryption_policy_rule_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
