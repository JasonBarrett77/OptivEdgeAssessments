"""Finding generation for the SaaS URL-filtering controls. PAN-SAS-002 and PAN-SAS-004.

TWO CONTROLS ON ONE ROW AND THEY FAIL INDEPENDENTLY, so the parts are mapped per control rather
than concatenated: a partition can insert a tenant-restriction header on the traffic and still
leave the consumer-storage web categories in no restricting list at all, and a reader of either
finding must not be sent to the other control's screen.

THE FIRST SENTENCE THE CODE MUST NOT WRITE IS "no header insertion is configured", and it is the
sharpest reading in this domain. In the collected payload "no header insertion" and
"url-filtering was never collected" are THE SAME ABSENCE. `url_filtering_profiles_read` is what
separates them, and where it is false the sentence says nobody looked - never that nothing is
configured. A control firing on the first without that split fires on every appliance in every
estate.

THREE MORE THINGS THE SENTENCE IS NOT ALLOWED TO SAY:

* THAT THE TENANT IDENTIFIER IS WRONG. The device stores whatever string it is given and cannot
  tell a correct tenant identifier from a plausible wrong one - for the Microsoft case the value
  comes from the customer's own cloud directory and from no firewall screen. So the finding
  reports presence, attachment and coverage, and the correctness of each identifier stays with
  the engineer's question. What the code CAN say is that a header names no tenant at all, which
  is `tenant_header_without_value_count`.
* THAT THE REMEDIATION IS ON THIS FIREWALL. Every url-filtering profile actually present on the
  lab appliances is Panorama-pushed, and a pushed profile is in the firewall's own container
  under no configuration read - so the sentence names the possibility rather than asserting a
  node an engineer can edit.
* THAT A CATEGORY IS PERMITTED ON PURPOSE. `in-no-restricting-list` means the category appears in
  no list at all, which the configuration cannot tell from a deliberate decision to permit: a
  predefined category explicitly set to permit is never written. The two read identically and the
  sentence says which one it saw.

AND ONE IT MUST SAY: `alert` IS NOT A RESTRICTION. The visit happens and is merely recorded,
which is why stage 3 grades it below the permitting values rather than with the restricting ones
- and a reader seeing a LOW finding needs to know the exposure is unchanged and only the record
of it exists.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_saas_url_filtering_posture_control_queries,
)
from assessments.models import (
    Control,
    SaasUrlFilteringPostureFinding,
    SaasUrlFilteringPostureFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import SaasUrlFilteringPosture

#: What the finding calls each treatment rank, in the reader's words rather than the config key's.
TREATMENT_PROSE = {
    SaasUrlFilteringPosture.TREATMENT_IN_NO_RESTRICTING_LIST: (
        "appears in no restricting list of any profile this partition can reach, so it is "
        "permitted by default - and the configuration cannot tell that from a deliberate "
        "decision to permit it, because a predefined category explicitly set to permit is "
        "never written"),
    SaasUrlFilteringPosture.TREATMENT_ALLOW: (
        "is permitted by an explicit `allow` entry"),
    SaasUrlFilteringPosture.TREATMENT_ALERT: (
        "is permitted and merely recorded by an `alert` entry - the visit happens, so the "
        "exposure is unchanged and what exists is a record of it"),
    SaasUrlFilteringPosture.TREATMENT_CONTINUE: (
        "is interrupted by a response page the user has to accept"),
    SaasUrlFilteringPosture.TREATMENT_OVERRIDE: (
        "is held behind a password"),
    SaasUrlFilteringPosture.TREATMENT_BLOCK: (
        "is refused outright"),
}


def _nobody_looked(obj) -> list[str]:
    """The sentence every part below defers to. False here is not a configuration reading."""
    return ["NOBODY LOOKED: no URL Filtering profile reachable from this partition was found in "
            "any read, and in the collected payload a partition with no profile and a partition "
            "nobody collected are the same absence. Nothing below is a reading of the "
            "configuration"]


def _tenant_restriction(obj) -> list[str]:
    if not obj.url_filtering_profiles_read:
        return _nobody_looked(obj)
    if obj.tenant_restriction_in_force:
        return []
    parts = []
    if obj.header_insertion_type_entry_count:
        parts.append(
            f"{obj.header_insertion_type_entry_count} HTTP header-insertion type entr(ies) "
            f"exist on the profiles this partition can reach and none that inserts a "
            f"tenant-restriction header is carried by a security rule of this partition - so the "
            f"restriction is defined and not in force. The unit of coverage is the TYPE entry: "
            f"one header-insertion entry carries exactly one type, so covering N applications "
            f"takes N sibling entries")
    else:
        parts.append(
            "no profile this partition can reach inserts a tenant-restriction header into the "
            "traffic, so nothing confines these applications to the corporate account")
    if obj.tenant_header_without_value_count:
        parts.append(
            f"{obj.tenant_header_without_value_count} header entr(ies) name a header and carry "
            f"NO value - a tenant restriction that names no tenant, which reads as configured "
            f"and restricts nothing")
    if obj.rule_bound_tenant_list_count:
        parts.append(
            f"{obj.rule_bound_tenant_list_count} rule(s) of this partition do reference a SaaS "
            f"Tenant List object, which is the native route where it is supported - but nothing "
            f"here reads how many tenants such a list names, and a list carrying no members "
            f"commits and restricts nothing")
    parts.append(
        "WHERE THE PROFILE IS PUSHED FROM PANORAMA the remediation is not on this firewall: a "
        "pushed url-filtering profile is in no firewall-local container and this row does not "
        "record which scope a definition came from")
    # NOT a claim about the identifier. The device cannot tell a correct tenant identifier from a
    # plausible wrong one, so the engineer's question carries that half.
    parts.append(
        "whether an identifier a header does carry is the organization's OWN account is not "
        "readable from any firewall and is the engineer's answer")
    return parts


def _categories(obj) -> list[str]:
    if not obj.url_filtering_profiles_read and (
            obj.consumer_storage_category_treatment
            == SaasUrlFilteringPosture.TREATMENT_IN_NO_RESTRICTING_LIST):
        return _nobody_looked(obj) + [
            "the weakest treatment reads as `in-no-restricting-list`, which is also what an "
            "unenumerated partition holds"]
    if obj.consumer_storage_categories_are_restricted:
        return []
    treatment = obj.consumer_storage_category_treatment
    prose = TREATMENT_PROSE.get(
        treatment, f"is recorded as `{treatment}`, which no ordering in this control ranks")
    return [f"the weakest-treated of the web categories that carry consumer file storage and "
            f"personal publishing {prose}. The verdict is the weakest link across those "
            f"categories and across every profile this partition can reach, because a "
            f"permissive profile that also applies leaves the category reachable",
            "TWO RESTRICTING SURFACES ARE NOT IN THIS READING and a category reachable only "
            "through one of them is restricted in fact: the block-response list and remote "
            "browser isolation, neither of which has a measured place in the order"]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. Two controls on one row, and a finding describes
#: what ITS OWN control asserts: a tenant-restriction finding that also reported the category
#: treatment would send a reader to Objects > Security Profiles > URL Filtering > Categories for
#: a defect in HTTP Header Insertion.
PARTS_BY_CONTROL = {
    "PAN-SAS-002": (_tenant_restriction,),
    "PAN-SAS-004": (_categories,),
}


def _subject(obj, control_id: str) -> str:
    appliance = obj.enforcement_point.appliance or obj.enforcement_point.appliance_group
    parts = [f"SaaS URL filtering posture of {obj.enforcement_point.vsys_name} on {appliance}"]
    for build in PARTS_BY_CONTROL.get(control_id, (_tenant_restriction, _categories)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_saas_url_filtering_posture_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


def _appliance_scope(obj) -> str:
    appliance = obj.enforcement_point.appliance
    return str(appliance.hostname if appliance is not None
               else obj.enforcement_point.appliance_group)


SPEC = ObjectFindingSpec(
    label="SaaS URL filtering posture",
    control_type=Control.ControlType.SAAS_URL_FILTERING_POSTURE,
    finding_model=SaasUrlFilteringPostureFinding,
    link_model=SaasUrlFilteringPostureFindingControlQuery,
    subject_fk="saas_url_filtering_posture",
    link_fk="saas_url_filtering_posture_finding",
    queryset=lambda: SaasUrlFilteringPosture.objects.select_related(
        "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group"),
    evaluate=evaluate_saas_url_filtering_posture_control_queries,
    summary=build_saas_url_filtering_posture_finding_summary,
    subject_name=lambda obj: obj.enforcement_point.vsys_name,
    subject_scope=_appliance_scope,
)


def generate_saas_url_filtering_posture_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_saas_url_filtering_posture_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
