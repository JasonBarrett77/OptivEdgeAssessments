"""Finding generation for one appliance's departures from the vendor's SSL exclusion list.

NO SHIPPED CONTROL PRODUCES ONE OF THESE, so this generator writes nothing today, and that is a
recorded state rather than dead code left behind - the same position `lldp_global_findings` is in,
and registered for the same reason `finding_run.GENERATORS` exists at all: that tuple has fallen
behind `finding_registry` twice without anything failing, and a finding model whose generator is
added later is exactly the shape that slipped.

WHY NO CONTROL TARGETS IT. PAN-DEC-004's two assertion records name two subjects - the exclusions
the organisation added itself, and these departures from the VENDOR's supplied list -
`_CONTROL_TYPE_TARGET_MODEL` maps one type to one model, and `ControlQuery.clean()` refuses a query
whose model differs from its control's target, so one catalogue id cannot hold both halves. The
exclusion half took the id: the catalogue row's own severity is medium and its `minimum_value_descr`
is about the local list, which is stage 3's record 0, while this is the `preferred_gap_severity`
half at low. And there is no walk between the two models to reach this half through -
`probe.relation_between SslDecryptionExclusion SslDecryptionVendorExclusionOptOut` finds NO RELATION
IN EITHER DIRECTION: six paths through shared ancestors, every one to-many and every one leaving a
scope field unconstrained, which is a WRONG ROW rather than an understated severity. Splitting
PAN-DEC-004 into two catalogue ids changes what a customer's report contains and is Jason's
decision.

AND NO ESTATE CAN MAKE THIS HALF FIRE TODAY, which is the sharper reason not to invent a control for
it now. The one clean assertion is that no switched-off entry is left on the list after the vendor
stopped shipping it, and that is a SET DIFFERENCE whose right-hand side - the vendor's own catalogue
- is invisible to `action=get` and to the merged configuration. Measured on all four lab appliances:
the config read a collector naturally reaches for answers a well-formed, TRUTHY, EMPTY count
envelope (`{"@total-count": "0", "@count": "0"}`) for a populated vendor list, `action=show` at the
same xpath denies the node exists, and only the `show predefined` OPERATIONAL read returns the 330
or 385 entries. Nothing issues that read on a collection run, so
`stale_disabled_vendor_exclusion_count` is zero on every row in every estate - and the normaliser
does not even compute the difference when the snapshot is absent, because a `set()` right-hand side
would make every switched-off entry look stale, which is the loudest possible false finding on
exactly the appliances that are fine.

WHAT THE SENTENCE WOULD SAY, AND IT IS NOT "SOMEBODY SWITCHED A VENDOR EXCLUSION OFF". The direction
is the opposite of the obvious reading: the vendor's own screen says the Disable control
"effectively removes support for the applications because they break decryption" and is there "to
ensure certain encrypted applications do not enter your network". That is a HARDENING act, so a
non-empty list is a review item and not a gap - and the arms below say so in those terms. What IS a
gap is the stale residue, and the vendor supplies the mechanic that makes it accumulate: an entry
left switched OFF stays on the list even after a content update stops defining it, while a
switched-ON one is removed automatically, so the residue gathers on exactly the entries an
administrator touched.

AND ZERO ON THAT COLUMN MEANS TWO THINGS A READER CANNOT TELL APART. Stage 5 declared no "did
anybody look" companion and took that concession deliberately, with the reasons written out; stage 7
filed the missing `predefined_list_collected` boolean as a gap and named the two shipped precedents
for its shape, `LoggingSettings.central_store_status_collected` and
`HighAvailabilityConfig.ha_runtime_state_collected`. `normalize_ssl_decryption_vendor_exclusion_
optout`'s return value carries the fact where no column can.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_ssl_decryption_vendor_exclusion_optout_control_queries,
)
from assessments.models import (
    Control,
    SslDecryptionVendorExclusionOptOutFinding,
    SslDecryptionVendorExclusionOptOutFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import SslDecryptionVendorExclusionOptOut


def _stale_departures(obj) -> list[str]:
    """What PAN-DEC-004's second record would say, if a control ever carried it."""
    return [
        f"{obj.stale_disabled_vendor_exclusion_count} of the "
        f"{obj.disabled_vendor_exclusion_count} vendor-supplied SSL decryption exclusion(s) "
        "switched off on this appliance NAME SERVERS THE VENDOR NO LONGER SHIPS AN ENTRY FOR, so "
        "they are enforcing a judgement about a product the vendor has since reassessed and "
        "nothing will remove them automatically",
        "SWITCHING ONE OFF IS A HARDENING ACT AND NOT A WEAKENING ONE, which is the direction the "
        "obvious reading gets backwards: the vendor's own screen says the option effectively "
        "removes support for applications that break decryption, and is there to ensure certain "
        "encrypted applications do not enter the network. So a non-empty list is a REVIEW ITEM "
        "and the stale residue is the part that is a defect",
        "AND THE RESIDUE GATHERS ON EXACTLY THE ENTRIES SOMEBODY TOUCHED. An entry left switched "
        "OFF stays on the list after a content update stops defining it, while a switched-ON one "
        "is removed automatically - so this count grows silently and only on the entries an "
        "administrator made a decision about",
        "WHETHER EACH DEPARTURE WAS DELIBERATE IS THE ORGANISATION'S ANSWER AND NO COLUMN HOLDS "
        "IT. The list records the departure and nothing about the reason for it; what is "
        "delivered is which entries are switched off and which of those the vendor no longer "
        "ships",
        "AND A ZERO ON THIS COUNT MEANS TWO THINGS THAT CANNOT BE TOLD APART FROM THE ROW: that "
        "no departure is stale, and that the vendor's own catalogue was never read. Only the "
        "`show predefined ssl-exclude-cert` operational read supplies that catalogue - the config "
        "read a collector reaches for answers a truthy, EMPTY count envelope for a populated list "
        "on every appliance measured - and nothing issues it on a collection run, so today it is "
        "the second reading on every row in every estate",
    ]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. EMPTY, because no control targets this type, and
#: `()` is the default for the same reason the sibling modules give: an arm tuple reached by a
#: control id nobody registered is how a finding gets somebody else's claims. `_stale_departures`
#: above is what the sentence WOULD be and is wired to nothing - deliberately, so that the prose
#: and the model land together and whoever splits PAN-DEC-004 adds one line here rather than
#: writing a generator from nothing.
PARTS_BY_CONTROL: dict[str, tuple] = {}


def _subject(obj, control_id: str) -> str:
    parts = [
        f"the vendor SSL decryption exclusion opt-outs on {obj.appliance.hostname}, "
        f"{obj.disabled_vendor_exclusion_count} entry/entries switched off"
    ]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_ssl_decryption_vendor_exclusion_optout_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="SSL decryption vendor exclusion opt-out",
    control_type=Control.ControlType.SSL_DECRYPTION_VENDOR_EXCLUSION_OPTOUT,
    finding_model=SslDecryptionVendorExclusionOptOutFinding,
    link_model=SslDecryptionVendorExclusionOptOutFindingControlQuery,
    subject_fk="ssl_decryption_vendor_exclusion_optout",
    link_fk="ssl_decryption_vendor_exclusion_optout_finding",
    queryset=lambda: SslDecryptionVendorExclusionOptOut.objects.select_related("appliance"),
    evaluate=evaluate_ssl_decryption_vendor_exclusion_optout_control_queries,
    summary=build_ssl_decryption_vendor_exclusion_optout_finding_summary,
    # The appliance. NOT `obj.name`, which this model does not have - the node is a bare member
    # list with no entry to be one row per, so the row is one per appliance and the hostname is the
    # whole of what names it. The dataclass default would raise inside generation, not at import.
    subject_name=lambda obj: obj.appliance.hostname,
    # NO `subject_scope`, and that is correct rather than an omission: the node has a SHARED
    # spelling only - measured at both scopes, the vsys one does not have it - so there is no
    # partition for a scope to name. ON AN HA PAIR THIS YIELDS TWO ROWS FOR ONE REAL CONFIGURATION
    # and the hostname is what tells them apart.
)


def generate_ssl_decryption_vendor_exclusion_optout_findings(
    assessment_run,
) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_ssl_decryption_vendor_exclusion_optout_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
