"""Engineer-detail xlsx, prototype: the remaining findings tabs, one per control type.

Jason, 2026-09-18: "Create the rest of the Findings tab. Follow the same column pattern as the
existing tabs." Fifteen domains were left: four device-wide settings and eleven named objects.

ONE MODULE, NOT FIFTEEN. Each is a `DeviceSettingSheet` differing only in its control type, its
domain sentence and which columns name the subject - so they are a TABLE here rather than fifteen
files repeating the same four lines. The four earlier tabs keep their own modules because each
carries an argument worth reading next to it (the sentinel zeros, the derived SSH verdicts, the
clean SNMP controls).

THREE SUBJECT SHAPES, which is what the pattern actually varies by:
- DEVICE-WIDE: the appliance is the subject. Login banner, master key, update server, logging.
  Jason, 2026-09-18: do NOT fold these into Device Services - each is its own question.
- NAMED ON AN APPLIANCE: a name, and for the scoped ones the scope it lives in (`shared`, or the
  vsys). A name is not unique across scopes - `TLSv1.3_Default` exists as both predefined and
  shared - so the scope column is part of the identity, not decoration.
- SCOPED TO A VSYS: security profiles belong to an enforcement point, like security rules, so they
  name the firewalls that run it rather than one appliance.

The settings columns, the marked value, the provenance and the metadata are the shared machinery's
- see `findings_sheet`.
"""
from __future__ import annotations

from assessments.models import Control

from optivedge_integrations.integrations.models import AddressObject, SecurityProfile

from assessments import decryption_policy_presentation as decryption_policy
from assessments import device_id_presentation as device_id
from assessments import device_services_presentation as device_services
from assessments import globalprotect_gateway_presentation as globalprotect_gateway
from assessments import globalprotect_portal_presentation as globalprotect_portal
from assessments import ha_panorama_presentation as ha_panorama
from assessments import ike_presentation as ike
from assessments import ipsec_presentation as ipsec
from assessments import logging_presentation as logging
from assessments import network_hardening_presentation as network_hardening
from assessments import platform_lifecycle_presentation as platform_lifecycle
from assessments import user_id_presentation as user_id

from . import findings as findings_sheet
from ..layout import NONE, SheetInfo, appliance_names, ha_role

T = Control.ControlType


def scope_of(obj) -> str:
    """Where a scoped object lives: its vsys, or the scope name where it is not vsys-scoped."""
    scope = getattr(obj, "scope", "") or ""
    vsys = getattr(obj, "vsys_name", "") or ""
    if scope == "vsys":
        return vsys or scope
    return scope or NONE


#: The appliance and its HA role - every device-wide sheet, and the anchor of every named one.
APPLIANCE = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
)

#: A named object on an appliance. Scope and kind are added only where the model has them. Each
#: declares the FIELD it presents, so a control testing that field marks this cell rather than
#: adding a second column of the same name - which is not merely untidy: a table with a duplicate
#: header is rejected by Excel, and xlsxwriter drops it with a warning, leaving a sheet of stray
#: cells where the table should be (seen 2026-09-18 on AAA Server Profile and Security Profile).
NAME = (("Object", None, False, lambda s, _p: s.name or NONE, "name"),)

def _device_content_total(obj) -> str:
    """Whether the DEVICE ever answered about an imported list's content, and with what total.

    THE WHOLE POINT OF THE COVERAGE DOMAIN RESTS ON THIS COLUMN and until 2026-11-02 it reached
    no cell on this tab. `scratch/control-changes.json` states the distinction in these terms:
    "An object with no size looks identical whether NOBODY ASKED or the DEVICE ANSWERED AND
    FAILED. Only the first is ours. The second is a real device defect - the rule enforces
    against a list the firewall cannot download - and is PAN-POL-023, unbuilt. They are told
    apart by `resolved_content_source_total`: set means the device answered."

    The finding sentence declines to choose between them - it says the firewall "has never
    fetched it, OR a fetch was attempted and returned nothing usable" - and no clause on this
    control reads the column, so `tested_fields` derives no settings column for it. Without this
    cell a reader is handed both diagnoses and nothing to pick between them, and the two need
    opposite remediations: ours is to run the cache refresh, theirs is a list the firewall cannot
    download.

    An em dash where the branch does not exist, which is `layout.NONE` and is what the shared
    `display_value` has no way to say: only an imported list has a device-reported content total
    at all, so a name-based or literal object is not unmeasured here, it is inapplicable.
    """
    if obj.address_type != AddressObject.TYPE_EDL:
        return NONE
    total = obj.resolved_content_source_total
    # Not "(none)": `display_value` would print that, and the whole reason this column exists is
    # that a reader cannot tell a NULL from a zero-sized answer. A NULL here is the device never
    # having answered, which is the sentence to say.
    return "Device did not answer" if total is None else f"{total:,}"


#: Coverage findings name an address object, which hangs off an enforcement point or an
#: appliance group rather than an appliance - so APPLIANCE, which reads `s.appliance`, does not
#: apply. "Where" carries whichever owner it has.
#:
#: "Device's own count" is EVIDENCE rather than identity, and it sits here for the same reason
#: the IKE sheet keeps "Key lifetime (as set)" beside its derived column: no clause on either
#: PAN-COV control reads `resolved_content_source_total`, so nothing derives a column for it, and
#: it is what the remediation turns on. Its `field` is declared so that a control later asserting
#: on that column marks THIS cell rather than drawing a second column headed the same way.
COVERAGE_SUBJECT = (
    ("Object", None, False, lambda s, _p: s.name or NONE, "name"),
    ("Type", 18, False, lambda s, _p: s.get_address_type_display(), "address_type"),
    ("Where", 24, False, lambda s, _p: str(s.enforcement_point or s.appliance_group or NONE)),
    ("Device's own count", 20, False, lambda s, _p: _device_content_total(s),
     "resolved_content_source_total"),
)
#: A normalization issue names OUR OWN RECORD of an object that failed, so three of its columns
#: differ from every other subject here. "Object" falls back to a placeholder because the name is
#: legitimately empty on the worst rows - the model says "Empty when the entry had no @name; that
#: is itself the problem" - and a blank cell would hide exactly those. "Kind" is free text rather
#: than a choices display, so a new kind of failure needs no migration and no change here. And
#: "Cause" carries root-versus-consequence, which is load-bearing: every one of these controls
#: reports at `informational` (Jason, 2026-10-28), so severity no longer separates the one fault
#: from the thousand rules that fell with it. This column does.
NORMALIZATION_SUBJECT = (
    ("Object", None, False,
     lambda s, _p: (s.name or f"<unnamed {s.kind or 'object'}>"), "name"),
    ("Kind", 20, False, lambda s, _p: s.kind or NONE, "kind"),
    ("Where", 24, False,
     lambda s, _p: str(s.enforcement_point or s.appliance_group or s.appliance or NONE)),
    ("Disposition", 14, False, lambda s, _p: s.get_disposition_display(), "disposition"),
    ("Cause", 26, False,
     lambda s, _p: (f"Consequence of {s.related_object_name}"
                    if s.is_consequent and s.related_object_name
                    else ("Consequence" if s.is_consequent else "Root")),
     "is_consequent"),
)
#: An IKE crypto profile. The three algorithm columns show the OFFER SET with the graded member
#: marked, because the profile offers every member and takes the first a peer accepts - the
#: weakest alone hides what a remediation has to delete. None of them declares a `field`: the
#: verdict each control asserts on (`*_floor_met`) gets a derived settings column of its own and
#: is the cell that should be marked, so declaring one here would move the mark off the verdict
#: and onto a list that is evidence rather than fault.
#:
#: "Key lifetime (as set)" exists BESIDE the derived `key_lifetime_hours` column and does not
#: replace it: the unit is which child element exists rather than a value on the device, so it
#: cannot be a column a reader compares - and it is what a remediation needs, since writing one
#: branch silently destroys another with nothing reporting the discard.
#:
#: "IKEv2 re-authentication" carries its own verdict in the cell. PAN-IKE-005's second record
#: asserts on `reauth_interval_bounded` from a NON-BASELINE query, and `tested_fields` reads the
#: baseline only, so nothing derives a column for it - without this the two rows that finding
#: produces would show no cell explaining themselves.
#: Both IKE models name their entry `entry_name` and have NO `name` field at all, so `NAME` above
#: - which reads `s.name` - does not apply to either. They are the first subjects here in that
#: position: every other named object on this page inherits `ApplianceScopedObject`, and these two
#: deliberately do not (they are `network/` objects with one firewall-local scope, like
#: `InterfaceManagementProfile`). The `field` is the column's own name so that a control testing
#: `entry_name` would mark this cell rather than adding a second column headed the same way.
IKE_ENTRY_NAME = (("Object", None, False, lambda s, _p: s.entry_name or NONE, "entry_name"),)

#: What to head the Coverage tab's derived setting columns. HEADINGS PROPOSED 2026-11-02 by the
#: stage 9 run on `assessment-coverage` and NOT SETTLED: Jason takes the heading pass once over
#: many domains rather than per domain (P399), and every one of these is one line in this dict.
#:
#: Without it the tab headed its five derived columns with the raw field names -
#: `referenced_by_policy`, `content_was_fetched`, `resolution_was_read`,
#: `resolved_content_truncated`, `content_shortfall_band` - because `setting_columns` falls back
#: to `spec.setting_labels.get(field, field)`, and this sheet declared no labels. Measured on a
#: built table, so these were the headings a customer read.
#:
#: THE QUESTION MARK IS LOAD-BEARING AND ONLY TWO OF THESE CARRY ONE, which is the distinction
#: this tab is about rather than a lapse in consistency. `content_was_fetched` and
#: `resolution_was_read` are the two assertions of PAN-COV-001's two halves, and a false on either
#: means THIS ASSESSMENT NEVER ESTABLISHED IT - not that the device is set a particular way - so
#: they are headed as the question they answer, for the reason the IKE labels below give. The other
#: three are facts about the device or the rulebase that a false states positively: a rule either
#: names the object or it does not, and the content either was truncated or was not. Heading those
#: as questions would imply the same doubt and there is none.
#:
#: The two assertions are also deliberately not headed alike, because they say WHO failed to
#: answer: the list's origin server for one, the firewall's own resolver for the other.
COVERAGE_SETTING_LABELS = {
    "referenced_by_policy": "Referenced by a rule",
    "content_was_fetched": "List content fetched?",
    "resolution_was_read": "Name resolution read?",
    "resolved_content_truncated": "Kept only part of it",
    "content_shortfall_band": "Shortfall band",
}

#: What to head the derived setting columns on the two IKE tabs - see
#: `DeviceSettingSheet.setting_labels`. Written rather than derived because every heading here is
#: an acronym this subject matter is made of, and a mechanical title-case gets all of them wrong.
#: The `_known` flags are headed as the QUESTION they answer, because that is what a false means:
#: not "the switch is off" but "no switch is set", which is a different thing on a device.
IKE_CRYPTO_PROFILE_SETTING_LABELS = {
    "dh_group_floor_met": "DH group meets the floor",
    "weakest_dh_group": "Weakest DH group",
    "encryption_floor_met": "Encryption meets the floor",
    "weakest_encryption_cipher": "Weakest cipher",
    "hash_floor_met": "Integrity meets the floor",
    "weakest_hash_algorithm": "Weakest integrity algorithm",
    "key_lifetime_known": "Key lifetime set?",
    "key_lifetime_hours": "Key lifetime (hours)",
    "used_by_ikev2_gateway": "Named by an IKEv2 gateway",
    "reauth_interval_bounded": "IKEv2 re-authentication bounded",
    "referenced_by_gateway_on_this_appliance": "Named by a gateway here",
}

IKE_GATEWAY_SETTING_LABELS = {
    "ike_version": "IKE version configured",
    "peer_authentication": "Peer authentication",
    "ikev1_exchange_mode": "IKEv1 exchange mode",
    "ikev1_dpd_enabled_known": "IKEv1 DPD set?",
    "ikev1_dpd_enabled": "IKEv1 DPD enabled",
    "ikev2_dpd_enabled_known": "IKEv2 idle probe set?",
    "ikev2_dpd_enabled": "IKEv2 idle probe enabled",
    "relies_on_factory_named_proposal": "Names a factory proposal",
    "gateway_is_active": "Gateway state",
}

IKE_CRYPTO_PROFILE_SUBJECT = APPLIANCE + IKE_ENTRY_NAME + (
    ("DH groups offered", 22, True,
     lambda s, _p: ike.offer_set(s.dh_groups, s.weakest_dh_group)),
    ("Encryption offered", 22, True,
     lambda s, _p: ike.offer_set(s.encryption_ciphers, s.weakest_encryption_cipher)),
    ("Integrity offered", 24, True, lambda s, _p: ike.integrity_offer(s)),
    ("Key lifetime (as set)", 20, False, lambda s, _p: ike.key_lifetime(s)),
    # NAMES `reauth_interval_bounded`, which is what PAN-IKE-005's second record asserts. Until
    # 2026-10-28 `tested_fields` read the baseline alone, nothing derived a column for that field,
    # and this column existed to compensate - unmarkable, because it named no field. The union
    # over active queries landed that day and the raw column started deriving BESIDE this one,
    # two columns for one setting. Naming the field here is better than either: the raw duplicate
    # is suppressed, the mark lands on the cell a reader can act on, and the cell still shows the
    # computed interval in hours, which no stored column holds.
    ("IKEv2 re-authentication", 26, True, lambda s, _p: ike.reauth_interval(s),
     "reauth_interval_bounded"),
    ("Named by a gateway here", 16, False,
     lambda s, _p: ("Yes" if s.referenced_by_gateway_on_this_appliance else "No"),
     "referenced_by_gateway_on_this_appliance"),
)

#: An IKE gateway. "Status" presents `gateway_is_active` and declares NO field, which is why that
#: column is named in `hidden_fields` instead - see the spec. The remaining four carry the keys
#: stage 5 declared presented that no baseline query names, so no settings column is derived for
#: them: the IKEv2 liveness branch, its retry sibling on the IKEv1 branch, how the peer
#: authenticates in the parts an engineer can act on, and the two crypto-profile pointers.
IKE_GATEWAY_SUBJECT = APPLIANCE + IKE_ENTRY_NAME + (
    # "Gateway state" and NOT "Status": `HEAD_COLUMNS` already carries a Status column - the
    # FINDING's status - and a table with a duplicate header is rejected by Excel, which
    # xlsxwriter drops with a warning, leaving a sheet of stray cells where the table should be.
    ("Gateway state", 14, False, lambda s, _p: ike.gateway_status(s), "gateway_is_active"),
    ("Peer authentication detail", 28, True,
     lambda s, _p: ike.peer_authentication_detail(s)),
    # NAMES `ikev2_dpd_enabled` for the same reason as the crypto tab's re-authentication column.
    # The companion flag `ikev2_dpd_enabled_known` keeps its own derived column: it is what the
    # "switch not established" query asserts on, a column can name only one field, and the two
    # are separately markable states.
    ("IKEv2 liveness check", 24, True, lambda s, _p: ike.ikev2_liveness(s),
     "ikev2_dpd_enabled"),
    ("IKEv1 DPD retry", 14, False, lambda s, _p: ike.ikev1_dpd_retry(s), "ikev1_dpd_retry"),
    ("IKE crypto profile named", 24, True, lambda s, _p: ike.named_crypto_profiles(s)),
)
#: PHASE 2, 2026-11-02. Both IPSec models name their entry `profile_name`/`tunnel_name` and
#: have NO `name` field, like their phase-1 siblings and for the same reason - they are
#: `network/` objects with one firewall-local scope, so neither inherits `ApplianceScopedObject`
#: and neither carries `scope` or `vsys_name`. `NAME` above reads `s.name` and does not apply.
#: The `field` is the column's own name so a control testing it marks THIS cell rather than
#: drawing a second column headed the same way.
IPSEC_PROFILE_NAME = (("Object", None, False, lambda s, _p: s.profile_name or NONE,
                       "profile_name"),)
IPSEC_TUNNEL_NAME = (("Object", None, False, lambda s, _p: s.tunnel_name or NONE,
                      "tunnel_name"),)

#: HOW FOUR DERIVED COLUMNS READ ON THE IPSEC CRYPTO TAB, through `value_readers` rather than
#: through `display_value`. EVERY FIELD HERE IS ONE THE MODEL DECLARES IN `DERIVED_FIELDS`, and
#: that restriction is load-bearing rather than tidiness: `build_rows` resolves a reader field's
#: Provenance cell through `remediation_accessor`, which is handed `stored=False` for a reader
#: field and therefore NEVER reads that field's own FieldProvenance row. On a DERIVED column there
#: is nothing to lose - `provenance_of` synthesises a DERIVED row and the accessor discards that
#: too, walking to the object either way - so the cell reads exactly as it would without the
#: reader. On a PAYLOAD KEY it would throw away the one thing that matters about it, which is why
#: the tunnel tab beside this declares no readers at all: `anti_replay` and
#: `tunnel_monitor_enable` are measured keys whose provenance says whether the key was absent or
#: explicitly off, and that distinction is the whole of PAN-IPS-006 and -007.
#:
#: WHAT IT BUYS. `weakest_encryption_offered` holds the EMPTY STRING on a profile with no ESP
#: branch, PAN-IPS-002 fires on exactly those profiles and marks that cell, so the unimproved row
#: offered `(empty)` as the thing an engineer should change - the shape the stage 9 contract's
#: fourth finding is about, and here it is the MARKED cell rather than an unmarked one. The
#: shared `display_value` cannot say "this branch does not exist on this subject" and must not
#: learn to, because every other tab reads it.
IPSEC_CRYPTO_PROFILE_READERS = {
    "protocol_branch": findings_sheet.ValueReader(
        read=ipsec.protocol_branch,
        provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label),
    "weakest_encryption_offered": findings_sheet.ValueReader(
        read=ipsec.weakest_cipher,
        provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label),
    "weakest_integrity_offered": findings_sheet.ValueReader(
        read=ipsec.weakest_integrity,
        provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label),
    "referencing_tunnel_count": findings_sheet.ValueReader(
        read=ipsec.referencing_tunnels,
        provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label),
}

#: What to head the derived setting columns on the two IPSec tabs. HEADINGS PROPOSED 2026-11-02
#: by the stage 9 run on `ipsec-crypto` and NOT SETTLED: Jason takes the heading pass once over
#: many domains rather than per domain (P399), and every one of these is one line in this dict.
#:
#: Written rather than derived, for the reason `setting_labels` gives: a mechanical title-case
#: turns `dh_group` into "Dh Group" and every acronym this subject matter is made of - ESP, AH,
#: AH, DH, SHA-2, AEAD - comes out wrong.
#:
#: THE QUESTION MARK IS LOAD-BEARING AND ONLY THREE OF THE FIFTEEN CARRY ONE. `anti_replay_
#: determined` and `tunnel_monitor_enable_determined` are the companion columns that exist
#: BECAUSE a null boolean matches no positive comparison: a false on either means THIS ASSESSMENT
#: NEVER ESTABLISHED IT, not that the device is set a particular way, so they are headed as the
#: question they answer. `all_offered_ciphers_authenticate` takes one because it is PAN-IPS-003's
#: applicability clause rather than an assertion - it decides whether the integrity verdict beside
#: it means anything. The other twelve are facts about the device that a false states positively,
#: and heading them as questions would imply a doubt there is none of.
#:
#: NEITHER `lifetime_unit` NOR THE THREE ALGORITHM LISTS APPEARS HERE: no clause reads any of
#: them, so none derives a column, and each is a declared SUBJECT column with a heading of its
#: own below.
IPSEC_CRYPTO_PROFILE_SETTING_LABELS = {
    "protocol_branch": "IPSec protocol",
    "weakest_encryption_offered": "Weakest cipher offered",
    "all_offered_ciphers_authenticate": "Every offered cipher authenticates too?",
    "integrity_meets_sha2_floor": "Integrity meets the SHA-2 floor",
    "weakest_integrity_offered": "Weakest integrity algorithm offered",
    "dh_group_meets_target": "Key agreement group meets the target",
    "dh_group": "Key agreement group",
    "lifetime_within_target": "Key lifetime within target",
    "lifetime_hours": "Key lifetime (hours)",
    "referencing_tunnel_count": "Named by a tunnel here",
}

IPSEC_TUNNEL_SETTING_LABELS = {
    "anti_replay": "Replay protection",
    "anti_replay_determined": "Replay protection read?",
    "tunnel_monitor_enable": "Far-end monitoring",
    "tunnel_monitor_enable_determined": "Far-end monitoring read?",
    "is_disabled": "Switched off",
}

#: An IPSec crypto profile. The three algorithm columns show the OFFER SET with the graded member
#: marked, because the profile offers every member and takes the first a peer accepts - the
#: weakest alone hides what a remediation has to delete, and stage 4 measured that `action=set`
#: with one member ADDS to the stored list, so a remediation cannot shrink an offer set by
#: overwriting it either.
#:
#: EACH ONE NAMES ITS FIELD, including the three lists no control clauses on. A subject column
#: that declares no field does not suppress the derived column for the same attribute, so one
#: value reaches the tab twice under two headings - and because the headings differ, the
#: duplicate-header guard never fires. These three are safe from that today only because the
#: lists are JSONFields nothing can clause on; naming them costs nothing and closes it anyway.
#:
#: THE ESP AND AH INTEGRITY LISTS ARE TWO COLUMNS AND NOT ONE, which is the model's own reasoning
#: rather than a layout choice: stage 4 measured that ONE grid column on the device serves both
#: branches, so a reading taken off the screen cannot say which branch's list it came from. Each
#: reads an em dash on a profile whose branch is the other one - a state `display_value` has no
#: word for and a declared subject column may say.
#:
#: "Key lifetime (as written)" exists BESIDE the derived `Key lifetime (hours)` and does not
#: replace it: the unit is WHICH CHILD ELEMENT EXISTS rather than a value on the device, so it
#: cannot be a column a reader compares - and it is what a remediation needs, since a profile
#: written in days holds nothing at all at the hour branch. Its field is `lifetime_unit`, which
#: stage 5 declares presented and no clause reads.
IPSEC_CRYPTO_PROFILE_SUBJECT = APPLIANCE + IPSEC_PROFILE_NAME + (
    ("Encryption offered (ESP)", 22, True, lambda s, _p: ipsec.esp_encryption_offered(s),
     "esp_encryption"),
    ("Integrity offered (ESP)", 26, True, lambda s, _p: ipsec.esp_integrity_offered(s),
     "esp_authentication"),
    ("Integrity offered (AH)", 22, True, lambda s, _p: ipsec.ah_integrity_offered(s),
     "ah_authentication"),
    ("Key lifetime (as written)", 22, False, lambda s, _p: ipsec.key_lifetime(s),
     "lifetime_unit"),
)

#: An IPSec tunnel. Six declared columns, every one of them a field stage 5 marks presented that
#: NO shipped query names - so no settings column derives for any of them and without these the
#: row would show the switch, the two monitoring verdicts and nothing about the bindings they
#: are verdicts on.
#:
#: `ike_gateway_names` IS DELIBERATELY NOT HERE, and it is the one column on this subject stage 5
#: marks `presented: false`. It is half of a join whose other half does not exist: PAN-IPS-008's
#: first stage 5 record asserts that a retired tunnel's gateway is retired with it, and this
#: domain's stage 4 never measured the gateway collection - so the assertion's gateway clause was
#: never written and nothing could be reconciled against this list. The column is stored so that
#: the day the collection IS measured the tunnel side is already there. Presenting it now would
#: put a list on the row that no sentence in the report refers to.
#:
#: "IPSec crypto profile named" IS THE ONE CELL ON EITHER TAB THAT READS `provenance_of`, and it
#: has to. Where the tunnel writes no reference the column holds the LITERAL `default`, which is
#: an inference and not a reading - stage 4 set `may_materialise: false` on three leads and not
#: one measurement - and the recorded `assumed_default` on that field reaches no other cell on
#: the row, because the Provenance column answers per TESTED field and no clause in this domain
#: reads this one. A row printing `default` as though it had been read is the shape P420 names.
IPSEC_TUNNEL_SUBJECT = APPLIANCE + IPSEC_TUNNEL_NAME + (
    ("Monitor probe target", 20, False, lambda s, _p: ipsec.monitor_probe(s),
     "tunnel_monitor_destination_ip"),
    ("Monitor profile named", 22, False, lambda s, _p: ipsec.monitor_profile_named(s),
     "tunnel_monitor_profile_name"),
    ("Monitor action if probing fails", 30, True, lambda s, _p: ipsec.monitor_action(s),
     "monitor_action_effective"),
    ("IPSec crypto profile named", 30, True,
     lambda s, provenance_of: ipsec.crypto_profile_named(s, provenance_of),
     "crypto_profile_name"),
    ("Crypto profile resolves here", 28, True, lambda s, _p: ipsec.crypto_profile_resolves(s),
     "crypto_profile_found"),
    ("Running on a chosen profile", 30, True,
     lambda s, _p: ipsec.running_on_a_chosen_profile(s), "effective_crypto_profile_chosen"),
)
SCOPE = (("Scope", 12, False, lambda s, _p: scope_of(s), "scope"),)
KIND = (("Kind", 22, False, lambda s, _p: s.get_kind_display(), "kind"),)


def scope_owner(obj):
    """The appliance group or appliance a scoped object belongs to.

    A vsys-scoped object hangs off an enforcement point; a SHARED-scope one hangs off the group
    directly and has no enforcement point at all. Both are real states - a security profile can be
    defined once for every vsys on a pair - so both are read rather than assumed.
    """
    point = getattr(obj, "enforcement_point", None)
    if point is not None:
        return point.appliance_group or point.appliance
    return getattr(obj, "appliance_group", None) or getattr(obj, "appliance", None)


#: A vsys-scoped object, named the way the policy tabs name one: who runs it, then where.
VSYS_SCOPED = (
    ("Firewalls", 16, True, lambda s, _p: appliance_names(scope_owner(s))),
    ("Vsys", 12, False,
     lambda s, _p: (s.enforcement_point.vsys_name
                    if getattr(s, "enforcement_point", None) is not None else "shared")),
)

# --------------------------------------------------------------------------------------------
# THE THREE DEVICE-ID TABS, 2026-11-02, for PAN-IOT-001 to -004. Three models, three grains and
# three PAN-OS categories - a device-wide service state (Device), the security zone (Network) and
# a verdict over an enforcement point's whole rule set (Policies) - so they are three tabs in
# three different places in the Summary rather than one domain's block.
#
# EVERY HEADING BELOW IS A PROPOSAL. Report content is Jason's and he takes the heading pass once
# across many domains (P399). The sourcing is in each comment: where the vendor has a label this
# uses it, and where the vendor has NO label the comment says so rather than implying one.
#
# NO TAB HERE HIDES A FIELD. `hidden_fields` is empty on all three. The gate accepts a field's
# presence in `hidden_fields` as proof something shows it, so a non-empty one is a CLAIM taken as
# proof and is the only known cause in this repository of a findings row that marks nothing as the
# thing to fix. There was no reason for a new sheet to declare one.
# --------------------------------------------------------------------------------------------

#: The device-identification state's four DISPLAY columns - no clause names any of them, and each
#: still declares its `field` so that a control which ever tests one marks THIS cell instead of
#: drawing a second column under a different heading.
#:
#: NO `Object` COLUMN, and that is stage 5's grain rather than an omission: the row is a conclusion
#: about the appliance, and the licence table's entries have no identity a finding would print.
#:
#: THE TWO CONTENT INSTRUMENTS SIT SIDE BY SIDE BECAUSE THEY DISAGREE. The dictionary version and
#: its release date are what PAN-IOT-003 grades; the two `show iot icd version` columns are the
#: instrument it must NOT grade, and the ordering puts the graded one first. See their readers.
DEVICE_IDENTIFICATION_SUBJECT = APPLIANCE + (
    ("Device dictionary version", 22, False,
     lambda s, _p: device_id.dictionary_version(s), "device_dictionary_version"),
    ("Content release date (as written)", 26, True,
     lambda s, _p: device_id.release_date(s), "device_dictionary_release_date"),
    ("Classification data build", 24, True,
     lambda s, _p: device_id.icd_build(s), "icd_build_version"),
    ("Classification data built", 24, True,
     lambda s, _p: device_id.icd_built_at(s), "icd_built_at"),
)

#: ONE READER ON THIS TAB, and the field it is on is the only one where it costs nothing.
#:
#: `device_dictionary_age_days` is declared in `DeviceIdentificationState.DERIVED_FIELDS`, so a
#: reader loses no `FieldProvenance` row: `build_rows` hands a reader field `stored=False` to
#: `remediation_accessor`, which then never consults that field's own row - and on a derived
#: column there is no such row to consult. Measured by the `ipsec-crypto` run and true here.
#:
#: WHAT IT BUYS: `display_value` would print `(none)` for the NULL, and NULL here is not a missing
#: reading in the ordinary sense - it is an appliance whose `show system info` carries no
#: release-date key at all, which PAN-IOT-003's applicability clause then narrows OUT of the
#: graded comparison. `(none)` in a column of day counts reads as a value somebody failed to fill
#: in, beside a finding about something else. The em dash says the comparison was not made.
#:
#: AND `edge_service_address` DELIBERATELY HAS NONE. It is the one PAYLOAD KEY among this tab's
#: tested fields, and whether the key was absent, explicitly blank or template-supplied is half of
#: what PAN-IOT-001 is about - which is exactly what a reader would discard. Refused for that
#: reason; the cell reads `(empty)` and the Provenance column keeps the answer.
DEVICE_IDENTIFICATION_READERS = {
    "device_dictionary_age_days": findings_sheet.ValueReader(
        read=device_id.content_age_days,
        provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label),
}

DEVICE_IDENTIFICATION_SETTING_LABELS = {
    # The vendor's own name for the subscription, help p.951 ("IoT, short for IoT Security").
    "device_id_licensed": "IoT Security subscription in force",
    # No vendor label: the entitlement is runtime state the firewall reports and never a screen
    # field. This is the companion that separates "not entitled" from "never asked" - on an
    # appliance holding no licences the whole reply is `{'licenses': None}`, which is exactly what
    # a collector that never issued the command produces.
    "licence_read_taken": "Licence listing answered",
    # `deviceconfig/setting/iot/edge/address`. No vendor label either: stage 4 could reach no
    # oracle for this node, and Device > IoT Security has no route in the UI map.
    "edge_service_address": "Edge service address",
    # Help p.951 calls the Dynamic Updates column "Release Date"; this is the companion that says
    # whether the appliance reported one at all, which two of the four lab appliances do not.
    "device_dictionary_release_date_known": "Content release date reported",
    "device_dictionary_age_days": "Content age (days)",
}

#: The zone's identity and its two Device-ID lists. VSYS-SCOPED because a zone name is unique only
#: per enforcement point - the stored constraint is literally
#: `integrations_unique_zone_per_enforcement_point` - so the same name legitimately exists in
#: several virtual systems and the vsys is part of the identity rather than decoration.
#:
#: THE TWO LIST COLUMNS READ THE VENDOR'S OWN WORDS WHEN EMPTY. See their readers: an empty
#: include list is `Any`, not a blank, because it means identification applies to every address in
#: the zone - the most permissive state on the device AND the compliant one for this control.
ZONE_SUBJECT = VSYS_SCOPED + NAME + (
    # Headed by analogy to the vendor's own User-ID labels, and the analogy is the best available:
    # help p.479-483's Security Zone Settings table lists "User Identification ACL Include List"
    # and "...Exclude List" and NO device equivalent of either - checked in three Help versions
    # and absent from all three. So the device wording here is ours, modelled on the vendor's.
    ("Device-ID address list (include)", 30, True,
     lambda z, _p: device_id.device_include_members(z), "device_include_acl"),
    ("Device-ID address list (exclude)", 30, True,
     lambda z, _p: device_id.device_exclude_members(z), "device_exclude_acl"),
)

#: THREE READERS ON THE ZONE TAB, AND THEY ARE NOT ABOUT WORDING. Each prints the same Yes/No the
#: shared renderer would; what they are for is that a reader whose `provenance` is not the DERIVED
#: label makes `build_rows` skip `remediation_accessor` entirely - and calling it on a `Zone`
#: RAISES. The shared `provenance_of` closure falls back to `field in model.DERIVED_FIELDS`
#: whenever no stored row exists, `Zone` is a `SyncTrackedModel` rather than a `ProvenancedMixin`,
#: it declares no `DERIVED_FIELDS`, and nothing writes a `FieldProvenance` row for a zone - so
#: every row takes that fallback and every row would crash the build.
#:
#: SO THE USUAL COST OF A READER IS ZERO HERE, which is the opposite of the `ipsec-crypto` case
#: and for a measurable reason: that run refused readers on two payload keys because a reader
#: discards the field's own `FieldProvenance` row, and a zone HAS no such row to discard. Nothing
#: is lost that was ever there.
#:
#: Recorded as a defect in this run's artifact rather than fixed: the model belongs to another
#: repository and the closure is shared machinery.
ZONE_READERS = {
    "enable_device_identification": findings_sheet.ValueReader(
        read=device_id.identification_enabled, provenance=device_id.ZONE_PROVENANCE),
    "device_identification_is_narrowed": findings_sheet.ValueReader(
        read=device_id.identification_narrowed, provenance=device_id.ZONE_PROVENANCE),
    "device_acl_lists_computed": findings_sheet.ValueReader(
        read=device_id.device_lists_read, provenance=device_id.ZONE_PROVENANCE),
    # THE FOURTH FIELD TO REACH THIS TAB, added 2026-11-02 by stage 9 of `user-id` for
    # PAN-UID-001, and it is a reader for the reason the block above gives rather than for its
    # wording - which is a plain Yes/No. WITHOUT IT THIS TAB CANNOT BE BUILT AT ALL for a
    # PAN-UID-001 row: `enable_user_identification` is a derived settings column here, nothing
    # covered it, and the no-reader path reaches `remediation_accessor`, whose `provenance_of`
    # falls back to `field in Zone.DERIVED_FIELDS` and raises `AttributeError`.
    #
    # SO THE READER SET ON AN UNPROVENANCED MODEL'S SHEET IS A PER-FIELD ALLOWLIST, not a
    # one-time fix for the model. The three readers above made this tab buildable for
    # PAN-IOT-002's three fields on the day it was written; the next control to reuse the tab
    # brought a fourth field and broke it again, and nothing fails until a row of that control
    # exists.
    #
    # THAT PREDICTION WAS WRONG AND IS CORRECTED HERE - 2026-11-02, by stage 9 of
    # `zone-dos-protection`, which is the third domain the original sentence named. It said a
    # PAN-ZON entry would be needed "for every field ITS controls clause on". It is not needed,
    # and adding one would FAIL A SHIPPED TEST:
    #
    #   - `2ff6cd6` changed the `provenance_of` closure to read
    #     `getattr(_model, "DERIVED_FIELDS", ())`, so the reader-less path no longer raises on a
    #     model that declares none. That commit is what fixed "Could not store the
    #     security-zones table for run 147".
    #   - `tests/test_findings_unprovenanced_subject.py` drives PAN-ZON-001 through the STORED
    #     path over this real spec and asserts BOTH that the table stores AND that none of
    #     `can_receive_traffic`, `zone_protection_unresolved`, `zone_type` is in
    #     `value_readers`. So an entry for any of those three would break that assertion.
    #
    # Measured by that run: all three of PAN-ZON-001's tested fields build, store and draw with
    # no reader at all. A reader is still the right tool for the WORDING reason the block above
    # gives; it is no longer a precondition for the tab being buildable.
    "enable_user_identification": user_id.ZONE_USER_ID_READER,
}

ZONE_SETTING_LABELS = {
    # NO VENDOR LABEL EXISTS FOR THIS FIELD and that is measured, not assumed: stage 1 read the
    # Security Zone Settings table in three Help versions and the device equivalent of "Enable
    # User Identification" is absent from all three, though the key is committable and the box
    # renders. So this heading is ours, worded to match the vendor's User-ID one beside it.
    "enable_device_identification": "Enable Device Identification",
    # The derived verdict over the two JSON lists. A clause cannot hold an OR across two columns
    # and there is no count operator, so "either list has a member" is computed at normalization.
    "device_identification_is_narrowed": "Device identification narrowed",
    # The column that answers the unknown. False means the row predates the two columns or its
    # merged read never arrived - NOT that the lists are empty.
    "device_acl_lists_computed": "Device-ID lists read",
    # PAN-UID-001, added 2026-11-02 by stage 9 of `user-id`. A PROPOSAL like every heading on
    # this tab.
    #
    # THE VENDOR HAS A LABEL FOR THIS ONE, which is the difference from the Device-ID heading
    # above: help p.479-483's Security Zone Settings table prints "Enable User Identification"
    # verbatim, and stage 1 of `user-id` cites it as the control's own field on the zone screen.
    # So this heading is the vendor's words and not ours - the Device-ID equivalent is absent
    # from three Help versions, which is why its comment says the opposite.
    "enable_user_identification": "Enable User Identification",
    # PAN-ZON-001's THREE fields, added 2026-11-02 by stage 9 of `zone-dos-protection` - the
    # third domain to report on this tab. ALL THREE ARE PROPOSALS, like every heading here.
    #
    # THEY WERE RAW DJANGO FIELD NAMES ON A CUSTOMER-FACING TAB UNTIL NOW, and the shipped
    # regression test records one of them as such in an assertion:
    # `test_findings_unprovenanced_subject.py` indexes `table.headers` by the literal string
    # "zone_protection_unresolved". Measured by this run by building the table and grepping the
    # headers for `_`.
    #
    # AND THAT ASSERTION HAD TO BE UPDATED, which is worth knowing before renaming any heading
    # on any tab: `FindingsTable.headers.index(...)` takes the HEADING, not the field, so adding
    # an entry here raised `ValueError: 'zone_protection_unresolved' is not in list` in a test
    # whose subject is the STORED PATH and has nothing to do with wording. Nothing couples the
    # two or warns that they are coupled - it was caught by the suite and not by reading. The
    # test now indexes "Zone protection unresolved" and pins the same behaviour.
    #
    # "Can receive traffic" is the POPULATION column, not an assertion: a zone with no type
    # subtree and no interfaces receives nothing, and stage 3 widened the population from the
    # catalogue row's "Layer-3 zone" to every zone that can carry traffic. The vendor has no
    # label for it - it is our reading of which subtree exists - so this wording is ours.
    "can_receive_traffic": "Can receive traffic",
    # THE ASSERTION, and the heading says `unresolved` rather than "has no profile" on purpose.
    # The column is TRUE in two different states: no attachment leaf at all, and a leaf naming a
    # profile that does not exist. Stage 4 measured that the attachment is a free string with no
    # referential integrity the configuration expresses and that the join is case-sensitive, so
    # a dangling name reads as configured while the zone meters nothing. A heading saying "no
    # zone protection profile" would describe only the first state and would read as FALSE on
    # exactly the dangerous rows this control exists for.
    "zone_protection_unresolved": "Zone protection unresolved",
    # The grading axis, and A PROXY WHICH THIS HEADING CANNOT ADMIT TO. What stage 3 grades on is
    # the zone's EXPOSURE - which side of a perimeter it faces - and no column of any model holds
    # that, so the nearest thing the configuration offers is which subtree carried the
    # interfaces. The vendor's own word for that subtree is the zone's Type, so the heading is
    # the vendor's even though the meaning is narrower than the grading wants.
    "zone_type": "Zone type",
}


# --------------------------------------------------------------------------------------------
# THE TWO ZONE/DoS TABS, 2026-11-02, for PAN-ZON-002 to -007. Two models, two grains and two
# PAN-OS categories - a device-local profile under Network Profiles (Network) and a row of one
# virtual system's DoS rulebase (Policies) - so they are two tabs in two different places in the
# Summary rather than one domain's block. The domain's other two controls add no tab: PAN-ZON-001
# reports on `Security Zones` and PAN-ZON-008 on `Security Profile`, both of which already exist.
#
# EVERY HEADING BELOW IS A PROPOSAL, on the Device-ID block's precedent above and for the same
# reason: report content is Jason's and he takes the heading pass once across many domains (P399).
#
# BOTH MODELS ARE `ProvenancedMixin` AND BOTH DECLARE `DERIVED_FIELDS`, measured in
# `integrations/models/zone_dos_protection.py` - `ZoneProtectionProfile(ProvenancedMixin,
# SyncTrackedModel)` at line 66 with 14 derived fields, `DosPolicyRule(ProvenancedMixin,
# SyncTrackedModel)` at line 506 with three. So neither tab needs the `ValueReader`-per-column
# workaround the Security Zones tab above carries: the per-field Provenance cell and the default
# template column both answer honestly here, and `provenance_cell` is left at the default.
# `integrations.Zone` is the model that is NOT one, and it is already on its own tab.

#: A zone protection profile. ITS OWNER IS THE APPLIANCE AND NOT A VSYS, which stage 4 measured:
#: `action=complete` answers code=6 Invalid sequence at both the shared and the vsys spelling of
#: `network/profiles/zone-protection-profile`, so the collection has exactly one scope on a
#: firewall. That is why this uses `APPLIANCE` rather than `VSYS_SCOPED`, and it is also why a
#: template-pushed profile attached on one device and not another is two rows saying different
#: things - which is the truth about those two devices rather than a duplicate.
#:
#: THE NAME FIELD IS `profile_name`, NOT `name`, so this cannot reuse `NAME` above.
#:
#: THE TWO COLUMNS AFTER THE NAME ARE EVIDENCE RATHER THAN IDENTITY, on the IKE sheet's precedent
#: for "Key lifetime (as set)": no control asserts on either, so `tested_fields` derives no
#: settings column for them, and they are what the applicability gate `is_in_force` TURNS ON.
#: Without them a reader who meets `In force: no` cannot tell a profile no zone names from one
#: whose attachment sweep never ran - which is the zero-versus-unknown distinction, per field.
#: Each declares its `field` so that a control later asserting on it marks THIS cell rather than
#: drawing a second column headed the same way.
ZONE_PROTECTION_PROFILE_SUBJECT = APPLIANCE + (
    ("Object", None, False, lambda s, _p: s.profile_name or NONE, "profile_name"),
    ("Zones attached", 16, False,
     lambda s, _p: (f"{s.attached_zone_count} zone(s)" if s.attached_zone_count
                    else "Nothing"), "attached_zone_count"),
    ("Attachment sweep completed", 24, False,
     lambda s, _p: ("Yes" if s.attachment_sweep_complete else "No"),
     "attachment_sweep_complete"),
)

ZONE_PROTECTION_PROFILE_SETTING_LABELS = {
    # The applicability gate all five controls on this tab share. TRUE is IN the population: at
    # least one zone of some vsys of this appliance names the profile. Its default is TRUE, which
    # is the safe side - a profile whose sweep has not run is assessed for its contents rather
    # than excused - and the two evidence columns above are what let a reader check it.
    "is_in_force": "In force (a zone names it)",
    # PAN-ZON-002. FALSE FIRES. Named for the vendor's own SYN Flood tab.
    "syn_flood_enabled": "SYN flood protection enabled",
    # PAN-ZON-003, and a DISJUNCTION over four leaves rather than a reading of one - the four
    # per-protocol enable columns behind it are deliberately not registered for search, because
    # a clause on one would answer a quarter of the question under the whole question's name.
    # "gap" is the word because TRUE is the FIRING side: it means at least one flood type is
    # unprotected, so a heading like "Flood protection" would read backwards.
    "volumetric_flood_gap": "Volumetric flood protection gap",
    # PAN-ZON-005. FALSE FIRES. The vendor's Packet Based Attack Protection tab calls the
    # checkbox "Spoofed IP address"; this heading is that label turned into a statement.
    "discard_ip_spoof": "Discards spoofed IP addresses",
    # PAN-ZON-006's second record, a disjunction over the four drops the catalogue row's
    # description names. TRUE FIRES, so "gap" again.
    "packet_drop_gap": "Packet drop protection gap",
    # PAN-ZON-006's ASSERTION, and the RESOLVED value rather than the profile's own leaf. Two
    # columns, two different questions, and the headings have to keep them apart: the leaf is a
    # three-valued pointer whose commonest state is `global` - a deferral to a device-wide
    # setting that has to be read separately - so comparing the leaf to `yes` is wrong in both
    # directions at once.
    "non_syn_reject_effective": "Non-SYN reject (resolved)",
    # PAN-ZON-006's GRADING axis: what the profile itself holds. Graded apart from the other two
    # states because the middle one is not an answer at all but that deferral.
    "non_syn_reject_configured": "Non-SYN reject (as configured)",
    # PAN-ZON-004's assertion. TRUE FIRES. The vendor's tab is Reconnaissance Protection, which
    # is the word a reader will look for on the device; "scan" is this repo's field name.
    "scan_detection_gap": "Reconnaissance detection gap",
    # PAN-ZON-004's grading axis. An em dash where no scan entry exists at all - see the
    # `unrenderable` note in the stage 9 artifact: a profile with no entry has no weakest action
    # BY STRUCTURE, and the shared `display_value` prints `(empty)` for that.
    "scan_weakest_action": "Weakest reconnaissance action",
    # The column that answers the unknown, and it is a statement about OUR READ rather than about
    # the profile: TRUE only where a profile carries at least one scan entry AND both sensitivity
    # numbers were read. FALSE is the firing side.
    "scan_sensitivity_known": "Scan interval and threshold both read",
    # PAN-ZON-004's second record. A count of ADDRESSES and not of entries - an entry can carry
    # both an ipv4 and an ipv6 leaf, so counting entries gives the same answer on this lab and a
    # different one anywhere else.
    "scan_white_list_count": "Sources exempt from detection",
}

#: A row of one virtual system's DoS rulebase. VSYS-SCOPED, so it names the firewalls that run
#: the virtual system rather than one appliance - a vsys on an HA pair spans both members.
#:
#: THE POSITION IS PART OF THE ROW'S IDENTITY AND NOT DECORATION: a rulebase resolves by ORDER
#: rather than by name, which is why stage 4 recorded `name_resolution` as unmeasured on this
#: object - the collision question that field asks is the wrong shape for a rulebase. The name is
#: what a finding prints; the position is what makes two rows of the same name different rows.
#:
#: "Disabled" IS A STRING ON THIS MODEL AND IS PRINTED AS READ. Every DoS rule in the measured
#: estate carries `disabled: yes` - stage 6 could not commit an enabled one and marks all four
#: `inoperative_support_object` - and PAN-ZON-007 deliberately fires regardless, because no
#: implicit was measured for that key and taking an absence for "disabled" would silently
#: suppress every rule in an estate. This column is here so a reader can see that is what
#: happened, and it is the single most likely source of a false finding on a real estate.
#:
#: THE TWO PROFILE COLUMNS ARE THE EVIDENCE BEHIND `names_a_profile`, which is the applicability
#: gate: that column is a verdict over these two leaves, and a reader who meets "Names a DoS
#: profile: no" needs to see which slot was empty.
DOS_POLICY_RULE_SUBJECT = VSYS_SCOPED + (
    ("Rulebase", 16, False, lambda s, _p: s.get_config_source_display(), "config_source"),
    ("Position", 10, False, lambda s, _p: s.rule_position, "rule_position"),
    ("Object", None, False, lambda s, _p: s.rule_name or NONE, "rule_name"),
    ("Aggregate profile", 22, False, lambda s, _p: s.aggregate_profile or "None",
     "aggregate_profile"),
    ("Classified profile", 22, False, lambda s, _p: s.classified_profile or "None",
     "classified_profile"),
    ("Disabled", 12, False, lambda s, _p: s.rule_disabled or NONE, "rule_disabled"),
)

DOS_POLICY_RULE_SETTING_LABELS = {
    # PAN-ZON-007's APPLICABILITY. TRUE is in the population: the rule names a profile in at
    # least one of its two protection slots. The two slot columns above are its evidence.
    "names_a_profile": "Names a DoS profile",
    # PAN-ZON-007's ASSERTION and its GRADING axis at once - the only column in this domain that
    # is both. `protect` is the one action that consults the profile the rule names; `deny` and
    # `allow` do not, and stage 3 grades them apart because a denying rule is at least refusing
    # traffic while an allowing one is doing nothing at all. The three actions are CHILD NODES
    # rather than values - stage 4 measured the stored shape as `action: {'protect': None}` - so
    # an empty cell here is a rule with no action branch and not an action nobody read.
    "rule_action": "Action",
}

#: The verdict's identity and its two counts, on `vsys_rule_posture`'s pattern.
#:
#: THE IDENTITY COLUMNS DECLARE NO `field`, which is that sheet's own ruling and the right one
#: here: declaring one would move the value-at-fault mark off the verdict and onto the row's
#: address. The two COUNT columns do declare theirs, because they are real model columns a control
#: could one day test and neither is part of the address.
RULEBASE_DEVICE_MATCH_SUBJECT = VSYS_SCOPED + (
    # Printed as numbers rather than through `display_value`, on `rule-posture`'s ruling for a
    # count column: zero is the reportable end, and a word like "Nothing" on a column named for a
    # count reads as "not counted" instead of "none found".
    ("Rules matching on a device", 26, False,
     lambda v, _p: device_id.rules_matching_count(v), "rules_matching_on_device_count"),
    ("Device objects visible here", 26, False,
     lambda v, _p: device_id.device_objects_visible(v), "device_object_count"),
)

RULEBASE_DEVICE_MATCH_SETTING_LABELS = {
    # HEADED IN THE FIELD'S OWN POLARITY, deliberately, and this is the one heading on the three
    # tabs that is a safety decision rather than a wording one. The column defaults True and True
    # is the FIRING side, so a heading like "Policy matches on a device" would put "No" in the
    # firing cell and "Yes" in the healthy one - and the failure this stage exists to catch is a
    # row whose most REASSURING cell is the finding. Worded this way the firing cell reads "Yes"
    # to a question whose Yes is plainly the problem, and cannot be scanned as a pass.
    #
    # The vendor names the two rule fields that take a device object "Source Device" and
    # "Destination Device" (help p.128) and has no name for the absence of both across a rule
    # set, which is what this column is.
    "has_no_rule_matching_on_device": "Device dimension absent from the rule set",
}


# --------------------------------------------------------------------------------------------
# THE TWO USER-ID TABS, 2026-11-02, for PAN-UID-002, -003, -004 and -006. Stage 9 of `user-id`.
#
# TWO TABS FOR TWO MODELS AT ONE VENDOR ADDRESS, on the `rule-posture`/`security` precedent that
# an engineer fixes one or the other. Both subjects live under Device > User Identification >
# User Mapping; the collector settings are the agent's own behaviour - whether it probes, which
# account it reads as, how long a mapping lives - and the discovery bound is the LIST that says
# where it may look at all. Different grids, different work.
#
# THE DOMAIN'S OTHER TWO CONTROLS ARE NOT HERE. PAN-UID-001 reports on Security Zones and
# PAN-UID-005 on Management Interface, both tabs other domains built first; this run added a
# reader and a heading to each rather than a tab. And `integrations.UserIdMonitoredServer` gets
# NO tab: it is the subject of the one PAN-UID-005 assertion record this domain leaves silent,
# no control can produce a finding over it, and stage 8 records that with `built: false`.
#
# EVERY HEADING BELOW IS A PROPOSAL (P399), as on the Device-ID tabs above.
#
# NEITHER TAB HIDES A FIELD. `hidden_fields` is empty on both. The gate accepts a field's
# presence in `hidden_fields` as proof something shows it, so a non-empty one is a CLAIM taken
# as proof and is the only known cause in this repository of a findings row that marks nothing
# as the thing to fix. There was no reason for a new sheet to declare one.
#
# BOTH SUBJECTS ARE VSYS-SCOPED AND NEITHER MODEL HAS AN `appliance`. They hang off an
# EnforcementPoint, which is this store's unit for a vsys, so both specs override the three
# appliance-scoped defaults - `subject_columns`, `appliance_of` and `subject_select_related` -
# on `vsys_rule_posture`'s precedent. `appliance_of` returns None deliberately: on an HA pair a
# vsys spans both firewalls and linking a row to one peer would assert something false.
# --------------------------------------------------------------------------------------------

#: The collector's identity plus the one stage 5 column no control clauses on.
#:
#: `syslog_service_profile` IS HERE BECAUSE STAGE 5 DECLARED IT PRESENTED AND NOTHING DERIVES IT.
#: A settings column is derived only for a field an active query has a clause on, and no query of
#: this domain touches this one - so the flag and the machinery disagree, and hand-declaring is
#: the documented way to settle it. It earns the space: it names the TLS profile the encrypted
#: syslog listener presents, and "nothing is bound" is the state in which the encrypted listener
#: cannot be switched on at all - which is the alternative an engineer reading PAN-UID-005's
#: unauthenticated-listener finding is being pointed at.
#:
#: IT DECLARES ITS `field` even though no control tests it, on the Device-ID tabs' ruling: a
#: control that ever clauses on it marks THIS cell instead of drawing a second column under a
#: different heading, and the duplicate-header guard would not fire on two different headings.
USER_ID_COLLECTOR_SUBJECT = VSYS_SCOPED + (
    ("Syslog TLS profile", 24, False,
     lambda c, _p: c.syslog_service_profile or NONE, "syslog_service_profile"),
)

#: NO `value_readers` ON THIS TAB, and that is the deliberate half of this domain's three
#: different answers to the reader question. See `user_id_presentation`'s module docstring: all
#: six assertable columns here are read from payload keys and carry real `FieldProvenance` rows -
#: `pan_os_default` for the four measured implicits, `not_configured` for the two that are not
#: assumed - and a reader would make `tested_fields` return `stored=False`, which is what stops
#: `remediation_accessor` ever reading that row. On `wmi_account` that row is the ONLY thing in
#: the report that tells an absent key from a key present and empty. So the shared renderer
#: prints the values and the Provenance column keeps the distinction.
USER_ID_COLLECTOR_SETTING_LABELS = {
    # Help p.977 names the checkbox "Enable Probing", under Palo Alto Networks User-ID Agent
    # Setup > Client Probing. The vendor's two words alone would not say what is probed or how,
    # and TRUE is the firing side, so the heading carries the transport: an engineer who reads
    # "probing" as harmless reconnaissance needs to see that the agent sends its own credentials.
    "enable_probing": "Client probing (WMI/NetBIOS)",
    # Help p.975 names the Server Monitor Account field "User Name". Headed as what it IS rather
    # than as what it is called, because the firing direction is NON-empty and the heading has to
    # make that legible: the finding is not that the account is wrong, it is that the firewall
    # stores a principal and nothing about what that principal may do.
    "wmi_account": "Server monitor account",
    # The vendor's own wording for this option is "Enable Session" (Server Monitor tab). TRUE
    # fires: reading sessions is the privilege the account needs and the reason its rights matter.
    "enable_session": "Session reading from monitored servers",
    # Help p.481 prints "Enable User Identification Timeout" verbatim. THE ONE HEADING ON THIS TAB
    # MOST LIKELY TO BE READ BACKWARDS, and the model's own docstring says so: this column defaults
    # TRUE where its neighbours default false, expiry ON is the GOOD state, and FALSE is what
    # fires. The vendor's label is kept because inventing one here would be worse, and the word
    # "expire" is added so the compliant direction is readable without the control beside it.
    "enable_mapping_timeout": "Mapping entries expire",
    # Help p.481's label verbatim, "User Identification Timeout (min)", with the unit kept because
    # a bare number in this column is meaningless and 45 is the measured implicit a reader will
    # meet most often. A larger number is worse, and it bounds nothing at all where the column
    # above is No - which is why they are two assertions and not one.
    "ip_user_mapping_timeout": "Mapping lifetime (minutes)",
}

#: The verdict's identity and the three columns that are its EVIDENCE.
#:
#: THIS BLOCK IS THE SUBSTANCE OF THIS TAB, and it exists because `presented: true` is not the
#: instruction it reads as. All four of stage 5's non-identity columns are flagged presented;
#: exactly ONE of them - `list_shape` - is a field a query clauses on, so exactly one gets a
#: derived settings column. The other three would have reached no cell at all, and the row would
#: have been a bare four-state verdict with nothing on it a reader could check: stage 5 is
#: explicit that the counts exist "to let a report say WHICH shape it found" and that the CIDRs
#: are "what stage 3 says the finding prints". So they are hand-declared here.
#:
#: THE COUNTS PRINT AS NUMBERS, on `rule-posture`'s ruling: zero is the reportable end of
#: `include_entry_count` - the vendor's documented unbounded state, where the collector discovers
#: in all subnetworks - and a word like "Nothing" on a column named for a count reads as "not
#: counted" instead of "none found".
#:
#: ZERO MEANS OPPOSITE THINGS IN THE TWO COUNT COLUMNS and nothing on the row says so, which is
#: this tab's one unresolved reading. Zero includes is the firing state; zero excludes is quiet.
#: The verdict column beside them is what separates the exclude-only shape from the unbounded
#: one, and the headings are worded to lean on it rather than to be read alone.
USER_ID_DISCOVERY_SUBJECT = VSYS_SCOPED + (
    ("Include entries in force", 22, False,
     lambda b, _p: b.include_entry_count, "include_entry_count"),
    ("Exclude entries in force", 22, False,
     lambda b, _p: b.exclude_entry_count, "exclude_entry_count"),
    ("Included ranges", 30, True,
     lambda b, _p: user_id.include_networks(b), "include_networks"),
)

#: ONE READER, ON THE ONE COLUMN A CONTROL ASSERTS ON, and it is free: `list_shape` is in
#: `UserIdDiscoveryBound.DERIVED_FIELDS`, so there is no provenance row for `stored=False` to
#: cost. See `user_id_presentation.list_shape` for what the shared renderer could not say.
USER_ID_DISCOVERY_READERS = {
    "list_shape": user_id.DISCOVERY_SHAPE_READER,
}

USER_ID_DISCOVERY_SETTING_LABELS = {
    # NO VENDOR LABEL EXISTS: this column is a verdict this assessment computes over the whole
    # include/exclude list, and the vendor has no name for "the shape of the list". The section
    # it is computed from is the vendor's own - help p.981, "Include or Exclude Subnetworks for
    # User Mapping" - and the heading is worded to name the list rather than the computation,
    # because the thing an engineer opens is the grid.
    "list_shape": "Discovery list shape",
}


#: Three fields controls test that are NOT columns on their model, each read from where the value
#: actually lives. Without these the sheet would refuse to build - which is the guard doing its
#: job: a control testing something the sheet cannot show must not fire onto it silently.
SERVICES_ENABLED = findings_sheet.ValueReader(
    read=lambda surface: "\n".join(
        sorted(service.name for service in surface.services.all() if service.enabled)) or "(none)",
    members=lambda surface: surface.services.all(),
)
#: `exposure` is a VERDICT the query layer computes over the permitted-source list - restricted,
#: unrestricted, or undetermined where an entry cannot be classified. The list is stored and is
#: what an engineer acts on, so the cell shows the list; the verdict is what the control asserts
#: and is in Fires when on the Controls tab.
PERMITTED_SOURCES = findings_sheet.ValueReader(
    read=lambda surface: "\n".join(
        source.value for source in surface.permitted_sources.all()) or "(any source)",
    members=lambda surface: surface.permitted_sources.all(),
)
#: `binding_count` is the query layer's name for `bound_interface_count`, which the model stores
#: and declares derived - so the answer comes from the model rather than from a sentence here.
BINDING_COUNT = findings_sheet.ValueReader(
    read=lambda profile: str(profile.bound_interface_count),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)




#: Whether any security rule points at this object, on either side - what keeps the coverage
#: controls proportionate, since an EDL nobody references is EXPECTED to be unsized. A reader
#: rather than a model property because the answer lives on the ref rows, and the spec prefetches
#: both so the sheet does not pay a query per row for it.
REFERENCED_BY_POLICY = findings_sheet.ValueReader(
    read=lambda obj: "Yes" if (obj.securityrulesourceaddressref_set.all()
                               or obj.securityruledestinationaddressref_set.all()) else "No",
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)


#: Which WildFire Inline ML models an antivirus profile does not run. A model the config never
#: mentions is OFF and is listed here, because the absence of a setting is not the absence of a
#: problem - a profile with no ML node runs no inline ML at all.
#:
#: NOT BLOCKING rather than OFF: `mlav-policy-action` has three values and `enable(alert-only)`
#: runs the model without stopping the file, so it belongs in this list as much as `disable`
#: does. Naming the column "off" would have made an alert-only model invisible here.
#: A per-application override defeats the decoder action for one application, so a profile
#: hardened on every decoder can still allow malware over whatever is listed here. "none" is
#: the normal answer - an override is an operator-added exception - and it is spelled out
#: rather than left blank so the cell distinguishes "no overrides" from "not looked at".
APP_OVERRIDE_COVERAGE = findings_sheet.ValueReader(
    read=lambda profile: (", ".join(profile.non_blocking_application_overrides)
                          if profile.non_blocking_application_overrides else "none"),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)

#: The decoder's second and third action columns. Separate verdict sources from the signature
#: action, so a profile hardened in the first column alone shows its gap only here.
WILDFIRE_COVERAGE = findings_sheet.ValueReader(
    read=lambda profile: (", ".join(profile.non_blocking_wildfire_decoders)
                          if profile.non_blocking_wildfire_decoders else "none"),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)

MLAV_COVERAGE = findings_sheet.ValueReader(
    read=lambda profile: (", ".join(profile.non_blocking_mlav_decoders)
                          if profile.non_blocking_mlav_decoders else "none"),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)

ML_COVERAGE = findings_sheet.ValueReader(
    read=lambda profile: (", ".join(profile.non_blocking_ml_models)
                          if profile.non_blocking_ml_models
                          else ("all enabled" if profile.ml_models.all() else "—")),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)


#: Which protocol decoders an antivirus profile does NOT stop malware on. Blank for every
#: other kind, which has no decoders. The resolved action, not the configured one - the
#: configuration says `default` on every decoder of every unedited profile, so a column showing
#: what the config holds would show the same word on a profile that blocks and one that does not.
DECODER_COVERAGE = findings_sheet.ValueReader(
    read=lambda profile: (", ".join(profile.non_blocking_decoders) + " (alert only)"
                          if profile.non_blocking_decoders
                          else ("all block" if profile.decoders.all() else "—")),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)


#: How far the reference walk reaches a profile, IN THE MODEL'S OWN WORDS.
#:
#: WHY THIS READER EXISTS: the `setting_labels` entry for `reference_reach` on the Security Profile
#: spec says "the model's own choice labels are already sentences ... so the heading is the short
#: noun and the CELL carries the meaning". MEASURED 2026-11-02 by building that table: the cell did
#: NOT carry the meaning. `read_value` falls through to `display_value`, which is choices-unaware
#: and ends in `str(value)`, so the cell printed the raw choice KEY - `named_by_a_rule`,
#: `unreferenced`, `undetermined` - to a customer, on both PAN-ZON-008's rows and this domain's.
#: The configuration explorer's own pages for the same column already call
#: `get_reference_reach_display()`, so the two surfaces disagreed about what one column says.
#:
#: IT COSTS NOTHING HERE, which is the condition `ipsec-crypto` established for a reader on a
#: derived settings column: a reader makes `tested_fields` report the field `stored=False`, and
#: `build_rows` then hands it to `remediation_accessor`, which never reads its `FieldProvenance`
#: row. `reference_reach` is in `SecurityProfile.DERIVED_FIELDS` and no payload key carries it, so
#: there is no such row to discard - the Provenance cell for this field read "Not recorded" before
#: this reader and reads "Derived" after it, which is the true answer and the one
#: `vsys_rule_posture` makes the same argument for.
#:
#: AND IT IS DELIBERATELY NOT DONE TO THE TWO GRADED ACTION COLUMNS of this domain,
#: `floor_file_type_action` and `nested_encoding_action`, on that same run's warning: for those the
#: EMPTY STRING is a measured state - a committed rule carrying no `action` key at all - and it is
#: what PAN-FIL-001's and PAN-FIL-002's absent-action rows turn on. Where whether a key was absent
#: is what the control is ABOUT, the rule is to refuse the reader and let the marked companion
#: column say it. Those two keep `display_value`'s `(empty)`.
REFERENCE_REACH = findings_sheet.ValueReader(
    read=lambda profile: profile.get_reference_reach_display(),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)

# --------------------------------------------------------------------------------------------
# TWO READERS ADDED 2026-11-02 BY STAGE 9 OF `url-filtering`, and both fix a cell rather than
# adding a column. Each one replaces a placeholder that reads as MISSING DATA on a row where the
# honest answer is the PASSING state - the shape Jason caught once already, where "the most
# reassuring cell on the row was the finding".
#
# MEASURED BEFORE WRITING THEM, over this domain's 21 findings rows:
#   `worst_unrecorded_request_header`         `(empty)` on the 2 rows that log all three headers
#   `broadest_inline_analysis_exemption_type` `(none)`  on 15 rows, 13 of which exempt nothing
# `display_value` has exactly three answers - a value, `(none)` for NULL and `(empty)` for the
# empty string - so neither state can be said through it.
#
# THEY COST NO PROVENANCE, which is the only reason they are allowed. Both fields are in
# `SecurityProfile.DERIVED_FIELDS`, and a reader is free on a derived field: there is no
# `FieldProvenance` row for `remediation_accessor` to discard. Contrast
# `credential_detection_mode`, which is a MEASURED PAYLOAD KEY carrying such a row - this run
# REFUSED a reader there and left the device's own token in the cell, because whether the
# credential-enforcement node was absent or explicitly `disabled` is what that control is about.
#
# AND THEY BRANCH ON `kind`, WHICH IS WHAT MAKES THEM SAFE ON A SHARED SPEC. This spec serves
# seven profile kinds and five other domains' controls, so a reader that answered unconditionally
# would put a sentence about HTTP request headers on an antivirus row, where the question does
# not exist. `reader.read(subject)` is handed the subject, so each reader answers for its own
# kind and returns `layout.NONE` - the em dash, U+2014, the sanctioned vocabulary for "this
# branch does not exist on this subject" - for every other kind. That is strictly more honest
# than the `(empty)`/`(none)` those rows show today, and it is the one thing this run changes
# about what another domain's rows read.
#
# NOTE THAT THIS MAKES THE EM-DASH ESCAPE REACHABLE ON A MULTI-KIND MODEL, which the stage 9
# contract's finding 4 says it is not: that finding says "your own subject columns can use an em
# dash for that state; the derived settings columns cannot, because `display_value` is shared by
# every tab". True of `display_value` - and `setting_columns` consults `value_readers` BEFORE it,
# so a reader branching on the row's own kind reaches the state per KIND rather than per MODEL.
# --------------------------------------------------------------------------------------------

def _url_filtering_only(read):
    """Answer for a url-filtering row; give every other kind the em dash.

    The columns these readers head are derived from THIS domain's clauses, so they appear on
    every kind's row of the shared tab while meaning something on one. The em dash says that.
    """
    def answer(profile):
        if profile.kind != SecurityProfile.KIND_URL_FILTERING:
            return NONE
        return read(profile)
    return answer


#: THE PASSING STATE WAS THE BLANK ONE. The store holds "" when every one of the three request
#: headers IS logged, so `display_value` printed `(empty)` on exactly the rows where nothing is
#: wrong - a cell that reads as "nobody collected this" where it means "we checked all three".
#: The header NAMES are the vendor's own (X-Forwarded-For, User-Agent, Referer) and are stored as
#: labels, so a failing cell needed no help; only the empty one did.
WORST_UNRECORDED_HEADER = findings_sheet.ValueReader(
    read=_url_filtering_only(
        lambda p: p.worst_unrecorded_request_header or "None missing"),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)

#: NULL HERE HAS TWO MEANINGS and `(none)` serves neither: the profile exempts nothing, or an
#: exemption names a category whose own row this assessment never read - which is the estate where
#: the categories are in force through the pushed read and nobody issued it. The COUNT separates
#: them and the reader reads it, so the cell says which.
BROADEST_EXEMPTION = findings_sheet.ValueReader(
    read=_url_filtering_only(
        lambda p: (p.broadest_inline_analysis_exemption_type
                   or ("Nothing exempted" if not p.inline_analysis_exemption_count
                       else "Exempted category not read"))),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)


# --------------------------------------------------------------------------------------------
# SIX MORE READERS, 2026-11-02 by stage 9 of `decryption-profiles`, for PAN-DCP-001, -002, -005
# and -007. Each one FIXES A CELL and none adds a column.
#
# ALL SIX ARE ON FIELDS IN `SecurityProfile.DERIVED_FIELDS`, which is the condition that makes a
# reader free: `tested_fields` marks a field that has a reader `stored=False`, `build_rows` hands
# that to `remediation_accessor`, which then never reads the field's `FieldProvenance` row - and
# for a derived column there is no such row to discard, so the Provenance cell goes from "Not
# recorded", which means "nothing tracks this field", to "Derived", which is the true answer.
# Verified per field with `field in SecurityProfile.DERIVED_FIELDS` rather than assumed.
#
# FIVE OF THE SIX BRANCH ON `kind` AND THE SIXTH DELIBERATELY DOES NOT. The columns these head are
# derived from THIS domain's clauses, so they are drawn on every kind's row of the shared tab while
# meaning something on one: an antivirus row carries `ssl_min_version_below_tls12 = True` and
# `weakest_broken_primitive_permitted = "rc4"`, because those are the measured implicit values of
# keys an antivirus profile has no container for at all. Before this change a vulnerability
# protection row told a customer its protocol floor was below TLS 1.2. The em dash says instead
# that the branch does not exist on that subject.
#
# `is_used` IS THE EXCEPTION AND THE REFUSAL IS ON THE RECORD. It is not a decryption column -
# it is `SecurityProfile.is_used`, declared beside `referrer_count` for every kind, and
# PAN-AVW-006 ("Unused AV / WildFire Profiles") is a shipped control over exactly it. A kind gate
# there would print an em dash over a value that is true and load-bearing on five other kinds,
# which is the opposite of what these readers are for. `display_value`'s Yes/No is honest for it
# and it keeps it.
#
# THE FOURTEEN MEASURED PAYLOAD KEYS GET NO READER AT ALL and that refusal is the larger half of
# this decision. See the `setting_labels` block on the SECURITY_PROFILE spec below, which records
# each one and why.
# --------------------------------------------------------------------------------------------

def _decryption_only(read):
    """Answer for a decryption row; give every other kind the em dash.

    `layout.NONE` - U+2014 EM DASH - is the sanctioned vocabulary for "this branch does not exist
    on this subject", and `read_value` consults `value_readers` BEFORE `display_value`, so a
    reader branching on the row's own kind reaches that state per KIND on a model that carries
    nine of them.
    """
    def answer(profile):
        if profile.kind != SecurityProfile.KIND_DECRYPTION:
            return NONE
        return read(profile)
    return answer


#: PAN-DCP-001's and PAN-DCP-002's applicability clause. Kind-gated only: `Yes`/`No` is the honest
#: rendering on a decryption row, and the three states behind a `Yes` - every rule naming it leaves
#: the destination open, NO rule names it, or the rulebase was not collected - are not separable
#: from this column and are not a cell's to invent. The companion column
#: `Decryption rulebase read from the device?` is what tells the third from the other two, and
#: stage 8 has that disagreement on the record as a `needs_human`.
RULE_DESTINATION_UNRESTRICTED = findings_sheet.ValueReader(
    read=_decryption_only(
        lambda p: findings_sheet.display_value(p.rule_destination_unrestricted)),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)

#: PAN-DCP-001's two verdicts. Both default TRUE so an unrecomputed row reports itself, and both
#: are meaningless on the other eight kinds, which is the whole reason for the gate.
SSL_MIN_BELOW_TLS12 = findings_sheet.ValueReader(
    read=_decryption_only(
        lambda p: findings_sheet.display_value(p.ssl_min_version_below_tls12)),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)
SSL_MAX_RESTRICTIVE = findings_sheet.ValueReader(
    read=_decryption_only(
        lambda p: findings_sheet.display_value(p.ssl_max_version_restrictive)),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)


def _weakest(value) -> str:
    """The worst algorithm still negotiable, with `none` SPELLED and the blank named.

    `none` is the COMPLIANT member of both of these columns and is the one a bare token reads
    wrongly: a cell reading `none` beside a passing row reads as "no value recorded" where it
    means "nothing weak is negotiable" - the same shape as `WORST_UNRECORDED_HEADER` above, where
    the passing state was the blank one.

    The algorithm names themselves are the vendor's own, upper-cased: RC4, 3DES, MD5 and SHA1 are
    help 11.2 p.345-346's own spellings, and RSA, AES-128-CBC and AES-256-CBC come from its Key
    Exchange and Encryption Algorithms lists. Upper-casing reproduces all seven exactly, so a
    member added to either ordering tuple comes out right rather than coming out missing.
    """
    if not value:
        return "Not computed"
    if value == SecurityProfile.PRIMITIVE_NONE:
        return "None negotiable"
    return value.upper()


#: PAN-DCP-002's two graded columns.
WEAKEST_BROKEN_PRIMITIVE = findings_sheet.ValueReader(
    read=_decryption_only(lambda p: _weakest(p.weakest_broken_primitive_permitted)),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)
WEAKEST_NON_PFS = findings_sheet.ValueReader(
    read=_decryption_only(
        lambda p: _weakest(p.weakest_non_pfs_or_unauthenticated_permitted)),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)

#: PAN-DCP-007's companion. It defaults FALSE, so on the other eight kinds the cell answered `No`
#: to "was the decryption rulebase read?" - a question those rows do not ask, answered in the
#: alarming direction. The em dash is the honest cell there.
DECRYPTION_RULEBASE_COLLECTED = findings_sheet.ValueReader(
    read=_decryption_only(
        lambda p: findings_sheet.display_value(p.decryption_rulebase_collected)),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)


#: Which appliance spoke for this point, and which virtual system the verdict is about.
#:
#: NEITHER DECLARES A `field`, and that is deliberate: the verdict this control asserts on is a
#: derived setting column, and declaring one here would move the value-at-fault mark off the verdict
#: and onto the row's address. (A subject column that declares no field also does NOT suppress the
#: derived column for the same attribute - so a column declared here with a field would hide the
#: verdict rather than present it.)
#:
#: "Firewall" singular and not "Firewalls": unlike the vsys-scoped tabs this row IS per appliance -
#: the model's unique constraint is (appliance, enforcement_point) - so listing a pair here would
#: say something the row does not mean. See the spec's own block.
DATA_FILTERING_POSTURE_SUBJECT = (
    ("Firewall", 16, False, lambda p, _prov: p.appliance.hostname or NONE),
    ("Vsys", 12, False, lambda p, _prov: p.enforcement_point.vsys_name or NONE),
)

#: PROPOSED HEADINGS for the Data Filtering Posture tab's derived setting columns. Jason takes the
#: heading pass once across many domains (P399), so none of these is a decision: the column SET
#: comes from PAN-FIL-003's own clause and only the words are typed here. Without an entry the
#: column would be headed `outward_data_filtering_effective`.
#:
#: THE VENDOR HAS NO WORD FOR ANY OF THEM, and that is measured rather than assumed: PAN-OS Web
#: Interface Help 11.2 p.309 describes the MECHANISM - "Data filtering enables the firewall to
#: detect sensitive information ... and prevent this data from leaving a secure network" - and names
#: no state at all. Of the vendor's own labels on that screen only "Data Pattern" (p.309) reaches a
#: heading here. The rest are ours.
#:
#: EACH IS PHRASED AS THE THING THAT SHOULD BE TRUE, so "No" is the finding and "Yes" is the healthy
#: answer on all three. That matters more here than on most tabs, because the two columns beside the
#: verdict exist to say WHICH of its three independent parts failed, and a reader scanning for the
#: cause must not have to work out which way each one points.
DATA_FILTERING_POSTURE_LABELS = {
    # PAN-FIL-003's one shipped clause, and the only one of the three any query names. The
    # conjunction is one column rather than three clauses because the assertion has no OR and the
    # three parts fail independently - which is what the two below are for.
    "outward_data_filtering_effective": "Outbound data watched",
    # "A profile WITH RULES", because the rule-bearing test is the whole point: the only referenced
    # data-filtering profile in the lab estate is a pushed one carrying no rules, so a bare "is it
    # referenced" reading finds one profile in force across four appliances and it scans nothing.
    "data_filtering_in_force": "A profile with rules reaches this traffic",
    # "Data Pattern" is the vendor's own word, p.309. FALSE means the profile names a pattern
    # object that matches nothing - valid configuration that filters nothing.
    "named_patterns_defined": "Every named data pattern defines one",
    # `profiles_in_force` has no entry: it is a JSONField, no clause names it, and
    # `setting_labels` is consulted only for columns `setting_columns` derived. The evidence list
    # is presented on the explorer page, where it is a column.
}


# --------------------------------------------------------------------------------------------
# THE FOUR SaaS TABS, 2026-11-02, for PAN-SAS-001 to -005. Four models, four grains and THREE
# PAN-OS categories - an application's approval tag (Objects), a URL Filtering profile's SaaS
# controls (Objects), a virtual system's whole rulebase (Policies) and a device-wide service
# switch (Device) - so they are four tabs in three different places in the Summary rather than
# one domain's block. The whole domain is new to presentation: nothing in this repository drew a
# row for any of these four control types before today, and not one of their ten clause fields
# had a heading.
#
# WHY FOUR AND NOT ONE. An engineer fixes one of four different things at four different vendor
# addresses, and that is the same split `vsys_rule_posture` and `security_rules` already make
# over the security rulebase. The rail items follow it.
#
# EVERY HEADING AND EVERY TAB TITLE BELOW IS A PROPOSAL. Report content is Jason's and he takes
# the heading pass once across many domains (P399). What is typed here is only the WORDS - the
# column SET is derived from the controls' own clauses. Where the vendor has a word this uses it
# and cites the page; where the vendor has NONE the comment says so rather than implying one.
# All four titles are 31 characters or fewer, which is Excel's silent cap on a sheet name:
# "Sanctioned Applications" (23), "SaaS URL Filtering Posture" (26), "SaaS Application Policy"
# (23) and "App-ID Cloud Engine" (19).
#
# THREE SUBJECTS ARE VSYS-SCOPED AND NONE OF THE THREE MODELS HAS AN `appliance`. They hang off
# an `EnforcementPoint`, so all three specs override the three appliance-scoped defaults -
# `subject_columns`, `appliance_of` and `subject_select_related` - on `vsys_rule_posture`'s
# precedent, and reuse `VSYS_SCOPED` above. `appliance_of` returns None deliberately: an
# enforcement point is unique per `(appliance_group, vsys_name)`, so on an HA pair ONE POINT
# SPANS BOTH MEMBERS and linking a row to one peer would assert something false.
#
# AND THAT IS WHY STAGE 5'S HA CLAIM IS NOT IMPLEMENTED HERE. Stage 5 says of all four subjects
# that an HA pair yields TWO rows for one real configuration "and nothing downstream
# deduplicates them". Measured 2026-11-02 off `_meta.constraints` and then on a deliberately
# built HA pair (two appliances in one `ha_pair` group, 7 points, 14 nodes, identical payloads):
# `SanctionedApplicationMarking`, `SaasUrlFilteringPosture` and `SaasApplicationPolicyPosture`
# each declare `unique(enforcement_point)`, so the pair SHARES one point and all three drew 7
# rows for 7 configurations in BOTH arms of `flows.get_in_scope_appliances`. They deduplicate one
# layer BELOW presentation and there is nothing for a sheet to collapse. Only
# `CloudAppEngineSetting` declares `unique(appliance)` and so draws a row per member - 1 row with
# `EnforcementPoint.appliance` set and 2 with it null, because `get_in_scope_appliances` takes
# that field and never consults the point's nodes. Its tab keeps both, on Data Filtering
# Posture's ruling that two peers' configurations are not known to be identical.
#
# NO PROVENANCE ROW EXISTS FOR ANY TESTED COLUMN OF ANY OF THE FOUR, so all four specs answer the
# Provenance cell themselves and none carries a Template column. Measured with the default cell:
# "Not recorded" on every tested field of every row of all four tabs. The three postures are
# documented - `normalization/saas_security.py:1036` says "NO PROVENANCE ROW ON ANY OF THE THREE,
# not even `__entry__`" - and the FOURTH was settled by building the row and reading the cell
# rather than by reasoning: `CloudAppEngineSetting` goes through `write_node_row`, which writes a
# row per NAMED field and no `__entry__` at all, and its provenance tuple names only
# `ace_disabled` and `cloudapp_server_address`, neither of which PAN-SAS-005 tests. So the one
# real `FieldProvenance` row in the whole domain belongs to a field no control tests, and the
# Provenance cell never reads it.
#
# NO VALUE READER ON ANY COLUMN, and that is a decision rather than an omission. NOT ONE FIELD of
# any of the four models declares `choices` - checked field by field through `_meta` - so no
# labelling reader is owed, and `get_<field>_display()` DOES NOT EXIST on any of them: the call
# would raise `AttributeError` at TEMPLATE RENDER, past `django check` and past all three
# cross-domain gates. Every tested column reads honestly through `display_value`.
#
# `hidden_fields` IS EMPTY ON ALL FOUR AND STAYS EMPTY. The gate counts a field as presented if a
# subject column, a settings column OR `hidden_fields` carries it, so a non-empty tuple is a
# CLAIM accepted as proof, and it is the only known cause in this repository of a findings row
# that marks nothing as the thing to fix (P409). Every tested field of all five controls has a
# real column.
#
# `tested_columns=ALL_TESTED_COLUMNS` ON ALL FOUR IS A CHOICE: the default `("Provenance",)`
# silently drops `Fires when` from the WORKBOOK while the live page keeps it, so the two surfaces
# would disagree about which cell a reader meets (P427). It is taken knowing that `fires_when`
# renders the BASELINE's condition alone - so on the one PAN-SAS-001 row whose finding comes from
# the calibration query alone, the stated condition is one that row does not meet. The
# alternative is a contradicting value with no stated condition beside it at all.

#: The word every Provenance cell on the four SaaS tabs reads. One answer for the whole row, on
#: `vsys_rule_posture`'s precedent: the default cell answers per tested field through the
#: remediation walk, which on all four of these models resolves to "Not recorded".
def _saas_derived_cell(subject, provenance_of, fields) -> str:
    return findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label


_SAAS_VSYS_SELECT_RELATED = ("enforcement_point__appliance_group", "enforcement_point__appliance")
_SAAS_VSYS_PREFETCH = ("enforcement_point__appliance_group__appliances",)

#: Sanctioned Applications. The address, then the inventory the verdict is computed over.
#:
#: `marked_application_names` IS HERE BECAUSE STAGE 5 DECLARED IT PRESENTED AND NOTHING DERIVES
#: IT. A settings column is derived only for a field an active query has a CLAUSE on, and no
#: query of this control touches this one - so the flag and the machinery disagree, and
#: hand-declaring is the documented way to settle it. It earns the space: the commonest failing
#: state is that the partition marks NOTHING, and this is the column that tells an engineer
#: whether the remediation is to start the inventory or to extend it. It DECLARES its `field`
#: even though no control tests it, on the Device-ID tabs' ruling.
SANCTIONED_APPLICATION_MARKING_SUBJECT = VSYS_SCOPED + (
    ("Applications marked approved", 30, True,
     lambda m, _p: "\n".join(m.marked_application_names) if m.marked_application_names
     else "Nothing marked",
     "marked_application_names"),
)

#: PROPOSED HEADINGS for Sanctioned Applications.
#:
#: THE VENDOR HAS A VERB FOR THE MECHANISM AND NO WORD FOR TWO OF THESE STATES. Help 11.2 p.231,
#: under `Objects > Applications`: "A predefined tag named sanctioned is available for you to tag
#: SaaS applications ... Tag applications as sanctioned to help differentiate sanctioned SaaS
#: application traffic from unsanctioned SaaS application traffic", and p.242 names the screen:
#: "A predefined tag named Sanctioned is available for tagging applications (Objects >
#: Applications)." So "approved" is OURS and "marked" tracks the vendor's verb.
SANCTIONED_APPLICATION_MARKING_LABELS = {
    # Record 0, and the whole control in one clause: the failure is the ABSENCE of the mechanism
    # rather than a value in it. Phrased as a count because that is what the clause names -
    # `equals 0` is the finding - and printed as a NUMBER, on `rule-posture`'s ruling for a count
    # column: "Nothing" on a column named for a count reads as "not counted" exactly where it
    # means "counted, and the answer was none".
    "sanctioned_application_count": "Applications marked approved (count)",
    # Record 1's APPLICABILITY clause, which draws a column because `tested_fields` registers
    # applicability clauses too. It is not the fault and is never marked; it is the condition
    # under which the column below means anything at all.
    "appliance_is_multi_vsys": "Appliance has several virtual systems",
    # THE ONE HEADING HERE IN THE VENDOR'S OWN WORDS: Help 11.2 p.57, on the ACC's application
    # view, "yellow indicates applications that have different sanctioned state across different
    # virtual systems or device groups". Phrased in the FIRING polarity deliberately - the column
    # defaults false and TRUE is the finding - so the firing cell reads "Yes" under a heading
    # that says the bad thing. The failure this stage exists to catch is a row whose most
    # reassuring cell is the finding.
    "marking_is_inconsistent_across_vsys": "Approval differs between virtual systems",
}

#: SaaS URL Filtering Posture. The address, then the four stage-5-presented columns no clause
#: derives.
#:
#: `url_filtering_profiles_read` IS THE MOST IMPORTANT COLUMN ON THAT TAB. Both verdicts are
#: booleans in the direction that PASSES, so FALSE is the finding - and FALSE is also what a
#: partition holds when NOBODY LOOKED. Measured on a seeded estate: two of nine rows carry
#: `url_filtering_profiles_read = False` with `tenant_restriction_in_force = False` beside it, so
#: the finding fires on a partition whose profiles were never read. `rules.md` puts it exactly: a
#: reading that cannot tell ZERO from UNKNOWN is an unknown, per FIELD and not per device - and an
#: unknown firing is the correct direction. What is NOT correct is a row that does not say which
#: it was, and this column is the only thing on the tab that can.
#:
#: THE THREE COUNTS ARE THE EVIDENCE FOR THE VERDICTS and stage 5 declared all three presented.
#: Each answers a different "why" an engineer would otherwise open the device for: how much
#: header-insertion coverage exists at all, how much of it names a header and carries no value
#: (configured and restricting nothing), and how many rules take the native route the control
#: prefers.
SAAS_URL_FILTERING_POSTURE_SUBJECT = VSYS_SCOPED + (
    ("Profiles read", 14, False,
     lambda p, _p: findings_sheet.display_value(p.url_filtering_profiles_read),
     "url_filtering_profiles_read"),
    ("Header insertion entries", 24, False,
     lambda p, _p: str(p.header_insertion_type_entry_count),
     "header_insertion_type_entry_count"),
    ("Headers naming no tenant", 24, False,
     lambda p, _p: str(p.tenant_header_without_value_count),
     "tenant_header_without_value_count"),
    ("Rules using a SaaS Tenant List", 30, False,
     lambda p, _p: str(p.rule_bound_tenant_list_count),
     "rule_bound_tenant_list_count"),
)

#: PROPOSED HEADINGS for SaaS URL Filtering Posture. TWO CONTROLS SHARE IT - PAN-SAS-002 and
#: PAN-SAS-004 - because `finding_registry.KIND_BY_MODEL` is keyed by model, so one model lives
#: under exactly one control type.
#:
#: THE VENDOR'S OWN WORDS, established in the corpus. Help 11.2 p.302 names the screen verbatim -
#: "select Objects > Security Profiles > URL Filtering > HTTP Header Insertion" - and p.303 gives
#: the field labels "Type", "Domains", "Header" and "Value". p.297, under URL Filtering
#: Categories, gives "Site Access": "For each URL category, select the action to take when a user
#: attempts to access a URL in that category", listing alert, allow, block, continue and
#: override. So the treatment column's heading is the vendor's and the two verdicts' are ours.
SAAS_URL_FILTERING_POSTURE_LABELS = {
    # PAN-SAS-002's whole assertion in one verdict, in the direction that PASSES, so "No" is the
    # finding. "In force" rather than "configured": the verdict requires both that a profile
    # inserts a tenant-restriction header AND that a security rule of this partition carries that
    # profile - a profile nothing references restricts nothing.
    "tenant_restriction_in_force": "Tenant restriction in force",
    # PAN-SAS-004's baseline assertion, also in the passing direction.
    "consumer_storage_categories_are_restricted": "Consumer storage categories restricted",
    # PAN-SAS-004's CALIBRATION query adds this one. "Site Access" is the vendor's own heading,
    # p.297. The value is the LEAST restrictive treatment any consumer-storage category gets, and
    # `in-no-restricting-list` means the category reaches no restricting surface at all - which is
    # why the raw token is printed rather than prettied: a word like "none" would not distinguish
    # "allowed by a list" from "in no list".
    "consumer_storage_category_treatment": "Site Access (least restrictive)",
}

#: SaaS Application Policy. The address, the graded column, and the three attribute-selection
#: columns no query can reach.
#:
#: `effective_action_for_function_apps` IS A SUBJECT COLUMN AND THAT WAS A FORCED CHOICE WORTH
#: STATING. Stage 8's diff disagrees with stage 6 on three of PAN-SAS-003's rows for exactly this
#: reason: the verdict and the severity agree and the COLUMN does not - stage 6 writes `fires_on`
#: as this GRADED column and the shipped query asserts on the verdict boolean beside it. A
#: settings column is derived only for a field an active query clauses on, and no query has one
#: here, so a derived column is not available; `hidden_fields` would forfeit the mark AND show
#: nothing. A subject column is the only state in which the value reaches a customer at all.
#:
#: THE PRICE, STATED RATHER THAN HIDDEN: it can never carry the value-at-fault fill. `implicated`
#: marks a subject column only when its field is in the matched query's `asserted_fields`, which
#: for PAN-SAS-003's baseline is `function_apps_are_refused` alone. So the row marks the boolean
#: and the column that tells a customer what the rulebase ACTUALLY DOES sits beside it unmarked.
#: Writing a query that would change that is stage 8's work.
#:
#: AND THE THREE `cloud_app_*` COLUMNS ARE HERE BECAUSE A CONTROL CANNOT REACH THEM. PAN-SAS-004
#: record 1 asserts `cloud_app_selection_is_refused equals false`, a column of THIS model, while
#: that control targets `SaasUrlFilteringPosture`; `Control.save()` derives one `target_model`
#: from `control_type` and `ControlQuery.clean()` refuses a query naming any other, so the catalog
#: row cannot be created. That is a live decision awaiting Jason (P390) and minting a control id
#: is not this stage's to do. Stage 8 measured the consequence: on one partition record 0 passes
#: and record 1 cannot fire, so a customer with that configuration is told their posture is sound.
#: Presenting the three columns is the most this stage can do - the values reach a reader even
#: though no control grades them - and each declares its `field` so that the control which
#: eventually can will mark the existing cell rather than draw a second one.
SAAS_APPLICATION_POLICY_POSTURE_SUBJECT = VSYS_SCOPED + (
    ("Action on function apps", 24, False,
     lambda p, _p: findings_sheet.display_value(p.effective_action_for_function_apps),
     "effective_action_for_function_apps"),
    ("Rules naming a function app", 28, False,
     lambda p, _p: str(p.function_app_rule_count), "function_app_rule_count"),
    ("Attribute-driven cloud filters", 30, False,
     lambda p, _p: str(p.cloud_app_filter_count), "cloud_app_filter_count"),
    ("Cloud-app selection refused", 28, False,
     lambda p, _p: findings_sheet.display_value(p.cloud_app_selection_is_refused),
     "cloud_app_selection_is_refused"),
    ("Selection carves out the approved", 32, False,
     lambda p, _p: findings_sheet.display_value(p.cloud_app_selection_excludes_approved),
     "cloud_app_selection_excludes_approved"),
)

#: PROPOSED HEADINGS for SaaS Application Policy.
#:
#: THE VENDOR NAMES THE SCREEN AND NOT THE STATE. `Policies > Security` is the address and
#: `Objects > Application Filters` is where the attribute-driven selection is built - Help 11.2
#: p.213 lists both in the Objects tree, and p.147 says an Application Filter "works the same way
#: as Objects > Application Filters ... You can filter cloud-based (with a SaaS Inline Security
#: subscription) and content-based applications". "Action" is the vendor's own column heading on
#: the security rulebase. The verdict's own wording is ours.
SAAS_APPLICATION_POLICY_POSTURE_LABELS = {
    # PAN-SAS-003's one shipped clause, in the direction that PASSES, so "No" is the finding - and
    # "No" is also what a rulebase naming none of these applications holds, which is the commonest
    # failing state. The verdict asserts a RELATION BETWEEN TWO RULES (a refusal of a function
    # child evaluated before a permission on its parent) reduced over a first-match walk across
    # three rulebases, so no leaf on the device holds it and the companion columns above are what
    # a reader has instead.
    "function_apps_are_refused": "Upload and sharing functions refused",
}

#: App-ID Cloud Engine. The appliance and its HA role, then the configuration key and the
#: did-we-look column.
#:
#: `ace_disabled` IS THE VENDOR'S OWN KEY AND THE THING AN ENGINEER FIXES, and no clause names it,
#: so nothing derives a column for it. Stage 5 declared it presented. It keeps the VENDOR'S
#: polarity - TRUE means the engine has been deliberately switched off, which is the vendor's own
#: checkbox and not a verdict - because inverting it would put our word over the vendor's screen.
#: It is also the ONE COLUMN IN THIS WHOLE DOMAIN WITH A REAL PROVENANCE ROW
#: (`assumed_default`, where the key is absent) and no control tests it, so the Provenance cell
#: never reads that row. Worth knowing and not something a sheet can fix.
#:
#: `cloudapp_node_read` IS THE PAIR THAT MAKES `ace_disabled` HONEST. `ace_disabled` is nullable
#: and NULL means the `deviceconfig/setting` subtree was never read - neither present nor absent
#: but UNREAD. One boolean cannot carry "off" and "never asked" at once, so this is the second
#: column rather than a label. `cloudapp_server_address` is NOT shown: stage 5 declares it
#: `presented: false`, it is not searchable, and an endpoint override is not what any finding here
#: is about.
CLOUD_APP_ENGINE_SETTING_SUBJECT = APPLIANCE + (
    # THREE-WAY, AND `display_value` CANNOT DO IT: it has only a value, `(none)` for NULL and
    # `(empty)`. Measured on a built row before this branch existed, the cell read `(none)` -
    # which on a column headed "Engine disabled in configuration" reads as "nothing is configured
    # there", and nothing configured is the engine being ON. This is a SUBJECT column, so the
    # branch costs nothing: no provenance row is discarded and no `value_readers` entry is
    # involved.
    ("Engine disabled in configuration", 32, False,
     lambda s, _p: ("Not read" if s.ace_disabled is None
                    else findings_sheet.display_value(s.ace_disabled)), "ace_disabled"),
    ("Configuration node read", 24, False,
     lambda s, _p: findings_sheet.display_value(s.cloudapp_node_read), "cloudapp_node_read"),
)

#: PROPOSED HEADINGS for App-ID Cloud Engine.
#:
#: THE VENDOR'S OWN SCREEN AND ITS OWN WORDS, established in the corpus. The section path
#: `Device > Setup > ACE` appears verbatim in all three indexed Help versions - 11.2 p.796, 11.1
#: p.783 and 12.2 p.824 - so the address is stable across releases. 11.2 p.796: "Enable or disable
#: App-ID Cloud Engine (ACE) settings and settings related to SaaS Security Inline policy
#: recommendations", the checkbox is labelled "Disable the App-ID Cloud Engine", and "You must
#: have a valid SaaS Security Inline license on the firewall to use ACE" - which is what the
#: applicability clause is about. The vendor has NO word for "the engine is not working": that is
#: a reading this assessment computes from an operational command, and the heading is ours.
CLOUD_APP_ENGINE_SETTING_LABELS = {
    # The APPLICABILITY clause, which draws a column because `tested_fields` registers them. It is
    # not the fault and is never marked. It reads `license_check_failed` on an unlicensed
    # appliance - which the clause EXCLUDES, because an appliance with no SaaS Security Inline
    # subscription is not misconfigured - and `unread` where no operational read came back at all.
    "ace_failure_reason": "Why the engine is not working",
    # The assertion, in the direction that FIRES, so "Yes" is the finding. Deliberately in that
    # polarity: the column defaults true and a heading like "Engine operational" would put "No" in
    # the firing cell and "Yes" in the healthy one.
    "ace_not_operational": "Engine not working",
}


# --------------------------------------------------------------------------------------------
# THE THREE DECRYPTION-POLICY TABS, 2026-11-02, for PAN-DEC-001 to -010. Three models, three
# grains, and the whole domain is new to presentation: nothing in this repository drew a row for
# any of these three control types before today, and not one of their seventeen clause fields had
# a heading.
#
# WHY THREE AND NOT ONE. A PAN-DEC-001 finding names a VIRTUAL SYSTEM - "this enforcement point
# opens no outbound web session at all" - and a PAN-DEC-002 finding names a RULE inside it, and an
# engineer fixes one or the other: the coverage findings are fixed by ADDING a rule that is not
# there, and the rule findings by editing a rule that is. The exclusion is a third subject at a
# third vendor address. That is the same split `vsys_rule_posture` and `security_rules` already
# make over the security rulebase, and the rail items follow it.
#
# WHY NOT FOUR. `integrations.SslDecryptionVendorExclusionOptOut` carries PAN-DEC-004's second
# assertion record and is named by NO SHIPPED QUERY, measured over the seed payload - so no
# finding of its kind can exist and it is owed no tab. See
# `decryption_policy_presentation`'s module docstring, and the generator's own, for the three
# reasons that is a recorded state rather than an omission.
#
# `hidden_fields` IS EMPTY ON ALL THREE AND IS NOT DECLARED. The gate counts a field as presented
# if a subject column, a settings column OR the sheet's own `hidden_fields` carries it, so a
# non-empty tuple is a CLAIM accepted as proof and it is the only known cause in this repository
# of a findings row that marks nothing as the thing to fix. Every one of the seventeen fields gets
# a real column here.

#: A row of one virtual system's decryption rulebase, as the four columns stage 5 keys the subject
#: on, in the shape the policy tabs already name a rule.
#:
#: VSYS-SCOPED AND SO NO APPLIANCE COLUMN. A decryption rule belongs to a virtual system, which on
#: an HA pair spans both members, so there is no one appliance to name or to link to - which is
#: also why `appliance_of` returns None on this spec. The Firewalls column lists the pair from the
#: enforcement point's own owner.
#:
#: NOT ONE OF THESE FOUR DECLARES A `field`, and on this tab that is the SAFE side of the trap
#: rather than the unsafe one. A subject column that declares no field does not suppress the
#: derived setting column for the same attribute - so one value can reach a tab twice under two
#: headings, and because the headings differ the duplicate-header guard never fires. None of these
#: four attributes is a clause field of any PAN-DEC control, so there is no derived column for any
#: of them and nothing to collide with; `rule_rulebase` carries the reasoning for the one that is
#: a stored column.
#:
#: THE POSITION IS DELIBERATELY ABSENT, which is where this differs from the DoS rules tab beside
#: it. Stage 5 excluded `rule_position` from the identity with a measurement: a rule keeps its name
#: and its uuid across an `action=move` - stage 4 moved a pair twice and both uuids were unchanged
#: - so keying on position would make a reorder look like a delete and an insert. And the stored
#: column is the CONFIGURATION rank rather than the evaluation index: `show running
#: decryption-policy` skips a disabled rule, so from the first disabled rule onward every rule
#: after it renders one lower than the number stored here. Printing it as "Position" would state
#: an evaluation order that is false on exactly the rulebases this domain is about.
DECRYPTION_RULE_SUBJECT = VSYS_SCOPED + (
    ("Rulebase", 16, False, decryption_policy.rule_rulebase),
    ("Object", None, False, lambda s, _p: s.rule_name or NONE),
)

#: A row of one virtual system's decryption rulebase as a CONCLUSION over all of its rules, with
#: the one piece of evidence that makes the three verdicts beside it legible.
#:
#: NEITHER ADDRESS COLUMN DECLARES A `field` AND NEITHER SHOULD: every value these two controls
#: assert on is a derived setting column, and declaring a field here would move the
#: value-at-fault mark off the verdict and onto the row's address. `data-filtering-posture`
#: records the same decision for the same reason.
#:
#: "Firewalls" PLURAL AND THE HA QUESTION IS ALREADY ANSWERED BY THE MODEL. Stage 5 declared this
#: subject's identity as (appliance, vsys_name) and said in prose that an HA pair yields TWO rows
#: for one real configuration. The shipped model does not do that: `DecryptionRulebaseVerdict`'s
#: unique constraint is on `enforcement_point` ALONE, and an enforcement point on an HA pair is
#: ONE point spanning both members - so the store already deduplicates on the PAIR, which is what
#: this stage's contract asks for, and there is no duplicate for this sheet to fold. The column
#: lists both members because both are what enforces the verdict.
DECRYPTION_RULEBASE_SUBJECT = VSYS_SCOPED + (
    ("Rules in force", 14, False, decryption_policy.rules_in_force),
)

#: One SSL decryption exclusion the organisation added itself. The standard named-object shape,
#: plus the vendor's `Exclude` switch - see `exclusion_excludes` for why that one is a subject
#: column and not a derived one.
SSL_DECRYPTION_EXCLUSION_SUBJECT = APPLIANCE + SCOPE + NAME + (
    ("Exclude", 10, False, decryption_policy.exclusion_excludes),
)


# --------------------------------------------------------------------------------------------
# THE THREE GLOBALPROTECT-PORTAL TABS, 2026-11-02, for PAN-GPP-001 to -006. Three models, three
# grains, and the whole domain is new to presentation: nothing in this repository drew a row for
# any of these three control types before today, and not one of their eight clause fields had a
# heading.
#
# ALL THREE ARE APPLIANCE-ANCHORED AND SO NONE USES `VSYS_SCOPED`. That constant reads
# `s.enforcement_point.vsys_name`, and these three models have no `enforcement_point` at all -
# they carry `appliance`, `scope` and `vsys_name` directly, which is what their shipped
# constraints key on. `APPLIANCE + SCOPE` is the shape that fits, and `scope_of` already prints
# the vsys name for a `scope=vsys` row, so the Scope column IS stage 5's `vsys_name` column.
#
# THAT IS ALSO THE HA ANSWER AND IT IS THE OPPOSITE OF THE DOMAIN BEFORE THIS ONE. A vsys-scoped
# model keyed on an enforcement point deduplicates itself across an HA pair, because the pair
# shares one point per vsys - which is why `decryption-policy` had nothing to fold. All three of
# these key on `appliance`, so an HA pair writes TWO rows for one configuration and the Appliance
# and HA role columns are what tell them apart. Measured by seeding a real pair and counting.
#
# `hidden_fields` IS EMPTY ON ALL THREE AND IS NOT DECLARED. The gate counts a field as presented
# if a subject column, a settings column OR the sheet's own `hidden_fields` carries it, so a
# non-empty tuple is a CLAIM accepted as proof and it is the only known cause in this repository
# of a findings row that marks nothing as the thing to fix. All eight fields get a real column.

#: One named portal entry of one virtual system. The standard named-object shape, plus the two
#: pieces of evidence the portal's own verdict columns cannot carry - see
#: `globalprotect_portal.portal_tls_profile` for the binding and `portal_client_auth_rows` for the
#: state no control on this tab can report.
PORTAL_SUBJECT = APPLIANCE + SCOPE + NAME + (
    ("SSL/TLS service profile", 22, False, globalprotect_portal.portal_tls_profile),
    ("Authentication rows", 12, False, globalprotect_portal.portal_client_auth_rows),
)

#: One row of one portal's client-authentication table. The portal comes BEFORE the row's own
#: name because it is the outer half of the identity and because the row name is meaningless on
#: its own, and the endpoint class comes after both because it is what a reader actually goes by.
#:
#: FOUR EVIDENCE COLUMNS, WHICH IS WIDE, and the reason is that this tab has exactly ONE derived
#: setting column: PAN-GPP-002 is the only control here and it clauses on one field. A verdict
#: over two leaves with neither leaf beside it is a row a reader cannot act on, so the evidence
#: has to be subject columns or it is nowhere.
CLIENT_AUTH_SUBJECT = APPLIANCE + SCOPE + (
    ("Portal", None, False, globalprotect_portal.portal_of_row),
) + NAME + (
    ("Endpoint class (OS)", 16, False, globalprotect_portal.row_operating_system),
    ("Authentication Profile", 22, False, globalprotect_portal.row_authentication_profile),
    ("Credentials OR certificate", 14, True, globalprotect_portal.row_either_factor_switch),
    ("Certificate profile bound", 12, True, globalprotect_portal.row_certificate_profile_bound),
)

#: One virtual system as a verdict over its GlobalProtect objects as a whole. NO `NAME`, because
#: the model has none: stage 5's identity is (appliance, scope, vsys_name) and the model's own
#: comment says why it does not inherit `ApplianceScopedObject` - "a vsys is not a named entry".
#:
#: SO THIS TAB RECONCILES THROUGH `_estate.reconcile`'s SECOND PASS rather than by entry name,
#: which is correct for a vsys-grain verdict and is worth knowing before reading a mismatch on
#: it: there is no device entry name for a stage 6 subject to match against.
ENFORCEMENT_POINT_SUBJECT = APPLIANCE + SCOPE + (
    ("Portals", 9, False, globalprotect_portal.point_portal_count),
    ("Clientless definitions", 26, True, globalprotect_portal.point_clientless_definitions),
    ("GlobalProtect licence", 26, True, globalprotect_portal.point_licence),
)

# THE THREE GLOBALPROTECT-GATEWAY TABS, 2026-11-02, for PAN-GPG-001 to -004, -006 and -007. Three
# models, three grains, and twenty clause fields none of which had a heading before today.
# PAN-GPG-005, the seventh control, adds no tab: it reports on
# `integrations.GlobalProtectEnforcementPoint` and reaches `GlobalProtect Coverage` above, which the
# domain before this one left deliberately un-narrowed so that it would.
#
# ALL THREE ARE APPLIANCE-ANCHORED, like the portal three and for the same measured reason: none of
# the models has an `enforcement_point` at all, they carry `appliance`, `scope` and `vsys_name`
# directly, and their shipped constraints key on `appliance`. So an HA pair draws TWO rows for one
# configuration and the Appliance and HA role columns are what tell them apart. Measured on a seeded
# pair, not inferred: see the stage 9 artifact's HA entry.
#
# `hidden_fields` IS EMPTY ON ALL THREE AND IS NOT DECLARED. The gate counts a field as presented if
# a subject column, a settings column OR the sheet's own `hidden_fields` carries it, so a non-empty
# tuple is a CLAIM accepted as proof, and it is the only known cause in this repository of a findings
# row that marks nothing as the thing to fix. Every clause field here gets a real column.
GATEWAY_SUBJECT = APPLIANCE + SCOPE + NAME + globalprotect_gateway.GATEWAY_EVIDENCE
GATEWAY_CLIENT_AUTH_SUBJECT = (
    APPLIANCE + SCOPE + globalprotect_gateway.GATEWAY_OF_ROW + NAME
    + globalprotect_gateway.CLIENT_AUTH_EVIDENCE)
GATEWAY_AGENT_CONFIG_SUBJECT = (
    APPLIANCE + SCOPE + globalprotect_gateway.GATEWAY_OF_ROW + NAME
    + globalprotect_gateway.AGENT_CONFIG_EVIDENCE)


# THE THREE PLATFORM-LIFECYCLE TABS, 2026-11-02, for PAN-PLT-002, PAN-PLT-004 and PAN-PLT-006.
# Three models, three device-wide singletons, and the whole domain is new to presentation: nothing
# in this repository drew a row for any of these three control types before today, `probe.surface_for`
# reported NO SHEET AT ALL for all three, and not one of their four clause fields had a heading.
#
# THE DOMAIN'S OTHER THREE CONTROLS ADD NO TAB and that is the correct state: PAN-PLT-001, -003 and
# -005 are discharged `engineer_answers` by stage 5, so they compile no query, have no catalog entry
# at all and can write no finding. Two of the three are CRITICAL severity and reach no customer
# through this report; stage 8's `needs_human` and `unexercised_assertions` are where that is on the
# record, and a tab here would have been a tab that can never hold a row.
#
# WHY THREE AND NOT ONE. An engineer fixes one of three different things, at three different vendor
# addresses: content that is behind is fixed on Device > Dynamic Updates, an entitlement that has
# lapsed on Device > Licenses, and an alarm nobody receives on Device > Log Settings. That is the
# same split the GlobalProtect and decryption blocks above make, and the rail items follow it.
#
# ALL THREE ARE APPLIANCE-ANCHORED and the appliance-scoped defaults are right: each model declares
# `unique(appliance)` in its own `Meta.constraints`, so a row IS one firewall and `s.appliance`
# resolves. SO AN HA PAIR DRAWS TWO ROWS FOR ONE REAL CONFIGURATION and nothing deduplicates them -
# stage 5 says so for all three subjects, and the Appliance and HA role columns are the only thing
# telling the two rows apart. Measured on the seeded estate rather than inferred; see the stage 9
# artifact's HA entry for which arm of `flows.get_in_scope_appliances` that measurement sits in.
#
# `hidden_fields` IS EMPTY ON ALL THREE AND IS DECLARED EMPTY. The gate counts a field as presented
# if a subject column, a settings column OR the sheet's own `hidden_fields` carries it, so a
# non-empty tuple is a CLAIM accepted as proof and it is the only known cause in this repository of
# a findings row that marks nothing as the thing to fix (P409). All four clause fields here get a
# real derived column.
#
# `tested_columns=ALL_TESTED_COLUMNS` ON ALL THREE IS A CHOICE AND IT IS NOT FREE HERE. The default
# `("Provenance",)` silently drops `Fires when` from the WORKBOOK while the live page keeps it, so
# the two surfaces would disagree about which cell a reader meets (P427). It is taken knowing that
# `fires_when` renders the BASELINE's condition alone: on the two Licenses rows whose finding comes
# from the support calibration alone - the two PA-VMs, whose subscription entitlements all read
# `Never` and are not expired - the stated condition is `entitlement_state ≠ active_beyond_90_days`
# beside a cell reading "All active, beyond 90 days", which that row does not meet. Measured on the
# built rows, recorded in the artifact, and the alternative is a contradicting value with no stated
# condition beside it at all.
#
# `source_columns=()` ON ALL THREE. The default names the TEMPLATE per tested field, and all four
# clause fields here are in their model's `DERIVED_FIELDS` - computations over an operational reply
# or over a configuration node, never a pushed value - so the column would be empty on every row of
# every tab. `ace` and the four SaaS tabs above drop it for the same reason.
#
# EVERY HEADING IS A PROPOSAL (P399) and every one of them is sourced in
# `platform_lifecycle_presentation`, beside the vendor sentence it came from or the note saying the
# vendor has no word for it.
CONTENT_STREAMS_SUBJECT = APPLIANCE + platform_lifecycle.CONTENT_STREAMS_EVIDENCE
LICENCE_INVENTORY_SUBJECT = APPLIANCE + platform_lifecycle.LICENCE_INVENTORY_EVIDENCE
LOG_ALARM_SUBJECT = APPLIANCE + platform_lifecycle.LOG_ALARM_EVIDENCE


def spec(control_type, description, *, title="", subject=APPLIANCE, **options):
    return findings_sheet.DeviceSettingSheet(
        control_types=(control_type,), title=title, description=description,
        subject_columns=subject, **options)


#: The domain each tab covers, and which columns name its subject. Nothing here says what a
#: missing provenance row means or which columns are computed: Integrations records the first and
#: declares the second on the model, as of 2026-09-21.
SPECS = (
    # Its own tab, deliberately separate from the object findings. Jason, 2026-10-02: "I don't
    # want them to disturb the highly structured, object related findings." It sits with the
    # Objects tabs because its subject is an address object and the workbook orders tabs by
    # category.
    spec(T.COVERAGE,
         "What this assessment could not establish, and why. These are gaps in the measurement "
         "rather than faults on the device: an external dynamic list whose content was never "
         "collected, or one collected only in part. A rule referencing an object of unknown "
         "size cannot be scored for breadth, and an unscored rule must not read as a narrow "
         "one - which is what these exist to prevent.",
         title="Coverage", subject=COVERAGE_SUBJECT,
         setting_labels=COVERAGE_SETTING_LABELS,
         # An address object hangs off an enforcement point or an appliance group, never a
         # single appliance - the same reason COVERAGE_SUBJECT reads "Where" instead of an
         # Appliance column. Both defaults here are appliance-scoped and neither applies, which
         # is what broke this tab and the coverage findings page: `appliance_of` reads
         # `s.appliance` and the select_related walks `appliance__appliance_group`.
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance_group",
                                 "enforcement_point__appliance", "appliance_group"),
         value_readers={"referenced_by_policy": REFERENCED_BY_POLICY},
         # The reverse accessors on AddressObject, which are NOT the names a rule uses for the
         # same tables - a rule has `source_address_refs`, an address object has
         # `securityrulesourceaddressref_set`. Prefetching so the Referenced column does not
         # cost a query per row.
         subject_prefetch=("securityrulesourceaddressref_set",
                           "securityruledestinationaddressref_set")),
    # Beside Coverage and for the same reason, but a SEPARATE tab because the subject differs:
    # Coverage names an address object that normalized, this names our record of one that did
    # not. Jason, 2026-10-28: "a separate location/tab for COV like controls. If we can separate
    # it by subject, that's better." It sits under Objects rather than in a category of its own
    # because `CATEGORIES` is PAN-OS's own four and `check_tabs_follow_the_summary` indexes into
    # it - a fifth category would be product structure invented here. Adjacent to Coverage is
    # what that answer gets without inventing one.
    spec(T.NORMALIZATION,
         "Objects this assessment could not build, and what fell with them. Like Coverage "
         "these are gaps in the measurement rather than faults on the device - but a step "
         "further back: the object did not normalize at all, so no control in this report has "
         "looked at it. A row with Cause 'Root' is the fault to fix; the Consequence rows are "
         "what it took down. An object nobody could build must not read as an object with "
         "nothing wrong, which is what these exist to prevent.",
         title="Normalization Coverage", subject=NORMALIZATION_SUBJECT,
         category="Objects",
         appliance_of=lambda obj: obj.appliance,
         subject_select_related=("enforcement_point__appliance_group",
                                 "enforcement_point__appliance", "appliance_group",
                                 "appliance")),
    spec(T.LOGIN_BANNER,
         "The banner shown before an administrator logs in, and whether they must acknowledge it."),
    spec(T.MASTER_KEY,
         "The key that encrypts the firewall's own stored secrets, and whether it is still the "
         "factory default."),
    spec(T.UPDATE_SERVER,
         "How the firewall talks to Palo Alto's update servers, and whether it verifies their "
         "identity."),
    # NINE CONTROLS ON ONE TAB, 2026-11-03: PAN-MGT-011, which has been here since
    # `management-services` minted the type, and the EIGHT `logging` controls PAN-LOG-001, -003,
    # -004, -006, -007, -008, -009 and -010. This spec was a bare two-liner until stage 9 of
    # `logging` - no title, no `setting_labels`, one derived settings column - so
    # `log_on_high_dp_load` was a raw Django field name heading a shipped tab, and eight controls
    # arriving would have added TEN more raw headings beside it.
    #
    # THE DESCRIPTION CHANGED AND IT IS A PROPOSAL (P399). The sentence it replaced described
    # PAN-MGT-011's one setting, which is now one column of eleven; a tab's description is the
    # SHEET's, and the sheet is what a customer reads.
    #
    # `log_on_high_dp_load` IS LABELLED HERE ALTHOUGH THE COLUMN IS NOT THIS DOMAIN'S, with the
    # vendor's own label from Help 11.2 p.720. The `management-services` run inherits it and may
    # replace it: labelling a column changes nothing about its control, and an eleven-column tab
    # with one bare heading is worse than one with eleven labelled.
    #
    # COLUMN ORDER, read off `FindingsTable.headers` on built rows rather than derived. Because
    # `setting_columns` walks `order_by("control_id")` and `PAN-LOG-001` sorts before
    # `PAN-MGT-011`, PAN-MGT-011's column - which was FIRST on this tab - is now eleventh.
    # Nothing gates that and nothing here can change it: `auto_setting_columns` is all or nothing.
    #
    # `tested_columns` IS THE FULL SET rather than the default `("Provenance",)` (P427), so the
    # workbook keeps `Fires when` and the two surfaces agree about which cells a reader meets.
    spec(T.LOGGING_SETTINGS,
         logging.LOGGING_SETTINGS_DESCRIPTION,
         subject=APPLIANCE + logging.LOGGING_POSTURE_EVIDENCE,
         setting_labels=logging.LOGGING_SETTING_LABELS,
         provenance_cell=logging.provenance_cell,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    # `logging`, 2026-11-03, for PAN-LOG-002 - the only control of this type. One row per server
    # entry inside one server profile, which is the grain transport is set at.
    #
    # ITS `provenance_cell` REPRODUCES THE DEFAULT'S ANSWER AND DE-DUPLICATES IT, and
    # `logging_presentation` carries the measurement that decided that: this model's clause fields
    # are MIXED, which the two-grep rule says to branch on `provenance_of`, and branching that way
    # is WRONG here because `kind` is a stored clause field carrying no provenance row of its own -
    # it would print "Not recorded" about it, and would lose the "Template" the one
    # template-contributed row carries. The default is right and reads "Local | Local | Local",
    # one line per clause field; this prints each distinct answer once.
    #
    # NO `value_readers`, AND `transport` IS THE ONE THAT WAS REFUSED - see
    # `LOG_SERVER_TARGET_READERS` for the measurement. A reader on a stored key costs that key's
    # own provenance row, and whether the transport key was ABSENT is what this control reports.
    spec(T.LOG_SERVER_TARGET,
         logging.LOG_SERVER_TARGET_DESCRIPTION,
         title=logging.LOG_SERVER_TARGET_TITLE,
         subject=logging.LOG_SERVER_TARGET_SUBJECT,
         setting_labels=logging.LOG_SERVER_TARGET_SETTING_LABELS,
         value_readers=logging.LOG_SERVER_TARGET_READERS,
         provenance_cell=logging.provenance_cell_through_the_object,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    # `logging`, 2026-11-03, for PAN-LOG-005 - the only control of this type. One row per virtual
    # system, because the gap it reports is a vsys with no adequate profile, and a profile-keyed
    # row cannot report something that does not exist.
    #
    # BOTH CLAUSE FIELDS ARE DECLARED DERIVED and the model carries no `choices` at all, so a
    # labelling reader would be FATAL here - `get_<field>_display()` raises `AttributeError` at
    # template render on a field with no choices - and the sheet-level provenance cell is the only
    # remedy left. Measured on built rows: the DEFAULT cell reads "Not recorded" on every row,
    # because `remediation_accessor` discards DERIVED and walks to an `__entry__` row this model
    # never carries. `logging.provenance_cell` is measured to return exactly "Derived" here, which
    # is the honest constant the rule asks for, written as the branch so that a stored clause
    # field added later cannot make it lie.
    spec(T.VSYS_LOG_FORWARDING,
         logging.VSYS_LOG_FORWARDING_DESCRIPTION,
         title=logging.VSYS_LOG_FORWARDING_TITLE,
         subject=logging.VSYS_LOG_FORWARDING_SUBJECT,
         setting_labels=logging.VSYS_LOG_FORWARDING_SETTING_LABELS,
         provenance_cell=logging.provenance_cell,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.WILDFIRE_SETTINGS,
         "What the firewall forwards to WildFire: the per-type file size limits, and whether "
         "session context and benign/grayware verdicts are shared. DEVICE-WIDE, as against "
         "the WildFire analysis profile, which decides what is asked for and is reported on "
         "the security rule."),
    # THE FIVE `device-services` TABS, stage 9, 2026-11-03. The three below already existed as
    # bare stubs - a description and a title and nothing else - so all 16 of their settings
    # columns were raw Django field names in front of a customer. Every heading and both new tab
    # titles are PROPOSALS (P399) sourced to the vendor's own Help where the vendor has a word;
    # `device_services_presentation` carries the source per heading and says so where it does not.
    #
    # ALL FIVE DECLARE `provenance_cell`, AND THAT IS MEASURED RATHER THAN COPIED. Not one of the
    # 23 clause fields across the five models carries a `FieldProvenance` row except
    # `community_is_default` and `addressing_mode`, and no model carries an `__entry__` row - so
    # the DEFAULT cell reads "Not recorded" on every row of all five tabs. Three of the five
    # models are MIXED, not two: a constant cell would also lie about `community_is_default` on
    # every PAN-SVC-005 row and about `addressing_mode` on every PAN-SVC-007 row. The module's
    # docstring has the per-tab, per-control measurement.
    #
    # `tested_columns=ALL_TESTED_COLUMNS` on all five, so the workbook keeps `Fires when` rather
    # than silently dropping it while the live page shows it (P427). The condition it prints reads
    # in Django field names on all five tabs - `render_node` consults `setting_labels` nowhere -
    # which is recorded as a defect in the stage 9 artifact rather than worked around here.
    #
    # `hidden_fields` is left empty on all five, so `check_every_tested_field_is_presented` passes
    # on REAL columns rather than on a claim (P409).
    spec(T.NTP_SETTINGS,
         device_services.NTP_DESCRIPTION,
         title="NTP",
         setting_labels=device_services.NTP_SETTING_LABELS,
         value_readers=device_services.NTP_READERS,
         provenance_cell=device_services.provenance_cell,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.SNMP_SETTINGS,
         "Whether each firewall exposes SNMP, which version, and whether its community string is "
         "a default one.",
         title="SNMP",
         setting_labels=device_services.SNMP_SETTING_LABELS,
         value_readers=device_services.SNMP_READERS,
         provenance_cell=device_services.provenance_cell,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.SYSTEM_IDENTITY,
         "How each firewall is named, what time zone its logs are written in, and whether its "
         "management address is static.",
         title="System Identity",
         setting_labels=device_services.SYSTEM_IDENTITY_SETTING_LABELS,
         value_readers=device_services.SYSTEM_IDENTITY_READERS,
         provenance_cell=device_services.provenance_cell,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    # NEW 2026-11-03, for PAN-SVC-003. `integrations.DnsSettings` was created by stage 7 for this
    # domain and had never been queried from this repository at all, so it had no rail item, no
    # results page and no tab. Category DERIVED from the rail (`category=''`), which is right for
    # a subject that IS a configuration object: the rail item is `dns-settings` at Device > Setup >
    # Services, so the workbook cannot disagree with the app about where the object lives.
    spec(T.DNS_SETTINGS,
         device_services.DNS_SETTINGS_DESCRIPTION,
         title=device_services.DNS_SETTINGS_TITLE,
         setting_labels=device_services.DNS_SETTINGS_SETTING_LABELS,
         value_readers=device_services.DNS_SETTINGS_READERS,
         provenance_cell=device_services.provenance_cell,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    # NEW 2026-11-03, for PAN-SVC-006, and the same history: created by stage 7, never queried,
    # no surface of any kind. ITS OWN SUBJECT COLUMNS, because the row is not identified by an
    # appliance alone - a firewall-wide set and a virtual system's own set are two rows on one
    # appliance. `Scope` names `field="scope"` so the identity column IS the presentation of that
    # field and no duplicate settings column is derived for it, which also buys
    # `get_scope_display()` without paying a `value_reader`'s price.
    #
    # ITS OWN `provenance_cell`, and the difference is one skipped field. `scope` is the FOURTH
    # provenance case - stored, not derived, not reader-only, and carrying no `FieldProvenance`
    # row at all - and `ServiceRoute` carries no `__entry__` row either, so the remedy the fourth
    # case normally has does not exist here. See `SERVICE_ROUTE_SCOPE_NOTE`.
    spec(T.SERVICE_ROUTE,
         device_services.SERVICE_ROUTE_DESCRIPTION,
         title=device_services.SERVICE_ROUTE_TITLE,
         subject=device_services.SERVICE_ROUTE_SUBJECT,
         setting_labels=device_services.SERVICE_ROUTE_SETTING_LABELS,
         value_readers=device_services.SERVICE_ROUTE_READERS,
         provenance_cell=device_services.service_route_provenance_cell,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.MANAGEMENT_INTERFACE,
         "Every surface an administrator can reach the firewall on - the management port, the aux "
         "ports and any data-plane interface offering administrative services - and what each "
         "offers.",
         subject=APPLIANCE + (
             ("Surface", 22, False,
              lambda s, _p: f"{s.get_plane_display()} {s.interface_name}".strip(), "plane"),
             ("Services enabled", 22, True, lambda s, _p: SERVICES_ENABLED.read(s),
              "service_enabled"),
             # Headed by what the cell HOLDS. The control tests `exposure`, a verdict over this
             # list; the list is what an engineer edits.
             ("Permitted sources", 24, True, lambda s, _p: PERMITTED_SOURCES.read(s), "exposure"),
         ),
         value_readers={"service_enabled": SERVICES_ENABLED, "exposure": PERMITTED_SOURCES,
                        # PAN-UID-005, 2026-11-02. See `setting_labels` below for why this field
                        # needs a reader and not a heading alone. FREE: the field is in
                        # `ManagementInterface.DERIVED_FIELDS`, so there is no `FieldProvenance`
                        # row for `stored=False` to discard, and the reader's `DERIVED` provenance
                        # keeps the remediation walk - which on the aux-2 surface is the only cell
                        # in the report that can say the node is Panorama's.
                        "userid_listener_state_established": user_id.LISTENER_STATE_READER},
         # ADDED 2026-11-02 by stage 9 of `user-id`, and THIS TAB IS NOT THAT DOMAIN'S.
         #
         # FIVE CONTROLS REPORT HERE AND FOUR OF THEM ARE PAN-MGT'S - PAN-MGT-001, -002, -003 and
         # -006, whose domain `management-services` has NOT been through stage 9. The fifth is
         # PAN-UID-005. So a heading written here is a decision that domain inherits, and this
         # dict was not written for it: it holds exactly ONE entry, for the one field PAN-UID-005
         # brings that no column already showed.
         #
         # WHY THERE ARE TWO ENTRIES AND NOT THREE, measured on a built table rather than
         # reasoned from the dict. `service_enabled` and `exposure` are SUBJECT columns above
         # with their `field` declared, so `setting_columns` dedupes them and no label could
         # reach them - they head "Services enabled" and "Permitted sources" and were never raw.
         # `plane` is a subject column too ("Surface"). What IS raw on this tab today is
         # `is_management_surface`, which belongs to PAN-MGT-003 and not to this domain: it is
         # the only derived settings column the tab had before PAN-UID-005 arrived, and it has
         # been heading a customer-facing column with a Django field name since that control
         # shipped. A label for it is proposed below rather than left for a reader to decode,
         # and `management-services` owns the decision.
         setting_labels={
             # PAN-MGT-003's FIELD AND NOT THIS DOMAIN'S - proposed here only because it was
             # found raw while measuring this tab, and a raw field name on a customer tab is the
             # one thing `setting_labels` exists to prevent. `management-services` has not been
             # through stage 9; when it is, this heading is that run's to confirm or replace.
             #
             # Headed as what the column DECIDES. It is computed, not stored: the three
             # deviceconfig planes are administrative surfaces unconditionally, and a data-plane
             # surface is one only where the bound profile enables an administrative service. The
             # vendor has no label for it because the vendor does not compute it.
             "is_management_surface": "Offers administrative access",
             # A PROPOSAL (P399), and the heading is OURS: no vendor label exists, because the
             # value is not a device setting at all - it is this assessment's record of whether
             # the listener's state on this surface was MEASURED or inferred.
             #
             # HEADED AS A QUESTION ABOUT THE READING AND NOT ABOUT THE DEVICE. False is the
             # firing side and means "nobody has measured what an absent key means on this
             # plane", so a heading like "Listener state established" would put "No" in the
             # firing cell and read as a fact about the listener. The cell's own reader carries
             # the rest - see `user_id_presentation.LISTENER_NOT_MEASURED`.
             "userid_listener_state_established": "Listener state measured on this surface",
         },
         subject_prefetch=("services", "permitted_sources")),
    # Network > Network Profiles > IKE Crypto and > IKE Gateways, 2026-10-28. TWO TABS AND NOT
    # ONE, for the reason they are two models and two rail items: a gateway names a profile, and
    # an engineer fixes one or the other. Both subjects are DEVICE-WIDE - stage 4 of the
    # `ike-crypto` domain found exactly one firewall-local scope for each, neither shared nor
    # under a vsys - so neither carries a Scope column: `scope` reads `device-local` on every row
    # in this lab and `vsys_name` is structurally empty, and a column that says the same word
    # everywhere teaches a reader nothing.
    #
    # ON AN HA PAIR each of these yields two rows for one real configuration and nothing
    # deduplicates them. Appliance and HA role are the first two columns precisely so a reader
    # can reconcile the count against the device list; the deduplication itself is not something
    # presentation can do, since the findings exist per appliance row.
    spec(T.IKE_CRYPTO_PROFILE,
         "The IKE proposal sets a gateway can offer in phase 1 of an IPSec VPN: which "
         "key-agreement groups, ciphers and integrity algorithms each profile still offers, how "
         "long a key lives, and whether any gateway on the same firewall names it. A profile "
         "offers every member of each list and takes the first a peer accepts, so what is "
         "assessed is the WEAKEST member on offer - the one an exchange can be driven down to.",
         title="IKE Crypto", subject=IKE_CRYPTO_PROFILE_SUBJECT,
         setting_labels=IKE_CRYPTO_PROFILE_SETTING_LABELS),
    spec(T.IKE_GATEWAY,
         "The peer gateways this firewall negotiates IKE with: which protocol version, how the "
         "peer is authenticated, the IKEv1 exchange mode, whether a dead peer is detected, and "
         "which crypto profile each branch names. THE CONFIGURED VERSION IS NOT THE NEGOTIATED "
         "ONE - `IKEv2 preferred` resolves to IKEv2 with an IKEv1 fallback the peer can elect - "
         "and no column here can say which a running tunnel uses.",
         title="IKE Gateways", subject=IKE_GATEWAY_SUBJECT,
         # `gateway_is_active` IS NOW NAMED ON THE "Gateway state" COLUMN rather than hidden.
         # It was hidden because it is the APPLICABILITY clause every control in this domain
         # carries - the value that brings the row into scope rather than the value at fault -
         # and as a derived column it read "Active" with the amber value-at-fault fill on every
         # row, which is the shape Jason caught twice: the most reassuring cell on the row was
         # the finding. `ControlQuery.asserted_fields` fixed the fill itself on 2026-10-28, so
         # the column no longer needs hiding to stay honest. Naming the field is better than
         # either: no second column derives, and the cell becomes markable if a control ever
         # does assert on it.
         setting_labels=IKE_GATEWAY_SETTING_LABELS),
    # Network > Network Profiles > IPSec Crypto and Network > IPSec Tunnels, 2026-11-02.
    # TWO TABS AND NOT ONE, for the reason they are two models and two rail items at two
    # different vendor addresses: a tunnel names a profile, and an engineer fixes one or the
    # other. It is also the SAFE arrangement for the em-dash escape, which is per MODEL and not
    # per control: `setting_columns` keeps a derived column off a row with `isinstance(subject,
    # model)`, so two control types over ONE model on one tab would each render the other's
    # firing values as real cells. These two types are over two different models.
    #
    # Both subjects are DEVICE-WIDE - stage 4 measured exactly one firewall-local scope for
    # each, neither shared nor under a vsys, one collection for the whole appliance even on the
    # multi-vsys PA-5220 - so neither carries a Scope column: `scope` and `vsys_name` are not
    # columns on either model at all.
    #
    # ON AN HA PAIR each of these yields two rows for one real configuration and nothing
    # deduplicates them. Appliance and HA role are the first two columns precisely so a reader
    # can reconcile the count against the device list; the deduplication itself is not something
    # presentation can do, since the findings exist per appliance row and `row_meta` carries no
    # pair key for a surface to fold on.
    #
    # NEITHER TAB HIDES A FIELD. `hidden_fields` is empty on both, which is the only known cause
    # of an unmarkable value-at-fault cell in this repository: of 33 findings tabs, the 28 that
    # declare it empty can all mark the cell at fault and every unmarkable field on the other
    # five is in that tab's own `hidden_fields`.
    spec(T.IPSEC_CRYPTO_PROFILE,
         "The phase-2 proposal an IPSec tunnel negotiates its payload protection with: which "
         "protocol branch protects the payload, which ciphers and integrity algorithms each "
         "profile still offers under it, the key-agreement group it re-keys with, how long a key "
         "lives, and whether any tunnel on the same firewall names it. A profile offers every "
         "member of each list and takes the first a peer accepts, so what is assessed is the "
         "WEAKEST member on offer - the one an exchange can be driven down to. THE TWO BRANCHES "
         "ARE EXCLUSIVE ON A DEVICE and a profile carrying NEITHER is a committed state, not a "
         "collection gap: the key lifetime is the object's only mandatory key, so a profile with "
         "no cipher and no integrity algorithm at all commits cleanly.",
         title="IPSec Crypto", subject=IPSEC_CRYPTO_PROFILE_SUBJECT,
         setting_labels=IPSEC_CRYPTO_PROFILE_SETTING_LABELS,
         value_readers=IPSEC_CRYPTO_PROFILE_READERS,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.IPSEC_TUNNEL,
         "The IPSec tunnels this firewall terminates: whether each is switched on, whether it "
         "protects against replayed packets, whether it watches the far end, and which crypto "
         "profile it runs on. A TUNNEL WITH NO ROW IS NOT A TUNNEL WITH NOTHING WRONG - an "
         "appliance that terminates none produces no rows here, and every control on this tab "
         "is written over the tunnels the firewall holds, so on such an appliance they are "
         "vacuously satisfied rather than assessed. Whether a tunnel is actually negotiating is "
         "not assessed either: that is live device state and no configuration read carries it.",
         title="IPSec Tunnels", subject=IPSEC_TUNNEL_SUBJECT,
         setting_labels=IPSEC_TUNNEL_SETTING_LABELS,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    # The three Device-ID tabs, 2026-11-02. Their column constants and the reasoning behind each
    # heading are above; what is decided HERE is the domain sentence, the title and the three
    # options each tab needs.
    #
    # `tested_columns` IS `ALL_TESTED_COLUMNS` ON ALL THREE AND THAT IS A CHOICE. The default is
    # `('Provenance',)`, which keeps `Fires when` on the live page and DROPS it from the xlsx - so
    # a row's defects split across the two media and the workbook shows a contradicting value
    # under the control's name with no stated condition beside it at all. Made knowing the price:
    # `fires_when` renders the BASELINE query alone, with no per-query hook, so on a row that
    # fired through a calibration query instead the condition printed is one the subject does not
    # meet. FOUR ROWS OF THIS DOMAIN ARE IN THAT STATE - the three narrowed zones, which fire on
    # "Identification narrowed to a device address list" while the baseline asks whether
    # identification is OFF, and the appliance reporting no release date, which fires on "Release
    # date never reported" while the baseline asks for an age over seven days. All four are
    # recorded in this run's artifact against `argued_against_itself`. The alternative is the
    # contradicting value with no stated condition at all, which an earlier run measured as worse.
    spec(T.DEVICE_IDENTIFICATION,
         "Whether each firewall can identify the unmanaged equipment on its networks at all: "
         "whether the IoT Security subscription is in force, whether the firewall is wired to "
         "the service that feeds it, and how current the classification data it holds is. THE "
         "SUBSCRIPTION IS THE PREMISE AND THE OTHER TWO REST ON IT - a zone with device "
         "identification switched on identifies nothing without the service behind it, so a "
         "finding here makes every Device-ID finding elsewhere in this report a smaller "
         "question. THREE UNRELATED INSTRUMENTS LAND ON ONE ROW: a licence listing, an "
         "operational reading of the installed content, and one configuration node. Each is "
         "reported with the companion column that says whether it was answered at all, because "
         "an appliance holding no subscription and an appliance nobody asked produce the same "
         "empty reply - and a firewall nobody could read must not report as a firewall that is "
         "fine. WHAT IS NOT ASSESSED is whether anything answers at the far end: a configured "
         "address proves the wiring exists and no configuration read proves delivery.",
         title="IoT Security", subject=DEVICE_IDENTIFICATION_SUBJECT,
         setting_labels=DEVICE_IDENTIFICATION_SETTING_LABELS,
         value_readers=DEVICE_IDENTIFICATION_READERS,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.ZONE,
         "The security zones on each virtual system, and whether each identifies the devices "
         "connected to it. THE FIRING STATE OF THE SECOND HALF IS THE OPPOSITE OF WHAT A "
         "REVIEWER LOOKS FOR, which is the one thing to read before acting on a row here: an "
         "absent or empty Device-ID address list means identification applies to EVERY address "
         "in the zone, which is the most permissive reading and the COMPLIANT one. What is "
         "reported is a POPULATED list, because that narrows identification away from equipment "
         "the zone was enabled for. The members are printed for a reviewer to check against "
         "what is actually plugged in, and the report makes no claim that they cover it: a "
         "member may be a literal, a CIDR block, an address object or an address GROUP, and "
         "nothing on the firewall says what a group currently contains. A ZONE WITH NO ROW IS "
         "NOT A ZONE WITH NOTHING WRONG - a zone whose read never arrived is absent here rather "
         "than unknown, and no column of this tab can say so.",
         title="Security Zones", subject=ZONE_SUBJECT,
         setting_labels=ZONE_SETTING_LABELS,
         value_readers=ZONE_READERS,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         # ONE ANSWER FOR THE WHOLE ROW, on `vsys_rule_posture`'s precedent, and here it is
         # forced as well as right: `Zone` tracks no per-field provenance at all, so there is no
         # per-field answer to give. See `device_id.zone_provenance`.
         provenance_cell=device_id.zone_provenance,
         # NO TEMPLATE COLUMN. It would be blank on every row whatever happened - nothing writes
         # a `FieldProvenance` row for a zone - and the default reader would raise on the way to
         # printing the blank. The Provenance cell beside it says why in words instead of
         # leaving a reader to read an empty cell as "configured locally".
         source_columns=(),
         # A zone hangs off an enforcement point, never a single appliance, so there is no one
         # appliance for a row to link to: linking to one half of an HA pair would assert
         # something false.
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance",
                                 "enforcement_point__appliance_group"),
         subject_prefetch=("enforcement_point__appliance_group__appliances",)),
    spec(T.RULEBASE_DEVICE_MATCH,
         "Whether each virtual system's security policy matches on what a connecting device IS, "
         "anywhere in its rule set. THE ROW IS A CONCLUSION ABOUT ALL THE RULES AND NOT ABOUT "
         "ANY ONE OF THEM, because the commonest state of this subject is a rule set with no "
         "device dimension anywhere in it - and the absence of a dimension is not a defect in "
         "any particular rule. THE RULE SET OF A VIRTUAL SYSTEM IS THREE READS AND NOT ONE: the "
         "firewall-local rulebase, the Panorama pre- and post-rulebases pushed to it, and the "
         "two predefined default rules; a verdict over any two of them would be a verdict about "
         "the wrong rule set. A POPULATED FIELD IS NOT A MATCH - the member list that carries a "
         "device object also carries GlobalProtect host-posture profiles and three bare "
         "keywords, and `any`, which is what every populated list in this estate holds, "
         "constrains nothing. So what is counted is members that RESOLVE against the device "
         "objects this virtual system can see, and the count of those objects is on the row "
         "because zero of them means no rule COULD name a device: a different piece of work "
         "from a policy that has the objects and does not use them.",
         title="Device-ID Policy Match", subject=RULEBASE_DEVICE_MATCH_SUBJECT,
         setting_labels=RULEBASE_DEVICE_MATCH_SETTING_LABELS,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         # Every column of this model is in its `DERIVED_FIELDS` - it is a verdict and holds no
         # key the firewall wrote - so the per-field remediation walk resolves to "Not recorded"
         # on all of them and one answer for the row is the honest shape. `vsys_rule_posture`,
         # the other verdict tab, made the same call for the same reason.
         provenance_cell=lambda v, _p, _f: "Derived",
         # A Template column would be blank on every row: there is no pushed key here to name a
         # template for, because there is no key at all.
         source_columns=(),
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance",
                                 "enforcement_point__appliance_group"),
         subject_prefetch=("enforcement_point__appliance_group__appliances",)),
    spec(T.USER_ID_COLLECTOR,
         "Each virtual system's integrated User-ID agent: whether it probes endpoints for the "
         "user logged in to them, which directory account it reads its monitored servers as, "
         "whether it reads user SESSIONS from those servers, and how long a learned "
         "address-to-user mapping is allowed to live. THREE CONTROLS REPORT ON ONE NODE here, so "
         "a row may carry several findings about one agent. A ROW EXISTS FOR EVERY VIRTUAL SYSTEM "
         "WHETHER THE NODE DOES OR NOT, and that is the point rather than an artefact: the "
         "vendor's implicit values apply to an unconfigured agent exactly as they do to a "
         "configured one, so a vsys nobody has set up is assessed on what the device actually "
         "does. WHAT THAT COSTS IS WORTH READING ONCE: a compliant row here may be reporting a "
         "measured default rather than a decision somebody made, and the Provenance column is "
         "what tells the two apart. A VIRTUAL SYSTEM WHOSE CONFIGURATION WAS NEVER COLLECTED is "
         "a third state again - it has no row at all and is reported by nothing on this tab. "
         "WHAT IS NOT ASSESSED is what the service account may actually do: the firewall stores "
         "the principal's name and nothing about its rights, and no configuration read on a "
         "firewall can establish them.",
         title="User-ID Collector", subject=USER_ID_COLLECTOR_SUBJECT,
         setting_labels=USER_ID_COLLECTOR_SETTING_LABELS,
         # The FULL set, on `ipsec-crypto`'s reasoning and knowing what it costs. TWO ROWS ON
         # THIS TAB RENDER A `Fires when` THAT THEIR OWN CELLS CONTRADICT, because `fires_when`
         # renders the BASELINE alone while the row may have fired from a calibration on a
         # different field: a PAN-UID-004 row firing on session reading states the service-account
         # condition, and a PAN-UID-006 row firing on the lifetime states the expiry-off
         # condition. Both are recorded in this run's artifact. The set is still the full one
         # because the alternative is the contradicting column with no stated condition beside it
         # at all - and between them `Matched queries`, `Severity basis` and the marked cell
         # resolve which clause actually fired.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         # KEPT, unlike the two verdict tabs above: five of this model's six assertable columns
         # are real payload keys, so a Template column has something to name and the per-field
         # Provenance walk has a row to find.
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance",
                                 "enforcement_point__appliance_group"),
         subject_prefetch=("enforcement_point__appliance_group__appliances",)),
    spec(T.USER_ID_DISCOVERY_BOUND,
         "Where each virtual system's User-ID agent is allowed to look for users: the "
         "include/exclude list that bounds discovery, read as one verdict over the whole list. "
         "THE ROW IS A CONCLUSION ABOUT THE LIST AND NOT ABOUT ANY ENTRY IN IT, because the "
         "state this control exists to report is a list that holds NOTHING - absent, or "
         "committed and empty, or holding only entries somebody disabled. In every one of those "
         "the vendor's collector discovers in all subnetworks, and a per-entry row could not "
         "report it at all: there is no entry to draw. AN EMPTY LIST AND NO LIST ARE ONE STATE "
         "HERE, deliberately - they read differently on the wire and they bound exactly the same "
         "nothing. THE EXCLUDE-ONLY SHAPE IS A FUNCTIONAL FAULT RATHER THAN AN EXPOSURE and "
         "grades below the unbounded state for that reason: the vendor's implicit exclude-all "
         "rule then stops user mapping entirely, so the firewall is not over-reaching, it is not "
         "working. THE RANGES ARE PRINTED AND NOT JUDGED: whether an included range holds the "
         "organisation's own staff is a question for the engineer, and nothing on the firewall "
         "answers it.",
         title="User-ID Discovery", subject=USER_ID_DISCOVERY_SUBJECT,
         setting_labels=USER_ID_DISCOVERY_SETTING_LABELS,
         value_readers=USER_ID_DISCOVERY_READERS,
         # The full set, and here it costs nothing: every active query of PAN-UID-002 clauses on
         # `list_shape` and on nothing else, so the baseline's rendered condition is true of every
         # row that fires - which is the opposite of the collector tab above and worth the
         # contrast being visible in one domain.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         # EVERY column of this model is in its `DERIVED_FIELDS` - it is a verdict over a
         # collection and holds no key the firewall wrote - so one answer for the row is the
         # honest shape and a Template column would be blank on every row. `vsys_rule_posture`
         # and `Device-ID Policy Match`, the other two verdict tabs, made the same call.
         provenance_cell=lambda b, _p, _f: "Derived",
         source_columns=(),
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance",
                                 "enforcement_point__appliance_group"),
         subject_prefetch=("enforcement_point__appliance_group__appliances",)),
    # --- globalprotect-portal, 2026-11-02 ----------------------------------------------------
    # Three tabs over three models. See the subject-column block above for why none of them uses
    # `VSYS_SCOPED` and what that means on an HA pair. Every heading is a PROPOSAL, sourced in
    # `globalprotect_portal_presentation`.
    spec(T.GLOBALPROTECT_PORTAL,
         "Each GlobalProtect portal a virtual system publishes, and what it hands the endpoints "
         "that reach it. A portal is the one service in this report that is MEANT to be reachable "
         "from the internet by an unauthenticated browser, so every control here is about what "
         "that exposure hands out: whether the portal presents a transport profile at all, "
         "whether it serves a browser-reachable login page, whether it drives the agent to a "
         "current version, and whether it lets the agent keep a credential on the endpoint. THE "
         "ROW IS ONE PORTAL ON ONE APPLIANCE, so an HA pair draws two rows for one configuration "
         "and the Appliance and HA role columns are what tell them apart - these models key on "
         "the appliance, not on the virtual system, so nothing below presentation folds them. "
         "WHAT THIS TAB CANNOT SAY is whether the certificate the portal presents chains to an "
         "authority the connecting endpoint already trusts: that is the other half of PAN-GPP-001 "
         "and stage 5 discharged it onto the engineer, because the firewall holds the certificate "
         "and no endpoint's trust store. Nor can it say whether the TLS floor actually negotiated "
         "is acceptable - the binding is a NAME, and on a template-managed appliance the profile "
         "it names is not in the same payload. A PORTAL WITH 0 IN THE AUTHENTICATION ROWS COLUMN "
         "IS THE WORST STATE ON THIS TAB AND NO CONTROL REPORTS IT: `client-auth` is optional at "
         "commit, so such a portal demands nothing at all, which is weaker than the lowest rank "
         "PAN-GPP-002 can grade - and it has no child row for that control to report on.",
         title="GlobalProtect Portals", subject=PORTAL_SUBJECT,
         setting_labels=globalprotect_portal.PORTAL_SETTING_LABELS,
         # TWO READERS AND BOTH ARE FREE, because both fields are in `DERIVED_FIELDS` and the
         # normalizer writes no `FieldProvenance` row for either. Without them a customer reads
         # `no_agent_configuration` and `0` - and the `0` is PAN-GPP-004's PASSING value, which is
         # the worst cell this tab could print. `custom_login_page` deliberately has NO reader:
         # it is the one stored field of the eight, a reader would cost its provenance row, and
         # whether that key was carried at all is what PAN-GPP-005's third query is about.
         value_readers=globalprotect_portal.PORTAL_VALUE_READERS,
         hidden_fields=(),
         # THE FULL SET, so `Fires when` is on the workbook as well as the live page. The default
         # is `("Provenance",)` and taking it would make the two surfaces disagree about which
         # cell a reader meets. It earns the space here for a reason the rows show: four controls
         # report on one row over five columns, and three of the four have SIX shipped queries
         # splitting one column's values - so two portals identical in every other cell report at
         # different severities, and the stated condition is the only cell that says on what.
         #
         # AND IT RENDERS IN FIELD NAMES, measured on the built table rather than assumed.
         # `render_node` consults `setting_labels` nowhere, so the condition reads
         # `saved_credentials_posture = 0` directly above a column headed "Save User Credentials"
         # whose cell reads "No" - the same value named two ways on one row, and the raw `0` that
         # the reader exists to keep out of the cell is printed in the condition anyway. The
         # alternative is the contradicting value with no stated condition beside it at all, which
         # is worse, so the column stays and the defect is recorded.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.GLOBALPROTECT_PORTAL_CLIENT_AUTH,
         "Each row of each portal's client-authentication table, and what it demands before it "
         "admits an endpoint. THE ROW AND NOT THE PORTAL IS THE GRAIN, which is the one thing to "
         "read before acting on this tab: the table is keyed by the endpoint CLASS it serves, so "
         "one portal can require both factors of a managed Windows endpoint and accept a password "
         "alone from a browser - measured on this estate, where two rows of one portal sit at high "
         "severity and at no finding at all. A portal-grain row would have had to print one of "
         "those and would have reported the compliant sibling as the fault. THE DEMAND IS A "
         "VERDICT OVER TWO LEAVES AND THE VENDOR'S POLARITY IS INVERTED: on the Credentials OR "
         "certificate switch, `no` is the HARDENED answer - both factors required - and `yes` "
         "means either will do, which is only a second factor at all where the owning portal binds "
         "a certificate profile. Both leaves are beside the verdict for that reason. WHAT THIS TAB "
         "CANNOT SAY is whether the thing named in Authentication Profile is a profile or a "
         "SEQUENCE, which are different objects at different rail addresses; the row holds only a "
         "name. Nor can it report a portal that demands NOTHING - a portal with no rows here has "
         "no row on this tab, and the Authentication rows column on the Portals tab is where that "
         "state appears.",
         # "Portal Client Authentication" AND NOT "GlobalProtect Portal Client Authentication",
         # which is what this tab wanted to be called: Excel caps a worksheet name at 31
         # characters and `probe.surface_for` reported the longer title truncating to
         # "GlobalProtect Portal Authentica" in the workbook while the live page kept the whole
         # of it - the two surfaces disagreeing about the tab's own name. 28 characters fits
         # both. "Client Authentication" is the vendor's own sub-heading for exactly this table
         # (help 11.2 p.1002, the row of settings beginning "Client Authentication / Name / Enter
         # a name to identify the client authentication configuration"), so what was dropped is
         # the product name and not the thing's own word.
         title="Portal Client Authentication", subject=CLIENT_AUTH_SUBJECT,
         setting_labels=globalprotect_portal.CLIENT_AUTH_SETTING_LABELS,
         # ONE READER AND IT IS FREE: `admission_demand` is in `DERIVED_FIELDS` and no payload key
         # carries it. Without it the one setting column on this tab would read
         # `password_and_certificate` to a customer.
         value_readers=globalprotect_portal.CLIENT_AUTH_VALUE_READERS,
         hidden_fields=(),
         # THE FULL SET. One control, one setting column, and four shipped queries splitting that
         # column's four values at three severities - so the stated condition is what distinguishes
         # a critical row from a high one on cells that are otherwise identical.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.GLOBALPROTECT_ENFORCEMENT_POINT,
         "Whether each virtual system publishes internal web applications to a browser with no "
         "GlobalProtect agent installed. THE ROW IS A CONCLUSION OVER ALL THE VIRTUAL SYSTEM'S "
         "GLOBALPROTECT OBJECTS AND NOT ABOUT ANY PORTAL, and that is the whole reason this "
         "subject exists beside the portal tab: the state worth reporting is sometimes the "
         "ABSENCE of a publishing portal while the application definitions sit there ready, and a "
         "vsys holding a definition no portal publishes has NO PORTAL ROW anywhere in this report "
         "to be reported on - measured on this estate's vsys6. What is graded here is PRESENCE, "
         "so there is no well-configured rank: the acceptable state is that the feature is not "
         "there. THE PIECES LIVE AT THREE RAIL ADDRESSES and the Clientless definitions cell is "
         "what says which one to open - the definitions at Network > GlobalProtect > Clientless "
         "Apps and Clientless App Groups, and the publishing at a portal's own Clientless VPN "
         "tab. WHAT THIS TAB CANNOT SAY is whether the applications published are ones somebody "
         "REVIEWED, which is the engineer's half of the control, nor whether the transport floor "
         "those browser sessions negotiate is acceptable - that is per portal, and stage 8 "
         "records it as the half it did not build. A LICENCE ROW READING `No` IN THE LICENSING "
         "COLUMN COVERS TWO STATES, licensed and never asked, and the GlobalProtect licence cell "
         "beside it is the only place they are told apart.",
         title="GlobalProtect Coverage", subject=ENFORCEMENT_POINT_SUBJECT,
         # TWO DOMAINS' LABELS ON ONE TAB, which is what a shared sheet costs and is why the merge
         # is here rather than either domain's map being extended. `globalprotect-portal` owns the
         # clientless and licence columns; `globalprotect-gateway`'s PAN-GPG-005 ADDS a column to
         # this tab the moment it ships, because `setting_columns` derives one per clause field of
         # the controls present in the build. That run predicted the arrival and could not name the
         # column, because it does not exist until the other domain ships.
         #
         # MEASURED BEFORE IT WAS WRITTEN, with the committed seeder against the real artifacts:
         # this tab drew 17 headings over 3 rows and reported "RAW HEADINGS: 1 of 17" -
         # `posture_referenced_in_policy`, heading a customer-facing cell on a tab that was
         # otherwise fully labelled.
         setting_labels={**globalprotect_portal.ENFORCEMENT_POINT_SETTING_LABELS,
                         **globalprotect_gateway.POSTURE_SETTING_LABELS},
         value_readers=globalprotect_portal.ENFORCEMENT_POINT_VALUE_READERS,
         hidden_fields=(),
         # EVERY COLUMN OF THIS MODEL IS IN ITS `DERIVED_FIELDS` and nothing writes a provenance
         # row for any of them - the model's own docstring says so ("CARRIES NO PER-FIELD
         # PROVENANCE, and that is a real `false` rather than a lapse: every column is computed")
         # and `normalization/globalprotect.py` passes `provenance=()` at the write. AND
         # `write_node_row` WRITES NO `__entry__` ROW EITHER, which is the half that decides this:
         # `write_scoped_objects` always writes one, so the other two tabs of this domain resolve
         # to `Local` and need nothing, while this one lands `provenance_cells` on its `row is
         # None` arm and prints "Not recorded" about values this assessment computed. Board record
         # P451, and it bites ONE of this domain's three tabs rather than two.
         #
         # ONE ANSWER FOR THE ROW IS THE HONEST SHAPE, copied from `T.DECRYPTION_RULEBASE_COVERAGE`
         # and `2b5f744`. It is a `provenance_cell` and not a `value_readers` entry because a
         # reader answers for a COLUMN and this answers for the ROW - and the reader on
         # `clientless_vpn_feature_state` above would fix only that one of the two cells, leaving
         # `licence_excludes_globalprotect` reading "Not recorded". It says only "Derived" and
         # names nothing beside it, because there is no recorded provenance anywhere on this model
         # to name.
         provenance_cell=lambda point, _p, _f: "Derived",
         # A Template column would be blank on every row: there is no pushed key here to name a
         # template for, because there is no key at all.
         source_columns=(),
         # THE FULL SET. Two setting columns, one of which is an applicability gate reading the
         # same value on every row, and four queries splitting the other's values - so the stated
         # condition is what says why a `live` vsys is medium and a `latent` one is low.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.GLOBALPROTECT_GATEWAY,
         "Each GlobalProtect gateway a virtual system publishes, and what it offers the endpoints "
         "that build a tunnel to it. A gateway is the service that actually carries remote-user "
         "traffic, so the controls here are about the transport: whether the profile it presents "
         "states a protocol floor at all, whether it builds an inspected tunnel, whether that "
         "tunnel runs over the transport and the algorithm the organisation chose, and how long a "
         "session and an idle session are allowed to last. THE ROW IS ONE GATEWAY ON ONE APPLIANCE, "
         "so an HA pair draws two rows for one configuration and the Appliance and HA role columns "
         "are what tell them apart. EVERY ROW ON THIS TAB IS DRAWN FROM A GATEWAY THAT EXISTS - and "
         "at the time this tab was built, no GlobalProtect gateway existed anywhere in the measured "
         "estate, so none of these controls has ever reported on real configuration. THE GATEWAY IS "
         "READ IN TWO HALVES AT TWO SCOPES and the transport half is the one that goes missing: a "
         "collection that retrieves the gateway entry gets the authentication half and can silently "
         "miss the networking half, which is why 'Transport half of the gateway was read' is a "
         "column rather than an assumption. WHAT THIS TAB CANNOT SAY is whether the certificate the "
         "gateway presents chains to an authority the connecting endpoint already trusts - that is "
         "the other half of PAN-GPG-001 and stage 5 discharged it onto the engineer, because the "
         "firewall holds the certificate and no endpoint's trust store. Nor can it say what "
         "protocol version is actually negotiated: the binding is a NAME, and the commonest state "
         "for a correctly hardened gateway is a name resolving into the predefined configuration, "
         "which no merged view carries. THE QUARANTINE PAIR IS ON THE ROW AND NO CONTROL REPORTS "
         "IT: stage 5 wrote a gateway-grain record for PAN-GPG-005 and stage 8 compiled no query "
         "for it, so 'Block login for quarantined devices' is evidence here and nothing grades it.",
         title="GlobalProtect Gateways", subject=GATEWAY_SUBJECT,
         setting_labels=globalprotect_gateway.GATEWAY_SETTING_LABELS,
         # THREE READERS AND ALL THREE ARE FREE - every one is in `GlobalProtectGateway.DERIVED_FIELDS`
         # and appears in no provenance list in `normalization/globalprotect.py`. Each says
         # "this branch does not exist on this subject", which `display_value` has no way to express:
         # without them an unbounded login reads `(none)` and a gateway with IPSec switched off reads
         # `(empty)` for a proposal list it does not have. TWO READERS WERE REFUSED on this tab -
         # `ipsec_enabled` and the cookie certificate on the sibling - because both are measured
         # payload keys whose own `FieldProvenance` row a reader would discard. See the module.
         value_readers=globalprotect_gateway.GATEWAY_VALUE_READERS,
         hidden_fields=(),
         # THE FULL SET, so `Fires when` reaches the workbook as well as the live page; the default
         # is `("Provenance",)` and taking it makes the two surfaces disagree about which cell a
         # reader meets (P427). It earns the space here: three controls report on one row over ten
         # derived columns, PAN-GPG-006 and -007 ship five and six calibration queries splitting
         # single columns' values across three severities, so two gateways identical in every other
         # cell report differently and the stated condition is the only cell that says on what.
         #
         # AND IT RENDERS IN DJANGO FIELD NAMES, measured on the built table rather than assumed:
         # `render_node` consults `setting_labels` nowhere, so the condition reads
         # `tunnel_mode = No` above a column headed "Tunnel Mode". The same value named two ways on
         # one row. The alternative is the contradicting value with no stated condition beside it,
         # which is worse, so the column stays and the defect is recorded.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.GLOBALPROTECT_GATEWAY_CLIENT_AUTH,
         "Each row of each gateway's client-authentication table, and what it demands before it "
         "admits an endpoint. THE ROW AND NOT THE GATEWAY IS THE GRAIN, which is the thing to read "
         "before acting on this tab: the table is keyed by the endpoint CLASS it serves, so one "
         "gateway can require a second factor of a managed Windows endpoint and accept a password "
         "alone from a third-party IPSec client. A gateway-grain row would have had to print one of "
         "those and would have reported the compliant sibling as the fault. THE VENDOR'S POLARITY "
         "IS INVERTED on the credentials switch: 'No' is the HARDENED answer - both factors "
         "required - and 'Yes' means either one alone admits the endpoint, which is why that column "
         "is headed as what is ACCEPTED rather than what is required. WHAT THIS TAB CANNOT SAY is "
         "whether the object named in Authentication Profile is a profile or a SEQUENCE: the leaf "
         "accepts either, the stored string does not say which, and a row naming a sequence resolves "
         "to nothing - so an empty 'Authentication back end' beside a named profile is that state "
         "and not a collection failure. A sequence can fall back to the firewall's own local "
         "database, which is the configuration this control exists to find. THE CERTIFICATE COLUMN "
         "IS READ OFF THE PARENT GATEWAY and not off this row; an em dash in it means the row's "
         "parent gateway did not resolve, which is not the same as 'no'.",
         # 29 characters. "GlobalProtect Gateway Client Authentication" is what this tab wanted to
         # be called and Excel caps a worksheet name at 31, so the longer title would truncate in
         # the workbook while the live page kept the whole of it - the two surfaces disagreeing
         # about the tab's own name, which `probe.surface_for` does not show because it prints the
         # untruncated title. "Client Authentication" is the vendor's own sub-heading for exactly
         # this table (Help 11.2 p.1046, "Client Authentication Area / Name / Enter a unique name to
         # identify this configuration"), so what was dropped is the product name and not the
         # thing's own word. The sibling tab in `globalprotect-portal` made the same trade.
         title="Gateway Client Authentication", subject=GATEWAY_CLIENT_AUTH_SUBJECT,
         setting_labels=globalprotect_gateway.CLIENT_AUTH_SETTING_LABELS,
         # ONE READER AND IT IS MANDATORY, not a nicety: `gateway_client_certificate_is_a_second_factor`
         # is a search-registry key with no attribute of that name on this model, so `tested_fields`
         # RAISES `ValueError` without it and takes down `store_run_tables` for the whole domain
         # rather than one cell. Stage 8 filed it as owed to this stage. It costs nothing - the
         # value it walks to is in the gateway's `DERIVED_FIELDS` and this row has no provenance key
         # by that name to lose.
         value_readers=globalprotect_gateway.CLIENT_AUTH_VALUE_READERS,
         hidden_fields=(),
         # THE FULL SET. One control, two setting columns and two shipped queries at two severities
         # - critical from the control default and high from the calibration - so the stated
         # condition is what distinguishes them on cells that are otherwise identical.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.GLOBALPROTECT_GATEWAY_AGENT_CONFIG,
         "Each agent configuration a gateway pushes to the endpoints that match it, and the two "
         "things about it that outlive a login: the reconnection cookie, and which traffic is sent "
         "outside the tunnel. THE ROW IS ONE AGENT CONFIGURATION, matched to users by source user, "
         "operating system and source address, so one gateway can hold several and they are not "
         "interchangeable. THE COOKIE IS A BEARER CREDENTIAL: whoever can present a valid one "
         "reconnects as that user without authenticating, so the lifetime is how long a stolen "
         "cookie stays useful and the certificate is what stops one being forged. A row that "
         "accepts no cookie is suppressed rather than passed - there is nothing to steal - which is "
         "why 'Accept cookie for authentication override' reads as a plain setting and not as a "
         "fault. THE EXCLUSION COUNT IS A NUMBER OVER EIGHT AXES, six inside the split-tunnel "
         "container and two siblings of it, and no PAN-OS screen presents them together; the two "
         "that are single switches are beside it and the six that are lists are on the "
         "configuration page, because a findings row is not where anyone reads two hundred domains. "
         "ZERO IS THE PASSING VALUE AND ALSO THE DEFAULT, so 'The exclusion inventory was computed' "
         "is what separates a full tunnel from a row nobody has counted - without it the most "
         "compliant cell on the tab and the least measured one are the same cell. WHAT THIS TAB "
         "CANNOT SAY is whether the excluded paths were ones somebody chose: an exclusion is a "
         "decision, and this reports only that it exists.",
         # 27 characters, and "Agent" is the vendor's own name for this half of the gateway dialog
         # (Help 11.2 p.1048, "GlobalProtect Gateways Agent Tab").
         title="Gateway Agent Configuration", subject=GATEWAY_AGENT_CONFIG_SUBJECT,
         setting_labels=globalprotect_gateway.AGENT_CONFIG_SETTING_LABELS,
         # ONE READER, FREE, AND ITS BRANCH IS NOT "IS IT NULL": two nulls with opposite meanings
         # share the cookie-lifetime column, and the control's own applicability clause is what
         # tells them apart, so the cell does too. A row accepting no cookie has no lifetime branch
         # and reads an em dash; a row that accepts one and bounds nothing is the FIRING state and
         # reads `(none)` beside a marked companion. An em dash on the second would read "not
         # applicable" over exactly the row the control exists to raise.
         value_readers=globalprotect_gateway.AGENT_CONFIG_VALUE_READERS,
         hidden_fields=(),
         # THE FULL SET. Two controls, seven derived columns, and PAN-GPG-003 ships five calibration
         # queries banding one column's values at two severities - so the stated condition is what
         # says why one cookie lifetime is high and another medium.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.INTERFACE_MANAGEMENT_PROFILE,
         "The profiles that decide which services a data-plane interface offers, and which "
         "interfaces carry them.",
         subject=APPLIANCE + NAME + (
             ("Bound interfaces", 18, True,
              lambda s, _p: "\n".join(s.bound_interface_names or []) or "(none)", "binding_count"),
         ),
         value_readers={"binding_count": BINDING_COUNT}),
    spec(T.SSL_TLS_SERVICE_PROFILE,
         "The TLS profiles the firewall presents to browsers and clients: their protocol floor "
         "and the certificate each uses.",
         title="SSL-TLS Service Profile", subject=APPLIANCE + SCOPE + NAME),
    spec(T.CERTIFICATE_PROFILE,
         "The profiles that decide how a presented certificate is validated - which CAs are "
         "trusted, and whether revocation is checked.",
         subject=APPLIANCE + SCOPE + NAME),
    spec(T.CERTIFICATE,
         "The certificates held on the firewall: who issued each, how strong its key is, and what "
         "signed it.",
         subject=APPLIANCE + SCOPE + NAME,),
    # Device > Certificate Management > Certificates, 2026-11-02, for PAN-DCP-006 - a NEW TAB,
    # because `probe.surface_for PAN-DCP-006` reported NO SHEET SHOWS IT while the domain's other
    # six controls already reach `Security Profile`. One domain, two tabs.
    #
    # IMMEDIATELY AFTER `certificate` AND THAT IS NOT INCIDENTAL. `finding_run.GENERATORS` already
    # placed this control type there, with its own reasoning: "the forward-proxy signing
    # designation is a POINTER into the certificate store, so a reader meets the certificates
    # before the node that names two of them". Within a category the `DOMAINS` list takes that
    # tuple's order, so the tab follows `Certificates` in the Device block.
    #
    # THE ROW IS ONE APPLIANCE, which is the grain the model takes and the reason it can report at
    # all: the commonest failing state is that NO certificate is designated anywhere, and
    # `/config/shared/ssl-decrypt` was absent on all four lab appliances before stage 6 built a
    # designation on one of them. A per-SLOT grain has no row in exactly that state, so it could
    # not carry the finding. THE HA CONSEQUENCE IS THE DUPLICATING ONE: the designation is
    # device-wide, one node per firewall, and `deviceconfig`'s non-HA fields are synchronised
    # across peers - so on an HA pair this tab draws TWO rows for ONE real configuration and
    # nothing downstream deduplicates them. Stage 5 declares `one_row_per: one appliance` and says
    # so in those words. IT COULD NOT BE EXERCISED HERE and that is recorded rather than denied:
    # stage 8's census states that every appliance group in this population is STANDALONE, one per
    # appliance, and that `fw-core-tpa-a` is one half of a real lab HA pair with only the one peer
    # collected. What would establish it is a collection carrying BOTH peers of one group; what
    # would fix it is a fold on the appliance GROUP rather than on the serial, which is not a
    # sheet's to do.
    #
    # THE FOUR DESIGNATION SLOTS ARE SUBJECT COLUMNS and each NAMES ITS `field`. No shipped query
    # clauses on any of them - the compiler declines to register them in terms, because
    # "registering them would ship a search surface no control asks for" - so `setting_columns`
    # derives no column for them and this is the only thing that puts them on the row. Stage 5
    # requires them presented, and the finding needs them: both of this control's verdicts cover
    # two failing states each ("nothing designated" and "something designated that is the wrong
    # thing"), and these four cells are what tells a reader which. They declare their `field` for
    # the reason the `Custom URL Category` tab's count column does: a subject column that declares
    # no field does NOT suppress a derived column for the same attribute, so one value could reach
    # the tab twice under two headings - and because the headings differ the duplicate-header
    # guard would never fire.
    #
    # `hidden_fields` IS EMPTY, and there was no reason for a new sheet to declare one: the gate
    # counts a field as presented if `hidden_fields` carries it, so a non-empty tuple is a CLAIM
    # accepted as proof and is the only known cause in this repository of a findings row that
    # marks nothing as the thing to fix (P409).
    #
    # `tested_columns` IS `ALL_TESTED_COLUMNS` AND THAT IS A CHOICE, MADE KNOWING ONE ROW IN THREE
    # RENDERS A WRONG `Fires when`. The default is `('Provenance',)`, which keeps `Fires when` on
    # the live page and silently DROPS it from the xlsx, so the two surfaces disagree about which
    # cell a reader meets (P427). The cost here is measured and named: `fires_when` renders the
    # BASELINE alone, and on `fw-core-tpa-a` and `pan-fw-201` the finding is matched by the
    # calibration query `No distinct forward-untrust authority` and NOT by the baseline - so those
    # rows print `forward_trust_is_designated_local_ca = No` beside a cell reading `Yes`. Carried
    # anyway, on `ipsec-crypto`'s reasoning: the alternative is the contradicting value with no
    # stated condition beside it at all, and `Matched queries` plus the marked cell resolve it
    # between them. Not fixable from a sheet - `fires_when` is shared machinery.
    #
    # ITS CATEGORY IS DERIVED FROM THE RAIL (`category=''`), which is right for a subject that IS a
    # configuration object: deriving it means the workbook cannot disagree with the app about where
    # the object lives. The rail item is `forward-proxy-signing`, at Device > Certificate
    # Management > Certificates, the second item at that address.
    #
    # THE TAB TITLE IS A PROPOSAL (P399). Without one the title derives from the control type's own
    # label, "Decryption Settings", which is both vague and misleading beside the `decryption-policy`
    # domain that runs next - this tab is not about decryption settings in general, it is about
    # which certificate the firewall signs with when it stands in for a destination. "Forward
    # Proxy" is the vendor's own name for that mode (help 11.2 p.339, "SSL FORWARD PROXY TAB ...
    # decrypted using Forward Proxy") and "Forward Trust Certificate" its own name for the usage
    # (p.170, p.889); "Signing" is ours, joining the two.
    #
    # EVERY HEADING BELOW IS A PROPOSAL, sourced in place.
    # --- decryption-policy, 2026-11-02 -------------------------------------------------------
    spec(T.DECRYPTION_POLICY_RULE,
         "Each decryption rule that leaves a session encrypted, and what it exempts. A rule here "
         "is not a defence that is weak - it is traffic the whole inspection stack downstream "
         "never sees, and every control on this tab is about how MUCH traffic one exemption "
         "covers: whether it is keyed on any criterion at all, whether it says why it exists, "
         "whether the population it exempts is a set of people somebody can review, and whether "
         "the firewall keeps any record of the sessions it declines to open. WHAT THIS TAB "
         "CANNOT SAY is whether the exempted traffic matters: a rule naming one 32-address "
         "object and a rule naming `any` differ by a number no column holds, because nothing in "
         "the configuration measures how large an address object is - that arithmetic belongs to "
         "PAN-POL-002 and is not built, and stage 8 carries it as an open question. A DISABLED "
         "RULE IS STILL IN SCOPE (Jason, 2026-10-14) and the Disabled column is where a reader "
         "sees which side of that each row is on.",
         title="Decryption Rules", subject=DECRYPTION_RULE_SUBJECT,
         setting_labels=decryption_policy.RULE_SETTING_LABELS,
         # THE FIVE CRITERIA WHOSE VALUE IS NOT ON THE RULE ROW. Required rather than chosen -
         # `tested_fields` raises without them - and the module they live in records what the
         # declaration costs and why there is no alternative.
         value_readers=decryption_policy.RULE_VALUE_READERS,
         hidden_fields=(),
         # THE FULL SET, which means `Fires when` is on the workbook as well as the live page.
         # The default is `("Provenance",)` and taking it would make the two surfaces disagree
         # about which cell a reader meets. It earns the space on this tab for a reason the rows
         # show: PAN-DEC-010 reports through TWO records over the same model at the same severity
         # - one about the failed-handshake record and one about the successful-session record -
         # and two rules identical in every other cell report differently between them. The
         # applicability clause `action = no-decrypt` is the other thing no other cell explains:
         # it is why a decrypting rule with an empty description draws no PAN-DEC-003 row.
         #
         # AND IT RENDERS IN FIELD NAMES, measured on the built table rather than assumed.
         # `render_node` consults `setting_labels` nowhere, so the condition reads
         # `source_user_is_keyword_population = Yes` directly above a column headed "Exempt
         # population is only platform keywords" - the same value named two ways on one row. The
         # alternative is the contradicting value with no stated condition beside it at all,
         # which is worse, so the column stays and the defect is recorded.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         # A rule belongs to a vsys, which on an HA pair spans both firewalls, so there is no one
         # appliance to link a row to - the same answer every vsys-scoped tab gives.
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance",
                                 "enforcement_point__appliance_group"),
         # THE FIVE MEMBER COLLECTIONS, PREFETCHED, and this is the one line on the spec that is
         # about cost rather than content. Each of the five readers walks a related manager with
         # `.all()`, which honours a prefetch - `.filter()` does not, which is the defect that
         # made `rules_by_device_group.fold()` issue one query per row and 88% of the whole
         # report build. Without these five entries this tab would pay five queries per RULE.
         subject_prefetch=("enforcement_point__appliance_group__appliances",
                           "decryptionpolicyrulecategorys",
                           "decryptionpolicyrulesources",
                           "decryptionpolicyruledestinations",
                           "decryptionpolicyrulesourceusers",
                           "decryptionpolicyruleservices")),
    spec(T.DECRYPTION_RULEBASE_COVERAGE,
         "Whether each virtual system's decryption policy opens a session for inspection at all, "
         "outbound and inbound. THE ROW IS A CONCLUSION ABOUT ALL THE RULES AND NOT ABOUT ANY "
         "ONE OF THEM, and that is the whole reason this subject exists beside the per-rule tab: "
         "the commonest failing state measured in this estate is an enforcement point with NO "
         "decryption rulebase at all, and a comparison over rule rows reports nothing where "
         "there is no row to compare - so the absence would be silent on exactly the firewalls "
         "where it matters most. An enforcement point nobody collected reads the same as one "
         "that decrypts nothing, deliberately: every column here defaults to its firing value, "
         "so silence reports itself rather than passing. WHAT THIS TAB CANNOT SAY is WHERE the "
         "gap is - a rule pushed from a device group contributes to these verdicts and this "
         "subject has no scope column, so a finding cannot tell a gap in the firewall's own "
         "rulebase from one in the device group; the per-rule tab answers that with its Rulebase "
         "column. Nor can it say which zone pair is the corporate web egress, which needs the "
         "engineer's own path list.",
         title="Decryption Coverage", subject=DECRYPTION_RULEBASE_SUBJECT,
         setting_labels=decryption_policy.RULEBASE_SETTING_LABELS,
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         # EVERY COLUMN OF THIS MODEL IS IN ITS `DERIVED_FIELDS` and the model writes NO
         # provenance row for any of them - its own docstring says so: "A verdict is computed
         # rather than read: no key supplies it, so there is no marker to store." So the
         # per-field walk finds no row, `remediation_accessor` discards a synthesised DERIVED row
         # on purpose, and nothing writes an `__entry__` row for this model either - which lands
         # `provenance_cells` on its `row is None` arm and prints "Not recorded" THREE TIMES on
         # every row. That means "nothing tracks that field" and reads to a customer as a gap in
         # the collection, about three values this assessment computed. Board record P451.
         #
         # ONE ANSWER FOR THE ROW IS THE HONEST SHAPE, and it is a `provenance_cell` rather than
         # a `value_readers` entry because a reader answers for a COLUMN and this answers for the
         # ROW. `rulebase-device-match` and `vsys-rule-posture`, the two existing verdict tabs,
         # made the same call for the same reason. It says only "Derived" and names nothing
         # beside it - unlike `forward-proxy-signing`, which has four measured payload keys to
         # name - because there is no recorded provenance anywhere on this model to name.
         provenance_cell=lambda v, _p, _f: "Derived",
         # A Template column would be blank on every row: there is no pushed key here to name a
         # template for, because there is no key at all.
         source_columns=(),
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance",
                                 "enforcement_point__appliance_group"),
         subject_prefetch=("enforcement_point__appliance_group__appliances",)),
    spec(T.SSL_DECRYPTION_EXCLUSION,
         "Each SSL decryption exclusion THE ORGANISATION ADDED ITSELF, and whether it says why. "
         "An exclusion keeps every session to or from the named server encrypted, so it is a "
         "standing hole in inspection that only the reason written on it can justify - and the "
         "device checks neither that a reason exists nor that it is still true. BOTH WRITABLE "
         "SCOPES ARE HERE: the appliance's own shared container and every virtual system, and "
         "the vsys scope matters because PAN-OS puts the screen at the shared one - a "
         "vsys-scoped exclusion is real, committable configuration no operator can see or remove "
         "through the interface they use. WHAT THIS TAB DOES NOT HOLD is the vendor's own 330 or "
         "385 predefined exclusions, which are a separate object invisible to the read behind "
         "this model, although the web interface renders both collections in ONE grid "
         "distinguished only by a Location column. Nor does it hold which of those an operator "
         "has switched OFF: that is this control's other half, over a model no shipped query "
         "names.",
         title="SSL Decryption Exclusions", subject=SSL_DECRYPTION_EXCLUSION_SUBJECT,
         setting_labels=decryption_policy.EXCLUSION_SETTING_LABELS,
         hidden_fields=(),
         # `Fires when` is worth the column here for the narrowest of this tab's reasons: the
         # control's one clause is `description is empty`, which a NULL also matches, so a reader
         # meeting `(empty)` in the Description cell is owed the statement that empty is the
         # condition. The Provenance cell is the default per-field walk and answers honestly on
         # this model - `description` is a stored column with a real `FieldProvenance` row, and an
         # `__entry__` row exists behind it.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.DECRYPTION_SETTINGS,
         "Which certificate this firewall signs with when it stands in for a destination it is "
         "decrypting. One row per appliance, because the designation is device-wide and the "
         "commonest failing state is that nothing is designated at all - in which state the "
         "firewall answers `No SSL Decryption CERT` in its own words and a per-slot row would not "
         "exist to report it. Each of the two verdicts covers TWO failing states that need "
         "different remediations - nothing designated, or something designated that is not a "
         "certificate authority this firewall holds and signed itself - so the four designation "
         "cells are presented beside them and a reader is never given a verdict without the slots "
         "behind it. WHAT THIS DOES NOT READ: the set of authorities the firewall trusts FOR "
         "decryption, at /config/shared/ssl-decrypt/trusted-root-CA, is owned by no model and "
         "asserted by no control, so a trust decision this tab reports on is tested against a "
         "boundary no part of this assessment reads.",
         title="Forward Proxy Signing",
         subject=APPLIANCE + (
             # THE VENDOR'S OWN LABELS for the two usages, help 11.2 p.889 verbatim ("usage is set
             # to Forward Trust Certificate or Forward Untrust Certificate") and p.170 for the
             # trust half. The algorithm in parentheses is the device's own child key - each
             # container carries an `rsa` and an `ecdsa` child - and the pair is not decoration:
             # the first verdict passes only when EVERY filled slot qualifies, because the weaker
             # of the two is what a session can end up negotiating.
             #
             # "Nothing designated" and not a blank. An empty slot is the whole finding, and an
             # empty cell reads as a gap in the collection - which is the distinction
             # `display_value` exists to make and which it cannot make here, because the store
             # holds "" rather than NULL (the search layer's `is_empty` compiles to
             # `filter(field="")`, so emptiness is only assertable on an empty string).
             ("Forward Trust Certificate (RSA)", 24, False,
              lambda d, _p: d.forward_trust_cert_rsa or "Nothing designated",
              "forward_trust_cert_rsa"),
             ("Forward Trust Certificate (ECDSA)", 24, False,
              lambda d, _p: d.forward_trust_cert_ecdsa or "Nothing designated",
              "forward_trust_cert_ecdsa"),
             ("Forward Untrust Certificate (RSA)", 24, False,
              lambda d, _p: d.forward_untrust_cert_rsa or "Nothing designated",
              "forward_untrust_cert_rsa"),
             ("Forward Untrust Certificate (ECDSA)", 24, False,
              lambda d, _p: d.forward_untrust_cert_ecdsa or "Nothing designated",
              "forward_untrust_cert_ecdsa"),),
         setting_labels={
             # BOTH OURS, and the vendor has no word for either: each is a quantifier this
             # assessment computes over the four slots above, one of them following a designated
             # name into the certificate store. `probe.corpus --all` returns the vendor's label for
             # the USAGE and nothing at this position.
             #
             # "local self-signed CA" spells the on-device proxy the column actually tests - the
             # name resolves to a certificate THIS appliance holds, marked a certificate authority,
             # and self-signed - rather than claiming "issued by the organisation", which is what
             # it stands in for and is not what was read. A name resolving to NO certificate row
             # makes this `No`, deliberately: a designation pointing at nothing is a worse state
             # than no designation, not a better-evidenced one. The finding sentence cannot say
             # WHICH of those three states it found, which stage 8 has on the record as a
             # `needs_human`; closing it needs a second column, which is stage 7's.
             "forward_trust_is_designated_local_ca":
                 "Trust certificate is a local self-signed CA",
             # "differs from" and not "is distinct from": the column is FALSE where no untrust
             # authority is designated at all and FALSE where any untrust slot names a certificate
             # a trust slot also names, and "differs" covers both without implying that one exists.
             # The reason the pair matters is the vendor's own purpose for it - a firewall using
             # one certificate for both gives a user no way to tell a trustworthy site from an
             # untrustworthy one.
             "untrust_distinct_from_trust": "Untrust authority differs from trust",
         },
         # BOTH TESTED FIELDS ARE IN `DecryptionSettings.DERIVED_FIELDS` and NEITHER GETS A
         # `value_readers` ENTRY, which is worth stating because it is the opposite call from the
         # six this run made on the shared profile tab. There is nothing for a reader to fix here:
         # both are non-nullable booleans, `display_value` prints `Yes`/`No`, and there is no
         # branch that fails to exist on this subject - the model has one kind and no kind column.
         #
         # BUT THE DEFAULT PROVENANCE CELL WAS WRONG AND THAT WAS FOUND BY READING THE ROWS, not
         # by reasoning about them. It printed "Not recorded" twice on all three rows, which means
         # "nothing tracks this field" and reads to a customer as a gap in the collection. The
         # mechanism is `data-filtering-posture`'s, one model over: `remediation_accessor` treats a
         # DERIVED row as NO ANSWER on purpose - "it is the case the object has to answer" - and
         # walks to the object's `__entry__` row, which nothing writes for this model, so
         # `provenance_cells` falls through to its `row is None` arm. The value is not untracked;
         # it is derived, and `provenance_cell` is the hook that says so.
         #
         # IT ALSO NAMES WHERE THE EVIDENCE CAME FROM, which the three existing verdict tabs have
         # no need to: EVERY column of their models is derived, and here only three of seven are.
         # The four designation slots ARE measured payload keys carrying real `FieldProvenance`
         # rows, they are the only thing on this row a device wrote, and whether `oep-p1-cert` was
         # designated on the firewall or pushed by a Panorama template is the first thing a reader
         # fixing this finding needs. Nothing is decided in this cell - it reads the recorded rows
         # and prints the distinct answers, which is what every provenance cell does.
         provenance_cell=lambda settings, provenance_of, _fields: "\n".join(
             ["Derived"] + [
                 label for label in dict.fromkeys(
                     (lambda row: row.get_provenance_type_display() if row is not None else None)(
                         provenance_of(slot))
                     for slot in ("forward_trust_cert_rsa", "forward_trust_cert_ecdsa",
                                  "forward_untrust_cert_rsa", "forward_untrust_cert_ecdsa"))
                 if label]),
         # CHECKED BEFORE DESIGNING THIS SHEET, because `device-id-iot` lost about an hour to the
         # inverse of the above: `build_findings_table`'s `provenance_of` closure reads
         # `field in _model.DERIVED_FIELDS` as a plain attribute whenever no stored row exists, so
         # a `SyncTrackedModel` that is NOT a `ProvenancedMixin` raises `AttributeError` for every
         # field of every row and the error does not say why. `DecryptionSettings(ProvenancedMixin,
         # SyncTrackedModel)` declares both, so that trap does not apply here - but the check is
         # one line and it is the line to run before choosing a spec option.
         subject_select_related=("appliance__appliance_group",),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    spec(T.AUTHENTICATION_PROFILE,
         "How administrators and users are authenticated: the identity service behind each "
         "profile, its lockout settings and who it admits.",
         subject=APPLIANCE + SCOPE + NAME,),
    spec(T.AUTHENTICATION_SEQUENCE,
         "The ordered fallbacks tried when one authentication profile does not answer.",
         subject=APPLIANCE + SCOPE + NAME,),
    spec(T.PASSWORD_PROFILE,
         "Per-account password rules, which override the firewall-wide policy for the accounts "
         "they are bound to.",
         subject=APPLIANCE + NAME,),
    spec(T.SECURITY_PROFILE,
         "The anti-spyware, vulnerability and antivirus profiles, and what each one blocks.",
         subject=VSYS_SCOPED + KIND + NAME + (
             # Antivirus has no severity verdict and the severity columns read n/a for it, so
             # without this an antivirus finding would land on a tab that says nothing about
             # why it fired.
             ("Decoders not blocking", 24, True,
              lambda profile, _p: DECODER_COVERAGE.read(profile), "has_non_blocking_decoder"),
             ("Inline ML not blocking", 26, True,
              lambda profile, _p: ML_COVERAGE.read(profile), "has_non_blocking_ml_model"),
             ("Application exceptions", 30, True,
              lambda profile, _p: APP_OVERRIDE_COVERAGE.read(profile),
              "has_non_blocking_application_override"),
             ("WildFire signature action allows", 26, True,
              lambda profile, _p: WILDFIRE_COVERAGE.read(profile),
              "has_non_blocking_wildfire_decoder"),
             ("WildFire inline ML action allows", 26, True,
              lambda profile, _p: MLAV_COVERAGE.read(profile),
              "has_non_blocking_mlav_decoder"),),
         value_readers={"has_non_blocking_decoder": DECODER_COVERAGE,
                        "has_non_blocking_ml_model": ML_COVERAGE,
                        "has_non_blocking_application_override": APP_OVERRIDE_COVERAGE,
                        "has_non_blocking_wildfire_decoder": WILDFIRE_COVERAGE,
                        "has_non_blocking_mlav_decoder": MLAV_COVERAGE,
                        # SIXTH READER, 2026-11-02 by stage 9 of `file-data-filtering`, and it
                        # fixes a cell rather than adding a column. See REFERENCE_REACH below.
                        "reference_reach": REFERENCE_REACH,
                        # SEVENTH AND EIGHTH, 2026-11-02 by stage 9 of `url-filtering`. Both fix a
                        # cell whose placeholder read as missing data on a PASSING row, both are
                        # free because their fields are DERIVED, and both branch on `kind` so that
                        # the other six kinds get the em dash rather than a sentence about a
                        # question their rows do not ask. The reasoning is above the readers.
                        "worst_unrecorded_request_header": WORST_UNRECORDED_HEADER,
                        "broadest_inline_analysis_exemption_type": BROADEST_EXEMPTION,
                        # NINTH TO FOURTEENTH, 2026-11-02 by stage 9 of `decryption-profiles`.
                        # All six fix a cell and none adds a column; all six are on fields in
                        # `DERIVED_FIELDS`, so all six are free; five branch on `kind`. The
                        # reasoning, and the refusal on `is_used` and on this domain's fourteen
                        # measured payload keys, is above the readers.
                        "rule_destination_unrestricted": RULE_DESTINATION_UNRESTRICTED,
                        "ssl_min_version_below_tls12": SSL_MIN_BELOW_TLS12,
                        "ssl_max_version_restrictive": SSL_MAX_RESTRICTIVE,
                        "weakest_broken_primitive_permitted": WEAKEST_BROKEN_PRIMITIVE,
                        "weakest_non_pfs_or_unauthenticated_permitted": WEAKEST_NON_PFS,
                        "decryption_rulebase_collected": DECRYPTION_RULEBASE_COLLECTED},
         # THE FIRST `setting_labels` THIS SHEET HAS CARRIED, added 2026-11-02 by stage 9 of
         # `zone-dos-protection` for PAN-ZON-008. Both are PROPOSALS.
         #
         # THEY WERE RAW DJANGO FIELD NAMES ON A CUSTOMER TAB, measured by building this table
         # and grepping `FindingsTable.headers` for `_`: `reference_reach_resolved` and
         # `reference_reach` were the only two headings on any of this domain's four tabs that
         # read as code. Nothing says which columns head raw, and this sheet had no map at all.
         #
         # THIS IS THE SHAPE FOR TWO DOMAINS AND NOT ONE. `reference_reach` is asserted by
         # exactly two controls in the catalogue - PAN-ZON-008 and PAN-FIL-004, whose domain
         # (`file-data-filtering`) runs later - so these two headings are what that run inherits
         # rather than chooses.
         #
         # TWO COLUMNS FOR ONE QUESTION, and the order is stage 5's clause order: the companion
         # that says whether the walk was COMPLETE is an applicability clause and is drawn
         # BEFORE the assertion it supports. That is the right way round here, unlike the
         # alphabetical-by-query-name case further down the row: an incomplete set of reads can
         # only hide a REFERRER, so it can turn "nothing names this" into a wrong answer and can
         # never turn "a rule names this" into one. A reader meets "was this established?" and
         # then "what did it establish?".
         setting_labels={
             # Not "Walk completed": the subject of the sentence is the REFERENCE walk, and this
             # sheet carries four other profile kinds whose rows have walks of their own.
             "reference_reach_resolved": "Reference walk completed",
             # The model's own choice labels are already sentences - "Named by a security rule",
             # "Nothing on this firewall names it", "The reference walk could not be completed" -
             # so the heading is the short noun and the CELL carries the meaning. THAT SECOND HALF
             # WAS NOT TRUE WHEN IT WAS WRITTEN and is now: see `REFERENCE_REACH` above, which is
             # what makes the cell print the sentence instead of the raw choice key.
             "reference_reach": "Reference reach",
             # SEVEN MORE, 2026-11-02 by stage 9 of `file-data-filtering`, for PAN-FIL-001, -002
             # and -004. EVERY ONE IS A PROPOSAL - Jason takes the heading pass once across many
             # domains (P399) - and each is sourced below to the vendor's own help where the vendor
             # has a word, and says so where it has none.
             #
             # MEASURED BEFORE WRITING THEM, by building this table and grepping
             # `FindingsTable.headers` for `_`: 44 of this tab's 65 headings read as Django field
             # names, and SEVEN of the 44 are this domain's. The other 37 belong to the
             # `decryption` and `url-filtering` controls on this same model and are not this run's
             # to name; they are recorded in the stage 9 artifact instead. A heading with no entry
             # here is not merely unpolished - `setting_columns` falls back to the raw field name,
             # so declaring a column without a label IS choosing to show a customer a database
             # field name.
             #
             # WHAT THE VENDOR CALLS THESE THINGS, PAN-OS Web Interface Help 11.2 p.305-306
             # (Objects > Security Profiles > File Blocking) and p.309-310 (> Data Filtering): a
             # rule carries a Name, Applications, File Types, Direction and Action, and Action has
             # exactly three values - alert, continue, block. The vendor has NO word for the
             # dangerous-file-type floor, for multi-level encoding or for the files the firewall
             # cannot look inside: those are this assessment's own groupings over the device's
             # file-type catalogue, and `probe.corpus` over all eleven indexes returns NOTHING for
             # `Multi-Level-Encoding`, the spelling the device itself accepts. Those headings are
             # ours and are marked as such rather than implying a vendor label.
             #
             # THE HEADINGS ARE THE SAME WORDS THE TWO EXPLORER PAGES USE, character for
             # character, so one column does not read two ways on two surfaces.
             #
             # ALSO THE VENDOR'S: "predefined", p.305 ("apply the predefined strict profile").
             # "Vendor-shipped" is ours, because `predefined` reads as a synonym for `default` to
             # anyone who has not met the namespace vocabulary. NOTE THAT THIS COLUMN IS SHARED:
             # `is_predefined` is PAN-FIL-004's applicability clause and PAN-AVW-006 tests it too,
             # so it was already on this tab heading raw before this domain arrived.
             "is_predefined": "Vendor-shipped",
             # OURS, no vendor label. "both ways" is the vendor's Direction value `both`, spelled.
             "stops_floor_file_types": "Dangerous file types blocked both ways",
             # "Action" is the vendor's word. "Weakest" because the column stores the weakest
             # action in force across the profile's RULES - a profile whose second rule only
             # alerts is not protected by its first.
             "floor_file_type_action": "Weakest action on those file types",
             # OURS: the member name the device's own catalogue uses, in plain English.
             "stops_nested_encoding": "Multi-level encoding blocked both ways",
             "nested_encoding_action": "Weakest action on multi-level encoding",
             # OURS. "Expressed" and not "made": the column tests whether a decision about files
             # the firewall cannot open is VISIBLE in the configuration, and says nothing about
             # which way it went.
             "expresses_unopenable_file_decision": "Decision expressed on unopenable files",
             # THE VENDOR HAS THE SENTENCE AND NOT A LABEL, p.306 verbatim: "When you create a
             # file blocking profile with the action continue, you can only choose the application
             # web-browsing. If you choose any other application, traffic that matches the Security
             # policy rule will not flow through the firewall." `continue` and `web-browsing` are
             # both the vendor's own words, so the heading is built out of them.
             "confirm_rule_beyond_web_browsing": "Continue rule beyond web-browsing",
             # `every_rule_carries_both_counts` IS DELIBERATELY ABSENT and that is not an
             # omission. PAN-FIL-003's second assertion record is the only thing that clauses on
             # it, and stage 8 did not build that half - one catalogue control has one target
             # model and that half's clauses are on this model while the control targets
             # `DataFilteringPosture`. So no shipped query names the field, `setting_columns`
             # derives no column for it, and `setting_labels` is consulted only for columns that
             # exist. The heading is written on the Data Filtering EXPLORER page, where the column
             # does exist. Add the entry here the day that half is built, not before.
             #
             # ----------------------------------------------------------------------------------
             # SIXTEEN MORE, 2026-11-02 by stage 9 of `url-filtering`, for PAN-URL-001 to -005.
             # EVERY ONE IS A PROPOSAL - Jason takes the heading pass once across many domains
             # (P399) - and each is sourced below to the vendor's own words where the vendor has
             # them, and SAYS SO WHERE IT DOES NOT.
             #
             # MEASURED BEFORE WRITING THEM, by building this table over this domain's six
             # controls and reading `FindingsTable.headers`: SIXTEEN of the 35 headings read as
             # Django field names and ALL SIXTEEN were this domain's. That is the same count the
             # `file-data-filtering` run recorded as left for `url-filtering` and `decryption`,
             # reached by a different route. The `decryption` share is NOT touched here - it is
             # not this run's to name and those headings stay raw until that domain's stage 9.
             #
             # THESE COLUMNS APPEAR ON EVERY KIND'S ROW, so labelling them improves other
             # domains' rows too: before this change a vulnerability-protection row showed a
             # customer `credential_detection_mode`, and a file-blocking row showed
             # `all_hostile_categories_blocked`. `setting_columns` is derived from the clauses of
             # whatever controls are seeded, so which of these columns a given build draws
             # depends on the catalogue - but when one is drawn it is drawn for every row.
             #
             # THE HEADINGS ARE THE SAME WORDS THE `url-filtering` EXPLORER PAGE USES, character
             # for character, so one column does not read two ways on two surfaces.
             #
             # WHAT THE VENDOR CALLS THESE THINGS, measured across THREE Help versions rather
             # than assumed. Web Interface Help 11.2 p.296-299 (Objects > Security Profiles >
             # URL Filtering) gives `Category`, `Site Access`, `User Credential Submission` and
             # `Log container page only` verbatim. BUT `probe.corpus --all` returns NOTHING for
             # `Inline Categorization`, `User Credential Detection` or `HTTP Header Logging` in
             # help 11.1, 11.2 OR 12.2 - a complete count, so that is silence worth citing: the
             # Web Interface Help has no label for those three screens at all. The URL Filtering
             # admin guide p.59 and p.61 do, and four headings below are sourced to it alone.
             # ----------------------------------------------------------------------------------
             #
             # PAN-URL-001. OURS, and deliberately NOT "Dangerous categories blocked": the
             # vendor's p.297 instruction is "Block all known dangerous URL categories" over a
             # list of ELEVEN, while this column is over the THREE the model calls confirmed
             # hostile (`HOSTILE_URL_CATEGORIES`), so the vendor's phrase would overstate the
             # question by eight categories. Built from the vendor's own three category NAMES
             # instead, which is the one wording that cannot be read too widely.
             "all_hostile_categories_blocked":
                 "Malware, phishing and command-and-control blocked",
             # "Site Access" is the vendor's own column name, p.297. "Weakest" is ours and is the
             # convention `file-blocking` set above: a profile that blocks two of the three and
             # shows a warning page on the third is not protected by the two.
             "weakest_hostile_category_action": "Weakest Site Access on those categories",
             #
             # PAN-URL-002. OURS - the vendor has the verb and not a label, p.297 verbatim:
             # "allow—...Because allow doesn't log unblocked traffic, set alert as the Action for
             # categories of traffic you don't block if you want to log the access attempts".
             # "Reachable" is ours and names the denominator: a category the profile blocks
             # outright is not reachable, and one at the inert action matches nothing.
             "all_reachable_categories_logged": "Every reachable category logged",
             "worst_reachable_unlogged_category": "Worst unlogged category",
             #
             # A COMPANION COLUMN, headed as the QUESTION IT ANSWERS and not as a setting: a `No`
             # here means this assessment never established the category population, NOT that the
             # device is set a particular way. Phrased as a question for the reason
             # `device-id-iot` gave - a reader should meet "was this established?" before "what
             # did it establish?".
             #
             # AND ON THIS TAB IT IS DRAWN AFTER THE VERDICT IT QUALIFIES, WHICH IS THE WRONG WAY
             # ROUND AND IS NOT FIXABLE FROM A SHEET. Measured off `FindingsTable.headers`: the
             # order is `all_reachable_categories_logged`, `worst_reachable_unlogged_category`,
             # then this - because `tested_fields` sorts the non-baseline queries ALPHABETICALLY
             # BY QUERY NAME and "The category population behind this verdict was never
             # established" sorts last. It matters here in a way it did not for
             # `reference_reach_resolved` above, which got the lucky order: both
             # `worst_reachable_unlogged_category` and `worst_credential_permissive_category` are
             # NULL FOR TWO UNRELATED REASONS - the catalogue was never read, or the failing set
             # is empty and the profile passes - so a reader meeting the verdict cell first sees
             # the reassuring answer before the caveat that invalidates it. On a real estate that
             # is every row, because stage 5 records that the operational catalogue read is
             # issued by no collector. `auto_setting_columns` is all-or-nothing and renaming a
             # shipped calibration query is stage 8's, so this is RECORDED rather than fixed; the
             # `url-filtering` explorer page, whose column order this module does control, draws
             # it BEFORE the pair instead.
             "category_catalogue_collected": "Category list read from the device?",
             #
             # PAN-URL-003. THE VENDOR'S OWN LABEL, exactly: the drop-down is called "User
             # Credential Detection" (URL Filtering admin guide p.61 and p.132). The Web
             # Interface Help is silent on it in all three versions, so this one is sourced to the
             # admin guide alone.
             #
             # THE CELL STILL SHOWS THE DEVICE'S OWN KEY - `ip-user`, not "Use IP User Mapping" -
             # and that is a REFUSAL rather than an omission. The field has no `choices`, so
             # `display_value` prints the stored string, and the only way to change it is a
             # `value_readers` entry. This column is a MEASURED PAYLOAD KEY carrying a
             # `FieldProvenance` row, and a reader makes `build_rows` hand `stored=False` to
             # `remediation_accessor`, which then never reads that row - so whether the
             # credential-enforcement node was ABSENT or explicitly `disabled` would stop being
             # visible, and that distinction is exactly what PAN-URL-003 is about (`disabled` is
             # the measured absent value AND the firing side, per the model's own comment). The
             # explorer page carries the vendor's sentence instead, where the cell is that
             # module's own lambda and costs no provenance.
             "credential_detection_mode": "User Credential Detection",
             # "User Credential Submission" is the vendor's column, p.298. "Restricted" is ours
             # and is deliberately weaker than "blocked": this column is satisfied by `block` OR
             # by the category being unreachable, which is not the claim the next one makes.
             "all_reachable_categories_credential_restricted":
                 "Every reachable category restricts credential submission",
             "credential_submission_blocked_for_every_category":
                 "Credential submission blocked on every category",
             "worst_credential_permissive_category": "Worst category accepting credentials",
             #
             # PAN-URL-004. "HTTP Header Logging" is the vendor's own label (admin guide p.59,
             # "Enabling HTTP Header Logging provides visibility into the attributes in the HTTP
             # request sent to a server"), and the three header names are the vendor's:
             # X-Forwarded-For, User-Agent, Referer. "All three" is ours and is a fact about the
             # device - the object offers these three and no more on all four lab appliances.
             "records_all_request_headers": "All three HTTP headers logged",
             "worst_unrecorded_request_header": "Worst HTTP header not logged",
             #
             # PAN-URL-005. THE VENDOR'S OWN LABELS, admin guide p.59, minus its "Enable "
             # prefix, which names the checkbox rather than the state: "Enable cloud Inline
             # Categorization" and "Enable local Inline Categorization". The screen they sit on
             # the vendor calls "Advanced URL Inline Categorization".
             "cloud_inline_categorization": "Cloud Inline Categorization",
             # THE HEADING DROPS THE `_on` SUFFIX because the suffix distinguishes this derived
             # boolean from the nullable measured key `local_inline_categorization`, which no
             # shipped query clauses on and which therefore draws no column here. If that key
             # ever gains a clause the two would collide under one heading, and the
             # duplicate-header guard would not fire because it compares HEADINGS and these two
             # would then be equal - so the day that happens, one of them needs a different word.
             "local_inline_categorization_on": "Local Inline Categorization",
             # "URL exceptions" is the vendor's noun, admin guide p.59: "Use the Advanced URL
             # Inline Categorization to enable and configure real-time web page analysis and
             # manage URL exceptions." "Broadest" is ours and ranks the two stored category types.
             "inline_analysis_exemption_count": "URL exceptions",
             "broadest_inline_analysis_exemption_type": "Broadest URL exception",
             # THE SECOND COMPANION COLUMN, and it has the same order problem: "The exemption list
             # behind this verdict was never read" sorts after the two it qualifies.
             "inline_analysis_exemptions_computed": "Exception list read from the device?",
             #
             # ----------------------------------------------------------------------------------
             # TWENTY-ONE MORE, 2026-11-02 by stage 9 of `decryption-profiles`, for PAN-DCP-001 to
             # -005 and -007. EVERY ONE IS A PROPOSAL - Jason takes the heading pass once across
             # many domains (P399) - and each is sourced below to the vendor's own words where the
             # vendor has them, and SAYS SO WHERE IT DOES NOT.
             #
             # MEASURED BEFORE WRITING THEM, by building this table over this domain's seven
             # controls and reading `FindingsTable.headers`: TWENTY-ONE of the 41 headings read as
             # Django field names and ALL TWENTY-ONE were this domain's. That is the block the
             # `file-data-filtering` and `url-filtering` runs each recorded as left for
             # `decryption`, reached by a third route. STATE THE SEEDED LIST BESIDE THE NUMBER:
             # 21 of 41 is over PAN-DCP-001..007 alone. `setting_columns` derives a column per
             # clause field of the controls PRESENT in the build, so that denominator is a
             # function of the seed and is NOT comparable with the 16 of 35 `url-filtering`
             # measured or the 44 of 65 before it. All three are right.
             #
             # `kind` AND `is_predefined` ARE NOT IN THIS BLOCK and neither is an omission. `kind`
             # is the `KIND` subject column, which declares `field="kind"` and therefore takes the
             # mark instead of a derived column being drawn; `is_predefined` is already headed
             # `Vendor-shipped` above, set by `file-data-filtering` and shared with PAN-AVW-006.
             #
             # THESE COLUMNS APPEAR ON EVERY KIND'S ROW, so labelling them improves other domains'
             # rows too: before this change an antivirus row showed a customer
             # `fwd_block_expired_certificate`, and a url-filtering row showed `ssl_min_version`.
             # Six of them now also print an EM DASH on a non-decryption row rather than the
             # measured implicit of a key that kind has no container for - see the six readers
             # above.
             #
             # AND LABELLING THEM DOES NOT MAKE THIS TAB CLEAN. Measured AFTER the labels landed,
             # which is the order the `url-filtering` run established: `render_node` consults
             # `setting_labels` NOWHERE, so every stated condition still reads in Django field
             # names. On this tab the workbook does not draw `Fires when` at all - `tested_columns`
             # is the default `('Provenance',)` here - while the live findings page passes
             # `ALL_TESTED_COLUMNS` and shows it, so the same value is named two ways on one row
             # of one surface and one way on the other. That is P437 and P427, both shared
             # machinery, and both are recorded in this run's stage 9 artifact rather than worked
             # around here.
             #
             # WHAT THE VENDOR CALLS THESE THINGS, PAN-OS Web Interface Help 11.2 p.339-346, the
             # section `Settings to Control Decrypted Traffic` under `Objects > Decryption
             # Profile`. Eleven of the twenty-one are the vendor's own label verbatim; the other
             # ten are ours and each says so.
             #
             # THE TAB-NAME PREFIX ON TWELVE OF THEM IS REQUIRED AND NOT DECORATION. The vendor
             # uses the SAME label on its two tabs - "Block sessions with unsupported versions"
             # heads a forward-proxy row on p.341 and an inbound-inspection row on p.343, and so
             # do four others - so five bare vendor labels would produce five DUPLICATE HEADINGS.
             # A table with a duplicate header is rejected by Excel and xlsxwriter drops it with a
             # warning, leaving a sheet of stray cells where the table should be, which this
             # module's `NAME` comment records having happened on this very tab on 2026-09-18.
             # `SSL Forward Proxy` and `SSL Inbound Inspection` are the vendor's own tab names
             # (p.339, p.343), shortened to the words that disambiguate.
             # ----------------------------------------------------------------------------------
             #
             # PAN-DCP-001. OURS, no vendor label: the vendor has the REMEDY and not a name for
             # this verdict. Its p.341 and p.344 sentences are "create a separate Decryption
             # profile that allows the weaker protocol and specify it in a Decryption policy rule
             # that applies only to the sites for which you must allow the weaker protocol", and
             # this column is the detection of that remedy's ABSENCE. Phrased in the negative
             # because that is the direction the column is stored in and the direction that fires:
             # `Yes` means no rule narrows it, which is when the control applies.
             "rule_destination_unrestricted": "No decryption rule narrows its destination",
             # "Min Version" is the vendor's own label (p.344) and "TLSv1.2" its own spelling
             # (p.341, "set the minimum Protocol Version to TLSv1.2"). "below" is ours.
             "ssl_min_version_below_tls12": "Min Version below TLSv1.2",
             # "Max Version" is the vendor's label (p.345) and the comparison is its own sentence:
             # "Set the Max Version to Max so that as protocols improve, the firewall
             # automatically supports them." "caps below what the appliance supports" is ours, and
             # names the APPLIANCE rather than the profile deliberately - the verdict is computed
             # against what that build implements, not against a fixed newest version.
             "ssl_max_version_restrictive": "Max Version caps below what the appliance supports",
             # THE VENDOR'S OWN LABELS, exactly, from the SSL PROTOCOL SETTINGS tab, p.344-345.
             # THE CELL STILL SHOWS THE DEVICE'S OWN TOKEN - `tls1-0`, not "TLSv1.0" - and that is
             # a REFUSAL rather than an omission, the same shape as `credential_detection_mode`
             # above. Both are MEASURED PAYLOAD KEYS carrying a `FieldProvenance` row, and a
             # `value_readers` entry makes `build_rows` hand the field `stored=False` to
             # `remediation_accessor`, which then never reads that row - so whether the floor was
             # ABSENT (provenance `pan_os_default`, the measured implicit `tls1-0`) or TYPED
             # locally as `tls1-0` would stop being visible, and that distinction is most of what
             # PAN-DCP-001 is about. The `decryption-profile` explorer page carries the vendor's
             # spelling instead, where the cell is that module's own lambda and costs no
             # provenance.
             "ssl_min_version": "Min Version",
             "ssl_max_version": "Max Version",
             #
             # PAN-DCP-002. BOTH OURS. The vendor names the ALGORITHMS and not the verdict:
             # p.345 "Don't support the weak 3DES or RC4 encryption algorithms", p.346 "Block the
             # old, weak MD5 algorithm (blocked by default). If no necessary sites use SHA1, block
             # SHA1." The cell carries those names, upper-cased, so the heading carries the
             # question. "Weakest" is the convention `file-blocking` set: a profile that disables
             # three of four broken primitives is not protected by the three.
             "weakest_broken_primitive_permitted": "Weakest broken algorithm still negotiable",
             # "forward secrecy" is the vendor's own term, p.345 verbatim: "The DHE
             # (Diffie-Hellman) and ECDHE (elliptic curve Diffie-Hellman) enable Perfect Forward
             # Secrecy (PFS)". "authenticated encryption" is OURS and is the second half the
             # column covers - the two CBC members are not a forward-secrecy question at all - so
             # the heading names both rather than letting the PFS half stand for the whole.
             "weakest_non_pfs_or_unauthenticated_permitted":
                 "Weakest algorithm lacking forward secrecy or authenticated encryption",
             #
             # PAN-DCP-003 and PAN-DCP-004. THE VENDOR'S OWN LABELS, exactly, p.340. These two
             # keys exist on the forward container ONLY - an inbound-proxy session presents the
             # organisation's own certificate and there is no issuer to distrust - so there is no
             # inbound twin to collide with, and the prefix is kept anyway so that all twelve
             # block switches read the same way down the row.
             "fwd_block_expired_certificate":
                 "Forward proxy: Block sessions with expired certificates",
             "fwd_block_untrusted_issuer":
                 "Forward proxy: Block sessions with untrusted issuers",
             #
             # PAN-DCP-005, all ten. EVERY LABEL BELOW IS THE VENDOR'S OWN, exactly: the forward
             # five from p.341-342 (`Unsupported Mode Checks` and `Failure Checks` on the SSL
             # FORWARD PROXY tab) and the inbound five from p.343-344 (the same two groups on the
             # SSL INBOUND INSPECTION tab). The five pairs are what makes the prefix load-bearing.
             "fwd_block_unsupported_version":
                 "Forward proxy: Block sessions with unsupported versions",
             "fwd_block_unsupported_cipher":
                 "Forward proxy: Block sessions with unsupported cipher suites",
             "inb_block_unsupported_version":
                 "Inbound inspection: Block sessions with unsupported versions",
             "inb_block_unsupported_cipher":
                 "Inbound inspection: Block sessions with unsupported cipher suites",
             "fwd_block_if_hsm_unavailable":
                 "Forward proxy: Block sessions if HSM not available",
             "inb_block_if_hsm_unavailable":
                 "Inbound inspection: Block sessions if HSM not available",
             "fwd_block_if_no_resource":
                 "Forward proxy: Block sessions if resources not available",
             "inb_block_if_no_resource":
                 "Inbound inspection: Block sessions if resources not available",
             # "Block downgrade on no resources" is the vendor's label verbatim, p.342 and p.344.
             # NOTE FOR WHOEVER READS A FINDING ON THIS ONE: stage 2 recorded a vendor
             # contradiction about its polarity - the field table says setting it terminates the
             # session instead of downgrading, while the device's own completion help-string says
             # the opposite - and the control asserts the FIELD TABLE's reading. The heading is the
             # field table's label, so the heading and the assertion agree; the sighting is in
             # `reference/known-vendor-contradictions.md` and in stage 8's `needs_human`.
             "fwd_block_tls13_downgrade_no_resource":
                 "Forward proxy: Block downgrade on no resources",
             "inb_block_tls13_downgrade_no_resource":
                 "Inbound inspection: Block downgrade on no resources",
             #
             # PAN-DCP-007. THE COMPANION COLUMN, headed as the QUESTION IT ANSWERS and not as a
             # setting - the convention `url-filtering` and `device-id-iot` set, because a `No`
             # here means this assessment never reached the decryption rulebase and NOT that the
             # device is set a particular way. It is stage 5's clause order and it is the RIGHT
             # way round on this tab: it is drawn BEFORE the verdict it qualifies, because it is a
             # baseline clause of PAN-DCP-007 rather than a calibration query sorted
             # alphabetically. OURS - the vendor has no notion of "did an audit reach this".
             "decryption_rulebase_collected": "Decryption rulebase read from the device?",
             # OURS, and it is NOT a decryption column: `is_used` sits beside `referrer_count` for
             # every kind of this model and PAN-AVW-006 is a shipped control over exactly it, so
             # the heading must not say "decryption". The model's own words are "Rules and profile
             # groups that name this definition", which is where the wording comes from. NOTE that
             # this column reads `No` wherever the rulebase was not collected as well as where
             # nothing names the profile, which is what the companion above exists to separate.
             "is_used": "Named by a rule or profile group",
         },
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance_group",
                                 "enforcement_point__appliance", "appliance_group"),
         subject_prefetch=("enforcement_point__appliance_group__appliances", "decoders", "ml_models",
                           "application_overrides")),
    # Objects > Custom Objects > URL Category, 2026-11-02, for PAN-URL-006 - a NEW TAB, because
    # `probe.surface_for PAN-URL-006` reported NO SHEET SHOWS IT while the domain's other five
    # controls already reach `Security Profile`. One domain, two tabs.
    #
    # THE ROW IS ONE CUSTOM CATEGORY DEFINITION AT THE SCOPE IT IS DEFINED AT, which is the grain
    # a PAN-URL-006 finding names. Names repeat across scopes - the same name can exist at a vsys,
    # at the firewall's own shared scope and in the pushed view, and the remediation differs by
    # scope - so the scope columns are part of the identity and not decoration.
    #
    # ITS CATEGORY IS DERIVED FROM THE RAIL (`category=''`), which is right for a subject that IS
    # a configuration object: deriving it means the workbook cannot disagree with the app about
    # where the object lives. The rail item is `custom-url-categories`, at Objects > Custom
    # Objects > URL Category.
    #
    # `hidden_fields` IS EMPTY, and there was no reason for a new sheet to declare one: the gate
    # counts a field as presented if `hidden_fields` carries it, so a non-empty tuple is a CLAIM
    # accepted as proof and is the only known cause in this repository of a findings row that
    # marks nothing as the thing to fix (P409).
    #
    # `tested_columns` IS `ALL_TESTED_COLUMNS` AND THAT IS A CHOICE. The default is
    # `('Provenance',)`, which keeps `Fires when` on the live page and silently DROPS it from the
    # xlsx, so the two surfaces disagree about which cell a reader meets (P427). Carrying it is
    # safe here in the way it was for `data-filtering-posture` and is not on most tabs: this
    # control's baseline is the clause that fires on every row this tab draws, so the rendered
    # condition is the clause that actually fired. The cost is that the condition prints
    # `is_used eq False` in the field's own name - `render_node` builds its text from the clause's
    # field and consults `setting_labels` NOWHERE - which is recorded in the stage 9 artifact as
    # shared machinery rather than worked around here.
    #
    # EVERY HEADING IS A PROPOSAL (P399), sourced below.
    spec(T.CUSTOM_URL_CATEGORY,
         "The custom URL categories defined on this firewall, and whether anything on it still "
         "names them: a category's stored type, how many entries its list holds, and how many "
         "referring surfaces this assessment read. A category is either a list of SITES or a "
         "conjunction of PREDEFINED CATEGORIES and the same stored key holds both, so the type "
         "is what makes the member list mean anything. AN UNREFERENCED CATEGORY IS A CANDIDATE "
         "FOR REVIEW AND NEVER A REMOVAL INSTRUCTION: the walk reads TWELVE surfaces - a URL "
         "filtering profile's six site-access lists and four credential lists, its inline "
         "analysis exemptions, and a security rule's category match - while the vendor documents "
         "FOUR rulebases that can match on a URL category and this project's normalizer collects "
         "TWO of them. So every error this reports is in the direction of calling a LIVE category "
         "unreferenced, and the count of surfaces searched is presented beside the verdict so "
         "that `unreferenced` is never printed without its denominator.",
         title="Custom URL Category",
         subject=VSYS_SCOPED + NAME + (
             # THE DENOMINATOR, and stage 5 requires it: it says this column must be "presented
             # beside every finding so that `unreferenced` is never printed without its
             # denominator". No shipped query clauses on it, so `setting_columns` derives no
             # column for it and this is the only thing that puts it on the row.
             #
             # IT NAMES ITS `field`, which matters even though nothing would collide today: a
             # subject column that declares no field does NOT suppress the derived column for the
             # same attribute, so one value would reach the tab twice under two headings - and
             # because the headings differ the duplicate-header guard would never fire.
             #
             # OURS, no vendor word: the vendor has no notion of "how far did an audit look".
             ("Referring surfaces searched", 26, True,
              lambda c, _p: len(c.reference_surfaces_searched or []),
              "reference_surfaces_searched"),
             # "Sites" IS THE VENDOR'S LABEL AND IS DELIBERATELY NOT USED, which is the one
             # judgement on this tab worth arguing. Web Interface Help 11.2 p.271 heads the
             # member list "Sites" - "Manage sites for the custom URL category" - but p.270 says
             # a `Category Match` entry's list holds "the specified URL categories" and not
             # sites, and the model's own comment says the same key holds two incompatible kinds
             # of thing with only `category_type` to say which. So the vendor's own word is
             # correct for one of the two types and wrong for the other, and "Members" is ours
             # precisely because it is true of both.
             ("Members", 12, False,
              lambda c, _p: (c.match_entry_count if c.match_entry_count_computed else NONE),
              "match_entry_count"),
             # THE COMPANION TO THE COUNT, and it earns its place because the count is NULLABLE
             # for exactly this reason: `match_entry_count` is null when the list was never read,
             # which is a different thing from a category that matches nothing. Drawn
             # IMMEDIATELY AFTER the count it qualifies - this module controls the order of its
             # own subject columns, unlike the derived settings columns further along the row.
             ("Member list read?", 18, False,
              lambda c, _p: ("Yes" if c.match_entry_count_computed else "No"),
              "match_entry_count_computed"),),
         setting_labels={
             # PAN-URL-006's BASELINE. OURS - the vendor has no word for this at all: it is a
             # fact about what else on the firewall names the object, not a setting on the
             # object, and `probe.corpus --all` offers nothing at this position. "Anything this
             # assessment read" and not "anything": the walk reads TWELVE surfaces while the
             # vendor documents FOUR rulebases that can match on a URL category and this project's
             # normalizer collects TWO, so the heading must not promise the whole firewall when
             # the `Referring surfaces searched` column beside it says twelve.
             "is_used": "Named by anything this assessment read",
             # THE VENDOR'S OWN LABEL, exactly: Web Interface Help 11.2 p.270 heads this leaf
             # "Type" and names its two values "Category Match" and "URL List", which are the
             # strings the store holds - so the cell needs no reader and the heading needs no
             # gloss. Kept as the bare vendor word rather than expanded to "Category type",
             # because this tab's subject IS a category and the longer form says it twice.
             "category_type": "Type",
         },
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance_group",
                                 "enforcement_point__appliance", "appliance_group"),
         subject_prefetch=("enforcement_point__appliance_group__appliances",),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    # Objects > Security Profiles > Data Filtering, 2026-11-02, for PAN-FIL-003.
    #
    # THE ROW IS THE ENFORCEMENT POINT AND NOT A PROFILE, and on this tab that is the whole point.
    # The commonest failing state of this domain is a virtual system with NO data-filtering profile
    # at all - three of the four lab appliances hold none at any local scope and
    # `/config/predefined/profiles/data-filtering` is absent on every one of them, so unlike file
    # blocking there is nothing shipped to fall back on. A profile-keyed row reports nothing on
    # exactly the devices that fail, which is the silence this tab replaces. Its sibling assertions,
    # about a profile that exists and is wrong, are on the Security Profile tab instead: both
    # grains, one domain.
    #
    # CATEGORY DERIVED FROM THE RAIL (`category=''`), which is right because this subject IS on the
    # rail: `data-filtering-posture`, at Objects > Security Profiles > Data Filtering. See that rail
    # item's own block for why a verdict this assessment computes belongs there - the test is
    # whether the SUBJECT has a vendor path, and this one does. Deriving means the workbook cannot
    # disagree with the app about where the subject lives.
    #
    # AN APPLIANCE COLUMN, AND IT IS NOT THE HA MISTAKE IT LOOKS LIKE. The Security Rules and
    # Virtual System Rule Posture tabs both refuse one, because a vsys belongs to an enforcement
    # point which on an HA pair spans both firewalls, so naming one member would assert something
    # false. HERE THE APPLIANCE IS PART OF THE ROW'S IDENTITY: the model's unique constraint is
    # (appliance, enforcement_point) and its `appliance` column records WHICH MEMBER SPOKE - the one
    # whose merged config the point was read from. Stage 5 declares the grain in those terms and
    # says an HA pair yields TWO rows for what an operator calls one estate. THEY ARE NOT
    # DEDUPLICATED HERE and stage 5 is why: it measured `running-sync: not synchronized` on both
    # PA-5220 members, with three collections present on one member's vsys3 and all three absent on
    # the peer's four days after the commit. Collapsing the pair would pick one of two genuinely
    # different configurations and report it as the estate.
    #
    # `hidden_fields` IS EMPTY AND STAYS EMPTY. The gate counts a field as presented if a subject
    # column, a settings column OR `hidden_fields` carries it, so a non-empty tuple is a CLAIM
    # accepted as proof, and it is the only known cause in this repository of a findings row that
    # marks nothing as the thing to fix (P409). This control's one tested field has a real column.
    #
    # `tested_columns=ALL_TESTED_COLUMNS` IS A CHOICE and the default would have been wrong: the
    # default `("Provenance",)` silently drops `Fires when` from the WORKBOOK while the live page
    # keeps it, so the two surfaces disagree about which cell a reader meets (P427). It is safe
    # here in a way it is not on most tabs: PAN-FIL-003 ships ONE query, the baseline, so the
    # rendered condition is the clause that actually fired and cannot contradict the row.
    #
    # NO SOURCE COLUMNS AND THE PROVENANCE CELL IS ANSWERED HERE, the same as Virtual System Rule
    # Posture and for the same measured reason. Every column of `DataFilteringPosture` is in its
    # `DERIVED_FIELDS` and the model's own docstring says no `FieldProvenance` row is ever written
    # for it, so the default Template column would be blank on every row of every estate - and the
    # default Provenance cell resolves through `remediation_accessor`, which discards a DERIVED row
    # on purpose and falls back to the object's `__entry__` row, which nothing writes. It then says
    # "Not recorded", which means "nothing tracks this field" and reads to a customer as a gap in
    # the collection. The value is not untracked; it is derived.
    spec(T.DATA_FILTERING_POSTURE,
         "Whether each virtual system's outbound traffic is watched for its own regulated data - "
         "credit card numbers, national insurance numbers, documents marked confidential. A "
         "finding here is about a virtual system where nothing is looking, or where something is "
         "looking at a pattern that matches nothing, so it names the virtual system rather than a "
         "profile. What it does NOT say is that sensitive data cannot leave: the mechanism reads a "
         "fixed set of document formats, and it cannot see that a rule supplying its only "
         "attachment sits behind a standing deny.",
         title="Data Filtering Posture",
         subject=DATA_FILTERING_POSTURE_SUBJECT,
         setting_labels=DATA_FILTERING_POSTURE_LABELS,
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         source_columns=(),
         provenance_cell=lambda posture, provenance_of, fields: (
             findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label),
         appliance_of=lambda posture: posture.appliance,
         subject_select_related=("appliance__appliance_group", "enforcement_point")),
    # Objects > Applications, 2026-11-02, for PAN-SAS-001. Category DERIVED from the rail, whose
    # item is `sanctioned-applications`. See the SaaS block above for the reasoning shared by all
    # four of these tabs.
    spec(T.SANCTIONED_APPLICATION_MARKING,
         "Whether each virtual system records which applications the business has approved, in "
         "the one mechanism the firewall itself reads - the predefined `sanctioned` tag on an "
         "application object. A finding names the VIRTUAL SYSTEM and not an application, because "
         "the commonest failing state is that no approval marking exists in the partition at "
         "all, and a row that is one application cannot report an inventory with nothing in it. "
         "WHAT A ROW HERE CANNOT SAY: whether the marked set is the RIGHT set. The firewall holds "
         "no record of what the business approved - the marking IS that record - so no column "
         "compares one against the other, and a partition that marks one wrong application reads "
         "the same as one that marks the right ten. THE SCREEN ALSO LIES IN THIS DOMAIN'S "
         "DIRECTION: the Objects > Applications grid renders the vendor's predefined "
         "CHARACTERISTIC tags and an operator's approval markings in the same chips, so a "
         "reviewer reading 'the Tags column is populated' as 'applications are tagged' reports a "
         "marked inventory on an estate that has marked nothing.",
         title="Sanctioned Applications",
         subject=SANCTIONED_APPLICATION_MARKING_SUBJECT,
         setting_labels=SANCTIONED_APPLICATION_MARKING_LABELS,
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         source_columns=(),
         provenance_cell=_saas_derived_cell,
         appliance_of=lambda marking: None,
         subject_select_related=_SAAS_VSYS_SELECT_RELATED,
         subject_prefetch=_SAAS_VSYS_PREFETCH),
    # Objects > Security Profiles > URL Filtering, 2026-11-02, for PAN-SAS-002 AND PAN-SAS-004 -
    # two controls on one tab, because the finding registry is keyed by model. Category DERIVED
    # from the rail, whose item is `saas-url-filtering`.
    spec(T.SAAS_URL_FILTERING_POSTURE,
         "What each virtual system's URL Filtering does for SaaS: whether anything inserts a "
         "tenant-restriction header into the traffic a rule of that partition actually carries, "
         "and how that partition treats the web categories that carry consumer file storage and "
         "personal publishing. A finding names the VIRTUAL SYSTEM because the commonest failing "
         "state is that NO profile reachable from the partition carries either, and because the "
         "profile object itself is another domain's subject. READ THE `Profiles read` COLUMN "
         "FIRST: both verdicts are false when the answer is no AND when nobody looked, and that "
         "column is the only thing on the row that tells those apart. WHAT A ROW HERE CANNOT "
         "SAY: whether the organisation's own approved applications are CARVED OUT of a "
         "restricted category. No object on the firewall expresses that exception, so the "
         "restriction half is all this tab reports and a partition that blocks a category "
         "wholesale reads the same as one that blocks it with the right exemptions.",
         title="SaaS URL Filtering Posture",
         subject=SAAS_URL_FILTERING_POSTURE_SUBJECT,
         setting_labels=SAAS_URL_FILTERING_POSTURE_LABELS,
         hidden_fields=(),
         # THE FULL SET, AND THIS IS THE TAB WHERE IT COSTS SOMETHING. `fires_when` renders the
         # BASELINE's clause alone and this tab carries two controls, so a PAN-SAS-002 row states
         # `tenant_restriction_in_force = No` and a PAN-SAS-004 row states
         # `consumer_storage_categories_are_restricted = No`, each correct for its own control.
         # What it CANNOT state is the calibration that moved a severity: the one row the
         # "Permitted and recorded rather than restricted" query lowered to `low` prints the
         # baseline's condition beside a `Site Access` cell reading `alert`, and Matched queries
         # and Severity basis are what resolve it between them.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         source_columns=(),
         provenance_cell=_saas_derived_cell,
         appliance_of=lambda posture: None,
         subject_select_related=_SAAS_VSYS_SELECT_RELATED,
         subject_prefetch=_SAAS_VSYS_PREFETCH),
    # Policies > Security, 2026-11-02, for PAN-SAS-003. Category DERIVED from the rail, whose item
    # is `saas-application-policy` - the FOURTH item at that one vendor address, after `security`,
    # `rule-posture` and `rulebase-device-match`.
    spec(T.SAAS_APPLICATION_POLICY_POSTURE,
         "Whether each virtual system's security policy refuses the UPLOAD and SHARING functions "
         "of the applications it permits - the function child App-IDs, which a rule permitting "
         "the parent application allows by default - and whether it carries an attribute-driven "
         "selection of unapproved cloud applications that policy refuses. A finding names the "
         "VIRTUAL SYSTEM because both assertions turn on the ABSENCE of a rule: the remediation "
         "is a rule that does not exist yet. ONLY THE FIRST HALF IS GRADED. The three "
         "cloud-application columns are shown and no control asserts on them - the control that "
         "should cannot be created, because its assertion is over this model while the control "
         "targets another, so a customer whose cloud-application selection is unrefused is told "
         "nothing about it. WHAT A ROW HERE CANNOT SAY: which of the three rulebases an absence "
         "spans. The verdict is a first-match walk across pushed pre-rules, the firewall's own "
         "rules and pushed post-rules, and the model stores no scope column.",
         title="SaaS Application Policy",
         subject=SAAS_APPLICATION_POLICY_POSTURE_SUBJECT,
         setting_labels=SAAS_APPLICATION_POLICY_POSTURE_LABELS,
         hidden_fields=(),
         # Safe here in a way it is not on the URL filtering tab: PAN-SAS-003 ships ONE query, the
         # baseline, so the rendered condition is the clause that actually fired.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         source_columns=(),
         provenance_cell=_saas_derived_cell,
         appliance_of=lambda posture: None,
         subject_select_related=_SAAS_VSYS_SELECT_RELATED,
         subject_prefetch=_SAAS_VSYS_PREFETCH),
    # Device > Setup > ACE, 2026-11-02, for PAN-SAS-005. Category DERIVED from the rail, whose
    # item is `ace`. THE APPLIANCE-SCOPED DEFAULTS ARE RIGHT HERE and the three tabs above
    # override them: this model declares `unique(appliance)`, so the row IS one firewall and
    # `s.appliance` resolves.
    spec(T.CLOUD_APP_ENGINE_SETTING,
         "Whether each firewall's App-ID Cloud Engine is switched off in configuration, and "
         "whether the engine is actually running. These are TWO DIFFERENT FINDINGS FROM ONE "
         "NODE and on the lab estate they point opposite ways: the configuration says the engine "
         "is not disabled and the engine reports that it is not working. A finding names the "
         "APPLIANCE because `deviceconfig/setting/cloudapp` is a device-wide singleton with no "
         "entry name and no vsys. WHY THIS TAB COMES FIRST AMONG THE SaaS FINDINGS IN GENERATOR "
         "ORDER: the engine's state is the PREMISE the other three rest on. Rules and filters "
         "naming cloud-delivered App-IDs stay visible in the policy while they stop enforcing, "
         "so a reader meets 'the engine is not working' before any finding that assumes it is. "
         "WHAT A ROW HERE CANNOT SAY: an appliance with no SaaS Security Inline subscription is "
         "EXCLUDED rather than reported, because it is not misconfigured - so an EMPTY TAB can "
         "mean an unlicensed estate and not a healthy one, which is the state of the measured "
         "lab.",
         title="App-ID Cloud Engine",
         subject=CLOUD_APP_ENGINE_SETTING_SUBJECT,
         setting_labels=CLOUD_APP_ENGINE_SETTING_LABELS,
         hidden_fields=(),
         # PAN-SAS-005 ships ONE query, so the rendered condition is the clause that fired.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         source_columns=(),
         # Settled by building the row and reading the cell - see the SaaS block above. The
         # default printed "Not recorded" for both tested columns on every row.
         provenance_cell=_saas_derived_cell),
    # Network > Network Profiles > Zone Protection, 2026-11-02, for PAN-ZON-002 to -006.
    #
    # CATEGORY DERIVED FROM THE RAIL (`category=''`), which is right for a subject that IS a
    # configuration object: deriving it means the workbook cannot disagree with the app about
    # where the object lives. The rail item is `zone-protection`.
    #
    # `hidden_fields` IS EMPTY AND STAYS EMPTY. The gate counts a field as presented if a subject
    # column, a settings column OR `hidden_fields` carries it - so a non-empty tuple is a CLAIM
    # accepted as proof, and it is the only known cause of a findings row that marks nothing as
    # the thing to fix (P409). Every tested field of all five controls here is presented by a
    # real column, so there is nothing to declare.
    #
    # `tested_columns=ALL_TESTED_COLUMNS` IS A CHOICE and the default would have been wrong: the
    # default `("Provenance",)` silently drops `Fires when` from the WORKBOOK while the live page
    # keeps it, so the two surfaces disagree about which cell a reader meets (P427). It is taken
    # knowing that `fires_when` renders the BASELINE's condition alone, so on a row whose
    # severity was moved by a calibration the stated condition is not the clause that moved it -
    # the alternative is a contradicting value with no stated condition beside it at all.
    spec(T.ZONE_PROTECTION_PROFILE,
         "The zone protection profiles on each firewall, and what each one actually stops. A "
         "profile is a reusable PROPOSAL: it enforces nothing until a zone names it, which is "
         "what the In force column says and what the two columns beside it are the evidence "
         "for. ONE PROFILE CAN BE IN FORCE ON MANY ZONES OF MIXED EXPOSURE, and the vendor asks "
         "for some of these settings on internal zones only - so where a profile is attached to "
         "several zones the remediation may be to SPLIT the profile rather than to change it, "
         "and no column here can say which of its zones are internal. A PROFILE SATISFYING "
         "EVERY CONTROL CAN STILL BE INERT: the firewall disables SYN cookies on an external "
         "zone, and the profile holds no record of which zone type it is attached to.",
         title="Zone Protection", subject=ZONE_PROTECTION_PROFILE_SUBJECT,
         setting_labels=ZONE_PROTECTION_PROFILE_SETTING_LABELS,
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    # Policies > DoS Protection, 2026-11-02, for PAN-ZON-007. Category DERIVED from the rail,
    # whose item is `dos-protection-rules`, on the same reasoning as the tab above.
    #
    # `appliance_of` RETURNS None: the rule belongs to a virtual system, which on an HA pair
    # spans both firewalls, so linking the row to one member of the pair would assert something
    # false. Same ruling as the security rules and security profile tabs.
    #
    # THE PUSHED RULEBASES ARE UNEXERCISED and this tab is where that will show. Stage 7 measured
    # the pushed DoS rulebase as EMPTY on every appliance in the estate, so the `pushed_pre` and
    # `pushed_post` config sources are part of a rule's identity, are printed in the Rulebase
    # column, and have never carried a row. On a Panorama-managed estate that is where most DoS
    # rules live - and a rule pushed from a device group is the one this control cannot
    # recommend editing locally.
    spec(T.DOS_POLICY_RULE,
         "The DoS protection rules in each virtual system's rulebase, and whether each one "
         "actually protects. Only the `protect` action consults the profile a rule names; a "
         "rule that denies is at least refusing traffic and a rule that allows is doing nothing "
         "at all. EVERY RULE IN THIS ASSESSMENT'S ESTATE IS DISABLED and the control fires "
         "anyway, deliberately: no implicit was measured for the disabled key, and taking an "
         "absence for 'disabled' would silently suppress every rule on an estate. Read the "
         "Disabled column before acting on a row - on a real estate the population is enabled "
         "rules, and the false-finding rate of the disabled ones is unmeasured.",
         title="DoS Protection Rules", subject=DOS_POLICY_RULE_SUBJECT,
         setting_labels=DOS_POLICY_RULE_SETTING_LABELS,
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance",
                                 "enforcement_point__appliance_group"),
         subject_prefetch=("enforcement_point__appliance_group__appliances",)),
    spec(T.ADMIN_USER,
         "The administrator accounts on each firewall: what each may do, and what it authenticates "
         "with.",
         subject=APPLIANCE + NAME,),
    spec(T.SERVER_PROFILE,
         "The identity services the firewall authenticates against - LDAP, RADIUS, TACACS+, "
         "Kerberos and SAML - and how it connects to each.",
         subject=APPLIANCE + SCOPE + KIND + NAME),
    # Device > Dynamic Updates, 2026-11-03, for PAN-UPD-001, -002, -004 and -005 - FOUR controls
    # sharing ONE model and so one tab. Category DERIVED from the rail (`category=''`), whose item
    # is `content-update-schedule`, beside `content-streams` below at the same vendor screen: this
    # tab is the SCHEDULE and that one is what the schedule has already loaded.
    #
    # NINE DERIVED SETTINGS COLUMNS AND NOT ONE `value_reader`, which is a decision rather than an
    # omission, and both halves of the `choices` rule were checked in the model's own `_meta`
    # before anything was written. All nine clause fields are `CharField(blank=True, default="")`
    # with `choices=None`, so `get_<field>_display()` DOES NOT EXIST on any of them and a reader
    # calling it would raise `AttributeError` at TEMPLATE RENDER - past `django check` and past all
    # three cross-domain gates (P462). The cells therefore print the device's own tokens, and
    # `configuration_results._update_token` carries the full reason that is the right answer here
    # rather than a map: the vendor documents no word for ANY recurrence value (a complete count -
    # `probe.corpus --all 'every-30-mins'` matches the CLI command hierarchy alone and 'Every 30
    # Minutes' matches nothing in eleven indexes), and translating the two actions it DOES name
    # would print one value two ways on one row, because `render_node` writes the `Fires when`
    # cell and consults `setting_labels` nowhere. The English goes in the headings below instead.
    #
    # P451 DOES BITE THIS TAB AND THE SHEET-LEVEL `provenance_cell` IS WHAT ANSWERS IT, which was
    # MEASURED on built rows after being reasoned the other way round first - the wrong reasoning
    # is recorded here because it is the plausible one. The caller
    # `normalization/content_updates.py:249` passes `write_node_row` a provenance list naming only
    # `threats_threshold_hours` and `threats_new_app_threshold_hours` - neither a clause field of
    # any of these four controls - and `write_node_row` writes no `__entry__` row. Measured on the
    # seeded estate: all eight `FieldProvenance` rows this model carries belong to those two
    # threshold fields and none to any of the nine clause fields.
    #
    # THE TEMPTING WRONG ANSWER was that nothing is owed, because all nine clause fields ARE
    # declared in `ContentUpdateSchedule.DERIVED_FIELDS` and `build_findings_table`'s
    # `provenance_of` closure SYNTHESISES a `FieldProvenance(DERIVED)` for a declared computed
    # column when no stored row exists. It does - and `remediation_accessor` then DISCARDS that
    # synthesised row on purpose ("DERIVED counts as no answer... it is the case the object has to
    # answer") and falls back to the object's `__entry__` row, which this normaliser never writes.
    # So `resolved` is None with `stored=True` and `provenance_cells` returns "Not recorded", whose
    # own docstring defines it as "nothing tracks that field" - the opposite of true here. Measured
    # before this line was added: every row's Provenance cell read "Not recorded" once per tested
    # field. The synthesis only reaches the cell for a field that is NOT a stored column, which
    # none of these nine is.
    #
    # SO THIS IS THE DISPROOF CONDITION OF A STANDING NOTE AND IT DOES NOT DISPROVE IT.
    # `reference/consumer-repo-notes.md` asks for "a stored column named in a model's
    # `DERIVED_FIELDS` whose Provenance cell reads `Derived` on a sheet with no `provenance_cell`
    # override and whose normaliser writes no `__entry__` row". All nine fields here are exactly
    # that, and all nine read "Not recorded". The note stands and the stage 9 artifact says so.
    #
    # `hidden_fields=()` ON PURPOSE. The gate counts a field as presented if `hidden_fields`
    # carries it, so a non-empty tuple is a CLAIM accepted as proof and is the only known cause of
    # a findings row that marks nothing as the thing to fix (P409). Every one of the nine is a real
    # column here.
    #
    # `tested_columns` IS THE FULL SET, KNOWING TWO ROWS OF ELEVEN RENDER A WRONG `Fires when`. The
    # default is `("Provenance",)`, which would silently drop `Fires when (failing condition)` from
    # the workbook while the live page kept it, so the two surfaces would disagree about which cell
    # a reader meets (P427). The cost is contract finding 1 and it was measured rather than
    # predicted: `fires_when` renders the BASELINE alone, and on PAN-UPD-001 and PAN-UPD-002 the
    # baseline is the CADENCE half while the ACTION half is carried by calibration queries - so
    # pan-fw-b458, whose antivirus runs `hourly` and only downloads, prints a condition requiring
    # the recurrence NOT to be hourly beside a correctly marked `av_action` cell. Those two rows
    # are the ones whose `Matched queries` names a calibration and NOT the baseline, which is how a
    # reader spots the state. The alternative is the contradicting value with no stated condition
    # beside it at all, which is worse. PAN-UPD-005's rows are NOT affected and that is worth
    # stating because its sign is the inverted one: stage 8 compiled `finding_when_clauses_fail`
    # INTO the baseline as an `or` group of the failing states, so its stated condition IS the
    # firing condition and reads correctly.
    spec(T.CONTENT_UPDATE_SCHEDULE,
         "The schedule on which each firewall retrieves Palo Alto's dynamic content updates, and "
         "whether the scheduled run INSTALLS what it fetches. Five content types on one row - "
         "antivirus, Applications and Threats, WildFire, the GlobalProtect data file and the "
         "clientless VPN content - because the node is one per appliance under "
         "`deviceconfig/system` with no vsys axis, so each content type is a COLUMN and not a row. "
         "A CADENCE FAULT AND AN ACTION FAULT ARE DIFFERENT FINDINGS AT THE SAME SEVERITY: a "
         "schedule that runs hourly and only downloads is a real failing with a faultless cadence, "
         "so read the MARKED CELL rather than the severity to see which half failed. TWO ROWS FOR "
         "AN HA PAIR ARE NOT A DUPLICATE AND NOTHING HERE DEDUPLICATES THEM - the update schedule "
         "does not synchronise across peers and must be configured on both, so two rows are two "
         "independent configurations and a pair showing one row is a pair half covered. "
         "`none` AND `not read` ARE DIFFERENT ANSWERS: the first is an absence the firewall "
         "reported, the second is an absence nobody collected, and the Schedule read column is "
         "what tells them apart. WHAT A ROW HERE CANNOT SAY: whether the schedule has ever RUN, or "
         "how old the content it fetched actually is. This is the configured cause; PAN-PLT-002 on "
         "the Installed Content tab owns the symptom, and both will report on a firewall with no "
         "schedule and stale content.",
         title="Dynamic Update Schedule",
         subject=APPLIANCE + (
             # THE COLUMN THAT SAYS WHETHER ANYBODY LOOKED, and the reason every token cell on the
             # row can be read literally. No clause of any of the four controls carries it, so
             # `tested_fields` derives NO settings column for it - and without this cell the tab
             # cannot tell a configured `none` from an uncollected read, which the model's own
             # comment calls "the only column here a control may rely on to tell 'we never asked'
             # from 'we asked and it was fine'". Stage 5 marks it `presented` and `fires` when
             # unknown. NOTE it reads Yes on all four appliances of the measured estate, so the
             # firing side of this column is UNEXERCISED there and the cell is load-bearing only
             # on an estate where a management-plane read failed.
             #
             # IT DECLARES ITS `field` though nothing derives a column for it today, per the rule
             # that every subject column names one: a control that later clauses on it would
             # otherwise add a SECOND column of the same value under a different heading, and
             # because the two headings differ the duplicate-header guard would not fire.
             ("Schedule read", 14, False,
              lambda s, _p: "Yes" if s.update_schedule_collected else "No",
              "update_schedule_collected"),
         ),
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         # `source_columns=()` - THE TEMPLATE COLUMN IS DROPPED, and this was measured before it
         # was decided. `_default_template_cell` names the pushed template PER TESTED FIELD, and
         # all nine tested fields here are computed from WHICH BRANCH ELEMENT EXISTS rather than
         # read from a key, so none can ever carry TEMPLATE provenance - the model's own comment
         # says they "can never carry a `FieldProvenance` row". Built with the default it was
         # blank on 11 of 11 rows, and a column blank on every row of a report reads as a gap in
         # the collection rather than as a column that does not apply. `content-streams`,
         # `licenses`, `log-alarms`, `ace` and the four SaaS tabs drop it on exactly this
         # argument. If a template-scoped schedule is ever normalised, the thing to restore is
         # the normaliser's provenance list first and this column second.
         source_columns=(),
         # EVERY HEADING HERE IS A PROPOSAL (P399) and the words in them are the vendor's own.
         # `Recurrence` and `Action` are the two field names on the screen that configures this
         # object - Help 11.2 p.950, "the Recurrence and time - and whether to Download Only or to
         # Download and Install scheduled updates" - and the content-type names are that page's
         # own: "new and modified applications, threat protection, device dictionary files for IoT
         # Security, and GlobalProtect data files". A field with no entry here would head a
         # customer-facing column with its raw Django name, which is what this map exists to
         # prevent, so all nine are named and none is left to the fallback.
         setting_labels={
             "av_recurrence": "Antivirus recurrence",
             "av_action": "Antivirus action",
             # THE VENDOR'S OWN NAME FOR THE CONTENT TYPE, "Applications and Threats" on p.950 and
             # not "App and Threat" - that shorter spelling is the PANORAMA schedule dialog's
             # `Type` dropdown (p.1224) and names a Panorama object, not this column.
             "threats_recurrence": "Applications and Threats recurrence",
             "threats_action": "Applications and Threats action",
             # NO ACTION COLUMN BESIDE IT, and the absence is PAN-UPD-004's rather than an
             # oversight: that control clauses on the recurrence alone, so `tested_fields` derives
             # no column for `wildfire_action` and nothing here could label one. The explorer page
             # shows it as an unqueryable reference column; this tab does not show it at all.
             "wildfire_recurrence": "WildFire recurrence",
             "gp_datafile_recurrence": "GlobalProtect data file recurrence",
             "gp_datafile_action": "GlobalProtect data file action",
             # "Clientless VPN" IS OURS AND THE VENDOR HAS NO WORD FOR IT ON THIS SCREEN, which is
             # said rather than implied. Stage 4 measured Device > Dynamic Updates as carrying a
             # group of its own for this content type while the Help's section for that screen
             # never names it - documentation and device disagreeing in that direction, which is
             # the opposite way round from the GlobalProtect data file, whose group the screen does
             # NOT carry and whose name the Help's opening sentence does. The configuration token
             # is `global-protect-clientless-vpn`.
             "gp_clientless_vpn_recurrence": "Clientless VPN recurrence",
             "gp_clientless_vpn_action": "Clientless VPN action",
         },
         # ONE ANSWER FOR THE WHOLE ROW, because every tested field on it is computed from WHICH
         # BRANCH ELEMENT EXISTS and none has a payload key of its own - the model's own comment
         # says they "have no payload key and can never carry a `FieldProvenance` row". The default
         # per-field cell printed "Not recorded" once per tested field, which states that nothing
         # TRACKS the field and is the opposite of what is true: the value is derived, deliberately
         # and by a documented rule. See the paragraph above for why the declaration in
         # `DERIVED_FIELDS` does not reach the cell on its own.
         #
         # WRITTEN INLINE RATHER THAN REUSING `platform_lifecycle.DERIVED_CELL`, which is the same
         # expression: that constant belongs to another pipeline domain's presentation module and
         # this sheet should not acquire a dependency on it for one lambda. If a third sheet wants
         # it, the shared home is `findings.py` and not either domain's module.
         provenance_cell=(
             lambda _subject, _provenance_of, _fields:
             findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label)),
    # Device > Dynamic Updates, 2026-11-02, for PAN-PLT-002. Category DERIVED from the rail
    # (`category=''`), whose item is `content-streams` - right for a subject that IS a thing an
    # assessor opens a vendor screen to read, and deriving it means the workbook cannot disagree
    # with the app about where the subject lives.
    spec(T.FIREWALL_CONTENT_STREAMS,
         "Whether each firewall is running current threat content, stream by stream. A finding "
         "names the APPLIANCE and not a content stream, because `show system info` returns every "
         "stream\'s version in one reply and the device offers no stream entity to key a row on - "
         "so each stream is a COLUMN here and the verdict is over the set. THE VERDICT NAMES THE "
         "WORST STATE IT FINDS AND A NEVER-INSTALLED STREAM IS CLASSIFIED FIRST, which is worth "
         "knowing when a row reads \"A stream was never installed\" and another stream on the same "
         "row is also behind its window: the reason given is the strongest one, not the only one. "
         "WHAT A ROW HERE CANNOT SAY: whether the organisation ever bought the subscription that "
         "delivers a stream. A never-installed WildFire stream on an appliance that holds no "
         "WildFire entitlement reports at the same severity as one on an appliance that does, "
         "because no column of this subject can hold a fact about the licence table - and the "
         "vendor keeps part of a stream flowing at a slower cadence after an entitlement expires, "
         "so a lapsed subscription is deliberately NOT an exemption. Stage 8 raised that as a "
         "question for a person rather than settling it. AND A STREAM WITH NO PUBLICATION DATE "
         "CANNOT BE AGED AT ALL: both PA-5220s in the measured estate report no release date for "
         "any stream, so the staleness arithmetic is not performed on them and the row says so "
         "rather than passing.",
         title="Installed Content",
         subject=CONTENT_STREAMS_SUBJECT,
         setting_labels=platform_lifecycle.CONTENT_STREAMS_LABELS,
         value_readers=platform_lifecycle.CONTENT_STREAMS_READERS,
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         source_columns=(),
         provenance_cell=platform_lifecycle.DERIVED_CELL),
    # Device > Licenses, 2026-11-02, for PAN-PLT-004. Category DERIVED from the rail, whose item is
    # `licenses`.
    spec(T.LICENCE_INVENTORY,
         "Whether each firewall\'s subscriptions and its support entitlement are current. TWO "
         "VERDICTS ON ONE ROW because this is one control stated as two assertion records over two "
         "columns of one model, and they are different consequences rather than two tiers of one: a "
         "lapsed SUBSCRIPTION stops the protection it delivers, and a lapsed SUPPORT entitlement "
         "stops the firewall obtaining software at all, which blocks the remedy for anything else "
         "found here. A finding names the APPLIANCE and not a licence, because the commonest "
         "failing state is an entitlement that is MISSING and a missing entitlement has no licence "
         "row to live on. WHAT A ROW HERE CANNOT SAY: whether the appliance was MEANT to carry its "
         "own support entitlement. Nothing on a firewall says whether it is a production device or "
         "a spare, a lab or an RMA unit that deliberately has none, so an absent support row is "
         "reported at high severity on every appliance - and on the measured estate that is every "
         "appliance, with nobody able to say whether `request license info` lists support "
         "entitlements on these platforms at all. Stage 8 raised that as a question for a person. "
         "AND AN UNREADABLE LICENCE TABLE IS NOT AN EMPTY ONE: `request license info` answers a "
         "present-and-empty element on both PA-5220s, which is the same shape an unlicensed "
         "appliance returns and the same shape a read that never ran would leave, so it is reported "
         "rather than passed.",
         title="Licenses",
         subject=LICENCE_INVENTORY_SUBJECT,
         setting_labels=platform_lifecycle.LICENCE_INVENTORY_LABELS,
         value_readers=platform_lifecycle.LICENCE_INVENTORY_READERS,
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         source_columns=(),
         provenance_cell=platform_lifecycle.DERIVED_CELL),
    # Device > Log Settings, 2026-11-02, for PAN-PLT-006. Category DERIVED from the rail, whose item
    # is `log-alarms` - the second item at that one vendor address is not in play here, because no
    # other rail item claims Device > Log Settings today.
    spec(T.LOG_ALARM_SETTINGS,
         "Whether each firewall would raise an alarm as a log database fills, and whether that "
         "alarm would reach anybody. A finding names the APPLIANCE because the alarm node is a "
         "device-wide singleton with no entry name and no vsys. THE MECHANISM IS GRADED AS ONE "
         "ORDERED VERDICT rather than as a list of switches, because the order matters and is not a "
         "conjunction: an alarm armed with no threshold to fire on is WORSE than one that fires and "
         "reaches nobody, and no combination of the leaf columns beside it expresses that. AN "
         "ABSENT ALARM NODE IS REPORTED AND NOT PASSED, which is the state of three of the four "
         "measured appliances: the configuration read materialises no defaults, the vendor "
         "documents a 90% default on one page and none in that page\'s own field table, and there is "
         "no oracle on the device to settle it - so \"nothing recorded\" means nobody knows, and a "
         "pass would be a customer told they are safe on the strength of nothing. WHAT A CLEAN ROW "
         "HERE DOES NOT COVER: this control\'s other half, sustained dataplane load, is reported "
         "NOWHERE in this report. No configuration node on the firewall holds a dataplane CPU or "
         "session-utilisation threshold and the vendor\'s own monitoring procedure puts the "
         "comparison on an off-box SNMP manager, so stage 5 discharged that half to an engineer\'s "
         "question. AND THE THRESHOLD\'S DENOMINATOR IS NOT SETTLED: the vendor describes the same "
         "percentage as a share of available disk space on one page of this screen\'s section and of "
         "the log database\'s maximum size on the next, which differ by a factor of thirty on one "
         "lab appliance - so a threshold is shown with its log type and no unit claim.",
         title="Alarm Settings",
         subject=LOG_ALARM_SUBJECT,
         setting_labels=platform_lifecycle.LOG_ALARM_LABELS,
         value_readers=platform_lifecycle.LOG_ALARM_READERS,
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         source_columns=(),
         provenance_cell=platform_lifecycle.DERIVED_CELL),
    # Device > High Availability, 2026-11-03, for PAN-HAP-001 to 004. Category DERIVED from the
    # rail (`category=''`), whose item is `high-availability` - right for a subject that IS a
    # vendor screen an assessor opens, and deriving it means the workbook cannot disagree with
    # the app about where the subject lives. APPENDED rather than placed among the Device specs
    # above: order in `SPECS` decides nothing, `DOMAINS` decides the tab order.
    #
    # `subject=APPLIANCE` IS THE WHOLE HA ANSWER AND IT IS ALREADY RIGHT. The pair's two rows are
    # told apart by `HA role`, which `APPLIANCE` carries and which reads Active / Passive off the
    # appliance group. MEASURED on a hand-built pair, 2026-11-03: one `ha_pair` group, one
    # `EnforcementPoint` with a NULL `appliance` and two `EnforcementNode`s gives TWO rows for
    # one real relationship, reading Active and Passive - and those two rows DISAGREE, `ha_mode`
    # being `active-passive` on the active member and `''` on the passive one, which is what
    # stage 4 measured on this estate and what the model's own docstring records. So the pair is
    # NOT deduplicated here, deliberately: collapsing it would be a pair half assessed. The
    # device-wide-settings warning in AGENTS.md:174-183 is about subjects whose peers are
    # expected to AGREE, and stage 5 says in terms that these are not.
    spec(T.HIGH_AVAILABILITY,
         "The redundant relationship each firewall is configured for, and whether it would "
         "actually carry a failover. A finding names the APPLIANCE because "
         "`deviceconfig/high-availability` is device-wide, so an HA pair draws TWO rows and the "
         "`HA role` column is what tells them apart - that is correct and not a duplicate, "
         "because the two members' configurations are NOT expected to agree and this estate "
         "measures the divergence directly. WHAT A ROW HERE CANNOT SAY: whether the pair is "
         "live. Every column is one appliance's, and whether a peer is answering, whether state "
         "is being exchanged and whether the control link is encrypted IN FORCE are properties "
         "of the PAIR that only `show high-availability all` reports - and NO COLLECTOR ISSUES "
         "IT, so `HA configuration collected` reads Yes while the runtime half is missing on "
         "every appliance in every estate today. PAN-HAP-001 therefore fires on every "
         "HA-enabled firewall and PAN-HAP-002 on every one of them too, and both sentences say "
         "the setting was NOT ESTABLISHED rather than that it failed. AND THE DEVICE'S OWN "
         "DEFAULTS READ THE REASSURING WAY ROUND HERE, which is why two switches a reader might "
         "expect are absent from this tab: `show high-availability state` answers link "
         "monitoring and path monitoring `enabled: yes` with `groups: null` on an appliance "
         "holding no monitoring node at all, so the honest column is the one that reports the "
         "GROUPS and the model forbids a clause on either switch.",
         title="High Availability",
         subject=ha_panorama.HIGH_AVAILABILITY_SUBJECT,
         setting_labels=ha_panorama.HIGH_AVAILABILITY_LABELS,
         # EMPTY, not a claim. `check_every_tested_field_is_presented` accepts `hidden_fields` as
         # PROOF that a field is presented, so a non-empty one is a claim rather than a column -
         # and it forfeits the value-at-fault mark, because the two `implicated` loops walk
         # `subject_columns` and the settings columns and never consult it. All seven clause
         # fields get a real derived column here and every row marks a real cell.
         hidden_fields=(),
         # The full set, knowing what it costs (P427): the default `("Provenance",)` drops
         # `Fires when` from the WORKBOOK while the live page keeps it, so the two surfaces would
         # disagree about which cell a reader meets. Taken knowing `fires_when` renders the
         # BASELINE's condition alone, so on a row whose finding came from the not-collected
         # calibration the stated condition is one that row does not meet. The alternative is a
         # contradicting value with no stated condition beside it at all.
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         # BRANCHING, and this is the first branching provenance cell in the repository. Six of
         # the seven clause fields are declared in `DERIVED_FIELDS` and `ha_enabled` is not -
         # it is a real key with a real `FieldProvenance` row - so the shipped constant "Derived"
         # would print a falsehood about it, and the DEFAULT cell prints "Not recorded" on the
         # other six. Both measured on built rows. See the module docstring.
         provenance_cell=ha_panorama.provenance_cell),
    # Device > Setup > Management, the `Panorama Settings` panel, 2026-11-03, for PAN-HAP-005.
    # Category DERIVED from the rail, whose item is `panorama-settings`.
    #
    # ONE CONTROL, TWO ASSERTION RECORDS, ONE ROW. The hardening half is the BASELINE tier at
    # `low` and the redundancy half is a CALIBRATION above it at `medium`, so a row failing both
    # is reported at `medium` and `Matched queries` says which halves fired. Measured on built
    # rows: `fw-core-tpa-a` matches the baseline alone at `low`, `pan-fw-7d6e` and `pan-fw-b458`
    # match both at `medium`.
    #
    # THE PAIR'S TWO ROWS AGREE HERE, which is the opposite of the tab above and is also
    # measured: `panorama-server-2`, written on one member alone, read back on BOTH twenty
    # minutes later, carried by the pair's configuration synchronisation with nothing ever
    # addressed to the peer. They are still two rows, because both members must be collected and
    # the management channel is per appliance.
    spec(T.PANORAMA_REGISTRATION,
         "The channel each firewall uses to reach its central management estate: which "
         "appliances it names, and whether the conversation runs on the customer's own "
         "certificate material with the station's name checked. A finding names the APPLIANCE "
         "because both nodes behind it are device-wide `deviceconfig`. WHAT A ROW HERE CANNOT "
         "SAY: whether the channel is authenticated. This is the FIREWALL'S HALF of the "
         "handshake and only that half - whether the management appliance accepts the "
         "certificate every appliance of this make ships with is `secure-conn-server` on the "
         "station, which is out of assessment scope, so even every column here on the hardened "
         "side leaves the question open. AND THE REDUNDANCY HALF APPLIES BY AN ASSUMPTION AND "
         "NOT BY A READING: whether the management estate is a pair lives on the station's own "
         "high-availability node, which nothing collects, and the column defaults to the "
         "APPLYING side because a false there would suppress the control on every firewall. The "
         "consequence is on the row rather than left to be discovered - on a single-appliance "
         "estate this fires everywhere and its remediation would point a firewall at an "
         "appliance that does not exist, which is the measured state of this lab. An engineer's "
         "answer should override that column.",
         title="Panorama Settings",
         setting_labels=ha_panorama.PANORAMA_REGISTRATION_LABELS,
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         # Two of the three clause fields are derived and `panorama_server_secondary` is a stored
         # `CharField` carrying a real provenance row - and it is the field the calibration
         # asserts on, so a constant "Derived" would be a falsehood about the very value this
         # control reports. Measured on a built row.
         provenance_cell=ha_panorama.provenance_cell),
    # ------------------------------------------------------- network-hardening, 2026-11-03
    # FIVE TABS FOR SEVEN CONTROLS, and the count is `_object_domain(slug, T.TYPE)` keying per
    # control type rather than a choice. THREE PAN-OS CATEGORIES, all DERIVED from the rail
    # (`category=""` on all five), which is right for a subject that IS a configuration object
    # and means the workbook cannot disagree with the app about where an object lives.
    #
    # EVERY TAB TITLE AND EVERY HEADING IS A PROPOSAL (P399), all five under Excel's 31-character
    # sheet-name cap, counted: Interfaces 10, Session Settings 16, DHCP Interfaces 15,
    # Tunnel Inspection 17, Routing Adjacencies 19. See `network_hardening_presentation` for
    # which words are the vendor's and which three columns the vendor has no word for.
    #
    # `hidden_fields=()` ON ALL FIVE. `check_every_tested_field_is_presented` accepts a non-empty
    # one as PROOF that a field is presented, so it is a claim rather than a column, and it
    # forfeits the value-at-fault mark - the two `implicated` loops walk `subject_columns` and
    # the settings columns and never consult it. All thirteen clause fields across these five
    # tabs get a real derived column.
    #
    # `tested_columns=ALL_TESTED_COLUMNS` ON ALL FIVE, knowing what it costs (P427): the default
    # `("Provenance",)` drops `Fires when` from the WORKBOOK while the live page keeps it, so the
    # two surfaces would disagree about which cell a reader meets. Taken knowing `fires_when`
    # renders the BASELINE's condition alone (`findings.py:452`, no per-spec hook), which on this
    # domain costs exactly one tab - see the session-settings spec.
    #
    # Network > Interfaces, for PAN-NET-001 and PAN-NET-003. Category DERIVED from the rail,
    # whose item is `firewall-interfaces`.
    #
    # THE ONE TAB IN THE PIPELINE OVER AN UNPROVENANCED MODEL, and it builds. `Interface` is a
    # `SyncTrackedModel` and not a `ProvenancedMixin`: it has no `DERIVED_FIELDS` ATTRIBUTE AT
    # ALL - which is not the empty tuple - and nothing writes a `FieldProvenance` row for an
    # interface, per field or `__entry__`. That is the shape that took out the whole Security
    # Zones tab in run 147, and `findings.py:731` was made defensive the same day
    # (`field in getattr(_model, "DERIVED_FIELDS", ())`), so the trap is FIXED. Measured here on
    # built rows rather than reasoned about.
    #
    # SO IT OWES NOTHING FOR P451 ON CORRECTNESS, which no tab before it has. Measured both ways
    # over all 24 built rows: the default and a branching cell BOTH answer "Not recorded" for
    # every clause field, because there is no row to find and nothing to synthesise. That is not
    # the P451 defect - "Not recorded" is the vocabulary's own words for "nothing tracks that
    # field" and it is TRUE of an interface, where the other tabs' "Not recorded" was false about
    # a column declared derived.
    #
    # IT TAKES THE BRANCHING CELL ANYWAY, AND ONLY TO DE-DUPLICATE. Measured: on the five
    # PAN-NET-003 rows - the control with TWO clause fields - the default prints "Not recorded"
    # TWICE in one cell, once per field, while the branching cell collapses it to one line. No
    # truth value changes either way; the repeated word is noise. De-duplication is that cell's
    # own stated purpose - `ha_panorama_presentation` puts it as "a tab whose seven clause fields
    # are six DERIVED and one Local prints two lines, not seven" - so this is the established use
    # and not a new one. The 19 single-field PAN-NET-001 rows read identically under both.
    spec(T.FIREWALL_INTERFACE,
         "What is left reachable on a firewall port that is out of service, and what each port "
         "announces about itself to its neighbours. A finding names ONE INTERFACE of ONE "
         "APPLIANCE, so a port synchronised across an HA pair draws TWO rows and the `HA role` "
         "column is what tells them apart - that is correct and not a duplicate, because "
         "interfaces have no appliance-group bridge and 'this peer holds no interfaces' would "
         "otherwise be indistinguishable from 'this peer was never normalized'. WHAT A ROW HERE "
         "CANNOT SAY: whether the protocol is on firewall-wide. LLDP has a device-wide switch at "
         "`network/lldp/enable` which stage 5 assessed as a SECOND record of PAN-NET-003, and "
         "the shipped catalogue carries no query for it - so an interface row reporting what a "
         "port announces cannot tell a reader whether anything is announced at all. THAT SWITCH "
         "IS READABLE FROM NO SURFACE IN THIS APPLICATION: nothing can fire over its model, so it "
         "has no findings tab, and a rail item is a promise of a findings page - see "
         "`configuration_navigation.py`, 'Network > LLDP IS DELIBERATELY ABSENT FROM THIS RAIL'. "
         "Closing it is one catalogue entry, which stage 8 already compiled. "
         "AND THE PROVENANCE COLUMN READS 'Not recorded' ON EVERY "
         "ROW, which is a true statement and not a gap: `integrations.Interface` is the one "
         "subject model in this report that carries no provenance records at all, so nothing "
         "tracks whether a value was written locally or pushed by a template.",
         title="Interfaces",
         subject=network_hardening.INTERFACE_SUBJECT,
         setting_labels=network_hardening.INTERFACE_LABELS,
         # TWO READERS AND ONE DELIBERATE REFUSAL, all three on clause fields of ONE control,
         # ONE query and ONE row - which is a first. `out_of_service_residue` and
         # `lldp_announced_content` are `CharField`s with choices, so without a reader their
         # cells print the stored key under a vendor heading (P457). `lldp_enabled` is a
         # `BooleanField` with `choices=None`, so `get_lldp_enabled_display()` DOES NOT EXIST and
         # a reader calling it raises `AttributeError` at template render, past `django check`
         # and past all three cross-domain gates (P462) - the defect that shipped a 500 on
         # `globalprotect-gateway`. `display_value` already answers a boolean "Yes"/"No"
         # correctly, so the refusal costs nothing. Pinned by name in
         # `test_one_reader_and_one_refusal_on_pan_net_003`.
         value_readers={
             "out_of_service_residue": network_hardening.OUT_OF_SERVICE_RESIDUE,
             "lldp_announced_content": network_hardening.LLDP_ANNOUNCED_CONTENT},
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         provenance_cell=network_hardening.provenance_cell),
    # Device > Setup > Session, for PAN-NET-002 and PAN-NET-005. Category DERIVED from the rail,
    # whose item is `session-settings`. The one tab of this domain that is not Network or
    # Policies.
    #
    # THE DEFAULT PROVENANCE CELL, AND IT IS HONEST PER FIELD HERE. Both model fields are stored
    # payload keys outside `DERIVED_FIELDS` carrying real `FieldProvenance` rows, so
    # `remediation_accessor` KEEPS the row and the cell prints what was recorded;
    # `rematch_known` takes the reader arm and prints the reader's own prose. Three cells, three
    # honest answers, and a sheet-level cell would collapse them into one line for no gain.
    #
    # THE ONE TAB WHERE `Fires when` IS WRONG ON A ROW, and it is kept anyway. PAN-NET-002's
    # calibration clauses on `rematch_known` while `fires_when` renders the BASELINE alone, so a
    # row that fired on "never established" prints the baseline's `session_rematch is not True`
    # as its stated condition. That condition IS met by a NULL row - `compile_search_clause`
    # negates at the pk-SET level, so the calibration's population is a strict SUBSET of the
    # baseline's, measured by stage 8 - so the sentence is true here rather than contradicting
    # the row, which is the better case of P436 and not an escape from it. `Matched queries`
    # names which group fired.
    spec(T.SESSION_SETTINGS,
         "Two device-wide session behaviours that decide whether a policy change actually "
         "reaches traffic already in flight, and whether IPv6 traffic is inspected at all. A "
         "finding names the APPLIANCE because both nodes are under `deviceconfig/setting`, which "
         "is device-wide rather than vsys-scoped, so an HA pair draws TWO rows for one real "
         "configuration - the values ARE expected to agree here, stage 4 read the same answer on "
         "both PA-5220s, and both peers are still collected because their configurations are not "
         "identical in general. WHAT A ROW HERE CANNOT SAY: whether IPv6 firewalling was ever "
         "CONSIDERED. `ipv6_firewalling` is non-nullable with a measured vendor default of true, "
         "so an absent key and a deliberate 'on' store the same value and no `*_known` companion "
         "is possible - PAN-NET-005 therefore cannot separate 'we asked and the device says it "
         "is on' from 'we never asked', and stage 8 recorded its declared second query as one "
         "that could not be compiled. The rematch half DOES have that distinction, because its "
         "key is nullable: `Rematch setting established` is the column that carries it.",
         title="Session Settings",
         setting_labels=network_hardening.SESSION_LABELS,
         # ONE READER, AND IT IS THE ONLY STATE IN WHICH THIS TAB EXISTS. PAN-NET-002's shipped
         # calibration clauses on `rematch_known`, which `PanOsSessionSettings` does not have, so
         # `tested_fields` RAISES `ValueError` without this entry. The contract's finding 4,
         # third case - the price is paid whether anyone wants it or not - except that here the
         # price is nil, because the field has no provenance row of its own to lose.
         #
         # NO READER ON `session_rematch`, REFUSED ON PURPOSE. It is a nullable boolean whose
         # NULL is the finding, and `display_value` renders that NULL `(none)` - contract finding
         # 4's shape exactly. A reader would print "Never established" AND would make
         # `remediation_accessor` skip the field's own `FieldProvenance` row, which is the only
         # thing separating an ABSENT key from one explicitly written. On the control whose
         # second query is ABOUT the absence, that is the wrong trade, so the companion column
         # says it instead. Recorded as a cell this stage chose not to improve.
         value_readers={"rematch_known": network_hardening.REMATCH_KNOWN},
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    # Network > DHCP, for PAN-NET-004. Category DERIVED from the rail, whose item is
    # `dhcp-interfaces`.
    #
    # THE TAB WHOSE THREE CLAUSE FIELDS SIT IN THREE DIFFERENT COMBINATIONS of the two greps, so
    # its provenance cell MUST branch. Measured by introspection: `dhcp_server_configured` is a
    # Boolean declared DERIVED (no reader, and a constant "Derived" would be true of it);
    # `dhcp_relay_state` is a CharField with choices AND declared DERIVED (reader mandatory,
    # "Derived" true); `dhcp_server_mode` is a CharField with choices and NOT derived - a
    # measured payload key carrying a real `FieldProvenance` row. A constant "Derived" would
    # state a falsehood about that third one.
    #
    # AND THE BRANCHING CELL IS WHAT MAKES THE READER ON `dhcp_server_mode` FREE. `build_rows`
    # computes the per-field provenance `cells` list and then DISCARDS it when a spec sets
    # `provenance_cell`, so the P451 price a reader normally pays on a measured payload key - the
    # walk past the field's own row to an `__entry__` that is never written - is not paid here.
    # That column gets both its English label and its recorded provenance, which neither remedy
    # could have delivered alone.
    spec(T.DHCP_INTERFACE_CONFIG,
         "Where a firewall is handing out addresses or relaying somebody else's DHCP, and "
         "whether such a configuration has been left switched off rather than removed. A finding "
         "names ONE INTERFACE of ONE APPLIANCE, so an HA pair draws TWO rows for one real "
         "configuration. A ROW EXISTS ONLY WHERE THE CONFIGURATION DOES: "
         "`network/dhcp/interface` carries an entry per port that has DHCP configured at all, so "
         "the passing state needs no row and this tab is short by design - the finding names the "
         "configuration that should not be there, not the port. WHAT A ROW HERE CANNOT SAY: "
         "whether a relay was ever switched on. `dhcp_relay_ipv4_enabled` is nullable and its "
         "NULL means no `enabled` key under a relay branch that exists, which the `Relay switch "
         "established` column on the explorer page reports; the graded relay column folds that "
         "into its own verdict rather than leaving it to be inferred.",
         title="DHCP Interfaces",
         subject=network_hardening.DHCP_SUBJECT,
         setting_labels=network_hardening.DHCP_LABELS,
         value_readers={
             "dhcp_relay_state": network_hardening.DHCP_RELAY_STATE,
             "dhcp_server_mode": network_hardening.DHCP_SERVER_MODE},
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         provenance_cell=network_hardening.provenance_cell),
    # Policies > Tunnel Inspection, for PAN-NET-006 - the one item of this domain on the Policies
    # tab. Category DERIVED from the rail, whose item is `tunnel-inspection`.
    #
    # THE DEFAULT PROVENANCE CELL. One clause field, declared in `DERIVED_FIELDS`, with a reader
    # for its eight choices - so the reader arm prints the reader's own prose "Derived", which is
    # what the model declares and is true. Nothing branches because there is nothing to branch
    # between.
    spec(T.TUNNEL_INSPECTION,
         "Whether encapsulated traffic crossing a virtual system is inspected inside the tunnel "
         "or carried through unexamined. A finding names ONE VIRTUAL SYSTEM of ONE APPLIANCE - "
         "this is the only vsys-scoped subject in the domain, because tunnel-inspect rules are "
         "vsys-scoped content - so an HA pair draws TWO rows for one real rulebase. IT IS A "
         "VERDICT OVER A RULEBASE AND NOT A ROW PER RULE, which is the whole reason the model "
         "exists: the commonest failing state is that NO RULE EXISTS, measured as the state of "
         "every vsys in the lab bar three, and a per-rule row cannot report it because there is "
         "no row. WHAT A ROW HERE CANNOT SAY: whether traffic is actually encapsulated. The "
         "verdict is about the rulebase's coverage of the encapsulations PAN-OS can inspect, not "
         "about what is crossing the firewall today, so a vsys carrying no tunnelled traffic "
         "reports the same gap as one carrying a great deal of it. A vsys named `vsys1` exists on "
         "single-vsys platforms too, so its presence proves nothing about the mode.",
         title="Tunnel Inspection",
         subject=network_hardening.TUNNEL_SUBJECT,
         setting_labels=network_hardening.TUNNEL_LABELS,
         value_readers={
             "tunnel_inspection_coverage_state": network_hardening.TUNNEL_COVERAGE_STATE},
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS),
    # Network > Virtual Routers, for PAN-NET-007. Category DERIVED from the rail, whose item is
    # `virtual-routers`.
    #
    # BRANCHING, AND FOR A THIRD REASON AGAIN. `authentication_strength` and `prefix_limit_state`
    # are declared DERIVED; `protocol` is NEITHER derived NOR a payload key - it is part of the
    # row's identity, so it has no `FieldProvenance` row and no declaration either, and the
    # default cell reads "Not recorded" for it beside two that are genuinely derived. A constant
    # would be a falsehood and the default is three answers where two are wrong, so the cell
    # reads `provenance_of` per field and prints what was recorded.
    #
    # `protocol` IS A SCOPE CLAUSE THAT BECAME A PRESENTED COLUMN. Stage 5 gives it
    # `role: "scope"` and it is a clause of the shipped "BGP peer with no enforced prefix
    # ceiling" query, so `tested_fields` derives a column for it among the verdict columns -
    # contract finding 1 in its original shape. It is NOT in that query's `asserted_fields`, so
    # it is not MARKED, confirmed on a built row.
    spec(T.ROUTING_ADJACENCY,
         "Whether each routing adjacency a firewall maintains is authenticated with a strong "
         "digest, and whether a BGP peer's prefix intake is bounded. A finding names ONE "
         "ADJACENCY within ONE VIRTUAL ROUTER of ONE APPLIANCE, so an HA pair draws TWO rows for "
         "one real adjacency. THE PROTOCOL IS PART OF THE IDENTITY and not decoration: a BGP peer "
         "and an OSPF area interface can carry the same name within one router and are different "
         "things, and an authentication reference resolves WITHIN the same virtual router - "
         "measured - so the same profile name on another router is a different object. WHAT A ROW "
         "HERE CANNOT SAY: whether the adjacency is UP. Every column is configuration; whether a "
         "peer is answering, whether a session is established and whether the digest is in force "
         "on the wire are runtime properties that only `show routing protocol <p> summary` "
         "reports, and no collector issues it. So a row reporting an unauthenticated adjacency is "
         "reporting the configured state of a relationship that may not be carrying a single "
         "route. AND THE PREFIX CEILING APPLIES TO BGP ALONE - the `Protocol` column is what "
         "tells a reader whether that half of the row was in scope for the adjacency at all.",
         title="Routing Adjacencies",
         subject=network_hardening.ROUTING_SUBJECT,
         setting_labels=network_hardening.ROUTING_LABELS,
         value_readers={
             "authentication_strength": network_hardening.AUTHENTICATION_STRENGTH,
             "prefix_limit_state": network_hardening.PREFIX_LIMIT_STATE,
             "protocol": network_hardening.PROTOCOL},
         hidden_fields=(),
         tested_columns=findings_sheet.ALL_TESTED_COLUMNS,
         provenance_cell=network_hardening.provenance_cell),
)


SPEC_BY_TYPE = {sheet_spec.control_types[0]: sheet_spec for sheet_spec in SPECS}


def writer(control_type):
    """The `write_sheet(build)` for one domain, so `build_workbook` can place its tab in the
    run's own order rather than taking these fifteen as a block."""
    sheet_spec = SPEC_BY_TYPE[control_type]

    def write_sheet(build) -> SheetInfo:
        return findings_sheet.write_sheet(build, sheet_spec)

    write_sheet.__name__ = f"write_{sheet_spec.sheet_title.lower().replace(' ', '_')}"
    return write_sheet
