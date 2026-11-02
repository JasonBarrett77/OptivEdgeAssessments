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

from optivedge_integrations.integrations.models import AddressObject

from assessments import device_id_presentation as device_id
from assessments import ike_presentation as ike
from assessments import ipsec_presentation as ipsec
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
    # exists. A third domain (`zone-dos-protection`, PAN-ZON) reuses this tab after us and will
    # need an entry here for every field ITS controls clause on.
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
    spec(T.LOGGING_SETTINGS,
         "What the firewall does about logging when the data plane is under load."),
    spec(T.WILDFIRE_SETTINGS,
         "What the firewall forwards to WildFire: the per-type file size limits, and whether "
         "session context and benign/grayware verdicts are shared. DEVICE-WIDE, as against "
         "the WildFire analysis profile, which decides what is asked for and is reported on "
         "the security rule."),
    spec(T.NTP_SETTINGS,
         "Where each firewall gets its time, and whether those exchanges are authenticated. "
         "Whether a configured server is reachable or synchronized is not assessed - that is "
         "live device state, not configuration.",
         title="NTP",),
    spec(T.SNMP_SETTINGS,
         "Whether each firewall exposes SNMP, which version, and whether its community string is "
         "a default one.",
         title="SNMP",),
    spec(T.SYSTEM_IDENTITY,
         "How each firewall is named, what time zone its logs are written in, and whether its "
         "management address is static.",
         title="System Identity",),
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
                        "has_non_blocking_mlav_decoder": MLAV_COVERAGE},
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance_group",
                                 "enforcement_point__appliance", "appliance_group"),
         subject_prefetch=("enforcement_point__appliance_group__appliances", "decoders", "ml_models",
                           "application_overrides")),
    spec(T.ADMIN_USER,
         "The administrator accounts on each firewall: what each may do, and what it authenticates "
         "with.",
         subject=APPLIANCE + NAME,),
    spec(T.SERVER_PROFILE,
         "The identity services the firewall authenticates against - LDAP, RADIUS, TACACS+, "
         "Kerberos and SAML - and how it connects to each.",
         subject=APPLIANCE + SCOPE + KIND + NAME),
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
