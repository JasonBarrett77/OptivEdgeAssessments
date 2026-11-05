"""Finding generation for the IKE crypto profile controls. PAN-IKE-002 to 005.

THE SENTENCE SAYS THE WHOLE OFFER SET AND NOT ONLY THE WEAKEST MEMBER. The profile offers every
member of each list and takes the first one a peer accepts, so a weak member left in place is a
live option and not a lower preference - and the remediation has to know the whole set, because
the fix is to remove members rather than to add a stronger one. The controls read the derived
`weakest_*` and `*_floor_met` columns, which is where a finding rests; the lists are read here,
off the row, for the prose.

THREE THINGS THE SENTENCE IS NOT ALLOWED TO SAY, each from a measurement:

* THAT A LIFETIME IS TOO LONG WHEN NOBODY READ IT. `key_lifetime_known` false means the key was
  absent or the row was never collected, and the absent state is UNMEASURED - stage 4 of the
  `ike-crypto` domain says in terms that every lab profile carries the key explicitly, so the
  vendor's documented eight hours is not evidence about a profile without it. So that case reads
  "the key lifetime was not established".
* THAT THE RE-AUTHENTICATION INTERVAL IS A NUMBER. `reauth_interval_hours` is null both where the
  multiplier is the sentinel 0 - "0 means reauthentication disabled", the device's own words, and
  the UNBOUNDED end of the axis while sorting as the smallest number - and where the multiplier
  was never read. `authentication_multiple_known` is the column that tells those two apart, and
  the sentence uses it rather than guessing.
* THAT `non-auth` IS A WEAKNESS ON AN AEAD PROFILE. Help p.658 MANDATES it alongside AES-GCM, so
  on a profile offering an authenticated-encryption cipher the member carries no severity at all
  and `hash_floor_met` is true. The same literal means opposite things on the two profiles.

FOUR OF THE FIVE CONTROLS THIS MODULE ONCE SERVED HAVE MOVED, as of 2026-11-04: PAN-IKE-002 to
-005 are keyed on the IPSec tunnel PATH, so a weak proposal is reported once per tunnel that uses
it rather than once per profile. Their sentence builders stay here and the path generator IMPORTS
them, because each carries a measurement and a second phrasing would be a second set of claims to
keep true. What this module generates on its own is PAN-IKE-010, the profile nothing names - the
one state the path controls cannot see, since a profile no path reaches has no path to be reported
on.

AND ONE IT MUST SAY: where the weakest key-agreement member is a post-quantum name, no severity
rank exists for it. Stage 3 ranked ten classical members and placed the other eighteen
`unranked` with the reason, so the finding reports at the control's baseline severity about a
group nobody has graded - and a reader cannot see that from the row.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_ike_crypto_profile_control_queries
from assessments.models import (
    Control, IkeCryptoProfileFinding, IkeCryptoProfileFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import IkeCryptoProfile

#: The ten key-agreement members stage 3 ranked. Anything else offered is a member no severity
#: band reaches, which the sentence has to say out loud.
RANKED_DH_GROUPS = frozenset({
    "group1", "group2", "group5", "group14", "group15", "group16",
    "group19", "group20", "group21", "none",
})


def _offer(label: str, members) -> str:
    if not members:
        return f"no {label} list was collected"
    return f"{label} offered: {', '.join(str(m) for m in members)}"


def _dh_group(obj) -> list[str]:
    if obj.dh_group_floor_met:
        return []
    detail = _offer("key agreement", obj.dh_groups)
    weakest = obj.weakest_dh_group
    if weakest == "none":
        # Not a weak group: the member that can take the key agreement OUT of the proposal, with
        # the device's own help string "Make this round optional".
        detail += (" - the weakest member is `none`, which is not a weak group but one that can "
                   "remove the key agreement from the proposal entirely")
    elif weakest and weakest not in RANKED_DH_GROUPS:
        detail += (f" - the weakest member is {weakest}, a key-encapsulation name no severity "
                   f"band in this control ranks, so this finding carries the control's own "
                   f"severity rather than a graded one")
    elif weakest:
        detail += f" - weakest {weakest}"
    return [detail]


def _encryption(obj) -> list[str]:
    if obj.encryption_floor_met:
        return []
    detail = _offer("encryption", obj.encryption_ciphers)
    if obj.weakest_encryption_cipher:
        detail += f" - weakest {obj.weakest_encryption_cipher}"
    return [detail]


def _hash(obj) -> list[str]:
    if obj.hash_floor_met:
        return []
    detail = _offer("integrity", obj.hash_algorithms)
    weakest = obj.weakest_hash_algorithm
    if weakest == "non-auth" and not obj.offers_aead_cipher:
        detail += (" - the weakest member is `non-auth`, which on a profile offering no "
                   "authenticated-encryption cipher is no integrity algorithm at all rather than "
                   "a weak one, and the device accepted this pairing without complaint")
    elif weakest:
        detail += f" - weakest {weakest}"
    if obj.offers_aead_cipher:
        detail += (f"; the profile does offer an authenticated-encryption cipher, so "
                   f"`non-auth` is permitted beside it - what is missing is a SHA-2 member for "
                   f"the non-AEAD ciphers it also offers ({_offer('encryption', obj.encryption_ciphers)})")
    return [detail]


def _lifetime(obj) -> list[str]:
    if not obj.key_lifetime_known:
        # NOT "the lifetime is too long". The absent state is unmeasured - every lab profile
        # carries the key explicitly - so the vendor's documented eight hours is not evidence
        # about a profile without it.
        return ["the key lifetime was not established - the lifetime key is absent from this "
                "profile or the profile was never collected, and what the device does with the "
                "key absent is unmeasured, so this is not a report that the lifetime is too long"]
    if not obj.key_lifetime_hours:
        return []
    written_as = (f", written in {obj.key_lifetime_unit}"
                  if obj.key_lifetime_unit and obj.key_lifetime_unit != "hours" else "")
    return [f"key lifetime {obj.key_lifetime_hours} hours{written_as}"]


def _reauth(obj) -> list[str]:
    if obj.reauth_interval_bounded:
        return []
    if not obj.authentication_multiple_known:
        return ["the IKEv2 re-authentication interval is not bounded: no authentication multiple "
                "was read on this profile, so the interval cannot be stated"]
    if obj.authentication_multiple == 0:
        return ["the IKEv2 re-authentication interval is not bounded: the authentication "
                "multiple is 0, which disables re-authentication entirely rather than setting a "
                "short interval"]
    if obj.reauth_interval_hours:
        return [f"the IKEv2 re-authentication interval is {obj.reauth_interval_hours} hours - "
                f"authentication multiple {obj.authentication_multiple} times the key lifetime"]
    return ["the IKEv2 re-authentication interval is not bounded and cannot be stated from what "
            "was read"]


def _unreferenced(obj) -> list[str]:
    if obj.referenced_by_gateway_on_this_appliance:
        return []
    # A CANDIDATE and not a confirmed leftover, per stage 3's own qualification: the count is
    # taken on this firewall, which cannot see a reference held anywhere else.
    return ["no IKE gateway on this appliance names this profile from either of its two "
            "crypto-profile pointers, which makes it a candidate for removal rather than a "
            "confirmed leftover - a reference held outside this firewall's own configuration is "
            "not visible here"]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. A finding describes what ITS OWN control
#: asserts, not everything the row happens to hold: a version finding that also reported the
#: key lifetime would send a reader to the wrong screen, and two controls reporting the same
#: fact is two findings for one condition. PAN-IKE-009's profile half is absent from this map
#: because it cannot be a query on this model - see the stage 8 artifact for `ike-crypto`.
PARTS_BY_CONTROL = {
    "PAN-IKE-002": (_dh_group,),
    "PAN-IKE-003": (_encryption,),
    "PAN-IKE-004": (_hash,),
    "PAN-IKE-005": (_lifetime, _reauth),
    # PAN-IKE-010, 2026-11-04: the hygiene half, which had no control id until the four above
    # moved their subject to the IPSec tunnel PATH. `_unreferenced` was written before this
    # control existed and is unchanged - it already carries the candidate-not-leftover
    # qualification a firewall-side count owes.
    "PAN-IKE-010": (_unreferenced,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"IKE crypto profile {obj.entry_name} on {obj.appliance}"]
    builders = PARTS_BY_CONTROL.get(control_id)
    if builders is None:
        # An unmapped control on this model: say everything rather than nothing, because a
        # finding with no detail is indistinguishable from a finding about a sound profile.
        builders = (_dh_group, _encryption, _hash, _lifetime, _reauth, _unreferenced)
    for build in builders:
        parts.extend(build(obj))
    return "; ".join(parts)


def build_ike_crypto_profile_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="IKE crypto profile",
    control_type=Control.ControlType.IKE_CRYPTO_PROFILE,
    finding_model=IkeCryptoProfileFinding,
    link_model=IkeCryptoProfileFindingControlQuery,
    subject_fk="ike_crypto_profile",
    link_fk="ike_crypto_profile_finding",
    queryset=lambda: IkeCryptoProfile.objects.select_related("appliance"),
    evaluate=evaluate_ike_crypto_profile_control_queries,
    summary=build_ike_crypto_profile_finding_summary,
    subject_name=lambda obj: obj.entry_name,
)


def generate_ike_crypto_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_ike_crypto_profile_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
