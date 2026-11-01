"""Finding generation for the IPSec crypto profile controls. PAN-IPS-001 to 005, and 009.

PHASE 2. `ike_crypto_profile_findings` beside this one is phase 1 over a different model at an
adjacent xpath. Nothing is shared between them on purpose: the stored shapes differ (`dh-group`
is a bare string here and a member list there), the severity bands differ, and a reused helper
would be a helper that has to ask which phase it is in.

THE SENTENCE SAYS THE WHOLE OFFER SET AND NOT ONLY THE WEAKEST MEMBER, for the same reason the
phase 1 module gives: the profile OFFERS every member of each list and a peer can negotiate down
to the weakest one however the list is ordered, so a weak member left in place is a live option
and not a lower preference - and the remediation has to know the whole set, because the fix is to
remove members rather than to add a stronger one. The controls read the derived `weakest_*` and
verdict columns, which is where a finding rests; the lists are read here, off the row, for the
prose.

THINGS THE SENTENCE IS NOT ALLOWED TO SAY, each from a measurement:

* THAT `none` IN THE INTEGRITY LIST IS A WEAKNESS ON AN AEAD-ONLY PROFILE. The vendor states the
  separate hash is IGNORED for those ciphers (gp p.877), so on a profile whose every offered
  cipher authenticates as it encrypts the member carries no severity at all - which is why
  PAN-IPS-003 excludes that profile by APPLICABILITY rather than scoring it. The same stored
  literal means opposite things on the two profiles, and both shipped Suite-B profiles store it
  as an ordinary member.
* THAT A POST-QUANTUM KEY-AGREEMENT GROUP IS WEAK. Nineteen of PAN-IPS-004's twenty-nine
  placements are UNRANKED - eighteen post-quantum encapsulations and a literal `none` - because
  no ordering places them, not because they are weaker choices. The baseline fires on them
  anyway, since `dh_group_meets_target` is false for anything outside the three elliptic-curve
  targets, so the finding reports at the control's own severity about a group nobody has graded.
  A reader cannot see that from the row, so the sentence says it.
* THAT A LIFETIME IS "TOO LONG" WITHOUT SAYING WHICH UNIT IT WAS WRITTEN IN. The same real
  lifetime is written four ways and `lifetime_hours` is the conversion, ROUNDED UP - stage 7
  settled the direction nothing in stage 5 stated. A reader sent to the screen will see the unit
  the engineer typed, not the hours, so the sentence carries both.
* THAT A BRANCHLESS PROFILE OFFERS WEAK ALGORITHMS. A profile carrying neither `esp` nor `ah`
  offers no confidentiality and no integrity at all; it is not a profile with a weak list, it is
  a profile with no list, and stage 4 committed that state twice.

AND ONE THING THE DISPATCH DOES NOT DO: its default is `()`. Measured across all 28 shipped
generators that key a dispatch by control id, EIGHTEEN default to another control's arm tuple -
so a different control reusing the type has its finding described with the first control's
claims. `()` is the convention the three most recent runs adopted and the one that fails visibly
rather than inventing prose, and this domain reuses no type anyway: both of its types were
minted here.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_ipsec_crypto_profile_control_queries
from assessments.models import (
    Control, IpsecCryptoProfileFinding, IpsecCryptoProfileFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import IpsecCryptoProfile

#: The ten key-agreement members stage 3 ranked. Anything else the field can hold is a member no
#: severity band in PAN-IPS-004 reaches, which the sentence has to say out loud.
RANKED_DH_GROUPS = frozenset({
    "no-pfs", "group1", "group2", "group5", "group14", "group15", "group16",
    "group19", "group20", "group21",
})


def _offer(label: str, members) -> str:
    if not members:
        return f"no {label} list is present on this profile"
    return f"{label} offered: {', '.join(str(m) for m in members)}"


def _branch(obj) -> list[str]:
    branch = obj.protocol_branch
    if branch == IpsecCryptoProfile.ProtocolBranch.ESP:
        return []
    if branch == IpsecCryptoProfile.ProtocolBranch.AH:
        return ["this profile carries the integrity-only AH branch, so the payload it protects "
                "is authenticated and travels in cleartext - a receiver can detect tampering "
                "and anyone on the path can read the traffic"]
    # Neither branch. Not a weak list - no list at all.
    return ["this profile carries NEITHER the esp nor the ah branch, so it offers no "
            "confidentiality and no integrity algorithm of any kind; it is not a profile with a "
            "weak proposal, it is a profile with no proposal"]


def _encryption(obj) -> list[str]:
    if obj.protocol_branch == IpsecCryptoProfile.ProtocolBranch.AH:
        # The AH branch has no cipher list to be weak. PAN-IPS-001 is the control that reports
        # it; saying "no encryption offered" here would report the same fact twice.
        return []
    detail = _offer("encryption", obj.esp_encryption)
    weakest = obj.weakest_encryption_offered
    if weakest == "null":
        detail += (" - the weakest member is the `null` cipher, which carries the payload in "
                   "CLEARTEXT inside what reads as an encrypted tunnel")
    elif weakest:
        detail += f" - weakest {weakest}"
    if obj.all_offered_ciphers_authenticate and obj.esp_encryption:
        detail += ("; every cipher offered authenticates as it encrypts, so the separate "
                   "integrity algorithm beside them is ignored by the device")
    return [detail]


def _integrity(obj) -> list[str]:
    if obj.integrity_meets_sha2_floor:
        return []
    if obj.all_offered_ciphers_authenticate:
        # PAN-IPS-003 excludes this profile by applicability and should never reach here, but a
        # second control on this model could - and the honest sentence is not "weak integrity".
        return ["every cipher this profile offers authenticates as it encrypts, so the separate "
                "integrity algorithm is ignored by the device and carries no weakness here"]
    offered = (obj.esp_authentication
               if obj.protocol_branch == IpsecCryptoProfile.ProtocolBranch.ESP
               else obj.ah_authentication)
    detail = _offer("integrity", offered)
    weakest = obj.weakest_integrity_offered
    if weakest == "none":
        detail += (" - the weakest member is the literal `none`, which beside a cipher that only "
                   "encrypts is no integrity algorithm at all rather than a weak one: the "
                   "payload is confidential and forgeable, and the device accepted the pairing "
                   "without complaint")
    elif weakest:
        detail += f" - weakest {weakest}, which is outside the SHA-2 family this control requires"
    return [detail]


def _dh_group(obj) -> list[str]:
    if obj.dh_group_meets_target:
        return []
    group = obj.dh_group
    if group == "no-pfs":
        return ["key agreement for the payload phase is turned OFF - `no-pfs` reuses the key "
                "already agreed in phase 1 rather than deriving a fresh one, so one compromised "
                "key exposes the traffic of every association that reused it"]
    if group == "none":
        return ["the key-agreement group is the literal value `none`, which this control's "
                "severity bands do not rank and which the device's own help-string describes "
                "for a different field - so what it does here is not established from the "
                "configuration alone, and it is reported rather than passed over"]
    if group and group not in RANKED_DH_GROUPS:
        return [f"the key-agreement group is {group}, a post-quantum key encapsulation that no "
                f"severity band in this control ranks - this is reported because it is not one "
                f"of the three elliptic-curve groups the control targets, NOT because it is a "
                f"weaker choice, and the severity carried here is the control's own default "
                f"rather than a graded one"]
    if group:
        return [f"the key-agreement group is {group}, below the elliptic-curve strength this "
                f"control targets"]
    return ["no key-agreement group is recorded for this profile"]


def _lifetime(obj) -> list[str]:
    if obj.lifetime_within_target:
        return []
    if obj.lifetime_hours is None:
        # NOT "the lifetime is too long". `lifetime` is the one unconditionally mandatory key of
        # this object - stage 4 measured a commit refusing a key-less profile - so a NULL here is
        # a row nobody recomputed rather than a configuration without a lifetime.
        return ["the key lifetime was not established for this profile - the column holds "
                "nothing, which on an object whose lifetime key is mandatory at commit means "
                "the row was never recomputed rather than that the lifetime is absent, so this "
                "is not a report that the lifetime is too long"]
    written_as = (f", written in the {obj.lifetime_unit} unit"
                  if obj.lifetime_unit and obj.lifetime_unit != "hours" else "")
    return [f"the payload key lifetime is {obj.lifetime_hours} hours{written_as} - longer than "
            f"the one hour this control targets, so one key protects more traffic than it "
            f"should before it is replaced"]


def _unreferenced(obj) -> list[str]:
    if obj.referencing_tunnel_count:
        return []
    # A CANDIDATE AND NOT A CONFIRMED LEFTOVER, and the qualification is not optional: stage 3
    # records that an object with nothing referencing it ON THE DEVICE may still be referenced
    # by configuration that is not pushed, that both states look identical from the firewall,
    # and that "a deletion recommendation acted on without it breaks the tunnel that the next
    # push creates". No column holds that, so it belongs in this sentence.
    return ["no tunnel on this appliance names this profile from either of the two referring "
            "leaves - the site-to-site key-exchange reference or the LSVPN satellite client "
            "reference - which makes it a CANDIDATE for removal rather than a confirmed "
            "leftover: a reference held on a management station and not yet pushed is not "
            "visible from this firewall and looks identical to no reference at all"]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. A finding describes what ITS OWN control
#: asserts, not everything the row happens to hold: a branch finding that also reported the key
#: lifetime would send a reader to the wrong part of one screen, and two controls reporting the
#: same fact is two findings for one condition.
#:
#: PAN-IPS-009 IS HERE FOR ITS PROFILE HALF ONLY. Its tunnel half - a tunnel running on a
#: profile nobody chose - is a query on `integrations.IpsecTunnel`, and a control has one
#: `target_model`, so that half ships nowhere. The stage 8 artifact for `ipsec-crypto` records
#: the choice and names the silent half.
PARTS_BY_CONTROL = {
    "PAN-IPS-001": (_branch,),
    "PAN-IPS-002": (_encryption,),
    "PAN-IPS-003": (_integrity,),
    "PAN-IPS-004": (_dh_group,),
    "PAN-IPS-005": (_lifetime,),
    "PAN-IPS-009": (_unreferenced,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"IPSec crypto profile {obj.profile_name} on {obj.appliance}"]
    # THE DEFAULT IS `()` AND NOT ANOTHER CONTROL'S ARMS. An unmapped control on this model gets
    # the subject line and no claims, which reads as incomplete - and that is the point: the
    # eighteen shipped generators that default to a non-empty tuple describe one control's
    # finding with a different control's assertions, silently and in prose a customer reads.
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_ipsec_crypto_profile_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="IPSec crypto profile",
    control_type=Control.ControlType.IPSEC_CRYPTO_PROFILE,
    finding_model=IpsecCryptoProfileFinding,
    link_model=IpsecCryptoProfileFindingControlQuery,
    subject_fk="ipsec_crypto_profile",
    link_fk="ipsec_crypto_profile_finding",
    queryset=lambda: IpsecCryptoProfile.objects.select_related("appliance"),
    evaluate=evaluate_ipsec_crypto_profile_control_queries,
    summary=build_ipsec_crypto_profile_finding_summary,
    # SET EXPLICITLY, because the spec's default is `obj.name` and this model has no `name`
    # field - which fails at GENERATION time rather than at import.
    subject_name=lambda obj: obj.profile_name,
)


def generate_ipsec_crypto_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_ipsec_crypto_profile_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
