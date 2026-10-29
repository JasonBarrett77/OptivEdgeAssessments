"""How an IKE crypto profile and an IKE gateway READ, in one place for both surfaces.

The configuration explorer's results page and the findings workbook show the same two objects,
and five of their cells are not a field but a reading of several - an offer set with the graded
member marked, a lifetime with the unit it was set in, a re-authentication interval whose zero is
not a small number. `optivedge_integrations.integrations.presentation` is the precedent for
keeping such readings in one module; it lives in the repository that owns the models, and this is
the assessment-side equivalent for a domain whose models that repository already owns.

Written once because the two surfaces disagreeing about what a row says is the failure this
domain's stage exists to catch: a cell that reads "0" on one page and "disabled" on the other
sends an engineer to argue with their own report.

Deliberately free of `django.urls` and of any queryset: it is imported both at request time and
during the workbook build, and the builder runs before any URL resolution.
"""
from __future__ import annotations

from optivedge_integrations.integrations.models import IkeGateway

#: A text column under a `not_assumed` declaration holds the EMPTY STRING for a key nobody read,
#: and that is not the same as a key absent by choice. Spelled out wherever such a column is
#: presented, because a blank cell reads as missing data and says nothing about whether that is
#: expected.
NOT_READ = "Not read"
#: Nothing applies here - the branch this cell describes is not the one the gateway runs.
NOT_APPLICABLE = "–"


def offer_set(members, weakest, *, suffix="") -> str:
    """An algorithm OFFER SET, with the member an exchange can be driven down to marked.

    The profile offers every member and takes the first a peer accepts, so what a control grades
    is the WEAKEST member on offer. The cell has to show the whole set - the weakest alone hides
    what a remediation must delete, and the set alone does not say which member is being graded.

    "Not collected" for an empty list rather than a blank cell or "none": `none` is a REAL member
    of the DH group list, so an empty cell and a profile offering `none` must not read alike.

    WHAT THE LABEL CANNOT SAY. The stored `weakest_*` column is the weakest member ON OFFER, which
    is not the same as the weakest member the control can GRADE: PAN-IKE-002's severity order
    covers the nine classical DH groups and `none`, and places none of the eighteen post-quantum
    members - so on a profile offering only post-quantum groups this marks the member the column
    names while the grading records it `unranked`. Nothing exposes that order to a presentation
    layer, so this cell cannot distinguish the two and does not try.
    """
    if not members:
        return "Not collected"
    lines = [f"{m} (weakest on offer)" if m == weakest else str(m) for m in members]
    return "\n".join(lines + ([suffix] if suffix else []))


def integrity_offer(profile) -> str:
    """The integrity list, and whether an AEAD cipher is on offer beside it.

    `offers_aead_cipher` is not an assertion of its own - it is the condition PAN-IKE-004's
    exception turns on, because the vendor MANDATES `non-auth` alongside AES-GCM. Without it on
    the row, a profile offering `non-auth` and passing reads as a profile that was not checked.
    """
    return offer_set(
        profile.hash_algorithms, profile.weakest_hash_algorithm,
        suffix=("an AEAD cipher is also offered" if profile.offers_aead_cipher
                else "no AEAD cipher offered"))


def key_lifetime(profile) -> str:
    """The lifetime in hours, and the unit the device actually expresses it in.

    THE UNIT IS WHICH CHILD ELEMENT EXISTS and is not a value anywhere on the device, so it
    cannot be a column of its own that a reader compares - and it matters to a remediation:
    writing one branch silently destroys another, with no gate reporting the discard.

    "Not established" rather than a number where `key_lifetime_known` is false. The stored hours
    are NULL there, and a threshold over a NULL passes every bound it was never compared against,
    which is the whole reason that companion column exists.
    """
    if not profile.key_lifetime_known or profile.key_lifetime_hours is None:
        return "Not established"
    unit = (profile.get_key_lifetime_unit_display() or "hours").lower()
    return f"{profile.key_lifetime_hours} h (set in {unit})"


def reauth_interval(profile) -> str:
    """The IKEv2 re-authentication interval: the multiplier times the lifetime, and the verdict.

    ZERO IS NOT A SMALL BOUND. The device's own words are "0 means reauthentication disabled", so
    it is the UNBOUNDED end of the axis while sorting as the smallest number - a cell showing "0"
    in a column of hours would read as the strictest setting on the page.

    The verdict is appended rather than left to a column of its own, because PAN-IKE-005's second
    record asserts on it from a NON-BASELINE query: nothing derives a column for it, so without
    this the row carrying that finding would show no cell explaining it.
    """
    # APPLICABILITY FIRST, and it is the whole reason this cell is not just the number.
    # PAN-IKE-005's second record carries `used_by_ikev2_gateway` as an applicability clause -
    # the multiplier governs re-authentication on the newer protocol version only - so a profile
    # no IKEv2 gateway on this firewall names is OUT of that population. Measured on the stage 6
    # lab: twelve of fourteen profiles read `not bounded` and only two produce a finding, so
    # without this line the tab shows twelve rows carrying a defect they were never assessed for,
    # and two identical-looking rows report differently. That is the third of the three recorded
    # presentation failures, verbatim: a derived scoping clause the row did not explain.
    if not profile.used_by_ikev2_gateway:
        return "Not assessed - no IKEv2 gateway on this firewall names this profile"
    if not profile.authentication_multiple_known or profile.authentication_multiple is None:
        quantity = "Not established"
    elif profile.authentication_multiple == 0:
        quantity = "Disabled (multiple 0)"
    elif profile.reauth_interval_hours is None:
        quantity = f"x{profile.authentication_multiple}, lifetime not established"
    else:
        quantity = f"{profile.reauth_interval_hours} h (x{profile.authentication_multiple})"
    return f"{quantity} — {'bounded' if profile.reauth_interval_bounded else 'not bounded'}"


def gateway_status(gateway) -> str:
    """Whether the gateway is in force. Both states spelled out.

    The device's own switch has NEGATED polarity - `disabled: yes` means off - and it is nullable,
    so every control in this domain clauses on the derived column instead. A blank cell on the
    hardened side would read as missing data.
    """
    return "Active" if gateway.gateway_is_active else "Disabled"


def peer_authentication_detail(gateway) -> str:
    """How the peer is authenticated, in the parts an engineer can act on.

    THE PRE-SHARED KEY'S VALUE IS NEVER STORED, so this is a presence line and never a strength
    one. The two branches are exclusive and the exclusion is enforced by silent replacement at the
    write, so a gateway showing neither is a gateway with no authentication staged - which is
    stated rather than left blank.
    """
    lines = []
    if gateway.uses_pre_shared_key:
        lines.append("Pre-shared key set (value never stored)")
    if gateway.certificate_profile_name:
        lines.append(f"Certificate profile: {gateway.certificate_profile_name}")
    elif gateway.local_certificate_named:
        lines.append("Certificate, no validation profile named")
    if gateway.local_certificate_named:
        lines.append("Local certificate named")
    return "\n".join(lines) or "Nothing staged"


def _switch(known, enabled) -> str:
    """`= false` over a NULL matches nothing, so "not established" is not "off"."""
    if not known or enabled is None:
        return "not established"
    return "on" if enabled else "off"


def ikev2_liveness(gateway) -> str:
    """The IKEv2 branch's idle probe, and nothing about IKEv1.

    IDLE PROBE and not "dead peer detection": the vendor's p.652 says the IKEv2 liveness check is
    always on and that all IKEv2 packets serve its purpose, so a cell reading "off" there would
    be false. What is true is that no idle probe is sent.

    "–" on an ikev1-only gateway: an absent ikev2 key on one asserts nothing and must not
    read as a setting.
    """
    if gateway.ike_version == IkeGateway.IkeVersion.IKEV1:
        return NOT_APPLICABLE
    line = f"Idle probe {_switch(gateway.ikev2_dpd_enabled_known, gateway.ikev2_dpd_enabled)}"
    if gateway.ikev2_dpd_interval is not None:
        line += f", every {gateway.ikev2_dpd_interval}s"
    return line


def ikev1_dpd_retry(gateway) -> str:
    """Probe retries before the peer is declared gone. EXISTS ONLY ON THE IKEV1 BRANCH.

    There is deliberately no column for the ikev1 dpd INTERVAL anywhere in this domain: that key
    carries no field record, so nothing presentable could be reconciled against a measurement.
    """
    if gateway.ike_version == IkeGateway.IkeVersion.IKEV2:
        return NOT_APPLICABLE
    return "Not set" if gateway.ikev1_dpd_retry is None else str(gateway.ikev1_dpd_retry)


def dead_peer_detection(gateway) -> str:
    """Both branches, labelled - for a surface with one cell for the pair.

    The two differ STRUCTURALLY: ikev1/dpd has enable, interval and retry, ikev2/dpd has two
    children, so a line written once for both loses `retry`. Each line is printed only for the
    branch the gateway's version reaches.
    """
    lines = []
    if gateway.ike_version != IkeGateway.IkeVersion.IKEV2:
        line = f"IKEv1 DPD {_switch(gateway.ikev1_dpd_enabled_known, gateway.ikev1_dpd_enabled)}"
        if gateway.ikev1_dpd_retry is not None:
            line += f", retry {gateway.ikev1_dpd_retry}"
        lines.append(line)
    if gateway.ike_version != IkeGateway.IkeVersion.IKEV1:
        lines.append(f"IKEv2 {ikev2_liveness(gateway).lower()}")
    return "\n".join(lines) or NOT_READ


def exchange_mode(gateway) -> str:
    """The ikev1 branch's exchange mode, and no claim about an absent key.

    `auto` is NOT a middle setting - the vendor's p.651 says a device in auto mode accepts both
    main and aggressive negotiation requests - but an ABSENT key is only DOCUMENTED to be auto,
    which this cell does not assert. It says the key is not set and leaves the control's negated
    clause to report it.
    """
    if gateway.ike_version == IkeGateway.IkeVersion.IKEV2:
        return NOT_APPLICABLE
    return gateway.get_ikev1_exchange_mode_display() or "Not set"


def named_crypto_profiles(gateway) -> str:
    """The profiles the two branches name. A gateway has TWO pointers and they can differ.

    NEITHER POINTER SET IS NOT "no crypto": such a gateway still consumes a proposal and nothing
    stored says which, so the cell says so rather than leaving a blank.
    """
    named = []
    if gateway.ikev1_crypto_profile_name:
        named.append(f"IKEv1: {gateway.ikev1_crypto_profile_name}")
    if gateway.ikev2_crypto_profile_name:
        named.append(f"IKEv2: {gateway.ikev2_crypto_profile_name}")
    return "\n".join(named) or "None named - the device resolves one"
