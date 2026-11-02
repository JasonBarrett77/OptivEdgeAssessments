"""How an IPSec crypto profile and an IPSec tunnel READ, in one place for both surfaces.

The configuration explorer's results page and the findings workbook show the same two objects,
and most of their interesting cells are not a field but a reading of several - an offer set with
the graded member marked, a lifetime whose number means nothing without the unit it was written
in, a profile reference that may never have been written at all. `ike_presentation` is the
assessment-side precedent for the sibling phase-1 objects, and
`optivedge_integrations.integrations.presentation` is the precedent for keeping such readings in
one module at all.

Written once because the two surfaces disagreeing about what a row says is the failure this
domain's stage exists to catch: a cell that reads "0" on one page and "nothing names it" on the
other sends an engineer to argue with their own report.

WHY SO MANY OF THESE ARE REACHED THROUGH `DeviceSettingSheet.value_readers` RATHER THAN THROUGH A
SUBJECT COLUMN, which is the thing this module does that `ike_presentation` does not. The shared
`findings.display_value` has exactly three answers - a value, `(none)` for NULL and `(empty)` for
the empty string - and it is shared by every tab, so a DERIVED setting column cannot say "this
branch does not exist on this subject". On this domain that gap is not cosmetic: a profile on the
integrity-only AH branch stores the EMPTY STRING in `weakest_encryption_offered`, PAN-IPS-002
fires on it and marks that cell, and the unimproved row therefore offers `(empty)` as the thing to
fix on a profile that has no encryption branch to fix. `value_readers` is declared PER SHEET and
is consulted by `setting_columns` before `display_value`, so it is the escape from that vocabulary
that keeps the field in its derived position, keeps the mark on it, and leaves `display_value`
untouched for every other tab.

Deliberately free of `django.urls` and of any queryset: it is imported both at request time and
during the workbook build, and the builder runs before any URL resolution.
"""
from __future__ import annotations

from optivedge_integrations.integrations.models import IpsecCryptoProfile

#: Nothing applies here - the branch or the binding this cell describes is not one this subject
#: has. U+2014 EM DASH, which is `artifacts.layout.NONE`'s own character: the two are asserted
#: equal by `tests/test_ipsec_tabs.py` rather than imported, because `artifacts.layout` is a
#: workbook module and this one is imported at request time.
#:
#: `ike_presentation.NOT_APPLICABLE` is U+2013 EN DASH, which is a divergence and not a
#: convention - four stage 9 artifacts called `layout.NONE` an en-dash until the `certificates`
#: run measured it on 2026-11-02.
NOT_APPLICABLE = "—"
#: The key was never read, which is not the same as the key being set to off. Spelled out
#: wherever a nullable switch is presented: a blank or a `(none)` cell reads as missing data and
#: says nothing about whether that is expected.
NOT_READ = "Not read"
#: A verdict column whose row has not been recomputed since the migration that added it. Every
#: such column on both of these models defaults to its FIRING side, so this state is reported
#: rather than silently passed - the cell says which it is.
NOT_RECOMPUTED = "Not recomputed"


#: `null` at `esp/encryption` IS A CIPHER AND NOT A MISSING VALUE - it is the one that encrypts
#: nothing, and it is the WORST member of PAN-IPS-002's order. Printed bare it reads as absent
#: data in a column of algorithm names, which inverts the row: the most alarming cell on it would
#: look like the one nobody filled in. Named wherever a member list or a weakest member is shown.
CLEARTEXT_CIPHER = "null"


def _member(name) -> str:
    return "null (the cleartext cipher - it encrypts nothing)" if name == CLEARTEXT_CIPHER \
        else str(name)


def _offer_set(members, weakest) -> str:
    """An algorithm OFFER SET, with the member an exchange can be driven down to marked.

    The profile offers every member and takes the first a peer accepts, so what a control grades
    is the WEAKEST member on offer. The cell has to show the whole set - the weakest alone hides
    what a remediation must delete, and the set alone does not say which member is being graded.

    A NULL list is NOTHING OFFERED and is said in those words. Stage 4 measured that an absent
    list carries no implicit algorithm behind it, and `none` is a REAL member of the ESP integrity
    list that both shipped Suite-B profiles store - so "nothing offered" and "`none` is offered"
    must not read alike, and neither may read as a blank cell.
    """
    if not members:
        return "Nothing offered"
    return "\n".join(f"{_member(m)} (weakest on offer)" if m == weakest else _member(m)
                     for m in members)


def protocol_branch(profile) -> str:
    """WHICH branch protects the payload, in the vendor's own words for it.

    Read through the choices display rather than printed raw, because the raw token for the third
    state is `none` and `display_value`'s word for a NULL is `(none)`: a reader meeting `none` in
    this column cannot tell "the firewall carries neither branch" from "this cell is empty". The
    branches are mutually exclusive on a device and that is measured in both directions, so there
    are exactly three answers and the blank below is a fourth that is ours and not the device's.
    """
    return profile.get_protocol_branch_display() or NOT_RECOMPUTED


def esp_encryption_offered(profile) -> str:
    """The cipher proposals on the ESP branch. An em dash where there is no ESP branch.

    The AH branch has no encryption at all - that is what makes it a finding - so a cipher cell
    on an AH profile is not an unmeasured one, it is an inapplicable one.
    """
    if profile.protocol_branch != IpsecCryptoProfile.ProtocolBranch.ESP:
        return NOT_APPLICABLE
    return _offer_set(profile.esp_encryption, profile.weakest_encryption_offered)


def esp_integrity_offered(profile) -> str:
    """The ESP branch's integrity algorithms, and whether the ciphers beside them authenticate.

    `all_offered_ciphers_authenticate` is not an assertion of its own - it is the condition
    PAN-IPS-003's APPLICABILITY clause turns on, because the vendor states the separate hash is
    ignored for an AEAD cipher (gp p.877). Without it on the row, a profile offering `none` and
    reporting nothing reads as a profile that was not checked. It has a derived column of its own
    beside this one; this line is what makes the two cells read across.
    """
    if profile.protocol_branch != IpsecCryptoProfile.ProtocolBranch.ESP:
        return NOT_APPLICABLE
    offered = _offer_set(profile.esp_authentication, profile.weakest_integrity_offered)
    aead = ("every offered cipher authenticates as it encrypts"
            if profile.all_offered_ciphers_authenticate
            else "a cipher that only encrypts is offered")
    return f"{offered}\n({aead})"


def ah_integrity_offered(profile) -> str:
    """The AH branch's integrity algorithms, where the profile is on that branch.

    A SEPARATE CELL FROM THE ESP ONE, and the model says why: stage 4 measured that ONE grid
    column on the device serves both branches, so a reading taken off the screen cannot say which
    branch's list it came from. Two cells is the shape that can. The literal `none` is REFUSED
    here and accepted on ESP, measured in both directions, so this list never carries it.
    """
    if profile.protocol_branch != IpsecCryptoProfile.ProtocolBranch.AH:
        return NOT_APPLICABLE
    return _offer_set(profile.ah_authentication, profile.weakest_integrity_offered)


def integrity_offered(profile) -> str:
    """Both branches' integrity lists in ONE cell, for a surface that has only one to give it.

    The two differ STRUCTURALLY rather than by name - the ESP list may carry the literal `none`
    and the AH list may not, measured in both directions - so this prints only the branch the
    profile is actually on, and names it. The workbook's wider row keeps the two apart; the
    explorer's results page has eight columns for the whole object.
    """
    if profile.protocol_branch == IpsecCryptoProfile.ProtocolBranch.ESP:
        return esp_integrity_offered(profile)
    if profile.protocol_branch == IpsecCryptoProfile.ProtocolBranch.AH:
        return f"AH branch:\n{ah_integrity_offered(profile)}"
    return "Neither branch, so no integrity algorithm is offered"


def weakest_cipher(profile) -> str:
    """The graded member of the cipher offer set - the value PAN-IPS-002 asserts on.

    THE EMPTY STRING IS TWO DIFFERENT THINGS HERE AND NEITHER IS A CIPHER. On a profile with no
    ESP branch nothing is offered, so there is no weakest member to name; on a row nobody has
    recomputed the column has never been written. Both store `''`, and `display_value` prints
    `(empty)` for both - which PAN-IPS-002 then MARKS as the value at fault, offering `(empty)`
    as the thing an engineer should change.
    """
    if profile.weakest_encryption_offered:
        return _member(profile.weakest_encryption_offered)
    if profile.protocol_branch == IpsecCryptoProfile.ProtocolBranch.AH:
        return "No cipher is offered - the AH branch only authenticates"
    if profile.protocol_branch == IpsecCryptoProfile.ProtocolBranch.NONE:
        return "No cipher is offered - the profile carries neither branch"
    return NOT_RECOMPUTED


def weakest_integrity(profile) -> str:
    """The graded member of whichever integrity list the profile's branch has.

    `none` here always means integrity DECLINED beside a cipher that only encrypts: the AEAD case
    is excluded by PAN-IPS-003's applicability clause rather than scored, so this column's `none`
    is never the harmless one. Said in the cell because the distinction decides whether the row
    beside it is a finding.
    """
    # The literal string, not `ProtocolBranch.NONE`, although the two spell the same word: this
    # is a member of the integrity list and has nothing to do with which branch exists.
    #
    # AND IT IS TWO DIFFERENT FACTS, WHICH THE FIRST VERSION OF THIS CELL GOT WRONG ON A REAL ROW.
    # It read "none - integrity declined" wherever the member was `none`, on the model docstring's
    # reasoning that the AEAD case is excluded by PAN-IPS-003's applicability clause rather than
    # scored. That is true of the rows PAN-IPS-003 REPORTS ON and this column is filled on every
    # row of the tab: `Suite-B-GCM-128` is a PAN-IPS-002 row whose only cipher is `aes-128-gcm`,
    # so its `none` is the one the VENDOR MANDATES (gp p.877: the separate hash "is ignored for
    # these ciphers even though it is required during configuration") - and the cell called it a
    # declined integrity algorithm beside a finding about something else entirely.
    if profile.weakest_integrity_offered == "none":
        if profile.all_offered_ciphers_authenticate:
            return "none - not required: every offered cipher authenticates as it encrypts"
        return "none - integrity declined beside a cipher that only encrypts"
    if profile.weakest_integrity_offered:
        return profile.weakest_integrity_offered
    if profile.protocol_branch == IpsecCryptoProfile.ProtocolBranch.NONE:
        return "No integrity algorithm is offered - the profile carries neither branch"
    return NOT_RECOMPUTED


def key_lifetime(profile) -> str:
    """The lifetime in hours, and the unit the administrator actually wrote it in.

    THE UNIT IS WHICH CHILD ELEMENT EXISTS and is not a value anywhere on the device, so it
    cannot be a column a reader compares - and it matters to a remediation: stage 4 measured that
    an element naming several units is ACCEPTED and only the LAST one lands, so a tool that sends
    two gets no error and a value it did not choose.

    The hours are the CONVERSION and the only figure stored; the unit is where to go and change
    it. A profile written in days holds nothing at all at the hour branch.
    """
    if profile.lifetime_hours is None:
        return "Not established"
    unit = profile.get_lifetime_unit_display() or "an unmapped unit"
    return f"{profile.lifetime_hours} h (written in {unit.lower()})"


def referencing_tunnels(profile) -> str:
    """How many tunnel configurations on THIS appliance name this profile.

    "Nothing names it" rather than a bare 0, which is this repository's own rule for a reference
    count: `configuration_results._nothing` says a bare zero in a reference column reads as "not
    counted" exactly where it means "counted, and the answer was none". Here zero is the finding,
    so reading it as "not counted" inverts the row.

    A FIREWALL-SIDE COUNT CANNOT SAY AN OBJECT IS UNUSED, which is why this says what it counted:
    a profile nothing on the device names may still be named by configuration held at the
    management station, and the two states look identical from here.
    """
    count = profile.referencing_tunnel_count
    if not count:
        return "Nothing on this firewall names it"
    return f"{count} tunnel configuration(s) on this firewall"


def replay_protection(tunnel) -> str:
    """The `anti-replay` switch, with the unread state named.

    NULL IS THE HONEST ANSWER AND NOT A CONVENIENCE - stage 4 recorded this implicit as UNMEASURED
    with three leads and promoted none - and a null boolean matches no positive comparison, so
    `anti_replay equals false` does not reach a tunnel whose key is simply absent. The firing is
    moved to `anti_replay_determined`, which has a derived column of its own and is the cell those
    findings mark. This one says why that cell is the one that is marked.
    """
    if tunnel.anti_replay is None:
        return NOT_READ
    return "On" if tunnel.anti_replay else "Off"


def far_end_monitoring(tunnel) -> str:
    """The `tunnel-monitor/enable` switch, with the unread state named.

    Same unmeasured implicit and same companion arrangement as the switch above, and the stake is
    larger: an absent monitor branch is the COMMONEST shape of the failure PAN-IPS-007 is about,
    so a cell reading "Off" there would claim a measurement nobody took on exactly the tunnels
    the control exists to find.
    """
    if tunnel.tunnel_monitor_enable is None:
        return NOT_READ
    return "On" if tunnel.tunnel_monitor_enable else "Off"


def monitor_probe(tunnel) -> str:
    """The address the monitor probes. NULL MEANS NO PROBE TARGET, measured at the commit gate.

    Not a blank cell: with monitoring enabled and the target deleted, commit validation refuses
    the configuration naming this exact key - so "no target" is a state with a consequence rather
    than a gap in the reading.
    """
    return tunnel.tunnel_monitor_destination_ip or "No probe target"


def monitor_profile_named(tunnel) -> str:
    """The monitor profile this tunnel's monitoring names.

    A NAME THAT DOES NOT RESOLVE IS A DELETION AND NOT A TYPO: stage 4 measured that a name which
    does not exist is refused AT THE WRITE, while deleting a profile a live tunnel-monitor names
    is accepted with no complaint. So a name here that `Monitor action` cannot answer for means
    somebody removed the far end of the binding.
    """
    return tunnel.tunnel_monitor_profile_name or "None named"


def monitor_action(tunnel) -> str:
    """What the monitoring WOULD DO when probing fails - the action of the profile it names.

    THE PROFILE IS A DIFFERENT OBJECT AND IT HAS NO TAB OF ITS OWN. `MonitorProfile` is stored
    and normalised and no shipped query names it, so it earns no rail entry and no findings tab -
    and this cell is the only place in the whole report where its content reaches a reader. The
    resolution is the normaliser's, on the same appliance, and includes the named profile's own
    materialised default where it stores no action.

    THREE DIFFERENT STATES STORE THE EMPTY STRING and they need opposite remediations, so the cell
    tells them apart rather than printing one blank for all three: the tunnel names no profile,
    the name resolves to nothing, or the row has not been recomputed. The first two are told apart
    by `tunnel_monitor_profile_name`, which is the column beside this one.
    """
    if tunnel.monitor_action_effective:
        return tunnel.get_monitor_action_effective_display()
    if not tunnel.tunnel_monitor_profile_name:
        return NOT_APPLICABLE
    return (f"{tunnel.tunnel_monitor_profile_name} does not resolve on this appliance, "
            f"so no action is defined")


def crypto_profile_named(tunnel, provenance_of=None) -> str:
    """The IPSec crypto profile the tunnel's auto-key branch names - A POINTER AND NOT A VALUE.

    WHERE THE KEY IS ABSENT THE COLUMN HOLDS THE LITERAL `default` AND THAT IS AN INFERENCE. Stage
    4 set `may_materialise: false` on three leads and not one measurement, so the declaration is
    `Implicit.assumed` and the row must not print it as a reading. The inference is the reason
    PAN-IPS-009 can fire at all - a materialised `default` is exactly "running on a profile nobody
    chose" - so it cannot be allowed to reassure either.

    `provenance_of` is what makes that sayable HERE rather than nowhere. The Provenance cell on
    this tab answers per TESTED field, and no clause in this domain reads this column, so the
    recorded `assumed_default` on it would otherwise reach no cell on the row at all - which is
    the shape P420 is about. It is optional so the explorer's results page, which has no
    provenance index, can call the same function.
    """
    name = tunnel.crypto_profile_name or "Nothing named"
    row = provenance_of("crypto_profile_name") if provenance_of is not None else None
    assumed = row is not None and row.provenance_type == "assumed_default"
    return f"{name} (inferred - the tunnel writes no reference)" if assumed else name


def crypto_profile_resolves(tunnel) -> str:
    """Whether the name the tunnel carries resolves to an entry in THIS appliance's collection.

    False with a name set is a dangling binding, and on this lab it is the MAJORITY state: the
    literal `default` resolves to nothing on both PA-5220s and on pan-fw-111, measured. So the
    reassuring-looking answer here is the rare one and the cell says which it is.
    """
    if tunnel.crypto_profile_found:
        return "Yes"
    return "No - the name resolves to no entry on this appliance"


def running_on_a_chosen_profile(tunnel) -> str:
    """Whether the profile this tunnel actually runs on is one somebody CHOSE AND HARDENED.

    THE TEST IS ON CONTENT AND NOT ON THE NAME, and a measurement is why: the factory-named
    entries are ordinary writable local config, present on one of four lab appliances and
    deletable, so a renamed copy of the shipped proposal passes a name test, a hand-made weak
    profile passes it too, and on an appliance where the shipped entry was deleted a name test is
    vacuously satisfied. The naive test passes exactly the configuration this one fails.

    IT HAS NO CONTROL REPORTING ON IT. PAN-IPS-009's first stage 5 record asserts on this column
    over the tunnel, its second asserts over the crypto profile, and a `Control` is one model per
    control type - so stage 8 could ship only the profile half, and did. The column is therefore
    on the row, is markable, and nothing will ever mark it. Said in the cell because the tab
    carries a control whose NAME promises a reader both halves.
    """
    if tunnel.effective_crypto_profile_chosen:
        return "Yes"
    return "No - nobody chose or hardened it (not reported by any control)"
