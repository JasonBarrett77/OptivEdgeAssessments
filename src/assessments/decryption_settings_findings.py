"""Finding generation for one appliance's forward-proxy signing designation. PAN-DCP-006.

THE SUBJECT IS THE APPLIANCE AND NOT THE DESIGNATION SLOT, and the commonest failing state
decides it: NO certificate designated at all. `/config/shared/ssl-decrypt` was absent on three of
the four lab appliances, and the firewall says so in its own words - `show system setting
ssl-decrypt certificate` answers `No SSL Decryption CERT`. A finding keyed on a slot would have
no row to report on in exactly the state the control exists for.

TWO ASSERTIONS, AND EACH OF THEM IS FALSE IN TWO DIFFERENT WAYS. That is why the sentence has to
say WHICH, because the two states carry different remediations and a reader who has seen one
expects the other to look like it:

* `forward_trust_is_designated_local_ca` is false where NOTHING is designated and false where
  something IS and it does not resolve to a self-signed certificate authority this appliance
  holds. The first is remediated by generating an authority; the second by replacing the one that
  is there, which may be a publicly-chained certificate - the worst case this control exists for,
  because a copy of that key impersonates any site to anybody rather than only to this estate.
* `untrust_distinct_from_trust` is false where NO untrust authority is designated and false where
  one is designated and a trust slot names the SAME certificate. The first leaves the
  certificate warning behind every blocking check unproduced; the second produces a warning the
  client will not show, because the certificate is one it already trusts. Neither is milder.

A DESIGNATION NAMING A CERTIFICATE THAT DOES NOT EXIST IS REPORTED AS A FAILURE, which is the
integrations verdict's own direction and is deliberate - a designation pointing at nothing is a
worse state than no designation, not a better-evidenced one.

AND THIS SENTENCE CANNOT SAY WHICH OF THAT VERDICT'S THREE FAILING STATES IT FOUND, which is a
boundary rather than an omission. `test_query_service_boundary` forbids any module outside
`assessments/search/` from filtering a normalized model by a field lookup, with the reason that a
module reaching around normalization "decides what the configuration means privately, where no
payload contract records it and no test pins it". The first draft of this module resolved the
designated name into `Certificate` to read `is_ca` and `is_self_signed` and say which of the three
states applied; the gate refused it, correctly, and the same argument that makes the verdict a
COLUMN rather than a clause - a predicate cannot traverse - applies to a finding sentence too.
So the trust arm names the slots and the verdict and sends the reader to the certificate store.
Discriminating the three needs either a second column on the signing model or the certificate's
own values presented beside the finding, and neither is this stage's to add.

WHAT THIS GENERATOR CANNOT SAY, and it is two of the control's four assertion records. Whether
the signing key can be exported is an argument to an operational request at the moment a
certificate is generated: there is no configuration node for it anywhere in the grammar, so no
column carries it and no clause can reach it. Whether the authority is short-lived with a
rehearsed replacement procedure is a question for a person. Both are discharged by stage 5 as
owing no query, so neither reaches a reader through this sentence and the audit text is where
they are asked.

THE PER-CONTROL DISPATCH IS KEYED WITH NO DEFAULT, which is the convention the `user-id` run
established after measuring the alternative: a dispatch whose fallback is some control's own arms
describes a DIFFERENT control's finding with those claims. One control uses this model today; an
unrecognised id contributes the subject line and no claim, which is thin rather than wrong.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_decryption_settings_control_queries
from assessments.models import (
    Control,
    DecryptionSettingsFinding,
    DecryptionSettingsFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import DecryptionSettings

#: (column, the label the vendor's own dialog uses for that slot).
_TRUST_SLOTS = (
    ("forward_trust_cert_rsa", "Forward Trust Certificate (RSA)"),
    ("forward_trust_cert_ecdsa", "Forward Trust Certificate (ECDSA)"),
)
_UNTRUST_SLOTS = (
    ("forward_untrust_cert_rsa", "Forward Untrust Certificate (RSA)"),
    ("forward_untrust_cert_ecdsa", "Forward Untrust Certificate (ECDSA)"),
)


def _filled(obj, slots) -> list[tuple[str, str]]:
    """(label, name) for every slot that holds a certificate name."""
    return [(label, getattr(obj, column)) for column, label in slots if getattr(obj, column)]


def _trust_designation(obj) -> list[str]:
    """PAN-DCP-006[0]: the trusted-site signing authority is one the organisation issued."""
    if obj.forward_trust_is_designated_local_ca:
        return []
    filled = _filled(obj, _TRUST_SLOTS)
    if not filled:
        return [
            "NO FORWARD-TRUST SIGNING AUTHORITY IS DESIGNATED ON THIS APPLIANCE. Neither the RSA "
            "nor the ECDSA slot of `/config/shared/ssl-decrypt` holds a certificate name, so "
            "there is no authority configured for the firewall to sign with when it stands in "
            "for a destination it trusts - which is also this appliance's own out-of-the-box "
            "state, so nothing distinguishes an appliance that was never set up from one set up "
            "wrongly",
        ]
    return [
        "THE DESIGNATED FORWARD-TRUST AUTHORITY IS NOT ONE THE ORGANISATION ISSUED AND CONTROLS: "
        + "; ".join(f"{label} names `{name}`" for label, name in filled)
        + ". The stored verdict is that at least one designated slot does not resolve to a "
          "self-signed certificate authority this appliance holds, and the quantifier is that "
          "EVERY filled slot must qualify - an RSA slot naming a local authority beside an ECDSA "
          "slot naming a third-party certificate does not pass, because the weaker of the two is "
          "what a session can end up negotiating. WHICH OF THREE STATES IT IS, THIS FINDING "
          "CANNOT SAY: the name may match no certificate on this appliance at all, or it may "
          "match one that is not a certificate authority, or one that is an authority and is not "
          "self-signed. Those three are read off the certificate store, which this control's "
          "subject is not - see the audit text",
    ]


def _untrust_distinct(obj) -> list[str]:
    """PAN-DCP-006[1]: a separate untrusted-site authority exists and no client trusts it."""
    if obj.untrust_distinct_from_trust:
        return []
    untrust = _filled(obj, _UNTRUST_SLOTS)
    if not untrust:
        return [
            "NO FORWARD-UNTRUST AUTHORITY IS DESIGNATED ON THIS APPLIANCE, so the firewall signs "
            "its stand-in for a destination it COULD NOT validate with the same material it uses "
            "for one it could. The certificate warning that is the last line behind every "
            "blocking check - PAN-DCP-003's expiry check and PAN-DCP-004's untrusted-issuer "
            "check both rely on it - is therefore never produced at all",
        ]
    trust_names = {name for _label, name in _filled(obj, _TRUST_SLOTS)}
    shared = [(label, name) for label, name in untrust if name in trust_names]
    if shared:
        return [
            "THE FORWARD-UNTRUST AUTHORITY IS THE SAME CERTIFICATE AS A FORWARD-TRUST ONE: "
            + "; ".join(f"{label} names `{name}`, which a forward-trust slot also names"
                        for label, name in shared)
            + ". Every destination the firewall could not validate then arrives at the user "
              "behind a certificate the client has been told to trust, so the warning looks like "
              "nothing at all and the safety net has been removed without anybody removing it",
        ]
    # THIS ARM IS REACHABLE ONLY ON A STALE ROW, and it is here rather than left as silence: the
    # verdict is computed from these same four columns, so a false verdict with an untrust slot
    # filled and no trust slot naming it means the row has not been recomputed. Printing nothing
    # on a finding that fired is the shape `_antivirus_gaps` in the profile generator exists to
    # prevent.
    return [
        "the stored forward-untrust verdict reports a failure that this appliance's own "
        "designation slots no longer explain - an untrust authority is designated and no "
        "forward-trust slot names it - which means the row has not been recomputed since the "
        "configuration it describes was collected",
    ]


#: WHICH FACTS THIS CONTROL'S FINDING MAY STATE. Keyed by control id and read with NO DEFAULT:
#: a dispatch falling back to some control's own arms describes a different control's finding
#: with that control's claims, which is a measured defect in a shipped module of this repository.
_PARTS_BY_CONTROL = {
    "PAN-DCP-006": (_trust_designation, _untrust_distinct),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"the forward-proxy signing designation on {obj.appliance}"]
    for build in _PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_decryption_settings_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="forward-proxy signing designation",
    control_type=Control.ControlType.DECRYPTION_SETTINGS,
    finding_model=DecryptionSettingsFinding,
    link_model=DecryptionSettingsFindingControlQuery,
    subject_fk="decryption_settings",
    link_fk="decryption_settings_finding",
    queryset=lambda: DecryptionSettings.objects.select_related("appliance"),
    evaluate=evaluate_decryption_settings_control_queries,
    summary=build_decryption_settings_finding_summary,
    # The appliance's hostname. Unique in an estate, which is why this model declares no
    # `subject_scope` - there is nothing for one to disambiguate.
    subject_name=lambda obj: str(obj.appliance),
)


def generate_decryption_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_decryption_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
