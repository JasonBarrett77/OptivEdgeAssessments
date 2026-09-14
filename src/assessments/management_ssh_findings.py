"""Finding generation for the management SSH controls. PAN-MCR-001 to 005.

The sentence says whether each list came from the BOUND PROFILE or from the DEVICE DEFAULT,
because the remediation differs: a default is fixed by binding a profile, a profile by editing it.
And it says, every time, that a bound profile takes effect only after an SSH service restart -
measured 2026-09-11, a commit alone left the old offer in place - which the configuration cannot
show. A finding that read "the profile restricts MACs" would otherwise be believed of a device
still offering the defaults.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_management_ssh_control_queries
from assessments.models import Control, ManagementSshFinding, ManagementSshFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import ManagementSshSettings

RESTART_CAVEAT = ("A bound SSH profile takes effect only after an SSH service restart, which the "
                  "configuration does not record")


def _source(obj, is_default) -> str:
    return "the device default" if is_default else f"profile {obj.profile_name}"


def _subject(obj) -> str:
    if not obj.profile_name:
        head = f"{obj.appliance} binds no SSH management profile, so it offers the device defaults"
    elif not obj.profile_found:
        head = (f"{obj.appliance} binds SSH management profile {obj.profile_name!r}, which does not "
                f"exist, so it offers the device defaults")
    else:
        head = f"{obj.appliance} binds SSH management profile {obj.profile_name}"
    parts = [head]
    # Each list says WHICH fault put it below the preferred value: members outside the allowed
    # set, or the preferred algorithm missing from an otherwise allowed list. The remediation is
    # the opposite in each case, so the sentence cannot collapse them.
    if obj.ciphers_below_preferred:
        if obj.non_preferred_ciphers:
            detail = (f"ciphers {', '.join(obj.non_preferred_ciphers)} beyond the preferred "
                      f"aes256-gcm/aes256-ctr")
            if obj.offers_cbc_cipher:
                detail += ", CBC mode among them"
        else:
            detail = "no aes256-gcm cipher"
        parts.append(f"{detail}, from {_source(obj, obj.ciphers_default)}")
    if obj.kex_below_preferred:
        if obj.kex_default:
            parts.append("key exchange unrestricted - the device's whole default set, "
                         "diffie-hellman-group14-sha1 included")
        elif obj.non_preferred_kex:
            parts.append(f"key exchange {', '.join(obj.non_preferred_kex)} beyond the preferred "
                         f"ECDH curves, from profile {obj.profile_name}")
        else:
            parts.append(f"no ECDH key exchange, from {_source(obj, obj.kex_default)}")
    if obj.macs_below_preferred:
        if obj.non_preferred_macs:
            detail = (f"MACs {', '.join(obj.non_preferred_macs)} beyond the preferred "
                      f"hmac-sha2-512/hmac-sha2-256")
        else:
            detail = "no hmac-sha2-512 MAC"
        parts.append(f"{detail}, from {_source(obj, obj.macs_default)}")
    # PAN-MCR-004's preferred value is ECDSA 256. A LARGER ECDSA curve is stronger and does not
    # report; `all` does, because it serves an RSA key alongside the ECDSA ones.
    if obj.host_key_type.lower() == "all":
        parts.append("host key type All - an RSA key served alongside every ECDSA curve")
    elif obj.host_key_type.upper() != "ECDSA" or obj.host_key_bits < 256:
        parts.append(f"a {obj.host_key_type} {obj.host_key_bits} host key (preferred: ECDSA 256)"
                     + ("" if obj.profile_found else ", the device default"))
    if not obj.rekey_interval_seconds:
        parts.append("no time-based rekey interval")
    if not obj.defaults_measured and (obj.ciphers_default or obj.macs_default or obj.kex_default):
        parts.append("the device default offer is unmeasured for this PAN-OS version")
    subject = "; ".join(parts)
    if obj.profile_name:
        subject += f". {RESTART_CAVEAT}"
    return subject


def build_management_ssh_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="management SSH server",
    control_type=Control.ControlType.MANAGEMENT_SSH,
    finding_model=ManagementSshFinding,
    link_model=ManagementSshFindingControlQuery,
    subject_fk="management_ssh_settings",
    link_fk="management_ssh_finding",
    queryset=lambda: ManagementSshSettings.objects.select_related("appliance"),
    evaluate=evaluate_management_ssh_control_queries,
    summary=build_management_ssh_finding_summary,
    subject_name=lambda obj: str(obj.appliance),
)


def generate_management_ssh_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_management_ssh_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
