"""Finding generation for anti-spyware and vulnerability profile controls. PAN-SPY-001, PAN-VLN-001.

The subject sentence names the severity that is not blocked AND why. Two profiles failing the same
severity can fail it for different reasons - an alert rule, or no catch-all rule at all - and the
fix differs. A predefined profile is named as predefined, with how many things use it: it cannot
be edited, so the remediation is to stop using it rather than to change it.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_security_profile_control_queries
from assessments.models import Control, SecurityProfileFinding, SecurityProfileFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import SecurityProfile

KIND_LABELS = dict(SecurityProfile.KIND_CHOICES)


def profile_owner(obj) -> str:
    """The appliance group for shared scope, `group / vsys` for vsys and predefined scope."""
    return obj.appliance_group.name if obj.appliance_group_id else str(obj.enforcement_point)


def _gaps(obj) -> list[str]:
    """The severities this profile fails, and why.

    `blocked is False` rather than `not blocked`: None means the profile does not assess that
    severity at all, which is not a gap.

    THREAT-RULE KINDS ONLY. This used to add that no control reaches it with a None, because
    the queries could not match a profile with no verdict row. PAN-AVW-001 and PAN-AVW-002 do -
    an antivirus profile has no severity rules at all - and the `blocked is False` test held,
    so the finding simply reported no gaps and the caller asserted the profile was fine.
    Guarding the value was not enough; the CALLER had to stop asking this kind the question.
    See `_antivirus_gaps`.
    """
    return [f"{severity}: {detail}" for severity, blocked, detail in (
        ("critical", obj.critical_blocked, obj.critical_detail),
        ("high", obj.high_blocked, obj.high_detail),
    ) if blocked is False]


def _antivirus_gaps(obj) -> list[str]:
    """What an ANTIVIRUS profile lets through, by verdict source.

    An antivirus profile has no severity rules, so `_gaps` - which reads the critical and high
    verdicts - returns nothing for one and the sentence fell through to "blocks critical and
    high threats". That was printed on every antivirus finding, including the shipped `default`
    profile that alerts on three mail decoders: the reassuring sentence, on the finding
    reporting the profile as failing. Measured against the lab 2026-10-08.

    Each entry names the verdict source as the UI column names it, because an engineer has to
    find the column to change it and the three look identical in the config.
    """
    gaps = []
    if obj.non_blocking_decoders:
        gaps.append(f"signature action allows on {', '.join(obj.non_blocking_decoders)}")
    if obj.non_blocking_wildfire_decoders:
        gaps.append("WildFire signature action allows on "
                    f"{', '.join(obj.non_blocking_wildfire_decoders)}")
    if obj.non_blocking_mlav_decoders:
        gaps.append("WildFire inline ML action allows on "
                    f"{', '.join(obj.non_blocking_mlav_decoders)}")
    if obj.non_blocking_application_overrides:
        gaps.append("application exceptions override the decoder for "
                    f"{', '.join(obj.non_blocking_application_overrides)}")
    if obj.non_blocking_ml_models:
        gaps.append("inline ML models not blocking: "
                    f"{', '.join(obj.non_blocking_ml_models)}")
    return gaps


def _url_filtering_gaps(obj) -> list[str]:
    """What a URL FILTERING profile permits, by the question each control asks. PAN-URL-001 to
    -005.

    THE SAME DEFECT SHAPE `_antivirus_gaps` EXISTS TO PREVENT, met a second time. A url-filtering
    profile has no severity rules, so `_gaps` returns nothing for it, the DNS and brute-force
    verdicts are None, and `_subject`'s final clause asserted that the profile "blocks critical
    and high threats" - printed on the finding that was reporting it as failing. Measured on this
    domain's census, 2026-11-01. Guarding the values was not enough for antivirus and it is not
    enough here: the CALLER has to stop asking this kind the threat-rule question.

    EVERY VERDICT READ HERE IS A STORED CONCLUSION over the device's own category catalogue minus
    the profile's member lists, so each clause names the WORST member as well as the verdict - a
    reader has to know which category or header to go and change, and the catalogue is not in the
    profile.

    `is False` rather than falsy throughout, for the reason the threat-rule clauses give: these
    are non-null booleans today, but a null would mean this kind writes no row and makes no
    claim, which is not the same as a gap.
    """
    gaps = []
    if obj.all_hostile_categories_blocked is False:
        worst = obj.weakest_hostile_category_action or "an action that was not established"
        gaps.append("does not refuse the confirmed-hostile categories "
                    f"(command-and-control, malware, phishing; weakest action {worst})")
    if obj.all_reachable_categories_logged is False:
        worst = obj.worst_reachable_unlogged_category or "a category that was not established"
        gaps.append(f"permits categories without logging them (worst: {worst})")
    if obj.credential_detection_mode == SecurityProfile.CREDENTIAL_MODE_DISABLED:
        gaps.append("detects no corporate credential submissions at all")
    elif obj.all_reachable_categories_credential_restricted is False:
        worst = obj.worst_credential_permissive_category or "a category that was not established"
        gaps.append("accepts corporate credentials on categories it permits "
                    f"(worst: {worst})")
    if obj.records_all_request_headers is False:
        missing = ", ".join(obj.unrecorded_request_headers or []) or "a header not established"
        gaps.append(f"does not record the request headers {missing}")
    if obj.cloud_inline_categorization is False:
        gaps.append("has cloud-side inline categorization switched off")
    if obj.local_inline_categorization_on is False:
        # THE ONE CLAUSE THAT MAY BE WRONG ON THE ROW IT IS PRINTED ON, and it says so. On a
        # PA-VM an absent `local-inline-cat` key means the on-box engine IS ON; on a PA-5220 it
        # means off. Stage 4 measured the condition as the APPLIANCE and the normalizer stores
        # false for the absence, so this is a FALSE POSITIVE on every PA-VM profile that stores
        # nothing. `local_inline_categorization_undetermined` is true on exactly those rows.
        if obj.local_inline_categorization_undetermined:
            gaps.append("may have on-box inline categorization switched off - the key is absent "
                        "and what an absence means here depends on the platform, so this one "
                        "needs a look at the profile rather than a change to it")
        else:
            gaps.append("has on-box inline categorization switched off")
    if obj.inline_analysis_exemption_count:
        broadest = obj.broadest_inline_analysis_exemption_type or "a type that was not resolved"
        gaps.append(f"exempts {obj.inline_analysis_exemption_count} custom "
                    f"categor{'y' if obj.inline_analysis_exemption_count == 1 else 'ies'} from "
                    f"real-time analysis (broadest: {broadest})")
    return gaps


#: THE TWELVE BLOCK SWITCHES PAN-DCP-003, -004 and -005 ASSERT ON, each labelled as the vendor's
#: own dialog labels it, because an engineer has to find the checkbox to tick it and the forward-
#: and inbound-proxy tabs carry near-identical wording. The two containers are NOT symmetric:
#: `block-expired-certificate` and `block-untrusted-issuer` exist on the forward tab only,
#: because an inbound-proxy session presents the organisation's own certificate and there is no
#: issuer to distrust.
_DECRYPTION_BLOCK_CHECKS = (
    ("fwd_block_expired_certificate", "forward proxy: block sessions with expired certificates"),
    ("fwd_block_untrusted_issuer", "forward proxy: block sessions with untrusted issuers"),
    ("fwd_block_unsupported_version", "forward proxy: block sessions with unsupported versions"),
    ("fwd_block_unsupported_cipher", "forward proxy: block sessions with unsupported cipher suites"),
    ("inb_block_unsupported_version", "inbound inspection: block sessions with unsupported versions"),
    ("inb_block_unsupported_cipher",
     "inbound inspection: block sessions with unsupported cipher suites"),
    ("fwd_block_if_no_resource", "forward proxy: block sessions if resources not available"),
    ("fwd_block_tls13_downgrade_no_resource",
     "forward proxy: block downgrade from TLS 1.3 to 1.2 if resources not available"),
    ("inb_block_if_no_resource", "inbound inspection: block sessions if resources not available"),
    ("inb_block_tls13_downgrade_no_resource",
     "inbound inspection: block downgrade from TLS 1.3 to 1.2 if resources not available"),
    ("fwd_block_if_hsm_unavailable", "forward proxy: block sessions if HSM not available"),
    ("inb_block_if_hsm_unavailable", "inbound inspection: block sessions if HSM not available"),
)


def _decryption_gaps(obj) -> list[str]:
    """What a DECRYPTION profile still permits, by the question each control asks. PAN-DCP-001 to
    -005 and -007.

    THE SAME DEFECT SHAPE `_antivirus_gaps` AND `_url_filtering_gaps` EXIST TO PREVENT, met a
    third time and recorded as such by both of their docstrings. A decryption profile writes no
    severity-verdict satellite row, so `_gaps` returns nothing for it, the two DNS verdicts and
    `brute_force_blocked_by_source` are all None, and `_subject`'s closing clause asserted that
    the profile "blocks critical and high threats" - printed on the finding reporting it as
    failing. Guarding the VALUES was not enough for antivirus and not enough for url-filtering:
    the CALLER has to stop asking this kind the threat-rule question, which is what the
    `KIND_DECRYPTION` guard below does.

    THE TWO POLARITIES ARE BOTH HERE AND THE COLUMN NAMES DO NOT ANNOUNCE THE CHANGE. The three
    verdicts are written in the FIRING direction, so TRUE is the defect; the twelve `*_block_*`
    switches are the vendor's own BLOCK keys, so FALSE is the defect - the check is not performed.
    Each clause below says which it is reading.

    EACH PRIMITIVE CLAUSE NAMES THE WORST MEMBER AND IS SILENT ABOUT THE REST, which is the
    composed column's own documented cost: where two broken primitives are permitted the column
    holds only the worse, so a sentence naming RC4 says nothing about SHA-1 on the same profile.
    The seven per-primitive booleans exist to be READ for exactly that reason, which is stage 9's
    business and not this sentence's.

    `is True` / `is False` throughout rather than truthiness, for the reason the threat-rule
    clauses give: these are non-null columns today, but a null would mean this kind writes no
    value and makes no claim, which is not the same as a gap.
    """
    gaps = []
    if obj.ssl_min_version_below_tls12 is True:
        floor = obj.ssl_min_version or "a floor that was not recorded"
        gaps.append("lets a decrypted session negotiate below TLS 1.2 "
                    f"(protocol floor {floor})")
    if obj.ssl_max_version_restrictive is True:
        ceiling = obj.ssl_max_version or "a ceiling that was not recorded"
        resolved = obj.ssl_max_version_resolved
        # BLANK IS NOT A PASS. The resolver returns nothing for a build its mapping does not
        # cover, and the verdict beside it stays TRUE so an unresolvable ceiling reports rather
        # than passing. Saying which of the two happened is the whole point of the third column.
        how = (f"resolves to {resolved}" if resolved
               else "could not be resolved against this appliance's own build, so what the "
                    "literal means here was never established")
        gaps.append("holds a protocol ceiling that excludes a version the appliance implements "
                    f"(ceiling {ceiling}, {how})")
    broken = obj.weakest_broken_primitive_permitted
    if broken and broken != SecurityProfile.PRIMITIVE_NONE:
        gaps.append(f"leaves the broken primitive {broken} negotiable")
    weaker = obj.weakest_non_pfs_or_unauthenticated_permitted
    if weaker and weaker != SecurityProfile.PRIMITIVE_NONE:
        gaps.append(f"leaves {weaker} negotiable, which is either a key exchange with no forward "
                    "secrecy or a cipher mode without authenticated encryption")
    unchecked = [label for field, label in _DECRYPTION_BLOCK_CHECKS
                 if getattr(obj, field) is False]
    if unchecked:
        gaps.append("does not perform these checks, so a session it cannot inspect is waved "
                    f"through rather than stopped: {'; '.join(unchecked)}")
    # THE REFERENCE PAIR, AND THE ORDER IS LOAD-BEARING. `is_used` false means "no referrer in
    # what was collected", which on an appliance whose decryption rulebase was never read is not
    # the same statement at all - so the companion is read FIRST and the unassessed arm says so
    # instead of calling the profile unused. PAN-DCP-007 carries the same pair as two queries.
    if obj.decryption_rulebase_collected is False:
        gaps.append("was not assessed for references, because no decryption rulebase was "
                    "collected from its appliance - which is not the same as nothing using it, "
                    "and no deletion follows from it")
    elif obj.is_used is False and not obj.is_predefined:
        gaps.append(f"is named by no decryption rule ({obj.referrer_count} referrers), so "
                    "whatever it was built for either changed or never arrived")
    return gaps


def _dos_protection_gaps(obj) -> list[str]:
    """What a DOS PROTECTION profile's hygiene verdict found. PAN-ZON-008.

    THE SAME DEFECT SHAPE `_antivirus_gaps`, `_url_filtering_gaps` AND `_decryption_gaps` EXIST TO
    PREVENT, met a FOURTH time, and all three of their docstrings record the earlier rounds. A
    dos-protection profile answers no severity question at all: it writes no severity-verdict
    satellite row, so `critical_blocked` and `high_blocked` are None and `_gaps` returns `[]`; it
    has no DNS tree, so both DNS verdicts are None; and it has no category verdict row, so
    `brute_force_blocked_by_source` is None. Every clause in the fallback is `is False`-guarded,
    none of them fires, and `_subject`'s closing clause therefore asserted that the profile
    "blocks critical and high threats" - measured byte for byte on 2026-11-01, printed on the
    finding reporting the profile as failing. Guarding the VALUES was not enough for the three
    kinds before this one and it is not enough here: the CALLER has to stop asking this kind the
    threat-rule question, which is what the `KIND_DOS_PROTECTION` guard below does.

    THE ONLY THING PAN-ZON-008 ASSERTS IS WHETHER ANYTHING REFERENCES THE PROFILE, and this
    function says nothing else on purpose. An unused profile's CONTENTS are other controls'
    business - the flood ceilings, the block durations and the concurrent-session limit are stored
    for a reader in `flood_and_resource_settings` and no control in this domain clauses on any of
    them.

    THE COMPANION IS READ FIRST AND THE ORDER IS LOAD-BEARING, on the `_decryption_gaps`
    precedent. `reference_reach` holds `undetermined` where the walk could not be shown to have
    seen every surface, and that is NOT the same statement as `unreferenced`: this control's
    remediation is a DELETION, so a false "nothing references this" ends in a profile deleted out
    from under the rule that was using it - which, unlike a finding raised where the estate is
    fine, is neither checkable in a minute nor reversible by reading.

    AND THE SENTENCE NAMES CANDIDATES RATHER THAN DECISIONS, which stage 5 requires in those terms
    and says nothing downstream will add unless a later stage writes it. Whether an unreferenced
    profile is being kept deliberately, and where that decision is recorded, is the engineer's
    question; what is deliverable without the answer is the LIST.
    """
    gaps = []
    if obj.reference_reach == SecurityProfile.REACH_UNDETERMINED:
        gaps.append(
            "WAS NOT SHOWN TO BE EITHER REFERENCED OR UNREFERENCED - the walk over this profile's "
            "reference surfaces could not be established as complete, so whether any DoS policy "
            "rule names it is unknown rather than answered. It is reported instead of passed "
            "because an unanswered walk stores the same zero as a profile nothing uses, and "
            "DELETING ON THE STRENGTH OF THAT ZERO is the one error on this control that cannot "
            "be undone by reading. Nothing is recommended here: establish the reference first")
    elif obj.reference_reach == SecurityProfile.REACH_UNREFERENCED:
        gaps.append(
            f"is named by nothing - {obj.referrer_count} referrers across either protection slot "
            "of any DoS policy rule in the scopes that were read, aggregate and classified alike "
            "- so it is a CANDIDATE FOR REMOVAL and not a decision: whether it is being kept "
            "deliberately, and where that decision is recorded, is in no configuration. Confirm "
            "before deleting anything")
        if obj.profile_type:
            article = "an" if obj.profile_type[:1].lower() in "aeiou" else "a"
            gaps.append(
                f"it is {article} {obj.profile_type} profile, which is worth knowing before "
                "acting: a "
                "count walking only the slot the sibling DoS rule control asserts would call "
                "every CLASSIFIED profile unreferenced, and a count taken per vsys would call a "
                "SHARED profile unreferenced in every vsys that does not happen to use it. This "
                "verdict is taken across both slots and across the vsys and shared scopes")
        if obj.is_predefined:
            gaps.append(
                "AND THIS PROFILE IS PREDEFINED, SO IT CANNOT BE DELETED AT ALL - the remediation "
                "would be to stop naming it, and nothing names it. Whether a hygiene control of "
                "this shape should exclude the predefined collection outright is an open question "
                "on this subject: stage 4 established there is no predefined ZONE protection "
                "profile and did not ask the same of this collection, so the clause that would "
                "have excluded it was not written and this sentence carries the consequence")
    return gaps


def _subject(obj) -> str:
    kind = KIND_LABELS.get(obj.kind, obj.kind)
    if obj.is_predefined:
        what = (f"The predefined {kind} profile {obj.name}, used by {obj.referrer_count} "
                f"rule{'s' if obj.referrer_count != 1 else ''} or profile group"
                f"{'s' if obj.referrer_count != 1 else ''} on {profile_owner(obj)},")
    else:
        what = f"{kind} profile {obj.name} on {profile_owner(obj)}"

    # ANTIVIRUS DOES NOT ANSWER THE SEVERITY QUESTION. It has no severity rules, so the
    # critical/high verdicts are None and the threat-rule sentence below would assert that the
    # profile blocks them - which is a claim about a question this kind never asked.
    if obj.kind == SecurityProfile.KIND_VIRUS:
        gaps = "; ".join(_antivirus_gaps(obj))
        return (f"{what} lets malware through ({gaps})" if gaps
                else f"{what} blocks malware on every decoder")

    # URL FILTERING DOES NOT ANSWER THE SEVERITY QUESTION EITHER. Same reasoning as antivirus
    # immediately above, and the same measured defect: without this branch a failing
    # url-filtering profile fell through to "blocks critical and high threats". The four shipped
    # kinds that reach this function are untouched by this guard.
    if obj.kind == SecurityProfile.KIND_URL_FILTERING:
        gaps = "; ".join(_url_filtering_gaps(obj))
        if gaps:
            return f"{what} {gaps}"
        # NOT "this profile is fine". A url-filtering profile can be reported by PAN-URL-006 for
        # being unreferenced while every verdict above passes, so the no-gap sentence must say
        # what was actually checked and no more.
        return (f"{what} refuses the confirmed-hostile categories, logs what it permits, "
                "restricts corporate credentials and runs both inline analysis engines")

    # DECRYPTION DOES NOT ANSWER THE SEVERITY QUESTION EITHER. Same reasoning as antivirus and
    # url-filtering above, and the same measured defect for the third time in this function:
    # without this branch a failing decryption profile fell through to "blocks critical and high
    # threats". The shipped kinds that reach the fallback below are untouched by this guard.
    if obj.kind == SecurityProfile.KIND_DECRYPTION:
        gaps = "; ".join(_decryption_gaps(obj))
        if gaps:
            return f"{what} {gaps}"
        # NOT "this profile is fine", and the url-filtering branch above records why the
        # distinction matters: PAN-DCP-007 reports a decryption profile for being referenced by no
        # rule while every protocol and primitive verdict on it passes, so the no-gap sentence has
        # to say what was actually checked and no more. It does not say anything about the
        # decryption PATH the profile is attached to - forward proxy, inbound inspection or SSH
        # proxy - because nothing stored records it; see the stage 8 artifact's `needs_human`.
        return (f"{what} requires TLS 1.2 or better, reaches the newest protocol version this "
                "appliance implements, leaves no broken primitive and no unauthenticated or "
                "non-forward-secret option negotiable, and performs every forward-proxy and "
                "inbound-inspection block check")

    # DOS PROTECTION DOES NOT ANSWER THE SEVERITY QUESTION EITHER. Same reasoning as antivirus,
    # url-filtering and decryption above, and the same measured defect for the FOURTH time in this
    # function: without this branch a failing DoS protection profile fell through to "blocks
    # critical and high threats", measured byte for byte at HEAD on 2026-11-01. The shipped kinds
    # that reach the fallback below are untouched by this guard, which was checked rather than
    # argued - `_subject` was called on one stub per kind before and after and the output is
    # byte-identical for all eight others.
    if obj.kind == SecurityProfile.KIND_DOS_PROTECTION:
        gaps = "; ".join(_dos_protection_gaps(obj))
        if gaps:
            return f"{what} {gaps}"
        # NOT "this profile is fine", for the reason the three branches above give. The ONLY
        # question any control in this domain asks of this kind is whether anything references it,
        # so the no-gap sentence may claim that and nothing more. In particular it says nothing
        # about the flood ceilings, the block durations, the block probabilities or the
        # concurrent-session limit: those are stored for a reader and no control clauses on them.
        return (f"{what} is named by at least one DoS policy rule, which is the only question any "
                "control here asks of it - nothing is asserted about the ceilings or durations it "
                "holds")

    # TWO INDEPENDENT QUESTIONS, and a profile can fail either alone. Blocking the threat
    # (PAN-VLN-001) and blocking its SOURCE (PAN-VLN-002) are different: `reset-both` passes the
    # first and fails the second. Without the second clause a profile failing only PAN-VLN-002
    # printed "blocks critical and high threats" ON ITS OWN FINDING - the same reassuring
    # sentence on a failing profile that `_antivirus_gaps` exists to prevent.
    clauses = []
    gaps = "; ".join(_gaps(obj))
    if gaps:
        clauses.append(f"does not block every critical and high threat ({gaps})")
    # ANTI-SPYWARE ANSWERS A QUESTION OF ITS OWN. A profile can block every severity and still
    # not sinkhole malicious DNS, and the severity sentence would have called it fine - the
    # same shape as the brute-force clause below, on the other kind.
    if obj.dns_sinkholes_malicious_queries is False:
        clauses.append(f"does not sinkhole malicious DNS queries ({obj.dns_sinkhole_detail})")
    # A SECOND, INDEPENDENT DNS QUESTION. The same screen carries the DNS Security categories,
    # and a profile can sinkhole the Palo Alto Networks Content list while leaving every
    # malicious category at `default` - which the predefined profiles both do.
    if obj.dns_security_categories_enforced is False:
        clauses.append("does not enforce malicious DNS Security categories "
                       f"({obj.dns_security_category_detail})")
    # `is False` rather than falsy: None means this kind writes no row and makes no claim.
    if obj.brute_force_blocked_by_source is False:
        clauses.append("does not block the source of brute-force attempts"
                       f" ({obj.brute_force_detail})")
    if clauses:
        return f"{what} " + ", and ".join(clauses)
    return f"{what} blocks critical and high threats"


def build_security_profile_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="security profile",
    control_type=Control.ControlType.SECURITY_PROFILE,
    finding_model=SecurityProfileFinding,
    link_model=SecurityProfileFindingControlQuery,
    subject_fk="security_profile",
    link_fk="security_profile_finding",
    # The antivirus subject sentence walks all three, so without these it is one query per
    # profile per collection.
    queryset=lambda: SecurityProfile.objects.select_related(
        "enforcement_point__appliance_group", "appliance_group").prefetch_related(
        "decoders", "ml_models", "application_overrides", "severity_verdicts",
        "category_verdicts", "dns_signature_sources"),
    evaluate=evaluate_security_profile_control_queries,
    summary=build_security_profile_finding_summary,
    subject_name=lambda obj: obj.name,
    # Names repeat across scopes - every vsys has its own predefined `default` - so the finding
    # carries where the definition lives, not only its name.
    subject_scope=lambda obj: f"{obj.namespace_type}:{profile_owner(obj)}"[:128],
)

SecurityProfileFindingRunResult = ObjectFindingRunResult


def generate_security_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_security_profile_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
