"""PAN-AVW-001 - an antivirus profile that detects malware without stopping it.

THE CONFIGURATION DOES NOT ANSWER THIS CONTROL. Every decoder of every unedited antivirus
profile stores the literal `default`, the shipped one included, and what `default` means is per
protocol: reset-both on http, http2, ftp and smb; alert on smtp, imap and pop3. Measured
2026-10-07 from the Panorama UI, with the predefined profile and a UI-created one rendering
identically, and agreeing with what controls.json says in words about the shipped profile.

So these tests are mostly about the resolution, not the query. A control reading the configured
literal would find every profile on every estate equally fine.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.models import AssessmentRun, Control, SecurityProfileFinding
from assessments.security_profile_findings import (
    _subject,
    generate_security_profile_findings,
)
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    ManagementStation,
    PolicyObjectNamespace,
    SecurityProfile,
    SecurityProfileApplicationOverride,
    SecurityProfileDecoder,
    SecurityProfileMlModel,
    Snapshot,
)

#: What the shipped profile stores, and what each decoder means.
SHIPPED = {"http": "reset-both", "http2": "reset-both", "ftp": "reset-both", "smb": "reset-both",
           "smtp": "alert", "imap": "alert", "pop3": "alert"}
ALL_BLOCK = {protocol: "reset-both" for protocol in SHIPPED}

#: As the predefined profile carries them on the lab. The CONTENT release names these, not
#: PAN-OS, so production reads them from the predefined profile rather than a constant.
MODELS = ("Windows Executables", "PowerShell Script 1", "PowerShell Script 2",
          "Executable Linked Format", "MSOffice", "Shell", "OOXML", "MachO")


class AntivirusDecoderControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.avw")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-avw",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-AVW", hostname="fw-avw")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="config_predefined_security_profiles", collected_at=timezone.now())
        seed_controls(["PAN-AVW-001", "PAN-AVW-002"],
                      control_type=Control.ControlType.SECURITY_PROFILE)
        self.rank = 0

    def _profile(self, name, effective_by_protocol, *, predefined=False, used=True,
                 kind=SecurityProfile.KIND_VIRUS, ml=None, overrides=None,
                 wildfire=None, mlav=None):
        self.rank += 1
        namespace = (PolicyObjectNamespace.PREDEFINED if predefined
                     else PolicyObjectNamespace.LOCAL_SHARED)
        profile = SecurityProfile.objects.create(
            management_station=self.station, appliance_group=self.group,
            source_snapshot=self.snapshot, config_source="local", name=name,
            namespace_type=namespace,
            namespace_value="predefined" if predefined else "shared",
            precedence_rank=self.rank, kind=kind, is_predefined=predefined,
            is_used=used, referrer_count=1 if used else 0)
        # THREE ACTION COLUMNS PER DECODER, and they default to matching the signature action
        # only because most tests are about one axis at a time. `wildfire=` and `mlav=` make
        # them differ, which is the shape that passed this control until 2026-10-08: hardened
        # in the first column, open in the other two.
        #
        # A `None` in the mlav mapping means NOT COMPUTED - a row written before the column
        # existed - which must report rather than pass.
        for protocol, effective in effective_by_protocol.items():
            wf = (wildfire or {}).get(protocol, effective)
            # NOT `ml`: that name is the ML-model parameter used by the loop below, and
            # binding it here silently emptied it.
            ml_effective = effective if mlav is None else mlav.get(protocol, effective)
            SecurityProfileDecoder.objects.create(
                security_profile=profile, protocol=protocol,
                # What an unedited profile actually stores, so the row under test is the real
                # shape rather than a tidied one.
                configured_action="default", effective_action=effective,
                blocks=effective in SecurityProfileDecoder.BLOCKING_ACTIONS,
                configured_wildfire_action="default", effective_wildfire_action=wf,
                wildfire_blocks=wf in SecurityProfileDecoder.BLOCKING_ACTIONS,
                configured_mlav_action="" if ml_effective is None else "default",
                effective_mlav_action="" if ml_effective is None else ml_effective,
                mlav_blocks=(None if ml_effective is None
                             else ml_effective in SecurityProfileDecoder.BLOCKING_ACTIONS))
        # One row per model the CONTENT release knows about, enabled or not. A model the config
        # never names still gets a row, saying off - which is the state a profile with no ML
        # node is in for every one of them.
        for model, enabled in (ml if ml is not None else {m: True for m in MODELS}).items():
            # `enabled` and `blocks` are different questions: mlav-policy-action has three
            # values and `enable(alert-only)` runs without stopping the file. A bare True here
            # means the plain `enable`.
            action = "enable" if enabled is True else (
                "disable" if enabled is False else enabled)
            SecurityProfileMlModel.objects.create(
                security_profile=profile, name=model, configured_action=action,
                enabled=action in ("enable", "enable(alert-only)"),
                blocks=action == "enable")
        # Per-application overrides, and ONLY the ones named - unlike the decoders and the ML
        # models above, nothing is synthesized. An override is an operator-added exception, so
        # the default of none is the state almost every real profile is in.
        for application, action in (overrides or {}).items():
            # `default` is accepted on an override and its resolution is NOT established - an
            # override is not per-protocol, so the decoder table cannot answer it. Null blocks,
            # which the control reports rather than passes.
            blocks = (None if action == "default"
                      else (action or SecurityProfileDecoder.ABSENT_ACTION)
                      in SecurityProfileDecoder.BLOCKING_ACTIONS)
            SecurityProfileApplicationOverride.objects.create(
                security_profile=profile, application=application,
                configured_action=action, blocks=blocks)
        return profile

    def _fired(self, control_id="PAN-AVW-001"):
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_security_profile_findings(run)
        return {f.security_profile.name: f.severity for f in
                SecurityProfileFinding.objects.filter(
                    control__control_id=control_id, assessment_run=run)
                .select_related("security_profile")}

    def test_the_shipped_default_profile_fires(self):
        """Three of its seven decoders alert. This is the finding the control exists for, and
        on the lab it is the only antivirus profile any rule uses."""
        self._profile("default", SHIPPED, predefined=True, used=True)

        self.assertEqual(self._fired(), {"default": "high"})

    def test_a_profile_blocking_on_every_decoder_is_silent(self):
        self._profile("hardened", ALL_BLOCK)

        self.assertEqual(self._fired(), {})

    def test_one_alerting_decoder_is_enough(self):
        """The corpus asserts reset-both on every decoder, not most of them."""
        self._profile("almost", dict(ALL_BLOCK, smtp="alert"))

        self.assertEqual(self._fired(), {"almost": "high"})

    def test_drop_counts_as_blocking(self):
        """The corpus names `reset-both` for its minimum and preferred alike. A profile that
        DROPS malware has not failed to block it - the same deviation PAN-SPY-001 makes."""
        self._profile("drops", dict(ALL_BLOCK, http="drop", smtp="reset-client"))

        self.assertEqual(self._fired(), {})

    def test_a_profile_hardened_ONLY_on_signature_action_fires(self):
        """The shape that passed this control until 2026-10-08.

        Signature Action is reset-both on all seven protocols, so the original question
        answers "fine". Both WildFire columns allow, so everything WildFire or inline ML
        catches is delivered - and the finding said the profile blocked malware on every
        decoder.
        """
        self._profile("sig-only", ALL_BLOCK,
                      wildfire={p: "allow" for p in SHIPPED},
                      mlav={p: "allow" for p in SHIPPED})

        self.assertEqual(self._fired(), {"sig-only": "high"})

    def test_the_wildfire_signature_column_alone_is_enough(self):
        self._profile("wf-gap", ALL_BLOCK, wildfire=dict(ALL_BLOCK, smtp="alert"))

        self.assertEqual(self._fired(), {"wf-gap": "high"})

    def test_the_inline_ML_action_column_alone_is_enough(self):
        """Distinct from PAN-AVW-002, which asks whether the MODELS run. A profile can enable
        every model and allow every verdict they produce."""
        self._profile("ml-action-gap", ALL_BLOCK, mlav=dict(ALL_BLOCK, http="alert"))

        self.assertEqual(self._fired(), {"ml-action-gap": "high"})

    def test_a_decoder_with_NO_inline_ML_verdict_recorded_is_reported(self):
        """`mlav-action` was never collected before 2026-10-08, so rows written earlier carry
        no value and nothing can backfill them. Null must report, not pass - otherwise the
        window between migrating and re-normalizing reads as a hardened estate."""
        profile = self._profile("not-computed", ALL_BLOCK,
                                mlav={p: None for p in SHIPPED})

        self.assertEqual(self._fired(), {"not-computed": "high"})
        self.assertEqual(profile.non_blocking_mlav_decoders, [
            "ftp (not yet computed)", "http (not yet computed)", "http2 (not yet computed)",
            "imap (not yet computed)", "pop3 (not yet computed)", "smb (not yet computed)",
            "smtp (not yet computed)"])

    def test_all_three_columns_blocking_is_silent(self):
        self._profile("all-three", ALL_BLOCK, wildfire=ALL_BLOCK, mlav=ALL_BLOCK)

        self.assertEqual(self._fired(), {})

    def test_the_subject_sentence_names_the_verdict_source_not_a_severity(self):
        """An antivirus profile has no severity rules, so the threat-rule sentence asserted it
        BLOCKED critical and high threats - printed on every antivirus finding, the shipped
        `default` profile included. The reassuring sentence, on the finding reporting the
        profile as failing. Measured against the lab 2026-10-08."""
        profile = self._profile("speaks", dict(ALL_BLOCK, smtp="alert"),
                                wildfire=dict(ALL_BLOCK, imap="alert"),
                                mlav=dict(ALL_BLOCK, http="allow"),
                                overrides={"gmail-base": "allow"})

        subject = _subject(profile)
        self.assertIn("lets malware through", subject)
        self.assertIn("signature action allows on smtp", subject)
        self.assertIn("WildFire signature action allows on imap", subject)
        self.assertIn("WildFire inline ML action allows on http", subject)
        self.assertIn("application exceptions override the decoder for gmail-base (allow)",
                      subject)
        self.assertNotIn("critical", subject)

    def test_a_clean_antivirus_profile_says_so_in_its_own_terms(self):
        profile = self._profile("clean", ALL_BLOCK, wildfire=ALL_BLOCK, mlav=ALL_BLOCK)

        self.assertEqual(_subject(profile).endswith("blocks malware on every decoder"), True)
        self.assertNotIn("critical", _subject(profile))

    def test_a_spyware_profile_still_speaks_in_severities(self):
        """The threat-rule kinds are unchanged - the fix branches on kind rather than
        rewriting the sentence for everyone."""
        profile = self._profile("spy", {}, kind=SecurityProfile.KIND_SPYWARE, ml={})

        self.assertIn("critical and high threats", _subject(profile))

    def test_a_permissive_application_override_fires_on_a_hardened_profile(self):
        """The whole reason this clause exists.

        Every decoder blocks, so the control's original question answers "fine". One
        per-application override says `allow`, which defeats the http decoder for that
        application. Reported as hardened until 2026-10-08.
        """
        self._profile("override-allow", ALL_BLOCK, overrides={"gmail-base": "allow"})

        self.assertEqual(self._fired(), {"override-allow": "high"})

    def test_an_override_that_only_alerts_fires(self):
        """`alert` is detection without prevention, the same reading as on a decoder."""
        self._profile("override-alert", ALL_BLOCK, overrides={"dropbox-base": "alert"})

        self.assertEqual(self._fired(), {"override-alert": "high"})

    def test_an_override_with_NO_action_fires_because_absent_means_allow(self):
        """The device accepts an override entry with no action and stores it absent - measured
        2026-10-08, along with the refusal of an EMPTY action element. Absent is the permissive
        end here exactly as it is on a decoder."""
        self._profile("override-absent", ALL_BLOCK, overrides={"ftp": ""})

        self.assertEqual(self._fired(), {"override-absent": "high"})

    def test_an_override_set_to_default_fires_because_its_resolution_is_UNESTABLISHED(self):
        """Not because `default` is known to be permissive - because it is not known at all.

        A decoder's `default` resolves per protocol and that was measured. An override is not
        per-protocol, so the same table cannot answer it and no device oracle was found that
        does. The control reports it so that "we could not establish this" does not render as
        "we checked and it was fine".
        """
        self._profile("override-default", ALL_BLOCK, overrides={"web-browsing": "default"})

        self.assertEqual(self._fired(), {"override-default": "high"})

    def test_a_permissive_override_fires_even_beside_a_BLOCKING_one(self):
        """The common real shape, and the one the first compiler got wrong.

        An exception list holds several entries and only some are permissive. The first version
        asked the question as `exclude(application_overrides__blocks=True)` on the PROFILE,
        which drops a profile for HAVING a blocking override - so this profile, whose
        gmail-base override allows, went unreported because dropbox-base blocks. The question
        has to be asked per ROW.
        """
        self._profile("mixed", ALL_BLOCK, overrides={
            "gmail-base": "allow", "dropbox-base": "reset-both"})

        self.assertEqual(self._fired(), {"mixed": "high"})

    def test_a_blocking_override_is_silent(self):
        """An override exists to CHANGE an action and may well tighten it. A profile whose
        override blocks is a profile that blocks, and the control must stay quiet - otherwise
        the clause would report every profile that has any override at all."""
        self._profile("override-blocks", ALL_BLOCK, overrides={"gmail-base": "reset-both"})

        self.assertEqual(self._fired(), {})

    def test_a_profile_with_no_overrides_at_all_is_silent(self):
        """The normal case for almost every profile, and the one that would break if the
        compiler required an override row the way the decoder compiler requires a decoder."""
        self._profile("no-overrides", ALL_BLOCK)

        self.assertEqual(self._fired(), {})

    def test_the_override_list_names_the_application_and_why(self):
        """What the finding row and both presentation surfaces read."""
        profile = self._profile("override-detail", ALL_BLOCK, overrides={
            "gmail-base": "allow", "ftp": "", "web-browsing": "default",
            "dropbox-base": "reset-both"})

        self.assertEqual(profile.non_blocking_application_overrides, [
            "ftp (no action set, which allows)",
            "gmail-base (allow)",
            "web-browsing (default, resolution not established)",
        ])
        self.assertTrue(profile.has_non_blocking_application_override)

    def test_an_UNUSED_predefined_profile_is_not_a_finding(self):
        """Same scope as PAN-SPY-001: the shipped profile sitting unreferenced says nothing
        about the estate. A rule protected by it does."""
        self._profile("default", SHIPPED, predefined=True, used=False)

        self.assertEqual(self._fired(), {})

    def test_an_unused_CUSTOM_profile_still_fires(self):
        """Somebody built it, so it is estate configuration whether or not a rule names it
        yet - and attaching it later is one click."""
        self._profile("custom-weak", SHIPPED, predefined=False, used=False)

        self.assertEqual(self._fired(), {"custom-weak": "high"})

    def test_a_profile_naming_NO_decoders_is_the_worst_case_not_an_absent_one(self):
        """Corrected 2026-10-08. An absent decoder action is `allow`, not the vendor default -
        measured from the UI's own export of a profile with no decoder node, which renders all
        seven protocols as `allow`. The first version of this control resolved absence to
        `default`, so such a profile produced no failing decoder and reported nothing at all.
        """
        self._profile("names-nothing", {p: "allow" for p in SHIPPED})

        self.assertEqual(self._fired(), {"names-nothing": "high"})

    def test_a_profile_of_another_kind_is_untouched(self):
        """An anti-spyware profile has no decoders at all. It must not read as one that blocks
        everywhere - that is why the `false` side of the search field requires a decoder row."""
        self._profile("spy", {}, kind=SecurityProfile.KIND_SPYWARE)

        self.assertEqual(self._fired(), {})

    def test_the_finding_names_the_protocols_that_let_malware_through(self):
        """An engineer needs the list, not the count: the remediation is per decoder."""
        profile = self._profile("default", SHIPPED, predefined=True, used=True)

        self.assertEqual(profile.non_blocking_decoders, ["imap", "pop3", "smtp"])
        self.assertTrue(profile.has_non_blocking_decoder)


class WildFireInlineMlControlTests(AntivirusDecoderControlTests):
    """PAN-AVW-002. The shipped profile PASSES this one and a hand-made profile fails it, which
    is the reverse of the usual direction and the reason the control is worth having."""

    def test_the_predefined_profile_passes(self):
        """It enables every model. An administrator who leaves it alone gets more inline ML
        than one who builds their own."""
        self._profile("default", SHIPPED, predefined=True, used=True,
                      ml={m: True for m in MODELS})

        self.assertEqual(self._fired("PAN-AVW-002"), {})

    def test_a_profile_created_and_left_alone_fails(self):
        """The UI writes `disable` for every model on a profile nobody edited."""
        self._profile("ui-made", ALL_BLOCK, ml={m: False for m in MODELS})

        self.assertEqual(self._fired("PAN-AVW-002"), {"ui-made": "medium"})

    def test_one_model_off_is_enough(self):
        """The corpus minimum is Windows Executables alone; its preferred is every model, and
        this asserts the preferred."""
        self._profile("almost", ALL_BLOCK,
                      ml={m: (m != "MachO") for m in MODELS})

        self.assertEqual(self._fired("PAN-AVW-002"), {"almost": "medium"})

    def test_a_model_the_config_never_mentions_counts_as_off(self):
        """A profile with no ML node has a row per model saying off, because the UI renders it
        that way. Without those rows it would have nothing switched off and would pass while
        running no inline ML at all."""
        profile = self._profile("names-nothing", ALL_BLOCK, ml={m: False for m in MODELS})

        self.assertEqual(profile.disabled_ml_models, sorted(MODELS))
        self.assertEqual(self._fired("PAN-AVW-002"), {"names-nothing": "medium"})

    def test_the_two_antivirus_controls_are_independent(self):
        """A profile can block on every decoder and still run no inline ML, and the reverse.
        They are different questions about the same object."""
        self._profile("blocks-no-ml", ALL_BLOCK, ml={m: False for m in MODELS})
        self._profile("ml-no-blocks", SHIPPED, ml={m: True for m in MODELS})

        self.assertEqual(self._fired("PAN-AVW-001"), {"ml-no-blocks": "high"})
        self.assertEqual(self._fired("PAN-AVW-002"), {"blocks-no-ml": "medium"})

    def test_an_unused_predefined_profile_is_out_of_scope(self):
        self._profile("default", SHIPPED, predefined=True, used=False,
                      ml={m: False for m in MODELS})

        self.assertEqual(self._fired("PAN-AVW-002"), {})

    def test_a_profile_of_another_kind_has_no_models(self):
        self._profile("spy", {}, kind=SecurityProfile.KIND_SPYWARE, ml={})

        self.assertEqual(self._fired("PAN-AVW-002"), {})


class UnusedProfileControlTests(AntivirusDecoderControlTests):
    """PAN-AVW-006. The finding is that nothing NAMES the profile, not that it is weak.

    Its scope decision is the mirror of PAN-SPY-001's: a predefined profile nobody uses says
    nothing about the estate, because it ships with the device whether anyone wants it or not.
    A custom one is different - somebody built it, and it stayed.
    """

    def setUp(self):
        super().setUp()
        seed_controls(["PAN-AVW-006"], control_type=Control.ControlType.SECURITY_PROFILE)

    def test_an_unreferenced_custom_profile_reports(self):
        self._profile("orphan", ALL_BLOCK, predefined=False, used=False)

        self.assertEqual(self._fired("PAN-AVW-006"), {"orphan": "low"})

    def test_a_referenced_custom_profile_is_silent(self):
        self._profile("in-service", ALL_BLOCK, predefined=False, used=True)

        self.assertEqual(self._fired("PAN-AVW-006"), {})

    def test_an_unused_PREDEFINED_profile_is_out_of_scope(self):
        """It ships with the device. Nobody chose to leave it there."""
        self._profile("default", SHIPPED, predefined=True, used=False)

        self.assertEqual(self._fired("PAN-AVW-006"), {})

    def test_it_says_nothing_about_what_the_profile_would_block(self):
        """An unused profile that blocks everything reports exactly like an unused one that
        blocks nothing. Being unattached is the whole assertion."""
        self._profile("strong-but-idle", ALL_BLOCK, used=False)
        self._profile("weak-but-idle", {p: "allow" for p in SHIPPED}, used=False)

        self.assertEqual(self._fired("PAN-AVW-006"),
                         {"strong-but-idle": "low", "weak-but-idle": "low"})

    def test_a_profile_of_another_kind_is_out_of_scope(self):
        """v1 is antivirus only. An unused anti-spyware profile is nobody's finding yet."""
        self._profile("spy-orphan", {}, kind=SecurityProfile.KIND_SPYWARE, used=False, ml={})

        self.assertEqual(self._fired("PAN-AVW-006"), {})

    def test_the_three_antivirus_controls_ask_different_questions(self):
        """One profile, unattached and wide open: unused, not blocking, and no inline ML."""
        self._profile("idle-and-open", {p: "allow" for p in SHIPPED}, used=False,
                      ml={m: False for m in MODELS})

        self.assertEqual(self._fired("PAN-AVW-001"), {"idle-and-open": "high"})
        self.assertEqual(self._fired("PAN-AVW-002"), {"idle-and-open": "medium"})
        self.assertEqual(self._fired("PAN-AVW-006"), {"idle-and-open": "low"})


class WildFireInlineMlAlertOnlyTests(AntivirusDecoderControlTests):
    """`enable(alert-only)` - the third value of mlav-policy-action, and the one that makes
    `enabled` and `blocks` different questions.

    Enumerated from the device with action=complete on 2026-10-08. Before that the normalizer
    tested `== "enable"` and would have recorded an alert-only model as disabled: the right
    answer for this control by luck, and the wrong statement about the configuration. A model on
    alert-only RUNS - it is not off - and it lets the file through.
    """

    # No setUp: the base class already seeds PAN-AVW-002.

    def test_alert_only_fires_because_it_does_not_block(self):
        self._profile("alert-only", ALL_BLOCK,
                      ml={m: "enable(alert-only)" for m in MODELS})

        self.assertEqual(self._fired("PAN-AVW-002"), {"alert-only": "medium"})

    def test_alert_only_is_NOT_the_same_as_disabled(self):
        """The distinction the two flags exist for. One profile runs the engine and logs; the
        other does not run it. The control reports both and an engineer fixes them
        differently."""
        running = self._profile("alert-only", ALL_BLOCK,
                                ml={m: "enable(alert-only)" for m in MODELS})
        off = self._profile("switched-off", ALL_BLOCK, ml={m: False for m in MODELS})

        self.assertEqual(running.disabled_ml_models, [], "it is running")
        self.assertEqual(running.non_blocking_ml_models, sorted(MODELS), "it is not blocking")
        self.assertEqual(off.disabled_ml_models, sorted(MODELS))
        self.assertEqual(off.non_blocking_ml_models, sorted(MODELS))

    def test_plain_enable_blocks_and_is_silent(self):
        self._profile("blocking", ALL_BLOCK, ml={m: "enable" for m in MODELS})

        self.assertEqual(self._fired("PAN-AVW-002"), {})
