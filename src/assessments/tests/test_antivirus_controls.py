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
from assessments.security_profile_findings import generate_security_profile_findings
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    ManagementStation,
    PolicyObjectNamespace,
    SecurityProfile,
    SecurityProfileDecoder,
    Snapshot,
)

#: What the shipped profile stores, and what each decoder means.
SHIPPED = {"http": "reset-both", "http2": "reset-both", "ftp": "reset-both", "smb": "reset-both",
           "smtp": "alert", "imap": "alert", "pop3": "alert"}
ALL_BLOCK = {protocol: "reset-both" for protocol in SHIPPED}


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
        seed_controls(["PAN-AVW-001"], control_type=Control.ControlType.SECURITY_PROFILE)
        self.rank = 0

    def _profile(self, name, effective_by_protocol, *, predefined=False, used=True,
                 kind=SecurityProfile.KIND_VIRUS):
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
        for protocol, effective in effective_by_protocol.items():
            SecurityProfileDecoder.objects.create(
                security_profile=profile, protocol=protocol,
                # What an unedited profile actually stores, so the row under test is the real
                # shape rather than a tidied one.
                configured_action="default", effective_action=effective,
                blocks=effective in SecurityProfileDecoder.BLOCKING_ACTIONS)
        return profile

    def _fired(self):
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_security_profile_findings(run)
        return {f.security_profile.name: f.severity for f in
                SecurityProfileFinding.objects.filter(
                    control__control_id="PAN-AVW-001", assessment_run=run)
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
