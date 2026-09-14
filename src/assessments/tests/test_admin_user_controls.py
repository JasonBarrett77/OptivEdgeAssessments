"""PAN-AUTH-019, 020, 021, 022 - the four controls over one administrator account.

They fail independently and share a tab, which is only worth anything if the lab holds rows
where they disagree. It does: pan-fw-111's `admin` fires all four, its `admin_with_auth_prof`
fires 020 and 022, and no lab account fires none of them any more - `oep-authtest` is bound to a
profile with no MFA, which is exactly what 020 is for.

PAN-AUTH-020 MOVED HERE from AuthenticationProfile on 2026-09-08. A profile row cannot say
which administrators are exposed: two accounts on one appliance can sit behind different
profiles, and the estate's profiles also serve GlobalProtect and Captive Portal. The finding is
about a person.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.admin_user_findings import generate_admin_user_findings
from assessments.tests._seed import seed_controls
from assessments.models import AdminUserFinding, AssessmentRun, Control, ControlQuery
from optivedge_integrations.integrations.models import (
    AdminUser, Appliance, ApplianceGroup, ManagementStation, Snapshot)

CONTROL_IDS = ("PAN-AUTH-019", "PAN-AUTH-020", "PAN-AUTH-021", "PAN-AUTH-022")


class AdminUserControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.au")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-au",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-AU", hostname="fw-au")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        seed_controls(CONTROL_IDS, control_type=Control.ControlType.ADMIN_USER)
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _user(self, name, **kwargs):
        fields = {
            "role_type": AdminUser.RoleType.SUPERUSER,
            "is_superuser": True,
            "has_password": True,
            # Every account is MFA-protected unless a test says otherwise, so a test about
            # 019 or 021 is not quietly also a test about 020.
            "admin_mfa_enabled": True,
        }
        fields.update(kwargs)
        fields["centrally_authenticated"] = (
            fields.get("authentication_is_external", False)
            and not fields["has_password"] and not fields.get("has_public_key", False))
        return AdminUser.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, source_snapshot=self.snapshot, name=name, **fields)

    def _fired(self, name):
        generate_admin_user_findings(self.run)
        return set(AdminUserFinding.objects
                   .filter(admin_user__name=name)
                   .values_list("control__control_id", flat=True))

    def test_an_ssh_key_with_no_profile_is_a_local_credential(self):
        """pan-fw-111's `azureuser`: no password at all, superuser, reachable by a key.

        The corpus note says to flag entries carrying `phash`. A key stored in the same config
        is exactly as local, and reading the note literally would pass this account.
        """
        self._user("keyonly", has_password=False, has_public_key=True,
                   superuser_cohort_size=1)
        self.assertIn("PAN-AUTH-019", self._fired("keyonly"))

    def test_an_external_profile_and_no_stored_credential_clears_019(self):
        self._user("bound", authentication_profile_name="corp-tacacs",
                   effective_authentication_profile="corp-tacacs",
                   authentication_is_external=True, has_password=False,
                   superuser_cohort_size=1)
        self.assertNotIn("PAN-AUTH-019", self._fired("bound"))

    def test_a_local_database_profile_does_not_clear_019(self):
        """Three of the four lab accounts that passed an earlier version were like this.

        A bound profile is not evidence of centralization: `local-database` and `none`
        authenticate against the firewall itself, and the control is named for external
        authentication.
        """
        self._user("localdb", authentication_profile_name="oep-auth-lockout",
                   effective_authentication_profile="oep-auth-lockout",
                   authentication_is_external=False, has_password=False,
                   superuser_cohort_size=1)
        self.assertIn("PAN-AUTH-019", self._fired("localdb"))

    def test_an_external_profile_does_not_excuse_a_stored_password(self):
        """Jason, 2026-09-08: "mfa/external=yes and local phash=no".

        The password is unreachable while the binding holds - measured - and becomes live the
        moment somebody removes the profile.
        """
        self._user("bound_with_phash", authentication_profile_name="corp-tacacs",
                   effective_authentication_profile="corp-tacacs",
                   authentication_is_external=True, has_password=True,
                   superuser_cohort_size=1)
        self.assertIn("PAN-AUTH-019", self._fired("bound_with_phash"))

    def test_the_summary_names_WHICH_half_failed(self):
        """A summary naming one half sends an engineer to fix the wrong thing."""
        self._user("localdb", authentication_profile_name="oep-auth-lockout",
                   effective_authentication_profile="oep-auth-lockout",
                   authentication_is_external=False, has_password=False,
                   superuser_cohort_size=1)
        self._user("bound_with_phash", authentication_profile_name="corp-tacacs",
                   effective_authentication_profile="corp-tacacs",
                   authentication_is_external=True, has_password=True,
                   superuser_cohort_size=1)
        generate_admin_user_findings(self.run)
        by_name = {f.admin_user.name: f.summary for f in AdminUserFinding.objects
                   .select_related("admin_user").filter(control__control_id="PAN-AUTH-019")}
        self.assertIn("not an external identity service", by_name["localdb"])
        self.assertIn("still holds a local password", by_name["bound_with_phash"])

    def test_client_certificate_only_does_not_clear_019(self):
        """It governs the web interface. The password still answers on the CLI."""
        self._user("webcert", client_certificate_only=True, superuser_cohort_size=1)
        self.assertIn("PAN-AUTH-019", self._fired("webcert"))

    def test_the_default_account_fires_021_by_name(self):
        self._user("admin", superuser_cohort_size=1)
        self.assertIn("PAN-AUTH-021", self._fired("admin"))

    def test_a_named_account_does_not_fire_021(self):
        self._user("jason", superuser_cohort_size=1)
        self.assertNotIn("PAN-AUTH-021", self._fired("jason"))

    def test_two_superusers_do_not_fire_022(self):
        """The corpus band calls 2 or fewer best practice, and the query threshold agrees.

        These have to agree: the band gives 1 and 2 a NULL severity, which the grader reads as
        "no opinion" and falls back to the control default - so a query firing at 2 would
        report best practice at `high`.
        """
        self._user("a", superuser_cohort_size=2)
        self.assertNotIn("PAN-AUTH-022", self._fired("a"))

    def test_a_non_superuser_never_fires_022(self):
        """Cohort size is 0 off-cohort, which is what keeps the query to one field."""
        self._user("reader", role_type=AdminUser.RoleType.DEVICEREADER,
                   is_superuser=False, superuser_cohort_size=0)
        self.assertNotIn("PAN-AUTH-022", self._fired("reader"))

    def test_022_grades_on_the_cohort_size_rather_than_the_default(self):
        """pan-fw-111 carries seven, which the 6-to-10 operator query calls medium."""
        self._user("one_of_seven", superuser_cohort_size=7)
        generate_admin_user_findings(self.run)
        finding = AdminUserFinding.objects.get(
            admin_user__name="one_of_seven", control__control_id="PAN-AUTH-022")
        self.assertEqual(finding.severity, "medium")

    def test_the_interview_only_020_stays_silent_on_an_account_it_used_to_fire_on(self):
        """PAN-AUTH-020 is an INTERVIEW QUESTION, complete, and asserts nothing from config.
        Jason, 2026-09-10: "PAN-AUTH-020 is not derived from the config, lock that decision in.";
        2026-09-14: "it needs to be handled via interview. Let's mark 020 as complete."

        Administrator MFA arrives only through RADIUS, SAML or the Cloud Authentication Service,
        and the configuration records none of the other side's MFA policy; the one factor it
        does show is not enforced for administrators (measured under PAN-AAA-011). This test is
        the lock: an account 020 used to fire on must not report it, while 019 still does.
        """
        self._user("local", superuser_cohort_size=1, admin_mfa_enabled=False)
        fired = self._fired("local")
        self.assertNotIn("PAN-AUTH-020", fired)
        self.assertIn("PAN-AUTH-019", fired)

    def test_an_external_account_without_a_declared_factor_fires_nothing(self):
        """External, no stored credential. 019 is clear, and 020 - which used to fire here - is
        deferred: whether the RADIUS server behind `corp-radius` enforces MFA is not in the
        configuration, so an absent factor proves nothing either way."""
        self._user("ext-no-mfa", role_type=AdminUser.RoleType.DEVICEREADER,
                   is_superuser=False, superuser_cohort_size=0, has_password=False,
                   authentication_profile_name="corp-radius",
                   effective_authentication_profile="corp-radius",
                   authentication_is_external=True,
                   authentication_binding=AdminUser.AuthenticationBinding.USER,
                   admin_mfa_enabled=False)
        self.assertEqual(self._fired("ext-no-mfa"), set())

    def test_every_active_control_can_fire_on_one_account(self):
        """The reason they share a tab rather than getting one each. Three, not four: 020 is
        deferred and stays seeded only so the machinery keeps its tests."""
        self._user("admin", superuser_cohort_size=7, admin_mfa_enabled=False)
        self.assertEqual(self._fired("admin"), set(CONTROL_IDS) - {"PAN-AUTH-020"})

    def test_an_account_can_fire_none_of_them(self):
        """Centrally authenticated, MFA on, no local credential, least privilege."""
        self._user("clean", role_type=AdminUser.RoleType.DEVICEREADER,
                   is_superuser=False, superuser_cohort_size=0, has_password=False,
                   authentication_profile_name="corp-saml",
                   effective_authentication_profile="corp-saml",
                   authentication_is_external=True,
                   authentication_binding=AdminUser.AuthenticationBinding.USER,
                   admin_mfa_enabled=True)
        self.assertEqual(self._fired("clean"), set())

    def test_the_summary_states_what_the_account_authenticates_with(self):
        self._user("keyonly", has_password=False, has_public_key=True,
                   superuser_cohort_size=1)
        generate_admin_user_findings(self.run)
        summary = AdminUserFinding.objects.get(
            admin_user__name="keyonly", control__control_id="PAN-AUTH-019").summary
        self.assertIn("an SSH public key", summary)
        self.assertIn("superuser", summary)
