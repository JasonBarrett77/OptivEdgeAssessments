"""Every non-policy control, in one run.

The UI offers two actions: policy, and everything else. That split is the one a user
recognises - "are my rules bad" versus "is my device configured badly" - whereas the
target-model split behind it is an implementation detail. A user pressing one button
expects one assessment run, so the per-type generators fill a run they are handed rather
than each creating their own.

Adding a control type means adding one line to GENERATORS - and a test fails until you do. It should not mean adding a
button, because the number of buttons is a question about what a user is asking, not about
how many models back the answer.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.utils import timezone

from assessments.admin_user_findings import generate_admin_user_findings
from assessments.authentication_profile_findings import generate_authentication_profile_findings
from assessments.authentication_sequence_findings import generate_authentication_sequence_findings
from assessments.authentication_settings_findings import generate_authentication_settings_findings
from assessments.certificate_findings import generate_certificate_findings
from assessments.certificate_profile_findings import generate_certificate_profile_findings
from assessments.interface_management_profile_findings import (
    generate_interface_management_profile_findings,
)
from assessments.logging_settings_findings import generate_logging_settings_findings
from assessments.login_banner_findings import generate_login_banner_findings
from assessments.management_interface_findings import generate_management_interface_findings
from assessments.management_tls_findings import generate_management_tls_findings
from assessments.management_ssh_findings import generate_management_ssh_findings
from assessments.master_key_findings import generate_master_key_findings
from assessments.models import AssessmentRun, Control
from assessments.ntp_settings_findings import generate_ntp_settings_findings
from assessments.password_complexity_findings import generate_password_complexity_findings
from assessments.password_profile_findings import generate_password_profile_findings
from assessments.security_profile_findings import generate_security_profile_findings
from assessments.server_profile_findings import generate_server_profile_findings
from assessments.snmp_settings_findings import generate_snmp_settings_findings
from assessments.ssl_tls_service_profile_findings import (
    generate_ssl_tls_service_profile_findings,
)
from assessments.system_identity_findings import generate_system_identity_findings
from assessments.update_server_settings_findings import generate_update_server_settings_findings

T = Control.ControlType

#: (label, the control type whose findings it writes, generator). Ordered so a report reads
#: device-wide settings before per-surface exposure, then the objects.
#:
#: The control type is carried so a test can compare this tuple with `finding_registry`. The
#: tuple fell behind the registry twice without anything failing: the administrator and AAA
#: server generators were never added, and when `DeviceConfigurationProfile` was split into
#: seven models on 2026-09-10, none of the seven was either - so for a day the one button
#: produced no findings at all for 24 controls. `test_configuration_findings_run` now checks the
#: two agree.
GENERATORS = (
    ("password complexity", T.PASSWORD_COMPLEXITY, generate_password_complexity_findings),
    ("authentication settings", T.AUTHENTICATION_SETTINGS, generate_authentication_settings_findings),
    ("login banner", T.LOGIN_BANNER, generate_login_banner_findings),
    ("management TLS", T.MANAGEMENT_TLS, generate_management_tls_findings),
    ("management SSH", T.MANAGEMENT_SSH, generate_management_ssh_findings),
    ("master key", T.MASTER_KEY, generate_master_key_findings),
    ("update server", T.UPDATE_SERVER, generate_update_server_settings_findings),
    ("logging settings", T.LOGGING_SETTINGS, generate_logging_settings_findings),
    # Device-wide services, so they sit with the settings above rather than with the objects
    # below: one row per appliance, and nothing references them.
    ("NTP", T.NTP_SETTINGS, generate_ntp_settings_findings),
    ("SNMP", T.SNMP_SETTINGS, generate_snmp_settings_findings),
    ("system identity", T.SYSTEM_IDENTITY, generate_system_identity_findings),
    ("management interface", T.MANAGEMENT_INTERFACE, generate_management_interface_findings),
    ("interface management profile", T.INTERFACE_MANAGEMENT_PROFILE,
     generate_interface_management_profile_findings),
    ("ssl/tls service profile", T.SSL_TLS_SERVICE_PROFILE, generate_ssl_tls_service_profile_findings),
    ("certificate profile", T.CERTIFICATE_PROFILE, generate_certificate_profile_findings),
    ("certificate", T.CERTIFICATE, generate_certificate_findings),
    ("authentication profile", T.AUTHENTICATION_PROFILE, generate_authentication_profile_findings),
    ("authentication sequence", T.AUTHENTICATION_SEQUENCE, generate_authentication_sequence_findings),
    ("password profile", T.PASSWORD_PROFILE, generate_password_profile_findings),
    ("security profile", T.SECURITY_PROFILE, generate_security_profile_findings),
    ("administrator", T.ADMIN_USER, generate_admin_user_findings),
    ("aaa server profile", T.SERVER_PROFILE, generate_server_profile_findings),
)


@dataclass
class ConfigurationFindingRunResult:
    assessment_run: AssessmentRun
    controls_evaluated: int
    findings_created: int
    query_links_created: int
    skipped_queries: int
    #: Per-generator counts, so a caller can say WHICH kind produced nothing.
    by_kind: dict


def regenerate_configuration_findings() -> ConfigurationFindingRunResult:
    assessment_run = AssessmentRun.objects.create(
        name=f"Configuration Findings {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        status=AssessmentRun.Status.RUNNING,
        started_at=timezone.now(),
    )
    totals = [0, 0, 0, 0]
    by_kind = {}
    try:
        for label, _control_type, generate in GENERATORS:
            counts = generate(assessment_run)
            by_kind[label] = counts
            totals = [a + b for a, b in zip(totals, counts)]
    except Exception:
        # One generator failing fails the run. A partially-filled run reported as complete
        # would understate findings, which is the direction that hides problems.
        assessment_run.mark_failed()
        assessment_run.save(update_fields=["status", "completed_at"])
        raise

    assessment_run.mark_completed()
    assessment_run.save(update_fields=["status", "completed_at"])
    return ConfigurationFindingRunResult(
        assessment_run=assessment_run,
        controls_evaluated=totals[0], findings_created=totals[1],
        query_links_created=totals[2], skipped_queries=totals[3], by_kind=by_kind)
