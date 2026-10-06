"""Every active control, in one run.

Until 2026-09-16 the UI offered two actions - policy findings and "everything else" - each
creating its own run, on the theory that a user asks "are my rules bad" separately from "is my
device configured badly". Jason, 2026-09-16: "The split between policy and device findings
shouldn't exist." A run is now the whole assessment, which is also what lets a finding's
reference number be unique across every finding model at once (see `FindingBase`).

The per-type generators fill a run they are handed rather than each creating their own. Adding
a control type means adding one line to GENERATORS - and a test fails until you do. It should
not mean adding a button, because the number of buttons is a question about what a user is
asking, not about how many models back the answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from django.utils import timezone

from assessments.admin_user_findings import generate_admin_user_findings
from assessments.authentication_profile_findings import generate_authentication_profile_findings
from assessments.authentication_sequence_findings import generate_authentication_sequence_findings
from assessments.authentication_settings_findings import generate_authentication_settings_findings
from assessments.findings import generate_rule_findings
from assessments.certificate_findings import generate_certificate_findings
from assessments.coverage_findings import generate_coverage_findings
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
#: produced no findings at all for 24 controls. `test_finding_run` now checks the two agree -
#: for EVERY registered kind, security rules included.
#:
#: The order is also the order reference numbers are allocated in, so F-0001 is the first
#: password-complexity finding and policy findings come last.
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
    # Last on purpose: it reports what the run could NOT establish, so it reads as the
    # footnote to everything above rather than as another finding family.
    ("coverage", T.COVERAGE, generate_coverage_findings),
    ("authentication profile", T.AUTHENTICATION_PROFILE, generate_authentication_profile_findings),
    ("authentication sequence", T.AUTHENTICATION_SEQUENCE, generate_authentication_sequence_findings),
    ("password profile", T.PASSWORD_PROFILE, generate_password_profile_findings),
    ("security profile", T.SECURITY_PROFILE, generate_security_profile_findings),
    ("administrator", T.ADMIN_USER, generate_admin_user_findings),
    ("aaa server profile", T.SERVER_PROFILE, generate_server_profile_findings),
    # Policy last: the device's own configuration reads before the rules it enforces.
    ("security rule", T.SECURITY_RULE, generate_rule_findings),
)


@dataclass
class FindingRunResult:
    assessment_run: AssessmentRun
    controls_evaluated: int
    findings_created: int
    query_links_created: int
    skipped_queries: int
    #: Per-generator counts, so a caller can say WHICH kind produced nothing.
    by_kind: dict


def summarise_run(controls, findings, links, skipped) -> str:
    """One sentence, led by the thing most easily missed."""
    summary = (f"Controls: {controls}. Findings: {findings}. Query links: {links}. "
               f"Skipped queries: {skipped}.")
    if skipped:
        summary = (f"Attention: {skipped} quer{'y' if skipped == 1 else 'ies'} could not be "
                   f"compiled, so the control{'' if skipped == 1 else 's'} using "
                   f"{'it' if skipped == 1 else 'them'} contributed nothing. " + summary)
    return summary


def open_findings_run() -> AssessmentRun:
    """The run row, RUNNING, before any generator touches it.

    Separated from `regenerate_findings` so a view can open it inside the REQUEST and hand the
    pk to a background thread. The page the browser lands on then always finds a run in
    progress; opened on the thread, it could render before the row existed and show nothing
    happening.
    """
    return AssessmentRun.objects.create(
        name=f"Findings {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        status=AssessmentRun.Status.RUNNING,
        started_at=timezone.now(),
    )


#: A RUNNING run younger than this blocks starting another. Older ones are taken to be orphans:
#: the worker thread is a daemon, so a server restart mid-run kills it and leaves the row
#: RUNNING for ever, which without an age limit would disable the button permanently. The same
#: reasoning and the same figure as Integrations' COLLECTION_LOCK_MAX_AGE.
FINDINGS_LOCK_MAX_AGE = timedelta(hours=2)


def findings_run_in_progress() -> AssessmentRun | None:
    """The findings run currently filling, or None. Orphans are ignored, not resumed."""
    return (AssessmentRun.objects
            .filter(status=AssessmentRun.Status.RUNNING,
                    started_at__gte=timezone.now() - FINDINGS_LOCK_MAX_AGE)
            .order_by("-started_at")
            .first())


def regenerate_findings(assessment_run: AssessmentRun | None = None) -> FindingRunResult:
    if assessment_run is None:
        assessment_run = open_findings_run()
    totals = [0, 0, 0, 0]
    by_kind = {}
    try:
        for label, _control_type, generate in GENERATORS:
            counts = generate(assessment_run)
            by_kind[label] = counts
            totals = [a + b for a, b in zip(totals, counts)]
    except Exception as exc:
        # One generator failing fails the run. A partially-filled run reported as complete
        # would understate findings, which is the direction that hides problems.
        assessment_run.mark_failed()
        assessment_run.notes = f"Run failed: {type(exc).__name__}: {exc}"[:2000]
        assessment_run.save(update_fields=["status", "completed_at", "notes"])
        raise

    assessment_run.mark_completed()
    # THE RUN REPORTS ITSELF. The outcome used to be a Django message written by the view, and
    # the view no longer waits for the run - it starts a thread and returns. A message cannot be
    # written from there, and the one signal that most needed carrying is the skipped-query
    # count: a query that no longer compiles makes its control contribute nothing, which reads
    # exactly like a clean result. So the sentence lives on the run, survives navigation, and is
    # still there when somebody asks later what that run actually did.
    assessment_run.notes = summarise_run(*totals)
    assessment_run.save(update_fields=["status", "completed_at", "notes"])
    return FindingRunResult(
        assessment_run=assessment_run,
        controls_evaluated=totals[0], findings_created=totals[1],
        query_links_created=totals[2], skipped_queries=totals[3], by_kind=by_kind)
