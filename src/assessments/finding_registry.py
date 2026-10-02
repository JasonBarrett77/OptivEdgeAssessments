"""Every finding model, in one place, so that "all findings" is derivable.

Two surfaces enumerated finding models by NAME - the findings page and the client report -
and both still list two of seven. Five models drifted out with no test failing, taking 22 of
the lab's 72 findings and the entire certificates domain out of the client deliverable, because
naming two models is indistinguishable from there being two.

So: consumers iterate this. A new finding model is registered once here and every aggregate
picks it up. `test_finding_registry` asserts the registry holds EVERY concrete subclass of
FindingBase, which is what makes registering it non-optional - forgetting fails a test rather
than silently narrowing a report.

This deliberately does not replace the typed models with one generic Finding. Typed foreign
keys give cascade behaviour, per-object indexes and queries that read like the domain; the
cost was never the models, it was that nothing enumerated them.
"""

from __future__ import annotations

from typing import Callable, NamedTuple

from django.db import models

from assessments import models as m


class FindingKind(NamedTuple):
    #: The concrete finding model.
    model: type[models.Model]
    #: Attribute holding the thing the finding is about.
    subject_field: str
    #: Control.ControlType value whose controls produce these.
    control_type: str
    #: Singular, lowercase, for prose: "certificate profile".
    label: str

    @property
    def name(self) -> str:
        return self.model.__name__

    def subject_of(self, finding):
        return getattr(finding, self.subject_field)


FINDING_KINDS: tuple[FindingKind, ...] = (
    FindingKind(m.RuleFinding, "security_rule",
                m.Control.ControlType.SECURITY_RULE, "security rule"),
    FindingKind(m.CoverageFinding, "address_object",
                m.Control.ControlType.COVERAGE, "coverage"),
    FindingKind(m.ManagementInterfaceFinding, "management_interface",
                m.Control.ControlType.MANAGEMENT_INTERFACE, "management interface"),
    FindingKind(m.InterfaceManagementProfileFinding, "interface_management_profile",
                m.Control.ControlType.INTERFACE_MANAGEMENT_PROFILE, "interface management profile"),
    FindingKind(m.SslTlsServiceProfileFinding, "ssl_tls_service_profile",
                m.Control.ControlType.SSL_TLS_SERVICE_PROFILE, "SSL/TLS service profile"),
    FindingKind(m.CertificateProfileFinding, "certificate_profile",
                m.Control.ControlType.CERTIFICATE_PROFILE, "certificate profile"),
    FindingKind(m.CertificateFinding, "certificate",
                m.Control.ControlType.CERTIFICATE, "certificate"),
    FindingKind(m.AuthenticationProfileFinding, "authentication_profile",
                m.Control.ControlType.AUTHENTICATION_PROFILE, "authentication profile"),
    FindingKind(m.AuthenticationSequenceFinding, "authentication_sequence",
                m.Control.ControlType.AUTHENTICATION_SEQUENCE, "authentication sequence"),
    FindingKind(m.PasswordProfileFinding, "password_profile",
                m.Control.ControlType.PASSWORD_PROFILE, "password profile"),
    FindingKind(m.SecurityProfileFinding, "security_profile",
                m.Control.ControlType.SECURITY_PROFILE, "security profile"),
    FindingKind(m.PasswordComplexityFinding, "password_complexity_policy",
                m.Control.ControlType.PASSWORD_COMPLEXITY, "password complexity"),
    FindingKind(m.AuthenticationSettingsFinding, "authentication_settings",
                m.Control.ControlType.AUTHENTICATION_SETTINGS, "authentication settings"),
    FindingKind(m.LoginBannerFinding, "login_banner",
                m.Control.ControlType.LOGIN_BANNER, "login banner"),
    FindingKind(m.MasterKeyFinding, "master_key",
                m.Control.ControlType.MASTER_KEY, "master key"),
    FindingKind(m.ManagementTlsFinding, "management_tls_binding",
                m.Control.ControlType.MANAGEMENT_TLS, "management TLS binding"),
    FindingKind(m.ManagementSshFinding, "management_ssh_settings",
                m.Control.ControlType.MANAGEMENT_SSH, "management SSH server"),
    FindingKind(m.UpdateServerSettingsFinding, "update_server_settings",
                m.Control.ControlType.UPDATE_SERVER, "update server settings"),
    FindingKind(m.LoggingSettingsFinding, "logging_settings",
                m.Control.ControlType.LOGGING_SETTINGS, "logging settings"),
    FindingKind(m.AdminUserFinding, "admin_user",
                m.Control.ControlType.ADMIN_USER, "administrator"),
    FindingKind(m.ServerProfileFinding, "server_profile",
                m.Control.ControlType.SERVER_PROFILE, "AAA server profile"),
    # "NTP" and "SNMP" rather than "NTP settings": the singular rule is a heuristic for catching
    # a plural where a singular was meant, and these are the vendor's own names for the screens
    # (Setup > Services > NTP, Setup > Operations > SNMP Setup). Adding them to the plural
    # allowlist would have been dodging a rule that is right.
    FindingKind(m.NtpSettingsFinding, "ntp_settings",
                m.Control.ControlType.NTP_SETTINGS, "NTP"),
    FindingKind(m.SnmpSettingsFinding, "snmp_settings",
                m.Control.ControlType.SNMP_SETTINGS, "SNMP"),
    FindingKind(m.SystemIdentityFinding, "system_identity",
                m.Control.ControlType.SYSTEM_IDENTITY, "system identity"),
)

FINDING_MODELS = tuple(kind.model for kind in FINDING_KINDS)
KIND_BY_MODEL = {kind.model: kind for kind in FINDING_KINDS}


def open_finding_counts() -> dict[str, int]:
    """{label: open findings} across every kind. The estate-wide number, from one place."""
    return {kind.label: kind.model.objects.filter(status=kind.model.Status.OPEN).count()
            for kind in FINDING_KINDS}


def total_open_findings() -> int:
    return sum(open_finding_counts().values())
