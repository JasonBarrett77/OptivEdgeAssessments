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
    FindingKind(m.NormalizationFinding, "normalization_issue",
                m.Control.ControlType.NORMALIZATION, "normalization issue"),
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
    FindingKind(m.WildfireSettingsFinding, "wildfire_settings",
                m.Control.ControlType.WILDFIRE_SETTINGS, "wildfire settings"),
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
    FindingKind(m.IkeCryptoProfileFinding, "ike_crypto_profile",
                m.Control.ControlType.IKE_CRYPTO_PROFILE, "IKE crypto profile"),
    FindingKind(m.IkeGatewayFinding, "ike_gateway",
                m.Control.ControlType.IKE_GATEWAY, "IKE gateway"),
    # "high availability" rather than "high availability configuration": the label goes into
    # prose and the subject is the relationship, not the node that describes it.
    FindingKind(m.HighAvailabilityFinding, "high_availability_config",
                m.Control.ControlType.HIGH_AVAILABILITY, "high availability"),
    FindingKind(m.PanoramaRegistrationFinding, "panorama_registration",
                m.Control.ControlType.PANORAMA_REGISTRATION, "panorama registration"),
    # Network hardening. Six kinds, and `global LLDP setting` is registered with no shipped
    # control over it - PAN-NET-003 asserts across two models and one control cannot hold both.
    # Registered anyway, because this tuple falling behind is exactly how five models once
    # dropped 22 findings out of the client deliverable with nothing failing.
    FindingKind(m.InterfaceFinding, "interface",
                m.Control.ControlType.FIREWALL_INTERFACE, "interface"),
    FindingKind(m.SessionSettingsFinding, "session_settings",
                m.Control.ControlType.SESSION_SETTINGS, "session settings"),
    FindingKind(m.LldpGlobalFinding, "lldp_global_settings",
                m.Control.ControlType.LLDP_GLOBAL, "global LLDP setting"),
    FindingKind(m.DhcpInterfaceConfigFinding, "dhcp_interface_config",
                m.Control.ControlType.DHCP_INTERFACE_CONFIG, "DHCP interface configuration"),
    FindingKind(m.TunnelInspectionFinding, "tunnel_inspection_coverage",
                m.Control.ControlType.TUNNEL_INSPECTION, "tunnel inspection coverage"),
    FindingKind(m.RoutingAdjacencyFinding, "routing_adjacency",
                m.Control.ControlType.ROUTING_ADJACENCY, "routing adjacency"),
    # The four `saas-security` subjects. THREE OF THE LABELS NAME A VERDICT rather than an
    # object, because that is what the row is - a conclusion about everything an enforcement
    # point can reach, written because the commonest state of this domain is that no entry
    # exists for a per-entry row to be about.
    FindingKind(m.SanctionedApplicationMarkingFinding, "sanctioned_application_marking",
                m.Control.ControlType.SANCTIONED_APPLICATION_MARKING,
                "sanctioned application marking"),
    FindingKind(m.SaasUrlFilteringPostureFinding, "saas_url_filtering_posture",
                m.Control.ControlType.SAAS_URL_FILTERING_POSTURE,
                "SaaS URL filtering posture"),
    FindingKind(m.SaasApplicationPolicyPostureFinding, "saas_application_policy_posture",
                m.Control.ControlType.SAAS_APPLICATION_POLICY_POSTURE,
                "SaaS application policy posture"),
    FindingKind(m.CloudAppEngineFinding, "cloud_app_engine_setting",
                m.Control.ControlType.CLOUD_APP_ENGINE_SETTING, "App-ID Cloud Engine"),
    # The three `device-id-iot` subjects. TWO CONTROLS SHARE THE FIRST KIND - PAN-IOT-001 asserts
    # over the entitlement and the wiring, PAN-IOT-003 over the currency of the installed
    # classification data - because all three instruments are device-wide and land on one row.
    # The zone is the one model here that shipped long before its control: nothing had ever
    # asserted over a zone, so it had no kind. The third names a VERDICT rather than an object,
    # like the SaaS three above, because the commonest state is a rule set with no device
    # dimension anywhere in it and the subject is the enforcement point.
    FindingKind(m.DeviceIdentificationFinding, "device_identification_state",
                m.Control.ControlType.DEVICE_IDENTIFICATION, "device identification"),
    FindingKind(m.ZoneFinding, "zone",
                m.Control.ControlType.ZONE, "security zone"),
    FindingKind(m.RulebaseDeviceMatchFinding, "rulebase_device_match_verdict",
                m.Control.ControlType.RULEBASE_DEVICE_MATCH, "rulebase device match"),
    # `file-data-filtering` adds ONE kind for its two models. The profile kinds - file-blocking
    # and data-filtering - report through `security_profile` above, which already had a kind, a
    # generator and a search surface; PAN-FIL-001, -002 and -004 reuse it. Only PAN-FIL-003's
    # first half needed a kind of its own, and it NAMES A VERDICT rather than an object, like the
    # SaaS three and the rulebase match above: the commonest failing state is no data-filtering
    # profile anywhere beneath the enforcement point, so the subject is the point.
    FindingKind(m.DataFilteringPostureFinding, "data_filtering_posture",
                m.Control.ControlType.DATA_FILTERING_POSTURE, "data filtering posture"),
    # `globalprotect-portal` adds THREE kinds for its three models, because every one of them is a
    # control's target: the portal entry (PAN-GPP-001, -003, -004, -005), its client-auth ROW
    # (PAN-GPP-002) and the vsys above both (PAN-GPP-006). None of the three had a kind, a
    # generator or a search surface before this change.
    #
    # THE ROW IS A KIND OF ITS OWN AND NOT A ROLL-UP ONTO THE PORTAL. A portal can demand both
    # factors of one endpoint class and neither of another - measured, two rows of one portal at
    # `high` and at `no_finding` - so a portal-keyed finding would report one verdict an engineer
    # cannot act on, which is the to-many downward grain standing ruling 6 refuses.
    FindingKind(m.GlobalProtectPortalFinding, "globalprotect_portal",
                m.Control.ControlType.GLOBALPROTECT_PORTAL, "GlobalProtect portal"),
    FindingKind(m.GlobalProtectPortalClientAuthFinding, "globalprotect_portal_client_auth_row",
                m.Control.ControlType.GLOBALPROTECT_PORTAL_CLIENT_AUTH,
                "GlobalProtect portal authentication row"),
    # A VERDICT rather than an object, like the SaaS three and the data-filtering posture above:
    # the commonest thing it reports is an ABSENCE - no portal, no published application, no
    # posture matcher - and nothing that does not exist can carry a row.
    FindingKind(m.GlobalProtectEnforcementPointFinding, "globalprotect_enforcement_point",
                m.Control.ControlType.GLOBALPROTECT_ENFORCEMENT_POINT,
                "GlobalProtect enforcement point"),
    # `platform-lifecycle` adds THREE kinds for its three models, because each of them is a
    # control's target and none of the three had a kind, a generator or a search surface before
    # this change. All three are DEVICE-WIDE SINGLETONS - one row per appliance, no vsys axis and
    # no entry name - so each finding's subject is the appliance and none declares `subject_scope`.
    #
    # The label is PLURAL and the reason is the one `test_labels_are_unique_and_prose_shaped`
    # allows for: the subject is one row carrying EVERY content stream as its own column, which is
    # stage 5's `identity.one_row_per` in terms, and the vendor's own screen (Device > Dynamic
    # Updates) lists several. "firewall content stream" would name one stream, which is the thing
    # this grain exists not to be.
    FindingKind(m.FirewallContentStreamsFinding, "firewall_content_streams",
                m.Control.ControlType.FIREWALL_CONTENT_STREAMS, "firewall content streams"),
    # A CONCLUSION ABOUT the licence table rather than one licence, which is what lets one control
    # report an entitlement that is MISSING. `LicenceEntitlement` holds the per-licence rows and
    # has no kind: no assertion record of this domain names that subject, and an absent
    # subscription has no row of its own to be reported on.
    FindingKind(m.LicenceInventoryFinding, "licence_inventory",
                m.Control.ControlType.LICENCE_INVENTORY, "licence inventory"),
    # The label names the MECHANISM rather than the node's leaves, because the control grades one
    # ordered verdict over them: stage 3's ordering - "on with no threshold" being worse than "on
    # with thresholds and no route" - is not expressible as a conjunction of the leaves.
    FindingKind(m.LogAlarmSettingsFinding, "log_alarm_settings",
                m.Control.ControlType.LOG_ALARM_SETTINGS, "log database alarm mechanism"),
    # `updates`. ONE kind for FOUR controls - PAN-UPD-001, -002, -004 and -005 - because all
    # five content types live on one row keyed by the appliance. A DEVICE-WIDE SINGLETON with no
    # vsys axis and no entry name, so the finding's subject is the appliance and it declares no
    # `subject_scope`; on an HA pair it yields two rows for what an operator calls one schedule,
    # which is correct because the node does not sync across peers.
    #
    # THE LABEL IS SINGULAR AND NAMES THE NODE, not the five content types it holds. The subject
    # is one `update-schedule` node - the vendor's own Device > Dynamic Updates screen is one
    # screen - so "content update schedule" names exactly the thing a finding is about and needs
    # no entry in `PLURAL_BY_NAME`.
    FindingKind(m.ContentUpdateScheduleFinding, "content_update_schedule",
                m.Control.ControlType.CONTENT_UPDATE_SCHEDULE, "content update schedule"),
    # `url-filtering`. ONE kind for ONE control - PAN-URL-006 - and the domain's other FIVE
    # controls need no line here at all: they target `SecurityProfile`, which already has a kind,
    # a generator and a search surface, exactly as PAN-FIL-001, -002 and -004 reuse it above.
    #
    # A NAMED OBJECT THAT COLLIDES ON NAME ACROSS SCOPES, so the model declares `subject_scope`:
    # one category name can exist at a vsys, at the firewall's own shared scope, in a Panorama
    # device group and in the pushed view, and the remediation differs by scope.
    #
    # THE LABEL IS SINGULAR and names the object as the vendor's own Objects > Custom Objects >
    # URL Category screen names it, so it needs no entry in `PLURAL_BY_NAME`.
    FindingKind(m.CustomUrlCategoryFinding, "custom_url_category",
                m.Control.ControlType.CUSTOM_URL_CATEGORY, "custom URL category"),
    # `user-id`. TWO kinds for TWO new models, and the domain's other two controls need no line
    # here at all: PAN-UID-001 reports through `zone` and PAN-UID-005 through
    # `management_interface`, both of which already have a kind, a generator and a search
    # surface - exactly as PAN-FIL-001/-002/-004 and the five url-filtering controls reuse
    # `security_profile` above.
    #
    # BOTH NAME A VERDICT OVER AN ENFORCEMENT POINT rather than a named entry, like the SaaS
    # three, the rulebase match and the data-filtering posture above, so both models declare
    # `subject_scope`: the row has no entry name, `subject_name` carries the vsys and without
    # the appliance beside it two findings about two appliances are one row to any presentation
    # that groups by subject name.
    #
    # THREE CONTROLS SHARE THE FIRST KIND - PAN-UID-003 asserts over client probing, PAN-UID-004
    # over the service account and session reading, PAN-UID-006 over mapping expiry - because
    # all of them live on one per-vsys agent settings node.
    #
    # `integrations.UserIdMonitoredServer` GETS NO KIND. It is the subject of the one PAN-UID-005
    # assertion record this domain leaves silent, so no control can produce a finding over it and
    # a kind would register a generator nothing dispatches to. That is a deliberate omission and
    # not this tuple falling behind - the failure mode the comment on the network-hardening block
    # above describes - and the stage 8 artifact for `user-id` records it in
    # `subjects_in_two_models` with `built: false`.
    FindingKind(m.UserIdCollectorFinding, "user_id_collector",
                m.Control.ControlType.USER_ID_COLLECTOR, "User-ID collector"),
    FindingKind(m.UserIdDiscoveryBoundFinding, "user_id_discovery_bound",
                m.Control.ControlType.USER_ID_DISCOVERY_BOUND, "User-ID discovery bound"),
    # `decryption-profiles`. ONE kind for ONE new model, and the domain's other SIX controls
    # need no line here at all: PAN-DCP-001 to -005 and -007 report through `security_profile`
    # above, over the `decryption` kind of the profile model, which already has a kind, a
    # generator and a search surface - exactly as the five url-filtering controls and
    # PAN-FIL-001/-002/-004 reuse it.
    #
    # THE SUBJECT IS THE APPLIANCE, so this model declares NO `subject_scope` - unlike the two
    # User-ID kinds above, whose subject is an enforcement point and whose `subject_name` is
    # therefore a vsys name that repeats across the estate. A hostname does not.
    #
    # `integrations.Certificate` ALREADY HAS A KIND (`certificate`, above) AND GETS NOTHING FROM
    # THIS DOMAIN. PAN-DCP-006's two certificate-side assertion records are discharged
    # `not_in_configuration` and `engineer_answers`, so neither owes a query and neither can
    # produce a finding; there is no second control id to register and nothing to add.
    #
    # THE LABEL IS `forward-proxy signing designation` AND NOT `decryption settings`, because
    # `test_labels_are_unique_and_prose_shaped` requires a SINGULAR label and the plural
    # allowlist beside it is for a subject that genuinely is a CLUSTER of settings on one panel.
    # This one is not: the node holds ONE designation pair, which is the thing a finding is about
    # and the thing an engineer changes. The control type keeps the model's own name.
    FindingKind(m.DecryptionSettingsFinding, "decryption_settings",
                m.Control.ControlType.DECRYPTION_SETTINGS,
                "forward-proxy signing designation"),
    # `globalprotect-gateway` adds THREE kinds for its three new models. The domain's fourth
    # model, the GlobalProtect enforcement point, already has a kind above and PAN-GPG-005
    # reuses it - which is why there are three entries here for a seven-control domain.
    #
    # EVERY LABEL HERE IS SINGULAR AND NONE IS IN THE PLURAL ALLOWLIST, which is a check worth
    # making deliberately rather than discovering: `test_labels_are_unique_and_prose_shaped`
    # asserts no label ends in `s` outside its own named exceptions, and the `decryption-profiles`
    # run took one failure out of 994 from a label transcribed off a model whose class name ends
    # in `Settings`. `GlobalProtectGatewayAgentConfig` ends in `Config`, which is already
    # singular, so the transcription is safe here - but the label is still written as the noun
    # phrase for what the row IS rather than as the class name.
    #
    # NONE OF THESE THREE KINDS HAS EVER PRODUCED A ROW, because no GlobalProtect gateway exists
    # in the measured estate. They are registered because registration is about the catalogue and
    # not about one lab's contents - the `ha-panorama` precedent - and because a query that cannot
    # compile is catchable with no rows at all, which is the one guarantee this domain can give.
    FindingKind(m.GlobalProtectGatewayFinding, "globalprotect_gateway",
                m.Control.ControlType.GLOBALPROTECT_GATEWAY, "GlobalProtect gateway"),
    # The row and not the gateway, for the per-platform reason the portal's own row kind carries:
    # one gateway can point a Windows row at a strong identity service and an `Any` row at the
    # firewall's own local database.
    FindingKind(m.GlobalProtectGatewayClientAuthFinding,
                "globalprotect_gateway_client_auth_row",
                m.Control.ControlType.GLOBALPROTECT_GATEWAY_CLIENT_AUTH,
                "GlobalProtect gateway authentication row"),
    # Shared by PAN-GPG-003 and PAN-GPG-004 - two controls, one model, one kind, which is what
    # `KIND_BY_MODEL` requires: a finding model may appear in this tuple exactly once.
    FindingKind(m.GlobalProtectGatewayAgentConfigFinding,
                "globalprotect_gateway_agent_config",
                m.Control.ControlType.GLOBALPROTECT_GATEWAY_AGENT_CONFIG,
                "GlobalProtect gateway agent configuration"),
    # `zone-dos-protection`. TWO kinds for a domain of eight controls, because its other two
    # subjects reuse kinds that already ship: PAN-ZON-001 reuses `security zone` and PAN-ZON-008
    # reuses `security profile`. Shared by PAN-ZON-002 to -006 - five controls, one model, one
    # kind, which is what `KIND_BY_MODEL` requires: a finding model may appear here exactly once.
    FindingKind(m.ZoneProtectionProfileFinding, "zone_protection_profile",
                m.Control.ControlType.ZONE_PROTECTION_PROFILE, "zone protection profile"),
    # PAN-ZON-007 only, and only one of its two halves - the other is discharged onto the
    # customer's asset inventory and has no configurational form at all.
    FindingKind(m.DosPolicyRuleFinding, "dos_policy_rule",
                m.Control.ControlType.DOS_POLICY_RULE, "DoS policy rule"),
)

FINDING_MODELS = tuple(kind.model for kind in FINDING_KINDS)
KIND_BY_MODEL = {kind.model: kind for kind in FINDING_KINDS}


def open_finding_counts() -> dict[str, int]:
    """{label: open findings} across every kind. The estate-wide number, from one place."""
    return {kind.label: kind.model.objects.filter(status=kind.model.Status.OPEN).count()
            for kind in FINDING_KINDS}


def total_open_findings() -> int:
    return sum(open_finding_counts().values())
