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
keys give cascade behavior, per-object indexes and queries that read like the domain; the
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
    #: WHAT A CLIENT CALLS THIS OBJECT, for the health check document's observation tables.
    #:
    #: NOT `label`, and the difference is the point. `label` is singular lowercase prose because
    #: three surfaces print it mid-sentence - "39 findings across 32 zones" - and it is unique
    #: per kind. This is the COMMON REPRESENTATION, close to what the UI calls the object, and
    #: several kinds share one: a gateway, its agent configuration and its authentication rows
    #: are all `GlobalProtect Gateway` to the person reading the report. Jason, 2026-11-06:
    #: *"the control detail which we'll work on later, as well as the other artifacts, will
    #: have more information about the exact remediation spot. The term we're looking for now
    #: is the common representation."*
    #:
    #: A REQUIRED FIELD rather than a lookup table, so a finding kind added tomorrow cannot
    #: reach a client document without somebody choosing what to call its object.
    common_name: str
    #: WHAT A CLIENT CALLS SEVERAL OF THEM, lowercase, for the Occurrences line of a Control
    #: table: "1 high, 9 medium, across 10 AAA server profiles".
    #:
    #: NOT `label` PLURALIZED, which is what that line printed first. `label` is the registry's
    #: own singular, written for whoever reads a query - and measured over all 75 kinds
    #: 2026-11-07, pluralizing it hands a client "12 password complexities", "coverages", "high
    #: availabilities", "virtual system rule postures" and "management plane addressings". Those
    #: are our words for a row, not the client's for the thing on their firewall.
    #:
    #: NOT `common_name` EITHER, and for two reasons. It is Title Case because it stands as a
    #: heading, and it is deliberately COARSE - three GlobalProtect kinds share `GlobalProtect
    #: Gateway` - so a count of gateways, of their authentication rows and of their agent
    #: configurations would all read as a count of gateways.
    #:
    #: WRITTEN OUT RATHER THAN DERIVED, because no pluralizer can make the judgement:
    #: `management plane addressing` becomes `management plane addresses` and `tunnel inspection
    #: coverage` becomes `tunnel inspection rulebases`. Where the label is already the term the
    #: vendor's own screen uses - `security rule`, `login banner`, `certificate` - its plural IS
    #: the answer, and 44 of the 75 are exactly that.
    #:
    #: A REQUIRED FIELD for the reason `common_name` is one: a kind added tomorrow cannot reach
    #: this document's prose without somebody choosing the client's word for a dozen of them.
    client_plural: str

    #: The same word for ONE of them, where `label` is not it. Empty means `label` serves, which
    #: it does for the 44 kinds whose plural is just the label pluralized.
    #:
    #: WHY THE LINE NEEDS BOTH. The Occurrences line counts, and a count can be one: measured
    #: the lab 2026-11-07, 11 of the 203 control blocks are about a single object, and six of
    #: them read `1, across 1 AAA server profiles` - `security rules`, `decryption rules`,
    #: `IKE gateways`, `security zones` and `password profiles` the same way. Falling back to
    #: `label` at one object would have printed `across 1 password complexity`, which is the
    #: vocabulary `client_plural` exists to keep out, so the kinds that chose their plural
    #: choose their singular too.
    #:
    #: A SETTINGS GROUP CARRIES ITS OWN PLURAL HERE, because that is the English: one appliance
    #: has one set of `logging settings`, and `1 logging setting` would be a different claim.
    #: `test_finding_registry` requires this field of exactly the kinds whose plural is not
    #: `plural_noun(2, label)`, so the two cannot drift apart.
    client_singular: str = ""

    @property
    def name(self) -> str:
        return self.model.__name__

    def subject_of(self, finding):
        return getattr(finding, self.subject_field)


FINDING_KINDS: tuple[FindingKind, ...] = (
    FindingKind(m.RuleFinding, "security_rule",
                m.Control.ControlType.SECURITY_RULE, "security rule", "Security Rule",
                "security rules"),
    FindingKind(m.CoverageFinding, "address_object",
                m.Control.ControlType.COVERAGE, "coverage", "Assessment Coverage",
                "address objects",
                "address object"),
    FindingKind(m.NormalizationFinding, "normalization_issue",
                m.Control.ControlType.NORMALIZATION, "normalization issue", "Assessment Coverage",
                "unreadable configuration entries",
                "unreadable configuration entry"),
    FindingKind(m.ManagementInterfaceFinding, "management_interface",
                m.Control.ControlType.MANAGEMENT_INTERFACE, "management interface", "Management Interface",
                "management interfaces"),
    FindingKind(m.InterfaceManagementProfileFinding, "interface_management_profile",
                m.Control.ControlType.INTERFACE_MANAGEMENT_PROFILE, "interface management profile", "Interface Management Profile",
                "interface management profiles"),
    FindingKind(m.SslTlsServiceProfileFinding, "ssl_tls_service_profile",
                m.Control.ControlType.SSL_TLS_SERVICE_PROFILE, "SSL/TLS service profile", "SSL/TLS Service Profile",
                "SSL/TLS service profiles"),
    FindingKind(m.CertificateProfileFinding, "certificate_profile",
                m.Control.ControlType.CERTIFICATE_PROFILE, "certificate profile", "Certificate Profile",
                "certificate profiles"),
    FindingKind(m.CertificateFinding, "certificate",
                m.Control.ControlType.CERTIFICATE, "certificate", "Certificate",
                "certificates"),
    FindingKind(m.AuthenticationProfileFinding, "authentication_profile",
                m.Control.ControlType.AUTHENTICATION_PROFILE, "authentication profile", "Authentication Profile",
                "authentication profiles"),
    FindingKind(m.AuthenticationSequenceFinding, "authentication_sequence",
                m.Control.ControlType.AUTHENTICATION_SEQUENCE, "authentication sequence", "Authentication Sequence",
                "authentication sequences"),
    FindingKind(m.PasswordProfileFinding, "password_profile",
                m.Control.ControlType.PASSWORD_PROFILE, "password profile", "Password Profile",
                "password profiles"),
    FindingKind(m.SecurityProfileFinding, "security_profile",
                m.Control.ControlType.SECURITY_PROFILE, "security profile", "Security Profile",
                "security profiles"),
    FindingKind(m.PasswordComplexityFinding, "password_complexity_policy",
                m.Control.ControlType.PASSWORD_COMPLEXITY, "password complexity", "Minimum Password Complexity",
                "password complexity settings",
                "password complexity settings"),
    FindingKind(m.AuthenticationSettingsFinding, "authentication_settings",
                m.Control.ControlType.AUTHENTICATION_SETTINGS, "authentication settings", "Authentication Settings",
                "authentication settings"),
    FindingKind(m.LoginBannerFinding, "login_banner",
                m.Control.ControlType.LOGIN_BANNER, "login banner", "Login Banner",
                "login banners"),
    FindingKind(m.MasterKeyFinding, "master_key",
                m.Control.ControlType.MASTER_KEY, "master key", "Master Key",
                "master keys"),
    FindingKind(m.ManagementTlsFinding, "management_tls_binding",
                m.Control.ControlType.MANAGEMENT_TLS, "management TLS binding", "Management Interface",
                "management TLS bindings"),
    FindingKind(m.ManagementSshFinding, "management_ssh_settings",
                m.Control.ControlType.MANAGEMENT_SSH, "management SSH server", "SSH Service Profile",
                "management SSH servers"),
    FindingKind(m.UpdateServerSettingsFinding, "update_server_settings",
                m.Control.ControlType.UPDATE_SERVER, "update server settings", "Dynamic Updates",
                "update server settings"),
    FindingKind(m.LoggingSettingsFinding, "logging_settings",
                m.Control.ControlType.LOGGING_SETTINGS, "logging settings", "Logging Settings",
                "logging settings"),
    FindingKind(m.WildfireSettingsFinding, "wildfire_settings",
                m.Control.ControlType.WILDFIRE_SETTINGS, "wildfire settings", "WildFire Settings",
                "WildFire settings",
                "WildFire settings"),
    FindingKind(m.AdminUserFinding, "admin_user",
                m.Control.ControlType.ADMIN_USER, "administrator", "Administrator",
                "administrators"),
    FindingKind(m.ServerProfileFinding, "server_profile",
                m.Control.ControlType.SERVER_PROFILE, "AAA server profile", "AAA Server Profile",
                "AAA server profiles"),
    # "NTP" and "SNMP" rather than "NTP settings": the singular rule is a heuristic for catching
    # a plural where a singular was meant, and these are the vendor's own names for the screens
    # (Setup > Services > NTP, Setup > Operations > SNMP Setup). Adding them to the plural
    # allowlist would have been dodging a rule that is right.
    FindingKind(m.NtpSettingsFinding, "ntp_settings",
                m.Control.ControlType.NTP_SETTINGS, "NTP", "NTP",
                "NTP settings",
                "NTP settings"),
    FindingKind(m.SnmpSettingsFinding, "snmp_settings",
                m.Control.ControlType.SNMP_SETTINGS, "SNMP", "SNMP",
                "SNMP settings",
                "SNMP settings"),
    FindingKind(m.SystemIdentityFinding, "system_identity",
                # `firewalls` AND NOT `general settings`, which is what this said first.
                # `SystemIdentityFinding` is one row per APPLIANCE - its name, its time zone and
                # its management addressing - so `across 4 general settings` counts panels where
                # the reader needs devices, and a panel is not a thing a client counts. Jason,
                # 2026-11-07, on four values flagged for his ruling: *"Go with your
                # recommendations on all four nouns"*.
                m.Control.ControlType.SYSTEM_IDENTITY, "system identity", "General Settings",
                "firewalls",
                "firewall"),
    # `device-services`, 2026-11-01. The labels are SINGULAR and are not the model names:
    # `test_labels_are_unique_and_prose_shaped` refuses a plural, and the allowlist beside it is
    # for a subject the vendor's own UI calls plural - neither of these is one.
    FindingKind(m.DnsSettingsFinding, "dns_settings",
                m.Control.ControlType.DNS_SETTINGS, "management resolver set", "DNS",
                "DNS settings",
                "DNS settings"),
    FindingKind(m.ServiceRouteFinding, "service_route",
                m.Control.ControlType.SERVICE_ROUTE, "management service path set", "Service Route",
                "service route configurations",
                "service route configuration"),
    FindingKind(m.IkeCryptoProfileFinding, "ike_crypto_profile",
                m.Control.ControlType.IKE_CRYPTO_PROFILE, "IKE crypto profile", "IKE Crypto Profile",
                "IKE crypto profiles"),
    FindingKind(m.IkeGatewayFinding, "ike_gateway",
                m.Control.ControlType.IKE_GATEWAY, "IKE gateway", "IKE Gateway",
                "IKE gateways"),
    # PHASE 2, and two kinds rather than one: the proposal set and the tunnel that carries it
    # are different objects at different xpaths and `_CONTROL_TYPE_TARGET_MODEL` is one-to-one.
    FindingKind(m.IpsecCryptoProfileFinding, "ipsec_crypto_profile",
                m.Control.ControlType.IPSEC_CRYPTO_PROFILE, "IPSec crypto profile", "IPSec Crypto Profile",
                "IPSec crypto profiles"),
    FindingKind(m.IpsecTunnelFinding, "ipsec_tunnel",
                m.Control.ControlType.IPSEC_TUNNEL, "IPSec tunnel", "IPSec Tunnel",
                "IPSec tunnels"),
    # THE COMPOSITE OVER BOTH PHASES AND THE SUBJECT OF THE NINE STRENGTH CONTROLS. A third kind
    # rather than a widening of either of the two above: the path is a different grain - one row
    # per tunnel-and-gateway pair, plus one per unreferenced gateway - and the finding count on it
    # is the number of tunnels a weak proposal actually reaches.
    FindingKind(m.IpsecTunnelPathFinding, "ipsec_tunnel_path",
                m.Control.ControlType.IPSEC_TUNNEL_PATH, "IPSec tunnel path", "IPSec Tunnel",
                "IPSec tunnel paths"),
    # "high availability" rather than "high availability configuration": the label goes into
    # prose and the subject is the relationship, not the node that describes it.
    FindingKind(m.HighAvailabilityFinding, "high_availability_config",
                m.Control.ControlType.HIGH_AVAILABILITY, "high availability", "High Availability",
                "high availability settings",
                "high availability settings"),
    FindingKind(m.PanoramaRegistrationFinding, "panorama_registration",
                m.Control.ControlType.PANORAMA_REGISTRATION, "panorama registration", "Panorama Connectivity",
                "Panorama registrations",
                "Panorama registration"),
    # Network hardening. Six kinds, and `global LLDP setting` is registered with no shipped
    # control over it - PAN-NET-003 asserts across two models and one control cannot hold both.
    # Registered anyway, because this tuple falling behind is exactly how five models once
    # dropped 22 findings out of the client deliverable with nothing failing.
    FindingKind(m.InterfaceFinding, "interface",
                m.Control.ControlType.FIREWALL_INTERFACE, "interface", "Interface",
                "interfaces"),
    FindingKind(m.SessionSettingsFinding, "session_settings",
                m.Control.ControlType.SESSION_SETTINGS, "session settings", "Session Settings",
                "session settings"),
    FindingKind(m.LldpGlobalFinding, "lldp_global_settings",
                m.Control.ControlType.LLDP_GLOBAL, "global LLDP setting", "LLDP",
                "LLDP settings",
                "LLDP settings"),
    FindingKind(m.DhcpInterfaceConfigFinding, "dhcp_interface_config",
                m.Control.ControlType.DHCP_INTERFACE_CONFIG, "DHCP interface configuration", "DHCP Server",
                "DHCP interface configurations"),
    FindingKind(m.TunnelInspectionFinding, "tunnel_inspection_coverage",
                m.Control.ControlType.TUNNEL_INSPECTION, "tunnel inspection coverage", "Tunnel Inspection Rule",
                "tunnel inspection rulebases",
                "tunnel inspection rulebase"),
    FindingKind(m.RoutingAdjacencyFinding, "routing_adjacency",
                m.Control.ControlType.ROUTING_ADJACENCY, "routing adjacency", "Dynamic Routing",
                "routing adjacencies"),
    # The four `saas-security` subjects. THREE OF THE LABELS NAME A VERDICT rather than an
    # object, because that is what the row is - a conclusion about everything an enforcement
    # point can reach, written because the commonest state of this domain is that no entry
    # exists for a per-entry row to be about.
    FindingKind(m.SanctionedApplicationMarkingFinding, "sanctioned_application_marking",
                m.Control.ControlType.SANCTIONED_APPLICATION_MARKING,
                "sanctioned application marking", "SaaS Application",
                "sanctioned application inventories",
                "sanctioned application inventory"),
    FindingKind(m.SaasUrlFilteringPostureFinding, "saas_url_filtering_posture",
                m.Control.ControlType.SAAS_URL_FILTERING_POSTURE,
                "SaaS URL filtering posture", "URL Filtering Profile",
                "SaaS URL filtering postures"),
    FindingKind(m.SaasApplicationPolicyPostureFinding, "saas_application_policy_posture",
                m.Control.ControlType.SAAS_APPLICATION_POLICY_POSTURE,
                "SaaS application policy posture", "SaaS Application",
                "SaaS application policy postures"),
    FindingKind(m.CloudAppEngineFinding, "cloud_app_engine_setting",
                m.Control.ControlType.CLOUD_APP_ENGINE_SETTING, "App-ID Cloud Engine", "App-ID Cloud Engine",
                "App-ID Cloud Engine settings",
                "App-ID Cloud Engine settings"),
    # The three `device-id-iot` subjects. TWO CONTROLS SHARE THE FIRST KIND - PAN-IOT-001 asserts
    # over the entitlement and the wiring, PAN-IOT-003 over the currency of the installed
    # classification data - because all three instruments are device-wide and land on one row.
    # The zone is the one model here that shipped long before its control: nothing had ever
    # asserted over a zone, so it had no kind. The third names a VERDICT rather than an object,
    # like the SaaS three above, because the commonest state is a rule set with no device
    # dimension anywhere in it and the subject is the enforcement point.
    FindingKind(m.DeviceIdentificationFinding, "device_identification_state",
                m.Control.ControlType.DEVICE_IDENTIFICATION, "device identification", "Device-ID",
                "Device-ID settings",
                "Device-ID settings"),
    FindingKind(m.ZoneFinding, "zone",
                m.Control.ControlType.ZONE, "security zone", "Zone",
                "security zones"),
    FindingKind(m.RulebaseDeviceMatchFinding, "rulebase_device_match_verdict",
                m.Control.ControlType.RULEBASE_DEVICE_MATCH, "rulebase device match", "Device-ID",
                "security rulebases",
                "security rulebase"),
    # `file-data-filtering` adds ONE kind for its two models. The profile kinds - file-blocking
    # and data-filtering - report through `security_profile` above, which already had a kind, a
    # generator and a search surface; PAN-FIL-001, -002 and -004 reuse it. Only PAN-FIL-003's
    # first half needed a kind of its own, and it NAMES A VERDICT rather than an object, like the
    # SaaS three and the rulebase match above: the commonest failing state is no data-filtering
    # profile anywhere beneath the enforcement point, so the subject is the point.
    FindingKind(m.DataFilteringPostureFinding, "data_filtering_posture",
                m.Control.ControlType.DATA_FILTERING_POSTURE, "data filtering posture", "Data Filtering Profile",
                "data filtering postures"),
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
                m.Control.ControlType.GLOBALPROTECT_PORTAL, "GlobalProtect portal", "GlobalProtect Portal",
                "GlobalProtect portals"),
    FindingKind(m.GlobalProtectPortalClientAuthFinding, "globalprotect_portal_client_auth_row",
                m.Control.ControlType.GLOBALPROTECT_PORTAL_CLIENT_AUTH,
                "GlobalProtect portal authentication row", "GlobalProtect Portal",
                "GlobalProtect portal client authentication entries",
                "GlobalProtect portal client authentication entry"),
    # A VERDICT rather than an object, like the SaaS three and the data-filtering posture above:
    # the commonest thing it reports is an ABSENCE - no portal, no published application, no
    # posture matcher - and nothing that does not exist can carry a row.
    FindingKind(m.GlobalProtectEnforcementPointFinding, "globalprotect_enforcement_point",
                m.Control.ControlType.GLOBALPROTECT_ENFORCEMENT_POINT,
                # `virtual systems` STANDS, the one of the four flagged that was already
                # right: the row IS the vsys, as the model says above, and every alternative
                # names something the control exists to report the absence of. A count of
                # GlobalProtect deployments cannot include the vsys that has none.
                "GlobalProtect enforcement point", "GlobalProtect Gateway",
                "virtual systems",
                "virtual system"),
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
                m.Control.ControlType.FIREWALL_CONTENT_STREAMS, "firewall content streams", "Dynamic Updates",
                "firewall content streams"),
    # A CONCLUSION ABOUT the licence table rather than one licence, which is what lets one control
    # report an entitlement that is MISSING. `LicenceEntitlement` holds the per-licence rows and
    # has no kind: no assertion record of this domain names that subject, and an absent
    # subscription has no row of its own to be reported on.
    FindingKind(m.LicenceInventoryFinding, "licence_inventory",
                # ITS PLURAL IS DERIVABLE AGAIN. The label read `licence inventory` and the
                # client plural `license inventories` - the spelling was the whole of the
                # difference, which is why this kind was in the chosen list. The 2026-11-09
                # sweep made the label American too, so `plural_noun` now gets there on its own
                # and the singular belongs to `label` again.
                m.Control.ControlType.LICENCE_INVENTORY, "license inventory", "Licenses",
                "license inventories"),
    # The label names the MECHANISM rather than the node's leaves, because the control grades one
    # ordered verdict over them: stage 3's ordering - "on with no threshold" being worse than "on
    # with thresholds and no route" - is not expressible as a conjunction of the leaves.
    FindingKind(m.LogAlarmSettingsFinding, "log_alarm_settings",
                m.Control.ControlType.LOG_ALARM_SETTINGS, "log database alarm mechanism", "Logging Settings",
                "log database alarm settings",
                "log database alarm settings"),
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
                m.Control.ControlType.CONTENT_UPDATE_SCHEDULE, "content update schedule", "Dynamic Updates",
                "content update schedules"),
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
                m.Control.ControlType.CUSTOM_URL_CATEGORY, "custom URL category", "Custom URL Category",
                "custom URL categories"),
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
                m.Control.ControlType.USER_ID_COLLECTOR, "User-ID collector", "User-ID Agent",
                "User-ID agent settings",
                "User-ID agent settings"),
    FindingKind(m.UserIdDiscoveryBoundFinding, "user_id_discovery_bound",
                m.Control.ControlType.USER_ID_DISCOVERY_BOUND, "User-ID discovery bound", "User-ID Agent",
                "User-ID include/exclude network lists",
                "User-ID include/exclude network list"),
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
                # `firewalls` FOR THE REASON THE MODEL GIVES: *"THE SUBJECT IS THE APPLIANCE
                # AND NOT THE DESIGNATION SLOT"*, because the commonest failing state is no
                # certificate designated at all. `across 2 decryption settings` counts a panel
                # that the label above is at pains not to call a cluster of settings, and
                # naming the certificate would count certificates that do not exist.
                "forward-proxy signing designation", "Decryption Settings",
                "firewalls",
                "firewall"),
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
                m.Control.ControlType.GLOBALPROTECT_GATEWAY, "GlobalProtect gateway", "GlobalProtect Gateway",
                "GlobalProtect gateways"),
    # The row and not the gateway, for the per-platform reason the portal's own row kind carries:
    # one gateway can point a Windows row at a strong identity service and an `Any` row at the
    # firewall's own local database.
    FindingKind(m.GlobalProtectGatewayClientAuthFinding,
                "globalprotect_gateway_client_auth_row",
                m.Control.ControlType.GLOBALPROTECT_GATEWAY_CLIENT_AUTH,
                "GlobalProtect gateway authentication row", "GlobalProtect Gateway",
                "GlobalProtect gateway client authentication entries",
                "GlobalProtect gateway client authentication entry"),
    # Shared by PAN-GPG-003 and PAN-GPG-004 - two controls, one model, one kind, which is what
    # `KIND_BY_MODEL` requires: a finding model may appear in this tuple exactly once.
    FindingKind(m.GlobalProtectGatewayAgentConfigFinding,
                "globalprotect_gateway_agent_config",
                m.Control.ControlType.GLOBALPROTECT_GATEWAY_AGENT_CONFIG,
                "GlobalProtect gateway agent configuration", "GlobalProtect Gateway",
                "GlobalProtect gateway agent configurations"),
    # `zone-dos-protection`. TWO kinds for a domain of eight controls, because its other two
    # subjects reuse kinds that already ship: PAN-ZON-001 reuses `security zone` and PAN-ZON-008
    # reuses `security profile`. Shared by PAN-ZON-002 to -006 - five controls, one model, one
    # kind, which is what `KIND_BY_MODEL` requires: a finding model may appear here exactly once.
    FindingKind(m.ZoneProtectionProfileFinding, "zone_protection_profile",
                m.Control.ControlType.ZONE_PROTECTION_PROFILE, "zone protection profile", "Zone Protection Profile",
                "zone protection profiles"),
    # PAN-ZON-007 only, and only one of its two halves - the other is discharged onto the
    # customer's asset inventory and has no configurational form at all.
    FindingKind(m.DosPolicyRuleFinding, "dos_policy_rule",
                m.Control.ControlType.DOS_POLICY_RULE, "DoS policy rule", "DoS Protection Rule",
                "DoS protection rules",
                "DoS protection rule"),
    # `decryption-policy`. FOUR kinds for a domain of ten controls, and none of the four reuses
    # anything: the reverse of `_CONTROL_TYPE_TARGET_MODEL` answered NO TYPE for all four models
    # before this run touched it.
    #
    # Shared by PAN-DEC-002, -003, -005, -006, -007, -008 and -010 - seven controls, one model,
    # one kind, which is what `KIND_BY_MODEL` requires: a finding model may appear here exactly
    # once.
    FindingKind(m.DecryptionPolicyRuleFinding, "decryption_policy_rule",
                m.Control.ControlType.DECRYPTION_POLICY_RULE, "decryption policy rule", "Decryption Rule",
                "decryption rules",
                "decryption rule"),
    # PAN-DEC-001 and PAN-DEC-009. The grain that can report an ABSENT rulebase, which stage 4
    # measured as the commonest state of this domain and which the per-rule kind above has no row
    # for.
    FindingKind(m.DecryptionRulebaseCoverageFinding, "decryption_rulebase_verdict",
                m.Control.ControlType.DECRYPTION_RULEBASE_COVERAGE,
                "decryption rulebase coverage", "Decryption Rule",
                "decryption rulebases",
                "decryption rulebase"),
    # PAN-DEC-004's first record only.
    FindingKind(m.SslDecryptionExclusionFinding, "ssl_decryption_exclusion",
                m.Control.ControlType.SSL_DECRYPTION_EXCLUSION, "SSL decryption exclusion", "Decryption Exclusion",
                "SSL decryption exclusions"),
    # NO SHIPPED CONTROL PRODUCES ONE OF THESE - the `lldp_global` state, and the model's own
    # docstring argues it: PAN-DEC-004's second record names this model, a control has one target
    # model, and splitting the catalogue id is not a build run's decision.
    FindingKind(m.SslDecryptionVendorExclusionOptOutFinding,
                "ssl_decryption_vendor_exclusion_optout",
                m.Control.ControlType.SSL_DECRYPTION_VENDOR_EXCLUSION_OPTOUT,
                "SSL decryption vendor exclusion opt-out", "Decryption Exclusion",
                "SSL decryption vendor exclusion opt-outs"),
    # `logging`, 2026-11-01. TWO MINTS; the domain's eight other controls reuse
    # `logging_settings`, whose kind is already registered above and which therefore cost
    # nothing here. The labels are SINGULAR, as the device-services note beside them records.
    FindingKind(m.LogServerTargetFinding, "log_server_target",
                m.Control.ControlType.LOG_SERVER_TARGET, "log server target", "Log Forwarding",
                "log server targets"),
    FindingKind(m.VsysLogForwardingFinding, "vsys_log_forwarding",
                m.Control.ControlType.VSYS_LOG_FORWARDING, "virtual system log forwarding", "Log Forwarding",
                "virtual system log forwarding settings",
                "virtual system log forwarding settings"),
    # `management-services`, 2026-11-01. Both subjects are APPLIANCE-grained, so neither
    # finding model carries `subject_scope`: the appliance's own name is the scope.
    FindingKind(m.ManagementPlaneAddressingFinding, "management_plane_addressing",
                m.Control.ControlType.MANAGEMENT_PLANE_ADDRESSING,
                "management plane addressing", "Management Interface",
                "management plane addresses",
                "management plane address"),
    FindingKind(m.ApplianceOperationalModeFinding, "appliance_operational_mode",
                m.Control.ControlType.APPLIANCE_OPERATIONAL_MODE,
                "appliance operational mode", "Operational Mode",
                "appliance operational modes"),
    # `security-policy`, 2026-11-01. TWO MINTS and fifteen reuses of `security_rule`, whose kind
    # is registered at the top of this tuple and which therefore cost nothing here. The first
    # subject is per-VIRTUAL-SYSTEM so its finding model carries `subject_scope`; the second is
    # per-APPLIANCE so the appliance's own name is the scope.
    FindingKind(m.VsysRulePostureFinding, "vsys_rule_posture",
                # `security rulebases`, THE SAME WORDS AS `rulebase_device_match` ABOVE,
                # because it is the same object: one vsys's security rulebase, read for a
                # different verdict. Two nouns for it left a client comparing `3 security
                # rulebases` in one Control Detail table with `3 virtual system rulebases` in
                # the next and counting two sets of three. The distinction between the verdicts
                # is ours; the rulebase is theirs.
                m.Control.ControlType.VSYS_RULE_POSTURE, "virtual system rule posture", "Security Rulebase",
                "security rulebases",
                "security rulebase"),
    # ITS ONE CONTROL SHIPS INACTIVE, by Jason's decision of 2026-10-31. The kind is registered
    # anyway, because `test_every_control_type_has_a_finding_kind` requires it of the type and
    # because the catalogue carries the question with its reason rather than dropping it.
    FindingKind(m.PolicyRuleSettingsFinding, "policy_rule_settings",
                m.Control.ControlType.POLICY_RULE_SETTINGS, "policy rule settings", "Security Rulebase",
                "policy rule settings"),
)

FINDING_MODELS = tuple(kind.model for kind in FINDING_KINDS)
KIND_BY_MODEL = {kind.model: kind for kind in FINDING_KINDS}


def open_finding_counts() -> dict[str, int]:
    """{label: open findings} across every kind. The estate-wide number, from one place."""
    return {kind.label: kind.model.objects.filter(status=kind.model.Status.OPEN).count()
            for kind in FINDING_KINDS}


def total_open_findings() -> int:
    return sum(open_finding_counts().values())
