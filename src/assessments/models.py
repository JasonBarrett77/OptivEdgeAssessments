"""Assessment app models."""

from __future__ import annotations

import uuid

from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.text import slugify

from optivedge.models import ApplicationEnvironment
from optivedge_integrations.integrations.models import (
    AddressObject,
    AdminUser,
    ServerProfile,
    AuthenticationProfile,
    AuthenticationSequence,
    AuthenticationSettings,
    LoggingSettings,
    LoginBanner,
    ManagementTlsBinding,
    ManagementSshSettings,
    MasterKey,
    DnsSettings,
    NtpSettings,
    ServiceRoute,
    SnmpSettings,
    SystemIdentity,
    UpdateServerSettings,
    PasswordComplexityPolicy,
    PasswordProfile,
    SecurityProfile,
    Certificate,
    CertificateProfile,
    SslTlsServiceProfile,
    InterfaceManagementProfile,
    IkeCryptoProfile,
    IkeGateway,
    IpsecCryptoProfile,
    IpsecTunnel,
    IpsecTunnelPath,
    HighAvailabilityConfig,
    PanoramaRegistration,
    ManagementInterface,
    SecurityRule,
    Snapshot,
    Interface,
    PanOsDhcpInterfaceConfig,
    PanOsLldpGlobalSettings,
    PanOsRoutingAdjacency,
    PanOsSessionSettings,
    PanOsTunnelInspectionCoverage,
    CloudAppEngineSetting,
    SaasApplicationPolicyPosture,
    SaasUrlFilteringPosture,
    SanctionedApplicationMarking,
    DeviceIdentificationState,
    RulebaseDeviceMatchVerdict,
    DataFilteringPosture,
    GlobalProtectPortal,
    GlobalProtectPortalClientAuthRow,
    GlobalProtectEnforcementPoint,
    GlobalProtectGateway,
    GlobalProtectGatewayClientAuth,
    GlobalProtectGatewayAgentConfig,
    FirewallContentStreams,
    LicenceInventory,
    LogAlarmSettings,
    ContentUpdateSchedule,
    CustomUrlCategory,
    UserIdCollectorSettings,
    UserIdDiscoveryBound,
    DecryptionSettings,
    Zone,
    ZoneProtectionProfile,
    DosPolicyRule,
    DecryptionPolicyRule,
    DecryptionRulebaseVerdict,
    SslDecryptionExclusion,
    SslDecryptionVendorExclusionOptOut,
    LogServerTarget,
    VsysLogForwarding,
    ManagementPlaneAddressing,
    ApplianceOperationalMode,
    VsysRulePosture,
    PolicyRuleSettings,
)


class ConfigurationSearchState(models.Model):
    """A built query, parked server-side so the URL can carry a token instead of the JSON.

    It carries `model_label` because the configuration explorer has a page per object and a
    token that arrived from another object's page must not be applied here - the fields would
    not compile, and a query that silently matched nothing would look like an answer.

    There was a second one, `SecurityRuleSearchState`, for the retired security rules page. It
    went with that page on 2026-09-25; the plain-language translator writes these instead, and
    `query_text` is what carries the prompt back for editing.

    Rows are cheap and disposable: one per query a person builds, never edited, and the token
    is the whole point - a built query survives a reload, a bookmark and a paste to a colleague
    without the JSON going through the address bar.
    """

    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False, db_index=True)
    #: The search registry's label for the model this query targets, e.g.
    #: "integrations.InterfaceManagementProfile".
    model_label = models.CharField(max_length=128)
    query_text = models.TextField(blank=True)
    canonical_query = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.model_label} {self.token}"


class Control(models.Model):
    class ControlType(models.TextChoices):
        SECURITY_RULE = "security_rule", "Security Rule"
        COVERAGE = "coverage", "Coverage"
        CONFIG = "config", "Configuration"
        MANAGEMENT_INTERFACE = "management_interface", "Management Interface"
        INTERFACE_MANAGEMENT_PROFILE = "interface_management_profile", "Interface Management Profile"
        SSL_TLS_SERVICE_PROFILE = "ssl_tls_service_profile", "SSL/TLS Service Profile"
        CERTIFICATE_PROFILE = "certificate_profile", "Certificate Profile"
        CERTIFICATE = "certificate", "Certificate"
        AUTHENTICATION_PROFILE = "authentication_profile", "Authentication Profile"
        AUTHENTICATION_SEQUENCE = "authentication_sequence", "Authentication Sequence"
        PASSWORD_PROFILE = "password_profile", "Password Profile"
        SECURITY_PROFILE = "security_profile", "Security Profile"
        PASSWORD_COMPLEXITY = "password_complexity", "Minimum Password Complexity"
        AUTHENTICATION_SETTINGS = "authentication_settings", "Authentication Settings"
        LOGIN_BANNER = "login_banner", "Login Banner"
        MASTER_KEY = "master_key", "Master Key"
        UPDATE_SERVER = "update_server", "Update Server Settings"
        LOGGING_SETTINGS = "logging_settings", "Logging and Reporting Settings"
        WILDFIRE_SETTINGS = "wildfire_settings", "WildFire Settings"
        MANAGEMENT_TLS = "management_tls", "Management TLS"
        MANAGEMENT_SSH = "management_ssh", "Management SSH"
        ADMIN_USER = "admin_user", "Administrator"
        SERVER_PROFILE = "server_profile", "AAA Server Profile"
        NTP_SETTINGS = "ntp_settings", "NTP"
        SNMP_SETTINGS = "snmp_settings", "SNMP"
        SYSTEM_IDENTITY = "system_identity", "System Identity"
        #: `device-services`, stage 8 on 2026-11-01. TWO MINTS for a domain that already
        #: shipped seven of its ten controls, and the reverse map was measured BEFORE
        #: either line was written, because nothing in this suite asserts one-to-one-ness
        #: in the direction a mint can break it: `test_every_control_type_targets_a_
        #: registered_model` asserts enum SUBSET of map and no test anywhere refuses two
        #: types sharing one target. Measured 2026-11-01, before the first edit: 67 types,
        #: 67 map entries, 67 DISTINCT targets, and `rev(_CONTROL_TYPE_TARGET_MODEL)`
        #: answering NO TYPE for both `integrations.DnsSettings` and
        #: `integrations.ServiceRoute`. The domain's five other subjects needed nothing:
        #: three already had a type (`ntp_settings`, `snmp_settings`, `system_identity`)
        #: and TWO ARE DELIBERATELY UNREGISTERED - `integrations.DeviceTelemetry`, whose
        #: one assertion record stage 5 discharged `engineer_answers` so it owes no query
        #: and ships no catalog entry at all, and `integrations.ManagementService`, which
        #: no assertion of this domain names.
        #:
        #: `len("dns_settings")` is 12 and `len("service_route")` is 13 against
        #: `control_type.max_length` 64, measured before writing these: a value too long
        #: makes `makemigrations` REFUSE with `fields.E009` rather than truncate.
        DNS_SETTINGS = "dns_settings", "Management Resolvers"
        SERVICE_ROUTE = "service_route", "Management Service Paths"
        #: Coverage over OUR OWN record of a failed normalization rather than over a device
        #: object. A separate type from COVERAGE because `_CONTROL_TYPE_TARGET_MODEL` is
        #: one-to-one and that map's own comment says so: "a coverage control over another
        #: model needs its own control_type".
        NORMALIZATION = "normalization", "Normalization Coverage"
        #: The two IKE objects are SEPARATE types because `_CONTROL_TYPE_TARGET_MODEL` is
        #: one-to-one. PAN-IKE-002 to 005 assert over the proposal set; PAN-IKE-001 and 006
        #: to 008 over the peer binding; PAN-IKE-009 asserts over BOTH and so cannot be one
        #: control - see the stage 8 artifact for `ike-crypto`.
        IKE_CRYPTO_PROFILE = "ike_crypto_profile", "IKE Crypto Profile"
        IKE_GATEWAY = "ike_gateway", "IKE Gateway"
        #: THE TWO IPSec OBJECTS - PHASE 2, AND NOT THE SAME THING AS THE TWO ABOVE. IKE and
        #: IPSec are two phases of one tunnel and the four class names are near-identical, so
        #: the trap is registering one against the other's model. PAN-IPS-001 to 005 assert
        #: over the phase-2 proposal set; PAN-IPS-006 to 008 over the tunnel that carries it.
        #: PAN-IPS-009 asserts over BOTH - a tunnel running on a profile nobody chose, and a
        #: profile no tunnel names - and `_CONTROL_TYPE_TARGET_MODEL` is one-to-one, so it
        #: ships as the PROFILE half and is silent about the tunnel half. See the stage 8
        #: artifact for `ipsec-crypto`, which records why that half was chosen.
        IPSEC_CRYPTO_PROFILE = "ipsec_crypto_profile", "IPSec Crypto Profile"
        IPSEC_TUNNEL = "ipsec_tunnel", "IPSec Tunnel"
        #: THE WHOLE TUNNEL PATH - one tunnel, the IKE gateway it names and both crypto
        #: profiles behind them - and the subject of the nine PROFILE STRENGTH controls as
        #: of 2026-11-04. A profile is a named algorithm set rather than an enforcement
        #: point, so a finding raised on the profile reads the same whether one tunnel uses
        #: it or a thousand do; keyed on the path, the finding count IS the blast radius.
        #: PAN-IPS-006 to -009 and PAN-IKE-001, -006 to -009 keep their own subjects.
        IPSEC_TUNNEL_PATH = "ipsec_tunnel_path", "IPSec Tunnel Path"
        #: The two `ha-panorama` subjects, SEPARATE types for the same one-to-one reason.
        #: PAN-HAP-001 to 004 assert over the high-availability relationship; PAN-HAP-005 over
        #: the channel to the management estate. PAN-HAP-006 and 007 assert over PANORAMA'S OWN
        #: configuration, which `rules.md` puts out of assessment scope, so they have no type
        #: here and no catalog entry - see the stage 8 artifact for `ha-panorama`.
        HIGH_AVAILABILITY = "high_availability", "High Availability"
        PANORAMA_REGISTRATION = "panorama_registration", "Panorama Registration"
        #: NETWORK HARDENING - SIX SUBJECTS AND SO SIX TYPES, for the one-to-one reason above
        #: and for no other: two of them are device-wide singleton nodes, which would otherwise
        #: have been tempting to fold together.
        #:
        #: NONE OF THESE CARRIES THE `PanOs` PREFIX ITS INTEGRATIONS MODEL DOES. Five of the six
        #: models are named `PanOs*` and `Interface` is not; that prefix appears on exactly five
        #: of 138 model classes in OptivEdgeIntegrations, all five in one file added on
        #: 2026-10-29, while four other model files added the SAME day used no vendor prefix. No
        #: comment or document in either repo gives a reason. So it is a one-file local choice
        #: rather than a convention, and the types here follow the 28 that shipped before them,
        #: none of which carries a vendor prefix.
        #:
        #: PAN-NET-001 and PAN-NET-003 SHARE `firewall_interface`: a type maps to one model, and
        #: many controls may share a type. PAN-NET-002 and PAN-NET-005 share `session_settings`
        #: the same way - two config nodes on one vendor screen, one row.
        FIREWALL_INTERFACE = "firewall_interface", "Interface"
        SESSION_SETTINGS = "session_settings", "Session Settings"
        #: Registered with NO shipped control. PAN-NET-003 asserts over this subject and over
        #: `Interface`, and one control cannot hold both; splitting the catalogue id is a
        #: product decision. See the stage 8 artifact for `network-hardening`.
        LLDP_GLOBAL = "lldp_global", "Global LLDP"
        DHCP_INTERFACE_CONFIG = "dhcp_interface_config", "DHCP Interface Configuration"
        TUNNEL_INSPECTION = "tunnel_inspection", "Tunnel Inspection Coverage"
        ROUTING_ADJACENCY = "routing_adjacency", "Routing Adjacency"
        #: The four `saas-security` subjects. THREE OF THEM ARE NAMED FOR A VERDICT AND NOT FOR
        #: A PAN-OS OBJECT, which is what their rows are: the commonest state of this domain is
        #: no entry at all, so the subject is the enforcement point and the row is a conclusion
        #: about everything reachable from it. PAN-SAS-002 and PAN-SAS-004 share one type,
        #: because two control types cannot name one model - `finding_registry` is keyed by
        #: model and `generate_object_findings` filters by type.
        SANCTIONED_APPLICATION_MARKING = (
            "sanctioned_application_marking", "Sanctioned Application Marking")
        SAAS_URL_FILTERING_POSTURE = (
            "saas_url_filtering_posture", "SaaS URL Filtering Posture")
        SAAS_APPLICATION_POLICY_POSTURE = (
            "saas_application_policy_posture", "SaaS Application Policy Posture")
        CLOUD_APP_ENGINE_SETTING = (
            "cloud_app_engine_setting", "App-ID Cloud Engine")
        #: The three `device-id-iot` subjects, THREE TYPES for the one-to-one reason above.
        #: PAN-IOT-001 and PAN-IOT-003 SHARE `device_identification`: both assert over one
        #: appliance's device-identification service state, which is one model and so one type -
        #: the entitlement, the wiring and the installed classification data all print the same
        #: appliance. PAN-IOT-002 asserts over the zone and PAN-IOT-004 over a verdict about an
        #: enforcement point's whole rule set.
        #:
        #: `ZONE` IS A TYPE FOR A MODEL THAT HAS SHIPPED SINCE LONG BEFORE THIS DOMAIN. `Zone`
        #: carried `enable_device_identification` and both Device-ID ACLs already and no control
        #: had ever been written over it, so the model existed with no type, no finding model and
        #: no page. PAN-IOT-002 is the first control to assert over a zone.
        #:
        #: `RULEBASE_DEVICE_MATCH` NAMES A VERDICT AND NOT A PAN-OS OBJECT, the same shape as the
        #: three `saas-security` verdicts above: 182 of the 188 rules measured carry neither
        #: device element, so keying the row on the rule would multiply the failure rather than
        #: locate it, and the subject is the enforcement point.
        DEVICE_IDENTIFICATION = "device_identification", "Device Identification"
        ZONE = "zone", "Security Zone"
        RULEBASE_DEVICE_MATCH = "rulebase_device_match", "Rulebase Device Match"
        #: `file-data-filtering` adds ONE type, not two, and which one was decided from the
        #: control's own language rather than from the model count. The domain's two models are
        #: `SecurityProfile` - which already had `security_profile`, a finding model, a generator
        #: and a full search surface - and `DataFilteringPosture`, which had none.
        #:
        #: PAN-FIL-001, -002 and -004 REUSE `security_profile`. A type maps to one model and many
        #: controls may share a type, as PAN-IOT-001/003, PAN-NET-001/003 and PAN-AVW-006 already
        #: do. Minting a second type for a model that has one is what this map's one-to-one
        #: property forbids, and NOTHING IN THE SUITE CATCHES IT IN THAT DIRECTION.
        #:
        #: ONLY PAN-FIL-003 TOUCHES THE SECOND MODEL, and it is stated as two halves over the two
        #: DIFFERENT models: "on the traffic that carries data out of the organisation's network,
        #: a data filtering profile is in force ... and the pattern object it names actually
        #: defines those patterns" - the control's own assertion at the control's own severity -
        #: and "a data filtering profile that is watching also carries both counts", which is
        #: stage 3's `preferred_gap_severity` half and carries an explicit `depends_on` back to
        #: the first. Standing ruling 6 says decide the target from the LANGUAGE: the first
        #: half's subject is THE TRAFFIC LEAVING ONE ENFORCEMENT POINT, and the commonest failing
        #: state is no data-filtering profile at all - three of four lab appliances - where a
        #: profile-row control has no row to report on at all. So the row is a verdict per
        #: enforcement point, the same shape as the three SaaS postures and `RULEBASE_DEVICE_MATCH`
        #: above. The second half stays SILENT and the stage 8 artifact says so in
        #: `subjects_in_two_models`: its clauses are per profile, `SecurityProfile.enforcement_point`
        #: is NULLABLE because a shared-scope profile hangs off the appliance group instead, so
        #: the downward relation walk ruling 6 prescribes cannot reach three of that half's five
        #: measured subjects at their own scope - and at this grain one point's row cannot name
        #: which profile failed.
        DATA_FILTERING_POSTURE = "data_filtering_posture", "Data Filtering Posture"
        #: `globalprotect-portal`. THREE SUBJECTS, THREE MODELS, THREE TYPES, for the one-to-one
        #: reason above - and the three are a PARENT, its CHILD ROW and the VSYS above both,
        #: which is the shape standing ruling 6's direction qualifier decides.
        #:
        #: The portal entry, which four of the domain's six controls target: PAN-GPP-001 (is a
        #: transport profile bound at all), -003 (does the portal drive agents to a current
        #: version), -004 (may the app keep a password on the endpoint) and -005 (is the
        #: browser-reachable login page served).
        GLOBALPROTECT_PORTAL = "globalprotect_portal", "GlobalProtect Portal"
        #: One row of one portal's client-authentication table, keyed by endpoint CLASS. It is
        #: PAN-GPP-002's subject and nothing else's, and it is A SEPARATE TYPE FROM THE PORTAL
        #: RATHER THAN A ROLL-UP ONTO IT: a portal can demand both factors of one endpoint class
        #: and neither of another - measured, two rows of one portal sit at `high` and at
        #: `no_finding` - so a portal-grain control would fire the parent for one child's fault
        #: and report the compliant sibling beside it. That is exactly the to-many DOWNWARD walk
        #: ruling 6 refuses. The row's own FK to its portal is the to-ONE walk it permits, and it
        #: is how the portal's `certificate_profile_bound` reaches the row at all.
        GLOBALPROTECT_PORTAL_CLIENT_AUTH = (
            "globalprotect_portal_client_auth", "GlobalProtect Portal Client Authentication")
        #: One virtual system as a VERDICT over its GlobalProtect objects as a whole, which is
        #: PAN-GPP-006's target. Chosen from the control's own language - "No portal publishes
        #: internal web applications, and neither the portal nor the firewall holds the
        #: application definitions" is a statement about the vsys and not about any one portal -
        #: and confirmed by the `latent` rank, which stage 5 says exists FOR this grain: a vsys
        #: holding a clientless application definition that no portal publishes has no portal row
        #: to be reported on, so a portal-grain control is silent on it by construction.
        #: PAN-GPP-006's second half, the clientless transport floor, is per portal and stays
        #: SILENT; the stage 8 artifact records it in `subjects_in_two_models`. There is no Django
        #: relation between this model and the portal in EITHER direction - introspected, not
        #: assumed - so ruling 6's relation remedy has nothing to walk: the two share only
        #: `appliance`, whose reverse accessor is to-many AND crosses vsys boundaries, which would
        #: fire one vsys's row for another vsys's portal.
        GLOBALPROTECT_ENFORCEMENT_POINT = (
            "globalprotect_enforcement_point", "GlobalProtect Enforcement Point")
        #: `platform-lifecycle`. THREE SUBJECTS, THREE MODELS, THREE TYPES, for the one-to-one
        #: reason above and measured the way this map's own comment now asks: the REVERSE map
        #: answered NO TYPE for all three of `integrations.FirewallContentStreams`,
        #: `integrations.LicenceInventory` and `integrations.LogAlarmSettings` before anything
        #: here was touched, so nothing below reuses a type and nothing mints a second one for a
        #: model that already has one.
        #:
        #: ALL THREE ARE DEVICE-WIDE SINGLETONS WITH NO VSYS AXIS AND NO ENTRY NAME - one row per
        #: appliance - which is why none of them carries `subject_scope` on its finding model and
        #: why each finding's `subject_name` is the appliance. ON AN HA PAIR EACH YIELDS TWO ROWS
        #: FOR ONE REAL CONFIGURATION and nothing deduplicates them; stage 5 records it per
        #: subject and the hostname is what tells the two rows apart.
        #:
        #: The appliance's content streams as ONE row carrying every stream as its own column,
        #: which is stage 5's `identity.one_row_per` in terms: "carrying every content stream as
        #: its own column rather than one row per stream". PAN-PLT-002 only. A stream-keyed row
        #: would have nothing to report on exactly the streams that are absent, and
        #: `content_currency_state` is a verdict over the set rather than over any one stream.
        FIREWALL_CONTENT_STREAMS = "firewall_content_streams", "Firewall Content Streams"
        #: One appliance's entitlement set as a CONCLUSION ABOUT its licence rows rather than one
        #: row per licence. PAN-PLT-004 only, and BOTH of its assertion records target it - the
        #: subscription half and the support half - so this is one type for one model carrying a
        #: control stated twice over, not a two-model control. `integrations.LicenceEntitlement`
        #: holds the per-licence rows and gets NO type here: no assertion record of this domain
        #: names that subject, so a type over it would be a search surface no control asks for.
        LICENCE_INVENTORY = "licence_inventory", "Licence Inventory"
        #: One appliance's log-database alarm mechanism - the singleton node under
        #: `deviceconfig/setting/management/common-criteria-alarm-generation`. PAN-PLT-006's
        #: first half only. Its second half, dataplane utilisation, is discharged
        #: `engineer_answers` by stage 5 and owes no query, so it needs no type and gets none:
        #: there is no configuration node anywhere on the firewall holding a dataplane CPU or
        #: session threshold, and the vendor's own procedure puts the comparison off-box.
        LOG_ALARM_SETTINGS = "log_alarm_settings", "Log Database Alarms"
        #: `updates`. ONE TYPE FOR TWO STAGE 5 SUBJECTS, and the second subject's absence is the
        #: decision worth reading. `rev(_CONTROL_TYPE_TARGET_MODEL)` answered NO TYPE for both
        #: `integrations.ContentUpdateSchedule` and `integrations.ContentDeploymentSchedule`
        #: before this change, measured against 51 types and 51 DISTINCT targets - so this mints
        #: one and reuses none.
        #:
        #: WHY THERE IS NO `content_deployment_schedule`, which is the question a reader of the
        #: models will ask. That subject is named by exactly ONE assertion record - PAN-UPD-006's
        #: first - and stage 5 discharges it `not_in_configuration`, so it owes no query and a
        #: type over it would be a search surface no control can ever reference. The reason it is
        #: discharged that way is a scope ruling and not a measurement gap: Jason, 2026-10-27,
        #: "own panorama is still out of scope (values that effect the panorama appliance only)",
        #: and `deviceconfig/system/deployment-update-schedule` exists only on the management
        #: station - `config_complete` answers `code=6 Invalid sequence` at that path on both lab
        #: firewalls. PAN-UPD-006 therefore has no catalog entry at all, which is a DIFFERENT
        #: state from a control that fired on nothing.
        #:
        #: ONE ROW PER APPLIANCE CARRYING ALL FIVE CONTENT TYPES AS THEIR OWN COLUMNS, which is
        #: stage 5's `identity.one_row_per` and is why four controls share this one type rather
        #: than taking one each: PAN-UPD-001 grades antivirus, -002 Applications-and-Threats,
        #: -004 WildFire and -005 the two GlobalProtect content types. A content-type-keyed row
        #: could not report the commonest failing state in this estate, which is a content type
        #: with no `update-schedule` branch at all and therefore nothing to key a row on.
        #:
        #: NO VSYS AXIS. The node is per APPLIANCE under `deviceconfig/system` - stage 4 measured
        #: the same path on the multi-vsys PA-5220 - so the finding's subject is the appliance.
        #: ON AN HA PAIR THIS YIELDS TWO ROWS FOR WHAT AN OPERATOR CALLS ONE SCHEDULE, and that
        #: is correct rather than a duplicate: the schedule does not sync across peers and each
        #: appliance carries its own.
        CONTENT_UPDATE_SCHEDULE = "content_update_schedule", "Content Update Schedule"

        #: `url-filtering`. ONE TYPE MINTED AND ONE REUSED, and the reuse is the load-bearing
        #: half. Five of this domain's six controls - PAN-URL-001 to -005 - target
        #: `integrations.SecurityProfile`, which ALREADY HAS `security_profile` serving
        #: PAN-AVW-006, PAN-FIL-001, -002 and -004, so they mint nothing and carry that type.
        #: `rev(_CONTROL_TYPE_TARGET_MODEL)` answered `security_profile` for `SecurityProfile`
        #: and NO TYPE for `integrations.CustomUrlCategory`, measured against 52 types and 52
        #: DISTINCT targets before this change. A SECOND TYPE FOR `SecurityProfile` IS WHAT THIS
        #: MAP'S ONE-TO-ONE PROPERTY FORBIDS AND NOTHING IN THE SUITE CATCHES, which is the same
        #: warning the `file-data-filtering` block above carries.
        #:
        #: WHICH HALF OF PAN-URL-006 OWNS THE CONTROL ID, because the control spans two models
        #: and a control id targets one. `probe.relation_between SecurityProfile
        #: CustomUrlCategory` reports NO RELATION IN EITHER DIRECTION - the only paths are
        #: through shared ancestors, every one to-many and every one leaving a scope field
        #: unconstrained, which is a WRONG ROW rather than an understated severity - so one half
        #: ships and the other is silent. The CATEGORY half owns it, and stage 3 is what decides
        #: that: its `severity_grading` is read "from the stored type of a custom web category"
        #: and its `unplaced` sentence says an unreferenced PROFILE "takes the baseline; it is
        #: not a value of this grading because the grading reads a category's stored type and a
        #: profile carries no such field". So the control's ONLY axis above its own baseline
        #: lives on this model: silence the category half and PAN-URL-006 can never report
        #: anything but `low`.
        CUSTOM_URL_CATEGORY = "custom_url_category", "Custom URL Category"
        #: `user-id`. TWO types for TWO new models, and TWO REUSES that mint nothing.
        #: `rev(_CONTROL_TYPE_TARGET_MODEL)` answered NO TYPE for
        #: `integrations.UserIdCollectorSettings` and `integrations.UserIdDiscoveryBound`, and
        #: answered `zone` and `management_interface` for this domain's other two subjects,
        #: measured against 53 types and 53 DISTINCT targets. So this mints two and reuses two.
        #:
        #: PAN-UID-003, -004 and -006 SHARE `user_id_collector`: three controls over one
        #: per-vsys agent settings node, which is one model and so one type - the same shape as
        #: PAN-IOT-001/003 and PAN-NET-001/003 above.
        #:
        #: PAN-UID-001 REUSES `zone` and PAN-UID-005 REUSES `management_interface`. Minting a
        #: second type for a model that already has one is what this map's one-to-one property
        #: forbids, and NOTHING IN THE SUITE CATCHES IT IN THAT DIRECTION - so the reverse map
        #: was measured before these two lines were written rather than after.
        #:
        #: `integrations.UserIdMonitoredServer` GETS NO TYPE, deliberately. It is the subject of
        #: the one PAN-UID-005 assertion record this domain leaves SILENT: that control's own
        #: configuration leaf is `deviceconfig/system/service/disable-userid-syslog-listener-udp`,
        #: which is the management plane's listener and not the per-sender transport, and
        #: `probe.relation_between ManagementInterface UserIdMonitoredServer` finds NO RELATION
        #: IN EITHER DIRECTION - so no query at either grain can carry both halves. A type here
        #: would be registrations spent on a row no finding references. See the stage 8 artifact
        #: for `user-id`, `subjects_in_two_models`.
        USER_ID_COLLECTOR = "user_id_collector", "User-ID Collector"
        USER_ID_DISCOVERY_BOUND = "user_id_discovery_bound", "User-ID Discovery Bound"
        #: `decryption-profiles`. ONE MINT FOR SEVEN CONTROLS, and the arithmetic is the point:
        #: six of the domain's seven controls REUSE `security_profile` above, because their
        #: subject is a `decryption`-kind row of `integrations.SecurityProfile` and
        #: `rev(_CONTROL_TYPE_TARGET_MODEL)` already answers `security_profile` for that model.
        #: Minting a second type for a model that already has one is what this map's one-to-one
        #: property forbids and NOTHING IN THE SUITE CATCHES IT IN THAT DIRECTION, so the reverse
        #: map was measured before this line was written: 55 types, 55 map entries, 55 DISTINCT
        #: targets, no duplicate, and `integrations.DecryptionSettings` answering nothing.
        #:
        #: PAN-DCP-006 IS THE ONLY CONTROL OF THE SEVEN THAT NEEDS IT. Its first two assertion
        #: records name the appliance's forward-proxy SIGNING designation -
        #: `/config/shared/ssl-decrypt`, one row per appliance - which is a different model from
        #: the profile the other six assert over.
        #:
        #: `integrations.Certificate` GETS NOTHING FROM THIS RUN. PAN-DCP-006's other two records
        #: name a signing certificate, and neither is discharged `expression`: one is
        #: `not_in_configuration` (key exportability has no configuration node) and one is
        #: `engineer_answers`. So there was never a query to place at that grain, `certificate`
        #: already exists as a type anyway, and `probe.relation_between DecryptionSettings
        #: Certificate` finds NO RELATION IN EITHER DIRECTION - six to-many paths through shared
        #: ancestors, each leaving a scope field unconstrained. See the stage 8 artifact for
        #: `decryption-profiles`, `subjects_in_two_models`.
        DECRYPTION_SETTINGS = "decryption_settings", "Decryption Settings"
        #: `globalprotect-gateway`. THREE MINTS FOR SEVEN CONTROLS, with one REUSE beside them.
        #: The reverse map was measured BEFORE any of these three lines was written, because
        #: nothing in the suite checks one-to-one-ness in the direction a mint can break it:
        #: `test_every_control_type_has_a_target_model` asserts enum SUBSET of map, and no test
        #: anywhere asserts that two types do not share one target model. Measured 2026-11-01,
        #: before the first edit: 56 types, 56 map entries, 56 DISTINCT targets, no duplicate,
        #: and `rev(_CONTROL_TYPE_TARGET_MODEL)` answering NO TYPE for all three of
        #: `integrations.GlobalProtectGateway`, `integrations.GlobalProtectGatewayClientAuth`
        #: and `integrations.GlobalProtectGatewayAgentConfig`. The FOURTH model this domain
        #: asserts over, `integrations.GlobalProtectEnforcementPoint`, already answered
        #: `globalprotect_enforcement_point`, so PAN-GPG-005 REUSES that type and mints nothing -
        #: which is as load-bearing as the three mints, because a second type for a model that
        #: already has one passes every gate in this repository.
        #:
        #: NO GLOBALPROTECT GATEWAY EXISTS IN THE MEASURED ESTATE, so all three of these types
        #: ship with no row of their model anywhere. That is deliberate and it follows the
        #: `ha-panorama` precedent: registration is about the CATALOGUE, not about whether one
        #: lab happens to hold rows. Stage 6 spent eleven lease windows trying to commit a
        #: gateway, met a new commit requirement every time, and DECLARED the twelve expression
        #: restatements it could not grade rather than fabricating them. Six of this domain's
        #: seven controls therefore ship UNEXERCISED - the stage 8 artifact's `needs_human`
        #: names the twelve, because no count in that artifact says it on its own.
        #:
        #: The gateway ENTRY, which three of the seven controls target: PAN-GPG-001 (is a TLS
        #: service profile bound, and does what it resolves to state a protocol floor), -006 (is
        #: the tunnel built, over which transport, and which algorithm is offered first) and
        #: -007 (are the login lifetime and the idle logout bounded). PAN-GPG-005's third
        #: record names this model too and THAT HALF IS SILENT: the control's own target is the
        #: enforcement point, and `probe.relation_between GlobalProtectEnforcementPoint
        #: GlobalProtectGateway` finds NO RELATION IN EITHER DIRECTION - the only paths run
        #: to-many through shared ancestors and each leaves a scope field unconstrained - so
        #: ruling 6's relation remedy has nothing to walk.
        GLOBALPROTECT_GATEWAY = "globalprotect_gateway", "GlobalProtect Gateway"
        #: One row of one gateway's client-authentication table, keyed by the client OPERATING
        #: SYSTEM. PAN-GPG-002's subject and nothing else's, and A SEPARATE TYPE FROM THE GATEWAY
        #: rather than a roll-up onto it, for the reason the sibling portal type already carries:
        #: the commonest real defect is PER PLATFORM - a Windows row pointed at a strong identity
        #: service and an `Any` row pointed at the firewall's own local database - so a
        #: gateway-grain verdict would fire the parent for one child's fault, could not say which
        #: platform was weak, and would show the compliant sibling beside it. That is exactly the
        #: to-many DOWNWARD walk standing ruling 6 refuses.
        #:
        #: THE ROW'S `gateway` FK IS THE TO-ONE UPWARD WALK RULING 6 PERMITS, and it is how
        #: PAN-GPG-002's OTHER half - the gateway-wide `client_certificate_is_a_second_factor` -
        #: is reached at all. Measured 2026-11-01: the walk exists, is to-one, and is NULLABLE,
        #: so it cannot reach a row whose gateway did not resolve and that half is silent for
        #: exactly those rows rather than for the whole population. No earlier run had met the
        #: nullable variant of ruling 6's own shape.
        GLOBALPROTECT_GATEWAY_CLIENT_AUTH = (
            "globalprotect_gateway_client_auth", "GlobalProtect Gateway Client Authentication")
        #: One agent client-settings row of one gateway - the row an engineer opens at Agent >
        #: Client Settings to change a cookie lifetime or a split-tunnel inventory. PAN-GPG-003
        #: (how long a reconnection cookie is accepted, and whether the certificate encrypting it
        #: is named) and PAN-GPG-004 (the inventory of paths leaving the tunnel uninspected) BOTH
        #: share it, which is the ordinary case this map's own comment describes: the number of
        #: types a domain needs is the number of distinct MODELS its controls assert over and not
        #: the number of controls.
        #:
        #: THE GRAIN IS THE ROW BECAUSE EVERY REMEDIATION ON THIS GROUND IS AN EDIT TO ONE ROW,
        #: and because absence here is the SAFE direction - a gateway with no settings row
        #: accepts no cookie and excludes nothing from its tunnel. The two columns that SUPPRESS
        #: on their own default, `accept_cookie_configured` and
        #: `authentication_override_configured`, have NO DEVICE INSTANCE OF EITHER BRANCH
        #: anywhere in this estate: stage 7 says so in terms, and it is the sharpest reason both
        #: of this type's controls ship unexercised.
        GLOBALPROTECT_GATEWAY_AGENT_CONFIG = (
            "globalprotect_gateway_agent_config", "GlobalProtect Gateway Agent Configuration")
        #: `zone-dos-protection`. TWO MINTS FOR FIVE CONTROLS, with TWO REUSES beside them, and
        #: the reverse map was measured BEFORE either line was written because nothing in the
        #: suite checks one-to-one-ness in the direction a mint can break it: the shipped test
        #: asserts enum SUBSET of map, and no test anywhere asserts that two types do not share
        #: one target model. Measured 2026-11-01, before the first edit: 59 types, 59 map
        #: entries, 59 DISTINCT targets, no duplicate, and `rev(_CONTROL_TYPE_TARGET_MODEL)`
        #: answering NO TYPE for both `integrations.ZoneProtectionProfile` and
        #: `integrations.DosPolicyRule`. The domain's other two models already answered:
        #: `integrations.Zone` -> `zone` and `integrations.SecurityProfile` ->
        #: `security_profile`, so PAN-ZON-001 and PAN-ZON-008 REUSE those types and mint nothing.
        #: Both reuses are as load-bearing as the mints, and both carried a live defect that
        #: reuse alone would have shipped: see `zone_findings._no_zone_defence` and
        #: `security_profile_findings._dos_protection_gaps`.
        #:
        #: SITE 8 WAS MEASURED AND DOES NOT BITE. `control_type.max_length` is 64, the longest
        #: shipped value is `globalprotect_gateway_agent_config` at 34, and these two are 23 and
        #: 15 characters.
        #:
        #: One named zone protection profile of one appliance - the device-local object an
        #: engineer opens to turn a flood protection, a packet drop or a scan action on.
        #: PAN-ZON-002, -003, -004, -005 and -006 share it, which is the ordinary case this map's
        #: own comment describes: the number of types a domain needs is the number of distinct
        #: MODELS its controls assert over, not the number of controls. PAN-ZON-008's FIRST half
        #: names this subject too and THAT HALF IS SILENT - the control's own target is
        #: `integrations.SecurityProfile`, chosen because stage 6 exercises that half with four
        #: expectation rows against this one's two, and a control has exactly one target model.
        ZONE_PROTECTION_PROFILE = "zone_protection_profile", "Zone Protection Profile"
        #: One DoS Protection policy rule of one rulebase of one vsys. PAN-ZON-007 only, and only
        #: ONE OF ITS TWO HALVES: the other is discharged onto the customer's asset inventory,
        #: because nothing in a firewall says which destination is a business-critical service.
        DOS_POLICY_RULE = "dos_policy_rule", "DoS Policy Rule"
        #: `decryption-policy`. FOUR MINTS FOR TEN CONTROLS AND NO REUSE, and the reverse map was
        #: measured BEFORE the first of these four lines was written, because nothing in the suite
        #: checks one-to-one-ness in the direction a mint can break it: the shipped test asserts
        #: enum SUBSET of map, and no test anywhere asserts that two types do not share one target
        #: model. Measured 2026-11-01, before the first edit: 63 types, 63 map entries, 63 DISTINCT
        #: targets, no duplicate, and `rev(_CONTROL_TYPE_TARGET_MODEL)` answering NO TYPE for all
        #: four of `integrations.DecryptionPolicyRule`, `integrations.DecryptionRulebaseVerdict`,
        #: `integrations.SslDecryptionExclusion` and
        #: `integrations.SslDecryptionVendorExclusionOptOut`. So nothing here reuses a type and
        #: nothing mints a second one for a model that already has one.
        #:
        #: SITE 8 IS WHY THIS DOMAIN IS BUILDABLE AT ALL AND IT WAS MEASURED, not assumed:
        #: `control_type.max_length` is 64 and the longest shipped value was
        #: `globalprotect_gateway_agent_config` at 34, while
        #: `ssl_decryption_vendor_exclusion_optout` below is 38 CHARACTERS. The field was 32 until
        #: 2026-11-01, so this domain could not have been registered yesterday - `makemigrations`
        #: would have REFUSED with `fields.E009` and generated nothing.
        #:
        #: TWO GRAINS OVER ONE PAN-OS OBJECT, which is the shape to read before the four names.
        #: The per-ENTRY grain reports a rule that exists and is wrong; the per-ENFORCEMENT-POINT
        #: verdict reports a rulebase that does not exist at all, which stage 4 measured as the
        #: commonest state of this domain - all four lab appliances, all twenty vsys, both Shared
        #: rulebases and all ten device groups, twice. A predicate cannot compare against a row
        #: that is not there, so the coverage controls have no row at the entry grain.
        #:
        #: One ordered entry of one decryption rulebase of one vsys. PAN-DEC-002, -003, -005,
        #: -006, -007, -008 and -010 share it - seven controls, one type, one model, which is the
        #: ordinary case this map's own comment describes.
        DECRYPTION_POLICY_RULE = "decryption_policy_rule", "Decryption Policy Rule"
        #: One enforcement point's decryption rulebase AS A VERDICT over all of its rules.
        #: PAN-DEC-001 and PAN-DEC-009. A SEPARATE TYPE FROM THE RULE RATHER THAN A ROLL-UP ONTO
        #: IT, and the direction is what decides it: these two controls fire where NO rule does
        #: something, and the remediation is to ADD a rule rather than to edit one.
        DECRYPTION_RULEBASE_COVERAGE = (
            "decryption_rulebase_coverage", "Decryption Rulebase Coverage")
        #: One SSL decryption exclusion the organisation added itself, in one scope of one
        #: appliance. PAN-DEC-004's FIRST record only, and that control's second record names the
        #: opt-out model below and STAYS SILENT: `probe.relation_between SslDecryptionExclusion
        #: SslDecryptionVendorExclusionOptOut` finds NO RELATION IN EITHER DIRECTION - six paths
        #: through shared ancestors, every one to-many and every one leaving a scope field
        #: unconstrained - so standing ruling 6's relation remedy has nothing to walk. The
        #: exclusion half owns the id because the control's own severity (medium) and its
        #: `minimum_value_descr` are stage 3's record 0, while record 1 is the
        #: `preferred_gap_severity` half at low. See the stage 8 artifact,
        #: `subjects_in_two_models`.
        SSL_DECRYPTION_EXCLUSION = "ssl_decryption_exclusion", "SSL Decryption Exclusion"
        #: One appliance's departures from the VENDOR-SUPPLIED SSL decryption exclusion list.
        #: REGISTERED WITH NO SHIPPED CONTROL, the same recorded state `lldp_global` above carries
        #: and for the same reason: PAN-DEC-004's two assertion records name two models, a control
        #: has one `target_model`, and splitting the catalogue id is a product decision rather than
        #: a build run's. Registering it now means the half somebody may decide to build reports
        #: the moment a control exists, rather than leaving a model, a normaliser and a migration
        #: with nothing that can ever read them. The generator's own docstring says what its
        #: sentence would be and why no estate can make it fire today.
        SSL_DECRYPTION_VENDOR_EXCLUSION_OPTOUT = (
            "ssl_decryption_vendor_exclusion_optout",
            "SSL Decryption Vendor Exclusion Opt-Out")
        #: `logging`, 2026-11-01. TWO MINTS AND ONE REUSE FOR TEN CONTROLS, and the reuse is
        #: where the work went rather than the mints. `rev(_CONTROL_TYPE_TARGET_MODEL)` was
        #: measured over 69 types, 69 map entries and 69 DISTINCT targets before either line
        #: below was written: it answered NO TYPE for `integrations.LogServerTarget` and
        #: `integrations.VsysLogForwarding`, and answered `logging_settings` for
        #: `integrations.LoggingSettings`. Minting a second type for a model that already has
        #: one is what this map's one-to-one property forbids and nothing in the suite catches
        #: it in that direction, so the reverse map was measured first.
        #:
        #: EIGHT OF THE TEN CONTROLS REUSE `logging_settings`, WHICH ALREADY CARRIED EXACTLY ONE
        #: CONTROL OF ANOTHER DOMAIN - PAN-MGT-011, management-services. Its generator was an
        #: unconditional single sentence about the high-DP-load setting with no dispatch of any
        #: kind, so eight PAN-LOG findings would each have asserted that setting was off, on
        #: findings about log retention, syslog transport and Panorama coverage. The dispatch
        #: `logging_settings_findings.PARTS_BY_CONTROL` was added for that, with PAN-MGT-011's
        #: sentence kept BYTE FOR BYTE in its own arm and the default arm `()`.
        #:
        #: `len("log_server_target")` is 17 and `len("vsys_log_forwarding")` is 19 against
        #: `control_type.max_length` 64, measured before writing these: a value too long makes
        #: `makemigrations` REFUSE with `fields.E009` rather than truncate.
        #:
        #: ONE TYPE FOR `LogServerTarget` AND NOT TWO, although stage 5 states TWO subjects over
        #: it - `syslog-server-target` and `email-server-target`, discriminated by the `kind`
        #: column of one table. One model is one type, and only the syslog half has a control:
        #: no assertion in this domain names the e-mail subject. PAN-LOG-008's second group
        #: would have, and stage 5 left it in `undetermined` rather than in `clauses`. EVERY
        #: CONTROL ON THIS MODEL MUST CLAUSE ON `kind`, which the model's own docstring says in
        #: terms: `transport` holds its UDP default on the e-mail kind too, so PAN-LOG-002
        #: without that clause reports every mail relay in the estate as sending syslog in the
        #: clear.
        LOG_SERVER_TARGET = "log_server_target", "Log Server Target"
        #: One virtual system's Log Forwarding availability AS A VERDICT over the profiles it can
        #: reach, at four scopes. PAN-LOG-005. The VSYS is the row and not the profile, because
        #: the gap this control reports is a vsys with no adequate profile and a profile-keyed
        #: row cannot report something that does not exist.
        VSYS_LOG_FORWARDING = "vsys_log_forwarding", "Virtual System Log Forwarding"
        #: `management-services`, 2026-11-01. TWO MINTS FOR TWO CONTROLS, and eight of this
        #: domain's thirteen controls REUSE a type instead - six of those reuses already
        #: resolve to a results page, which is why `AWAITING_PRESENTATION` took one line for
        #: the two mints and not one per control.
        #:
        #: `rev(_CONTROL_TYPE_TARGET_MODEL)` was measured over 71 types, 71 map entries and 70
        #: DISTINCT non-empty targets before either line below was written. It answered NO TYPE
        #: for `integrations.ManagementPlaneAddressing` and
        #: `integrations.ApplianceOperationalMode`, so neither mint is a second type for a model
        #: that already has one - the thing this map's one-to-one property forbids and which
        #: nothing in the suite catches in that direction, because the test checks enum ⊆ map
        #: and not injectivity.
        #:
        #: `len("management_plane_addressing")` is 27 and `len("appliance_operational_mode")` is
        #: 26 against `control_type.max_length` 64, measured before writing these: a value too
        #: long makes `makemigrations` REFUSE with `fields.E009` rather than truncate, which is
        #: how the 32-character bound was found on 2026-11-01.
        #:
        #: NEITHER MODEL COULD HAVE BEEN A COLUMN OF `ManagementInterface`. That model's grain
        #: is the administrative SURFACE and both of these are facts about the appliance: three
        #: of the four surface rows would carry permanently-null columns whose null meant "not
        #: applicable here", which is the same argument that put a surface's services in a
        #: child table.
        MANAGEMENT_PLANE_ADDRESSING = (
            "management_plane_addressing", "Management Plane Addressing")
        #: PAN-MGT-012. Held in NO configuration node at any scope - the mode is set from
        #: maintenance mode and is reported only by `show system info` - so both of this
        #: model's assessed columns are verdicts over a RUNTIME reading.
        APPLIANCE_OPERATIONAL_MODE = (
            "appliance_operational_mode", "Appliance Operational Mode")
        #: `security-policy`, 2026-11-01. TWO MINTS for a domain of 24 controls, and FIFTEEN of
        #: its twenty-one shipping controls REUSE `security_rule` instead - which is why
        #: `AWAITING_PRESENTATION` took ONE line for the whole domain and not one per model:
        #: `integrations.SecurityRule` and `integrations.AddressObject` both already resolve to a
        #: results page, and only these two do not.
        #:
        #: `rev(_CONTROL_TYPE_TARGET_MODEL)` was measured over 73 types, 73 map entries and 72
        #: DISTINCT non-empty targets before either line below was written. It answered NO TYPE
        #: for `integrations.VsysRulePosture` and `integrations.PolicyRuleSettings`, so neither
        #: mint is a second type for a model that already has one - the thing this map's
        #: one-to-one property forbids and which NOTHING IN THE SUITE CATCHES in that direction:
        #: `test_reseed` asserts every type HAS a target and every target has a label, and
        #: neither of those is injectivity.
        #:
        #: `len("vsys_rule_posture")` is 17 and `len("policy_rule_settings")` is 20 against
        #: `control_type.max_length` 64, measured before writing these: a value too long makes
        #: `makemigrations` REFUSE with `fields.E009` rather than truncate.
        #:
        #: NEITHER COULD HAVE BEEN A COLUMN OF `SecurityRule`, and the two reasons differ. Every
        #: column of `VsysRulePosture` is a statement about the ABSENCE of a rule somebody should
        #: have written, and a rule-keyed row cannot report a rule that does not exist - three of
        #: nine vsys on one lab PA-5220 have no `rulebase/security/rules` node at all and each one
        #: still enforces the two rules PAN-OS ships. `PolicyRuleSettings` reads a node with NO
        #: VSYS AXIS, so its grain is the appliance and a per-rule row would carry the same two
        #: values 666 times over.
        VSYS_RULE_POSTURE = ("vsys_rule_posture", "Virtual System Rule Posture")
        #: PAN-POL-011, which SHIPS INACTIVE by Jason's decision of 2026-10-31 recorded in
        #: `stage5-security-policy.json`: "Let's just leave PAN-POL-011 as disabled or not in
        #: use." Both of this model's columns are nullable booleans whose NULL is the firing side,
        #: and `disable-shadow-rule-check`'s implicit is unmeasured - so the control as written
        #: reports every appliance whose key is absent, on the strength of a reading nobody took.
        POLICY_RULE_SETTINGS = ("policy_rule_settings", "Policy Rule Settings")

    class Severity(models.TextChoices):
        INFORMATIONAL = "informational", "Informational"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    control_id = models.CharField(max_length=128, unique=True)
    name = models.CharField(max_length=255)
    #: WIDENED FROM 32 TO 64 ON 2026-11-01 BY THE `globalprotect-gateway` STAGE 8 RUN, and this
    #: is an EIGHTH registration site that the seven-place list in
    #: `OptivEdgeProbe/pipeline/stage-8-findings.md` does not mention. The field had been at 32
    #: with `globalprotect_portal_client_auth` - 32 characters exactly - already filling it, so
    #: the next type value longer than that could not be added at all.
    #:
    #: WHAT CAUGHT IT IS WORTH KNOWING, because this file already carries a note about the silent
    #: version of the same defect: a `CharField` too short for its own declared value set
    #: truncates in SQLite with NO error. That is true of a column without `choices`. Here the
    #: declared `choices` make it loud instead - `makemigrations` refused with
    #: `fields.E009: 'max_length' is too small to fit the longest value in 'choices' (34
    #: characters)` and generated nothing - so the trap for a type-minting run is a REFUSAL at
    #: migration time rather than a truncated row.
    #:
    #: Widening is additive: a CharField grown wider never truncates or rewrites existing data,
    #: nothing in this repository asserts the width, and `controls_catalog/drift.py` hashes the
    #: control_type VALUE rather than the field, so the catalogue reads no drift from it. 64
    #: rather than 35 so that the next domain to mint a long type does not pay this again.
    control_type = models.CharField(
        max_length=64,
        choices=ControlType.choices,
        default=ControlType.SECURITY_RULE,
    )
    description = models.TextField()
    rationale = models.TextField(blank=True)
    audit = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    #: The same recommendation in one sentence, for the client-facing health check document.
    #:
    #: WHY A SECOND FIELD AND NOT A TRUNCATION OF THE FIRST. `remediation` is written for the
    #: engineer who will make the change: it names dialogs, gives CLI, and says what to do about
    #: the awkward cases. Measured 2026-11-06, 96 of the 218 controls carry a command or a UI
    #: path in its FIRST SENTENCE, so no amount of trimming turns it into something a client
    #: reads. Jason, 2026-11-06: *"The 'Recommendation' is too long, and the values themselves
    #: aren't appropriate for this customer facing artifact."*
    #:
    #: The rule, enforced by `controls_catalog.schemas`: one sentence, 100 characters or fewer,
    #: imperative, naming the change and never the steps - no commands, no UI paths, no control
    #: ids. Optiv's own template sets that register in its other recommendation tables ("Create
    #: Panorama Log Forwarders", "Review unused rules and remove where practical").
    short_remediation = models.TextField(blank=True)
    #: The four lines of the health check document's Control Detail section, which gives a
    #: client one block per control that raised a finding. They are WRITTEN FOR THAT AUDIENCE
    #: and are not condensed from the four fields above.
    #:
    #: WHY NOT CONDENSE. Jason, 2026-11-06: *"These probably all need to be produced because the
    #: existing seed data isn't consistently using the right level language."* Measured the same
    #: day over all 218 controls, counting backticked identifiers, ALL-CAPS asides, dated notes
    #: and control ids: `rationale` is clean on 209, `audit` on 140, `remediation` on 116, and
    #: `description` runs to a median of 1,924 characters written to us. Those four stay as they
    #: are - the remediation pages, the findings workbook and the UI print them.
    #:
    #: The rules, enforced by `controls_catalog.schemas`: a length cap each, no commands, no
    #: control ids, nothing in the first person. `where_to_confirm` is the exception that may
    #: carry a UI path, because a UI path is what it is for.
    what_it_checks = models.TextField(blank=True)
    why_it_matters = models.TextField(blank=True)
    where_to_confirm = models.TextField(blank=True)
    what_to_change = models.TextField(blank=True)
    #: The severity a finding reports when only the baseline query matched - the baseline-tier
    #: severity, stored here rather than on the query because a control has exactly one baseline.
    #: A non-baseline query carrying `adjusted_severity` overrides it, and the WORST such match
    #: wins; see `control_queries.derive_control_query_severity_value`. That is the ONLY severity
    #: mechanism. A second one - declarative bands on the control - existed until 2026-09-09 and
    #: was removed: it was seed-only, reachable from no form, and produced every severity defect
    #: this project had.
    default_severity = models.CharField(
        max_length=32,
        choices=Severity.choices,
        default=Severity.MEDIUM,
    )
    implementation_version = models.CharField(max_length=64, default="v1")
    target_model = models.CharField(max_length=128, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    #: Every ControlType needs an entry. `save()` DERIVES target_model from this for any
    #: recognised type, so a type added to the enum and forgotten here has its target_model
    #: silently wiped to "" on every save - which reads as permanent catalog drift, since
    #: the payload carries the value and the live row does not. A test asserts the two stay
    #: in step, because nothing else does.
    _CONTROL_TYPE_TARGET_MODEL = {
        "security_rule": "integrations.SecurityRule",
        # Coverage controls assess OUR visibility, not the device. They target address objects
        # because that is where an unresolvable or uncollected EDL shows up; a coverage control
        # over another model needs its own control_type, since this map is one-to-one.
        "coverage": "integrations.AddressObject",
        "management_interface": "integrations.ManagementInterface",
        "interface_management_profile": "integrations.InterfaceManagementProfile",
        "ssl_tls_service_profile": "integrations.SslTlsServiceProfile",
        "certificate_profile": "integrations.CertificateProfile",
        "certificate": "integrations.Certificate",
        "authentication_profile": "integrations.AuthenticationProfile",
        "authentication_sequence": "integrations.AuthenticationSequence",
        "password_profile": "integrations.PasswordProfile",
        "security_profile": "integrations.SecurityProfile",
        "password_complexity": "integrations.PasswordComplexityPolicy",
        "authentication_settings": "integrations.AuthenticationSettings",
        "login_banner": "integrations.LoginBanner",
        "master_key": "integrations.MasterKey",
        "update_server": "integrations.UpdateServerSettings",
        "logging_settings": "integrations.LoggingSettings",
        "wildfire_settings": "integrations.WildfireSettings",
        "management_tls": "integrations.ManagementTlsBinding",
        "management_ssh": "integrations.ManagementSshSettings",
        "admin_user": "integrations.AdminUser",
        "server_profile": "integrations.ServerProfile",
        "ntp_settings": "integrations.NtpSettings",
        "snmp_settings": "integrations.SnmpSettings",
        "system_identity": "integrations.SystemIdentity",
        "dns_settings": "integrations.DnsSettings",
        # ONE ROW PER ENFORCEMENT POINT rather than per appliance - the firewall-wide
        # paths and then every vsys - which is why its finding model carries
        # `subject_scope` where the three device-wide siblings above do not.
        "service_route": "integrations.ServiceRoute",
        # Device-wide network objects: one row per named entry per appliance, no vsys axis.
        "ike_crypto_profile": "integrations.IkeCryptoProfile",
        "ike_gateway": "integrations.IkeGateway",
        "ipsec_crypto_profile": "integrations.IpsecCryptoProfile",
        "ipsec_tunnel": "integrations.IpsecTunnel",
        # The composite over the four above: one row per tunnel-and-gateway pair, plus one
        # per IKE gateway no tunnel names.
        "ipsec_tunnel_path": "integrations.IpsecTunnelPath",
        # Device-wide management-plane settings: one row per appliance, no entry name at all.
        # On an HA pair each yields two rows for one real configuration and nothing
        # deduplicates them - which is correct for the HA subject, whose two rows genuinely
        # differ, and a known duplication for the registration subject, whose two agree.
        "high_availability": "integrations.HighAvailabilityConfig",
        "panorama_registration": "integrations.PanoramaRegistration",
        # The subject is the issue record, which exists precisely when the object does not.
        "normalization": "integrations.NormalizationIssue",
        "config": "",
        "firewall_interface": "integrations.Interface",
        "session_settings": "integrations.PanOsSessionSettings",
        "lldp_global": "integrations.PanOsLldpGlobalSettings",
        "dhcp_interface_config": "integrations.PanOsDhcpInterfaceConfig",
        "tunnel_inspection": "integrations.PanOsTunnelInspectionCoverage",
        "routing_adjacency": "integrations.PanOsRoutingAdjacency",
        "sanctioned_application_marking": "integrations.SanctionedApplicationMarking",
        "saas_url_filtering_posture": "integrations.SaasUrlFilteringPosture",
        "saas_application_policy_posture": "integrations.SaasApplicationPolicyPosture",
        "cloud_app_engine_setting": "integrations.CloudAppEngineSetting",
        # `device-id-iot`. One row per APPLIANCE for the service state - the licence table,
        # `show system info` and the edge node are all device-wide, so on an HA pair both peers
        # hold their own and the two may legitimately differ, because a licence is per serial.
        "device_identification": "integrations.DeviceIdentificationState",
        # One row per named zone per vsys. The only one of the three whose model predates this
        # domain by months; it had no type because no control had ever asserted over a zone.
        "zone": "integrations.Zone",
        # One row per enforcement point: a conclusion about the rule SET, not about any rule.
        "rulebase_device_match": "integrations.RulebaseDeviceMatchVerdict",
        # `file-data-filtering`. One row per enforcement point: a conclusion about whether the
        # traffic leaving this point is watched for regulated data at all, NOT about any one
        # profile. The commonest failing state is no data-filtering profile anywhere beneath the
        # point - three of four lab appliances - so a profile-keyed row would report nothing on
        # exactly the devices that fail. The domain's other three controls REUSE
        # `security_profile` above rather than mint a second type for one model.
        "data_filtering_posture": "integrations.DataFilteringPosture",
        # `globalprotect-portal`. THREE models and THREE types, because none of the three had a
        # type: `rev(_CONTROL_TYPE_TARGET_MODEL)` answered NO TYPE for all three before this
        # change, so nothing here is a second type for a model that already has one.
        #
        # One portal entry of one vsys. PAN-GPP-001, -003, -004 and -005 share it, which is the
        # normal case - many controls, one type, one model.
        "globalprotect_portal": "integrations.GlobalProtectPortal",
        # One row of one portal's client-auth table, keyed by the endpoint class it serves.
        # PAN-GPP-002 only. The child grain is the control's own grain: the parent cannot say
        # which class is weak, and firing the parent for one child is the downward walk ruling 6
        # refuses.
        "globalprotect_portal_client_auth": "integrations.GlobalProtectPortalClientAuthRow",
        # One vsys, as a verdict over its GlobalProtect objects as a whole. PAN-GPP-006 only.
        # The absence of a portal, of a published application or of a posture matcher has no
        # entry row to live on, which is what this grain exists for.
        "globalprotect_enforcement_point": "integrations.GlobalProtectEnforcementPoint",
        # `platform-lifecycle`. THREE models and THREE types, because none of the three had a
        # type: `rev(_CONTROL_TYPE_TARGET_MODEL)` answered NO TYPE for all three before this
        # change, measured against 48 types and 48 DISTINCT targets, so nothing here is a second
        # type for a model that already has one.
        #
        # One appliance's content streams, as one row over the whole set. PAN-PLT-002 only.
        "firewall_content_streams": "integrations.FirewallContentStreams",
        # One appliance's entitlement verdict. PAN-PLT-004 only - and both of that control's
        # assertion records clause on THIS model, one on the subscription state and one on the
        # support state, so the control has no silent half.
        "licence_inventory": "integrations.LicenceInventory",
        # One appliance's log-database alarm mechanism. PAN-PLT-006's first half only.
        "log_alarm_settings": "integrations.LogAlarmSettings",
        # `updates`. ONE model and ONE type, for FOUR controls - PAN-UPD-001, -002, -004 and
        # -005 - because all five content types live on one row keyed by the appliance.
        # `rev()` answered NO TYPE before this change, measured against 51 types and 51 DISTINCT
        # targets, so this is not a second type for a model that already has one.
        #
        # `integrations.ContentDeploymentSchedule` gets NO entry here on purpose: PAN-UPD-006's
        # only record naming it is discharged `not_in_configuration` on a scope ruling, so it
        # owes no query and has no catalog entry to target anything.
        "content_update_schedule": "integrations.ContentUpdateSchedule",
        # `url-filtering`. ONE entry for ONE control - PAN-URL-006 - and FIVE of this
        # domain's six controls get NO entry here at all, because they carry the EXISTING
        # `security_profile` type and this map already points it at
        # `integrations.SecurityProfile`. `rev()` answered NO TYPE for
        # `integrations.CustomUrlCategory` and `security_profile` for `integrations.
        # SecurityProfile` before this change, measured against 52 types and 52 DISTINCT
        # targets, so this mints one and reuses one.
        "custom_url_category": "integrations.CustomUrlCategory",
        # `user-id`. TWO entries for TWO new models and SIX controls. PAN-UID-001 and
        # PAN-UID-005 get NO entry here at all, because they carry the EXISTING `zone` and
        # `management_interface` types and this map already points those at `integrations.Zone`
        # and `integrations.ManagementInterface`. Measured against 53 types and 53 DISTINCT
        # targets before the mint, so neither line below is a second type for a model that
        # already has one.
        #
        # One row per VSYS: the PAN-OS integrated User-ID agent's settings node. PAN-UID-003
        # (client probing), PAN-UID-004 (the service account and session reading) and
        # PAN-UID-006 (mapping expiry) all share it.
        "user_id_collector": "integrations.UserIdCollectorSettings",
        # One row per VSYS: a verdict over the whole include/exclude discovery list, including
        # the commonest state, which is that the list holds nothing. PAN-UID-002 only.
        "user_id_discovery_bound": "integrations.UserIdDiscoveryBound",
        # One row per APPLIANCE: which certificate the firewall signs with when it stands in for
        # a destination it is decrypting. PAN-DCP-006 only - the other six PAN-DCP controls are
        # `security_profile` above, over the `decryption` kind of the profile model.
        "decryption_settings": "integrations.DecryptionSettings",
        # `globalprotect-gateway`. THREE models and THREE types, because none of the three had
        # one: `rev(_CONTROL_TYPE_TARGET_MODEL)` answered NO TYPE for all of them before this
        # change, measured against 56 types and 56 DISTINCT targets, so nothing here is a second
        # type for a model that already has one. The domain's FOURTH model,
        # `integrations.GlobalProtectEnforcementPoint`, already answered
        # `globalprotect_enforcement_point` and PAN-GPG-005 reuses it.
        #
        # One gateway entry of one vsys. PAN-GPG-001, -006 and -007 share it - many controls,
        # one type, one model, which is the normal case.
        "globalprotect_gateway": "integrations.GlobalProtectGateway",
        # One row of one gateway's client-auth table, keyed by the client operating system.
        # PAN-GPG-002 only. The child grain is the control's own grain: the parent cannot say
        # which platform is weak, and firing the parent for one child is the downward walk
        # ruling 6 refuses. The row's own nullable `gateway` FK is the upward walk it permits.
        "globalprotect_gateway_client_auth": "integrations.GlobalProtectGatewayClientAuth",
        # One agent client-settings row of one gateway. PAN-GPG-003 and PAN-GPG-004 share it.
        "globalprotect_gateway_agent_config": "integrations.GlobalProtectGatewayAgentConfig",
        # `zone-dos-protection`. TWO models and TWO types, because neither had one:
        # `rev(_CONTROL_TYPE_TARGET_MODEL)` answered NO TYPE for both before this change,
        # measured against 59 types and 59 DISTINCT targets, so neither line is a second type for
        # a model that already has one. The domain's other two models already answered - `zone`
        # for `integrations.Zone` and `security_profile` for `integrations.SecurityProfile` - and
        # PAN-ZON-001 and PAN-ZON-008 reuse those.
        #
        # One named zone protection profile of one appliance. PAN-ZON-002 to -006 share it. THE
        # OWNER IS THE APPLIANCE AND NOT AN ENFORCEMENT POINT: `network/profiles/zone-protection-
        # profile` has exactly one scope on a firewall, measured - `action=complete` answers
        # code=6 Invalid sequence at both the shared and the vsys spellings - so there is no
        # per-vsys copy to tell apart.
        "zone_protection_profile": "integrations.ZoneProtectionProfile",
        # One DoS Protection policy rule of one rulebase of one vsys. PAN-ZON-007 only.
        "dos_policy_rule": "integrations.DosPolicyRule",
        # `decryption-policy`. FOUR models and FOUR types, because none of the four had one:
        # `rev(_CONTROL_TYPE_TARGET_MODEL)` answered NO TYPE for all of them before this change,
        # measured against 63 types and 63 DISTINCT targets, so nothing here is a second type for
        # a model that already has one.
        #
        # One ordered entry of one decryption rulebase of one vsys. Seven controls share it -
        # PAN-DEC-002, -003, -005, -006, -007, -008 and -010.
        "decryption_policy_rule": "integrations.DecryptionPolicyRule",
        # One enforcement point's rulebase as a verdict over all of its rules. PAN-DEC-001 and
        # PAN-DEC-009. The absence of a rulebase has no entry row to live on, which is what this
        # grain exists for and is the commonest state stage 4 measured.
        "decryption_rulebase_coverage": "integrations.DecryptionRulebaseVerdict",
        # One exclusion the organisation added itself, in one scope of one appliance.
        # PAN-DEC-004's first record only.
        "ssl_decryption_exclusion": "integrations.SslDecryptionExclusion",
        # One appliance's departures from the vendor's list. NO SHIPPED CONTROL TARGETS THIS, the
        # `lldp_global` state above: PAN-DEC-004's second record names it and a control has one
        # target model, so the half is silent until somebody splits the catalogue id.
        "ssl_decryption_vendor_exclusion_optout":
            "integrations.SslDecryptionVendorExclusionOptOut",
        # `logging`, 2026-11-01. ONE SERVER ENTRY of one log-settings server profile, in one
        # scope of one appliance - a CHILD row whose identity is the parent profile's name and
        # its own, which is why its finding model carries `subject_scope`. Stage 5 states two
        # subjects over this one table and only the syslog kind has a control; the e-mail kind
        # is reachable by the same type the day something asserts it.
        "log_server_target": "integrations.LogServerTarget",
        # ONE ROW PER VIRTUAL SYSTEM rather than per appliance, so its finding model carries
        # `subject_scope` too: `vsys1` is not unique in an estate and is not unique on one
        # Panorama.
        "vsys_log_forwarding": "integrations.VsysLogForwarding",
        # ONE ROW PER APPLIANCE, both of them. On an HA pair that is two rows for two peers and
        # the difference is real rather than duplication: the peers have different management
        # addresses and are separately reachable, and the operational mode is set per appliance
        # and synchronised by nothing.
        "management_plane_addressing": "integrations.ManagementPlaneAddressing",
        "appliance_operational_mode": "integrations.ApplianceOperationalMode",
        # ONE ROW PER ENFORCEMENT POINT, so its finding model carries `subject_scope`: the row's
        # own name is a vsys name, which is not unique in an estate.
        "vsys_rule_posture": "integrations.VsysRulePosture",
        # ONE ROW PER APPLIANCE, and on an HA pair that is TWO ROWS FOR ONE REAL CONFIGURATION
        # with nothing deduplicating them - the node has no vsys axis and the two peers'
        # management containers have been measured differing while config sync reported
        # synchronized, so the difference is data rather than duplication.
        "policy_rule_settings": "integrations.PolicyRuleSettings",
    }

    class Meta:
        ordering = ["control_id"]

    def __str__(self) -> str:
        return f"{self.control_id} - {self.name}"

    def save(self, *args, **kwargs):
        # For recognized control types, always derive target_model from the mapping
        # so it can never go stale when control_type changes.
        # For unrecognized types (future extension), preserve explicit target_model.
        if self.control_type in {c.value for c in self.ControlType}:
            self.target_model = self._CONTROL_TYPE_TARGET_MODEL.get(self.control_type, "")
        super().save(*args, **kwargs)

    _TARGET_MODEL_LABELS = {
        "integrations.AddressObject": "Address Object",
        "integrations.SecurityRule": "Security Rule",
        "integrations.ManagementInterface": "Management Interface",
        "integrations.InterfaceManagementProfile": "Interface Management Profile",
        "integrations.SslTlsServiceProfile": "SSL/TLS Service Profile",
        "integrations.CertificateProfile": "Certificate Profile",
        "integrations.Certificate": "Certificate",
        "integrations.AuthenticationProfile": "Authentication Profile",
        "integrations.AuthenticationSequence": "Authentication Sequence",
        "integrations.PasswordProfile": "Password Profile",
        "integrations.SecurityProfile": "Security Profile",
        "integrations.PasswordComplexityPolicy": "Minimum Password Complexity",
        "integrations.AuthenticationSettings": "Authentication Settings",
        "integrations.LoginBanner": "Login Banner",
        "integrations.MasterKey": "Master Key",
        "integrations.UpdateServerSettings": "Update Server Settings",
        "integrations.LoggingSettings": "Logging and Reporting Settings",
        "integrations.WildfireSettings": "WildFire Settings",
        "integrations.ManagementTlsBinding": "Management TLS",
        "integrations.ManagementSshSettings": "Management SSH",
        "integrations.AdminUser": "Administrator",
        "integrations.ServerProfile": "AAA Server Profile",
        "integrations.NtpSettings": "NTP",
        "integrations.SnmpSettings": "SNMP",
        "integrations.SystemIdentity": "System Identity",
        "integrations.DnsSettings": "Management Resolvers",
        "integrations.ServiceRoute": "Management Service Paths",
        "integrations.NormalizationIssue": "Normalization Issue",
        "integrations.IkeCryptoProfile": "IKE Crypto Profile",
        "integrations.IkeGateway": "IKE Gateway",
        "integrations.IpsecCryptoProfile": "IPSec Crypto Profile",
        "integrations.IpsecTunnel": "IPSec Tunnel",
        "integrations.IpsecTunnelPath": "IPSec Tunnel Path",
        "integrations.HighAvailabilityConfig": "High Availability",
        "integrations.PanoramaRegistration": "Panorama Registration",
        "integrations.Interface": "Interface",
        "integrations.PanOsSessionSettings": "Session Settings",
        "integrations.PanOsLldpGlobalSettings": "Global LLDP",
        "integrations.PanOsDhcpInterfaceConfig": "DHCP Interface Configuration",
        "integrations.PanOsTunnelInspectionCoverage": "Tunnel Inspection Coverage",
        "integrations.PanOsRoutingAdjacency": "Routing Adjacency",
        "integrations.SanctionedApplicationMarking": "Sanctioned Application Marking",
        "integrations.SaasUrlFilteringPosture": "SaaS URL Filtering Posture",
        "integrations.SaasApplicationPolicyPosture": "SaaS Application Policy Posture",
        "integrations.CloudAppEngineSetting": "App-ID Cloud Engine",
        "integrations.DeviceIdentificationState": "Device Identification",
        "integrations.Zone": "Security Zone",
        "integrations.RulebaseDeviceMatchVerdict": "Rulebase Device Match",
        "integrations.DataFilteringPosture": "Data Filtering Posture",
        "integrations.GlobalProtectPortal": "GlobalProtect Portal",
        "integrations.GlobalProtectPortalClientAuthRow": "GlobalProtect Portal Client Authentication",
        "integrations.GlobalProtectEnforcementPoint": "GlobalProtect Enforcement Point",
        "integrations.FirewallContentStreams": "Firewall Content Streams",
        "integrations.LicenceInventory": "Licence Inventory",
        "integrations.LogAlarmSettings": "Log Database Alarms",
        "integrations.ContentUpdateSchedule": "Content Update Schedule",
        "integrations.CustomUrlCategory": "Custom URL Category",
        "integrations.UserIdCollectorSettings": "User-ID Collector",
        "integrations.UserIdDiscoveryBound": "User-ID Discovery Bound",
        "integrations.DecryptionSettings": "Decryption Settings",
        "integrations.GlobalProtectGateway": "GlobalProtect Gateway",
        "integrations.GlobalProtectGatewayClientAuth": "GlobalProtect Gateway Client Authentication",
        "integrations.GlobalProtectGatewayAgentConfig": "GlobalProtect Gateway Agent Configuration",
        "integrations.ZoneProtectionProfile": "Zone Protection Profile",
        "integrations.DosPolicyRule": "DoS Policy Rule",
        "integrations.DecryptionPolicyRule": "Decryption Policy Rule",
        "integrations.DecryptionRulebaseVerdict": "Decryption Rulebase Coverage",
        "integrations.SslDecryptionExclusion": "SSL Decryption Exclusion",
        "integrations.SslDecryptionVendorExclusionOptOut":
            "SSL Decryption Vendor Exclusion Opt-Out",
        "integrations.LogServerTarget": "Log Server Target",
        "integrations.VsysLogForwarding": "Virtual System Log Forwarding",
        "integrations.ManagementPlaneAddressing": "Management Plane Addressing",
        "integrations.ApplianceOperationalMode": "Appliance Operational Mode",
        "integrations.VsysRulePosture": "Virtual System Rule Posture",
        "integrations.PolicyRuleSettings": "Policy Rule Settings",
    }

    @property
    def assessment_target_label(self) -> str:
        return self._TARGET_MODEL_LABELS.get(self.target_model, "Configuration")

    @property
    def supports_security_rule_ui(self) -> bool:
        return self.target_model == "integrations.SecurityRule"


class AssessmentRun(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    name = models.CharField(max_length=255, blank=True)
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.PENDING,
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.name or f"Assessment Run {self.pk}"

    def mark_running(self) -> None:
        self.status = self.Status.RUNNING
        if not self.started_at:
            self.started_at = timezone.now()

    def mark_completed(self) -> None:
        self.status = self.Status.COMPLETED
        self.completed_at = timezone.now()

    def mark_failed(self) -> None:
        self.status = self.Status.FAILED
        self.completed_at = timezone.now()

    def next_reference_number(self) -> int:
        """The next free finding reference number in this run, across EVERY finding model.

        The counter lives on this instance, seeded once from the highest number already stored
        in the run, so a generator filling a run allocates without querying 23 tables per
        finding. Every generator in `finding_run.GENERATORS` is handed the same instance, which
        is what makes the numbers unique across models. The database cannot enforce that - no
        constraint spans tables - so `test_finding_reference` does.
        """
        if getattr(self, "_next_reference_number", None) is None:
            from django.db.models import Max

            from assessments.finding_registry import FINDING_MODELS

            highest = 0
            for model in FINDING_MODELS:
                stored = (model.objects.filter(assessment_run=self)
                          .aggregate(highest=Max("reference_number"))["highest"])
                highest = max(highest, stored or 0)
            self._next_reference_number = highest + 1
        number = self._next_reference_number
        self._next_reference_number += 1
        return number


class ControlQuery(models.Model):
    control = models.ForeignKey(
        Control,
        on_delete=models.CASCADE,
        related_name="queries",
    )
    name = models.CharField(max_length=255)
    short_description = models.CharField(max_length=255, blank=True)
    canonical_query = models.JSONField(default=dict)
    #: The fields this query ASSERTS on, as distinct from the ones that scope it. Stage 5 of the
    #: pipeline gives every clause a `role` - assertion, applicability or scope - and
    #: `validate_search_clause` whitelists clause keys and rebuilds the dict from them, so the
    #: role cannot ride on the clause and has to be carried beside it.
    #:
    #: WHY IT MATTERS: `findings.build_rows` draws the value-at-fault fill, and without this it
    #: marks every field the BASELINE query clauses on - whichever query actually matched, and
    #: including the clauses that merely scope the control. Measured across the 28 pipeline
    #: artifacts: 107 of 220 controls have a non-assertion clause in their baseline record, so
    #: nearly half the catalogue marks at least one cell that is not the fault. On one IKE gateway
    #: the marked cell was `ike_version = ikev2` - which the baseline EXCLUDES and the matched
    #: query REQUIRES, so the row named as the fault the one setting that gateway had right.
    #:
    #: EMPTY MEANS "NOT STATED" AND FALLS BACK TO THE OLD BEHAVIOUR, deliberately. Controls that
    #: predate the pipeline have hand-written queries whose fields correspond to nothing stage 5
    #: declares - 71 of 249 such fields resolve to no role - so they cannot be backfilled and get
    #: this only when their domain's stage 8 run rewrites the entry. Until then their rows stay
    #: imperfect rather than breaking.
    asserted_fields = models.JSONField(default=list, blank=True)
    is_baseline = models.BooleanField(default=False)
    adjusted_severity = models.CharField(
        max_length=32,
        choices=Control.Severity.choices,
        blank=True,
        null=True,
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["control__control_id", "-is_baseline", "name", "id"]

    def __str__(self) -> str:
        return f"{self.control.control_id} / {self.name}"

    def clean(self) -> None:
        super().clean()
        if self.control_id and isinstance(self.canonical_query, dict):
            q_model = self.canonical_query.get("model")
            control_target = self.control.target_model
            if control_target and q_model != control_target:
                raise ValidationError({
                    "canonical_query": (
                        f"Query model must be {control_target} for control "
                        f"{self.control.control_id}"
                        + (f" but got {q_model!r}" if q_model else " — model key is missing")
                        + "."
                    )
                })
        if not self.is_baseline:
            return
        if self.adjusted_severity not in (None, ""):
            raise ValidationError(
                {
                    "adjusted_severity": (
                        "Baseline queries must not define an adjusted severity."
                    )
                }
            )

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class FindingBase(models.Model):
    """Everything every finding carries, regardless of what it is a finding ABOUT.

    Seven finding models existed with the same thirty-odd lines copied into each, and copying
    is what let five of them drift out of the report and the findings page without a test
    failing. Shared shape belongs in one place so that "all findings" is a statement about a
    base class rather than a list somebody has to remember to extend.

    `assessment_run` and `control` are DELIBERATELY left on each concrete model rather than
    lifted here. A foreign key on an abstract base needs `related_name="%(class)ss"`, which
    interpolates to the lowercased class name and would turn
    `run.certificate_profile_findings` into `run.certificateprofilefindings` on every reverse
    accessor in the app. Four duplicated lines per model is the cheaper of the two.

    The indexes here name those concrete fields. That is legal - an abstract Meta is validated
    against the concrete model, which does declare them - but it means a subclass that forgets
    `assessment_run` or `control` fails at check time rather than silently.

    `reference_number` is the finding's human-readable identifier - rendered F-0001 by
    `reference` - used by every presentation of a finding, in the app and in artifacts alike.
    Jason, 2026-09-16: "A consistent, human readable, unique identifier used at presentation layers
    in the app and all related artifacts. Re-runs should reset the identifier." So it is unique
    within a RUN, across every finding model, and a new run starts again at 1. The database id is
    none of those things: each model numbers its own rows, so ids collide across models, and every
    run deletes and recreates findings, so they never repeat.

    `snapshot` is the configuration the finding was COMPUTED FROM, copied off the subject at
    generation time. It is not the same question as the subject's own `source_snapshot`, which
    says what that object is CURRENTLY parsed from: re-collect without re-running findings and
    the subject is repointed in place, so a finding reading through the relationship starts
    reporting a collection date later than anything it was derived from. Pinning it here makes
    the date a fact about the run, and makes a stale assessment visible instead of invisible.

    It CAN live on the abstract base, unlike the two above, because nothing needs a reverse
    accessor: `related_name="+"` declines the reverse relation outright, so there is no name to
    interpolate and `Snapshot` does not grow twenty-four accessors nobody asked for.

    `on_delete=PROTECT` so configuration an assessment depends on cannot be deleted out from
    under it. `null=True` because a run predating this field, or a subject that normalization
    left without a snapshot, is a real state and not worth refusing a finding over - it renders
    as "Not recorded" rather than failing the run.

    Subclass Meta must CONCATENATE `constraints` as well as `indexes` - Django replaces both rather
    than merging them, and `test_finding_reference` fails for a model that loses the constraint.
    """

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        SUPPRESSED = "suppressed", "Suppressed"
        RESOLVED = "resolved", "Resolved"

    status = models.CharField(max_length=32, choices=Status.choices, default=Status.OPEN)
    severity = models.CharField(max_length=32, choices=Control.Severity.choices)
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    #: Allocated from the run on first save; see the class docstring and `reference`.
    reference_number = models.PositiveIntegerField(editable=False)
    #: The configuration this finding was COMPUTED FROM, copied off the subject when the
    #: generator writes the finding. See the class docstring.
    snapshot = models.ForeignKey(
        Snapshot,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
    )

    class Meta:
        abstract = True
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["assessment_run", "control"]),
            models.Index(fields=["status"]),
            models.Index(fields=["severity"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["assessment_run", "reference_number"],
                name="%(app_label)s_%(class)s_unique_reference_per_run",
            ),
        ]

    @property
    def reference(self) -> str:
        """F-0001. Widens past four digits rather than wrapping."""
        return f"F-{self.reference_number:04d}"

    def save(self, *args, **kwargs):
        if self.reference_number is None:
            self.reference_number = self.assessment_run.next_reference_number()
        super().save(*args, **kwargs)


class ObjectFindingBase(FindingBase):
    """A finding against a NAMED object rather than a device-wide setting.

    The subject name is frozen at generation time: the object can be renamed or deleted and the
    finding must still say what it found. `subject_scope` is added only by the models whose
    objects can collide on name across scopes - a name is not unique on a device, measured
    2026-09-02 on `TLSv1.3_Default`, which exists as both predefined and shared.
    """

    matched_query_names = models.JSONField(default=list, blank=True)
    subject_name = models.CharField(max_length=64, blank=True)

    class Meta(FindingBase.Meta):
        abstract = True


class FindingControlQueryBase(models.Model):
    """The join row between a finding and the control query that matched it."""

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True
        ordering = ["created_at", "id"]


class RuleFinding(ObjectFindingBase):
    """A finding against one security rule.

    An OBJECT finding, like every other named subject. It was built on `FindingBase` until
    2026-09-16, so it carried no `subject_name` and its summary could not say which rule it was
    about - a policy finding read "Matched control query: Baseline." and nothing more. The
    subject was deferred until a control fired; splitting PAN-SVC-009 and starting on the
    security-policy domain is what made it due.

    `subject_scope` is required here for the reason the base class gives: a rule name is unique
    only per enforcement point (`integrations_unique_security_rule_name_per_point`), so the same
    name legitimately exists in several vsys. The scope also carries the rulebase, since a local
    rule and a Panorama pre-rule are different objects a reader must tell apart.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun,
        on_delete=models.CASCADE,
        related_name="rule_findings",
    )
    control = models.ForeignKey(
        Control,
        on_delete=models.PROTECT,
        related_name="rule_findings",
    )
    security_rule = models.ForeignKey(
        SecurityRule,
        on_delete=models.CASCADE,
        related_name="rule_findings",
    )
    #: "<config_source>:<vsys>" - e.g. "local:vsys1", "pushed_pre:vsys3".
    subject_scope = models.CharField(max_length=128, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery,
        through="RuleFindingControlQuery",
        related_name="rule_findings",
        blank=True,
    )

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["security_rule"]),
        ]
        constraints = FindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "security_rule"],
                name="unique_rule_finding_per_run_control_rule",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on rule {self.security_rule_id}"


class RuleFindingControlQuery(FindingControlQueryBase):
    rule_finding = models.ForeignKey(
        RuleFinding,
        on_delete=models.CASCADE,
        related_name="query_links",
    )
    control_query = models.ForeignKey(
        ControlQuery,
        on_delete=models.CASCADE,
        related_name="finding_links",
    )

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["rule_finding", "control_query"],
                name="unique_rule_finding_control_query_link",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.rule_finding_id} <- {self.control_query_id}"


class Catalog(models.Model):
    key = models.SlugField(max_length=128, unique=True, blank=True)
    label = models.CharField(max_length=255)
    version = models.CharField(max_length=64, default="v1")
    description = models.TextField(blank=True)
    payload = models.JSONField(default=dict)
    is_seeded = models.BooleanField(default=False)
    is_snapshot = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["is_snapshot", "-is_seeded", "label", "version", "pk"]

    def __str__(self) -> str:
        return f"{self.label} ({self.version})"

    @classmethod
    def generate_unique_key(cls, label: str, *, exclude_pk: int | None = None) -> str:
        base_key = slugify(label)[:110] or "catalog"
        candidate = base_key
        suffix = 2
        queryset = cls.objects.all()
        if exclude_pk is not None:
            queryset = queryset.exclude(pk=exclude_pk)
        while queryset.filter(key=candidate).exists():
            candidate = f"{base_key[:110]}-{suffix}"
            suffix += 1
        return candidate

    @property
    def control_count(self) -> int:
        controls = self.payload.get("controls", [])
        return len(controls) if isinstance(controls, list) else 0

    @property
    def query_count(self) -> int:
        controls = self.payload.get("controls", [])
        if not isinstance(controls, list):
            return 0
        return sum(
            len(control.get("queries", []))
            for control in controls
            if isinstance(control, dict) and isinstance(control.get("queries", []), list)
        )

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_unique_key(self.label, exclude_pk=self.pk)
        return super().save(*args, **kwargs)


class ApplicationEnvironmentCatalogState(models.Model):
    application_environment = models.OneToOneField(
        ApplicationEnvironment,
        on_delete=models.CASCADE,
        related_name="assessment_catalog_state",
    )
    current_catalog = models.ForeignKey(
        Catalog,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="environment_states",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["application_environment_id"]

    def __str__(self) -> str:
        catalog_label = self.current_catalog.label if self.current_catalog else "None"
        return f"{self.application_environment} -> {catalog_label}"


class ManagementInterfaceFinding(ObjectFindingBase):
    """A finding against ONE management surface, not one appliance.

    The subject is what makes the finding useful. "10.0.0.0/8 is allowed" is not
    actionable; "allowed to ethernet1/1" is. An appliance has several surfaces - MGT,
    aux-1, aux-2, and one per layer-3 interface carrying a management profile - so a single
    control against a single appliance produces several findings. They are different doors,
    not duplicates.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="management_interface_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="management_interface_findings")
    management_interface = models.ForeignKey(
        ManagementInterface, on_delete=models.CASCADE, related_name="findings")
    #: Frozen at generation time, like RuleFinding.matched_query_names - a finding stays a
    #: faithful record of its run even after the catalog is edited.
    #: Also frozen: the surface's reportable name at the time of the run. An interface can
    #: be renamed or a profile unbound, and a stale finding must still say what it found.
    control_queries = models.ManyToManyField(
        ControlQuery, through="ManagementInterfaceFindingControlQuery",
        related_name="management_interface_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["management_interface"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "management_interface"],
                name="unique_management_interface_finding_per_run_control_surface"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on {self.subject_name or self.management_interface_id}"


class ManagementInterfaceFindingControlQuery(FindingControlQueryBase):
    management_interface_finding = models.ForeignKey(
        ManagementInterfaceFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="management_interface_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["management_interface_finding", "control_query"],
                name="unique_management_interface_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.management_interface_finding_id} <- {self.control_query_id}"


class InterfaceManagementProfileFinding(ObjectFindingBase):
    """A finding against one profile ON ONE APPLIANCE.

    Unlike the management-surface findings, the subject here is not a door - it is an
    object that opens none. An unused profile grants no access; it is configuration debt,
    and the finding says so rather than implying exposure.

    Per appliance rather than per template, deliberately. A profile pushed from a Panorama
    template exists in each firewall's merged config separately, and bound on one device
    but unbound on another is two different facts about two devices. Aggregating them would
    make the finding easier to read and less true.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="interface_management_profile_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="interface_management_profile_findings")
    interface_management_profile = models.ForeignKey(
        InterfaceManagementProfile, on_delete=models.CASCADE, related_name="findings")
    #: Frozen at generation time, as everywhere else - a finding stays a faithful record of
    #: its run after the catalog is edited.
    #: Also frozen: the profile's name at the time of the run, since a profile can be
    #: renamed or removed and the finding must still say what it found.
    control_queries = models.ManyToManyField(
        ControlQuery, through="InterfaceManagementProfileFindingControlQuery",
        related_name="interface_management_profile_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["interface_management_profile"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "interface_management_profile"],
                name="unique_imp_finding_per_run_control_profile"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on profile {self.subject_name}"


class InterfaceManagementProfileFindingControlQuery(FindingControlQueryBase):
    interface_management_profile_finding = models.ForeignKey(
        InterfaceManagementProfileFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="interface_management_profile_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["interface_management_profile_finding", "control_query"],
                name="unique_imp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.interface_management_profile_finding_id} <- {self.control_query_id}"


class SslTlsServiceProfileFinding(ObjectFindingBase):
    """A finding against one SSL/TLS service profile ON ONE APPLIANCE.

    Per appliance for the reason InterfaceManagementProfileFinding records: the same object
    pushed from a Panorama template exists in each firewall's merged config separately, and
    present on one peer but not another is two facts about two devices.

    The subject carries its SCOPE as well as its name. Two profiles can share a name in
    different scopes - a shared entry and a predefined one, measured 2026-09-02 - and a
    finding naming only "TLSv1.3_Default" would not say which was assessed.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="ssl_tls_service_profile_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="ssl_tls_service_profile_findings")
    ssl_tls_service_profile = models.ForeignKey(
        SslTlsServiceProfile, on_delete=models.CASCADE, related_name="findings")
    subject_scope = models.CharField(max_length=16, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery, through="SslTlsServiceProfileFindingControlQuery",
        related_name="ssl_tls_service_profile_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["ssl_tls_service_profile"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "ssl_tls_service_profile"],
                name="unique_stsp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on SSL/TLS service profile {self.subject_name}"


class SslTlsServiceProfileFindingControlQuery(FindingControlQueryBase):
    ssl_tls_service_profile_finding = models.ForeignKey(
        SslTlsServiceProfileFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="ssl_tls_service_profile_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["ssl_tls_service_profile_finding", "control_query"],
                name="unique_stsp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.ssl_tls_service_profile_finding_id} <- {self.control_query_id}"


class CertificateProfileFinding(ObjectFindingBase):
    """A finding against one certificate profile ON ONE APPLIANCE.

    Per appliance for the reason InterfaceManagementProfileFinding records: the same object
    pushed from a Panorama template exists in each firewall's merged config separately, and
    present on one peer but not another is two facts about two devices.

    The subject carries its SCOPE as well as its name. Two profiles can share a name in
    different scopes - a shared entry and a predefined one, measured 2026-09-02 - and a
    finding naming only "TLSv1.3_Default" would not say which was assessed.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="certificate_profile_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="certificate_profile_findings")
    certificate_profile = models.ForeignKey(
        CertificateProfile, on_delete=models.CASCADE, related_name="findings")
    subject_scope = models.CharField(max_length=16, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery, through="CertificateProfileFindingControlQuery",
        related_name="certificate_profile_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["certificate_profile"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "certificate_profile"],
                name="unique_cp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on certificate profile {self.subject_name}"


class CertificateProfileFindingControlQuery(FindingControlQueryBase):
    certificate_profile_finding = models.ForeignKey(
        CertificateProfileFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="certificate_profile_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["certificate_profile_finding", "control_query"],
                name="unique_cp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.certificate_profile_finding_id} <- {self.control_query_id}"


class CertificateFinding(ObjectFindingBase):
    """A finding against one certificate ON ONE APPLIANCE IN ONE SCOPE.

    Scope is on the finding because a name is not unique on a device, and because the
    predefined scope is read-only: a finding against a vendor-shipped certificate cannot be
    remediated on the device at all, and the row has to say so.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="certificate_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="certificate_findings")
    certificate = models.ForeignKey(
        Certificate, on_delete=models.CASCADE, related_name="findings")
    subject_scope = models.CharField(max_length=16, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery, through="CertificateFindingControlQuery",
        related_name="certificate_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["certificate"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "certificate"],
                name="unique_cert_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on certificate {self.subject_name}"


class CoverageFinding(ObjectFindingBase):
    """A finding about what this ASSESSMENT could not see, rather than about the device.

    Jason, 2026-10-02: "I want these to be somewhat generic in nature, it doesn't need to
    follow the object related pattern strictly ... I'd prefer a separate tab for 'coverage'
    findings with descriptions that include object names if relevant. I don't want them to
    disturb the highly structured, object related findings."

    The generic half is the PRESENTATION and the summary: these get their own tab and say what
    is unknown in prose, rather than being columns beside the object findings. The structure is
    kept, because the first attempt at this dropped the foreign key and six convergence
    invariants rejected it - every finding model extends ObjectFindingBase, freezes a subject
    name, and is generated through one spec. Those tests exist because five finding models once
    drifted out of the report by being special, and a coverage finding is not worth being the
    exception that reopens it.

    So the subject is an address object, keyed. The limit that implies is real and worth
    stating: a coverage control about something that is NOT an address object - a rule whose
    application count cannot be resolved, say - cannot use this model, because control_type
    maps to exactly one target model. That control needs its own, and the question of a truly
    subject-less finding should be reopened then, with a real case rather than a hypothetical.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="coverage_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="coverage_findings")
    address_object = models.ForeignKey(
        AddressObject, on_delete=models.CASCADE, related_name="coverage_findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="CoverageFindingControlQuery",
        related_name="coverage_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["address_object"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "address_object"],
                name="unique_coverage_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} coverage: {self.subject_name}"


class CoverageFindingControlQuery(FindingControlQueryBase):
    coverage_finding = models.ForeignKey(
        CoverageFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="coverage_finding_links")


class NormalizationFinding(ObjectFindingBase):
    """A finding whose subject is an object this assessment could not build.

    `CoverageFinding` above reports a gap in what we know ABOUT an object that normalized. This
    reports the gap `CoverageFinding` structurally cannot: its `address_object` foreign key is
    non-null, and `NormalizationIssue.disposition` has a member meaning the object does not
    exist downstream at all - so the objects that failed worst have no row to point at. The
    issue record is the only row that exists in that case, which is why it is the subject here.

    This is the branch `CoverageFinding`'s own docstring describes: "a coverage control about
    something that is NOT an address object [...] cannot use this model, because control_type
    maps to exactly one target model. That control needs its own, and the question of a truly
    subject-less finding should be reopened then, with a real case rather than a hypothetical."
    The case arrived; the finding is not subject-less after all, because the issue row IS a
    subject. So this stays on `ObjectFindingBase` with every convergence invariant satisfied
    rather than excepted, and `FindingBase` keeps its property of having no direct subclasses.

    TWO FIELD-WIDTH FACTS DECIDE THE `subject_name` CALLABLE, and both cut the wrong way here.
    `ObjectFindingBase.subject_name` is 64 characters while `NormalizationIssue.name` is 255,
    which is harmless for every other finding model and is not harmless for this one - the rows
    that exist are the ones whose payload was malformed. And `name` is legitimately EMPTY on
    some of them ("Empty when the entry had no @name; that is itself the problem"), so the
    callable needs a fallback or the worst rows arrive with a blank subject. See
    `normalization_findings.SPEC`.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="normalization_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="normalization_findings")
    normalization_issue = models.ForeignKey(
        "integrations.NormalizationIssue", on_delete=models.CASCADE,
        related_name="normalization_findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="NormalizationFindingControlQuery",
        related_name="normalization_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["normalization_issue"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "normalization_issue"],
                name="unique_normalization_finding_per_run_control_issue"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} normalization: {self.subject_name}"


class NormalizationFindingControlQuery(FindingControlQueryBase):
    normalization_finding = models.ForeignKey(
        NormalizationFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="normalization_finding_links")


class CertificateFindingControlQuery(FindingControlQueryBase):
    certificate_finding = models.ForeignKey(
        CertificateFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="certificate_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["certificate_finding", "control_query"],
                name="unique_cert_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.certificate_finding_id} <- {self.control_query_id}"


class AuthenticationProfileFinding(ObjectFindingBase):
    """A finding against one authentication profile ON ONE APPLIANCE.

    Per appliance and carrying its scope, for the reasons the certificate objects record: the
    same object pushed from a template exists separately in each firewall's merged config, and
    a profile defined in `shared` and one defined in a vsys can share a name.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="authentication_profile_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="authentication_profile_findings")
    authentication_profile = models.ForeignKey(
        AuthenticationProfile, on_delete=models.CASCADE, related_name="findings")
    subject_scope = models.CharField(max_length=16, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery, through="AuthenticationProfileFindingControlQuery",
        related_name="authentication_profile_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["authentication_profile"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "authentication_profile"],
                name="unique_ap_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on authentication profile {self.subject_name}"


class AuthenticationProfileFindingControlQuery(FindingControlQueryBase):
    authentication_profile_finding = models.ForeignKey(
        AuthenticationProfileFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="authentication_profile_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["authentication_profile_finding", "control_query"],
                name="unique_ap_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.authentication_profile_finding_id} <- {self.control_query_id}"


class AuthenticationSequenceFinding(ObjectFindingBase):
    """A finding against one authentication sequence ON ONE APPLIANCE. PAN-AAA-012.

    Per appliance and carrying its scope, as for authentication profiles: a template-pushed
    sequence exists separately in each firewall's merged config, and a `shared` and a vsys
    definition can share a name.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="authentication_sequence_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="authentication_sequence_findings")
    authentication_sequence = models.ForeignKey(
        AuthenticationSequence, on_delete=models.CASCADE, related_name="findings")
    subject_scope = models.CharField(max_length=16, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery, through="AuthenticationSequenceFindingControlQuery",
        related_name="authentication_sequence_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["authentication_sequence"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "authentication_sequence"],
                name="unique_aseq_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on authentication sequence {self.subject_name}"


class AuthenticationSequenceFindingControlQuery(FindingControlQueryBase):
    authentication_sequence_finding = models.ForeignKey(
        AuthenticationSequenceFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="authentication_sequence_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["authentication_sequence_finding", "control_query"],
                name="unique_aseq_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.authentication_sequence_finding_id} <- {self.control_query_id}"


class ManagementSshFinding(ObjectFindingBase):
    """A finding against one appliance's management SSH server. PAN-MCR-001 and 003.

    One row per appliance, like management TLS: the server is the device's, and a bound profile
    only narrows what it offers.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="management_ssh_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="management_ssh_findings")
    management_ssh_settings = models.ForeignKey(
        ManagementSshSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="ManagementSshFindingControlQuery",
        related_name="management_ssh_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["management_ssh_settings"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "management_ssh_settings"],
                name="unique_mssh_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on management SSH {self.subject_name}"


class ManagementSshFindingControlQuery(FindingControlQueryBase):
    management_ssh_finding = models.ForeignKey(
        ManagementSshFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="management_ssh_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["management_ssh_finding", "control_query"],
                name="unique_mssh_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.management_ssh_finding_id} <- {self.control_query_id}"


class IkeCryptoProfileFinding(ObjectFindingBase):
    """A finding against one named IKE crypto profile. PAN-IKE-002 to 005.

    One row per named entry per appliance. The object is DEVICE-WIDE - stage 4 of the
    `ike-crypto` pipeline domain found exactly one firewall-local scope, neither shared nor
    under a vsys - so `subject_scope` is NOT declared: a profile name is unique per appliance
    and there is no second scope for it to collide across. On an HA pair the same real profile
    yields two rows and so two findings, which nothing deduplicates.

    THE SUBJECT NAME IS NOT EVIDENCE OF STRENGTH. `default` on one lab appliance offers 3DES,
    SHA-1 and Group 2 - measured - but an estate may equally have hardened it in place, so every
    assertion here reads the derived columns and none reads the name.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="ike_crypto_profile_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="ike_crypto_profile_findings")
    ike_crypto_profile = models.ForeignKey(
        IkeCryptoProfile, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="IkeCryptoProfileFindingControlQuery",
        related_name="ike_crypto_profile_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["ike_crypto_profile"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "ike_crypto_profile"],
                name="unique_ikecp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on IKE crypto profile {self.subject_name}"


class IkeCryptoProfileFindingControlQuery(FindingControlQueryBase):
    ike_crypto_profile_finding = models.ForeignKey(
        IkeCryptoProfileFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="ike_crypto_profile_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["ike_crypto_profile_finding", "control_query"],
                name="unique_ikecp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.ike_crypto_profile_finding_id} <- {self.control_query_id}"


class IkeGatewayFinding(ObjectFindingBase):
    """A finding against one named IKE gateway. PAN-IKE-001, 006, 007, 008 and 009.

    One row per named entry per appliance, device-wide like the sibling object, so no
    `subject_scope`.

    EVERY CONTROL ON THIS SUBJECT CARRIES `gateway_is_active` AS APPLICABILITY, so a gateway
    switched off produces no finding at all rather than a passing one. That suppression is
    deliberate - a disabled gateway negotiates nothing - and it is why the absence of a finding
    on a gateway is not a statement that the gateway is sound.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="ike_gateway_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="ike_gateway_findings")
    ike_gateway = models.ForeignKey(
        IkeGateway, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="IkeGatewayFindingControlQuery",
        related_name="ike_gateway_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["ike_gateway"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "ike_gateway"],
                name="unique_ikegw_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on IKE gateway {self.subject_name}"


class IkeGatewayFindingControlQuery(FindingControlQueryBase):
    ike_gateway_finding = models.ForeignKey(
        IkeGatewayFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="ike_gateway_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["ike_gateway_finding", "control_query"],
                name="unique_ikegw_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.ike_gateway_finding_id} <- {self.control_query_id}"


class IpsecCryptoProfileFinding(ObjectFindingBase):
    """A finding against one named IPSec crypto profile. PAN-IPS-001 to 005, and 009's half.

    PHASE 2, NOT PHASE 1. The sibling `IkeCryptoProfileFinding` above is the same shape over a
    different object at an adjacent xpath, and the two are easy to cross-wire: `network/ike/
    crypto-profiles/ipsec-crypto-profiles` is this one, `.../ike-crypto-profiles` is that one.
    What distinguishes them in the data is the stored shape of `dh-group` - a bare string here
    and a `{"member": [...]}` list there, measured both ways - so a reader who reuses the phase-1
    shape at this path reads nothing and reads it silently.

    One row per named entry per appliance. The collection sits under `network`, so it is neither
    vsys nor shared and there is exactly one of it for the whole appliance even on the multi-vsys
    PA-5220 - measured by stage 4 of the `ipsec-crypto` domain. `subject_scope` is therefore NOT
    declared: a profile name is unique per appliance and there is no second scope to collide
    across. ON AN HA PAIR THIS YIELDS TWO FINDINGS FOR ONE REAL PROFILE and nothing deduplicates
    them; stage 5 recorded that the lab's PA-5220 pair was NOT synchronising at the time it was
    read, so the two rows are two measurements rather than a copy.

    THE SUBJECT NAME IS NOT EVIDENCE OF STRENGTH, and this object is where that bites hardest.
    `default`, `Suite-B-GCM-128` and `Suite-B-GCM-256` arrive with the firewall and are ORDINARY
    WRITABLE LOCAL CONFIGURATION rather than predefined objects - `action=get` at
    /config/predefined/ipsec-crypto-profiles answers None on all four lab appliances - so they
    are deletable, renameable and hardenable in place. Every assertion here reads a derived
    column and none reads the name.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="ipsec_crypto_profile_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="ipsec_crypto_profile_findings")
    ipsec_crypto_profile = models.ForeignKey(
        IpsecCryptoProfile, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="IpsecCryptoProfileFindingControlQuery",
        related_name="ipsec_crypto_profile_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["ipsec_crypto_profile"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "ipsec_crypto_profile"],
                name="unique_ipseccp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on IPSec crypto profile {self.subject_name}"


class IpsecCryptoProfileFindingControlQuery(FindingControlQueryBase):
    ipsec_crypto_profile_finding = models.ForeignKey(
        IpsecCryptoProfileFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="ipsec_crypto_profile_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["ipsec_crypto_profile_finding", "control_query"],
                name="unique_ipseccp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.ipsec_crypto_profile_finding_id} <- {self.control_query_id}"


class IpsecTunnelFinding(ObjectFindingBase):
    """A finding against one named IPSec tunnel. PAN-IPS-006, 007 and 008.

    One row per named entry per appliance, device-wide like the crypto profile beside it, so no
    `subject_scope`.

    NO APPLICABILITY CLAUSE SUPPRESSES A DISABLED TUNNEL HERE, which is the opposite of the
    sibling `IkeGatewayFinding` and is deliberate: PAN-IPS-008 asserts ON the disabled state -
    a tunnel left switched off is the finding, not a reason to stay quiet - so the three
    controls over this model all fire on tunnels nothing is routed through.

    AND THE ABSENCE OF A FINDING ON AN APPLIANCE IS NOT A STATEMENT ABOUT ITS TUNNELS. The row
    grain is the entry, so an appliance terminating NO tunnel produces no row, every query over
    it returns nothing, and all three controls read as satisfied. Stage 5 of the `ipsec-crypto`
    domain recorded that as the domain's one wrong-direction limit and named the remedy - a
    per-appliance coverage subject carrying a tunnel count and whether the collection was
    reached - which is a fourth model and not a column of this one.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="ipsec_tunnel_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="ipsec_tunnel_findings")
    ipsec_tunnel = models.ForeignKey(
        IpsecTunnel, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="IpsecTunnelFindingControlQuery",
        related_name="ipsec_tunnel_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["ipsec_tunnel"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "ipsec_tunnel"],
                name="unique_ipsectun_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on IPSec tunnel {self.subject_name}"


class IpsecTunnelFindingControlQuery(FindingControlQueryBase):
    ipsec_tunnel_finding = models.ForeignKey(
        IpsecTunnelFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="ipsec_tunnel_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["ipsec_tunnel_finding", "control_query"],
                name="unique_ipsectun_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.ipsec_tunnel_finding_id} <- {self.control_query_id}"


class IpsecTunnelPathFinding(ObjectFindingBase):
    """A finding against one IPSec tunnel path. PAN-IKE-002 to -005 and PAN-IPS-001 to -005.

    ONE ROW PER TUNNEL-AND-GATEWAY PAIR per appliance, plus one per IKE gateway no tunnel on that
    appliance names. Device-wide like the four collections the path joins, so no `subject_scope`.

    WHY THE NINE STRENGTH CONTROLS LANDED HERE. Keyed on the crypto profile, as they shipped, one
    weak profile earned one finding whether one tunnel ran on it or a thousand did - so the
    finding count said nothing about reach. Jason, 2026-11-04: *"A weak profile use on one IPSec
    tunnel should not receive the same treatment as a weak profile used on 1000 IPSec tunnels. The
    best way to accomplish this is to raise a finding per effected tunnel."* Keyed on the path,
    the number of findings for a control IS the number of tunnels affected, and the blast radius
    is on the findings page without anything having to compute it.

    THE SAME PROFILE THEREFORE EARNS SEVERAL FINDINGS FOR ONE CONTROL, which is the point rather
    than a duplication to collapse: each is a different tunnel, each is a place traffic crosses,
    and the remediation page folds them back to the one profile to edit.

    NO APPLICABILITY CLAUSE SUPPRESSES A DISABLED TUNNEL OR AN INACTIVE GATEWAY. Jason,
    2026-11-04: *"The 'disabled' value is ignored. So give a tunnel/gateway the same treatment
    regardless of the disabled state."* All four of pan-fw-111's tunnels are `disabled=yes`, so a
    suppression would silence the only appliance in this lab with tunnels at all.

    AND THE ABSENCE OF A FINDING ON AN APPLIANCE IS NOT A STATEMENT ABOUT ITS VPN. An appliance
    holding crypto profiles and neither a tunnel nor a gateway produces NO PATH ROW - both
    PA-5220s are in exactly that state - so every query over this model returns nothing and all
    nine controls read as satisfied. That is the same wrong-direction limit the tunnel and profile
    models carry, and the same remedy answers it: a per-appliance coverage subject, which is
    PAN-COV-001's shape and not a column of this one.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="ipsec_tunnel_path_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="ipsec_tunnel_path_findings")
    ipsec_tunnel_path = models.ForeignKey(
        IpsecTunnelPath, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="IpsecTunnelPathFindingControlQuery",
        related_name="ipsec_tunnel_path_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["ipsec_tunnel_path"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "ipsec_tunnel_path"],
                name="unique_ipsecpath_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on IPSec tunnel path {self.subject_name}"


class IpsecTunnelPathFindingControlQuery(FindingControlQueryBase):
    ipsec_tunnel_path_finding = models.ForeignKey(
        IpsecTunnelPathFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="ipsec_tunnel_path_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["ipsec_tunnel_path_finding", "control_query"],
                name="unique_ipsecpath_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.ipsec_tunnel_path_finding_id} <- {self.control_query_id}"


class HighAvailabilityFinding(ObjectFindingBase):
    """A finding against one appliance's high-availability relationship. PAN-HAP-001 to 004.

    ONE ROW PER APPLIANCE and no entry name: `deviceconfig/high-availability` is device-wide, so
    a vsys never appears here. `subject_scope` is not declared - there is one address per
    appliance and nothing to collide with.

    ON AN HA PAIR THIS IS TWO FINDINGS FOR ONE RELATIONSHIP and that is correct here rather than
    a duplication to fix. OptivEdgeIntegrations AGENTS.md says HA state "genuinely differs per
    node and should not be collapsed", and stage 4 of the `ha-panorama` domain measured the
    divergence on this lab's own pair: `group/mode` present on one member and absent on the
    other, four successful commits on one member changing nothing on the other, and
    `running-sync` reading `not synchronized` throughout.

    WHAT NO ROW OF THIS MODEL CAN SAY. Whether the HA1 control link is encrypted is a property of
    the PAIR - a pair with the key imported on one member only reports as two independent
    findings rather than as one broken link - and the operational reply carries no identifier
    that would let the two members' rows be joined. Every finding here is the per-appliance half.

    THE ABSENCE OF A FINDING ON AN APPLIANCE IS NOT A STATEMENT THAT ITS HA IS SOUND.
    PAN-HAP-002, 003 and 004 all carry `ha_enabled` as applicability, so a firewall in no pair
    produces nothing from them at all; and an appliance nobody collected is reported by a
    separate query on `ha_config_collected` rather than by any of the three assertions.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="high_availability_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="high_availability_findings")
    high_availability_config = models.ForeignKey(
        HighAvailabilityConfig, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="HighAvailabilityFindingControlQuery",
        related_name="high_availability_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["high_availability_config"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "high_availability_config"],
                name="unique_hacfg_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on high availability for {self.subject_name}"


class HighAvailabilityFindingControlQuery(FindingControlQueryBase):
    high_availability_finding = models.ForeignKey(
        HighAvailabilityFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="high_availability_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["high_availability_finding", "control_query"],
                name="unique_hacfg_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.high_availability_finding_id} <- {self.control_query_id}"


class PanoramaRegistrationFinding(ObjectFindingBase):
    """A finding against one appliance's channel to its management estate. PAN-HAP-005.

    ONE ROW PER APPLIANCE, device-wide like the HA model beside it, and no `subject_scope`.

    ON AN HA PAIR THIS IS TWO FINDINGS FOR ONE CONFIGURATION AND THE TWO ROWS DO AGREE, which is
    the opposite of the HA model's case: the management addresses and the secure-communication
    switches are not HA fields, and this estate measured the synchronisation directly -
    `panorama-server-2` written on one member was present on both twenty minutes later with
    nothing addressed to the peer. So a pair produces two identical findings for one gap, and
    nothing deduplicates them.

    THE CONTROL CARRIES TWO ASSERTIONS AT TWO SEVERITIES over this one row - the estate's address
    redundancy at medium and the channel's certificate hardening at low - so a row can fire for
    either or both and there is only ever one finding. The queries are written so the two cannot
    both match: the hardening query excludes the redundancy query's population, because
    `derive_control_query_severity_value` takes the WORST matched calibration and a row failing
    both would otherwise be reported at the gentler tier.

    WHAT NO ROW OF THIS MODEL CAN SAY, and no firewall can. The management appliance's own half of
    the handshake - whether it accepts only customer-issued certificates, and whether it checks
    each firewall against an authorisation list - lives on `secure-conn-server` on the station,
    which `rules.md` puts out of assessment scope. A row on the hardened side of every column
    here still does not say the channel is authenticated.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="panorama_registration_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="panorama_registration_findings")
    panorama_registration = models.ForeignKey(
        PanoramaRegistration, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="PanoramaRegistrationFindingControlQuery",
        related_name="panorama_registration_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["panorama_registration"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "panorama_registration"],
                name="unique_panoreg_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on management channel for {self.subject_name}"


class PanoramaRegistrationFindingControlQuery(FindingControlQueryBase):
    panorama_registration_finding = models.ForeignKey(
        PanoramaRegistrationFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="panorama_registration_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["panorama_registration_finding", "control_query"],
                name="unique_panoreg_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.panorama_registration_finding_id} <- {self.control_query_id}"


class ManagementTlsFinding(ObjectFindingBase):
    """A finding against one appliance's management TLS binding. PAN-MGT-010 and PAN-CRT-006.

    One row per appliance, two controls that fail independently: the shipped TLSv1.3_Default
    profile passes the protocol floor and fails the certificate on the same row.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="management_tls_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="management_tls_findings")
    management_tls_binding = models.ForeignKey(
        ManagementTlsBinding, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="ManagementTlsFindingControlQuery",
        related_name="management_tls_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["management_tls_binding"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "management_tls_binding"],
                name="unique_mt_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on management TLS {self.subject_name}"


class ManagementTlsFindingControlQuery(FindingControlQueryBase):
    management_tls_finding = models.ForeignKey(
        ManagementTlsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="management_tls_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["management_tls_finding", "control_query"],
                name="unique_mt_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.management_tls_finding_id} <- {self.control_query_id}"


class MasterKeyFinding(ObjectFindingBase):
    """A finding against one appliance's master key. PAN-CRT-007."""

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="master_key_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="master_key_findings")
    master_key = models.ForeignKey(
        MasterKey, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="MasterKeyFindingControlQuery",
        related_name="master_key_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [models.Index(fields=["master_key"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "master_key"],
                name="unique_mk_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on master key {self.subject_name}"


class MasterKeyFindingControlQuery(FindingControlQueryBase):
    master_key_finding = models.ForeignKey(
        MasterKeyFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="master_key_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["master_key_finding", "control_query"],
                name="unique_mk_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.master_key_finding_id} <- {self.control_query_id}"


class UpdateServerSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's update server settings. PAN-MGT-009."""

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="update_server_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="update_server_settings_findings")
    update_server_settings = models.ForeignKey(
        UpdateServerSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="UpdateServerSettingsFindingControlQuery",
        related_name="update_server_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [models.Index(fields=["update_server_settings"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "update_server_settings"],
                name="unique_uss_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on update server settings {self.subject_name}"


class UpdateServerSettingsFindingControlQuery(FindingControlQueryBase):
    update_server_settings_finding = models.ForeignKey(
        UpdateServerSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="update_server_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["update_server_settings_finding", "control_query"],
                name="unique_uss_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.update_server_settings_finding_id} <- {self.control_query_id}"


class LoggingSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's logging settings. PAN-MGT-011."""

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="logging_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="logging_settings_findings")
    logging_settings = models.ForeignKey(
        LoggingSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="LoggingSettingsFindingControlQuery",
        related_name="logging_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [models.Index(fields=["logging_settings"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "logging_settings"],
                name="unique_ls_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on logging settings {self.subject_name}"


class WildfireSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's device-wide WildFire settings.

    TWO CONTROLS share this model and they ask opposite-polarity questions - PAN-AVW-004
    fires when nothing has been TUNED, PAN-AVW-005 when something has been WITHHELD - so the
    subject sentence is built per control rather than once for the object.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="wildfire_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="wildfire_settings_findings")
    wildfire_settings = models.ForeignKey(
        "integrations.WildfireSettings", on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="WildfireSettingsFindingControlQuery",
        related_name="wildfire_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["wildfire_settings"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "wildfire_settings"],
                name="unique_wfs_finding_per_run_control_object"),
        ]


class WildfireSettingsFindingControlQuery(FindingControlQueryBase):
    wildfire_settings_finding = models.ForeignKey(
        WildfireSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="wildfire_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["wildfire_settings_finding", "control_query"],
                name="unique_wfs_finding_control_query_link"),
        ]


class LoggingSettingsFindingControlQuery(FindingControlQueryBase):
    logging_settings_finding = models.ForeignKey(
        LoggingSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="logging_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["logging_settings_finding", "control_query"],
                name="unique_ls_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.logging_settings_finding_id} <- {self.control_query_id}"


class LoginBannerFinding(ObjectFindingBase):
    """A finding against one appliance's login banner. PAN-MGT-007 and 008."""

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="login_banner_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="login_banner_findings")
    login_banner = models.ForeignKey(
        LoginBanner, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="LoginBannerFindingControlQuery",
        related_name="login_banner_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [models.Index(fields=["login_banner"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "login_banner"],
                name="unique_lb_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on login banner {self.subject_name}"


class LoginBannerFindingControlQuery(FindingControlQueryBase):
    login_banner_finding = models.ForeignKey(
        LoginBannerFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="login_banner_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["login_banner_finding", "control_query"],
                name="unique_lb_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.login_banner_finding_id} <- {self.control_query_id}"


class AuthenticationSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's device-wide authentication settings.

    PAN-AUTH-014 to 017. One row per appliance, so `subject_name` is the appliance - the
    settings have no name of their own.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="authentication_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="authentication_settings_findings")
    authentication_settings = models.ForeignKey(
        AuthenticationSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="AuthenticationSettingsFindingControlQuery",
        related_name="authentication_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["authentication_settings"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "authentication_settings"],
                name="unique_as_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on authentication settings {self.subject_name}"


class AuthenticationSettingsFindingControlQuery(FindingControlQueryBase):
    authentication_settings_finding = models.ForeignKey(
        AuthenticationSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="authentication_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["authentication_settings_finding", "control_query"],
                name="unique_as_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.authentication_settings_finding_id} <- {self.control_query_id}"


class PasswordComplexityFinding(ObjectFindingBase):
    """A finding against one appliance's minimum password complexity. PAN-AUTH-001 to 013.

    The subject is ONE ROW PER APPLIANCE, so `subject_name` is the appliance rather than an
    object name - the policy has no name of its own. It is still an ObjectFinding rather than a
    device-configuration finding because the subject is a row that can be missing: an appliance
    whose snapshot has no `mgt-config` at all gets no policy and therefore no finding, which is
    the correct answer and not "compliant".
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="password_complexity_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="password_complexity_findings")
    password_complexity_policy = models.ForeignKey(
        PasswordComplexityPolicy, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="PasswordComplexityFindingControlQuery",
        related_name="password_complexity_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["password_complexity_policy"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "password_complexity_policy"],
                name="unique_pc_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on password complexity {self.subject_name}"


class PasswordComplexityFindingControlQuery(FindingControlQueryBase):
    password_complexity_finding = models.ForeignKey(
        PasswordComplexityFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="password_complexity_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["password_complexity_finding", "control_query"],
                name="unique_pc_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.password_complexity_finding_id} <- {self.control_query_id}"


class PasswordProfileFinding(ObjectFindingBase):
    """A finding against one password profile ON ONE APPLIANCE.

    No `subject_scope`: password profiles live only at mgt-config/password-profile, which is
    neither shared nor per-vsys, so there is no scope to disambiguate a name with.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="password_profile_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="password_profile_findings")
    password_profile = models.ForeignKey(
        PasswordProfile, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="PasswordProfileFindingControlQuery",
        related_name="password_profile_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["password_profile"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "password_profile"],
                name="unique_pp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on password profile {self.subject_name}"


class PasswordProfileFindingControlQuery(FindingControlQueryBase):
    password_profile_finding = models.ForeignKey(
        PasswordProfileFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="password_profile_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["password_profile_finding", "control_query"],
                name="unique_pp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.password_profile_finding_id} <- {self.control_query_id}"


class SecurityProfileFinding(ObjectFindingBase):
    """A finding against one anti-spyware or vulnerability profile DEFINITION.

    Carries `subject_scope` because names repeat across scopes: every vsys has its own predefined
    `default`, and a vsys can define a profile with the same name as a shared one.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="security_profile_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="security_profile_findings")
    security_profile = models.ForeignKey(
        SecurityProfile, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="SecurityProfileFindingControlQuery",
        related_name="security_profile_findings", blank=True)
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["security_profile"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "security_profile"],
                name="unique_secprof_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on security profile {self.subject_name}"


class SecurityProfileFindingControlQuery(FindingControlQueryBase):
    security_profile_finding = models.ForeignKey(
        SecurityProfileFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="security_profile_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["security_profile_finding", "control_query"],
                name="unique_secprof_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.security_profile_finding_id} <- {self.control_query_id}"


class AdminUserFinding(ObjectFindingBase):
    """A finding against one administrator account ON ONE APPLIANCE.

    No `subject_scope`: `mgt-config/users` is neither shared nor per-vsys, so an account name
    is already unique on an appliance - the same reason PasswordProfileFinding has none.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="admin_user_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="admin_user_findings")
    admin_user = models.ForeignKey(
        AdminUser, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="AdminUserFindingControlQuery",
        related_name="admin_user_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["admin_user"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "admin_user"],
                name="unique_au_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on administrator {self.subject_name}"


class AdminUserFindingControlQuery(FindingControlQueryBase):
    admin_user_finding = models.ForeignKey(
        AdminUserFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="admin_user_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["admin_user_finding", "control_query"],
                name="unique_au_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.admin_user_finding_id} <- {self.control_query_id}"


class ServerProfileFinding(ObjectFindingBase):
    """A finding against one AAA server profile, in the scope that defines it.

    Carries `subject_scope` because a profile name is only unique WITHIN a scope: one appliance
    can hold a shared `corp-ldap` and a vsys3 `corp-ldap`, and they are two objects with two
    configurations. The same reason the certificate objects carry it.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="server_profile_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="server_profile_findings")
    server_profile = models.ForeignKey(
        ServerProfile, on_delete=models.CASCADE, related_name="findings")
    #: "shared", or "vsys:<name>". Wider than the 16 the certificate models use, because a vsys
    #: name is part of the value here rather than a separate column.
    subject_scope = models.CharField(max_length=72, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery, through="ServerProfileFindingControlQuery",
        related_name="server_profile_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["server_profile"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "server_profile"],
                name="unique_sp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on server profile {self.subject_name}"


class ServerProfileFindingControlQuery(FindingControlQueryBase):
    server_profile_finding = models.ForeignKey(
        ServerProfileFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="server_profile_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["server_profile_finding", "control_query"],
                name="unique_sp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.server_profile_finding_id} <- {self.control_query_id}"


class NtpSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's NTP configuration. PAN-SVC-001 and 002.

    One row per appliance: there are two server slots and no third, so the subject is the pair
    rather than either server. A finding naming one server would have nothing to say about
    redundancy, which is what PAN-SVC-001 asserts.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="ntp_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="ntp_settings_findings")
    ntp_settings = models.ForeignKey(
        NtpSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="NtpSettingsFindingControlQuery",
        related_name="ntp_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["ntp_settings"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "ntp_settings"],
                name="unique_ntp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on NTP {self.subject_name}"


class NtpSettingsFindingControlQuery(FindingControlQueryBase):
    ntp_settings_finding = models.ForeignKey(
        NtpSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="ntp_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["ntp_settings_finding", "control_query"],
                name="unique_ntp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.ntp_settings_finding_id} <- {self.control_query_id}"


class SnmpSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's SNMP configuration. PAN-SVC-004 and 005.

    One row per appliance. `snmp-setting` is a single device-wide node - there is no per-surface
    SNMP configuration - and whether any surface EXPOSES it is resolved onto that row, so both
    halves of the answer stay on one finding.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="snmp_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="snmp_settings_findings")
    snmp_settings = models.ForeignKey(
        SnmpSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="SnmpSettingsFindingControlQuery",
        related_name="snmp_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["snmp_settings"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "snmp_settings"],
                name="unique_snmp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on SNMP {self.subject_name}"


class SnmpSettingsFindingControlQuery(FindingControlQueryBase):
    snmp_settings_finding = models.ForeignKey(
        SnmpSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="snmp_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["snmp_settings_finding", "control_query"],
                name="unique_snmp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.snmp_settings_finding_id} <- {self.control_query_id}"


class SystemIdentityFinding(ObjectFindingBase):
    """A finding against one appliance's name, time zone and management addressing.
    PAN-SVC-007 and 009.

    One row per appliance, carrying two controls that can fail independently - and they are on
    one row for the reason the model groups them: a device addressed by DHCP can be NAMED by
    DHCP, so the two findings can have a single cause and belong in front of one reader.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="system_identity_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="system_identity_findings")
    system_identity = models.ForeignKey(
        SystemIdentity, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="SystemIdentityFindingControlQuery",
        related_name="system_identity_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["system_identity"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "system_identity"],
                name="unique_sysid_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on system identity {self.subject_name}"


class SystemIdentityFindingControlQuery(FindingControlQueryBase):
    system_identity_finding = models.ForeignKey(
        SystemIdentityFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="system_identity_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["system_identity_finding", "control_query"],
                name="unique_sysid_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.system_identity_finding_id} <- {self.control_query_id}"


class DnsSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's MANAGEMENT-PLANE resolvers. PAN-SVC-003.

    One row per appliance, device-wide like the NTP and SNMP models beside it, so NO
    `subject_scope`: there is one `dns-setting` node per firewall and the appliance is the
    subject. On an HA pair this yields two findings for one real configuration and nothing
    deduplicates them - `deviceconfig/system` does not synchronise between peers, so the two
    rows can genuinely differ and collapsing them would lose a finding.

    WHAT THE SEVERITY TURNS ON IS NOT IN THIS MODEL. The grading separates "no resolver chosen
    on a LEASED management address" from "no resolver chosen on a FIXED one", and the addressing
    mode is a `SystemIdentity` column - the normalizer resolves it into
    `management_resolver_posture` before this ever sees it, which is why the control can clause
    on one model while the distinction rests on two.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="dns_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="dns_settings_findings")
    dns_settings = models.ForeignKey(
        DnsSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="DnsSettingsFindingControlQuery",
        related_name="dns_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["dns_settings"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "dns_settings"],
                name="unique_dns_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on management resolvers {self.subject_name}"


class DnsSettingsFindingControlQuery(FindingControlQueryBase):
    dns_settings_finding = models.ForeignKey(
        DnsSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="dns_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["dns_settings_finding", "control_query"],
                name="unique_dns_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.dns_settings_finding_id} <- {self.control_query_id}"


class ServiceRouteFinding(ObjectFindingBase):
    """A finding against one enforcement point's management service paths. PAN-SVC-006.

    `subject_scope` IS NOT OPTIONAL HERE and this is the one model of its domain that needs it.
    The subject is an ENFORCEMENT POINT rather than an appliance: the firewall-wide paths are
    one row and every virtual system the firewall names is another, so `subject_name` would be a
    partition name like `vsys3` - which is not unique in an estate and is not unique even on one
    Panorama. The scope carries the appliance, and the firewall-wide row's subject name is the
    appliance itself with the scope saying which half it is.

    THE TWO HALVES ARE ONE CONTROL AND ARE NOT THE SAME QUESTION. The firewall-wide half asks
    whether every service the firewall originates has a source interface and address chosen; the
    per-system half asks whether a virtual system recorded a choice at all. The per-system
    columns hold their FIRING defaults on the device-local row, where the question has no answer
    - which is why every query on that half carries `scope eq vsys`.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="service_route_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="service_route_findings")
    service_route = models.ForeignKey(
        ServiceRoute, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="ServiceRouteFindingControlQuery",
        related_name="service_route_findings", blank=True)
    #: The appliance that owns the enforcement point. See the class docstring.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["service_route"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "service_route"],
                name="unique_service_route_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on service paths {self.subject_name}"


class ServiceRouteFindingControlQuery(FindingControlQueryBase):
    service_route_finding = models.ForeignKey(
        ServiceRouteFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="service_route_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["service_route_finding", "control_query"],
                name="unique_service_route_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.service_route_finding_id} <- {self.control_query_id}"


class GeneratedArtifact(models.Model):
    """A client deliverable built in the background and kept until somebody deletes it.

    The workbook was built on the request until 2026-10-14, and the browser showed nothing for
    however long that took - longer on the VDI an engagement runs on than on the lab. Jason,
    2026-10-14: build it in the background, and retrieve it from a view that lists the files
    available for download. Kept until deleted, never pruned: what leaves the machine is the
    engineer's call.

    The FILE lives under MEDIA_ROOT rather than in a column, for the reason the lab's settings
    give: the database gets snapshotted and copied, and a deliverable stored in it would ride
    along in every copy. Deleting the row deletes the file (`artifact_store`), because Django
    does not, and an orphaned client deliverable is exactly the file nobody remembers is there.
    """

    class Kind(models.TextChoices):
        WORKBOOK = "workbook", "Engineer-detail workbook"
        #: The second deliverable, 2026-11-05. Jason: *"Remediation needs its own artifact,
        #: separate from the existing Findings artifact."* Same findings, folded onto the object
        #: an engineer opens - so a row is a place to go rather than a thing that is wrong.
        REMEDIATION = "remediation", "Remediation workbook"
        #: The third deliverable, 2026-11-05: Optiv's own PAN Health Check document, generated
        #: into a scaffold derived from their .dotx. Jason: *"Go with the scaffold approach."*
        #: A .docx rather than a workbook, which is why `ArtifactDownloadView` now serves a
        #: content type BY KIND instead of sending the one spreadsheet type for everything.
        HEALTH_CHECK = "health_check", "Health check document"

    class Status(models.TextChoices):
        BUILDING = "building", "Building"
        READY = "ready", "Ready"
        FAILED = "failed", "Failed"

    kind = models.CharField(max_length=32, choices=Kind.choices)
    #: Whether a HEALTH_CHECK build was asked for its Control Detail section - one block per
    #: control that raised a finding, which on the lab is 203 blocks and some forty pages.
    #: Jason, 2026-11-06: a parameter on the generator, and a checkbox on the downloads page
    #: ticked by default.
    #:
    #: KEPT ON THE ROW rather than handed to the thread, for two reasons. The build runs on a
    #: thread that is given a pk and reads everything else back, so this is how the choice
    #: reaches it at all; and two documents built on one day share a filename, so without this
    #: nothing on the downloads page would say which of them is the long one. Always False on
    #: the two workbooks, which have no such section.
    control_detail = models.BooleanField(default=False)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.BUILDING)
    #: The findings run the file was built FROM. SET_NULL rather than CASCADE: a reseed
    #: discards runs, and a kept deliverable must not vanish with them - it becomes stale, and
    #: says so, instead.
    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.SET_NULL, null=True, blank=True, related_name="artifacts")
    #: What the browser is told to call it - `artifacts.naming`. The stored name can differ:
    #: storage suffixes a name that is already taken, and two builds on one day share one.
    filename = models.CharField(max_length=255, blank=True)
    file = models.FileField(upload_to="assessments/artifacts/", blank=True)
    size = models.PositiveBigIntegerField(null=True, blank=True)
    requested_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    #: Why a build FAILED, in words - usually the guard that refused it. Empty otherwise.
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-requested_at", "-pk"]

    def __str__(self) -> str:
        return self.filename or f"{self.get_kind_display()} {self.pk}"


class PresentedTable(models.Model):
    """A findings table as the pages and the workbook draw it, kept for the run it describes.

    Every page load and every workbook build rebuilt each table from the findings, their
    subjects and the subjects' members - 136k rows on production, most of a 81s build, and a
    domain page that took as long to open as its tab took to write. What a row says is a
    function of the run, the catalog and the presentation code, and nothing else, because a run
    does not outlive the configuration it was computed from (`lifecycle.py`). So it is kept:

    * **with the run** - CASCADE, so a discarded run takes its tables, and a reseed or a
      normalization needs nothing of its own to invalidate them
    * **under a fingerprint** of the catalog this table reads and the code that lays it out - a
      control edited after the run, or a package upgrade, misses and rebuilds instead of
      showing the old layout

    `artifacts/stored.py` is the only reader and writer.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="presented_tables")
    #: A domain slug, or another table's own name - see `artifacts/stored.py`.
    key = models.CharField(max_length=100)
    fingerprint = models.CharField(max_length=64)
    #: zlib-compressed JSON. The cells repeat heavily - a rule's columns appear once per finding
    #: on it - so this is a tenth of its text.
    payload = models.BinaryField()
    created_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["assessment_run", "key"],
                                    name="assessments_presented_table_unique_per_run"),
        ]

    def __str__(self) -> str:
        return f"{self.key} for run {self.assessment_run_id}"


class InterfaceFinding(ObjectFindingBase):
    """A finding against one interface or subinterface. PAN-NET-001 and PAN-NET-003.

    TWO CONTROLS, ONE SUBJECT, AND THEY ASK UNRELATED QUESTIONS: what an out-of-service port is
    left holding, and what a port announces to whatever is plugged into it. They share this model
    because they share the row, not because they share a reading - `PARTS_BY_CONTROL` in
    `interface_findings.py` is what keeps each finding's sentence to its own control's assertion.

    THE ABSENCE OF A FINDING HERE IS NOT A STATEMENT THAT THE PORT IS IN SERVICE. PAN-NET-001's
    scope - "every interface the customer confirms is not in service" - is deliberately NOT a
    clause, because no column can hold it: a port carrying an address and a zone may be a spare
    built in advance of a project, and a port carrying nothing may be a live uplink waiting on
    the far end. So the control reports every port whose stored configuration and administrative
    state disagree, and the customer's list narrows which of those rows are called findings at
    presentation time. The same is true of PAN-NET-003's "facing an untrusted network".
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="interface_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="interface_findings")
    interface = models.ForeignKey(
        Interface, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="InterfaceFindingControlQuery",
        related_name="interface_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["interface"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "interface"],
                name="unique_iface_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on interface {self.subject_name}"


class InterfaceFindingControlQuery(FindingControlQueryBase):
    interface_finding = models.ForeignKey(
        InterfaceFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="interface_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["interface_finding", "control_query"],
                name="unique_iface_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.interface_finding_id} <- {self.control_query_id}"


class SessionSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's Session settings. PAN-NET-002 and PAN-NET-005.

    One row per appliance, two controls that fail independently and in opposite evidential
    positions - which is the thing worth knowing before reading one of these findings:

    * PAN-NET-002 rests on `session_rematch`, where NOTHING is stored for an absent key. The
      vendor says the capability is on by default and says so twice; no oracle on the appliance
      moves for it, so the value remains a guess. The finding therefore reports "nobody has
      established this" as well as "this is switched off", and says which.
    * PAN-NET-005 rests on `ipv6_firewalling`, where the default IS measured - the device's own
      dataplane reports it on with the key absent, paid in both directions on a committed state.
      So an absent key here is COMPLIANT, and the naive reading of the same absence would have
      raised a finding on every appliance in this estate.

    `subject_name` is the appliance, because the subject has no name of its own.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="session_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="session_settings_findings")
    session_settings = models.ForeignKey(
        PanOsSessionSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="SessionSettingsFindingControlQuery",
        related_name="session_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["session_settings"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "session_settings"],
                name="unique_sess_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on session settings {self.subject_name}"


class SessionSettingsFindingControlQuery(FindingControlQueryBase):
    session_settings_finding = models.ForeignKey(
        SessionSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="session_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["session_settings_finding", "control_query"],
                name="unique_sess_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.session_settings_finding_id} <- {self.control_query_id}"


class LldpGlobalFinding(ObjectFindingBase):
    """A finding against one appliance's device-wide LLDP enable.

    NO CONTROL PRODUCES ONE OF THESE TODAY, and that is recorded rather than accidental.
    PAN-NET-003's second half asserts over this subject and its first half over `Interface`;
    `_CONTROL_TYPE_TARGET_MODEL` is one-to-one and `ControlQuery.clean()` refuses a query whose
    model differs from its control's target, so one catalogue control cannot hold both. The
    per-interface half took the id. Splitting PAN-NET-003 into two catalogue ids changes what a
    customer's report contains and is Jason's decision; this model exists so that the half he
    may decide to build has somewhere to land, and so that nothing silently narrows the report
    when it does.

    WHAT IT WOULD SAY. The node is absent on every appliance measured, and what the absence
    MEANS is unestablished in both directions - globally enabled by default, in which case the
    preferred value is unmet everywhere, or globally disabled, in which case the per-interface
    keys are moot. So the finding this model carries is "the firewall-wide state was never
    established", not "LLDP is on".
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="lldp_global_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="lldp_global_findings")
    lldp_global_settings = models.ForeignKey(
        PanOsLldpGlobalSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="LldpGlobalFindingControlQuery",
        related_name="lldp_global_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["lldp_global_settings"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "lldp_global_settings"],
                name="unique_lldpg_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on global LLDP {self.subject_name}"


class LldpGlobalFindingControlQuery(FindingControlQueryBase):
    lldp_global_finding = models.ForeignKey(
        LldpGlobalFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="lldp_global_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["lldp_global_finding", "control_query"],
                name="unique_lldpg_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.lldp_global_finding_id} <- {self.control_query_id}"


class DhcpInterfaceConfigFinding(ObjectFindingBase):
    """A finding against one interface's DHCP configuration. PAN-NET-004.

    THE SUBJECT IS THE CONFIGURATION THAT SHOULD NOT BE THERE, not the port. A row exists only
    where `network/dhcp/interface` carries an entry, so this control's passing state for its
    server half is the ABSENCE of the row and needs no representation at all - and the finding
    names the DHCP configuration rather than the interface, which is what an engineer deletes.

    TWO HALVES THAT FAIL INDEPENDENTLY, server and relay, which are independent siblings in the
    configuration: the absence of one asserts nothing about the other. One row can violate both,
    and then there is still one finding, reported at the worse of the two severities.

    WHAT NO FINDING HERE PROVES, and it is the one gap in this domain that fails quiet: an
    appliance with no DHCP and a collector that skipped `network/dhcp` both produce no rows, and
    no column on this model can tell them apart, because a reading about whether the container
    was fetched has no row to live on when no row exists.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="dhcp_interface_config_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="dhcp_interface_config_findings")
    dhcp_interface_config = models.ForeignKey(
        PanOsDhcpInterfaceConfig, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="DhcpInterfaceConfigFindingControlQuery",
        related_name="dhcp_interface_config_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["dhcp_interface_config"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "dhcp_interface_config"],
                name="unique_dhcp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on DHCP configuration {self.subject_name}"


class DhcpInterfaceConfigFindingControlQuery(FindingControlQueryBase):
    dhcp_interface_config_finding = models.ForeignKey(
        DhcpInterfaceConfigFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="dhcp_interface_config_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["dhcp_interface_config_finding", "control_query"],
                name="unique_dhcp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.dhcp_interface_config_finding_id} <- {self.control_query_id}"


class TunnelInspectionFinding(ObjectFindingBase):
    """A finding against one enforcement point's tunnel inspection coverage. PAN-NET-006.

    THE SUBJECT IS A VERDICT OVER A RULEBASE AND NOT A RULE, because the commonest failing state
    is that NO RULE EXISTS and a per-rule finding cannot report it. An engineer fixing it does
    not open a rule either; the rule they need does not exist.

    `subject_scope` IS DECLARED HERE AND NOWHERE ELSE IN THIS DOMAIN. A vsys's coverage can come
    from its own rulebase or from a Panorama device group, so the same vsys name legitimately
    carries two rows with two different answers, and a reader has to be able to tell which copy
    a finding is about. The scope says which config subtree the rules came from and NOT who owns
    them.

    WHAT THIS FINDING CANNOT SAY: whether any tunnel actually transits this firewall. That is
    traffic and not configuration, so the verdict fires on a vsys with no policy whether or not
    a tunnel has ever crossed it, and four of the eight ranks cannot be computed from
    configuration at all. The finding says which, rather than reporting a rank nobody measured.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="tunnel_inspection_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="tunnel_inspection_findings")
    tunnel_inspection_coverage = models.ForeignKey(
        PanOsTunnelInspectionCoverage, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="TunnelInspectionFindingControlQuery",
        related_name="tunnel_inspection_findings", blank=True)
    #: Which config subtree the counted rules came from - `vsys` or `device-group`. See the class
    #: docstring; this is the one subject in the domain whose name can collide.
    subject_scope = models.CharField(max_length=32, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["tunnel_inspection_coverage"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "tunnel_inspection_coverage"],
                name="unique_tunnel_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on tunnel inspection {self.subject_name}"


class TunnelInspectionFindingControlQuery(FindingControlQueryBase):
    tunnel_inspection_finding = models.ForeignKey(
        TunnelInspectionFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="tunnel_inspection_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["tunnel_inspection_finding", "control_query"],
                name="unique_tunnel_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.tunnel_inspection_finding_id} <- {self.control_query_id}"


class RoutingAdjacencyFinding(ObjectFindingBase):
    """A finding against one dynamic routing adjacency. PAN-NET-007.

    THE SUBJECT IS THE ADJACENCY AND NOT THE AUTHENTICATION PROFILE. A profile is reusable, so
    reporting it once would understate how many adjacencies are unauthenticated - and the
    adjacency is what an engineer opens to attach authentication or a prefix ceiling.

    THE ROW'S EXISTENCE IS THE APPLICABILITY TEST, so the absence of a finding on an appliance
    means either that every adjacency is sound or that the firewall forms none. Those are
    different facts and this model cannot tell them apart; a firewall routing only on static
    entries produces no row.

    WHAT THE FINDING MAY NOT SAY, from the standing ruling on stored secrets: nothing about the
    key itself. The authentication secret and the OSPF password are encrypted-text and cannot be
    read back from the firewall at all, so whether a key is unique to an adjacency or shared
    across sites is an engineer's question. The finding reports the STRENGTH the attachment
    amounts to, which is computed from which child the profile carries and never from a value.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="routing_adjacency_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="routing_adjacency_findings")
    routing_adjacency = models.ForeignKey(
        PanOsRoutingAdjacency, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="RoutingAdjacencyFindingControlQuery",
        related_name="routing_adjacency_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["routing_adjacency"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "routing_adjacency"],
                name="unique_radj_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on routing adjacency {self.subject_name}"


class RoutingAdjacencyFindingControlQuery(FindingControlQueryBase):
    routing_adjacency_finding = models.ForeignKey(
        RoutingAdjacencyFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="routing_adjacency_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["routing_adjacency_finding", "control_query"],
                name="unique_radj_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.routing_adjacency_finding_id} <- {self.control_query_id}"


class SanctionedApplicationMarkingFinding(ObjectFindingBase):
    """A finding against one enforcement point's approved-application inventory. PAN-SAS-001.

    THE SUBJECT IS A VERDICT AND NOT A NAMED OBJECT, so `subject_name` holds the enforcement
    point rather than an entry key. That is a departure from every other `ObjectFindingBase`
    subclass and it is the right one here: the commonest failing state of this control is that
    NO application-tag entry exists at all, so there is no object to name - and the engineer
    fixing "this partition approves nothing" opens Objects > Applications for that vsys rather
    than any one application.

    `subject_scope` IS DECLARED, because the name is the partition and a partition name is not
    unique across an estate: `vsys1` exists on every single-vsys firewall. The scope carries the
    appliance, which is what makes two rows of the same name tellable apart.

    WHAT THE FINDING CANNOT SAY. A marking pushed from a Panorama device group counts toward the
    count - it is in force here - and the row has no column saying where a marking was authored,
    so "this partition approves nothing" cannot be told from "this partition's whole inventory is
    pushed". The remediation names the firewall's own vsys node, which an engineer cannot edit
    for a pushed marking.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="sanctioned_application_marking_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="sanctioned_application_marking_findings")
    sanctioned_application_marking = models.ForeignKey(
        SanctionedApplicationMarking, on_delete=models.CASCADE, related_name="findings")
    #: The appliance the partition belongs to. See the class docstring.
    subject_scope = models.CharField(max_length=128, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery, through="SanctionedApplicationMarkingFindingControlQuery",
        related_name="sanctioned_application_marking_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["sanctioned_application_marking"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "sanctioned_application_marking"],
                name="unique_sasmark_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on approval marking {self.subject_name}"


class SanctionedApplicationMarkingFindingControlQuery(FindingControlQueryBase):
    sanctioned_application_marking_finding = models.ForeignKey(
        SanctionedApplicationMarkingFinding, on_delete=models.CASCADE,
        related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="sanctioned_application_marking_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["sanctioned_application_marking_finding", "control_query"],
                name="unique_sasmark_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return (f"{self.sanctioned_application_marking_finding_id} "
                f"<- {self.control_query_id}")


class SaasUrlFilteringPostureFinding(ObjectFindingBase):
    """A finding against what one enforcement point's URL Filtering profiles do for SaaS.

    PAN-SAS-002 and PAN-SAS-004, which fail independently on one row: a partition can insert a
    tenant-restriction header on the traffic and still leave the consumer-storage web categories
    in no restricting list at all.

    A VERDICT SUBJECT, named and scoped like the sibling above and for the same reason: no
    url-filtering profile row exists to hang either control on, because
    `normalization/security_profiles.py::PROFILE_KINDS` holds four kinds and this is not one of
    them.

    THE FINDING CANNOT ATTRIBUTE THE SCOPE OF WHAT IT READ, and on this estate that matters:
    every url-filtering profile actually present on the lab appliances is Panorama-pushed, and a
    pushed profile is in the firewall's own container under no configuration read. So a finding
    that this partition enforces no tenant restriction may be remediated by telling an engineer
    to add header insertion to a profile the firewall will refuse to edit.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="saas_url_filtering_posture_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="saas_url_filtering_posture_findings")
    saas_url_filtering_posture = models.ForeignKey(
        SaasUrlFilteringPosture, on_delete=models.CASCADE, related_name="findings")
    subject_scope = models.CharField(max_length=128, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery, through="SaasUrlFilteringPostureFindingControlQuery",
        related_name="saas_url_filtering_posture_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["saas_url_filtering_posture"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "saas_url_filtering_posture"],
                name="unique_sasurl_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on SaaS URL filtering posture {self.subject_name}"


class SaasUrlFilteringPostureFindingControlQuery(FindingControlQueryBase):
    saas_url_filtering_posture_finding = models.ForeignKey(
        SaasUrlFilteringPostureFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="saas_url_filtering_posture_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["saas_url_filtering_posture_finding", "control_query"],
                name="unique_sasurl_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.saas_url_filtering_posture_finding_id} <- {self.control_query_id}"


class SaasApplicationPolicyPostureFinding(ObjectFindingBase):
    """A finding against what one enforcement point's application policy does about SaaS.

    PAN-SAS-003. A VERDICT SUBJECT, named and scoped like its siblings.

    ONE HALF OF PAN-SAS-004 ALSO ASSERTS ON THIS SUBJECT AND CANNOT REACH IT. That control's
    `control_type` resolves to the URL-filtering posture, `Control.save()` derives one
    `target_model` from the type, and `ControlQuery.clean()` refuses a query on another model -
    so the attribute-driven half of PAN-SAS-004 produces no finding anywhere. Splitting that
    control into two catalogue ids is a product decision; the stage 8 artifact for
    `saas-security` records it under `subjects_in_two_models`.

    A DISABLED RULE COUNTS toward every verdict this model carries, which the normalizer that
    writes them records as probably wrong: a disabled deny rule reports a refusal no session will
    ever meet. The direction of that error is the unsafe one and it is stated rather than hidden.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="saas_application_policy_posture_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="saas_application_policy_posture_findings")
    saas_application_policy_posture = models.ForeignKey(
        SaasApplicationPolicyPosture, on_delete=models.CASCADE, related_name="findings")
    subject_scope = models.CharField(max_length=128, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery, through="SaasApplicationPolicyPostureFindingControlQuery",
        related_name="saas_application_policy_posture_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["saas_application_policy_posture"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "saas_application_policy_posture"],
                name="unique_sasapp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return (f"{self.control.control_id} on SaaS application policy posture "
                f"{self.subject_name}")


class SaasApplicationPolicyPostureFindingControlQuery(FindingControlQueryBase):
    saas_application_policy_posture_finding = models.ForeignKey(
        SaasApplicationPolicyPostureFinding, on_delete=models.CASCADE,
        related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="saas_application_policy_posture_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["saas_application_policy_posture_finding", "control_query"],
                name="unique_sasapp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return (f"{self.saas_application_policy_posture_finding_id} "
                f"<- {self.control_query_id}")


class CloudAppEngineFinding(ObjectFindingBase):
    """A finding against one appliance's App-ID Cloud Engine. PAN-SAS-005.

    ONE ROW PER APPLIANCE, because the node is a device-wide singleton - so unlike the three
    verdict models above, the owner is the appliance and `subject_name` is its hostname. On an HA
    pair the setting is synchronised and this produces two findings for one configuration, which
    nothing deduplicates. No `subject_scope`: a hostname is the scope.

    THE FINDING RESTS ON AN OPERATIONAL READ AND NOT ON THE CONFIGURATION, which is the whole
    point of this subject. The configured `disable` key is absent on every lab appliance, so a
    control reading it alone passes all four - while the engine itself reports a failed licence
    check, a failed cloud connection and a missing device certificate on every one of them.

    AND THE CONTROL IS SILENT WHERE THE LICENCE IS THE REASON, by design: an appliance with no
    subscription was never what this half of PAN-SAS-005 was about, and its other half - whether
    the adoption decision is on the record - is an engineer's answer rather than a configuration
    read, so no query exists for it. The absence of a finding here is therefore not a statement
    that the engine is healthy.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="cloud_app_engine_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="cloud_app_engine_findings")
    cloud_app_engine_setting = models.ForeignKey(
        CloudAppEngineSetting, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="CloudAppEngineFindingControlQuery",
        related_name="cloud_app_engine_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["cloud_app_engine_setting"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "cloud_app_engine_setting"],
                name="unique_sasace_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on App-ID Cloud Engine {self.subject_name}"


class CloudAppEngineFindingControlQuery(FindingControlQueryBase):
    cloud_app_engine_finding = models.ForeignKey(
        CloudAppEngineFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="cloud_app_engine_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["cloud_app_engine_finding", "control_query"],
                name="unique_sasace_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.cloud_app_engine_finding_id} <- {self.control_query_id}"


class DeviceIdentificationFinding(ObjectFindingBase):
    """A finding against one appliance's device-identification service state. PAN-IOT-001, -003.

    THREE UNRELATED INSTRUMENTS LAND ON ONE ROW and two controls assert over it: the licence
    table (is the entitlement in force), the edge-service configuration node (is the firewall
    wired to the service at all) and `show system info`'s classification-data keys (is the
    installed data current). They share a row because all three are device-wide, which is the
    merge `integrations.DeviceIdentificationState` argues in its own docstring.

    `subject_name` IS THE HOSTNAME, because the row is a conclusion about the appliance and has
    no entry name of its own - the licence table's entries have no identity a finding would
    print, and the edge node is a singleton container.

    WHAT NO FINDING HERE PROVES. Two of the three readings are operational replies that carry
    no provenance decoration of any kind, and the companion booleans
    (`licence_read_taken`, `device_dictionary_release_date_known`) are the only things that
    separate "we asked and it was fine" from "nobody asked". Both controls carry a query that
    fires on those companions at false, so the unread state reports rather than passing - but an
    appliance with NO ROW AT ALL is absent rather than unknown, and no column of that model can
    say so.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="device_identification_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="device_identification_findings")
    device_identification_state = models.ForeignKey(
        DeviceIdentificationState, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="DeviceIdentificationFindingControlQuery",
        related_name="device_identification_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["device_identification_state"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "device_identification_state"],
                name="unique_devid_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on device identification {self.subject_name}"


class DeviceIdentificationFindingControlQuery(FindingControlQueryBase):
    device_identification_finding = models.ForeignKey(
        DeviceIdentificationFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="device_identification_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["device_identification_finding", "control_query"],
                name="unique_devid_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.device_identification_finding_id} <- {self.control_query_id}"


class ZoneFinding(ObjectFindingBase):
    """A finding against one security zone. PAN-IOT-002.

    THE FIRST CONTROL EVER WRITTEN OVER A ZONE, which is why this model arrives years after
    `integrations.Zone` did. The zone already stored `enable_device_identification` and both
    Device-ID ACLs; nothing had ever queried them.

    `subject_scope` IS REQUIRED HERE. A zone name is unique only per enforcement point
    (`integrations_unique_zone_per_enforcement_point`), so the same name legitimately exists in
    several vsys and a finding that printed the name alone would not say which zone it found.

    THE REMEDIATION THIS FINDING IMPLIES MAY BE ONE THE FIREWALL REFUSES, and it is the normal
    case rather than the edge one. `Zone` carries no scope, `config_source` or provenance column,
    so a zone pushed from a Panorama template is indistinguishable in the row from a
    firewall-local one - 48 of the 50 zones measured in the lab are unidentified, and a finding
    on a pushed zone names a local zone and tells an engineer to tick a box this firewall will
    not accept. Stage 6 for `device-id-iot` grades that case as a verdict of its own
    (`iot6-16-zone-pushed-unidentified`) precisely so that somebody can ask about it.

    WHAT THE NARROWING HALF CANNOT SAY. A populated Device-ID ACL is the firing state, and what
    the finding reports is that identification in the zone is NARROWED - never that the list
    fails to cover the equipment. A member may be a literal address, a CIDR, an address object
    or an address GROUP, and nothing on the firewall says what is plugged in, so coverage is a
    reviewer's judgement and the finding names the members for them to check.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="zone_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="zone_findings")
    zone = models.ForeignKey(Zone, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="ZoneFindingControlQuery",
        related_name="zone_findings", blank=True)
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["zone"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "zone"],
                name="unique_zone_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on zone {self.subject_name}"


class ZoneFindingControlQuery(FindingControlQueryBase):
    zone_finding = models.ForeignKey(
        ZoneFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="zone_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["zone_finding", "control_query"],
                name="unique_zone_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.zone_finding_id} <- {self.control_query_id}"


class RulebaseDeviceMatchFinding(ObjectFindingBase):
    """A finding against one enforcement point's rule set, about the device dimension. PAN-IOT-004.

    THE SUBJECT IS THE ENFORCEMENT POINT AND NOT THE RULE, deliberately. "No rule names what a
    device IS" cannot be said of a particular rule, and 182 of the 188 rules measured in the lab
    carry neither device element - so keying the finding on the rule would multiply one failure
    across the whole rulebase instead of locating it.

    `subject_name` IS THE VSYS NAME, with the appliance in `subject_scope`: the row has no entry
    name, and a rule's own name would be the wrong thing to print on a verdict about all of them.

    WHAT THIS FINDING CANNOT TELL A READER, and both are remediation problems rather than
    detection ones:

    * WHICH RULEBASE THE ABSENCE SPANS. The verdict is computed over the point's whole rule set -
      the firewall-local vsys rulebase, the Panorama pre- and post-rulebases pushed to it, and
      the vendor's two predefined defaults - and carries no scope column, so an estate whose
      policy is pushed from Panorama is told to edit a vsys rulebase the firewall will not accept
      rules into. The distinction IS stored, on `SecurityRule.config_source`.
    * A DEVICE OBJECT FROM A GLOBALPROTECT HIP PROFILE. One `source-hip` member list holds device
      objects, HIP profiles and the bare keywords any/no-hip/quarantine all as plain strings, and
      the only discriminator is resolving the member against the device-object namespace. No HIP
      profile exists anywhere in the lab, so the gap is inert here and wrong on the first estate
      that uses host posture.

    AND THE COMPANION THIS SUBJECT DOES NOT HAVE. Every other uncertain reading in this domain
    carries a "was this read" flag; the verdict - the most expensive reading of the four - has
    none, so a verdict taken over six rules of 109 is indistinguishable in the row from one taken
    over all 109. Stage 7 recorded that gap and the only existing signal beside it:
    `integrations.NormalizationIssue` rows are written per enforcement point by the rule pass, so
    a finding here should be read beside them. Nothing in the row says so.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="rulebase_device_match_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="rulebase_device_match_findings")
    rulebase_device_match_verdict = models.ForeignKey(
        RulebaseDeviceMatchVerdict, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="RulebaseDeviceMatchFindingControlQuery",
        related_name="rulebase_device_match_findings", blank=True)
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["rulebase_device_match_verdict"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "rulebase_device_match_verdict"],
                name="unique_rbdm_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on rulebase device match {self.subject_name}"


class RulebaseDeviceMatchFindingControlQuery(FindingControlQueryBase):
    rulebase_device_match_finding = models.ForeignKey(
        RulebaseDeviceMatchFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="rulebase_device_match_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["rulebase_device_match_finding", "control_query"],
                name="unique_rbdm_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.rulebase_device_match_finding_id} <- {self.control_query_id}"


class DataFilteringPostureFinding(ObjectFindingBase):
    """A finding against one enforcement point's outward data-filtering posture. PAN-FIL-003.

    THE SUBJECT IS THE ENFORCEMENT POINT AND NOT THE PROFILE, and that is the whole reason this
    model exists. The commonest failing state of this domain is NO DATA-FILTERING PROFILE AT ALL -
    three of the four lab appliances, and `/config/predefined/profiles/data-filtering` is absent on
    every one of them, so unlike file blocking there is nothing shipped to fall back on. A
    profile-keyed finding reports nothing on exactly the devices that fail, which is the silence
    this row replaces.

    `subject_name` IS THE VSYS NAME, with the appliance in `subject_scope`: the row has no entry
    name, and one profile's name would be the wrong thing to print on a verdict about whether any
    of them is in force.

    WHAT A PASS HERE DOES NOT MEAN, and a later stage must not render it as "sensitive data cannot
    leave". The vendor's own disclaimer on this screen says the file-type selection "does not block
    all possible file types, just the listed ones", and that list was measured at THIRTEEN members
    on both lab platforms - office documents, PDFs and HTML. A zip, a CSV export, a plain text
    file, a database dump or an image passes this mechanism unexamined. The verdict column's own
    note in stage 5 carries the whole of it.

    AND IT DOES NOT MEAN THE ORGANISATION HAS NO DATA-LOSS PROTECTION. Stage 3 deliberately
    declined to make the licensing question an applicability clause, "because the suppressing form
    would convert an unanswered licensing question into silence": an Enterprise DLP subscription
    supersedes pattern-based data filtering where licensed, and the control's own evidence source
    for that is another system. The finding says this firewall's own pattern matching is not in
    force, and no more.

    THE HALF OF PAN-FIL-003 THAT IS SILENT HERE. Its second record - every rule of a watching
    profile carries both the alert and the block count - clauses on `integrations.SecurityProfile`,
    a different model, so no query on this control can carry it. Standing ruling 6 would reach it
    by a relation; `SecurityProfile.enforcement_point` is nullable because a shared-scope profile
    hangs off the appliance group instead, so that walk misses three of that half's five measured
    subjects, and a row at this grain cannot name which profile failed anyway. What would close it
    is a column on THIS model carrying that quantifier at this grain, which stage 8 may not add.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="data_filtering_posture_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="data_filtering_posture_findings")
    data_filtering_posture = models.ForeignKey(
        DataFilteringPosture, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="DataFilteringPostureFindingControlQuery",
        related_name="data_filtering_posture_findings", blank=True)
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["data_filtering_posture"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "data_filtering_posture"],
                name="unique_dfp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on data filtering posture {self.subject_name}"


class DataFilteringPostureFindingControlQuery(FindingControlQueryBase):
    data_filtering_posture_finding = models.ForeignKey(
        DataFilteringPostureFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="data_filtering_posture_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["data_filtering_posture_finding", "control_query"],
                name="unique_dfp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.data_filtering_posture_finding_id} <- {self.control_query_id}"

class GlobalProtectPortalFinding(ObjectFindingBase):
    """A finding against one GlobalProtect portal entry of one vsys. PAN-GPP-001, -003, -004, -005.

    THE PORTAL IS AN INTERNET-FACING TLS ENDPOINT AND AN AGENT-CONFIGURATION SERVER AT ONCE, which
    is why four controls land on one row. Two of them read `portal-config` - the transport binding
    and the browser login page - and two read the FIRST agent configuration an endpoint would match,
    because the portal delivers the first match and stops.

    `subject_name` IS THE PORTAL NAME AND `subject_scope` CARRIES THE VSYS AND THE APPLIANCE. The
    name is unique DEVICE-WIDE rather than per vsys - measured at the write, a second vsys was
    refused the same name with code=12 "already in use" - but a reader still needs the vsys,
    because what the portal enforces belongs to that enforcement point.

    WHAT NO FINDING HERE CAN SAY, and both are in stage 5's `not_stored`:

    * WHETHER THE TLS FLOOR THE PORTAL NEGOTIATES IS ACCEPTABLE. PAN-GPP-001's clause is on the
      BINDING and nothing else. The bound value is a NAME, and on a template-managed appliance the
      profile it names is not in the same payload at all - measured, the estate's one adopted
      portal binds `oep-tpl-tls`, which answers `No such node` in both committed views. What that
      profile permits is PAN-CRT-005's subject.
    * WHETHER THE CERTIFICATE THE PORTAL PRESENTS IS TRUSTED. That is PAN-GPP-001's SECOND half,
      which stage 5 discharged `engineer_answers`: no column exists for it, it owes no query, and
      a reader of a clean PAN-GPP-001 finding must not read it as "the chain is trusted".

    AND ONE THING A PASS ON PAN-GPP-003 DOES NOT MEAN. Stage 3 asserts both that the portal drives
    endpoints to a current version AND that the versions actually connecting are within one major
    release of current. The second half has no column anywhere: the only read that could answer it
    returns None with status=success and carries no counter, no row count and no timestamp, so "no
    agent has ever connected" and "this is never populated here" are the same reply.

    THE PART OF PAN-GPP-003 THAT IS SILENT HERE. Its second record - access conditioned on the app
    version the endpoint reports - clauses on `integrations.GlobalProtectEnforcementPoint`, a
    different model, so no query on this control can carry it. There is no Django relation between
    the two in either direction; the stage 8 artifact records it in `subjects_in_two_models`.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="globalprotect_portal_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="globalprotect_portal_findings")
    globalprotect_portal = models.ForeignKey(
        GlobalProtectPortal, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="GlobalProtectPortalFindingControlQuery",
        related_name="globalprotect_portal_findings", blank=True)
    #: Declared because a name is not unique across the estate: the portal name's namespace is
    #: ONE APPLIANCE - measured at the write, a second vsys was refused the same name with code=12
    #: "already in use" - so two appliances and an HA pair all collide on it, and what the portal
    #: enforces belongs to a particular vsys of a particular appliance.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["globalprotect_portal"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "globalprotect_portal"],
                name="unique_gpp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on GlobalProtect portal {self.subject_name}"


class GlobalProtectPortalFindingControlQuery(FindingControlQueryBase):
    globalprotect_portal_finding = models.ForeignKey(
        GlobalProtectPortalFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="globalprotect_portal_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["globalprotect_portal_finding", "control_query"],
                name="unique_gpp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.globalprotect_portal_finding_id} <- {self.control_query_id}"


class GlobalProtectPortalClientAuthFinding(ObjectFindingBase):
    """A finding against one row of one portal's client-authentication table. PAN-GPP-002.

    THE ROW IS THE SUBJECT AND THE PORTAL IS NOT, and that is this model's whole reason for
    existing rather than a roll-up onto `GlobalProtectPortalFinding`. The table is KEYED BY THE
    ENDPOINT CLASS it serves - `Any`, `Browser`, `Satellite`, or one of eleven per-platform names -
    so one portal can demand both factors of one class and neither of another. Measured on this
    estate: two rows of ONE portal on pan-fw-111 sit at `high` and at `no_finding`, which is the
    shape a parent-grain finding reports as one verdict and an engineer cannot act on.

    `subject_name` IS THE ROW'S OWN NAME, which is OPERATOR-CHOSEN and carries no meaning - four
    portals of one vsys each carry a row called `r1`. It is here because it is what tells two rows
    of one portal apart and what an engineer opens; `os` is what a reader goes by and the finding's
    sentence names it. `subject_scope` carries the appliance, the vsys and the portal name,
    because the row name alone is not unique within a vsys.

    THE PORTAL'S FACT IS CARRIED ONTO THE ROW AND THE WALK IS UPWARD. Whether a client certificate
    can be demanded of anybody is a leaf on the PARENT - `portal-config/certificate-profile` - and
    the and/or switch beside it says nothing without it. `certificate_profile_bound` is that fact,
    written onto the row at normalisation; the row's `portal` FK is the to-ONE upward relation
    standing ruling 6 permits, and it is why one severity separates two rows whose own switch
    values are identical.

    WHAT NO FINDING HERE CAN SAY. Whether the first factor is a PROFILE or a SEQUENCE - two
    different objects, both shipped downstream - and stage 5's `not_stored` says the column cannot
    tell them apart. A sequence is tried member by member until one succeeds, so a portal bound to
    one whose last member is the firewall's own local user database accepts a locally held password
    whenever the identity service is unreachable. That is stage 3's fallback-path assertion, and it
    is unexpressed rather than satisfied.

    AND IT CANNOT SAY WHETHER THE IDENTITY SERVICE ENFORCES A SECOND FACTOR. The firewall records
    WHICH service it asks and never what that service demands, which is why stage 3's `acceptable`
    minimum is not a value of any column and stage 5 placed no rank for it.

    THE WEAKEST ADMISSION STATE THE DEVICE PERMITS PRODUCES NO ROW OF THIS MODEL AT ALL: a portal
    with an empty authentication table demands nothing, and there is no row to report it on.
    `GlobalProtectPortal.client_auth_row_count` is the only column anywhere that can see it, and no
    query of this control can reach a column on another model.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="globalprotect_portal_client_auth_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="globalprotect_portal_client_auth_findings")
    globalprotect_portal_client_auth_row = models.ForeignKey(
        GlobalProtectPortalClientAuthRow, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="GlobalProtectPortalClientAuthFindingControlQuery",
        related_name="globalprotect_portal_client_auth_findings", blank=True)
    #: Declared because the ROW name is the least unique name in this domain: it is
    #: operator-chosen and carries no meaning, and four portals of one vsys were measured each
    #: carrying a row called `r1`. The scope holds the appliance, the vsys and the PORTAL name,
    #: without which a reader cannot find the row the finding is about.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["globalprotect_portal_client_auth_row"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "globalprotect_portal_client_auth_row"],
                name="unique_gppca_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return (f"{self.control.control_id} on GlobalProtect portal authentication row "
                f"{self.subject_name}")


class GlobalProtectPortalClientAuthFindingControlQuery(FindingControlQueryBase):
    globalprotect_portal_client_auth_finding = models.ForeignKey(
        GlobalProtectPortalClientAuthFinding, on_delete=models.CASCADE,
        related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="globalprotect_portal_client_auth_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["globalprotect_portal_client_auth_finding", "control_query"],
                name="unique_gppca_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return (f"{self.globalprotect_portal_client_auth_finding_id} "
                f"<- {self.control_query_id}")


class GlobalProtectEnforcementPointFinding(ObjectFindingBase):
    """A finding against one vsys's GlobalProtect objects taken as a whole. PAN-GPP-006.

    THE VSYS IS THE ROW AND NOT THE PORTAL, because what this control asserts is an ABSENCE and
    nothing that does not exist can carry a row. PAN-GPP-006 asserts that no portal publishes
    internal web applications for browser access AND that neither the portal nor the firewall holds
    the application definitions or application groups such publishing would draw on - which is a
    statement about the virtual system, not about any one portal.

    THE RANK THIS GRAIN EXISTS FOR IS `latent`: a vsys holding a clientless application definition
    that NO portal publishes. Measured on vsys6 of this estate - one definition, no portal, no
    interface imported - so nothing is reachable today and what is present is a configuration one
    edit from being live. There is no portal row for it to be reported on, so a portal-grain
    control is silent on it by construction, and that silence is the reason this model is here.

    NODE PRESENCE IS THE WRONG TEST AND AN ENTRY COUNT IS THE RIGHT ONE. Deleting the last entry
    leaves the container present and empty; deleting the container leaves `global-protect` present
    and empty; one appliance in this estate carries exactly that, committed and undecorated, and
    `action=get` answers a count of one for it. A truthiness test on the container reports a portal
    where there is none.

    `subject_name` IS THE VSYS NAME, with the appliance in `subject_scope`: the row has no entry
    name at all, and one portal's name would be the wrong thing to print on a verdict about whether
    any of them publishes anything.

    THE HALF OF PAN-GPP-006 THAT IS SILENT HERE, and a reader of this finding must not take it for
    the whole control. Its second record - where a portal DOES publish, the browser sessions
    carrying those applications may not negotiate weaker transport than the portal itself requires
    - clauses on `integrations.GlobalProtectPortal`. That is a different model, and standing ruling
    6's relation remedy has nothing to walk: there is no Django relation between these two models in
    EITHER direction, introspected rather than assumed. They share only `appliance`, and
    `appliance__globalprotectportals__*` - the default reverse accessor, there being no
    `related_name` - is to-MANY and crosses vsys boundaries, so it would fire one virtual system's
    row for a portal in another. The stage 8 artifact records the half as
    silent in `subjects_in_two_models`; what would close it is either a column on THIS model
    carrying the floor at this grain, which stage 8 may not add, or a second control id.

    AND A PASS HERE IS NOT A STATEMENT ABOUT WHETHER THE FEATURE IS SUPPORTED. The vendor says it
    is unsupported on a multi-vsys firewall IF the traffic must traverse several virtual systems -
    a statement about where traffic GOES, which no configuration node holds - so that precondition
    is stage 3's `engineer_supplies` question and deliberately not a clause.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="globalprotect_enforcement_point_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="globalprotect_enforcement_point_findings")
    globalprotect_enforcement_point = models.ForeignKey(
        GlobalProtectEnforcementPoint, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="GlobalProtectEnforcementPointFindingControlQuery",
        related_name="globalprotect_enforcement_point_findings", blank=True)
    #: Declared because `subject_name` here is the VSYS NAME, and `vsys1` exists on every
    #: single-vsys platform in the estate - so without the appliance the name identifies nothing.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["globalprotect_enforcement_point"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "globalprotect_enforcement_point"],
                name="unique_gppep_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return (f"{self.control.control_id} on GlobalProtect enforcement point "
                f"{self.subject_name}")


class GlobalProtectEnforcementPointFindingControlQuery(FindingControlQueryBase):
    globalprotect_enforcement_point_finding = models.ForeignKey(
        GlobalProtectEnforcementPointFinding, on_delete=models.CASCADE,
        related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="globalprotect_enforcement_point_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["globalprotect_enforcement_point_finding", "control_query"],
                name="unique_gppep_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return (f"{self.globalprotect_enforcement_point_finding_id} "
                f"<- {self.control_query_id}")


class FirewallContentStreamsFinding(ObjectFindingBase):
    """A finding against one appliance's content streams, taken as a set. PAN-PLT-002.

    ONE ROW PER APPLIANCE CARRYING EVERY STREAM AS A COLUMN, which is stage 5's own
    `identity.one_row_per` and not a convenience: a stream-keyed row would have nothing to report
    on exactly the streams that are absent, and `stream_never_installed` is the commonest state in
    this estate - WildFire reads the never-installed sentinel on three of four lab appliances and
    antivirus on three of four. `content_currency_state` is a verdict over the SET.

    IT IS THE AGE OF WHAT IS INSTALLED AND NOT THE DISTANCE FROM THE NEWEST RELEASE. Whether a
    version is current needs the publication date of the newest AVAILABLE release, which the
    appliance does not hold and no collector fetches; stage 5 records that in `not_stored`. So this
    reports the appliance's own reported release date against the windows stage 3 named, and the
    half that needs the vendor's catalogue is absent rather than guessed.

    TWO SPELLINGS OF "NEVER INSTALLED" AND BOTH ARE TRUTHY. The four content streams answer `0`
    and the URL filtering stream answers `0000.00.00.000`, so a truthiness test reports an
    uninstalled stream as installed and a numeric comparison ranks `0` as the lowest version
    rather than as no version. Only a comparison against the literals is right, and the
    normaliser's `NEVER_INSTALLED_VERSIONS` is where it lives.

    WHAT NO FINDING HERE CAN SAY, and both are stage 3 halves stage 5 could not place:

    * WHETHER A DEVIATION ALERT IS WIRED TO ANYBODY WHO WOULD ACT ON IT. Stage 3's acceptable rank
      requires it and no column of any subject can hold it, so a clean row means the device-readable
      half of acceptable and says nothing about the alerting half.
    * WHETHER THE ESTATE IS INTERNALLY CONSISTENT. PAN-UPD-006 owns the RELATIVE comparison - no
      device more than one release behind - and this control owns the ABSOLUTE age per device. The
      two fail in opposite directions and nothing in this row reaches across appliances.

    AND THE ENTITLEMENT GATE IS DELIBERATELY ABSENT RATHER THAN LOST. Stage 3 scopes each stream to
    "where the organisation has ever held the entitlement that delivers it", which is a fact about
    `integrations.LicenceInventory` - another model, so no query of this control can carry it. The
    absence errs in the safe direction and stage 5 says why: A LAPSED ENTITLEMENT DOES NOT SUPPRESS
    THE STREAM AND IS NOT AN EXEMPTION, because the vendor keeps part of it flowing at a slower
    cadence after expiry. A stream behind its window on an unlicensed appliance is a finding here.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="firewall_content_streams_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="firewall_content_streams_findings")
    firewall_content_streams = models.ForeignKey(
        FirewallContentStreams, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="FirewallContentStreamsFindingControlQuery",
        related_name="firewall_content_streams_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["firewall_content_streams"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "firewall_content_streams"],
                name="unique_fcs_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on content streams {self.subject_name}"


class FirewallContentStreamsFindingControlQuery(FindingControlQueryBase):
    firewall_content_streams_finding = models.ForeignKey(
        FirewallContentStreamsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="firewall_content_streams_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["firewall_content_streams_finding", "control_query"],
                name="unique_fcs_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.firewall_content_streams_finding_id} <- {self.control_query_id}"


class LicenceInventoryFinding(ObjectFindingBase):
    """A finding against one appliance's entitlement set. PAN-PLT-004, BOTH of its halves.

    THE ROW IS A CONCLUSION ABOUT THE LICENCE TABLE AND NOT ONE LICENCE, which is what lets one
    control report an entitlement that is MISSING. `integrations.LicenceEntitlement` holds the
    per-licence rows and carries no control: an absent subscription has no row of its own to be
    reported on, and the commonest failing state in this estate is exactly that.

    BOTH OF THIS CONTROL'S ASSERTION RECORDS LAND ON THIS MODEL, so the control has no silent half
    and the stage 8 artifact declares none. Record 0 grades the subscription set through
    `entitlement_state`; record 1 grades the SUPPORT entitlement through `support_entitlement_state`,
    and they are separate columns because the two lapse independently and carry different
    consequences - a lapsed protection subscription stops a content stream, a lapsed support
    entitlement stops software updates and the vendor's help with an incident.

    ONE BASELINE QUERY, AND RECORD 1 IS CARRIED BY ITS CALIBRATIONS. A control has exactly one
    baseline - `derive_control_query_severity_value` falls back to the control's default only where
    no calibration matched - so the second record's assertion is expressed as the four `eq` queries
    that partition its column's failing set, each carrying that record's own assertion clause. The
    union is the record, because the column holds exactly one of five tokens and four of them fail.

    THE EMPTY LICENCE ELEMENT IS THE TRAP THIS MODEL EXISTS TO REPORT HONESTLY. `request license
    info` answers `{"licenses": null}` on both PA-5220s in this estate: the element is PRESENT and
    EMPTY, `bool(result)` is true while `bool(result["licenses"])` is false, and
    `result["licenses"]["entry"]` raises. That is NOT "no licences are needed" - it is UNKNOWN, and
    `no_licence_rows_returned` reports it as what it is. A customer told their entitlements are fine
    on the strength of a null element has been told they are safe on the strength of nothing.

    HOW A SUPPORT ENTITLEMENT IS RECOGNISED, AND WHICH WAY THE ERROR RUNS. The normaliser matches a
    word-boundary `support` in the feature name, which is the same test stage 6 made independently.
    A name containing `support` that is not a support entitlement would be read as one and move an
    appliance off `absent_from_inventory` and onto a pass - the UNSAFE direction - and it is
    recorded here rather than hidden because no appliance in this estate holds a support row, so
    neither reading is exercised today.

    WHAT NO FINDING HERE CAN SAY. Whether the organisation ever HELD an entitlement it no longer
    holds: the reply lists what is present, so a subscription cancelled last year is
    indistinguishable from one never bought. And an unreadable expiry date lands on
    `active_inside_90_days`, a finding at the lowest graded band, because the vendor's own `expired`
    flag is read first and what an unreadable date leaves open is only HOW SOON a live entitlement
    lapses - which is said without asserting a thirty-day claim the device did not support.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="licence_inventory_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="licence_inventory_findings")
    licence_inventory = models.ForeignKey(
        LicenceInventory, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="LicenceInventoryFindingControlQuery",
        related_name="licence_inventory_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["licence_inventory"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "licence_inventory"],
                name="unique_licinv_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on licence inventory {self.subject_name}"


class LicenceInventoryFindingControlQuery(FindingControlQueryBase):
    licence_inventory_finding = models.ForeignKey(
        LicenceInventoryFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="licence_inventory_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["licence_inventory_finding", "control_query"],
                name="unique_licinv_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.licence_inventory_finding_id} <- {self.control_query_id}"


class LogAlarmSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's log-database alarm mechanism. PAN-PLT-006's first half.

    THE SUBJECT IS THE SINGLETON NODE under `deviceconfig/setting/management/
    common-criteria-alarm-generation` - no entry name, no vsys axis, one row per appliance - so
    `subject_name` is the appliance and this model declares no `subject_scope`.

    THE ORDERING IS STAGE 3's AND NO SET OF CLAUSES EXPRESSES IT, which is why the control grades
    one derived column rather than clausing the leaves. "On but with no threshold recorded" is
    WORSE than "on with thresholds and no notification route", and a conjunction of the three
    leaves says nothing about which is worse. `alarm_mechanism_state` resolves the node into one
    ordered verdict and the control asserts a negated equality against its one passing token.

    AN ABSENT NODE AND AN EMPTIED CONTAINER ARE DIFFERENT VERDICTS, measured. Deleting the leaves
    alone leaves a container that reads as PRESENT, which is `generation_off` and not `node_absent`
    - so a truthiness test on the container reports an alarm mechanism where there is none, and
    stage 6's own teardown note says to delete the whole node for exactly this reason.

    THE NODE IS ABSENT ON EVERY APPLIANCE THIS ESTATE SHIPPED WITH, which is why `node_absent` is
    placed at the control's own severity rather than lower: an appliance with no alarm node raises
    no alarm when a log database fills, and the oldest records are then discarded silently.

    A SEVERITY DIRECTION THIS ROW CANNOT SETTLE, recorded because it is a live hazard and not a
    doubt. A log-type threshold of `0` is STORABLE - written, validated and committed on one lab
    appliance, and read back as `0` from the running view - and what it MEANS is unmeasured. "Alarm
    always" and "alarm never" are both readings, nothing on the device says which, and a comparison
    ranking lower-is-stricter would be exactly inverted at the one value an unconfigured-looking
    appliance would hold. This control grades the COUNT of thresholds recorded and never their
    magnitude, so it is unaffected; a later control that ranks the magnitude must measure it first.

    AND WHAT A CLEAN ROW DOES NOT MEAN. `alarm_generation_enabled_known` is the column that says
    whether the master switch was in the node at all, and it is a separate fact from the node
    answering: the first version of the normaliser read them as one and stored "known" beside a
    null on both PA-5220s, which is the exact circularity a companion column exists to prevent.

    THE OTHER HALF OF PAN-PLT-006 IS NOT A SILENT HALF AND THE DISTINCTION MATTERS. Its second
    assertion record - sustained dataplane load - is discharged `engineer_answers` by stage 5 and
    owes NO query, because there is no configuration node anywhere on the firewall holding a
    dataplane CPU or session-utilisation threshold, so "sustained" has no stored definition and the
    vendor's own monitoring procedure puts the comparison on the SNMP manager. That is a measurable
    expression nobody can write, not a model this control could not reach.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="log_alarm_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="log_alarm_settings_findings")
    log_alarm_settings = models.ForeignKey(
        LogAlarmSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="LogAlarmSettingsFindingControlQuery",
        related_name="log_alarm_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["log_alarm_settings"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "log_alarm_settings"],
                name="unique_logalarm_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on log database alarms {self.subject_name}"


class LogAlarmSettingsFindingControlQuery(FindingControlQueryBase):
    log_alarm_settings_finding = models.ForeignKey(
        LogAlarmSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="log_alarm_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["log_alarm_settings_finding", "control_query"],
                name="unique_logalarm_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.log_alarm_settings_finding_id} <- {self.control_query_id}"


class ContentUpdateScheduleFinding(ObjectFindingBase):
    """A finding against one appliance's dynamic content update schedule. PAN-UPD-001 to -005.

    ONE ROW PER APPLIANCE CARRYING ALL FIVE CONTENT TYPES, which is stage 5's
    `identity.one_row_per` and is why FOUR controls share this finding model rather than one
    each. A content-type-keyed row could not report the commonest failing state measured in this
    estate - a content type with NO `update-schedule` branch at all, which has nothing to key a
    row on - and that state is what eight of this domain's twenty lab subjects hold.

    THE FOUR CONTROLS ARE FOUR CONTENT TYPES AND THEY ARE NOT INTERCHANGEABLE, because each
    content type's cadence grammar is its own. `hourly` is the CEILING for antivirus, so
    PAN-UPD-001's preferred posture is already the fastest the grammar offers; Applications and
    Threats alone offers `every-30-mins`; WildFire's six members are disjoint from every other
    content type's and include `real-time`, which is streaming and the only value PAN-UPD-004
    accepts. A clause moved from one content type to another would compare against a value its
    column cannot hold.

    THE EMPTY STRING IS A STATE OF EVERY RECURRENCE AND ACTION COLUMN AND IT FIRES, which is the
    one thing a reader of a clause here must not get wrong. An appliance whose
    `deviceconfig/system` node arrived empty was not usefully read, and the normaliser writes
    `""` to all ten columns rather than `none` - because `none` would say "we read it and nothing
    is scheduled" about a reply nobody received. `""` is not `daily`, so every negated equality
    in this domain catches it with no companion clause; `update_schedule_collected` is what tells
    a reader the row is unread rather than unscheduled. The model's own `clean()` enforces the
    coupling: a token on any of the ten columns with `update_schedule_collected` false is
    refused.

    `none` AND `""` ARE DIFFERENT ANSWERS AND BOTH FIRE. `none` is an absence that WAS read - no
    branch element, or an explicit `<none/>` - and means the appliance retrieves nothing for that
    content type. `""` is an absence nobody read. They carry different remediations and the
    generator's sentence says which.

    WHAT NO FINDING HERE CAN SAY, and each is a stage 5 limit rather than caution added here:

    * WHETHER THE VALUE IS OWNED BY A TEMPLATE. The merged configuration carries a pushed
      template's value, so the column is right about what the firewall runs - but the store holds
      no row for the template's own copy. So a remediation may send an engineer to the firewall's
      local node when the value is owned by a template they must edit on Panorama instead. Stage
      4 measured the sharp half: a value already set locally SURVIVES a push of a different
      value, so a template holding the right schedule is not evidence the firewall runs it.
    * WHETHER THE SCHEDULE HAS EVER RUN. The node is a schedule and not an outcome. PAN-PLT-002
      owns the runtime symptom - whether installed content is actually recent - and stage 3
      settled the division in writing: that control owns the symptom read off the device, this
      domain owns the configured cause. Both will report on a firewall with no schedule and stale
      content, and that visible duplicate is the direction the contract prefers.
    * WHAT A TIMED BRANCH WITH NO `action` KEY ACTUALLY DOES WHEN IT FIRES. It is stored as
      `none` and read as "retrieves nothing", which is the safe direction and is measured only as
      far as the configuration goes: no schedule was allowed to fire in the lab.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="content_update_schedule_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="content_update_schedule_findings")
    content_update_schedule = models.ForeignKey(
        ContentUpdateSchedule, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="ContentUpdateScheduleFindingControlQuery",
        related_name="content_update_schedule_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["content_update_schedule"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "content_update_schedule"],
                name="unique_cus_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on content update schedule {self.subject_name}"


class ContentUpdateScheduleFindingControlQuery(FindingControlQueryBase):
    content_update_schedule_finding = models.ForeignKey(
        ContentUpdateScheduleFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="content_update_schedule_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["content_update_schedule_finding", "control_query"],
                name="unique_cus_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.content_update_schedule_finding_id} <- {self.control_query_id}"


class CustomUrlCategoryFinding(ObjectFindingBase):
    """A finding against one custom URL category definition, at the scope it is defined at.
    PAN-URL-006.

    ONE CONTROL, ONE RECORD, AND TWO RECORDS OF THAT CONTROL DELIBERATELY SILENT. PAN-URL-006
    spans two stage 5 subjects - the custom category and the URL filtering profile - and a
    control id targets ONE model. `probe.relation_between SecurityProfile CustomUrlCategory`
    reports NO RELATION IN EITHER DIRECTION: the only paths run through shared ancestors
    (`management_station`, `appliance_group`, `source_snapshot`, `enforcement_point`), every one
    to-many and every one leaving a scope field unconstrained, so a join would attach a finding
    to a WRONG ROW rather than merely understate a severity. The category half ships here and the
    two profile records are silent, recorded in the stage 8 artifact's `subjects_in_two_models`.

    WHY THIS HALF AND NOT THE PROFILE, since the control's own name puts profiles first. Stage 3
    settles it: the record's `severity_grading` is graded "from the stored type of a custom web
    category", and its `unplaced` sentence says an unreferenced PROFILE "takes the baseline; it is
    not a value of this grading because the grading reads a category's stored type and a profile
    carries no such field". The control's only severity above its own `low` baseline is therefore
    reachable on this model alone - a `Category Match` category at `medium` - so silencing this
    half would leave PAN-URL-006 unable to report anything but its baseline, while silencing the
    profile half costs only placements that already sit AT the baseline or that stage 7 measured
    unreachable.

    WHAT NO FINDING HERE CAN SAY, from stage 5's `not_stored`, and the first is the one that
    matters most:

    * THE UNDER-REPORTING HAZARD IS NOT AT THE ROW LEVEL AND NO COLUMN CAN CARRY IT. Absence is
      this object's PASSING answer - no category, nothing to clean up - and the firewall's own
      `custom-url-category` containers were ABSENT on all four lab appliances while 22 categories
      were in force through the pushed view. So a collector that omits `pushed-shared-policy`
      reports ZERO ROWS and this control reports a clean estate. "This collection was not
      collected" is not a value a row can hold.
    * WHETHER THE CATEGORY IS REFERENCED BY A RULEBASE NOBODY READ. The vendor documents four
      rulebases that can match on a URL category - Security, QoS, Decryption and Authentication -
      and the normalizer collects two. Stage 2's uncapped referrer enumeration found 39 referrer
      fields where a capped ask gives 8. Every error is therefore in the direction of calling a
      LIVE category unreferenced, which is why the control's deliverable is a list of candidates
      for review and NEVER a removal instruction, and why `reference_surfaces_searched` is
      presented beside every finding so that `unreferenced` is never printed without its
      denominator.
    * WHETHER THE CATEGORY'S SITES STILL BELONG TO WHOEVER ASKED FOR IT. Nothing in the
      configuration records a reason or an owner, which is stage 3's `engineer_supplies`.

    `subject_scope` IS DECLARED because a category name is not unique in an estate. The same name
    exists at one vsys, at the firewall's own shared scope, in a Panorama device group and in the
    pushed view, the remediation differs by scope, and on all four lab appliances the live
    categories were in the management station's shared container rather than the firewall's own.
    Without it, two findings about two scopes are one row to any presentation grouping by name.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="custom_url_category_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="custom_url_category_findings")
    custom_url_category = models.ForeignKey(
        CustomUrlCategory, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="CustomUrlCategoryFindingControlQuery",
        related_name="custom_url_category_findings", blank=True)
    #: Declared for the reason the class docstring gives: one name exists at four scopes and the
    #: remediation differs by scope.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["custom_url_category"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "custom_url_category"],
                name="unique_cuc_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on custom URL category {self.subject_name}"


class CustomUrlCategoryFindingControlQuery(FindingControlQueryBase):
    custom_url_category_finding = models.ForeignKey(
        CustomUrlCategoryFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="custom_url_category_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["custom_url_category_finding", "control_query"],
                name="unique_cuc_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.custom_url_category_finding_id} <- {self.control_query_id}"


class UserIdCollectorFinding(ObjectFindingBase):
    """A finding against one vsys's PAN-OS integrated User-ID agent settings. PAN-UID-003/-004/-006.

    ONE ROW PER VSYS, AND THE NODE EXISTS NOWHERE IN THE ESTATE IT WAS MEASURED AGAINST. Stage 4
    for `user-id` measured `vsys/entry/user-id-collector/setting` absent on all four appliances
    and all twenty vsys, so every assertion over this subject is today an assertion about an
    IMPLICIT value rather than a stored one. That is not a defect in the control: the vendor's
    implicits are what an unconfigured agent does, and three of this domain's six controls assert
    over exactly that. It does mean a row's absence and a row's compliance are different states,
    and only the second is a pass.

    `subject_scope` IS REQUIRED HERE, for the reason `ObjectFindingBase` gives and the
    `saas-security` run measured: the subject is an ENFORCEMENT POINT rather than a named entry,
    so there is no entry key to put in `subject_name` and the partition name goes there instead.
    `vsys1` is then the subject name on every single-vsys firewall in the estate, and without the
    appliance in `subject_scope` two findings about two appliances are one row to any presentation
    that groups by subject name.

    THREE CONTROLS SHARE THIS MODEL AND THEY ASSERT OVER FOUR DIFFERENT COLUMNS, so the summary
    dispatches on the control id rather than running one clause chain. A per-control dispatch
    whose DEFAULT is some other control's arms is the defect `zone_findings` carries and this
    module's `_subject` refuses to repeat: an unknown control id contributes NO claim here.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="user_id_collector_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="user_id_collector_findings")
    user_id_collector = models.ForeignKey(
        UserIdCollectorSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="UserIdCollectorFindingControlQuery",
        related_name="user_id_collector_findings", blank=True)
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["user_id_collector"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "user_id_collector"],
                name="unique_uid_collector_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on User-ID collector {self.subject_name}"


class UserIdCollectorFindingControlQuery(FindingControlQueryBase):
    user_id_collector_finding = models.ForeignKey(
        UserIdCollectorFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="user_id_collector_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["user_id_collector_finding", "control_query"],
                name="unique_uid_collector_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.user_id_collector_finding_id} <- {self.control_query_id}"


class UserIdDiscoveryBoundFinding(ObjectFindingBase):
    """A finding against one vsys's User-ID discovery include/exclude list. PAN-UID-002.

    THE SUBJECT IS A VERDICT OVER THE WHOLE LIST, NOT A LIST ENTRY, and the commonest failing
    state is that the list holds NOTHING. A finding keyed on an entry would have no row to report
    on in exactly the case the control exists for: help p.981 says a collector with no in-force
    entry performs discovery in ALL subnetworks, so every address reachable through a monitored
    server is eligible to become a named user in policy. `list_shape` carries that conclusion as
    one of four values and the row exists per enforcement point whether any entry does or not.

    `subject_scope` IS REQUIRED HERE for the same reason as the collector model above: the
    subject is an enforcement point, so `subject_name` carries the partition name and the
    appliance has nowhere else to go.

    THE ASSERTION OVER THIS SUBJECT IS INVERTED, which is worth knowing when reading a row.
    Stage 5 states it as `list_shape equals include_present` with
    `sign: finding_when_clauses_fail`, so the finding fires on the NEGATION - every shape that is
    not an in-force include list, the empty string among them. The empty string is what the
    column holds when nobody looked, and a negated equality reaches it without help, so an
    uncollected row FIRES here rather than passing. That is the direction `rules.md` requires and
    it is the opposite of what an unknown normally does in SQL.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="user_id_discovery_bound_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="user_id_discovery_bound_findings")
    user_id_discovery_bound = models.ForeignKey(
        UserIdDiscoveryBound, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="UserIdDiscoveryBoundFindingControlQuery",
        related_name="user_id_discovery_bound_findings", blank=True)
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["user_id_discovery_bound"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "user_id_discovery_bound"],
                name="unique_uid_discovery_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on User-ID discovery bound {self.subject_name}"


class UserIdDiscoveryBoundFindingControlQuery(FindingControlQueryBase):
    user_id_discovery_bound_finding = models.ForeignKey(
        UserIdDiscoveryBoundFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="user_id_discovery_bound_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["user_id_discovery_bound_finding", "control_query"],
                name="unique_uid_discovery_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.user_id_discovery_bound_finding_id} <- {self.control_query_id}"


class DecryptionSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's forward-proxy signing designation. PAN-DCP-006.

    THE SUBJECT IS THE APPLIANCE AND NOT THE DESIGNATION SLOT, and the commonest failing state
    decides it: NO certificate designated at all. `/config/shared/ssl-decrypt` was absent on
    three of the lab's four appliances, and the firewall says so in its own words - `show system
    setting ssl-decrypt certificate` answers `No SSL Decryption CERT`. A finding keyed on a slot
    would have NO ROW in exactly the state the control exists for. The row this reports on
    always exists and can say that nothing is designated.

    `subject_scope` IS NOT DECLARED HERE, and that is a decision rather than an omission.
    `ObjectFindingBase` adds it only on the models whose objects can collide on name across
    scopes, and this subject is the appliance itself: `subject_name` carries the hostname, which
    is unique in an estate, so there is nothing for a scope field to disambiguate. Compare
    `UserIdDiscoveryBoundFinding` above, whose `subject_name` is a vsys name - `vsys1` on every
    single-vsys firewall - and which therefore needs one.

    ON AN HA PAIR THIS YIELDS TWO ROWS FOR ONE REAL CONFIGURATION. The designation is
    device-wide, so the integrations model takes an appliance directly rather than an appliance
    group, and writing to either peer writes to both; nothing deduplicates them. That is the
    OPPOSITE of the decryption profile six of this domain's controls report on, where a
    shared-scoped definition anchors to the appliance GROUP and an HA pair is one row.

    BOTH OF THIS CONTROL'S ASSERTIONS ARE VERDICTS THAT FOLLOW A REFERENCE, which is why they
    are columns on the integrations row rather than clauses over it: one walks the designated
    name into `Certificate` to ask whether the target is a locally-held authority, and the other
    compares four columns of the row to each other. A predicate compares one field to one
    literal and can do neither.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="decryption_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="decryption_settings_findings")
    decryption_settings = models.ForeignKey(
        DecryptionSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="DecryptionSettingsFindingControlQuery",
        related_name="decryption_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["decryption_settings"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "decryption_settings"],
                name="unique_decryption_settings_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on decryption settings {self.subject_name}"


class DecryptionSettingsFindingControlQuery(FindingControlQueryBase):
    decryption_settings_finding = models.ForeignKey(
        DecryptionSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="decryption_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["decryption_settings_finding", "control_query"],
                name="unique_decryption_settings_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.decryption_settings_finding_id} <- {self.control_query_id}"


class GlobalProtectGatewayFinding(ObjectFindingBase):
    """A finding against one GlobalProtect gateway entry of one vsys. PAN-GPG-001, -006, -007.

    NO ROW OF THIS SUBJECT EXISTS ANYWHERE IN THE MEASURED ESTATE, and that is recorded here
    rather than only in the pipeline artifact, because a reader of this class would otherwise
    take the three controls above for exercised ones. Stage 6 spent ELEVEN LEASE WINDOWS trying
    to commit a gateway on the one candidate-clean appliance in the lab and met a new commit
    requirement each time - the tunnel interface in a virtual router, `local-address` needing
    `ip/ipv4`, the vsys half needing `remote-user-tunnel`, a unique local address refused at the
    write. It declared the restatements it could not grade instead of inventing them. So every
    column these controls clause on rests on a normaliser proved against constructed shapes, and
    nothing here has been seen to fire.

    ONE DIALOG, TWO SUBTREES. Network > GlobalProtect > Gateways writes a vsys-scoped entry AND a
    device-local entry of the SAME NAME under `network/tunnel`, and the second carries the
    transport - which is why PAN-GPG-006's three records divide the way they do. The integrations
    row merges both halves and reports an unjoined one as `networking_half_present` false, so a
    finding here can be about a gateway whose transport nobody read.

    `subject_name` IS THE GATEWAY'S OWN ENTRY NAME and `subject_scope` carries the appliance and
    the vsys, because a gateway name is operator-chosen and nothing makes it unique across the
    twelve virtual systems of this estate. Without the scope two findings about two appliances
    are one row to any presentation that groups by subject name - which is the defect
    `ManagementInterfaceFinding` still carries and which this model does not repeat.

    THE HALF OF PAN-GPG-005 THAT WOULD HAVE LIVED HERE DOES NOT. Its third record asserts that a
    gateway refuses a login from a quarantined device and that something puts devices on that
    list automatically - two columns of THIS model - but PAN-GPG-005's target is
    `integrations.GlobalProtectEnforcementPoint`, chosen because that is the only record of the
    whole domain with a stage 6 verdict to be graded against. There is NO RELATION between the
    two models in either direction, introspected and not assumed, so ruling 6's remedy has
    nothing to walk and no query of that control can reach `block_quarantined_devices` at any
    clause. `block_quarantined_devices` and `automatic_quarantine_path_exists` are registered in
    the search layer anyway, so that the day a control owns them it has a surface; nothing
    queries them today.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="globalprotect_gateway_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="globalprotect_gateway_findings")
    globalprotect_gateway = models.ForeignKey(
        GlobalProtectGateway, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="GlobalProtectGatewayFindingControlQuery",
        related_name="globalprotect_gateway_findings", blank=True)
    #: The appliance and the vsys. A gateway's entry name is operator-chosen and this estate's
    #: four appliances carry twelve virtual systems between them, so the name alone cannot
    #: identify the row a reader has to open.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["globalprotect_gateway"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "globalprotect_gateway"],
                name="unique_gpgw_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on GlobalProtect gateway {self.subject_name}"


class GlobalProtectGatewayFindingControlQuery(FindingControlQueryBase):
    globalprotect_gateway_finding = models.ForeignKey(
        GlobalProtectGatewayFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="globalprotect_gateway_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["globalprotect_gateway_finding", "control_query"],
                name="unique_gpgw_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.globalprotect_gateway_finding_id} <- {self.control_query_id}"


class GlobalProtectGatewayClientAuthFinding(ObjectFindingBase):
    """A finding against one row of one gateway's client-authentication table. PAN-GPG-002.

    NOT THE PORTAL'S CLIENT-AUTH TABLE. `client-auth` is a leaf name both GlobalProtect objects
    carry under different parents, and `GlobalProtectPortalClientAuthFinding` above is the other
    one. The two subjects are not interchangeable and neither are their normalisers.

    THE ROW IS THE SUBJECT AND THE GATEWAY IS NOT, because the commonest real defect on this
    control is PER PLATFORM: a Windows row pointed at a strong identity service and an `Any` row
    pointed at the firewall's own local database. A gateway-grain verdict reports one weak
    gateway without saying which platform to repoint, and shows the compliant row beside the
    failing one as though they agreed.

    `subject_name` IS THE ROW'S OWN ENTRY NAME, which is free text and not the operating system;
    `client_os` is what a reader goes by and the finding's sentence names it. `subject_scope`
    carries the appliance, the vsys and the GATEWAY name, without which a reader cannot find the
    row - the entry name is not unique within a vsys.

    PAN-GPG-002's SECOND HALF IS REACHED BY A NULLABLE UPWARD WALK, and this is the model where
    that is visible. The gateway-wide question - is a client certificate a genuine second factor
    at all - is a column of `integrations.GlobalProtectGateway`, and the row's own `gateway`
    foreign key is the to-ONE UPWARD relation standing ruling 6 permits. It is `null=True`, so a
    row whose gateway did not resolve is unreachable by that query and that half is silent FOR
    THOSE ROWS - not for the population. The search layer registers the walked column as
    `gateway_client_certificate_is_a_second_factor` for exactly this.

    AND A FINDING HERE CANNOT SAY WHETHER THE IDENTITY SERVICE ENFORCES A SECOND FACTOR. The
    firewall records WHICH service it asks and never what that service demands, so stage 3's
    acceptable minimum is not a value of any column. `authentication_backend_method` names the
    object an engineer repoints and cannot say whether the name is a profile or a SEQUENCE, whose
    last member may be the firewall's own local database.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="globalprotect_gateway_client_auth_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="globalprotect_gateway_client_auth_findings")
    globalprotect_gateway_client_auth_row = models.ForeignKey(
        GlobalProtectGatewayClientAuth, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="GlobalProtectGatewayClientAuthFindingControlQuery",
        related_name="globalprotect_gateway_client_auth_findings", blank=True)
    #: The appliance, the vsys and the GATEWAY name. The row's own entry name is free text and
    #: not unique within a vsys, so the scope is what tells two rows of two gateways apart.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["globalprotect_gateway_client_auth_row"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control",
                        "globalprotect_gateway_client_auth_row"],
                name="unique_gpgca_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return (f"{self.control.control_id} on GlobalProtect gateway authentication row "
                f"{self.subject_name}")


class GlobalProtectGatewayClientAuthFindingControlQuery(FindingControlQueryBase):
    globalprotect_gateway_client_auth_finding = models.ForeignKey(
        GlobalProtectGatewayClientAuthFinding, on_delete=models.CASCADE,
        related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="globalprotect_gateway_client_auth_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["globalprotect_gateway_client_auth_finding", "control_query"],
                name="unique_gpgca_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return (f"{self.globalprotect_gateway_client_auth_finding_id} "
                f"<- {self.control_query_id}")


class GlobalProtectGatewayAgentConfigFinding(ObjectFindingBase):
    """A finding against one agent client-settings row of one gateway. PAN-GPG-003, -004.

    THE ROW AN ENGINEER OPENS, which is the whole reason for this grain: every remediation on
    this ground - shortening a reconnection cookie, naming the certificate that encrypts it,
    removing a split-tunnel exclusion - is an edit to one of these rows, and a gateway-wide
    verdict would name none of them.

    ABSENCE HERE IS THE SAFE DIRECTION and that is why no finding exists for it. A gateway with
    no settings row at all accepts no cookie and excludes nothing from its tunnel, so there is
    nothing to report and no row to report it on.

    TWO COLUMNS SUPPRESS ON THEIR OWN DEFAULT AND NEITHER BRANCH HAS A DEVICE INSTANCE.
    `accept_cookie_configured` gates PAN-GPG-003's cookie-lifetime assertion and
    `authentication_override_configured` gates its certificate assertion; both are
    `default=False`, both are applicability clauses, and an applicability clause that is false
    drops the row out of the control silently. Stage 7 measured that no gateway exists in this
    estate and therefore no instance of either branch does either, so the suppression is
    untested in both directions. It is the sharpest single reason both controls over this model
    ship unexercised.

    THE SPLIT-TUNNEL INVENTORY IS SIX JSON COLUMNS AND NO FINDING READS THEM. A JSONField may not
    be registered in the search layer - `test_findings_rest_on_columns` compiles every registered
    field and walks the query tree for one - so PAN-GPG-004 asserts over
    `uninspected_egress_path_count`, the integer aggregate beside them, and the finding's own
    sentence prints that count. `egress_inventory_computed` is what tells a count of zero that
    nobody computed from a tunnel with genuinely nothing excluded, and the two are different
    facts with different remediations.

    `subject_name` IS THE ROW'S OWN NAME and `subject_scope` carries the appliance, the vsys and
    the gateway, for the same reason as the client-authentication row beside it.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="globalprotect_gateway_agent_config_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="globalprotect_gateway_agent_config_findings")
    globalprotect_gateway_agent_config = models.ForeignKey(
        GlobalProtectGatewayAgentConfig, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="GlobalProtectGatewayAgentConfigFindingControlQuery",
        related_name="globalprotect_gateway_agent_config_findings", blank=True)
    #: The appliance, the vsys and the gateway name, for the same reason as the
    #: client-authentication row: the settings row's own name is operator-chosen.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["globalprotect_gateway_agent_config"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "globalprotect_gateway_agent_config"],
                name="unique_gpgac_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return (f"{self.control.control_id} on GlobalProtect gateway agent configuration "
                f"{self.subject_name}")


class GlobalProtectGatewayAgentConfigFindingControlQuery(FindingControlQueryBase):
    globalprotect_gateway_agent_config_finding = models.ForeignKey(
        GlobalProtectGatewayAgentConfigFinding, on_delete=models.CASCADE,
        related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="globalprotect_gateway_agent_config_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["globalprotect_gateway_agent_config_finding", "control_query"],
                name="unique_gpgac_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return (f"{self.globalprotect_gateway_agent_config_finding_id} "
                f"<- {self.control_query_id}")


class ZoneProtectionProfileFinding(ObjectFindingBase):
    """A finding against one zone protection profile. PAN-ZON-002, -003, -004, -005, -006.

    FIVE CONTROLS ON ONE SUBJECT, each asserting on a disjoint column of the same row: the SYN
    flood enable, the four volumetric flood enables rolled into one verdict, reconnaissance
    detection and its exemption list, the spoofed-address drop, and the non-SYN refusal with the
    four packet drops. One profile can legitimately carry five findings.

    THE SUBJECT IS OWNED BY AN APPLIANCE AND NOT BY AN ENFORCEMENT POINT, which is unusual on this
    page and is measured rather than assumed. `network/profiles/zone-protection-profile` has
    exactly ONE scope on a firewall: `action=complete` answers code=6 Invalid sequence at both the
    shared and the vsys spellings of the collection, so there is no per-vsys or shared copy and no
    second namespace a name could collide in. `subject_scope` therefore carries the appliance
    alone, and the shipped uniqueness constraint on the integrations row is `(appliance,
    profile_name)` - which is what makes that enough rather than a guess.

    WHAT THIS SUBJECT CANNOT SAY, AND IT BEARS ON EVERY ONE OF THE FIVE CONTROLS. The profile
    holds NO RECORD OF WHICH ZONE IT IS ATTACHED TO, let alone of which zone TYPE - and the vendor
    disables three of its mechanisms on an external zone (help p.663). So three of the columns
    these controls assert on can read true on a profile that enforces none of them where it is
    actually in force, one profile may be on an internal zone and an internet-facing one at once,
    and no column of any subject in this estate can say so. Two of the five controls are scoped by
    the vendor to a zone class for exactly that reason - PAN-ZON-005 to internal zones and
    PAN-ZON-006's exception to tunnel-inspection zones - and neither scope could become a clause.
    Both fire on every profile in force instead, which is the fail-safe direction, and both
    findings owe the sentence that the population was not established. The generator carries it.

    PAN-ZON-008's FIRST HALF WOULD HAVE LIVED HERE AND DOES NOT. Its assertion that no zone names
    the profile is over THIS model - `is_unreferenced` and `attachment_sweep_complete` are columns
    of it - but PAN-ZON-008's target is `integrations.SecurityProfile`, because a control has
    exactly one `target_model` and `ControlQuery.clean()` refuses a query on any other. The DoS
    profile half was built because stage 6 exercises it with four expectation rows against this
    half's two, including the only rows that test the kind clause and the shared scope. So this
    model carries no PAN-ZON-008 finding, the two columns are registered in the search layer
    anyway so that the day a control owns them it has a surface, and the silence is recorded in
    that control's `subjects_in_two_models`.

    A PROFILE ON A SHARED GATEWAY HAS NO ROW HERE AT ALL. Stage 5 records it under
    `not_representable`: such a zone is in PAN-ZON-001's population on the device and has nowhere
    to be stored, so it is neither reported nor excluded - it is invisible. That is also what
    `attachment_sweep_complete` is about from the other end.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="zone_protection_profile_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="zone_protection_profile_findings")
    zone_protection_profile = models.ForeignKey(
        ZoneProtectionProfile, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="ZoneProtectionProfileFindingControlQuery",
        related_name="zone_protection_profile_findings", blank=True)
    #: The appliance, and nothing finer - see the class docstring. A profile name is unique per
    #: appliance and this collection has one scope, so two findings about two appliances cannot
    #: collapse into one row the way they would without any scope at all.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["zone_protection_profile"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "zone_protection_profile"],
                name="unique_zpp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on zone protection profile {self.subject_name}"


class ZoneProtectionProfileFindingControlQuery(FindingControlQueryBase):
    zone_protection_profile_finding = models.ForeignKey(
        ZoneProtectionProfileFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="zone_protection_profile_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["zone_protection_profile_finding", "control_query"],
                name="unique_zpp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.zone_protection_profile_finding_id} <- {self.control_query_id}"


class DosPolicyRuleFinding(ObjectFindingBase):
    """A finding against one DoS Protection policy rule. PAN-ZON-007.

    THE RULE IS THE SUBJECT AND THE PROFILE IS NOT, and stage 5 records that as a choice between
    two defensible answers rather than as the only one. The finding this control wants names a
    SERVICE, and a service is no model's subject anywhere in this estate; what an engineer creates
    or edits to close the finding is the rule, so the rule is what the finding names and the
    profile is read rather than named.

    ONLY ONE OF THE CONTROL'S TWO HALVES REACHES THIS MODEL. That each business-critical service
    is covered by a DoS rule carrying a classified profile ranges over a population the
    configuration cannot enumerate - the firewall holds the rules, the profiles and the
    destination addresses and nothing in it says which destination is a crown-jewel service - so
    stage 5 discharges that half onto a question for a person and it owes no query. What is left,
    and what every row of this model is about, is that the rules which DO exist enforce the
    profile they name.

    THE HALF THAT IS DELIVERABLE AND HAS NO SUBJECT: that no DoS rule exists ANYWHERE on an
    appliance. Stage 3 says that one IS deliverable without the inventory, because then no service
    is covered whatever the inventory says - but it is a verdict per APPLIANCE and this is a row
    per RULE, so on an appliance with no DoS rules at all this control produces nothing, and
    nothing is indistinguishable from an appliance whose rules are all correct. No model holds
    that verdict; the gap is recorded in the stage 8 artifact rather than invented here.

    `subject_scope` CARRIES THE RULEBASE AS WELL AS THE APPLIANCE AND THE VSYS, because the
    shipped uniqueness constraint is `(enforcement_point, config_source, rule_name)`: a local rule
    and a Panorama pre-rule of the same name in the same vsys are different objects, and a reader
    sent to the wrong rulebase does not find the row.

    AND THE POSITION IS PART OF WHAT A ROW IS WITHOUT BEING PART OF ITS IDENTITY. A DoS rulebase
    resolves by order, no configuration key holds that order, and it cannot be recovered from a
    stored row later - so stage 7 stores `rule_position` as plumbing and deliberately keeps it out
    of the constraint, for the reason `DecryptionRule` gives: a rule keeps its name across a move,
    so keying on position would make a reorder look like a delete and an insert.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="dos_policy_rule_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="dos_policy_rule_findings")
    dos_policy_rule = models.ForeignKey(
        DosPolicyRule, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="DosPolicyRuleFindingControlQuery",
        related_name="dos_policy_rule_findings", blank=True)
    #: The appliance, the vsys and the rulebase - see the class docstring for why the rulebase is
    #: not optional here.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["dos_policy_rule"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "dos_policy_rule"],
                name="unique_dospr_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on DoS Protection rule {self.subject_name}"


class DosPolicyRuleFindingControlQuery(FindingControlQueryBase):
    dos_policy_rule_finding = models.ForeignKey(
        DosPolicyRuleFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="dos_policy_rule_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["dos_policy_rule_finding", "control_query"],
                name="unique_dospr_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.dos_policy_rule_finding_id} <- {self.control_query_id}"


class DecryptionPolicyRuleFinding(ObjectFindingBase):
    """A finding against one decryption policy rule. PAN-DEC-002, -003, -005 to -008 and -010.

    THE ENTRY GRAIN IS THE EXEMPTION GRAIN. Every exemption assertion in this domain is about a
    rule that EXISTS and is wrong - it leaves traffic encrypted with a criterion at `any`, or with
    no written reason, or with no profile attached, or with the source match inverted - and what an
    engineer opens to close the finding is that rule. The three coverage assertions are the
    opposite shape and belong to `DecryptionRulebaseCoverageFinding`, because the state they report
    is that NO rule does something and a row per rule has nothing to report it on.

    `subject_scope` CARRIES THE RULEBASE AS WELL AS THE APPLIANCE AND THE VSYS, because the shipped
    uniqueness constraint is `(enforcement_point, config_source, rule_name)`: the same rule NAME may
    exist in a device-group pre-rulebase and a post-rulebase at the same scope, and those are two
    different objects a reader sent to the wrong one does not find.

    AND THE RULE'S NAME MAY BE LONGER THAN THIS FINDING CAN HOLD. `DecryptionPolicyRule.rule_name`
    is 255 characters, because no length was measured for that key and `SecurityRule.name` is 255;
    `ObjectFindingBase.subject_name` is 64. A rule named longer than that is truncated in the
    FINDING while the configuration row holds it whole, which is a property of the shared base and
    not of this domain.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="decryption_policy_rule_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="decryption_policy_rule_findings")
    decryption_policy_rule = models.ForeignKey(
        DecryptionPolicyRule, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="DecryptionPolicyRuleFindingControlQuery",
        related_name="decryption_policy_rule_findings", blank=True)
    #: The appliance, the vsys and the rulebase - see the class docstring for why the rulebase is
    #: not optional here.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["decryption_policy_rule"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "decryption_policy_rule"],
                name="unique_decrule_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on decryption rule {self.subject_name}"


class DecryptionPolicyRuleFindingControlQuery(FindingControlQueryBase):
    decryption_policy_rule_finding = models.ForeignKey(
        DecryptionPolicyRuleFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="decryption_policy_rule_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["decryption_policy_rule_finding", "control_query"],
                name="unique_decrule_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.decryption_policy_rule_finding_id} <- {self.control_query_id}"


class DecryptionRulebaseCoverageFinding(ObjectFindingBase):
    """A finding against one enforcement point's decryption rulebase as a whole. PAN-DEC-001, -009.

    THE ROW THAT CAN REPORT AN ABSENCE. Stage 4 measured the commonest state of this domain as NO
    DECRYPTION RULEBASE AT ALL - all four lab appliances, all twenty virtual systems, both Panorama
    Shared rulebases and all ten device groups, twice - and a predicate cannot compare against a row
    that is not there. So the two coverage controls name the enforcement point, where every column's
    uncollected and unrecomputed value is the FIRING one, and the remediation is to ADD a rule.

    `subject_scope` IS NOT OPTIONAL ON A VERDICT GRAIN. The subject is one virtual system, so the
    finding's `subject_name` is a partition name like `vsys2` - which is not unique in an estate and
    is not even unique on a Panorama. The scope carries the appliance or the HA pair that owns the
    point.

    AND THE VERDICT IS RIGHT BUT UNATTRIBUTABLE, which a reader of the finding has to be told: a
    decryption rule pushed from a device-group or Shared pre/post-rulebase CONTRIBUTES to these
    counts because it is in force here, and the verdict row has no scope column - so a finding
    saying "this enforcement point opens no outbound web session" cannot say whether the gap is in
    the firewall's own rulebase or in the device group above it. The per-rule model answers that
    with `config_source`; this one cannot, and the generator's sentence says so.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="decryption_rulebase_coverage_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="decryption_rulebase_coverage_findings")
    decryption_rulebase_verdict = models.ForeignKey(
        DecryptionRulebaseVerdict, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="DecryptionRulebaseCoverageFindingControlQuery",
        related_name="decryption_rulebase_coverage_findings", blank=True)
    #: The appliance or HA pair that owns the enforcement point. See the class docstring.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["decryption_rulebase_verdict"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "decryption_rulebase_verdict"],
                name="unique_decrbv_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on decryption rulebase {self.subject_name}"


class DecryptionRulebaseCoverageFindingControlQuery(FindingControlQueryBase):
    decryption_rulebase_coverage_finding = models.ForeignKey(
        DecryptionRulebaseCoverageFinding, on_delete=models.CASCADE,
        related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="decryption_rulebase_coverage_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["decryption_rulebase_coverage_finding", "control_query"],
                name="unique_decrbv_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.decryption_rulebase_coverage_finding_id} <- {self.control_query_id}"


class SslDecryptionExclusionFinding(ObjectFindingBase):
    """A finding against one SSL decryption exclusion the organisation added itself. PAN-DEC-004.

    THE ORGANISATION'S OWN ENTRIES AND NOT THE VENDOR'S. The read behind this subject returns
    `ssl-decrypt/ssl-exclude-cert` at the appliance's shared scope and at each vsys; the vendor's
    330 or 385 entries live at `/config/predefined/ssl-exclude-cert`, are a separate object, and are
    invisible to it. The web interface renders BOTH collections in ONE grid distinguished only by a
    Location column, so an operator looking at the screen sees entries this finding never names.

    `subject_scope` IS REQUIRED because the shipped constraint is
    `(appliance, scope, vsys_name, name)`: the same server name may be excluded in a vsys and in the
    appliance's own shared container, and those are two different entries an operator removes in two
    different places.

    ONLY PAN-DEC-004'S FIRST RECORD REACHES THIS MODEL. Its second - that every departure from the
    VENDOR's list is deliberate and current - is a conclusion about a different model, and
    `probe.relation_between` finds no relation between the two in either direction, so that half is
    silent. See `SslDecryptionVendorExclusionOptOutFinding` and the stage 8 artifact's
    `subjects_in_two_models`.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="ssl_decryption_exclusion_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="ssl_decryption_exclusion_findings")
    ssl_decryption_exclusion = models.ForeignKey(
        SslDecryptionExclusion, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="SslDecryptionExclusionFindingControlQuery",
        related_name="ssl_decryption_exclusion_findings", blank=True)
    #: The appliance and the scope the entry sits in. See the class docstring.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["ssl_decryption_exclusion"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "ssl_decryption_exclusion"],
                name="unique_sslexcl_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on SSL decryption exclusion {self.subject_name}"


class SslDecryptionExclusionFindingControlQuery(FindingControlQueryBase):
    ssl_decryption_exclusion_finding = models.ForeignKey(
        SslDecryptionExclusionFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="ssl_decryption_exclusion_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["ssl_decryption_exclusion_finding", "control_query"],
                name="unique_sslexcl_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.ssl_decryption_exclusion_finding_id} <- {self.control_query_id}"


class SslDecryptionVendorExclusionOptOutFinding(ObjectFindingBase):
    """A finding against one appliance's departures from the VENDOR's SSL exclusion list.

    NO SHIPPED CONTROL PRODUCES ONE OF THESE, which is a recorded state rather than dead code.
    PAN-DEC-004's two assertion records name two models - the organisation's own exclusions and
    these departures from the vendor's list - and `Control` maps one type to one model while
    `ControlQuery.clean()` refuses a query whose model differs from its control's target, so one
    catalogue id cannot hold both halves. The exclusion half took the id, because the control's own
    severity and its minimum value are stage 3's record 0 while this is the
    `preferred_gap_severity` half at low. Splitting PAN-DEC-004 into two catalogue ids changes what
    a customer's report contains and is Jason's decision.

    AND NO ESTATE CAN MAKE IT FIRE TODAY, which is the sharper reason to register it rather than
    build a control for it now. The one clean assertion is that no switched-off entry is left on the
    list after the vendor stopped shipping it, and that is a SET DIFFERENCE whose right-hand side -
    the vendor's own catalogue - is invisible to `action=get` and to the merged configuration: the
    config read a collector naturally reaches for answers a well-formed, TRUTHY, EMPTY count
    envelope (`{"@total-count": "0", "@count": "0"}`) for a populated vendor list on every appliance
    measured. Only the `show predefined` operational read supplies it, nothing issues that read on a
    collection run, and `stale_disabled_vendor_exclusion_count` is therefore zero on every row in
    every estate. Stage 5 took that concession deliberately and declared the column's unknown as
    reading compliant, with the reasons written out; stage 7 filed the missing
    `predefined_list_collected` companion as a gap. The model's own normaliser returns that fact
    where no column can carry it.

    `subject_scope` IS ABSENT AND THAT IS CORRECT: the node is a single shared-scoped member list
    with no vsys spelling at all, measured at both scopes, so the row is one per appliance and the
    appliance's own hostname is the whole of what tells two rows apart. ON AN HA PAIR THIS YIELDS
    TWO ROWS FOR ONE REAL CONFIGURATION and nothing deduplicates them.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="ssl_decryption_vendor_exclusion_optout_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="ssl_decryption_vendor_exclusion_optout_findings")
    ssl_decryption_vendor_exclusion_optout = models.ForeignKey(
        SslDecryptionVendorExclusionOptOut, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="SslDecryptionVendorExclusionOptOutFindingControlQuery",
        related_name="ssl_decryption_vendor_exclusion_optout_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["ssl_decryption_vendor_exclusion_optout"]),
        ]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control",
                        "ssl_decryption_vendor_exclusion_optout"],
                name="unique_sslopt_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return (f"{self.control.control_id} on vendor exclusion opt-outs "
                f"{self.subject_name}")


class SslDecryptionVendorExclusionOptOutFindingControlQuery(FindingControlQueryBase):
    ssl_decryption_vendor_exclusion_optout_finding = models.ForeignKey(
        SslDecryptionVendorExclusionOptOutFinding, on_delete=models.CASCADE,
        related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="ssl_decryption_vendor_exclusion_optout_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["ssl_decryption_vendor_exclusion_optout_finding", "control_query"],
                name="unique_sslopt_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return (f"{self.ssl_decryption_vendor_exclusion_optout_finding_id} "
                f"<- {self.control_query_id}")


class LogServerTargetFinding(ObjectFindingBase):
    """A finding against one server entry of one log-settings server profile. PAN-LOG-002.

    THE SUBJECT IS A CHILD ROW, which is why `subject_scope` is not optional here. The entry's
    own name is `server_name`, and that is unique only inside its parent profile: one appliance
    can hold a shared syslog profile and a shared e-mail profile whose server entries have the
    same names, which is why the shipped uniqueness constraint on the integrations model is
    `(appliance, scope, vsys_name, kind, profile_name, server_name)` and why the scope here
    carries the appliance, the config scope and the parent profile together.

    ONE MODEL, TWO KINDS, ONE CONTROL. Stage 5 states two subjects over this table -
    `syslog-server-target` and `email-server-target` - and no assertion in the logging domain
    names the second. PAN-LOG-002's queries therefore all clause on `kind eq syslog`: the
    model's own docstring records that `transport` holds its UDP default on the e-mail kind too,
    so a query without that clause reports every mail relay in the estate as sending syslog in
    the clear. Nothing downstream enforces it - not the catalog schema, not the compiler, not a
    lint, not a generic test.

    ON AN HA PAIR THIS IS TWO ROWS FOR ONE REAL CONFIGURATION, one per peer, and nothing
    deduplicates them.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="log_server_target_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="log_server_target_findings")
    log_server_target = models.ForeignKey(
        LogServerTarget, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="LogServerTargetFindingControlQuery",
        related_name="log_server_target_findings", blank=True)
    #: The appliance, the config scope and the parent profile. See the class docstring.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["log_server_target"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "log_server_target"],
                name="unique_lst_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on log server target {self.subject_name}"


class LogServerTargetFindingControlQuery(FindingControlQueryBase):
    log_server_target_finding = models.ForeignKey(
        LogServerTargetFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE, related_name="log_server_target_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["log_server_target_finding", "control_query"],
                name="unique_lst_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.log_server_target_finding_id} <- {self.control_query_id}"


class VsysLogForwardingFinding(ObjectFindingBase):
    """A finding against one virtual system's Log Forwarding availability. PAN-LOG-005.

    `subject_scope` IS NOT OPTIONAL HERE, for the reason `ServiceRouteFinding` records: the
    subject is a VIRTUAL SYSTEM, so `subject_name` is a partition name like `vsys1`, which is
    not unique in an estate and is not unique even on one Panorama. The scope carries the
    appliance.

    THE VSYS IS THE ROW AND NOT THE PROFILE, because the gap this control reports is a vsys with
    NO adequate profile available to it, and a profile-keyed row cannot report something that
    does not exist. The verdict spans four namespaces - the vsys's own profiles, shared,
    Panorama-pushed and vendor-predefined - and the integrations model's own docstring records
    that name resolution between them has no single true precedence ladder, which is why the gap
    column takes the UNION rather than a winner.

    ON AN HA PAIR BOTH PEERS HOLD THE SAME VSYS and produce two rows for one real
    configuration, with nothing deduplicating them.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="vsys_log_forwarding_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="vsys_log_forwarding_findings")
    vsys_log_forwarding = models.ForeignKey(
        VsysLogForwarding, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="VsysLogForwardingFindingControlQuery",
        related_name="vsys_log_forwarding_findings", blank=True)
    #: The appliance that owns the virtual system. See the class docstring.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["vsys_log_forwarding"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "vsys_log_forwarding"],
                name="unique_vlf_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on vsys log forwarding {self.subject_name}"


class VsysLogForwardingFindingControlQuery(FindingControlQueryBase):
    vsys_log_forwarding_finding = models.ForeignKey(
        VsysLogForwardingFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="vsys_log_forwarding_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["vsys_log_forwarding_finding", "control_query"],
                name="unique_vlf_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.vsys_log_forwarding_finding_id} <- {self.control_query_id}"


class ManagementPlaneAddressingFinding(ObjectFindingBase):
    """A finding against one appliance's management-plane addressing. PAN-MGT-004.

    THE SUBJECT IS THE APPLIANCE and `subject_name` carries it, so no `subject_scope` is needed:
    unlike a virtual system, an appliance's own name is the scope. On an HA pair each peer
    produces its own row and that is a real difference - the peers have different management
    addresses and are separately reachable, and the management-plane subtree is not synchronised
    between them.

    WHAT NO FINDING HERE CAN SAY, and it is the control's own gap rather than this model's. The
    firewall holds the address, the mask and whether a route leaves the segment, and NOTHING
    about whether the networks those reach are ones the organisation controls. So the graded
    column reports the configuration's CONTRIBUTION to exposure and a finding is not a statement
    that the plane is reachable. The remediation the control carries is a reachability test,
    which is a person's work.

    AND IT IS NOT A REMEDIATION TARGET. Jason's standing restriction: no change to a management
    IP address or to management-plane routing is to be proposed or implied. A finding here
    PRINTS the value an assessor goes and looks at.

    ONE CLASS REPORTS AT A SEVERITY NOBODY ASSIGNED, which is recorded here because a reader of
    a row cannot see it. Stage 3 left `dynamically_allocated` UNRANKED, and the control's
    assertion is that the posture is not the preferred one - which is true of a DHCP-addressed
    plane - so such a row fires, matches no calibration, and reports at the control's own
    default. The stage 8 artifact for `management-services` raises it as an open question.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="management_plane_addressing_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="management_plane_addressing_findings")
    management_plane_addressing = models.ForeignKey(
        ManagementPlaneAddressing, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="ManagementPlaneAddressingFindingControlQuery",
        related_name="management_plane_addressing_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["management_plane_addressing"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "management_plane_addressing"],
                name="unique_mpa_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return (f"{self.control.control_id} on management plane addressing "
                f"{self.subject_name}")


class ManagementPlaneAddressingFindingControlQuery(FindingControlQueryBase):
    management_plane_addressing_finding = models.ForeignKey(
        ManagementPlaneAddressingFinding, on_delete=models.CASCADE,
        related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="management_plane_addressing_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["management_plane_addressing_finding", "control_query"],
                name="unique_mpa_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.management_plane_addressing_finding_id} <- {self.control_query_id}"


class ApplianceOperationalModeFinding(ObjectFindingBase):
    """A finding against the cryptographic operational mode one appliance reports. PAN-MGT-012.

    THE SUBJECT IS THE APPLIANCE, as above, so `subject_scope` is not needed.

    THE VALUE IS HELD IN NO CONFIGURATION NODE AT ANY SCOPE. The mode is set from maintenance
    mode and is reported at `/response/result/system/operational-mode` in `show system info`;
    `show fips-mode` answers code=17 on all four lab appliances and the CLI grammar carries no
    node for it. So a finding here rests on a RUNTIME reading, which is why the integrations
    model carries neither column in provenance: `ProvenanceType`'s members are all about where a
    CONFIGURATION value came from, and the fallthrough for an unmarked present value is
    "defined on this device", which is the one thing a runtime reading is not.

    WHAT A FINDING HERE ACTUALLY SAYS, and the wording matters because the alternative reading
    is wrong. Nothing on the device records whether the approved mode is REQUIRED of this
    appliance, and stage 5's restatement carries one clause and no applicability - so stage 3's
    contractual obligation did not become a clause and every appliance in any estate reports
    this whether the obligation exists or not. The finding says "the mode is not the approved one
    and nobody has confirmed whether it must be", which is an item an assessor is owed rather
    than a verdict.

    AND IT MUST NOT BE USED TO REINTERPRET ANOTHER DOMAIN'S DEFAULTS. Jason decided 2026-09-04
    that a half-implemented assessment of this mode "would lie - a device in FIPS-CC mode would
    be judged against normal-mode defaults, and would be reported as failing controls it
    satisfies and passing ones it does not". That runs outwards: implicit values differ by mode,
    so an unanswered mode propagates into every other domain's findings wherever a control
    reasons from an absent key. No appliance in this estate runs the other mode, so the
    question cannot be settled on current hardware either.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE,
        related_name="appliance_operational_mode_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT,
        related_name="appliance_operational_mode_findings")
    appliance_operational_mode = models.ForeignKey(
        ApplianceOperationalMode, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="ApplianceOperationalModeFindingControlQuery",
        related_name="appliance_operational_mode_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["appliance_operational_mode"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "appliance_operational_mode"],
                name="unique_aom_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return (f"{self.control.control_id} on appliance operational mode "
                f"{self.subject_name}")


class ApplianceOperationalModeFindingControlQuery(FindingControlQueryBase):
    appliance_operational_mode_finding = models.ForeignKey(
        ApplianceOperationalModeFinding, on_delete=models.CASCADE,
        related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="appliance_operational_mode_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["appliance_operational_mode_finding", "control_query"],
                name="unique_aom_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.appliance_operational_mode_finding_id} <- {self.control_query_id}"


class VsysRulePostureFinding(ObjectFindingBase):
    """A finding against one virtual system's whole-policy posture. `security-policy`, stage 8.

    PAN-POL-007, -010, -017, -018 and -019. Minted 2026-11-01.

    THE VSYS IS THE ROW AND NOT THE RULE, and this is the one model in the domain where that is
    not a convenience. Every column of the integrations model is a statement about the ABSENCE of
    a rule somebody should have written - no catch-all refusal with its sessions recorded, no
    refusal of named applications above the permits, no rule naming a region, no refusal matched
    on a port - and a rule-keyed row cannot report a rule that does not exist. The subject is
    real whether or not the vsys has a rulebase node at all: three of nine vsys on one lab
    PA-5220 have none, and each one still enforces the two rules PAN-OS ships.

    `subject_scope` IS NOT OPTIONAL HERE, for the reason `VsysLogForwardingFinding` records: the
    subject's own name is a partition name like `vsys6`, which is not unique in an estate and is
    not unique even on one Panorama. The scope carries the appliance.

    WHAT NO FINDING HERE CAN SAY, and it is a remediation gap rather than a cosmetic one: WHICH
    OF THE THREE RULEBASES an absence spans. A rule set is the firewall-local vsys rulebase plus
    the Panorama pre- and post-rulebases pushed to it, the integrations model stores no scope
    column, and so an estate whose policy is pushed from Panorama would be told to edit a vsys
    rulebase the firewall will not accept rules into. The distinction IS stored, on
    `SecurityRule.config_source`; joining back to it is a presentation question.

    ON AN HA PAIR both peers hold the same virtual systems behind one `EnforcementPoint`, so one
    real vsys yields ONE row here - unlike `PolicyRuleSettingsFinding` below.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="vsys_rule_posture_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="vsys_rule_posture_findings")
    vsys_rule_posture = models.ForeignKey(
        VsysRulePosture, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="VsysRulePostureFindingControlQuery",
        related_name="vsys_rule_posture_findings", blank=True)
    #: The appliance that owns the virtual system. See the class docstring.
    subject_scope = models.CharField(max_length=128, blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["vsys_rule_posture"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "vsys_rule_posture"],
                name="unique_vrp_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on vsys rule posture {self.subject_name}"


class VsysRulePostureFindingControlQuery(FindingControlQueryBase):
    vsys_rule_posture_finding = models.ForeignKey(
        VsysRulePostureFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="vsys_rule_posture_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["vsys_rule_posture_finding", "control_query"],
                name="unique_vrp_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.vsys_rule_posture_finding_id} <- {self.control_query_id}"


class PolicyRuleSettingsFinding(ObjectFindingBase):
    """A finding against one appliance's device-wide policy-rule switches. Stage 8, 2026-11-01.

    PAN-POL-011, WHICH SHIPS INACTIVE. Jason, 2026-10-31, recorded in stage 5's own record for
    that control: "Let's just leave PAN-POL-011 as disabled or not in use." The reason is in the
    column rather than in the control: `PolicyRuleSettings.disable_shadow_rule_check` is a
    nullable boolean whose implicit value stage 4 left UNMEASURED, the restatement clauses it
    `is not false` so that NULL reports, and the key is absent on every appliance in the lab - so
    the control as written reports every appliance on the strength of a reading nobody took. The
    model exists so the question is in the catalogue with its reason, and generates no findings by
    design, which is this project's recorded convention for exactly that state.

    WHAT WOULD BRING IT BACK IS NOT A SCREEN. There is no UI control for the key: the vendor's
    Policy Rulebase Settings panel enumerates its controls and this is not among them, and
    `shadow` appears in the 11.1 and 11.2 Help only under Validate Commit and in the
    commit-warnings list. The feature surfaces as a `Rule Shadow` commit warning, so the
    experiment is two rules where one shadows the other in a vsys of an appliance where the key
    is absent, then one `validate full` - which is a commit gate no collector may issue.

    ONE ROW PER APPLIANCE, so ON AN HA PAIR THIS IS TWO ROWS FOR ONE REAL CONFIGURATION with
    nothing downstream deduplicating them. That is not cosmetic and it is not a defect: the node
    sits at `deviceconfig/setting/management` and has no vsys axis, and the two peers' management
    containers have been measured DIFFERING while config sync reported synchronized - so a
    difference between peers is data.
    """

    assessment_run = models.ForeignKey(
        AssessmentRun, on_delete=models.CASCADE, related_name="policy_rule_settings_findings")
    control = models.ForeignKey(
        Control, on_delete=models.PROTECT, related_name="policy_rule_settings_findings")
    policy_rule_settings = models.ForeignKey(
        PolicyRuleSettings, on_delete=models.CASCADE, related_name="findings")
    control_queries = models.ManyToManyField(
        ControlQuery, through="PolicyRuleSettingsFindingControlQuery",
        related_name="policy_rule_settings_findings", blank=True)

    class Meta(ObjectFindingBase.Meta):
        indexes = ObjectFindingBase.Meta.indexes + [
            models.Index(fields=["policy_rule_settings"])]
        constraints = ObjectFindingBase.Meta.constraints + [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "policy_rule_settings"],
                name="unique_prs_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on policy rule settings {self.subject_name}"


class PolicyRuleSettingsFindingControlQuery(FindingControlQueryBase):
    policy_rule_settings_finding = models.ForeignKey(
        PolicyRuleSettingsFinding, on_delete=models.CASCADE, related_name="query_links")
    control_query = models.ForeignKey(
        ControlQuery, on_delete=models.CASCADE,
        related_name="policy_rule_settings_finding_links")

    class Meta(FindingControlQueryBase.Meta):
        constraints = [
            models.UniqueConstraint(
                fields=["policy_rule_settings_finding", "control_query"],
                name="unique_prs_finding_control_query_link"),
        ]

    def __str__(self) -> str:
        return f"{self.policy_rule_settings_finding_id} <- {self.control_query_id}"
