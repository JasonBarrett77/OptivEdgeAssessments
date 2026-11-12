"""`Licence Inventory` -> `License Inventory` on `Control.control_type`'s choices.

LABELS ONLY. The stored value is still `licence_inventory` and no row changes, so there is
nothing to backfill and nothing to undo. It is the half of the 2026-11-10 spelling sweep that
was left without a migration: the integrations app got `0123` for its three fields and this one
was missed, which is what production reported on 2026-11-12 - makemigrations sees a choices list
that disagrees with the last recorded state and says the app has unmigrated changes, whatever
the database holds.

The value keeps its British spelling deliberately. A client never reads it; renaming it would
rewrite every stored `Control.control_type`, every catalog entry keyed on it and the finding
registry's own mapping, for a string nobody sees.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('assessments', '0065_remove_generatedartifact_control_detail'),
    ]

    operations = [
        migrations.AlterField(
            model_name='control',
            name='control_type',
            field=models.CharField(choices=[('security_rule', 'Security Rule'), ('coverage', 'Coverage'), ('config', 'Configuration'), ('management_interface', 'Management Interface'), ('interface_management_profile', 'Interface Management Profile'), ('ssl_tls_service_profile', 'SSL/TLS Service Profile'), ('certificate_profile', 'Certificate Profile'), ('certificate', 'Certificate'), ('authentication_profile', 'Authentication Profile'), ('authentication_sequence', 'Authentication Sequence'), ('password_profile', 'Password Profile'), ('security_profile', 'Security Profile'), ('password_complexity', 'Minimum Password Complexity'), ('authentication_settings', 'Authentication Settings'), ('login_banner', 'Login Banner'), ('master_key', 'Master Key'), ('update_server', 'Update Server Settings'), ('logging_settings', 'Logging and Reporting Settings'), ('wildfire_settings', 'WildFire Settings'), ('management_tls', 'Management TLS'), ('management_ssh', 'Management SSH'), ('admin_user', 'Administrator'), ('server_profile', 'AAA Server Profile'), ('ntp_settings', 'NTP'), ('snmp_settings', 'SNMP'), ('system_identity', 'System Identity'), ('dns_settings', 'Management Resolvers'), ('service_route', 'Management Service Paths'), ('normalization', 'Normalization Coverage'), ('ike_crypto_profile', 'IKE Crypto Profile'), ('ike_gateway', 'IKE Gateway'), ('ipsec_crypto_profile', 'IPSec Crypto Profile'), ('ipsec_tunnel', 'IPSec Tunnel'), ('ipsec_tunnel_path', 'IPSec Tunnel Path'), ('high_availability', 'High Availability'), ('panorama_registration', 'Panorama Registration'), ('firewall_interface', 'Interface'), ('session_settings', 'Session Settings'), ('lldp_global', 'Global LLDP'), ('dhcp_interface_config', 'DHCP Interface Configuration'), ('tunnel_inspection', 'Tunnel Inspection Coverage'), ('routing_adjacency', 'Routing Adjacency'), ('sanctioned_application_marking', 'Sanctioned Application Marking'), ('saas_url_filtering_posture', 'SaaS URL Filtering Posture'), ('saas_application_policy_posture', 'SaaS Application Policy Posture'), ('cloud_app_engine_setting', 'App-ID Cloud Engine'), ('device_identification', 'Device Identification'), ('zone', 'Security Zone'), ('rulebase_device_match', 'Rulebase Device Match'), ('data_filtering_posture', 'Data Filtering Posture'), ('globalprotect_portal', 'GlobalProtect Portal'), ('globalprotect_portal_client_auth', 'GlobalProtect Portal Client Authentication'), ('globalprotect_enforcement_point', 'GlobalProtect Enforcement Point'), ('firewall_content_streams', 'Firewall Content Streams'), ('licence_inventory', 'License Inventory'), ('log_alarm_settings', 'Log Database Alarms'), ('content_update_schedule', 'Content Update Schedule'), ('custom_url_category', 'Custom URL Category'), ('user_id_collector', 'User-ID Collector'), ('user_id_discovery_bound', 'User-ID Discovery Bound'), ('decryption_settings', 'Decryption Settings'), ('globalprotect_gateway', 'GlobalProtect Gateway'), ('globalprotect_gateway_client_auth', 'GlobalProtect Gateway Client Authentication'), ('globalprotect_gateway_agent_config', 'GlobalProtect Gateway Agent Configuration'), ('zone_protection_profile', 'Zone Protection Profile'), ('dos_policy_rule', 'DoS Policy Rule'), ('decryption_policy_rule', 'Decryption Policy Rule'), ('decryption_rulebase_coverage', 'Decryption Rulebase Coverage'), ('ssl_decryption_exclusion', 'SSL Decryption Exclusion'), ('ssl_decryption_vendor_exclusion_optout', 'SSL Decryption Vendor Exclusion Opt-Out'), ('log_server_target', 'Log Server Target'), ('vsys_log_forwarding', 'Virtual System Log Forwarding'), ('management_plane_addressing', 'Management Plane Addressing'), ('appliance_operational_mode', 'Appliance Operational Mode'), ('vsys_rule_posture', 'Virtual System Rule Posture'), ('policy_rule_settings', 'Policy Rule Settings')], default='security_rule', max_length=64),
        ),
    ]
