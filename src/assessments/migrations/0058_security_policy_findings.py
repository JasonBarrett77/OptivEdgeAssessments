"""`security-policy` stage 8: two finding models, two link models, and the type widening.

TWO MINTS FOR A DOMAIN OF TWENTY-FOUR CONTROLS, and FIFTEEN of its twenty-one shipping controls
reuse `security_rule` instead - so this migration is smaller than the domain is. The `AlterField`
on `Control.control_type` below is GENERATED and not hand-written: the choices literal must match
the enum exactly, and `makemigrations --check --dry-run` is the only thing that catches a
transcription slip.

`VsysRulePostureFinding` is per ENFORCEMENT POINT and carries `subject_scope`, because the row's
own name is a vsys name and `vsys6` is not unique in an estate. Every one of its five controls
reports a rule that DOES NOT EXIST, which is why the subject could not be a rule.

`PolicyRuleSettingsFinding` is per APPLIANCE and needs no scope - the appliance's own name is
one. Its single control, PAN-POL-011, ships with `is_active: false` by Jason's decision of
2026-10-31, so these tables are created and stay empty by design until the implicit value of
`disable-shadow-rule-check` is measured. That is this project's recorded convention rather than
an oversight: the catalogue carries the question and the reason, and generates no findings.

BOTH MODELS' INTEGRATIONS TABLES ALREADY EXIST - `integrations_vsysruleposture` and
`integrations_policyrulesettings`, built by this domain's stage 7 - so nothing here touches
OptivEdgeIntegrations and no column of any integrations model moves.
"""


import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('assessments', '0057_management_services_findings'),
        ('integrations', '0121_zone_dos_protection'),
    ]

    operations = [
        migrations.AlterField(
            model_name='control',
            name='control_type',
            field=models.CharField(choices=[('security_rule', 'Security Rule'), ('coverage', 'Coverage'), ('config', 'Configuration'), ('management_interface', 'Management Interface'), ('interface_management_profile', 'Interface Management Profile'), ('ssl_tls_service_profile', 'SSL/TLS Service Profile'), ('certificate_profile', 'Certificate Profile'), ('certificate', 'Certificate'), ('authentication_profile', 'Authentication Profile'), ('authentication_sequence', 'Authentication Sequence'), ('password_profile', 'Password Profile'), ('security_profile', 'Security Profile'), ('password_complexity', 'Minimum Password Complexity'), ('authentication_settings', 'Authentication Settings'), ('login_banner', 'Login Banner'), ('master_key', 'Master Key'), ('update_server', 'Update Server Settings'), ('logging_settings', 'Logging and Reporting Settings'), ('wildfire_settings', 'WildFire Settings'), ('management_tls', 'Management TLS'), ('management_ssh', 'Management SSH'), ('admin_user', 'Administrator'), ('server_profile', 'AAA Server Profile'), ('ntp_settings', 'NTP'), ('snmp_settings', 'SNMP'), ('system_identity', 'System Identity'), ('dns_settings', 'Management Resolvers'), ('service_route', 'Management Service Paths'), ('normalization', 'Normalization Coverage'), ('ike_crypto_profile', 'IKE Crypto Profile'), ('ike_gateway', 'IKE Gateway'), ('ipsec_crypto_profile', 'IPSec Crypto Profile'), ('ipsec_tunnel', 'IPSec Tunnel'), ('high_availability', 'High Availability'), ('panorama_registration', 'Panorama Registration'), ('firewall_interface', 'Interface'), ('session_settings', 'Session Settings'), ('lldp_global', 'Global LLDP'), ('dhcp_interface_config', 'DHCP Interface Configuration'), ('tunnel_inspection', 'Tunnel Inspection Coverage'), ('routing_adjacency', 'Routing Adjacency'), ('sanctioned_application_marking', 'Sanctioned Application Marking'), ('saas_url_filtering_posture', 'SaaS URL Filtering Posture'), ('saas_application_policy_posture', 'SaaS Application Policy Posture'), ('cloud_app_engine_setting', 'App-ID Cloud Engine'), ('device_identification', 'Device Identification'), ('zone', 'Security Zone'), ('rulebase_device_match', 'Rulebase Device Match'), ('data_filtering_posture', 'Data Filtering Posture'), ('globalprotect_portal', 'GlobalProtect Portal'), ('globalprotect_portal_client_auth', 'GlobalProtect Portal Client Authentication'), ('globalprotect_enforcement_point', 'GlobalProtect Enforcement Point'), ('firewall_content_streams', 'Firewall Content Streams'), ('licence_inventory', 'Licence Inventory'), ('log_alarm_settings', 'Log Database Alarms'), ('content_update_schedule', 'Content Update Schedule'), ('custom_url_category', 'Custom URL Category'), ('user_id_collector', 'User-ID Collector'), ('user_id_discovery_bound', 'User-ID Discovery Bound'), ('decryption_settings', 'Decryption Settings'), ('globalprotect_gateway', 'GlobalProtect Gateway'), ('globalprotect_gateway_client_auth', 'GlobalProtect Gateway Client Authentication'), ('globalprotect_gateway_agent_config', 'GlobalProtect Gateway Agent Configuration'), ('zone_protection_profile', 'Zone Protection Profile'), ('dos_policy_rule', 'DoS Policy Rule'), ('decryption_policy_rule', 'Decryption Policy Rule'), ('decryption_rulebase_coverage', 'Decryption Rulebase Coverage'), ('ssl_decryption_exclusion', 'SSL Decryption Exclusion'), ('ssl_decryption_vendor_exclusion_optout', 'SSL Decryption Vendor Exclusion Opt-Out'), ('log_server_target', 'Log Server Target'), ('vsys_log_forwarding', 'Virtual System Log Forwarding'), ('management_plane_addressing', 'Management Plane Addressing'), ('appliance_operational_mode', 'Appliance Operational Mode'), ('vsys_rule_posture', 'Virtual System Rule Posture'), ('policy_rule_settings', 'Policy Rule Settings')], default='security_rule', max_length=64),
        ),
        migrations.CreateModel(
            name='PolicyRuleSettingsFinding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('open', 'Open'), ('suppressed', 'Suppressed'), ('resolved', 'Resolved')], default='open', max_length=32)),
                ('severity', models.CharField(choices=[('informational', 'Informational'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], max_length=32)),
                ('title', models.CharField(max_length=255)),
                ('summary', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('reference_number', models.PositiveIntegerField(editable=False)),
                ('matched_query_names', models.JSONField(blank=True, default=list)),
                ('subject_name', models.CharField(blank=True, max_length=64)),
                ('assessment_run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='policy_rule_settings_findings', to='assessments.assessmentrun')),
                ('control', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='policy_rule_settings_findings', to='assessments.control')),
                ('policy_rule_settings', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='integrations.policyrulesettings')),
                ('snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['-created_at'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='PolicyRuleSettingsFindingControlQuery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('control_query', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='policy_rule_settings_finding_links', to='assessments.controlquery')),
                ('policy_rule_settings_finding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='query_links', to='assessments.policyrulesettingsfinding')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='policyrulesettingsfinding',
            name='control_queries',
            field=models.ManyToManyField(blank=True, related_name='policy_rule_settings_findings', through='assessments.PolicyRuleSettingsFindingControlQuery', to='assessments.controlquery'),
        ),
        migrations.CreateModel(
            name='VsysRulePostureFinding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('open', 'Open'), ('suppressed', 'Suppressed'), ('resolved', 'Resolved')], default='open', max_length=32)),
                ('severity', models.CharField(choices=[('informational', 'Informational'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], max_length=32)),
                ('title', models.CharField(max_length=255)),
                ('summary', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('reference_number', models.PositiveIntegerField(editable=False)),
                ('matched_query_names', models.JSONField(blank=True, default=list)),
                ('subject_name', models.CharField(blank=True, max_length=64)),
                ('subject_scope', models.CharField(blank=True, max_length=128)),
                ('assessment_run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vsys_rule_posture_findings', to='assessments.assessmentrun')),
                ('control', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='vsys_rule_posture_findings', to='assessments.control')),
                ('snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='integrations.snapshot')),
                ('vsys_rule_posture', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='integrations.vsysruleposture')),
            ],
            options={
                'ordering': ['-created_at'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='VsysRulePostureFindingControlQuery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('control_query', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vsys_rule_posture_finding_links', to='assessments.controlquery')),
                ('vsys_rule_posture_finding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='query_links', to='assessments.vsysruleposturefinding')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='vsysruleposturefinding',
            name='control_queries',
            field=models.ManyToManyField(blank=True, related_name='vsys_rule_posture_findings', through='assessments.VsysRulePostureFindingControlQuery', to='assessments.controlquery'),
        ),
        migrations.AddConstraint(
            model_name='policyrulesettingsfindingcontrolquery',
            constraint=models.UniqueConstraint(fields=('policy_rule_settings_finding', 'control_query'), name='unique_prs_finding_control_query_link'),
        ),
        migrations.AddIndex(
            model_name='policyrulesettingsfinding',
            index=models.Index(fields=['assessment_run', 'control'], name='assessments_assessm_5df422_idx'),
        ),
        migrations.AddIndex(
            model_name='policyrulesettingsfinding',
            index=models.Index(fields=['status'], name='assessments_status_162610_idx'),
        ),
        migrations.AddIndex(
            model_name='policyrulesettingsfinding',
            index=models.Index(fields=['severity'], name='assessments_severit_c4c42c_idx'),
        ),
        migrations.AddIndex(
            model_name='policyrulesettingsfinding',
            index=models.Index(fields=['policy_rule_settings'], name='assessments_policy__be032b_idx'),
        ),
        migrations.AddConstraint(
            model_name='policyrulesettingsfinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'reference_number'), name='assessments_policyrulesettingsfinding_unique_reference_per_run'),
        ),
        migrations.AddConstraint(
            model_name='policyrulesettingsfinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'control', 'policy_rule_settings'), name='unique_prs_finding_per_run_control_object'),
        ),
        migrations.AddConstraint(
            model_name='vsysruleposturefindingcontrolquery',
            constraint=models.UniqueConstraint(fields=('vsys_rule_posture_finding', 'control_query'), name='unique_vrp_finding_control_query_link'),
        ),
        migrations.AddIndex(
            model_name='vsysruleposturefinding',
            index=models.Index(fields=['assessment_run', 'control'], name='assessments_assessm_4ae5c1_idx'),
        ),
        migrations.AddIndex(
            model_name='vsysruleposturefinding',
            index=models.Index(fields=['status'], name='assessments_status_6a5d56_idx'),
        ),
        migrations.AddIndex(
            model_name='vsysruleposturefinding',
            index=models.Index(fields=['severity'], name='assessments_severit_dae485_idx'),
        ),
        migrations.AddIndex(
            model_name='vsysruleposturefinding',
            index=models.Index(fields=['vsys_rule_posture'], name='assessments_vsys_ru_b460f6_idx'),
        ),
        migrations.AddConstraint(
            model_name='vsysruleposturefinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'reference_number'), name='assessments_vsysruleposturefinding_unique_reference_per_run'),
        ),
        migrations.AddConstraint(
            model_name='vsysruleposturefinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'control', 'vsys_rule_posture'), name='unique_vrp_finding_per_run_control_object'),
        ),
    ]
