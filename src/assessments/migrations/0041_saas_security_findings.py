"""The four `saas-security` finding models, their query links, and the four control types.

PAN-SAS-001 to 005. THE MIGRATION NUMBER IS ASSIGNED AND NOT SEQUENTIAL: this was generated as
0038 and renamed, because four stage 8 runs were in flight in four worktrees of this repository
at once and each was given a number so that no two picked the same one. `dependencies` names the
head this worktree was cut from, and re-chaining the four leaves into a line happens at merge -
Django refuses four leaf migrations on one app.

THREE REGISTRATIONS PER SUBJECT AND TWO OF THEM ARE SILENT WHEN MISSED. This migration is the
visible half of one: the `ControlType` enum. The other two - `_CONTROL_TYPE_TARGET_MODEL` and
`finding_registry.FINDING_KINDS` - are not migrated at all, and a type added to the enum without
the map has its `target_model` silently emptied on every save, which reads as permanent catalog
drift because the payload carries the value and the live row does not.

PAN-SAS-002 AND PAN-SAS-004 SHARE ONE CONTROL TYPE, so there are five controls and four types.
Two control types cannot name one model: `finding_registry` is keyed by model and
`generate_object_findings` selects controls by type, so a second type over one model would need a
second finding model for the same subject.

NOTHING HERE TOUCHES THE `integrations` TABLES. The four subject models were migrated by
OptivEdgeIntegrations `0107_saas_security`; this adds only the assessment-side finding rows that
point at them.

RE-CHAINED AT MERGE, FROM `0037_controlquery_asserted_fields` TO `0040_ha_panorama_findings`, for
the reason `0040` records: all four runs of this wave read `0037` as the head in their own
worktree, which is right for each alone and is three leaves together. The line is 0039
network-hardening, 0040 ha-panorama, 0041 here, with 0038 deliberately unused.
"""


import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('assessments', '0040_ha_panorama_findings'),
        ('integrations', '0110_wildfire_rule_absence_is_null'),
    ]

    operations = [
        migrations.AlterField(
            model_name='control',
            name='control_type',
            field=models.CharField(choices=[('security_rule', 'Security Rule'), ('coverage', 'Coverage'), ('config', 'Configuration'), ('management_interface', 'Management Interface'), ('interface_management_profile', 'Interface Management Profile'), ('ssl_tls_service_profile', 'SSL/TLS Service Profile'), ('certificate_profile', 'Certificate Profile'), ('certificate', 'Certificate'), ('authentication_profile', 'Authentication Profile'), ('authentication_sequence', 'Authentication Sequence'), ('password_profile', 'Password Profile'), ('security_profile', 'Security Profile'), ('password_complexity', 'Minimum Password Complexity'), ('authentication_settings', 'Authentication Settings'), ('login_banner', 'Login Banner'), ('master_key', 'Master Key'), ('update_server', 'Update Server Settings'), ('logging_settings', 'Logging and Reporting Settings'), ('wildfire_settings', 'WildFire Settings'), ('management_tls', 'Management TLS'), ('management_ssh', 'Management SSH'), ('admin_user', 'Administrator'), ('server_profile', 'AAA Server Profile'), ('ntp_settings', 'NTP'), ('snmp_settings', 'SNMP'), ('system_identity', 'System Identity'), ('normalization', 'Normalization Coverage'), ('ike_crypto_profile', 'IKE Crypto Profile'), ('ike_gateway', 'IKE Gateway'), ('sanctioned_application_marking', 'Sanctioned Application Marking'), ('saas_url_filtering_posture', 'SaaS URL Filtering Posture'), ('saas_application_policy_posture', 'SaaS Application Policy Posture'), ('cloud_app_engine_setting', 'App-ID Cloud Engine')], default='security_rule', max_length=32),
        ),
        migrations.CreateModel(
            name='CloudAppEngineFinding',
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
                ('assessment_run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='cloud_app_engine_findings', to='assessments.assessmentrun')),
                ('cloud_app_engine_setting', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='integrations.cloudappenginesetting')),
                ('control', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='cloud_app_engine_findings', to='assessments.control')),
                ('snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['-created_at'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='CloudAppEngineFindingControlQuery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('cloud_app_engine_finding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='query_links', to='assessments.cloudappenginefinding')),
                ('control_query', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='cloud_app_engine_finding_links', to='assessments.controlquery')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='cloudappenginefinding',
            name='control_queries',
            field=models.ManyToManyField(blank=True, related_name='cloud_app_engine_findings', through='assessments.CloudAppEngineFindingControlQuery', to='assessments.controlquery'),
        ),
        migrations.CreateModel(
            name='SaasApplicationPolicyPostureFinding',
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
                ('assessment_run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saas_application_policy_posture_findings', to='assessments.assessmentrun')),
                ('control', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='saas_application_policy_posture_findings', to='assessments.control')),
                ('saas_application_policy_posture', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='integrations.saasapplicationpolicyposture')),
                ('snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['-created_at'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='SaasApplicationPolicyPostureFindingControlQuery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('control_query', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saas_application_policy_posture_finding_links', to='assessments.controlquery')),
                ('saas_application_policy_posture_finding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='query_links', to='assessments.saasapplicationpolicyposturefinding')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='saasapplicationpolicyposturefinding',
            name='control_queries',
            field=models.ManyToManyField(blank=True, related_name='saas_application_policy_posture_findings', through='assessments.SaasApplicationPolicyPostureFindingControlQuery', to='assessments.controlquery'),
        ),
        migrations.CreateModel(
            name='SaasUrlFilteringPostureFinding',
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
                ('assessment_run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saas_url_filtering_posture_findings', to='assessments.assessmentrun')),
                ('control', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='saas_url_filtering_posture_findings', to='assessments.control')),
                ('saas_url_filtering_posture', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='integrations.saasurlfilteringposture')),
                ('snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['-created_at'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='SaasUrlFilteringPostureFindingControlQuery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('control_query', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='saas_url_filtering_posture_finding_links', to='assessments.controlquery')),
                ('saas_url_filtering_posture_finding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='query_links', to='assessments.saasurlfilteringposturefinding')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='saasurlfilteringposturefinding',
            name='control_queries',
            field=models.ManyToManyField(blank=True, related_name='saas_url_filtering_posture_findings', through='assessments.SaasUrlFilteringPostureFindingControlQuery', to='assessments.controlquery'),
        ),
        migrations.CreateModel(
            name='SanctionedApplicationMarkingFinding',
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
                ('assessment_run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sanctioned_application_marking_findings', to='assessments.assessmentrun')),
                ('control', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='sanctioned_application_marking_findings', to='assessments.control')),
                ('sanctioned_application_marking', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='integrations.sanctionedapplicationmarking')),
                ('snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['-created_at'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='SanctionedApplicationMarkingFindingControlQuery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('control_query', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sanctioned_application_marking_finding_links', to='assessments.controlquery')),
                ('sanctioned_application_marking_finding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='query_links', to='assessments.sanctionedapplicationmarkingfinding')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='sanctionedapplicationmarkingfinding',
            name='control_queries',
            field=models.ManyToManyField(blank=True, related_name='sanctioned_application_marking_findings', through='assessments.SanctionedApplicationMarkingFindingControlQuery', to='assessments.controlquery'),
        ),
        migrations.AddConstraint(
            model_name='cloudappenginefindingcontrolquery',
            constraint=models.UniqueConstraint(fields=('cloud_app_engine_finding', 'control_query'), name='unique_sasace_finding_control_query_link'),
        ),
        migrations.AddIndex(
            model_name='cloudappenginefinding',
            index=models.Index(fields=['assessment_run', 'control'], name='assessments_assessm_31928f_idx'),
        ),
        migrations.AddIndex(
            model_name='cloudappenginefinding',
            index=models.Index(fields=['status'], name='assessments_status_333e01_idx'),
        ),
        migrations.AddIndex(
            model_name='cloudappenginefinding',
            index=models.Index(fields=['severity'], name='assessments_severit_bfec92_idx'),
        ),
        migrations.AddIndex(
            model_name='cloudappenginefinding',
            index=models.Index(fields=['cloud_app_engine_setting'], name='assessments_cloud_a_9ee79d_idx'),
        ),
        migrations.AddConstraint(
            model_name='cloudappenginefinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'reference_number'), name='assessments_cloudappenginefinding_unique_reference_per_run'),
        ),
        migrations.AddConstraint(
            model_name='cloudappenginefinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'control', 'cloud_app_engine_setting'), name='unique_sasace_finding_per_run_control_object'),
        ),
        migrations.AddConstraint(
            model_name='saasapplicationpolicyposturefindingcontrolquery',
            constraint=models.UniqueConstraint(fields=('saas_application_policy_posture_finding', 'control_query'), name='unique_sasapp_finding_control_query_link'),
        ),
        migrations.AddIndex(
            model_name='saasapplicationpolicyposturefinding',
            index=models.Index(fields=['assessment_run', 'control'], name='assessments_assessm_6cfc3e_idx'),
        ),
        migrations.AddIndex(
            model_name='saasapplicationpolicyposturefinding',
            index=models.Index(fields=['status'], name='assessments_status_9dc6e4_idx'),
        ),
        migrations.AddIndex(
            model_name='saasapplicationpolicyposturefinding',
            index=models.Index(fields=['severity'], name='assessments_severit_7d5a68_idx'),
        ),
        migrations.AddIndex(
            model_name='saasapplicationpolicyposturefinding',
            index=models.Index(fields=['saas_application_policy_posture'], name='assessments_saas_ap_aa2c5a_idx'),
        ),
        migrations.AddConstraint(
            model_name='saasapplicationpolicyposturefinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'reference_number'), name='assessments_saasapplicationpolicyposturefinding_unique_reference_per_run'),
        ),
        migrations.AddConstraint(
            model_name='saasapplicationpolicyposturefinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'control', 'saas_application_policy_posture'), name='unique_sasapp_finding_per_run_control_object'),
        ),
        migrations.AddConstraint(
            model_name='saasurlfilteringposturefindingcontrolquery',
            constraint=models.UniqueConstraint(fields=('saas_url_filtering_posture_finding', 'control_query'), name='unique_sasurl_finding_control_query_link'),
        ),
        migrations.AddIndex(
            model_name='saasurlfilteringposturefinding',
            index=models.Index(fields=['assessment_run', 'control'], name='assessments_assessm_af2fbe_idx'),
        ),
        migrations.AddIndex(
            model_name='saasurlfilteringposturefinding',
            index=models.Index(fields=['status'], name='assessments_status_7d5cca_idx'),
        ),
        migrations.AddIndex(
            model_name='saasurlfilteringposturefinding',
            index=models.Index(fields=['severity'], name='assessments_severit_f9d790_idx'),
        ),
        migrations.AddIndex(
            model_name='saasurlfilteringposturefinding',
            index=models.Index(fields=['saas_url_filtering_posture'], name='assessments_saas_ur_0b69a1_idx'),
        ),
        migrations.AddConstraint(
            model_name='saasurlfilteringposturefinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'reference_number'), name='assessments_saasurlfilteringposturefinding_unique_reference_per_run'),
        ),
        migrations.AddConstraint(
            model_name='saasurlfilteringposturefinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'control', 'saas_url_filtering_posture'), name='unique_sasurl_finding_per_run_control_object'),
        ),
        migrations.AddConstraint(
            model_name='sanctionedapplicationmarkingfindingcontrolquery',
            constraint=models.UniqueConstraint(fields=('sanctioned_application_marking_finding', 'control_query'), name='unique_sasmark_finding_control_query_link'),
        ),
        migrations.AddIndex(
            model_name='sanctionedapplicationmarkingfinding',
            index=models.Index(fields=['assessment_run', 'control'], name='assessments_assessm_975690_idx'),
        ),
        migrations.AddIndex(
            model_name='sanctionedapplicationmarkingfinding',
            index=models.Index(fields=['status'], name='assessments_status_89bbf7_idx'),
        ),
        migrations.AddIndex(
            model_name='sanctionedapplicationmarkingfinding',
            index=models.Index(fields=['severity'], name='assessments_severit_135691_idx'),
        ),
        migrations.AddIndex(
            model_name='sanctionedapplicationmarkingfinding',
            index=models.Index(fields=['sanctioned_application_marking'], name='assessments_sanctio_43ac26_idx'),
        ),
        migrations.AddConstraint(
            model_name='sanctionedapplicationmarkingfinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'reference_number'), name='assessments_sanctionedapplicationmarkingfinding_unique_reference_per_run'),
        ),
        migrations.AddConstraint(
            model_name='sanctionedapplicationmarkingfinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'control', 'sanctioned_application_marking'), name='unique_sasmark_finding_per_run_control_object'),
        ),
    ]
