"""The two `ha-panorama` finding models, their query links, and the widened control type.

Stage 8 of the `ha-panorama` pipeline domain. The number 0040 was ASSIGNED to this run so
that four concurrent stage 8 runs could not pick the same one; its dependency is the head
this worktree was cut from, `0037_controlquery_asserted_fields`. All four runs depend on that
same head, so at merge there are four leaves and Django refuses that - the re-chaining into a
line is the orchestrator's and happens after the four hand back. Expect this dependency line
to be rewritten.

NOTHING HERE TOUCHES A DEVICE MODEL. `HighAvailabilityConfig` and `PanoramaRegistration` are
OptivEdgeIntegrations', built by stage 7 and migrated there (`integrations.0094_ha_panorama`);
this adds only the assessment-side finding rows that point at them.

RE-CHAINED AT MERGE, FROM `0037_controlquery_asserted_fields` TO
`0039_network_hardening_findings`. All four stage 8 runs of this wave read `0037` as the head in
their own OptivEdgeAssessments worktree and wrote it as their dependency, which is correct for
each of them alone and is three leaves together - Django refuses that. The wave was landed as
0039 network-hardening, 0040 here, 0041 saas-security, and this file's dependency is the only
thing about it the merge changed. **0038 IS DELIBERATELY UNUSED**: it was assigned to
`certificates`, whose run needed no new finding model - registering a control type with no
control id to use it would ship a finding kind that can never fire, and `test_finding_registry`
would then require it for ever. The gap is that result, not a lost file.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('assessments', '0039_network_hardening_findings'),
        ('integrations', '0110_wildfire_rule_absence_is_null'),
    ]

    operations = [
        migrations.AlterField(
            model_name='control',
            name='control_type',
            field=models.CharField(choices=[('security_rule', 'Security Rule'), ('coverage', 'Coverage'), ('config', 'Configuration'), ('management_interface', 'Management Interface'), ('interface_management_profile', 'Interface Management Profile'), ('ssl_tls_service_profile', 'SSL/TLS Service Profile'), ('certificate_profile', 'Certificate Profile'), ('certificate', 'Certificate'), ('authentication_profile', 'Authentication Profile'), ('authentication_sequence', 'Authentication Sequence'), ('password_profile', 'Password Profile'), ('security_profile', 'Security Profile'), ('password_complexity', 'Minimum Password Complexity'), ('authentication_settings', 'Authentication Settings'), ('login_banner', 'Login Banner'), ('master_key', 'Master Key'), ('update_server', 'Update Server Settings'), ('logging_settings', 'Logging and Reporting Settings'), ('wildfire_settings', 'WildFire Settings'), ('management_tls', 'Management TLS'), ('management_ssh', 'Management SSH'), ('admin_user', 'Administrator'), ('server_profile', 'AAA Server Profile'), ('ntp_settings', 'NTP'), ('snmp_settings', 'SNMP'), ('system_identity', 'System Identity'), ('normalization', 'Normalization Coverage'), ('ike_crypto_profile', 'IKE Crypto Profile'), ('ike_gateway', 'IKE Gateway'), ('high_availability', 'High Availability'), ('panorama_registration', 'Panorama Registration')], default='security_rule', max_length=32),
        ),
        migrations.CreateModel(
            name='HighAvailabilityFinding',
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
                ('assessment_run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='high_availability_findings', to='assessments.assessmentrun')),
                ('control', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='high_availability_findings', to='assessments.control')),
                ('high_availability_config', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='integrations.highavailabilityconfig')),
                ('snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['-created_at'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='HighAvailabilityFindingControlQuery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('control_query', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='high_availability_finding_links', to='assessments.controlquery')),
                ('high_availability_finding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='query_links', to='assessments.highavailabilityfinding')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='highavailabilityfinding',
            name='control_queries',
            field=models.ManyToManyField(blank=True, related_name='high_availability_findings', through='assessments.HighAvailabilityFindingControlQuery', to='assessments.controlquery'),
        ),
        migrations.CreateModel(
            name='PanoramaRegistrationFinding',
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
                ('assessment_run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='panorama_registration_findings', to='assessments.assessmentrun')),
                ('control', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='panorama_registration_findings', to='assessments.control')),
                ('panorama_registration', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='integrations.panoramaregistration')),
                ('snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['-created_at'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='PanoramaRegistrationFindingControlQuery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('control_query', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='panorama_registration_finding_links', to='assessments.controlquery')),
                ('panorama_registration_finding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='query_links', to='assessments.panoramaregistrationfinding')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='panoramaregistrationfinding',
            name='control_queries',
            field=models.ManyToManyField(blank=True, related_name='panorama_registration_findings', through='assessments.PanoramaRegistrationFindingControlQuery', to='assessments.controlquery'),
        ),
        migrations.AddConstraint(
            model_name='highavailabilityfindingcontrolquery',
            constraint=models.UniqueConstraint(fields=('high_availability_finding', 'control_query'), name='unique_hacfg_finding_control_query_link'),
        ),
        migrations.AddIndex(
            model_name='highavailabilityfinding',
            index=models.Index(fields=['assessment_run', 'control'], name='assessments_assessm_b6a255_idx'),
        ),
        migrations.AddIndex(
            model_name='highavailabilityfinding',
            index=models.Index(fields=['status'], name='assessments_status_e77eb2_idx'),
        ),
        migrations.AddIndex(
            model_name='highavailabilityfinding',
            index=models.Index(fields=['severity'], name='assessments_severit_abecb4_idx'),
        ),
        migrations.AddIndex(
            model_name='highavailabilityfinding',
            index=models.Index(fields=['high_availability_config'], name='assessments_high_av_c54a66_idx'),
        ),
        migrations.AddConstraint(
            model_name='highavailabilityfinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'reference_number'), name='assessments_highavailabilityfinding_unique_reference_per_run'),
        ),
        migrations.AddConstraint(
            model_name='highavailabilityfinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'control', 'high_availability_config'), name='unique_hacfg_finding_per_run_control_object'),
        ),
        migrations.AddConstraint(
            model_name='panoramaregistrationfindingcontrolquery',
            constraint=models.UniqueConstraint(fields=('panorama_registration_finding', 'control_query'), name='unique_panoreg_finding_control_query_link'),
        ),
        migrations.AddIndex(
            model_name='panoramaregistrationfinding',
            index=models.Index(fields=['assessment_run', 'control'], name='assessments_assessm_f6d3a4_idx'),
        ),
        migrations.AddIndex(
            model_name='panoramaregistrationfinding',
            index=models.Index(fields=['status'], name='assessments_status_abb3d7_idx'),
        ),
        migrations.AddIndex(
            model_name='panoramaregistrationfinding',
            index=models.Index(fields=['severity'], name='assessments_severit_0980fb_idx'),
        ),
        migrations.AddIndex(
            model_name='panoramaregistrationfinding',
            index=models.Index(fields=['panorama_registration'], name='assessments_panoram_22875a_idx'),
        ),
        migrations.AddConstraint(
            model_name='panoramaregistrationfinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'reference_number'), name='assessments_panoramaregistrationfinding_unique_reference_per_run'),
        ),
        migrations.AddConstraint(
            model_name='panoramaregistrationfinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'control', 'panorama_registration'), name='unique_panoreg_finding_per_run_control_object'),
        ),
    ]
