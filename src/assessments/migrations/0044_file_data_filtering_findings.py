"""`file-data-filtering`'s stage 8: ONE new finding model and ONE new control type.

THE NUMBER WAS TAKEN IMMEDIATELY BEFORE WRITING with `ls src/assessments/migrations/ | tail -3`,
not from the dispatch brief, which named `0043_device_id_iot_findings` as the leaf at dispatch and
was right. Two domains both claiming the next number collide and neither migrates.

THIS CARRIES ITS OWN `AlterField` ON `Control.control_type` AND THAT IS ONLY SAFE BECAUSE THIS IS
A WAVE OF ONE. Migration 0042 exists because four concurrent stage 8 runs each generated an
`AlterField` declaring the choices as they stood in its own worktree - every one correct alone,
none correct on the merged tree - so the orchestrator had to declare the union once. This run is
the only stage 8 domain in flight against this leaf; it adds ONE type, bringing the field to 45,
and `makemigrations --check --dry-run` is clean after it. A SECOND DOMAIN LANDING BESIDE THIS ONE
WOULD NEED THE 0042 TREATMENT AGAIN; nothing here prevents that and this comment is the warning.

ONE TYPE AND NOT TWO, which is the decision this migration records. The domain has two models.
`integrations.SecurityProfile` ALREADY HAD `security_profile`, a finding model, a generator and
the largest search compiler in the tree, so PAN-FIL-001, -002 and -004 reuse it and add no type -
a type maps to one model and many controls may share one, as PAN-IOT-001/003 and PAN-AVW-006 do,
while a SECOND type for one model is what `_CONTROL_TYPE_TARGET_MODEL`'s one-to-one property
forbids and nothing in the suite catches. `integrations.DataFilteringPosture` had no type, no
finding model and no compiler; only PAN-FIL-003 touches it, and only the first of that control's
two halves.

NO `integrations` COLUMN IS ADDED OR ALTERED HERE. Every column these controls query shipped in
OEI `0096_file_data_filtering`, this domain's stage 7 work, which is in the main checkout and
applied. Stage 8 may not change a normaliser or a model's columns.
"""


import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('assessments', '0043_device_id_iot_findings'),
        ('integrations', '0121_zone_dos_protection'),
    ]

    operations = [
        migrations.AlterField(
            model_name='control',
            name='control_type',
            field=models.CharField(choices=[('security_rule', 'Security Rule'), ('coverage', 'Coverage'), ('config', 'Configuration'), ('management_interface', 'Management Interface'), ('interface_management_profile', 'Interface Management Profile'), ('ssl_tls_service_profile', 'SSL/TLS Service Profile'), ('certificate_profile', 'Certificate Profile'), ('certificate', 'Certificate'), ('authentication_profile', 'Authentication Profile'), ('authentication_sequence', 'Authentication Sequence'), ('password_profile', 'Password Profile'), ('security_profile', 'Security Profile'), ('password_complexity', 'Minimum Password Complexity'), ('authentication_settings', 'Authentication Settings'), ('login_banner', 'Login Banner'), ('master_key', 'Master Key'), ('update_server', 'Update Server Settings'), ('logging_settings', 'Logging and Reporting Settings'), ('wildfire_settings', 'WildFire Settings'), ('management_tls', 'Management TLS'), ('management_ssh', 'Management SSH'), ('admin_user', 'Administrator'), ('server_profile', 'AAA Server Profile'), ('ntp_settings', 'NTP'), ('snmp_settings', 'SNMP'), ('system_identity', 'System Identity'), ('normalization', 'Normalization Coverage'), ('ike_crypto_profile', 'IKE Crypto Profile'), ('ike_gateway', 'IKE Gateway'), ('high_availability', 'High Availability'), ('panorama_registration', 'Panorama Registration'), ('firewall_interface', 'Interface'), ('session_settings', 'Session Settings'), ('lldp_global', 'Global LLDP'), ('dhcp_interface_config', 'DHCP Interface Configuration'), ('tunnel_inspection', 'Tunnel Inspection Coverage'), ('routing_adjacency', 'Routing Adjacency'), ('sanctioned_application_marking', 'Sanctioned Application Marking'), ('saas_url_filtering_posture', 'SaaS URL Filtering Posture'), ('saas_application_policy_posture', 'SaaS Application Policy Posture'), ('cloud_app_engine_setting', 'App-ID Cloud Engine'), ('device_identification', 'Device Identification'), ('zone', 'Security Zone'), ('rulebase_device_match', 'Rulebase Device Match'), ('data_filtering_posture', 'Data Filtering Posture')], default='security_rule', max_length=32),
        ),
        migrations.CreateModel(
            name='DataFilteringPostureFinding',
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
                ('assessment_run', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='data_filtering_posture_findings', to='assessments.assessmentrun')),
                ('control', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='data_filtering_posture_findings', to='assessments.control')),
                ('data_filtering_posture', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='findings', to='integrations.datafilteringposture')),
                ('snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='integrations.snapshot')),
            ],
            options={
                'ordering': ['-created_at'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='DataFilteringPostureFindingControlQuery',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('control_query', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='data_filtering_posture_finding_links', to='assessments.controlquery')),
                ('data_filtering_posture_finding', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='query_links', to='assessments.datafilteringposturefinding')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='datafilteringposturefinding',
            name='control_queries',
            field=models.ManyToManyField(blank=True, related_name='data_filtering_posture_findings', through='assessments.DataFilteringPostureFindingControlQuery', to='assessments.controlquery'),
        ),
        migrations.AddConstraint(
            model_name='datafilteringposturefindingcontrolquery',
            constraint=models.UniqueConstraint(fields=('data_filtering_posture_finding', 'control_query'), name='unique_dfp_finding_control_query_link'),
        ),
        migrations.AddIndex(
            model_name='datafilteringposturefinding',
            index=models.Index(fields=['assessment_run', 'control'], name='assessments_assessm_11c869_idx'),
        ),
        migrations.AddIndex(
            model_name='datafilteringposturefinding',
            index=models.Index(fields=['status'], name='assessments_status_1bd1d6_idx'),
        ),
        migrations.AddIndex(
            model_name='datafilteringposturefinding',
            index=models.Index(fields=['severity'], name='assessments_severit_873b1d_idx'),
        ),
        migrations.AddIndex(
            model_name='datafilteringposturefinding',
            index=models.Index(fields=['data_filtering_posture'], name='assessments_data_fi_3dff91_idx'),
        ),
        migrations.AddConstraint(
            model_name='datafilteringposturefinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'reference_number'), name='assessments_datafilteringposturefinding_unique_reference_per_run'),
        ),
        migrations.AddConstraint(
            model_name='datafilteringposturefinding',
            constraint=models.UniqueConstraint(fields=('assessment_run', 'control', 'data_filtering_posture'), name='unique_dfp_finding_per_run_control_object'),
        ),
    ]
