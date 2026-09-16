"""Give every finding a reference number, unique within its run across all finding models.

Existing findings are numbered here so the column can be required. The order - by run, then the
finding models in `finding_run.GENERATORS` order, then control, then row - is the one a fresh run
allocates in, so a database that is migrated and then regenerated reads the same way throughout.
The model list is written out rather than imported: a migration must not change when app code does.
"""

from django.db import migrations, models

#: `finding_run.GENERATORS` order on 2026-09-16, security rules last.
FINDING_MODELS_IN_RUN_ORDER = (
    "passwordcomplexityfinding",
    "authenticationsettingsfinding",
    "loginbannerfinding",
    "managementtlsfinding",
    "managementsshfinding",
    "masterkeyfinding",
    "updateserversettingsfinding",
    "loggingsettingsfinding",
    "ntpsettingsfinding",
    "snmpsettingsfinding",
    "systemidentityfinding",
    "managementinterfacefinding",
    "interfacemanagementprofilefinding",
    "ssltlsserviceprofilefinding",
    "certificateprofilefinding",
    "certificatefinding",
    "authenticationprofilefinding",
    "authenticationsequencefinding",
    "passwordprofilefinding",
    "securityprofilefinding",
    "adminuserfinding",
    "serverprofilefinding",
    "rulefinding",
)


def number_existing_findings(apps, schema_editor):
    next_number = {}  # run id -> next free number
    for model_name in FINDING_MODELS_IN_RUN_ORDER:
        model = apps.get_model("assessments", model_name)
        for finding in model.objects.order_by("assessment_run_id", "control__control_id", "pk"):
            number = next_number.get(finding.assessment_run_id, 1)
            model.objects.filter(pk=finding.pk).update(reference_number=number)
            next_number[finding.assessment_run_id] = number + 1


class Migration(migrations.Migration):

    dependencies = [
        ("assessments", "0026_alter_control_control_type_ntpsettingsfinding_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="passwordcomplexityfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="authenticationsettingsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="loginbannerfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="managementtlsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="managementsshfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="masterkeyfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="updateserversettingsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="loggingsettingsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="ntpsettingsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="snmpsettingsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="systemidentityfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="managementinterfacefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="interfacemanagementprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="ssltlsserviceprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="certificateprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="certificatefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="authenticationprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="authenticationsequencefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="passwordprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="securityprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="adminuserfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="serverprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="rulefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.RunPython(number_existing_findings, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="passwordcomplexityfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="passwordcomplexityfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_passwordcomplexityfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="authenticationsettingsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="authenticationsettingsfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_authenticationsettingsfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="loginbannerfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="loginbannerfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_loginbannerfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="managementtlsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="managementtlsfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_managementtlsfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="managementsshfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="managementsshfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_managementsshfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="masterkeyfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="masterkeyfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_masterkeyfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="updateserversettingsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="updateserversettingsfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_updateserversettingsfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="loggingsettingsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="loggingsettingsfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_loggingsettingsfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="ntpsettingsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="ntpsettingsfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_ntpsettingsfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="snmpsettingsfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="snmpsettingsfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_snmpsettingsfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="systemidentityfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="systemidentityfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_systemidentityfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="managementinterfacefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="managementinterfacefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_managementinterfacefinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="interfacemanagementprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="interfacemanagementprofilefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_interfacemanagementprofilefinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="ssltlsserviceprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="ssltlsserviceprofilefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_ssltlsserviceprofilefinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="certificateprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="certificateprofilefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_certificateprofilefinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="certificatefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="certificatefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_certificatefinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="authenticationprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="authenticationprofilefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_authenticationprofilefinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="authenticationsequencefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="authenticationsequencefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_authenticationsequencefinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="passwordprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="passwordprofilefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_passwordprofilefinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="securityprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="securityprofilefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_securityprofilefinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="adminuserfinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="adminuserfinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_adminuserfinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="serverprofilefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="serverprofilefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_serverprofilefinding_unique_reference_per_run",
            ),
        ),
        migrations.AlterField(
            model_name="rulefinding",
            name="reference_number",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="rulefinding",
            constraint=models.UniqueConstraint(
                fields=("assessment_run", "reference_number"),
                name="assessments_rulefinding_unique_reference_per_run",
            ),
        ),
    ]
