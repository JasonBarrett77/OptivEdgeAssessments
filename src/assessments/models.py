"""Assessment app models."""

from __future__ import annotations

import uuid

from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.text import slugify

from optivedge.models import ApplicationEnvironment
from optivedge_integrations.integrations.models import (
    DeviceConfigurationProfile,
    SecurityRule,
)


class SecurityRuleSearchState(models.Model):
    """Server-side state for structured security-rule searches."""

    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False, db_index=True)
    query_text = models.TextField(blank=True)
    canonical_query = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return str(self.token)


class Control(models.Model):
    class ControlType(models.TextChoices):
        SECURITY_RULE = "security_rule", "Security Rule"
        CONFIG = "config", "Configuration"
        DEVICE_CONFIGURATION = "device_configuration", "Device Configuration"

    class Severity(models.TextChoices):
        INFORMATIONAL = "informational", "Informational"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    control_id = models.CharField(max_length=128, unique=True)
    name = models.CharField(max_length=255)
    control_type = models.CharField(
        max_length=32,
        choices=ControlType.choices,
        default=ControlType.SECURITY_RULE,
    )
    description = models.TextField()
    rationale = models.TextField(blank=True)
    audit = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
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

    _CONTROL_TYPE_TARGET_MODEL = {
        "security_rule": "integrations.SecurityRule",
        "device_configuration": "integrations.DeviceConfigurationProfile",
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
        "integrations.SecurityRule": "Security Rule",
        "integrations.DeviceConfigurationProfile": "Device Configuration",
    }

    @property
    def assessment_target_label(self) -> str:
        return self._TARGET_MODEL_LABELS.get(self.target_model, "Configuration")

    @property
    def supports_security_rule_ui(self) -> bool:
        return self.target_model == "integrations.SecurityRule"

    @property
    def supports_device_configuration_ui(self) -> bool:
        return self.target_model == "integrations.DeviceConfigurationProfile"


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


class ControlQuery(models.Model):
    control = models.ForeignKey(
        Control,
        on_delete=models.CASCADE,
        related_name="queries",
    )
    name = models.CharField(max_length=255)
    short_description = models.CharField(max_length=255, blank=True)
    canonical_query = models.JSONField(default=dict)
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


class RuleFinding(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        SUPPRESSED = "suppressed", "Suppressed"
        RESOLVED = "resolved", "Resolved"

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
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.OPEN,
    )
    severity = models.CharField(
        max_length=32,
        choices=Control.Severity.choices,
    )
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    # Point-in-time snapshot of the names of the control queries that matched this rule,
    # frozen at generation time. Kept separate from the live control_queries M2M (whose
    # names/links follow later catalog edits and deletes) so a finding stays a faithful
    # record of its assessment run.
    matched_query_names = models.JSONField(default=list, blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery,
        through="RuleFindingControlQuery",
        related_name="rule_findings",
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["assessment_run", "control"]),
            models.Index(fields=["security_rule"]),
            models.Index(fields=["status"]),
            models.Index(fields=["severity"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "security_rule"],
                name="unique_rule_finding_per_run_control_rule",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on rule {self.security_rule_id}"


class RuleFindingControlQuery(models.Model):
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
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["rule_finding", "control_query"],
                name="unique_rule_finding_control_query_link",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.rule_finding_id} <- {self.control_query_id}"


class DeviceConfigurationFinding(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        SUPPRESSED = "suppressed", "Suppressed"
        RESOLVED = "resolved", "Resolved"

    assessment_run = models.ForeignKey(
        AssessmentRun,
        on_delete=models.CASCADE,
        related_name="device_configuration_findings",
    )
    control = models.ForeignKey(
        Control,
        on_delete=models.PROTECT,
        related_name="device_configuration_findings",
    )
    device_configuration_profile = models.ForeignKey(
        DeviceConfigurationProfile,
        on_delete=models.CASCADE,
        related_name="findings",
    )
    status = models.CharField(
        max_length=32,
        choices=Status.choices,
        default=Status.OPEN,
    )
    severity = models.CharField(
        max_length=32,
        choices=Control.Severity.choices,
    )
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    control_queries = models.ManyToManyField(
        ControlQuery,
        through="DeviceConfigurationFindingControlQuery",
        related_name="device_configuration_findings",
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["assessment_run", "control"]),
            models.Index(fields=["device_configuration_profile"]),
            models.Index(fields=["status"]),
            models.Index(fields=["severity"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "device_configuration_profile"],
                name="unique_device_configuration_finding_per_run_control_profile",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on profile {self.device_configuration_profile_id}"


class DeviceConfigurationFindingControlQuery(models.Model):
    device_configuration_finding = models.ForeignKey(
        DeviceConfigurationFinding,
        on_delete=models.CASCADE,
        related_name="query_links",
    )
    control_query = models.ForeignKey(
        ControlQuery,
        on_delete=models.CASCADE,
        related_name="device_configuration_finding_links",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["device_configuration_finding", "control_query"],
                name="unique_device_configuration_finding_control_query_link",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.device_configuration_finding_id} <- {self.control_query_id}"


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
