"""Assessment app models."""

from __future__ import annotations

import uuid

from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.text import slugify

from optivedge.models import ApplicationEnvironment
from optivedge_integrations.integrations.models import (
    AuthenticationProfile,
    Certificate,
    CertificateProfile,
    SslTlsServiceProfile,
    InterfaceManagementProfile,
    DeviceConfigurationProfile,
    ManagementInterface,
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
        MANAGEMENT_INTERFACE = "management_interface", "Management Interface"
        INTERFACE_MANAGEMENT_PROFILE = "interface_management_profile", "Interface Management Profile"
        SSL_TLS_SERVICE_PROFILE = "ssl_tls_service_profile", "SSL/TLS Service Profile"
        CERTIFICATE_PROFILE = "certificate_profile", "Certificate Profile"
        CERTIFICATE = "certificate", "Certificate"
        AUTHENTICATION_PROFILE = "authentication_profile", "Authentication Profile"

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
    #: Graded severity from the corpus: bands, sentinels and ranks. Empty means the control
    #: reports `default_severity` for every finding, which is what all 30 controls did before
    #: this existed. See `severity_for_measure`.
    severity_scale = models.JSONField(default=dict, blank=True)
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
        "device_configuration": "integrations.DeviceConfigurationProfile",
        "management_interface": "integrations.ManagementInterface",
        "interface_management_profile": "integrations.InterfaceManagementProfile",
        "ssl_tls_service_profile": "integrations.SslTlsServiceProfile",
        "certificate_profile": "integrations.CertificateProfile",
        "certificate": "integrations.Certificate",
        "authentication_profile": "integrations.AuthenticationProfile",
        "config": "",
    }

    class Meta:
        ordering = ["control_id"]

    #: Worst first, so capping is a list-position comparison.
    _SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")

    def severity_for_measure(self, measure):
        """Severity for one measured value, or None to fall back to `default_severity`.

        The corpus grades 25 controls and this app reported `default_severity` for all of
        them, so a 4-character password and an 11-character one arrived identical. The bands
        are the corpus author's judgement and are not re-derived here.

        Three rules, in this order, and the order is the whole thing:

        SENTINELS FIRST, because PAN-OS overloads these fields and the overloaded value is not
        on the scale at all. `failed-attempts 0` means lockout is DISABLED and `idle-timeout 0`
        means sessions never expire - both worse than any large number, so a band lookup would
        rank them as the best possible value. Sentinels are strings in the corpus and are
        compared as strings.

        THEN BANDS, keyed by `direction`: `higher-is-worse` bands carry `min` and are listed
        worst first; `lower-is-worse` bands carry `max` and are listed best first. A null bound
        is open-ended. `direction` SELECTS THE KEY - that is its documented meaning - and it is
        not always the semantic reading: PAN-AUTH-014 is labelled `lower-is-worse` while its own
        band labels say more attempts is worse. The keys are unambiguous, the label is not.

        NEVER ABOVE `default_severity`. The corpus promises "a step severity never exceeds the
        control severity, so the headline is always safe to report unmeasured"; a scale that
        could escalate would quietly break that.

        A null band severity means the value MEETS the baseline. That returns None, and no
        finding should exist for it anyway - the query decides whether there IS a finding, this
        decides only how bad it is.
        """
        scale = self.severity_scale or {}
        if not scale or measure is None:
            return None

        for sentinel in scale.get("sentinels") or []:
            if str(sentinel.get("value")) == str(measure):
                return self._capped(sentinel.get("severity"))

        kind = scale.get("kind")
        if kind == "ranked":
            for rank in scale.get("ranks") or []:
                if str(rank.get("value")) == str(measure):
                    return self._capped(rank.get("severity"))
            return None
        if kind != "numeric":
            return None

        try:
            value = int(measure)
        except (TypeError, ValueError):
            return None
        key = "min" if scale.get("direction") == "higher-is-worse" else "max"
        for band in scale.get("bands") or []:
            bound = band.get(key)
            if bound is None:
                return self._capped(band.get("severity"))
            if key == "min" and value >= bound:
                return self._capped(band.get("severity"))
            if key == "max" and value <= bound:
                return self._capped(band.get("severity"))
        return None

    def _capped(self, severity):
        """A band never reports worse than the control's own severity."""
        if not severity:
            return None
        order = self._SEVERITY_ORDER
        if severity not in order or self.default_severity not in order:
            return severity
        return (severity if order.index(severity) >= order.index(self.default_severity)
                else self.default_severity)

    def measured_field(self):
        """The model field this control's baseline query reads, or None if not exactly one.

        Derived rather than declared, for the reason the password tab derives its highlighting:
        a second place naming the field would drift from the query the first time a threshold
        moved. A control reading two different fields has no single measure and is not graded.
        """
        fields = set()
        for query in self.queries.all():
            for clause in (query.canonical_query or {}).get("clauses") or []:
                if clause.get("field"):
                    fields.add(clause["field"])
        return next(iter(fields)) if len(fields) == 1 else None

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
        "integrations.ManagementInterface": "Management Interface",
        "integrations.InterfaceManagementProfile": "Interface Management Profile",
        "integrations.SslTlsServiceProfile": "SSL/TLS Service Profile",
        "integrations.CertificateProfile": "Certificate Profile",
        "integrations.Certificate": "Certificate",
        "integrations.AuthenticationProfile": "Authentication Profile",
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

    class Meta:
        abstract = True
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["assessment_run", "control"]),
            models.Index(fields=["status"]),
            models.Index(fields=["severity"]),
        ]


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


class RuleFinding(FindingBase):
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

    class Meta(FindingBase.Meta):
        indexes = FindingBase.Meta.indexes + [
            models.Index(fields=["security_rule"]),
        ]
        constraints = [
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


class DeviceConfigurationFinding(FindingBase):
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
    control_queries = models.ManyToManyField(
        ControlQuery,
        through="DeviceConfigurationFindingControlQuery",
        related_name="device_configuration_findings",
        blank=True,
    )

    class Meta(FindingBase.Meta):
        indexes = FindingBase.Meta.indexes + [
            models.Index(fields=["device_configuration_profile"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "device_configuration_profile"],
                name="unique_device_configuration_finding_per_run_control_profile",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on profile {self.device_configuration_profile_id}"


class DeviceConfigurationFindingControlQuery(FindingControlQueryBase):
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

    class Meta(FindingControlQueryBase.Meta):
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
        constraints = [
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
        constraints = [
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
        constraints = [
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
        constraints = [
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
        constraints = [
            models.UniqueConstraint(
                fields=["assessment_run", "control", "certificate"],
                name="unique_cert_finding_per_run_control_object"),
        ]

    def __str__(self) -> str:
        return f"{self.control.control_id} on certificate {self.subject_name}"


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
        constraints = [
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
