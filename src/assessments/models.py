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
    NtpSettings,
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
    ManagementInterface,
    SecurityRule,
    Snapshot,
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
        "config": "",
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
