"""Assessment-facing views.

This module owns read-oriented assessment surfaces built on top of normalized
integration data. Keep collector and normalization logic in `integrations`.
"""

import datetime as _dt
import json
from urllib.parse import urlencode

from collections import defaultdict

from assessments.artifacts import (
    ALL_TESTED_COLUMNS,
    ArtifactBuildError,
    build_findings_table,
)
from assessments.artifacts import domains as artifact_domains
from assessments.artifacts.layout import category_of as artifact_category_of
from assessments.environment import get_application_environment
from assessments.forms import ControlForm, ControlQueryForm
from assessments.control_queries import (
    SECURITY_RULE_QUERY_MODEL,
    default_security_rule_search_query,
    evaluate_control_queries,
    evaluate_queryset_control_queries,
    severity_label,
)
from assessments.finding_run import regenerate_findings
from assessments.controls_catalog.drift import catalog_has_drifted
from assessments.management_interface_naming import surface_label
from assessments.tables import Column
from assessments import configuration_navigation as config_nav
from assessments import configuration_dashboard
from assessments import configuration_results as config_results
from assessments import configuration_selection as selection_module
from django.contrib.contenttypes.models import ContentType

from assessments.search.security_rules.fields.address_semantic import (
    SUPPORTED_OPERATORS as ADDRESS_SEMANTIC_OPERATORS,
)
from assessments.search.management_interface.fields.services import (
    ADMINISTRATIVE_SERVICES,
    INSECURE_SERVICES,
)
from assessments.search.management_interface.fields.exposure import (
    exposure_by_interface,
)
from assessments.models import (
    AssessmentRun,
    AuthenticationProfileFinding,
    AuthenticationSequenceFinding,
    AdminUserFinding,
    ServerProfileFinding,
    AuthenticationSettingsFinding,
    LoggingSettingsFinding,
    LoginBannerFinding,
    ManagementTlsFinding,
    ManagementSshFinding,
    MasterKeyFinding,
    NtpSettingsFinding,
    SnmpSettingsFinding,
    SystemIdentityFinding,
    PasswordComplexityFinding,
    UpdateServerSettingsFinding,
    PasswordProfileFinding,
    SecurityProfileFinding,
    ApplicationEnvironmentCatalogState,
    Control,
    ControlQuery,
    ConfigurationSearchState,
    CertificateFinding,
    CertificateProfileFinding,
    InterfaceManagementProfileFinding,
    ManagementInterfaceFinding,
    RuleFinding,
    SslTlsServiceProfileFinding,
)
from assessments.search.compiler import (
    apply_search, apply_search_node, compile_predicate, parse_search_payload)
from assessments.search import registry as search_registry
from assessments.search.exceptions import SearchSyntaxError
from assessments.security_rule_queries import (
    build_security_rule_display_queryset,
    get_cached_security_rule_pks,
)
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import Count
from django.http import Http404, HttpResponseRedirect
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views.generic import DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, DeleteView, UpdateView
from django.views import View

from optivedge_integrations.integrations.presentation import (
    entry_device_group_name,
    listed_address_ref_values,
    listed_member_values,
    security_rule_config_source_label,
)
from optivedge_integrations.integrations.models import (
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
    PasswordComplexityPolicy,
    UpdateServerSettings,
    PasswordProfile,
    SecurityProfile,
    Certificate,
    CertificateProfile,
    FieldProvenance,
    InterfaceManagementProfile,
    ManagementInterface,
    SecurityRule,
    SslTlsServiceProfile,
)


PAGE_SIZE = 100

#: The controls this tab is about. Named rather than derived, so an unrelated
#: device-configuration control appearing later does not silently widen the tab.
BANNER_CONTROLS = ("PAN-MGT-007", "PAN-MGT-008")
#: The bound profile and the certificate it carries. Two controls, deliberately: the shipped
#: TLSv1.3_Default profile satisfies the protocol floor and still serves the device's own
#: self-signed certificate, so they pass and fail independently on the same row.
MANAGEMENT_TLS_CONTROLS = ("PAN-MGT-010", "PAN-CRT-006")
#: Ciphers, key exchange and MACs, one row per appliance. 002 fires on an UNRESTRICTED KEX
#: list - nothing weaker than group14-sha1 exists to fire on (measured 2026-09-11).
MANAGEMENT_SSH_CONTROLS = ("PAN-MCR-001", "PAN-MCR-002", "PAN-MCR-003",
                           "PAN-MCR-004", "PAN-MCR-005")
#: Two controls, one object, and they fail independently - the floor and the algorithms. Shown
#: together on one row per profile, because an engineer fixes the profile, not the control.
SSL_TLS_PROFILE_CONTROLS = ("PAN-CRT-005", "PAN-CRT-009")
CERTIFICATE_PROFILE_CONTROLS = ("PAN-CRT-004",)
MASTER_KEY_CONTROLS = ("PAN-CRT-007",)
#: Redundancy and authentication of the time source. They fail independently: a device can have
#: two servers and authenticate neither, or authenticate the one server it has.
NTP_CONTROLS = ("PAN-SVC-001", "PAN-SVC-002")
#: Which SNMP version answers, and whether the community string is a published default. Both are
#: silent on a device with no SNMP configuration at all, which is the compliant state.
SNMP_CONTROLS = ("PAN-SVC-004", "PAN-SVC-005")
#: The management address mode, and the name/time zone the logs are read by. One row, because a
#: device addressed by DHCP can be NAMED by DHCP - the two findings can have one cause.
SYSTEM_IDENTITY_CONTROLS = ("PAN-SVC-007", "PAN-SVC-009", "PAN-SVC-010")
CERTIFICATE_CONTROLS = ("PAN-CRT-002", "PAN-CRT-003")
#: PAN-AUTH-020 is NOT here. It asks whether a second factor governs an ADMINISTRATOR, which
#: is a fact about a person reached through a binding - a profile row cannot say which people
#: are exposed. It reports on the Administrators tab.
#:
#: That is a decision about 019 and 020, NOT a direction of travel for this tab. Jason,
#: 2026-09-09: "it is not a general rule. The other authentication profile controls should stay
#: profile-centric." The test is what the finding NAMES - "this profile has no lockout" is
#: reportable about a profile; "this administrator is reachable by a password alone" is not,
#: because two accounts on one appliance can sit behind different profiles.
AUTHENTICATION_PROFILE_CONTROLS = (
    "PAN-AUTH-018", "PAN-AUTH-025", "PAN-AAA-010", "PAN-AAA-011")
AUTHENTICATION_SEQUENCE_CONTROLS = ("PAN-AAA-012",)
PASSWORD_PROFILE_CONTROLS = ("PAN-AUTH-026",)
SECURITY_PROFILE_CONTROLS = ("PAN-SPY-001", "PAN-VLN-001")
#: All three assess the same account and fail independently, which is the whole reason they
#: share a tab: `admin` on pan-fw-111 fires all three at once.
#:
#: PAN-AUTH-020 was here and is COMPLETE AS AN INTERVIEW QUESTION - not derivable from
#: configuration (Jason, 2026-09-10; marked complete 2026-09-14). An administrator's second
#: factor arrives through RADIUS, SAML or the Cloud Authentication Service, and the firewall
#: records none of the other side's policy; the one factor the configuration does show, the
#: Factors tab, is not enforced for administrators. The question it became is recorded in
#: control-changes.json, and it generates no findings by design.
ADMIN_USER_CONTROLS = ("PAN-AUTH-019", "PAN-AUTH-021", "PAN-AUTH-022")
#: Six kinds on one tab, because they are one object type with one set of questions asked
#: differently. Six tabs would put one profile per page on most estates.
SERVER_PROFILE_CONTROLS = ("PAN-AAA-001", "PAN-AAA-002", "PAN-AAA-004", "PAN-AAA-006",
                           "PAN-AAA-008", "PAN-AAA-009", "PAN-AAA-013")


def build_profile_rows(profiles, severity_by_profile_id=None):
    rows = []
    severity_by_profile_id = severity_by_profile_id or {}
    for profile in profiles:
        rows.append({
            "profile": profile,
            "control_severity": severity_by_profile_id.get(profile.pk),
        })
    return rows


def _default_query_for_control(control):
    if control and control.target_model:
        return {"model": control.target_model, "operator": "and", "clauses": []}
    return default_security_rule_search_query()


def build_query_string_without(request, *keys_to_remove):
    params = request.GET.copy()
    for key in keys_to_remove:
        params.pop(key, None)
    encoded = params.urlencode()
    if not encoded:
        return request.path
    return f"{request.path}?{encoded}"


def describe_search_node(node):
    if not node:
        return "No search applied"
    if "operator" in node:
        if not node["clauses"]:
            return "Empty search group"
        joiner = f" {node['operator'].upper()} "
        return "(" + joiner.join(describe_search_node(clause) for clause in node["clauses"]) + ")"

    description = f"{node['field']} {node['op']} {node['value']}"
    if node.get("case_sensitive"):
        description += " [case]"
    if node.get("negated"):
        description = f"NOT {description}"
    return description


def build_security_rule_rows(security_rules, severity_by_rule_id=None):
    rows = []
    severity_by_rule_id = severity_by_rule_id or {}
    for security_rule in security_rules:
        profile_groups = [value.value for value in security_rule.securityruleprofilegroups.all()]
        profiles = [
            f"{profile.profile_type}: {profile.value}"
            for profile in security_rule.securityruleprofiles.all()
        ]
        rows.append(
            {
                "security_rule": security_rule,
                "config_source_label": security_rule_config_source_label(security_rule.config_source),
                "device_group_name": entry_device_group_name(security_rule),
                "from_zones": listed_member_values(security_rule, "securityrulefromzones"),
                "to_zones": listed_member_values(security_rule, "securityruletozones"),
                "source_addresses": listed_address_ref_values(
                    security_rule,
                    "source_address_refs",
                ),
                "destination_addresses": listed_address_ref_values(
                    security_rule,
                    "destination_address_refs",
                ),
                "applications": listed_member_values(security_rule, "securityruleapplications"),
                "services": listed_member_values(security_rule, "securityruleservices"),
                "profile_groups": profile_groups,
                "profiles": profiles,
                "control_severity": severity_by_rule_id.get(security_rule.pk),
            }
        )
    return rows


def pagination_range(page_obj, window=2):
    start = max(page_obj.number - window, 1)
    end = min(page_obj.number + window, page_obj.paginator.num_pages)
    return range(start, end + 1)


# --- Findings presentation (security-rules tab) ------------------------------
# Findings are grouped (by control or rule), severity-ranked, and shown with
# semantic badges; heavy per-rule context lives in the detail overlay, not the row.
FINDING_GROUP_PAGE_SIZE = 50

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
_SEVERITY_RANK = {value: rank for rank, value in enumerate(reversed(_SEVERITY_ORDER))}
_SEVERITY_LABELS = {value: label for value, label in Control.Severity.choices}

# One place color lives: severity and status badges. Everything else stays neutral.
_SEVERITY_BADGE_CLASSES = {
    "critical": "text-red-700 bg-red-50 border-red-200",
    "high": "text-orange-700 bg-orange-50 border-orange-200",
    "medium": "text-amber-700 bg-amber-50 border-amber-200",
    "low": "text-slate-600 bg-slate-100 border-slate-300",
    "informational": "text-slate-500 bg-slate-50 border-slate-200",
}
_SEVERITY_SWATCH_CLASSES = {
    "critical": "bg-red-500",
    "high": "bg-orange-500",
    "medium": "bg-amber-500",
    "low": "bg-slate-400",
    "informational": "bg-slate-300",
}
_STATUS_BADGE = {
    "open": ("text-slate-700", "bg-orange-500"),
    "suppressed": ("text-slate-400", "bg-slate-300"),
    "resolved": ("text-emerald-700", "bg-emerald-500"),
}


def _severity_rank(value):
    return _SEVERITY_RANK.get(value, -1)


def build_finding_querystring(*, group, severities, hide_suppressed, page=None, finding=None):
    """Canonical query string for the findings (security-rules tab) view, so grouping,
    filters, pagination, and the selected finding round-trip together."""
    params = [("tab", "security-rules"), ("group", group)]
    for severity in severities:
        params.append(("severity", severity))
    if hide_suppressed:
        params.append(("hide_suppressed", "1"))
    if page:
        params.append(("page", str(page)))
    if finding:
        params.append(("finding", str(finding)))
    return "?" + urlencode(params, doseq=True)


def _finding_scope_label(security_rule):
    enforcement_point = security_rule.enforcement_point
    if enforcement_point is None:
        return str(security_rule.management_station)
    scope = enforcement_point.vsys_name
    if enforcement_point.vsys_display_name:
        scope = f"{scope} · {enforcement_point.vsys_display_name}"
    return scope


def _finding_rule_config(rule_row):
    """The rulebase-style config (zones/source/destination/app/service/action) shown on an
    expanded finding row, pulled from a build_security_rule_rows() row."""
    security_rule = rule_row["security_rule"]
    return {
        "from_zones": rule_row["from_zones"],
        "to_zones": rule_row["to_zones"],
        "source_addresses": rule_row["source_addresses"],
        "destination_addresses": rule_row["destination_addresses"],
        "applications": rule_row["applications"],
        "services": rule_row["services"],
        "action": security_rule.action,
        "negate_source": security_rule.negate_source,
        "negate_destination": security_rule.negate_destination,
    }


def get_control_list_queryset():
    return Control.objects.annotate(
        query_count=Count("queries", distinct=True),
    ).order_by("control_id")


def build_control_detail_context(control):
    """The control's queries, each carrying WHERE its results can be read.

    The destination is derived from the query's own model. It used to be hard-coded to the
    security rules page for every control, so opening the results of a certificate or NTP query
    landed on a builder that refused it - "This query targets integrations.NtpSettings and
    cannot be applied to security rules" - which reads as the query being broken rather than the
    link being wrong. Annotated onto the instances rather than resolved in the template, because
    the choice needs `scope` (see `configuration_results.object_for_canonical_query`).
    """
    control_queries = list(control.queries.order_by("-is_baseline", "name", "pk"))
    for control_query in control_queries:
        control_query.results_url = config_results.query_results_url(
            control_query.canonical_query, control_query_pk=control_query.pk)
    #: The control-level button applies the WHOLE control - the union of its active queries at
    #: worst-wins severity, which is what a finding is and what a single query cannot show. It
    #: goes to the same place the per-query links do, chosen from the BASELINE query because
    #: that is the one guaranteed to name the control's own object.
    baseline = next((q for q in control_queries if q.is_baseline), None)
    return {
        "control_queries": control_queries,
        "control_results_url": config_results.control_results_url(
            control.target_model,
            baseline.canonical_query if baseline else None,
            control_pk=control.pk),
    }


class RightOverlayMixin:
    overlay_close_url = None
    overlay_panel_class = "w-[32rem] max-w-[calc(100vw-15rem)]"

    def get_overlay_close_url(self):
        return self.overlay_close_url

    def get_overlay_panel_class(self):
        return self.overlay_panel_class

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["overlay_is_open"] = True
        context["overlay_close_url"] = self.get_overlay_close_url()
        context["overlay_panel_class"] = self.get_overlay_panel_class()
        return context


class ControlListBackgroundMixin:
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["controls"] = get_control_list_queryset()
        return context


class ControlDetailBackgroundMixin:
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        control = context["control"]
        context.update(build_control_detail_context(control))
        return context


class ControlListView(ListView):
    model = Control
    context_object_name = "controls"
    template_name = "assessments/control_list.html"

    def get_queryset(self):
        return get_control_list_queryset()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        from assessments.environment import get_application_environment as _get_env_safe
        application_environment = _get_env_safe()
        current_catalog_state = None
        if application_environment is not None:
            current_catalog_state = (
                ApplicationEnvironmentCatalogState.objects.filter(
                    application_environment=application_environment,
                )
                .select_related("current_catalog")
                .first()
            )
        drifted = False
        if current_catalog_state and current_catalog_state.current_catalog:
            drifted = catalog_has_drifted(current_catalog_state.current_catalog.payload)
        context["current_catalog_state"] = current_catalog_state
        context["catalog_drifted"] = drifted
        return context


class SystemView(TemplateView):
    template_name = "assessments/system.html"


def _entry_provenance(instances, field_name: str = "__entry__") -> dict[int, str]:
    """{pk: source name} for objects carrying a provenance row for `field_name`.

    One query for a whole page rather than a lookup per row. A missing entry means either
    the value was written locally or PAN-OS defaulted it - both render blank - and the two
    are distinguishable in the data (a local value HAS a row, typed local, with no name)
    even though the page does not yet use the difference.
    """
    instances = [i for i in instances if i is not None]
    if not instances:
        return {}
    content_type = ContentType.objects.get_for_model(type(instances[0]))
    return {
        row.object_id: row.raw_value
        for row in FieldProvenance.objects.filter(
            content_type=content_type,
            object_id__in=[i.pk for i in instances],
            field_name=field_name,
        )
        if row.raw_value
    }


def _administrative_service_cells(surface, sources_by_pk):
    """One cell per administrative service, in a fixed order so columns line up.

    All five administrative services exist on both management planes - they fall inside the
    nine names the deviceconfig planes and interface management profiles share - so no cell
    is ever "not applicable" and the column set does not vary by row. The six services that
    differ between planes are all non-administrative, and none of them gets a column.
    """
    by_name = {service.name: service for service in surface.services.all()}
    return [
        {
            "name": name,
            "enabled": by_name[name].enabled if name in by_name else False,
            "insecure": name in INSECURE_SERVICES,
            "provenance": sources_by_pk.get(by_name[name].pk, "") if name in by_name else "",
        }
        for name in ADMINISTRATIVE_SERVICES
    ]


def report_finding_run(request, message: str, *, skipped_queries: int) -> None:
    """Report a findings run, escalating to a warning when a query was dropped.

    A skipped query is one that no longer compiles - a field it names has been removed or
    renamed. The control then contributes nothing, so if it was the control's only query
    the run reports zero findings for it, which reads exactly like a clean result. The
    count has always been in the message; success styling was burying it.
    """
    if skipped_queries:
        messages.warning(request, message)
    else:
        messages.success(request, message)


class ControlRunFindingsView(View):
    """Every active control, policy and device alike, in one run - see assessments.finding_run."""

    def post(self, request, *args, **kwargs):
        result = regenerate_findings()
        report_finding_run(
            request,
            (
                f"Findings regenerated. Controls: {result.controls_evaluated}. "
                f"Findings: {result.findings_created}. Query links: {result.query_links_created}. "
                f"Skipped queries: {result.skipped_queries}."
            ),
            skipped_queries=result.skipped_queries,
        )
        return HttpResponseRedirect(reverse("assessment_control_list"))


class ControlDetailView(DetailView):
    model = Control
    context_object_name = "control"
    pk_url_kwarg = "pk"
    template_name = "assessments/control_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(build_control_detail_context(self.object))
        return context


class ControlCreateView(RightOverlayMixin, ControlListBackgroundMixin, CreateView):
    form_class = ControlForm
    model = Control
    template_name = "assessments/control_form.html"
    overlay_close_url = "/assessments/controls/"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form_mode"] = "create"
        return context

    def get_success_url(self):
        return reverse("assessment_control_detail", kwargs={"pk": self.object.pk})


class ControlUpdateView(RightOverlayMixin, ControlDetailBackgroundMixin, UpdateView):
    form_class = ControlForm
    model = Control
    context_object_name = "control"
    pk_url_kwarg = "pk"
    template_name = "assessments/control_form.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form_mode"] = "update"
        return context

    def get_success_url(self):
        return reverse("assessment_control_detail", kwargs={"pk": self.object.pk})

    def get_overlay_close_url(self):
        return reverse("assessment_control_detail", kwargs={"pk": self.object.pk})


class ControlDeleteView(RightOverlayMixin, ControlDetailBackgroundMixin, DeleteView):
    model = Control
    context_object_name = "control"
    pk_url_kwarg = "pk"
    template_name = "assessments/control_confirm_delete.html"
    success_url = reverse_lazy("assessment_control_list")

    def get_overlay_close_url(self):
        return reverse("assessment_control_detail", kwargs={"pk": self.object.pk})


class ControlQueryCreateView(RightOverlayMixin, ControlListBackgroundMixin, TemplateView):
    template_name = "assessments/control_query_form.html"
    overlay_close_url = "/assessments/controls/"

    def get_selected_control(self):
        control_id = self.request.GET.get("control") or self.request.POST.get("control")
        if not control_id:
            return None
        return get_object_or_404(Control, pk=control_id)

    def get_initial(self):
        selected_control = self.get_selected_control()
        canonical_query = None
        self._load_search_error = None
        if "load_from_search" in self.request.POST:
            search_payload = self.request.POST.get("search", "").strip()
            if search_payload:
                try:
                    canonical_query = parse_search_payload(search_payload)
                except SearchSyntaxError:
                    canonical_query = _default_query_for_control(selected_control)
                else:
                    if selected_control and isinstance(canonical_query, dict):
                        query_model = canonical_query.get("model")
                        expected = selected_control.target_model or None
                        if expected and query_model != expected:
                            self._load_search_error = (
                                f"The loaded query targets {query_model}, but "
                                f"{selected_control.control_id} is a "
                                f"{selected_control.get_control_type_display()} control "
                                f"({expected} required). The default query has been restored."
                            )
                            canonical_query = _default_query_for_control(selected_control)
        return {
            "control": selected_control.pk if selected_control else None,
            "adjusted_severity": None,
            "canonical_query": canonical_query or _default_query_for_control(selected_control),
            "is_active": True,
        }

    def post(self, request, *args, **kwargs):
        if "load_from_search" in request.POST:
            form = ControlQueryForm(initial=self.get_initial())
            return self.render_to_response(self.get_context_data(form=form))

        form = ControlQueryForm(self.request.POST)
        if form.is_valid():
            control_query = form.save()
            return HttpResponseRedirect(
                reverse("assessment_control_detail", kwargs={"pk": control_query.control.pk})
            )
        return self.render_to_response(self.get_context_data(form=form))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        selected_control = self.get_selected_control()
        form = kwargs.get("form") or ControlQueryForm(initial=self.get_initial())
        context["selected_control"] = selected_control
        if selected_control:
            context["control"] = selected_control
            context.update(build_control_detail_context(selected_control))
        else:
            context["control"] = None
            context["control_queries"] = []
        context["form"] = form
        context["load_search_error"] = getattr(self, "_load_search_error", None)
        context["control_query_close_url"] = (
            reverse("assessment_control_detail", kwargs={"pk": selected_control.pk})
            if selected_control
            else reverse("assessment_control_list")
        )
        return context


class ControlQueryUpdateView(RightOverlayMixin, ControlDetailBackgroundMixin, UpdateView):
    form_class = ControlQueryForm
    model = ControlQuery
    context_object_name = "control_query"
    pk_url_kwarg = "query_pk"
    template_name = "assessments/control_query_form.html"

    def get_object(self, queryset=None):
        return get_object_or_404(
            ControlQuery.objects.select_related("control"),
            pk=self.kwargs["query_pk"],
            control_id=self.kwargs["pk"],
        )

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["control"] = self.object.control
        return kwargs

    def get_context_data(self, **kwargs):
        control = self.object.control
        context = super().get_context_data(control=control, **kwargs)
        context["control"] = control
        context.update(build_control_detail_context(control))
        context["form_mode"] = "update"
        context["form_title"] = "Edit Query"
        context["submit_label"] = "Save Query"
        context["control_query_close_url"] = reverse(
            "assessment_control_detail",
            kwargs={"pk": control.pk},
        )
        return context

    def get_success_url(self):
        return reverse("assessment_control_detail", kwargs={"pk": self.object.control.pk})

    def get_overlay_close_url(self):
        return reverse("assessment_control_detail", kwargs={"pk": self.object.control.pk})


class ControlQueryDeleteView(RightOverlayMixin, ControlDetailBackgroundMixin, DeleteView):
    model = ControlQuery
    context_object_name = "control_query"
    pk_url_kwarg = "query_pk"
    template_name = "assessments/control_query_confirm_delete.html"

    def get_object(self, queryset=None):
        return get_object_or_404(
            ControlQuery.objects.select_related("control"),
            pk=self.kwargs["query_pk"],
            control_id=self.kwargs["pk"],
        )

    def get_context_data(self, **kwargs):
        control_query = self.object
        control = control_query.control
        context = super().get_context_data(control=control, **kwargs)
        context["control"] = control
        context.update(build_control_detail_context(control))
        context["control_query_close_url"] = reverse(
            "assessment_control_detail",
            kwargs={"pk": control.pk},
        )
        return context

    def get_success_url(self):
        return reverse("assessment_control_detail", kwargs={"pk": self.object.control.pk})

    def get_overlay_close_url(self):
        return reverse("assessment_control_detail", kwargs={"pk": self.object.control.pk})


PASSWORD_COMPLEXITY_CONTROLS = tuple(f"PAN-AUTH-{n:03d}" for n in range(1, 14))
AUTHENTICATION_SETTINGS_CONTROLS = ("PAN-AUTH-014", "PAN-AUTH-015", "PAN-AUTH-016",
                                    "PAN-AUTH-017")

#: Each cell: (field, label, kind). `kind` drives rendering only - the verdict never comes from
#: here. "unassessed" marks the three keys PAN-OS accepts that no corpus control reads; they are
#: shown because collecting a value and then hiding it is how a page starts lying about what was
#: looked at, and they are styled apart so nobody mistakes one for a passing check.
#: Field names carry no `password_` prefix since the subject became `PasswordComplexityPolicy`
#: on 2026-09-10: on a model that IS the password policy the prefix said nothing. The three
#: `unassessed_*` cells are values PAN-OS accepts that no corpus control reads.
PASSWORD_COMPLEXITY_GROUPS = (
    ("Composition", (
        ("minimum_length", "Length", "length"),
        ("minimum_uppercase", "Uppercase", "int"),
        ("minimum_lowercase", "Lowercase", "int"),
        ("minimum_numeric", "Numeric", "int"),
        ("minimum_special", "Special", "int"),
        ("block_username_inclusion", "Blocks username", "bool"),
        ("block_repeated_characters", "Repeated chars", "unassessed_int"),
    )),
    ("Reuse", (
        ("new_differs_by_characters", "Differs by", "int"),
        ("history_count", "History", "int"),
    )),
    ("Expiry", (
        ("expiration_period", "Period", "days_never"),
        ("expiration_warning_period", "Warning", "int"),
    )),
    ("Password change", (
        ("post_expiration_admin_login_count", "Post-expiry logins", "int"),
        ("post_expiration_grace_period", "Grace period", "int"),
        ("change_on_first_login", "On first login", "unassessed_bool"),
        ("change_period_block", "Period block", "unassessed_int"),
    )),
)


def _fields_by_control(control_ids) -> dict[str, set[str]]:
    """{control_id: fields its baseline query reads}, taken from the query itself.

    DERIVED rather than written down, because a hand-kept map would be a second place where
    the relationship between a control and a column lives, and the two would drift the first
    time a threshold moved. It also means the page never restates a threshold: which cell a
    finding lights up comes from the query, and WHETHER it lights up comes from the finding.
    """
    mapping: dict[str, set[str]] = {}
    for control in Control.objects.filter(control_id__in=control_ids).prefetch_related(
            "queries"):
        fields: set[str] = set()
        for query in control.queries.all():
            canonical = query.canonical_query or {}
            for clause in canonical.get("clauses") or []:
                field = clause.get("field")
                if field:
                    fields.add(field)
        mapping[control.control_id] = fields
    return mapping


# --------------------------------------------------------------------------------------------
# Findings: the same tables the workbook ships, on screen
# --------------------------------------------------------------------------------------------

class FindingsSummaryView(TemplateView):
    """What the workbook opens on: how much, how bad, and where to look.

    Counted rather than built - `severity_counts` is one query per finding model, where
    building all twenty-two tables to total them would do the whole job of every page to draw
    one page.
    """

    template_name = "assessments/findings/summary.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        counts = artifact_domains.severity_counts()

        categories = []
        for category in config_nav.CATEGORIES:
            domains = []
            for domain in artifact_domains.DOMAINS:
                if findings_domain_category(domain) != category:
                    continue
                by_severity = counts[domain.slug]
                domains.append({
                    "slug": domain.slug,
                    "title": domain.title,
                    "description": domain.description,
                    "total": sum(by_severity.values()),
                    "severities": severity_breakdown(by_severity),
                })
            if domains:
                categories.append({
                    "label": category,
                    "domains": domains,
                    "total": sum(d["total"] for d in domains),
                })

        totals = defaultdict(int)
        for by_severity in counts.values():
            for severity, count in by_severity.items():
                totals[severity] += count

        context["environment"] = get_application_environment()
        context["categories"] = categories
        context["total"] = sum(totals.values())
        context["severities"] = severity_breakdown(totals)
        context["run"] = AssessmentRun.objects.order_by("-pk").first()
        return context


class FindingsDomainView(TemplateView):
    """One domain's findings, as the workbook lays them out.

    The columns and the rows come from `build_findings_table`, which is the same table
    `write_sheet` draws - so this page and that tab agree by construction. It asks for every
    tested column, because a surface with room for provenance should show it even where the
    workbook's own tab has no space (Jason, 2026-09-25).
    """

    template_name = "assessments/findings/domain.html"

    def get_domain(self):
        domain = artifact_domains.DOMAIN_BY_SLUG.get(self.kwargs.get("slug", ""))
        if domain is None:
            raise Http404(f"no such findings domain: {self.kwargs.get('slug')!r}")
        return domain

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        domain = self.get_domain()
        context["domain"] = domain
        context["domains"] = artifact_domains.DOMAINS

        try:
            table = build_findings_table(domain.spec, tested=ALL_TESTED_COLUMNS)
        except ArtifactBuildError as exc:
            # A guard refused - a control testing a field no column presents, or a row count
            # that does not match the findings. Saying so beats a 500 and beats a page that
            # quietly omits findings, which is the failure this whole surface exists to avoid.
            context["build_error"] = str(exc)
            return context

        control_column = table.headers.index("Control ID")
        severity_column = table.headers.index("Severity")
        controls_by_id = {c.control_id: c for c in table.controls}
        implicated = set(table.implicated)

        rows = []
        for index, (row, finding) in enumerate(zip(table.rows, table.findings)):
            cells = []
            for column, value in enumerate(row):
                control = controls_by_id.get(value) if column == control_column else None
                cells.append({
                    "value": value,
                    "implicated": (index, column) in implicated,
                    "control_url": (reverse("assessment_control_detail",
                                            kwargs={"pk": control.pk}) if control else ""),
                    "severity_classes": (_SEVERITY_BADGE_CLASSES.get(finding.severity, "")
                                         if column == severity_column else ""),
                })
            rows.append(cells)

        context["table"] = table
        context["rows"] = rows
        context["severities"] = severity_breakdown(table.by_severity)
        return context


def findings_href_for(config_object) -> str:
    """Where a configuration object's findings are presented, or "" where nothing reports."""
    if not config_object.search_model:
        return ""
    domain = artifact_domains.domain_for_model(config_object.search_model)
    if domain is None:
        return ""
    return reverse("assessment_findings_domain", kwargs={"slug": domain.slug})


def findings_domain_category(domain) -> str:
    """The PAN-OS category a domain belongs to - the same answer the workbook's tab colour uses."""
    spec = domain.spec
    return artifact_category_of(spec.subject_model(spec.kind_for(spec.control_types[0])))


def severity_breakdown(by_severity):
    """Counts worst-first, so a reader sees the worst thing before the tally."""
    return [{
        "value": value,
        "label": _SEVERITY_LABELS.get(value, value),
        "count": by_severity.get(value, 0),
        "classes": _SEVERITY_BADGE_CLASSES.get(value, ""),
        "swatch": _SEVERITY_SWATCH_CLASSES.get(value, ""),
    } for value in _SEVERITY_ORDER if by_severity.get(value)]



class ConfigurationObjectView(TemplateView):
    """One object in the configuration explorer, inside the PAN-OS-shaped frame.

    What lands here is the pair `/assessments/security-rules/` already has: a query built over
    this object's fields, and the objects that match it. That is a DIFFERENT surface from the
    findings tabs under Device Configuration, which present what the controls found - these
    pages are for asking a question and reading the answer, including trying out a control's
    query before it is a control. Both surfaces stay; each object links to the other.

    Every object routes here for now. The frame is being built before the views that fill it, so
    that the ORGANISATION - which category an object is in, which rail group, in what order - is
    reviewable while it is still cheap to move things. A rail that is wrong after fifteen views
    are attached to it is fifteen rewrites; a rail that is wrong today is one tuple.

    The category and the object both come from the URL rather than from a class attribute,
    because there is one view and fifteen pages. When a real view replaces the placeholder for an
    object it takes the nav context from here rather than rebuilding it - `nav_context` is the
    part worth sharing, and it is a function so a ListView can use it too.
    """

    def config_object(self):
        category = config_nav.CATEGORY_BY_SLUG.get(self.kwargs.get("category", ""))
        if category is None:
            raise Http404(f"no such configuration category: {self.kwargs.get('category')!r}")
        obj = config_nav.CONFIG_OBJECTS_BY_KEY.get((category, self.kwargs.get("slug", "")))
        if obj is None:
            raise Http404(f"{category} has no object {self.kwargs.get('slug')!r}")
        return obj

    def get_template_names(self):
        return ["assessments/configuration_object_query.html"
                if self.config_object().search_model
                else "assessments/configuration_object_placeholder.html"]

    def post(self, request, *args, **kwargs):
        """Store the built query and redirect to it, rather than rendering the results here.

        A POST that renders leaves the browser on a page that cannot be reloaded, bookmarked or
        sent to anyone, and re-submits on back. The token in the URL is what makes a built query
        a thing you can pass around.
        """
        obj = self.config_object()
        if not obj.search_model:
            raise Http404("this object has no query view")
        here = reverse("assessment_configuration_object",
                       args=[config_nav.category_slug(obj.category), obj.slug])

        if "build_from_selection" in request.POST:
            return self.build_from_selection(request, obj, here)

        payload = (request.POST.get("search") or "").strip()
        if not payload:
            return HttpResponseRedirect(here)
        try:
            node = parse_search_payload(payload)
            compile_predicate(config_results.RESULTS[obj.slug].base_queryset().model, node)
        except SearchSyntaxError as exc:
            context = self.get_context_data(**kwargs)
            context.update({
                "search_error": str(exc),
                "search_payload": payload,
                "edit_search_open": True,
            })
            return self.render_to_response(context)
        state = ConfigurationSearchState.objects.create(
            model_label=obj.search_model,
            query_text=request.POST.get("q", ""),
            canonical_query=node,
        )
        return HttpResponseRedirect(f"{here}?search_state={state.token}")

    def build_from_selection(self, request, obj, here):
        """Turn the ticked rows into a query and open the builder on it.

        Refining ANDs a new group onto the query already applied, which is why the first press
        produces a group too: each press is one thought, and they stack rather than merge.
        """
        spec = config_results.RESULTS[obj.slug]
        pks = [pk for pk in request.POST.getlist("selected") if pk.isdigit()]
        applied = self.request.POST.get("search") or ""
        back = f"{here}?search_state={request.POST['search_state']}" \
            if request.POST.get("search_state") else here
        if not pks:
            return HttpResponseRedirect(back)

        objects = list(spec.base_queryset().filter(pk__in=pks))
        fields = [spec.query_fields[c] for c in spec.columns if c in spec.query_fields]
        group = selection_module.selection_group(
            obj.search_model, objects, fields,
            resolved_addresses=bool(request.POST.get("resolved_addresses")))
        if group is None:
            # Nothing the selected rows agree on survived the compiler. Saying so beats
            # opening an empty builder, which reads as the button having done nothing.
            context = self.get_context_data()
            context["search_error"] = (
                "Those rows have no column values in common, so there is nothing to build a "
                "query from. Try a narrower selection.")
            return self.render_to_response(context)

        try:
            existing = parse_search_payload(applied) if applied else None
        except SearchSyntaxError:
            existing = None
        node = selection_module.combine(obj.search_model, existing, group)
        state = ConfigurationSearchState.objects.create(
            model_label=obj.search_model, canonical_query=node)
        return HttpResponseRedirect(f"{here}?search_state={state.token}&edit_search=1")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        obj = self.config_object()
        context.update(configuration_nav_context(obj))
        if obj.search_model:
            context.update(self.query_context(obj))
        return context

    def query_context(self, obj):
        spec = config_results.RESULTS[obj.slug]
        rows = spec.base_queryset()
        if spec.scope:
            # One kind of a shared model: the split is a query the search service applies,
            # not a filter written here. See ResultsSpec.scope.
            rows = apply_search_node(rows, spec.scope)
        total = rows.count()
        node = None
        error = ""
        prompt_text = ""

        token = self.request.GET.get("search_state", "")
        if token:
            try:
                state = ConfigurationSearchState.objects.get(token=token)
            except (ConfigurationSearchState.DoesNotExist, ValidationError, ValueError):
                error = "That query is no longer available. Build it again."
            else:
                # A token from ANOTHER object's page compiles against fields this model does
                # not have. Refusing it by name is the difference between an error and a page
                # that says "0 results" about a question it never asked.
                if state.model_label != obj.search_model:
                    error = (f"That query targets {state.model_label} and cannot be applied to "
                             f"{obj.label}.")
                else:
                    node = state.canonical_query
                    # A state that carries the WORDS that produced it came from the
                    # plain-language page, and the way back to them is this link. Keyed on the
                    # state rather than on the object, so nothing here needs to know which
                    # pages have a plain-language front end.
                    prompt_text = state.query_text

        control_query_id = self.request.GET.get("control_query")
        if control_query_id and not error:
            try:
                saved = ControlQuery.objects.select_related("control").get(pk=int(control_query_id))
            except (ControlQuery.DoesNotExist, ValueError, TypeError):
                error = "Saved query could not be found."
            else:
                model = (saved.canonical_query or {}).get("model")
                if model != obj.search_model:
                    error = (f"{saved.control.control_id}'s query targets {model} and cannot be "
                             f"applied to {obj.label}.")
                else:
                    node = saved.canonical_query

        if node is not None and not error:
            try:
                rows = apply_search_node(rows, node)
            except SearchSyntaxError as exc:
                error, node = str(exc), None

        # A whole CONTROL, which is a different question from a query and the one an assessor
        # actually asks: a finding is the union of a control's active queries, at the severity
        # the worst matching one sets. Previewing a single query cannot answer it - a control
        # whose severity comes from a calibration query previews at the wrong severity, or at
        # none - so this path evaluates the control the way finding generation does, through the
        # same function, rather than reimplementing worst-wins here.
        control_preview = {}
        extra_cells = None
        control_id = self.request.GET.get("control")
        if control_id and not error:
            rows, extra_cells, control_preview, error = self.control_preview(obj, rows, control_id)

        # ONE pagination path for both modes. A page that renders every row is fine over forty
        # certificates and not over the lab's 878 security rules, and two paginators - one per
        # mode - is how the two drift apart.
        paginator = Paginator(rows, PAGE_SIZE)
        page_obj = paginator.get_page(self.request.GET.get("page"))
        page_rows = [
            tuple(spec.row(item)) + (extra_cells(item) if extra_cells else ())
            for item in page_obj.object_list
        ]
        # The pk beside the cells, so a row can be ticked and sent back. Kept ALONGSIDE `rows`
        # rather than folded into it: `rows` is a tuple of cells and several tests read it by
        # column index, which is the right shape for "what does this table say".
        selectable_rows = [{"pk": item.pk, "cells": cells}
                           for item, cells in zip(page_obj.object_list, page_rows)]

        context = {
            "search_model": obj.search_model,
            "search_state_token": token,
            # The builder's field list comes from the COMPILER's registry, so a field the
            # compiler cannot handle is never offered. The security rules builder hard-codes
            # both lists in its template and they are a second copy to keep in step.
            "field_operators": {
                name: sorted(ops)
                for name, ops in sorted(
                    search_registry.get_model_entry(obj.search_model)["field_operators"].items())
                # `spec.fields` scopes the dropdown where several rail items share a model.
                # Empty means the page IS the model and offers everything.
                if not spec.fields or name in spec.fields
            },
            # Which fields honour `include_any`. Only the semantic address fields do - every
            # other compiler carries the flag and ignores it - and the builder had no control
            # for it at all, so `source_address exactly any` was a query a person could build
            # and that could never match: the gate excludes exactly the members being asked
            # for. Derived from the operator set rather than listed, so a new semantic address
            # field arrives with the toggle already.
            "include_any_fields": sorted(
                name for name, ops in
                search_registry.get_model_entry(obj.search_model)["field_operators"].items()
                if set(ops) & ADDRESS_SEMANTIC_OPERATORS),
            "columns": spec.columns + (("Severity", "Matched query") if extra_cells else ()),
            "rows": page_rows,
            "selectable_rows": selectable_rows,
            #: Which columns can seed a query from a ticked row. Empty disables the button
            #: rather than offering one that would build nothing.
            "selection_fields": [spec.query_fields[c] for c in spec.columns
                                 if c in spec.query_fields],
            "selection_addresses": any(
                spec.query_fields.get(c) in selection_module.RESOLVED_ADDRESS_FIELDS
                for c in spec.columns),
            "total_count": total,
            "shown_count": paginator.count,
            "page_obj": page_obj,
            "page_range": pagination_range(page_obj),
            "pager_query": build_query_string_without(self.request, "page"),
            "search_query": node,
            "search_summary": describe_search_node(node),
            "search_payload": json.dumps(node) if node else "",
            # Filled in below from the previewed control, when there is one and no query of
            # the reader's own.
            "search_error": error,
            "plain_language_edit_url": (
                f"{reverse('assessment_security_rule_plain_language')}?search_state={token}"
                if prompt_text else ""),
            "edit_search_open": self.request.GET.get("edit_search") == "1",
            "edit_search_close_url": build_query_string_without(self.request, "edit_search"),
            "clear_search_url": build_query_string_without(
                self.request, "search_state", "control_query", "control", "edit_search"),
        }
        context.update(control_preview)
        if not context["search_payload"] and context.get("preview_baseline_payload"):
            context["search_payload"] = context["preview_baseline_payload"]
        return context

    def control_preview(self, obj, rows, control_id):
        """What this control WOULD report against the rows on this page.

        Returns (rows, extra_cells, context, error). `extra_cells` appends the two preview cells
        to each row the caller renders, so the body and the header grow together - a table that
        gains a column in one of them shifts every value after it, silently.
        """
        def unchanged(message=""):
            return rows, None, {}, message

        try:
            control = Control.objects.prefetch_related("queries").get(pk=int(control_id))
        except (Control.DoesNotExist, ValueError, TypeError):
            return unchanged("Control could not be found.")

        baseline = next((q for q in control.queries.all() if q.is_baseline), None)
        destination = config_results.object_for_canonical_query(
            baseline.canonical_query if baseline else None)
        if not control.target_model:
            # Every query would be skipped and the page would report nothing, which reads as
            # "this control finds no problem here" rather than "this control assesses nothing".
            return unchanged(f"{control.control_id} declares no assessment target, so it "
                             f"generates no findings and there is nothing to preview.")
        if control.target_model != obj.search_model:
            return unchanged(f"{control.control_id} targets {control.target_model} and cannot "
                             f"be applied to {obj.label}.")
        if destination is not None and destination.slug != obj.slug:
            # Same model, different page - the anti-spyware / vulnerability split. Scoped rows
            # would return nothing and read as "this control finds no problem here", which is
            # the most misleading answer available.
            return unchanged(f"{control.control_id} is about {destination.label} and cannot be "
                             f"applied to {obj.label}.")

        matched, active_queries, skipped, matched_by_object, severity_by_id = (
            evaluate_queryset_control_queries(rows, control, model_name=obj.search_model))

        def extra_cells(item):
            # One query name per line, like every other multi-value cell (Jason, 2026-09-27).
            return (severity_label(severity_by_id[item.pk]),
                    "\n".join(q.name for q in matched_by_object[item.pk]))

        note = ""
        if skipped:
            # Silence here would under-report and look like a clean result.
            note = (f"{skipped} of {len(active_queries)} active queries could not be applied to "
                    f"{obj.label} and were not counted.")
        return matched, extra_cells, {
            "control_preview": {
                # `pk` so "Save Query" can carry the control being previewed back to the
                # control-query form. That is the calibration path: open a control here, adjust
                # its query against real data, save it onto the same control.
                "pk": control.pk,
                "control_id": control.control_id,
                "name": control.name,
                "href": f"/assessments/controls/{control.pk}/",
                "query_count": len(active_queries),
                "note": note,
            },
            # What the builder opens on when this control is being previewed. Starting EMPTY
            # made calibration mean "rebuild the control's query from scratch before you can
            # adjust it", which is the opposite of what previewing it here is for. The save
            # action creates a NEW query rather than editing this one, so what an operator
            # writes from here is the calibration query, next to the baseline it started from.
            "preview_baseline_payload": (
                json.dumps(baseline.canonical_query) if baseline else ""),
            "search_summary": f"{control.control_id} - what this control would report here",
        }, ""


def configuration_nav_context(active):
    """The category bar and the rail, for whichever object is open.

    Derived from the URL's object rather than passed in per page, for the reason the device tab
    bar derives its active section: a hand-passed active marker is a second thing to keep in
    step, and it goes wrong silently.
    """
    def href(obj):
        return reverse("assessment_configuration_object",
                       args=[config_nav.category_slug(obj.category), obj.slug])

    return {
        "dashboard_is_active": False,
        "categories": [
            {
                "name": name,
                "count": len(config_nav.objects_in(name)),
                # An empty category has nothing to link to. It still renders, greyed, because
                # the point of showing the product's four categories is that a reader can see
                # what has not been built yet as well as what has.
                "href": href(config_nav.first_object(name)) if config_nav.first_object(name) else "",
                "is_active": name == active.category,
            }
            for name in config_nav.CATEGORIES
        ],
        "rail": [
            {
                "heading": heading,
                "objects": [
                    {
                        "label": obj.label,
                        "icon": obj.icon,
                        "href": href(obj),
                        "is_active": obj.slug == active.slug,
                    }
                    for obj in objects
                ],
            }
            for heading, objects in config_nav.groups_in(active.category)
        ],
        "config_object": {
            "label": active.label,
            "where": active.where,
            # Derived from the object's MODEL rather than named beside the rail: the findings
            # page for an object is whichever domain reports on it, and that answer already
            # exists in `artifacts.domains`.
            "findings_href": findings_href_for(active),
        },
    }


class ConfigurationIndexView(TemplateView):
    """`/assessments/configuration/` - what the explorer holds, rather than a redirect into it.

    This used to redirect to the landing object, on the reasoning that a category index would be
    "a fourth thing to design and would be passed through without being read". That holds for a
    category index - a page repeating the four links already in the bar above it. It does not
    hold for this page, which answers what no object page can: every object page sees one
    object, and all of these are comparisons - how much is normalized behind each object, which
    controls read it, which rail items no control reads yet, and which controls have nowhere to
    be previewed.

    The aggregation lives in `configuration_dashboard`; this view supplies the URL builder, so
    that module never reverses a URL or decides where an object lives.
    """

    template_name = "assessments/configuration_dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        def href(obj):
            return reverse("assessment_configuration_object",
                           args=[config_nav.category_slug(obj.category), obj.slug])

        context.update(configuration_dashboard.build(href))
        context["dashboard_is_active"] = True
        # The category bar, with nothing active: the dashboard sits above the categories rather
        # than inside one, and marking a category active here would claim otherwise.
        context["categories"] = [
            {
                "name": name,
                "count": len(config_nav.objects_in(name)),
                "href": href(config_nav.first_object(name)) if config_nav.first_object(name) else "",
                "is_active": False,
            }
            for name in config_nav.CATEGORIES
        ]
        return context
