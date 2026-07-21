"""Assessment-facing views.

This module owns read-oriented assessment surfaces built on top of normalized
integration data. Keep collector and normalization logic in `integrations`.
"""

import json
import tempfile
from pathlib import Path

from assessments.forms import ControlForm, ControlQueryForm
from assessments.control_queries import (
    DEVICE_CONFIGURATION_MODEL,
    SECURITY_RULE_QUERY_MODEL,
    default_security_rule_search_query,
    evaluate_control_queries,
    evaluate_device_configuration_control_queries,
    severity_label,
)
from assessments.reporting import (
    build_report_context,
    build_workbook_export_data,
    render_health_check_report,
    render_health_check_workbook,
)
from assessments.findings import regenerate_rule_findings
from assessments.device_configuration_findings import regenerate_device_configuration_findings
from assessments.controls_catalog.drift import catalog_has_drifted
from assessments.models import (
    ApplicationEnvironmentCatalogState,
    Control,
    ControlQuery,
    DeviceConfigurationFinding,
    RuleFinding,
    SecurityRuleSearchState,
)
from assessments.search.compiler import apply_search, apply_search_node, parse_search_payload
from assessments.search.exceptions import SearchSyntaxError
from assessments.security_rule_queries import (
    build_security_rule_display_queryset,
    get_cached_security_rule_pks,
)
from django.contrib import messages
from django.db.models import Count
from django.http import HttpResponse, HttpResponseRedirect
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views.generic import DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, DeleteView, UpdateView
from django.views import View

from optivedge_integrations.integrations.presentation import (
    listed_address_ref_values,
    listed_member_values,
    security_rule_config_source_label,
)
from optivedge.models import ApplicationEnvironment
from optivedge_integrations.integrations.models import DeviceConfigurationProfile, SecurityRule


PAGE_SIZE = 100


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


def get_control_list_queryset():
    return Control.objects.annotate(
        query_count=Count("queries", distinct=True),
    ).order_by("control_id")


def build_control_detail_context(control):
    return {
        "control_queries": control.queries.order_by("-is_baseline", "name", "pk"),
    }


def get_application_environment():
    application_environments = list(ApplicationEnvironment.objects.order_by("pk")[:2])
    if len(application_environments) > 1:
        raise ValueError("Expected a single ApplicationEnvironment record for this deployment.")
    if not application_environments:
        raise ValueError("ApplicationEnvironment must be configured before generating the report.")
    return application_environments[0]


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


class FindingListView(TemplateView):
    template_name = "assessments/finding_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tab = self.request.GET.get("tab", "security-rules")
        if tab not in {"security-rules", "device-configuration"}:
            tab = "security-rules"
        context["active_tab"] = tab
        if tab == "security-rules":
            context.update(self._security_rule_context())
        else:
            context.update(self._device_configuration_context())
        return context

    def _security_rule_context(self):
        security_rules = (
            SecurityRule.objects.filter(rule_findings__isnull=False)
            .select_related(
                "management_station",
                "enforcement_point",
                "enforcement_point__appliance_group",
                "source_snapshot",
            )
            .prefetch_related(
                "securityrulefromzones",
                "securityruletozones",
                "source_address_refs__address_object",
                "source_address_refs__address_group",
                "destination_address_refs__address_object",
                "destination_address_refs__address_group",
                "securityruleapplications",
                "securityruleservices",
                "rule_findings__control",
                "rule_findings__control_queries",
            )
            .distinct()
            .order_by(
                "management_station__hostname",
                "enforcement_point__vsys_name",
                "effective_order",
                "name",
                "pk",
            )
        )
        paginator = Paginator(security_rules, PAGE_SIZE)
        page_obj = paginator.get_page(self.request.GET.get("page"))
        security_rule_rows = build_security_rule_rows(page_obj.object_list)
        for row in security_rule_rows:
            findings = []
            for finding in row["security_rule"].rule_findings.all().order_by("-created_at", "-pk"):
                findings.append({
                    "control_id": finding.control.control_id,
                    "title": finding.title,
                    "severity": finding.get_severity_display(),
                    "status": finding.get_status_display(),
                    "query_count": finding.control_queries.count(),
                    "query_names": [query.name for query in finding.control_queries.all()],
                    "summary": finding.summary,
                })
            row["findings"] = findings
        return {
            "security_rule_rows": security_rule_rows,
            "page_obj": page_obj,
            "page_range": pagination_range(page_obj),
        }

    def _device_configuration_context(self):
        queryset = (
            DeviceConfigurationFinding.objects.select_related(
                "assessment_run",
                "control",
                "device_configuration_profile",
                "device_configuration_profile__management_station",
                "device_configuration_profile__appliance",
                "device_configuration_profile__appliance_group",
            )
            .prefetch_related("control_queries")
            .order_by("-created_at", "-pk")
        )
        paginator = Paginator(queryset, PAGE_SIZE)
        page_obj = paginator.get_page(self.request.GET.get("page"))
        return {
            "device_configuration_findings": page_obj.object_list,
            "page_obj": page_obj,
            "page_range": pagination_range(page_obj),
        }


class RuleFindingDocxDownloadView(View):
    def get(self, request, *args, **kwargs):
        application_environment = get_application_environment()
        context = build_report_context()

        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        try:
            output_path = render_health_check_report(
                output_path=temp_path,
                context=context,
                client_name=application_environment.client_name,
                short_name=application_environment.client_short_name,
                report_date=context.assessment_run.created_at.astimezone().strftime("%B %-d, %Y"),
                revision_number="0.1",
                opportunity_number=application_environment.opportunity_number.removeprefix("OP-"),
            )
            report_bytes = output_path.read_bytes()
        finally:
            temp_path.unlink(missing_ok=True)

        filename = (
            f"{application_environment.client_short_name.lower()}-"
            f"pan-health-check-{context.assessment_run.created_at.strftime('%Y%m%d')}.docx"
        )
        response = HttpResponse(
            report_bytes,
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class RuleFindingXlsxDownloadView(View):
    def get(self, request, *args, **kwargs):
        application_environment = get_application_environment()
        context = build_report_context()
        generated_date = context.assessment_run.created_at.astimezone().strftime("%B %-d, %Y")
        export_data = build_workbook_export_data(generated_date=generated_date)

        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        try:
            output_path = render_health_check_workbook(
                output_path=temp_path,
                export_data=export_data,
            )
            report_bytes = output_path.read_bytes()
        finally:
            temp_path.unlink(missing_ok=True)

        filename = (
            f"{application_environment.client_short_name.lower()}-"
            f"pan-health-check-{context.assessment_run.created_at.strftime('%Y%m%d')}.xlsx"
        )
        response = HttpResponse(
            report_bytes,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response



class SystemView(TemplateView):
    template_name = "assessments/system.html"


class DeviceConfigurationProfileListView(TemplateView):
    template_name = "assessments/device_configuration_profile_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        profiles = (
            DeviceConfigurationProfile.objects.select_related(
                "management_station",
                "appliance",
                "appliance_group",
            )
            .order_by("management_station__hostname", "appliance__hostname", "pk")
        )

        selected_control = None
        selected_control_query = None
        severity_by_profile_id = {}
        filter_suffix = ""

        context["show_control_severity"] = False
        context["search_summary"] = "All device configuration profiles"
        context["search_error"] = ""
        context["selected_control_query_count"] = 0
        context["selected_control_skipped_queries"] = 0
        context["applied_control_close_url"] = reverse("assessment_device_configuration_profile_list")

        control_id = self.request.GET.get("control")
        control_query_id = self.request.GET.get("control_query")

        if control_id:
            try:
                selected_control = Control.objects.get(pk=int(control_id))
                if selected_control.target_model != DEVICE_CONFIGURATION_MODEL:
                    context["search_error"] = (
                        f"Control {selected_control.control_id} is a "
                        f"{selected_control.get_control_type_display()} control and cannot "
                        f"be applied to device configuration profiles."
                    )
                    selected_control = None
                else:
                    (
                        profiles,
                        active_queries,
                        skipped_queries,
                        _matched_by_profile,
                        severity_by_profile_id,
                    ) = evaluate_device_configuration_control_queries(profiles, selected_control)
                    severity_by_profile_id = {
                        profile_id: severity_label(severity_value)
                        for profile_id, severity_value in severity_by_profile_id.items()
                    }
                    context["show_control_severity"] = True
                    context["selected_control_query_count"] = len(active_queries)
                    context["selected_control_skipped_queries"] = skipped_queries
                    context["search_summary"] = (
                        f"Control candidates: {selected_control.control_id} "
                        f"({len(active_queries)} quer{'y' if len(active_queries) == 1 else 'ies'})"
                    )
                    filter_suffix = f"&control={control_id}"
            except (Control.DoesNotExist, ValueError, TypeError):
                context["search_error"] = "Control could not be found."

        elif control_query_id:
            try:
                selected_control_query = ControlQuery.objects.select_related("control").get(
                    pk=int(control_query_id)
                )
                canonical_query = selected_control_query.canonical_query
                if not isinstance(canonical_query, dict) or canonical_query.get("model") != DEVICE_CONFIGURATION_MODEL:
                    context["search_error"] = "This query does not target device configuration profiles."
                    selected_control_query = None
                else:
                    try:
                        profiles = apply_search_node(profiles, canonical_query)
                        context["search_summary"] = (
                            f"Query: {selected_control_query.control.control_id} / "
                            f"{selected_control_query.name}"
                        )
                        filter_suffix = f"&control_query={control_query_id}"
                    except SearchSyntaxError as exc:
                        context["search_error"] = str(exc) or "Saved query is invalid."
                        selected_control_query = None
            except (ControlQuery.DoesNotExist, ValueError, TypeError):
                context["search_error"] = "Saved query could not be found."

        context["selected_control"] = selected_control
        context["selected_control_query"] = selected_control_query
        context["filter_suffix"] = filter_suffix

        # Filtering complete — now paginate.
        paginator = Paginator(profiles, PAGE_SIZE)
        page_obj = paginator.get_page(self.request.GET.get("page"))

        context["profile_rows"] = build_profile_rows(
            page_obj.object_list,
            severity_by_profile_id=severity_by_profile_id,
        )
        context["page_obj"] = page_obj
        context["page_range"] = pagination_range(page_obj)
        context["total_row_count"] = paginator.count

        return context


class ControlRunFindingsView(View):
    def post(self, request, *args, **kwargs):
        result = regenerate_rule_findings()
        messages.success(
            request,
            (
                f"Rule findings regenerated. Controls: {result.controls_evaluated}. "
                f"Findings: {result.findings_created}. Query links: {result.query_links_created}. "
                f"Skipped queries: {result.skipped_queries}."
            ),
        )
        return HttpResponseRedirect(reverse("assessment_control_list"))


class ControlRunDeviceConfigurationFindingsView(View):
    def post(self, request, *args, **kwargs):
        result = regenerate_device_configuration_findings()
        messages.success(
            request,
            (
                f"Device configuration findings regenerated. Controls: {result.controls_evaluated}. "
                f"Findings: {result.findings_created}. Query links: {result.query_links_created}. "
                f"Skipped queries: {result.skipped_queries}."
            ),
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


class SecurityRuleListView(TemplateView):
    template_name = "assessments/security_rule_list.html"

    def post(self, request, *args, **kwargs):
        query_text = request.POST.get("q", "")
        search_payload = request.POST.get("search", "").strip() or query_text.strip()
        if not search_payload:
            return HttpResponseRedirect(reverse("assessment_security_rule_list"))

        try:
            _queryset, canonical_query = apply_search(
                SecurityRule.objects.none(),
                search_payload,
            )
        except SearchSyntaxError:
            context = self.get_context_data(**kwargs)
            context["search_error"] = "Search payload must be valid canonical search JSON."
            context["query_text"] = query_text
            context["search_payload"] = search_payload
            context["search_editor_query"] = search_payload
            context["overlay_is_open"] = True
            context["overlay_close_url"] = build_query_string_without(request, "edit_search")
            return self.render_to_response(context)

        search_state = SecurityRuleSearchState.objects.create(
            query_text=query_text,
            canonical_query=canonical_query,
        )
        return HttpResponseRedirect(
            f"{reverse('assessment_security_rule_list')}?search_state={search_state.token}"
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        selected_control_query = None
        selected_control = None
        security_rules = build_security_rule_display_queryset()
        context["query_text"] = ""
        context["search_payload"] = ""
        context["search_error"] = ""
        context["search_query"] = None
        context["search_summary"] = "No search applied"
        context["search_state_token"] = self.request.GET.get("search_state", "")
        context["show_control_severity"] = False
        severity_by_rule_id = {}
        control_query_id = self.request.GET.get("control_query")
        control_id = self.request.GET.get("control")
        context["edit_search_open"] = self.request.GET.get("edit_search") == "1"
        context["applied_control_close_url"] = build_query_string_without(
            self.request,
            "control",
        )
        context["edit_search_close_url"] = build_query_string_without(
            self.request,
            "edit_search",
            "control_query",
            "control",
        )
        context["plain_language_edit_url"] = ""

        if control_query_id:
            try:
                selected_control_query = ControlQuery.objects.select_related("control").get(
                    pk=int(control_query_id)
                )
                q_model = (
                    selected_control_query.canonical_query.get("model")
                    if isinstance(selected_control_query.canonical_query, dict)
                    else None
                )
                if q_model and q_model != SECURITY_RULE_QUERY_MODEL:
                    context["search_error"] = (
                        f"This query targets {q_model} and cannot be applied to security rules."
                    )
                    selected_control_query = None
                    context["edit_search_open"] = True
            except (ControlQuery.DoesNotExist, ValueError, TypeError):
                context["search_error"] = "Saved query could not be found."
                context["edit_search_open"] = True

        if control_id:
            try:
                selected_control = Control.objects.get(pk=int(control_id))
                if selected_control.target_model and selected_control.target_model != SECURITY_RULE_QUERY_MODEL:
                    context["search_error"] = (
                        f"Control {selected_control.control_id} targets "
                        f"{selected_control.target_model} and cannot be applied to security rules."
                    )
                    selected_control = None
            except (Control.DoesNotExist, ValueError, TypeError):
                context["search_error"] = "Control could not be found."

        if context["search_state_token"]:
            try:
                search_state = SecurityRuleSearchState.objects.get(
                    token=context["search_state_token"]
                )
                canonical_query = search_state.canonical_query
                if (
                    isinstance(canonical_query, dict)
                    and "operator" in canonical_query
                    and "model" not in canonical_query
                ):
                    canonical_query = {
                        "model": SECURITY_RULE_QUERY_MODEL,
                        **canonical_query,
                    }
                security_rules = apply_search_node(
                    security_rules,
                    canonical_query,
                )
                context["search_query"] = canonical_query
                context["search_summary"] = describe_search_node(canonical_query)
                context["query_text"] = search_state.query_text
                context["search_payload"] = json.dumps(canonical_query)
                if search_state.query_text:
                    context["plain_language_edit_url"] = (
                        f"{reverse('assessment_security_rule_plain_language')}?search_state={search_state.token}"
                    )
            except (SecurityRuleSearchState.DoesNotExist, SearchSyntaxError) as exc:
                context["search_error"] = str(exc) or "Stored search state is invalid."
                context["edit_search_open"] = True
        elif selected_control:
            (
                security_rules,
                active_queries,
                skipped_queries,
                _matched_by_rule,
                severity_by_rule_id,
            ) = evaluate_control_queries(security_rules, selected_control)
            severity_by_rule_id = {
                rule_id: severity_label(severity_value)
                for rule_id, severity_value in severity_by_rule_id.items()
            }
            context["selected_control"] = selected_control
            context["selected_control_query_count"] = len(active_queries)
            context["selected_control_skipped_queries"] = skipped_queries
            context["show_control_severity"] = True
            context["search_summary"] = (
                f"Control candidates: {selected_control.control_id} ({len(active_queries)} quer"
                f"{'y' if len(active_queries) == 1 else 'ies'})"
            )
        elif selected_control_query and isinstance(selected_control_query.canonical_query, dict):
            try:
                canonical_query = selected_control_query.canonical_query
                security_rules = apply_search_node(
                    security_rules,
                    canonical_query,
                )
                context["search_query"] = canonical_query
                context["search_summary"] = describe_search_node(canonical_query)
                context["search_payload"] = json.dumps(canonical_query)
            except SearchSyntaxError as exc:
                context["search_error"] = str(exc) or "Saved query is invalid."
                context["edit_search_open"] = True

        editor_query = context["search_query"] or default_security_rule_search_query()
        if selected_control_query and isinstance(selected_control_query.canonical_query, dict):
            editor_query = selected_control_query.canonical_query

        context["search_editor_query"] = json.dumps(
            editor_query,
            indent=2,
        )
        context["selected_control_query"] = selected_control_query
        context.setdefault("selected_control", selected_control)

        filter_applied = bool(
            context["search_state_token"] or selected_control or selected_control_query
        )
        if filter_applied:
            paginator = Paginator(security_rules, PAGE_SIZE)
            page_obj = paginator.get_page(self.request.GET.get("page"))
            page_rules = page_obj.object_list
            total_row_count = paginator.count
        else:
            # No search/control filter active - serve the unfiltered listing from the
            # cached pk order instead of re-running the full ordering query on every
            # request. Paginator accepts plain sequences (count falls back to len()),
            # so page_obj's interface is identical either way.
            pks = get_cached_security_rule_pks()
            paginator = Paginator(pks, PAGE_SIZE)
            page_obj = paginator.get_page(self.request.GET.get("page"))
            page_pks = list(page_obj.object_list)
            # build_security_rule_display_queryset()'s own order_by is the same
            # deterministic total order the pks were cached with, so filtering to just
            # this page's pks reproduces the correct order without re-sorting in Python.
            page_rules = list(build_security_rule_display_queryset().filter(pk__in=page_pks))
            total_row_count = paginator.count

        context["security_rule_rows"] = build_security_rule_rows(
            page_rules,
            severity_by_rule_id=severity_by_rule_id,
        )
        context["page_obj"] = page_obj
        context["page_range"] = pagination_range(page_obj)
        context["total_row_count"] = total_row_count
        return context
