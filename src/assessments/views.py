"""Assessment-facing views.

This module owns read-oriented assessment surfaces built on top of normalized
integration data. Keep collector and normalization logic in `integrations`.
"""

import json
import tempfile
from pathlib import Path
from urllib.parse import urlencode

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
from assessments.configuration_findings import regenerate_configuration_findings
from assessments.controls_catalog.drift import catalog_has_drifted
from assessments.management_interface_naming import surface_label
from django.contrib.contenttypes.models import ContentType

from assessments.search.management_interface.fields.services import (
    ADMINISTRATIVE_SERVICES,
    INSECURE_SERVICES,
)
from assessments.search.management_interface.fields.exposure import (
    exposure_by_interface,
)
from assessments.models import (
    ApplicationEnvironmentCatalogState,
    Control,
    ControlQuery,
    CertificateProfileFinding,
    DeviceConfigurationFinding,
    InterfaceManagementProfileFinding,
    ManagementInterfaceFinding,
    RuleFinding,
    SecurityRuleSearchState,
    SslTlsServiceProfileFinding,
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
    entry_device_group_name,
    listed_address_ref_values,
    listed_member_values,
    security_rule_config_source_label,
)
from optivedge.models import ApplicationEnvironment
from optivedge_integrations.integrations.models import (
    CertificateProfile,
    DeviceConfigurationProfile,
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
#: Two controls, one object, and they fail independently - the floor and the algorithms. Shown
#: together on one row per profile, because an engineer fixes the profile, not the control.
SSL_TLS_PROFILE_CONTROLS = ("PAN-CRT-005", "PAN-CRT-009")
CERTIFICATE_PROFILE_CONTROLS = ("PAN-CRT-004",)


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

    def _finding_display(self, finding):
        status_text_class, status_dot_class = _STATUS_BADGE.get(
            finding.status, ("text-slate-700", "bg-slate-400")
        )
        return {
            "id": finding.pk,
            "severity": finding.severity,
            "severity_label": finding.get_severity_display(),
            "severity_classes": _SEVERITY_BADGE_CLASSES.get(finding.severity, ""),
            "status": finding.status,
            "status_label": finding.get_status_display(),
            "status_text_class": status_text_class,
            "status_dot_class": status_dot_class,
            "control_id": finding.control.control_id,
            "control_name": finding.control.name,
            "title": finding.title,
            "summary": finding.summary,
            "matched_query_names": finding.matched_query_names,
            "security_rule_id": finding.security_rule_id,
            "rule_name": finding.security_rule.name,
            "rule_order": finding.security_rule.effective_order,
            "rule_scope": _finding_scope_label(finding.security_rule),
        }

    def _security_rule_context(self):
        request = self.request
        group_by = request.GET.get("group", "control")
        if group_by not in {"control", "rule"}:
            group_by = "control"
        selected_severities = [
            value for value in request.GET.getlist("severity") if value in _SEVERITY_RANK
        ]
        hide_suppressed = request.GET.get("hide_suppressed") == "1"

        # matched_query_names is a stored snapshot on the finding, so the list no longer
        # needs the control_queries M2M prefetch.
        base_findings = RuleFinding.objects.select_related(
            "control",
            "security_rule",
            "security_rule__management_station",
            "security_rule__enforcement_point",
        )

        # Severity summary — stable totals across the whole tab, so the chips also
        # read as "how bad is it overall", independent of the active filters.
        severity_counts = {
            row["severity"]: row["n"]
            for row in RuleFinding.objects.values("severity").annotate(n=Count("id"))
        }

        try:
            selected_finding_id = int(request.GET.get("finding"))
        except (TypeError, ValueError):
            selected_finding_id = None

        list_findings = base_findings
        if selected_severities:
            list_findings = list_findings.filter(severity__in=selected_severities)
        if hide_suppressed:
            list_findings = list_findings.exclude(status=RuleFinding.Status.SUPPRESSED)
        findings = list(list_findings)

        groups_map = {}
        for finding in findings:
            if group_by == "control":
                # A control can yield findings at different (per-query adjusted) severities;
                # each control+severity is its own section, so a section is uniform severity.
                key = (finding.control.control_id, finding.severity)
                header = {
                    "kind": "control",
                    "mono_primary": True,
                    "primary": finding.control.control_id,
                    "secondary": finding.control.name,
                }
            else:
                key = finding.security_rule_id
                header = {
                    "kind": "rule",
                    "mono_primary": False,
                    "primary": finding.security_rule.name,
                    "secondary": f"order {finding.security_rule.effective_order} · "
                    f"{_finding_scope_label(finding.security_rule)}",
                }
            group = groups_map.get(key)
            if group is None:
                group = {"header": header, "findings": [], "max_rank": -1}
                groups_map[key] = group
            group["findings"].append(self._finding_display(finding))
            group["max_rank"] = max(group["max_rank"], _severity_rank(finding.severity))

        groups = list(groups_map.values())
        for group in groups:
            group["findings"].sort(key=lambda item: -_severity_rank(item["severity"]))
            worst = _SEVERITY_ORDER[len(_SEVERITY_ORDER) - 1 - group["max_rank"]]
            group["count"] = len(group["findings"])
            group["worst_label"] = _SEVERITY_LABELS.get(worst, worst)
            group["worst_classes"] = _SEVERITY_BADGE_CLASSES.get(worst, "")
        groups.sort(
            key=lambda group: (-group["max_rank"], -group["count"], str(group["header"]["primary"]))
        )

        paginator = Paginator(groups, FINDING_GROUP_PAGE_SIZE)
        page_obj = paginator.get_page(request.GET.get("page"))

        # Rule config for the expanded rows — bounded to the rules actually on this page,
        # so the heavy display prefetch never scales with the full finding count.
        page_rule_ids = {
            item["security_rule_id"]
            for group in page_obj.object_list
            for item in group["findings"]
        }
        row_by_rule = {}
        if page_rule_ids:
            page_rows = build_security_rule_rows(
                list(build_security_rule_display_queryset().filter(pk__in=page_rule_ids))
            )
            row_by_rule = {row["security_rule"].pk: row for row in page_rows}

        # Row links carry the current page so closing the detail overlay returns here.
        for group in page_obj.object_list:
            for item in group["findings"]:
                item["rule_row"] = row_by_rule.get(item["security_rule_id"])
                item["detail_url"] = build_finding_querystring(
                    group=group_by,
                    severities=selected_severities,
                    hide_suppressed=hide_suppressed,
                    page=page_obj.number,
                    finding=item["id"],
                )
            # The section owning the selected finding renders expanded, so the detail
            # overlay's context is visible (browsers don't restore <details> state on reload).
            group["has_selected"] = selected_finding_id is not None and any(
                item["id"] == selected_finding_id for item in group["findings"]
            )
            # When grouped by rule, the group *is* one rule — show its config once.
            if group_by == "rule" and group["findings"]:
                first_row = row_by_rule.get(group["findings"][0]["security_rule_id"])
                group["rule_config"] = _finding_rule_config(first_row) if first_row else None

        severity_summary = []
        for value in _SEVERITY_ORDER:
            count = severity_counts.get(value, 0)
            if value == "informational" and count == 0:
                continue
            if value in selected_severities:
                toggled = [s for s in selected_severities if s != value]
            else:
                toggled = selected_severities + [value]
            severity_summary.append({
                "value": value,
                "label": _SEVERITY_LABELS.get(value, value),
                "count": count,
                "active": value in selected_severities,
                "swatch_class": _SEVERITY_SWATCH_CLASSES.get(value, "bg-slate-300"),
                "url": build_finding_querystring(
                    group=group_by, severities=toggled, hide_suppressed=hide_suppressed
                ),
            })

        pagination_base = urlencode(
            [("tab", "security-rules"), ("group", group_by)]
            + [("severity", value) for value in selected_severities]
            + ([("hide_suppressed", "1")] if hide_suppressed else []),
            doseq=True,
        )

        context = {
            "security_group_by": group_by,
            "severity_summary": severity_summary,
            "selected_severities": selected_severities,
            "hide_suppressed": hide_suppressed,
            "hide_suppressed_url": build_finding_querystring(
                group=group_by, severities=selected_severities, hide_suppressed=not hide_suppressed
            ),
            "group_control_url": build_finding_querystring(
                group="control", severities=selected_severities, hide_suppressed=hide_suppressed
            ),
            "group_rule_url": build_finding_querystring(
                group="rule", severities=selected_severities, hide_suppressed=hide_suppressed
            ),
            "finding_groups": page_obj.object_list,
            "total_findings": len(findings),
            "page_obj": page_obj,
            "page_range": pagination_range(page_obj),
            "pagination_base": pagination_base,
        }
        context.update(
            self._selected_finding_context(
                group_by=group_by,
                selected_severities=selected_severities,
                hide_suppressed=hide_suppressed,
                page_number=page_obj.number,
            )
        )
        return context

    def _selected_finding_context(self, *, group_by, selected_severities, hide_suppressed, page_number):
        finding_id = self.request.GET.get("finding")
        if not finding_id:
            return {}
        finding = (
            RuleFinding.objects.select_related("control", "security_rule")
            .filter(pk=finding_id)
            .first()
        )
        if finding is None:
            return {}
        rule = build_security_rule_display_queryset().filter(pk=finding.security_rule_id).first()
        rule_row = build_security_rule_rows([rule])[0] if rule is not None else None
        status_text_class, status_dot_class = _STATUS_BADGE.get(
            finding.status, ("text-slate-700", "bg-slate-400")
        )
        selected_finding = {
            "id": finding.pk,
            "control_id": finding.control.control_id,
            "control_name": finding.control.name,
            "title": finding.title,
            "summary": finding.summary,
            "severity_label": finding.get_severity_display(),
            "severity_classes": _SEVERITY_BADGE_CLASSES.get(finding.severity, ""),
            "status_label": finding.get_status_display(),
            "status_text_class": status_text_class,
            "status_dot_class": status_dot_class,
            "description": finding.control.description,
            "rationale": finding.control.rationale,
            "remediation": finding.control.remediation,
            # Frozen snapshot of the matched query names, same source as the list column.
            "matched_query_names": finding.matched_query_names,
            "rule_row": rule_row,
        }
        return {
            "selected_finding": selected_finding,
            "overlay_is_open": True,
            "overlay_panel_class": "w-[34rem] max-w-[calc(100vw-15rem)]",
            "overlay_close_url": build_finding_querystring(
                group=group_by,
                severities=selected_severities,
                hide_suppressed=hide_suppressed,
                page=page_number,
            ),
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


class ManagementInterfaceListView(TemplateView):
    """Management surfaces and their permitted sources - configuration, not findings.

    Separate from the device-configuration table because that one was accumulating a column
    group per subject (HA, services, permitted IPs, banner, NTP) and each new finding type
    widened it further. A surface is its own row here, which is also the row a finding
    attaches to.
    """

    template_name = "assessments/management_interface_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        findings_only = self.request.GET.get("findings") == "1"
        # Provenance doubles the height of every populated cell, so it is off by default and
        # asked for. One toggle for the whole table rather than per column: the question a
        # reader has is "where did any of this come from", not "where did this one value".
        show_provenance = self.request.GET.get("provenance") == "1"

        surfaces = list(
            ManagementInterface.objects.select_related("appliance", "source_snapshot")
            .prefetch_related("permitted_sources", "services")
            .order_by("appliance__hostname", "plane", "interface_name")
        )
        exposure = exposure_by_interface()

        findings_by_surface = {}
        for finding in (
            ManagementInterfaceFinding.objects.select_related("control")
            .filter(status=ManagementInterfaceFinding.Status.OPEN)
            .order_by("control__control_id")
        ):
            findings_by_surface.setdefault(finding.management_interface_id, []).append(finding)

        # Three lookups for the page, not three per row.
        surface_sources = _entry_provenance(surfaces)
        # The binding is a field OF the surface, so it has its own row - a locally created
        # interface can bind a template-pushed profile, and the reverse.
        binding_sources = _entry_provenance(surfaces, "profile_name")
        all_services = [s for surface in surfaces for s in surface.services.all()]
        service_sources = _entry_provenance(all_services)
        all_permitted = [p for surface in surfaces for p in surface.permitted_sources.all()]
        permitted_sources = _entry_provenance(all_permitted)

        rows = [
            {
                "surface": surface,
                "label": surface_label(surface),
                "provenance": surface_sources.get(surface.pk, ""),
                "binding_provenance": binding_sources.get(surface.pk, ""),
                "exposure": exposure.get(surface.pk, ""),
                "sources": [
                    {"source": source, "provenance": permitted_sources.get(source.pk, "")}
                    for source in surface.permitted_sources.all()
                ],
                "services": _administrative_service_cells(surface, service_sources),
                "findings": findings_by_surface.get(surface.pk, []),
            }
            for surface in surfaces
        ]
        shown = [row for row in rows if row["findings"]] if findings_only else rows

        context["rows"] = shown
        context["findings_only"] = findings_only
        context["show_provenance"] = show_provenance
        context["total_count"] = len(rows)
        context["shown_count"] = len(shown)
        return context


class InterfaceManagementProfileListView(TemplateView):
    """Profiles as objects, with a findings-only filter.

    A separate tab from Management Interfaces rather than a section of it, because a
    profile is not a surface. The surfaces tab answers "what is this door exposed to"; an
    unused profile opens no door at all, and putting it there would imply exposure the
    finding is careful not to claim.
    """

    template_name = "assessments/interface_management_profile_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        findings_only = self.request.GET.get("findings") == "1"
        show_provenance = self.request.GET.get("provenance") == "1"

        profiles = list(
            InterfaceManagementProfile.objects.select_related("appliance", "source_snapshot")
            .order_by("appliance__hostname", "name")
        )

        findings_by_profile = {}
        for finding in (
            InterfaceManagementProfileFinding.objects.select_related("control")
            .filter(status=InterfaceManagementProfileFinding.Status.OPEN)
        ):
            findings_by_profile.setdefault(
                finding.interface_management_profile_id, []).append(finding)

        # A profile overrides at the ENTRY, so it has one provenance - unlike a management
        # surface, whose services and sources each carry their own.
        origin_by_profile = _entry_provenance(profiles)

        rows = [
            {
                "profile": profile,
                "origin": origin_by_profile.get(profile.pk, ""),
                "findings": findings_by_profile.get(profile.pk, []),
            }
            for profile in profiles
        ]
        shown = [row for row in rows if row["findings"]] if findings_only else rows

        context["rows"] = shown
        context["findings_only"] = findings_only
        context["show_provenance"] = show_provenance
        context["total_count"] = len(rows)
        context["shown_count"] = len(shown)
        return context


class LoginBannerListView(TemplateView):
    """The login banner and its acknowledgement, with findings and provenance toggles.

    Its own tab rather than columns on Device Configuration, for the reason that table was
    broken up in the first place: it was accumulating a column group per finding type and
    each new control widened it. The banner and its acknowledgement are one subject with two
    controls between them - PAN-MGT-007 and PAN-MGT-008 - so they belong together and apart.

    Unlike the surfaces and profiles tabs, provenance here is stored under NAMED fields
    rather than "__entry__": a DeviceConfigurationProfile carries many values on one row, so
    each field has its own provenance record.
    """

    template_name = "assessments/login_banner_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        findings_only = self.request.GET.get("findings") == "1"
        show_provenance = self.request.GET.get("provenance") == "1"

        profiles = list(
            DeviceConfigurationProfile.objects.select_related("appliance", "source_snapshot")
            .order_by("appliance__hostname")
        )

        findings_by_profile = {}
        for finding in (
            DeviceConfigurationFinding.objects.select_related("control")
            .filter(status=DeviceConfigurationFinding.Status.OPEN,
                    control__control_id__in=BANNER_CONTROLS)
        ):
            findings_by_profile.setdefault(
                finding.device_configuration_profile_id, []).append(finding)

        banner_sources = _entry_provenance(profiles, "login_banner")
        ack_sources = _entry_provenance(profiles, "ack_login_banner")

        rows = [
            {
                "profile": profile,
                "banner_provenance": banner_sources.get(profile.pk, ""),
                "ack_provenance": ack_sources.get(profile.pk, ""),
                "findings": findings_by_profile.get(profile.pk, []),
            }
            for profile in profiles
        ]
        shown = [row for row in rows if row["findings"]] if findings_only else rows

        context["rows"] = shown
        context["findings_only"] = findings_only
        context["show_provenance"] = show_provenance
        context["total_count"] = len(rows)
        context["shown_count"] = len(shown)
        return context


class ManagementTlsListView(TemplateView):
    """What the management web interface negotiates, and what it presents while doing it.

    Its own tab rather than columns on Device Configuration, for the reason recorded on
    LoginBannerListView: that table was accumulating a column group per finding type and each
    new control widened it. This subject needs five columns on its own, and the tab it would
    otherwise have widened is being retired in favour of exactly this shape.

    The two controls are shown side by side because the interesting rows are the ones where
    they disagree. A device bound to the shipped TLSv1.3_Default profile passes PAN-MGT-010
    with the strongest protocol floor available and fails PAN-CRT-006, because that profile's
    certificate is the device's own self-signed one. Splitting them across tabs would hide
    the single most common remediation trap.

    Provenance is under a NAMED field rather than "__entry__" - a DeviceConfigurationProfile
    carries many values on one row - and only the BINDING has any. The resolved values are
    read from a profile object elsewhere in the tree, so they carry no @ptpl of their own and
    a provenance line under them would be an invention.
    """

    template_name = "assessments/management_tls_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        findings_only = self.request.GET.get("findings") == "1"
        show_provenance = self.request.GET.get("provenance") == "1"

        profiles = list(
            DeviceConfigurationProfile.objects.select_related("appliance", "source_snapshot")
            .order_by("appliance__hostname")
        )

        findings_by_profile = {}
        for finding in (
            DeviceConfigurationFinding.objects.select_related("control")
            .filter(status=DeviceConfigurationFinding.Status.OPEN,
                    control__control_id__in=MANAGEMENT_TLS_CONTROLS)
        ):
            findings_by_profile.setdefault(
                finding.device_configuration_profile_id, []).append(finding)

        binding_sources = _entry_provenance(profiles, "ssl_tls_service_profile_name")

        rows = [
            {
                "profile": profile,
                "binding_provenance": binding_sources.get(profile.pk, ""),
                "findings": findings_by_profile.get(profile.pk, []),
            }
            for profile in profiles
        ]
        shown = [row for row in rows if row["findings"]] if findings_only else rows

        context["rows"] = shown
        context["findings_only"] = findings_only
        context["show_provenance"] = show_provenance
        context["total_count"] = len(rows)
        context["shown_count"] = len(shown)
        return context


class SslTlsServiceProfileListView(TemplateView):
    """Every SSL/TLS service profile as an OBJECT, with all its findings on one row.

    The difference from the Management TLS tab is the subject. That one asks what the
    management interface has BOUND - one row per appliance. This asks about every profile on
    the device whether anything uses it or not, which is what PAN-CRT-005 and PAN-CRT-009
    assess, and a profile nobody has bound yet is exactly the one an audit of the bound
    profile misses.

    Both controls appear in the same row rather than on separate tabs. They fail
    independently - the protocol floor and the algorithms - so a profile can carry one, both
    or neither, and splitting them would imply two problems where there is one object to
    remediate.

    Scope is shown beside the name because a name is NOT unique on a device: TLSv1.3_Default
    exists as both a predefined and a shared entry, and the predefined definition is the one
    in force.
    """

    template_name = "assessments/ssl_tls_service_profile_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        findings_only = self.request.GET.get("findings") == "1"
        show_provenance = self.request.GET.get("provenance") == "1"

        profiles = list(
            SslTlsServiceProfile.objects.select_related("appliance", "source_snapshot")
            .order_by("appliance__hostname", "scope", "name")
        )
        findings_by_profile = {}
        for finding in (
            SslTlsServiceProfileFinding.objects.select_related("control")
            .filter(status=SslTlsServiceProfileFinding.Status.OPEN,
                    control__control_id__in=SSL_TLS_PROFILE_CONTROLS)
        ):
            findings_by_profile.setdefault(
                finding.ssl_tls_service_profile_id, []).append(finding)

        sources = _entry_provenance(profiles)
        rows = []
        for profile in profiles:
            algorithms = profile.protocol_algorithms or {}
            # Named explicitly rather than "everything not AEAD": these are the three the
            # remediation calls out, and a list that drifts from the remediation is worse
            # than a short one.
            weak = [label for label, key in (
                ("SHA1", "auth-algo-sha1"),
                ("AES-128-CBC", "enc-algo-aes-128-cbc"),
                ("AES-256-CBC", "enc-algo-aes-256-cbc"),
                ("static RSA", "keyxchg-algo-rsa"),
            ) if algorithms.get(key)]
            rows.append({
                "profile": profile,
                "weak_algorithms": weak,
                # Absent keys are why this matters: a profile that wrote nothing permits
                # everything, and the row should say which of the two it is.
                "algorithms_are_implicit": not profile.explicit_algorithms,
                "provenance": sources.get(profile.pk, ""),
                "findings": findings_by_profile.get(profile.pk, []),
            })
        shown = [row for row in rows if row["findings"]] if findings_only else rows

        context["rows"] = shown
        context["findings_only"] = findings_only
        context["show_provenance"] = show_provenance
        context["total_count"] = len(rows)
        context["shown_count"] = len(shown)
        return context


class CertificateProfileListView(TemplateView):
    """Every certificate profile, with what it actually checks.

    All six booleans default OFF, so a profile that sets nothing validates against a CA and
    never asks whether the certificate was revoked. The row shows the absence rather than
    leaving blanks, because blank reads as "not applicable" and this is "not checking".
    """

    template_name = "assessments/certificate_profile_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        findings_only = self.request.GET.get("findings") == "1"
        show_provenance = self.request.GET.get("provenance") == "1"

        profiles = list(
            CertificateProfile.objects.select_related("appliance", "source_snapshot")
            .order_by("appliance__hostname", "scope", "name")
        )
        findings_by_profile = {}
        for finding in (
            CertificateProfileFinding.objects.select_related("control")
            .filter(status=CertificateProfileFinding.Status.OPEN,
                    control__control_id__in=CERTIFICATE_PROFILE_CONTROLS)
        ):
            findings_by_profile.setdefault(finding.certificate_profile_id, []).append(finding)

        sources = _entry_provenance(profiles)
        rows = []
        for profile in profiles:
            checks = [label for label, on in (
                ("CRL", profile.use_crl), ("OCSP", profile.use_ocsp)) if on]
            blocks = [label for label, on in (
                ("expired", profile.block_expired_cert),
                ("unknown", profile.block_unknown_cert),
                ("timeout", profile.block_timeout_cert),
                ("unauthenticated", profile.block_unauthenticated_cert)) if on]
            rows.append({
                "profile": profile,
                "revocation_checks": checks,
                "blocks": blocks,
                "provenance": sources.get(profile.pk, ""),
                "findings": findings_by_profile.get(profile.pk, []),
            })
        shown = [row for row in rows if row["findings"]] if findings_only else rows

        context["rows"] = shown
        context["findings_only"] = findings_only
        context["show_provenance"] = show_provenance
        context["total_count"] = len(rows)
        context["shown_count"] = len(shown)
        return context


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
    def post(self, request, *args, **kwargs):
        result = regenerate_rule_findings()
        report_finding_run(
            request,
            (
                f"Rule findings regenerated. Controls: {result.controls_evaluated}. "
                f"Findings: {result.findings_created}. Query links: {result.query_links_created}. "
                f"Skipped queries: {result.skipped_queries}."
            ),
            skipped_queries=result.skipped_queries,
        )
        return HttpResponseRedirect(reverse("assessment_control_list"))


class ControlRunConfigurationFindingsView(View):
    """Everything that is not policy, in one run - see assessments.configuration_findings."""

    def post(self, request, *args, **kwargs):
        result = regenerate_configuration_findings()
        report_finding_run(
            request,
            (
                f"Configuration findings regenerated. Controls: {result.controls_evaluated}. "
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
