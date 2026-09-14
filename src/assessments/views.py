"""Assessment-facing views.

This module owns read-oriented assessment surfaces built on top of normalized
integration data. Keep collector and normalization logic in `integrations`.
"""

import datetime as _dt
import json
import tempfile
from pathlib import Path
from urllib.parse import urlencode

from assessments.forms import ControlForm, ControlQueryForm
from assessments.control_queries import (
    SECURITY_RULE_QUERY_MODEL,
    default_security_rule_search_query,
    evaluate_control_queries,
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
from assessments.tables import Column
from assessments import configuration_navigation as config_nav
from assessments import configuration_results as config_results
from django.contrib.contenttypes.models import ContentType

from assessments.search.management_interface.fields.services import (
    ADMINISTRATIVE_SERVICES,
    INSECURE_SERVICES,
)
from assessments.search.management_interface.fields.exposure import (
    exposure_by_interface,
)
from assessments.models import (
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
    SecurityRuleSearchState,
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
from django.http import Http404, HttpResponse, HttpResponseRedirect
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


class LegacyFindingListView(TemplateView):
    """PENDING REPLACEMENT. Do not extend this view or wire new finding models into it.

    Jason, 2026-09-03: "The Findings menu item is not anchored to anything permanent right
    now." It is too flat to be useful - the device-configuration half is a queryset ordered by
    `-created_at` and paginated, with no grouping, no severity filter and no object context -
    and the per-object tabs strictly dominate it for browsing.

    It is also INCOMPLETE, which is part of why it reads as thin. Eighteen finding models exist
    and this view knows one: RuleFinding. ManagementInterface,
    InterfaceManagementProfile, SslTlsServiceProfile, CertificateProfile and Certificate
    findings do not appear at all - 22 of the lab's 72 findings, the whole certificates domain
    among them. Nothing fails; they are simply not queried.

    Deliberately NOT fixed. The enumeration is expected to change as the remaining domains
    land, so wiring five models into a view that is being replaced would be work done twice.

    What replaces it, when the object tabs are further along:
      - per-object browsing -> the object tabs, which already do this better
      - "everything wrong on ONE appliance, across every object type" -> a per-appliance
        rollup, which no object tab can answer because each tab is one model by construction
      - the client deliverable -> the report path, which has the same two-model gap

    Whatever replaces it should DERIVE its finding-model set from the registry rather than
    naming models, which is the pattern that would have prevented this drift.
    """

    template_name = "assessments/finding_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # One tab now. The device-configuration tab went with DeviceConfigurationFinding on
        # 2026-09-11; a bookmarked ?tab=device-configuration lands here rather than erroring.
        context["active_tab"] = "security-rules"
        context.update(self._security_rule_context())
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


class RuleFindingDocxDownloadView(View):
    """Covers RuleFinding only - see reporting/context.py. DeviceConfigurationFinding was the
    other, until that model was deleted on 2026-09-11.

    The other seventeen finding models reach no client deliverable. Worse, this 500s outright when
    there are no RuleFinding rows at all: `build_report_context()` raises rather than reporting
    on what exists. The lab has 72 findings, none of them rule findings, and both downloads
    fail there today.

    Deliberately not fixed; the enumeration is expected to change as the remaining domains
    land. See `LegacyFindingListView` for the full account.
    """

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


class DeviceTabListView(TemplateView):
    """The shape every device tab shares: subjects, their open findings, and two toggles.

    Nine views repeated the same forty lines - read two query parameters, load a queryset,
    group findings by subject id, build a row per subject, filter to rows with findings, and
    set four counts. A subclass now declares what differs and implements `build_row`.

    `finding_controls` empty means EVERY control of that finding model, which is what the
    interface-profile tab wants. Naming them is for tabs showing one slice of a model's
    findings - no two tabs share a finding model today, but four did until 2026-09-10 and the
    next pair that does will need it.

    Ordering is declared rather than defaulted because it is load-bearing for the rendered
    page, and three of these tabs sort by more than hostname.
    """

    #: Rendered by `{% table_header %}`; its length is what the squareness test checks.
    COLUMNS: tuple = ()
    tab_title = ""
    all_label = "All appliances"
    has_provenance_toggle = False

    subject_model = None
    subject_select_related: tuple = ("appliance", "source_snapshot")
    subject_order: tuple = ("appliance__hostname",)

    finding_model = None
    #: Attribute on the finding holding the subject, without the `_id` suffix.
    finding_subject_field = ""
    finding_controls: tuple = ()
    finding_order: tuple = ()

    def get_subjects(self):
        return list(
            self.subject_model.objects
            .select_related(*self.subject_select_related)
            .order_by(*self.subject_order)
        )

    def findings_by_subject(self) -> dict:
        """{subject pk: [open findings]}. One query for the page, not one per row."""
        queryset = self.finding_model.objects.select_related("control")
        if self.finding_controls:
            queryset = queryset.filter(
                status=self.finding_model.Status.OPEN,
                control__control_id__in=self.finding_controls)
        else:
            queryset = queryset.filter(status=self.finding_model.Status.OPEN)
        if self.finding_order:
            queryset = queryset.order_by(*self.finding_order)
        grouped: dict = {}
        attribute = f"{self.finding_subject_field}_id"
        for finding in queryset:
            grouped.setdefault(getattr(finding, attribute), []).append(finding)
        return grouped

    def row_context(self, subjects) -> dict:
        """Anything needing ONE query for the whole page - provenance maps, mostly.

        Passed to every `build_row` call, so a per-row lookup does not become a per-row query.
        """
        return {}

    def build_row(self, subject, findings, **shared) -> dict:
        raise NotImplementedError

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        findings_only = self.request.GET.get("findings") == "1"
        # Ignored on a tab with no provenance to show. Otherwise ?provenance=1 would be
        # carried through the findings link on pages where it means nothing - Master Key and
        # Certificates read provenance no view can supply.
        show_provenance = (self.request.GET.get("provenance") == "1"
                           and self.has_provenance_toggle)

        subjects = self.get_subjects()
        findings_by_pk = self.findings_by_subject()
        shared = self.row_context(subjects)
        rows = [self.build_row(subject, findings_by_pk.get(subject.pk, []), **shared)
                for subject in subjects]
        shown = [row for row in rows if row["findings"]] if findings_only else rows

        context["columns"] = self.COLUMNS
        context["tab_title"] = self.tab_title
        context["all_label"] = self.all_label
        context["has_provenance_toggle"] = self.has_provenance_toggle
        context["rows"] = shown
        context["findings_only"] = findings_only
        context["show_provenance"] = show_provenance
        context["total_count"] = len(rows)
        context["shown_count"] = len(shown)
        return context


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


class InterfaceManagementProfileListView(DeviceTabListView):
    """Profiles as objects, with a findings-only filter.

    A separate tab from Management Interfaces rather than a section of it, because a
    profile is not a surface. The surfaces tab answers "what is this door exposed to"; an
    unused profile opens no door at all, and putting it there would imply exposure the
    finding is careful not to claim.
    """

    template_name = "assessments/interface_management_profile_list.html"

    #: Declared once; the header renders from this and
    #: test_device_tab_tables_are_square checks every body row against its length.
    COLUMNS = (
        Column("Appliance"),
        Column("Profile"),
        Column("Bound To"),
        Column("Findings"),
        Column("Collected"),
    )

    tab_title = "Interface Profiles"
    all_label = "All profiles"
    has_provenance_toggle = True
    subject_model = InterfaceManagementProfile
    subject_order = ("appliance__hostname", "name")
    finding_model = InterfaceManagementProfileFinding
    finding_subject_field = "interface_management_profile"

    def row_context(self, subjects):
        # A profile overrides at the ENTRY, so it has one provenance - unlike a management
        # surface, whose services and sources each carry their own.
        return {"origin_by_profile": _entry_provenance(subjects)}

    def build_row(self, profile, findings, origin_by_profile):
        return {
            "profile": profile,
            "origin": origin_by_profile.get(profile.pk, ""),
            "findings": findings,
        }

class LoginBannerListView(DeviceTabListView):
    """The login banner and its acknowledgement, with findings and provenance toggles.

    Its own tab rather than columns on Device Configuration, for the reason that table was
    broken up in the first place: it was accumulating a column group per finding type and
    each new control widened it. The banner and its acknowledgement are one subject with two
    controls between them - PAN-MGT-007 and PAN-MGT-008 - so they belong together and apart.

    Unlike the surfaces and profiles tabs, provenance here is stored under NAMED fields
    rather than "__entry__": the banner and its acknowledgement are pushed independently, so
    each field has its own provenance record.
    """

    template_name = "assessments/login_banner_list.html"

    #: Declared once; the header renders from this and
    #: test_device_tab_tables_are_square checks every body row against its length.
    COLUMNS = (
        Column("Appliance"),
        Column("Banner"),
        Column("Acknowledge"),
        Column("Findings"),
        Column("Collected"),
    )

    tab_title = "Login Banner"
    has_provenance_toggle = True
    subject_model = LoginBanner
    subject_order = ("appliance__hostname",)
    finding_model = LoginBannerFinding
    finding_subject_field = "login_banner"
    finding_controls = BANNER_CONTROLS

    def row_context(self, subjects):
        return {"banner_sources": _entry_provenance(subjects, "text"),
                "ack_sources": _entry_provenance(subjects, "acknowledgement_required")}

    def build_row(self, profile, findings, banner_sources, ack_sources):
        return {
            "profile": profile,
            "banner_provenance": banner_sources.get(profile.pk, ""),
            "ack_provenance": ack_sources.get(profile.pk, ""),
            "findings": findings,
        }

class ManagementTlsListView(DeviceTabListView):
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

    Provenance is under a NAMED field rather than "__entry__", and only the BINDING has any.
    Since 2026-09-10 the subject is `ManagementTlsBinding`, which reads the floor and the
    certificate THROUGH the profile row rather than copying them - the copies had drifted. The resolved values are
    read from a profile object elsewhere in the tree, so they carry no @ptpl of their own and
    a provenance line under them would be an invention.
    """

    template_name = "assessments/management_tls_list.html"

    #: Declared once; the header renders from this and
    #: test_device_tab_tables_are_square checks every body row against its length.
    COLUMNS = (
        Column("Appliance"),
        Column("Bound Profile"),
        Column("Protocol Range"),
        Column("Certificate"),
        Column("Issuer"),
        Column("Findings"),
        Column("Collected"),
    )

    tab_title = "Management TLS"
    has_provenance_toggle = True
    subject_model = ManagementTlsBinding
    subject_order = ("appliance__hostname",)
    finding_model = ManagementTlsFinding
    finding_subject_field = "management_tls_binding"
    finding_controls = MANAGEMENT_TLS_CONTROLS

    def row_context(self, subjects):
        return {"binding_sources": _entry_provenance(subjects, "profile_name")}

    def build_row(self, profile, findings, binding_sources):
        return {
            "profile": profile,
            "binding_provenance": binding_sources.get(profile.pk, ""),
            "findings": findings,
        }


class ManagementSshListView(DeviceTabListView):
    """What each appliance's management SSH server offers. PAN-MCR-001 and 003.

    Each list says whether it came from the BOUND PROFILE or the DEVICE DEFAULT, because the
    remediation differs - bind a profile, or edit the one bound - and because the default is
    not in the configuration: it was measured (2026-09-11, 11.1 and 11.2, identical) and the row
    says when a release's default is unmeasured. The guidance line repeats what every finding
    says: a bound profile is not in force until the SSH service restarts.
    """

    template_name = "assessments/management_ssh_list.html"
    COLUMNS = (
        Column("Appliance"),
        Column("Bound Profile"),
        Column("Ciphers"),
        Column("MACs"),
        Column("Key Exchange"),
        Column("Host Key"),
        Column("Findings"),
        Column("Collected"),
    )
    tab_title = "Management SSH"
    has_provenance_toggle = True
    subject_model = ManagementSshSettings
    subject_order = ("appliance__hostname",)
    finding_model = ManagementSshFinding
    finding_subject_field = "management_ssh_settings"
    finding_controls = MANAGEMENT_SSH_CONTROLS

    def row_context(self, subjects):
        return {"binding_sources": _entry_provenance(subjects, "profile_name")}

    def build_row(self, ssh, findings, binding_sources):
        return {
            "ssh": ssh,
            "cbc": [c for c in ssh.ciphers if c.endswith("-cbc")],
            "binding_provenance": binding_sources.get(ssh.pk, ""),
            "findings": findings,
        }


class SslTlsServiceProfileListView(DeviceTabListView):
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

    #: Declared once; the header renders from this and
    #: test_device_tab_tables_are_square checks every body row against its length.
    COLUMNS = (
        Column("Appliance"),
        Column("Profile"),
        Column("Protocol Range"),
        Column("Certificate"),
        Column("Weak Algorithms"),
        Column("Findings"),
        Column("Collected"),
    )

    tab_title = "SSL/TLS Profiles"
    all_label = "All profiles"
    has_provenance_toggle = True
    subject_model = SslTlsServiceProfile
    subject_order = ("appliance__hostname", "scope", "name")
    finding_model = SslTlsServiceProfileFinding
    finding_subject_field = "ssl_tls_service_profile"
    finding_controls = SSL_TLS_PROFILE_CONTROLS

    def row_context(self, subjects):
        return {"sources": _entry_provenance(subjects)}

    def build_row(self, profile, findings, sources):
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
        return {
            "profile": profile,
            "weak_algorithms": weak,
            # Absent keys are why this matters: a profile that wrote nothing permits
            # everything, and the row should say which of the two it is.
            "algorithms_are_implicit": not profile.explicit_algorithms,
            "provenance": sources.get(profile.pk, ""),
            "findings": findings,
        }

class CertificateProfileListView(DeviceTabListView):
    """Every certificate profile, with what it actually checks.

    All six booleans default OFF, so a profile that sets nothing validates against a CA and
    never asks whether the certificate was revoked. The row shows the absence rather than
    leaving blanks, because blank reads as "not applicable" and this is "not checking".
    """

    template_name = "assessments/certificate_profile_list.html"

    #: Declared once; the header renders from this and
    #: test_device_tab_tables_are_square checks every body row against its length.
    COLUMNS = (
        Column("Appliance"),
        Column("Profile"),
        Column("Revocation Checks"),
        Column("Blocks On"),
        Column("CA Certificates"),
        Column("Findings"),
        Column("Collected"),
    )

    tab_title = "Certificate Profiles"
    all_label = "All profiles"
    has_provenance_toggle = True
    subject_model = CertificateProfile
    subject_order = ("appliance__hostname", "scope", "name")
    finding_model = CertificateProfileFinding
    finding_subject_field = "certificate_profile"
    finding_controls = CERTIFICATE_PROFILE_CONTROLS

    def row_context(self, subjects):
        return {"sources": _entry_provenance(subjects)}

    def build_row(self, profile, findings, sources):
        checks = [label for label, on in (
            ("CRL", profile.use_crl), ("OCSP", profile.use_ocsp)) if on]
        blocks = [label for label, on in (
            ("expired", profile.block_expired_cert),
            ("unknown", profile.block_unknown_cert),
            ("timeout", profile.block_timeout_cert),
            ("unauthenticated", profile.block_unauthenticated_cert)) if on]
        return {
            "profile": profile,
            "revocation_checks": checks,
            "blocks": blocks,
            "provenance": sources.get(profile.pk, ""),
            "findings": findings,
        }

class MasterKeyListView(DeviceTabListView):
    """The master key, per appliance. PAN-CRT-007.

    Device-level rather than an object, so one row per appliance - the same shape as the Login
    Banner tab rather than the profile tabs.

    NO PROVENANCE TOGGLE, deliberately. These values come from `show system
    masterkey-properties`, an operational command, not from configuration - so they carry no
    `@ptpl` and never will. A toggle here would render blank on every row for every device
    forever, which is indistinguishable from a broken one. Show only the provenance you
    actually have.

    The tab also states what the verdict rests on, because it rests on an INFERENCE rather
    than a measurement: an unset expiry means no key was ever set, since a lifetime is
    mandatory when setting one. That is vendor-documented and has not been reproduced on
    hardware here, and an engineer acting on a high-severity finding should be able to see
    that from the page.
    """

    template_name = "assessments/master_key_list.html"

    #: Declared once; the header renders from this and
    #: test_device_tab_tables_are_square checks every body row against its length.
    COLUMNS = (
        Column("Appliance"),
        Column("Master Key"),
        Column("Expires"),
        Column("Auto-renew"),
        Column("On HSM"),
        Column("Findings"),
        Column("Collected"),
    )

    tab_title = "Master Key"
    subject_model = MasterKey
    subject_order = ("appliance__hostname",)
    finding_model = MasterKeyFinding
    finding_subject_field = "master_key"
    finding_controls = MASTER_KEY_CONTROLS

    def build_row(self, profile, findings):
        raw_expiry = (profile.expires_at or "").strip()
        # The API returns 0 where the CLI prints "unspecified". Rendered in the CLI's
        # words, because that is what an engineer sees when they go and check.
        if raw_expiry and raw_expiry != "0":
            try:
                expires = _dt.datetime.fromtimestamp(
                    int(raw_expiry), tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            except (ValueError, OverflowError, OSError):
                expires = raw_expiry
        elif raw_expiry == "0":
            expires = "unspecified"
        else:
            expires = ""
        return {"profile": profile, "expires": expires, "findings": findings}

class CertificateListView(DeviceTabListView):
    """Every certificate as an object, with all its findings on one row.

    Key size, key algorithm and signature algorithm are shown together because they are only
    meaningful together: 256-bit EC is strong and 256-bit RSA is broken, so a size column on
    its own would mislead every reader the same way a size-only control would mislead every
    query.

    Predefined certificates are listed. They are read-only, so a finding against one cannot be
    fixed on the device - but omitting them would silently exclude the certificate the vendor's
    own hardened profile presents.
    """

    template_name = "assessments/certificate_list.html"

    #: Declared once; the header renders from this and
    #: test_device_tab_tables_are_square checks every body row against its length.
    COLUMNS = (
        Column("Appliance"),
        Column("Certificate"),
        Column("Key"),
        Column("Signature"),
        Column("Type"),
        Column("Expires"),
        Column("Findings"),
    )

    tab_title = "Certificates"
    all_label = "All certificates"
    subject_model = Certificate
    subject_order = ("appliance__hostname", "scope", "name")
    finding_model = CertificateFinding
    finding_subject_field = "certificate"
    finding_controls = CERTIFICATE_CONTROLS

    def build_row(self, certificate, findings):
        now = _dt.datetime.now(_dt.timezone.utc)
        days_left = None
        if certificate.not_valid_after:
            days_left = (certificate.not_valid_after - now).days
        return {
            "certificate": certificate,
            "days_left": days_left,
            # Surfaced even though no control asserts it yet - PAN-CRT-001 will, and an
            # engineer reading a certificate inventory asks this first.
            "expired": days_left is not None and days_left < 0,
            "findings": findings,
        }

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


class PasswordComplexityListView(DeviceTabListView):
    """Minimum password complexity, per appliance. PAN-AUTH-001 through 013.

    Thirteen controls over ONE object, so this follows Jason's rule that controls sharing an
    object are presented together: one row per appliance carrying all thirteen verdicts, rather
    than thirteen rows or thirteen tabs.

    A cell is marked weak IFF a control that reads it has an open finding. The page therefore
    contains no thresholds of its own - not 12, not 90, not "at least one". Restating them here
    would have created a second source of truth that looks authoritative and silently goes
    stale, and it would have got PAN-AUTH-010 wrong in a way nobody would notice: the naive
    reading is "higher is worse", but that control is bounded at BOTH ends, so 0 and 365 are
    both findings while 60 is not. Deriving the highlight from the finding gets that right
    without knowing why.

    The three "not assessed" cells are values PAN-OS accepts and no corpus control reads. They
    are shown, greyed, because the alternative is a page that quietly implies the seven keys it
    displays are the whole object.

    Provenance is a real column here, unlike the master key tab: mgt-config IS
    template-managed, measured 2026-09-03 - `action=complete` on a template's config root
    returns mgt-config beside devices and shared, and pushed values arrive carrying @ptpl. The
    lab pushes two deliberately weak values so the column is exercised rather than blank.
    """

    template_name = "assessments/password_complexity_list.html"

    #: Declared once; the header renders from this and
    #: test_device_tab_tables_are_square checks every body row against its length.
    COLUMNS = (
        Column("Appliance"),
        Column("Complexity"),
        Column("Composition"),
        Column("Reuse"),
        Column("Expiry"),
        Column("Password change"),
        Column("Findings"),
        Column("Collected"),
    )

    tab_title = "Password Complexity"
    has_provenance_toggle = True
    subject_model = PasswordComplexityPolicy
    subject_order = ("appliance__hostname",)
    finding_model = PasswordComplexityFinding
    finding_subject_field = "password_complexity_policy"
    finding_controls = PASSWORD_COMPLEXITY_CONTROLS
    finding_order = ("control__control_id",)

    def row_context(self, subjects):
        provenance_by_field = {
            field: _entry_provenance(subjects, field)
            for _, cells in PASSWORD_COMPLEXITY_GROUPS
            for field, _, _ in cells
        }
        provenance_by_field["enabled"] = _entry_provenance(subjects, "enabled")
        return {"fields_by_control": _fields_by_control(PASSWORD_COMPLEXITY_CONTROLS),
                "provenance_by_field": provenance_by_field}

    def build_row(self, profile, findings, fields_by_control, provenance_by_field):
        weak_fields: set[str] = set()
        for finding in findings:
            weak_fields |= fields_by_control.get(finding.control.control_id, set())
        groups = []
        for label, cells in PASSWORD_COMPLEXITY_GROUPS:
            groups.append({
                "label": label,
                "cells": [
                    {
                        "label": cell_label,
                        "kind": kind,
                        "value": getattr(profile, field),
                        "weak": field in weak_fields,
                        "provenance": provenance_by_field.get(field, {}).get(profile.pk, ""),
                    }
                    for field, cell_label, kind in cells
                ],
            })
        return {
            "profile": profile,
            "groups": groups,
            "findings": findings,
            "enabled_provenance": provenance_by_field["enabled"].get(profile.pk, ""),
            "enabled_weak": "enabled" in weak_fields,
        }


class AuthenticationSettingsListView(DeviceTabListView):
    """Admin lockout, idle timeout and API key lifetime. PAN-AUTH-014 through 017.

    One PAN-OS screen - Device > Setup > Management > Authentication Settings - so one tab,
    which keeps the page and the remediation in the same place.

    Every value here is zero-by-default and none of the zeros mean the same thing. The row
    spells each out rather than printing a bare 0, because "0" in the Lockout column is
    compliant and "0" in the Failed Attempts column beside it is the worst value available.
    A table that renders both as `0` invites exactly the wrong conclusion.
    """

    template_name = "assessments/authentication_settings_list.html"
    tab_title = "Authentication Settings"
    has_provenance_toggle = True
    subject_model = AuthenticationSettings
    subject_order = ("appliance__hostname",)
    finding_model = AuthenticationSettingsFinding
    finding_subject_field = "authentication_settings"
    finding_controls = AUTHENTICATION_SETTINGS_CONTROLS
    finding_order = ("control__control_id",)

    COLUMNS = (
        Column("Appliance"),
        Column("Failed Attempts"),
        Column("Lockout Time"),
        Column("Idle Timeout"),
        Column("API Key Lifetime"),
        Column("Findings"),
        Column("Collected"),
    )

    #: The `admin_` prefix went with the aggregate on 2026-09-10: on a model that IS the
    #: administrator settings it said nothing.
    FIELDS = ("lockout_failed_attempts", "lockout_time_minutes",
              "idle_timeout_minutes", "api_key_lifetime_minutes")

    def row_context(self, subjects):
        return {"fields_by_control": _fields_by_control(AUTHENTICATION_SETTINGS_CONTROLS),
                "provenance_by_field": {field: _entry_provenance(subjects, field)
                                        for field in self.FIELDS}}

    def build_row(self, profile, findings, fields_by_control, provenance_by_field):
        weak = set()
        for finding in findings:
            weak |= fields_by_control.get(finding.control.control_id, set())

        def cell(field, value, meaning):
            return {"value": value, "meaning": meaning, "weak": field in weak,
                    "provenance": provenance_by_field.get(field, {}).get(profile.pk, "")}

        attempts = profile.lockout_failed_attempts
        lockout = profile.lockout_time_minutes
        idle = profile.idle_timeout_minutes
        lifetime = profile.api_key_lifetime_minutes
        return {
            "profile": profile,
            "findings": findings,
            "cells": [
                # Each zero says what it MEANS. Two of these columns hold a 0 that is the
                # worst available value and one holds a 0 that is the best.
                cell("lockout_failed_attempts", attempts,
                     "lockout disabled" if attempts == 0 else f"after {attempts}"),
                cell("lockout_time_minutes", lockout,
                     "until released" if lockout == 0 else f"{lockout} min"),
                cell("idle_timeout_minutes", idle,
                     "never" if idle == 0 else f"{idle} min"),
                cell("api_key_lifetime_minutes", lifetime,
                     "never expires" if lifetime == 0 else f"{lifetime} min"),
            ],
        }


class AuthenticationProfileListView(DeviceTabListView):
    """Authentication profiles. PAN-AUTH-018 and 020.

    The METHOD column leads, because it is what decides whether the rest of the row means
    anything: a profile with method `none` performs no authentication, and one with
    `local-database` checks the firewall's own store rather than an external authority. Three of
    the lab's four profiles on one device are `none`.

    Failed Attempts renders its meaning rather than its number when it is zero, for the reason
    the Authentication Settings tab does: 0 there is UNLIMITED ATTEMPTS, the worst value
    available, and a bare "0" beside a Lockout column reads as strictness.

    The MFA column used to amber "off" and leave a factor count plain. That was backwards for
    administrator-bound profiles: PAN-OS invokes vendor-API MFA server profiles for
    Authentication Policy only, so "1 factor" on a profile an administrator logs in through is
    the finding (PAN-AAA-011) and "off" there is no control's business - PAN-AUTH-019 assesses
    an administrator's exposure, on the account, on another tab.
    """

    template_name = "assessments/authentication_profile_list.html"
    tab_title = "Authentication Profiles"
    all_label = "All profiles"
    has_provenance_toggle = True
    subject_model = AuthenticationProfile
    subject_order = ("appliance__hostname", "scope", "name")
    finding_model = AuthenticationProfileFinding
    finding_subject_field = "authentication_profile"
    finding_controls = AUTHENTICATION_PROFILE_CONTROLS

    COLUMNS = (
        Column("Appliance"),
        Column("Profile"),
        Column("Method"),
        Column("Lockout"),
        Column("MFA"),
        Column("Referenced By"),
        Column("Allow List"),
        Column("Findings"),
        Column("Collected"),
    )

    def row_context(self, subjects):
        return {"sources": _entry_provenance(subjects)}

    def build_row(self, profile, findings, sources):
        attempts = profile.lockout_failed_attempts
        return {
            "profile": profile,
            # "0" alone reads as strict. It means the opposite.
            "lockout": ("unlimited attempts" if attempts == 0
                        else f"after {attempts}, for "
                             + ("until released" if profile.lockout_time_minutes == 0
                                else f"{profile.lockout_time_minutes} min")),
            "lockout_weak": attempts == 0,
            # "all" alone is not a finding; "all on a profile an administrator authenticates
            # through" is. The row says which, because the allow-list cell reads identically on
            # all nine lab profiles, of which five report and four do not.
            "administrative": profile.is_administrative,
            "allow_all": profile.allow_list_is_all,
            # "Nothing" rather than 0: a blank or a bare zero in a reference column reads as
            # "not counted" exactly where it means "counted, and the answer was none".
            "referrers": (f"{profile.referrer_count} place(s)" if profile.referrer_count
                          else "Nothing"),
            "referrer_paths": profile.referrer_paths,
            "unused": profile.referrer_count == 0,
            # PAN-AAA-011 fires on MFA being PRESENT, which is the opposite direction from every
            # other control here, so the MFA cell cannot render "on" as good and "off" as bad.
            # It amber-flags a factor list on an administrator-bound profile - where PAN-OS does
            # not invoke it - and says so, because "1 factor" is otherwise the most reassuring
            # cell on the row and is exactly the finding.
            "mfa_inert": profile.is_administrative and profile.mfa_enabled
                         and profile.mfa_factor_count > 0,
            "external": profile.method_is_external,
            "provenance": sources.get(profile.pk, ""),
            "findings": findings,
        }


class AuthenticationSequenceListView(DeviceTabListView):
    """Authentication sequences. PAN-AAA-012.

    The members are listed IN ORDER with each one's method, because the order is the meaning:
    the firewall tries them top to bottom until one succeeds, so a local-database member is
    reached whenever everything above it fails. A local member is ambered only on an
    administrator-bound sequence - the same members behind captive portal are not this
    control's business, and the Referenced By cell says which kind each row is, because the
    scoping clause is derived and the member list alone reads identically on both.
    """

    template_name = "assessments/authentication_sequence_list.html"
    tab_title = "Authentication Sequences"
    all_label = "All sequences"
    has_provenance_toggle = True
    subject_model = AuthenticationSequence
    subject_order = ("appliance__hostname", "scope", "name")
    finding_model = AuthenticationSequenceFinding
    finding_subject_field = "authentication_sequence"
    finding_controls = AUTHENTICATION_SEQUENCE_CONTROLS

    COLUMNS = (
        Column("Appliance"),
        Column("Sequence"),
        Column("Profiles, In Order"),
        Column("Exit On Failure"),
        Column("Referenced By"),
        Column("Findings"),
        Column("Collected"),
    )

    def row_context(self, subjects):
        return {"sources": _entry_provenance(subjects)}

    def build_row(self, sequence, findings, sources):
        local = set(sequence.local_member_names)
        return {
            "sequence": sequence,
            "steps": [{"name": name, "method": method or "not found", "local": name in local}
                      for name, method in zip(sequence.member_names, sequence.member_methods)],
            "exit_on_failure": "yes" if sequence.exit_sequence_on_failure else "no",
            "administrative": sequence.is_administrative,
            "referrers": (f"{sequence.referrer_count} place(s)" if sequence.referrer_count
                          else "Nothing"),
            "referrer_paths": sequence.referrer_paths,
            "unused": sequence.referrer_count == 0,
            "provenance": sources.get(sequence.pk, ""),
            "findings": findings,
        }


class PasswordProfileListView(DeviceTabListView):
    """Password profiles and the global policy each one overrides. PAN-AUTH-026.

    Both operands are on the row, deliberately. "Weakens the global policy" is a conclusion an
    engineer cannot check; "never expires, where the global expires after 90 days" is one they
    can act on without opening the device.

    Zero renders as "never" rather than as a number in BOTH columns, because 0 is the weakest
    value on this field and a bare "0" beside a "90" reads as the strictest.
    """

    template_name = "assessments/password_profile_list.html"
    tab_title = "Password Profiles"
    all_label = "All profiles"
    has_provenance_toggle = True
    subject_model = PasswordProfile
    subject_order = ("appliance__hostname", "name")
    finding_model = PasswordProfileFinding
    finding_subject_field = "password_profile"
    finding_controls = PASSWORD_PROFILE_CONTROLS

    COLUMNS = (
        Column("Appliance"),
        Column("Profile"),
        Column("Expires"),
        Column("Global Policy"),
        Column("Warning"),
        Column("Post-expiry"),
        Column("Findings"),
        Column("Collected"),
    )

    @staticmethod
    def _period(days):
        return "never" if days == 0 else f"{days} days"

    def row_context(self, subjects):
        return {"sources": _entry_provenance(subjects)}

    def build_row(self, profile, findings, sources):
        return {
            "profile": profile,
            "expires": self._period(profile.expiration_period),
            "global_expires": self._period(profile.global_expiration_period),
            "weakens": profile.weakens_global_expiration,
            "warning": self._period(profile.expiration_warning_period),
            "post_expiry": (f"{profile.post_expiration_admin_login_count} login(s), "
                            f"{self._period(profile.post_expiration_grace_period)}"),
            "provenance": sources.get(profile.pk, ""),
            "findings": findings,
        }


class SecurityProfileListView(DeviceTabListView):
    """Anti-spyware and vulnerability profiles - custom, pushed and predefined. PAN-SPY-001, PAN-VLN-001.

    Each severity cell carries its verdict AND the reason, because the verdict is computed over
    the whole rule list and two profiles failing the same severity can fail it differently.

    Predefined profiles are listed only when something uses them, which is the same scoping the
    controls apply: an unused `default` protects nothing, and ten vsys each carrying two of them
    would bury the profiles that matter. "Used by" is on every row so a predefined profile's
    presence explains itself.
    """

    template_name = "assessments/security_profile_list.html"
    tab_title = "Security Profiles"
    all_label = "All profiles"
    has_provenance_toggle = True
    subject_model = SecurityProfile
    subject_select_related = ("enforcement_point__appliance_group", "appliance_group", "source_snapshot")
    subject_order = ("kind", "is_predefined", "name", "appliance_group__name", "enforcement_point__vsys_name")
    finding_model = SecurityProfileFinding
    finding_subject_field = "security_profile"
    finding_controls = SECURITY_PROFILE_CONTROLS

    COLUMNS = (
        Column("Owner"),
        Column("Profile"),
        Column("Critical"),
        Column("High"),
        Column("Medium"),
        Column("Used by"),
        Column("Findings"),
        Column("Collected"),
    )

    #: Referrers shown per row before "and N more" - a Panorama-shared group can reach every vsys.
    REFERRERS_SHOWN = 3

    def get_subjects(self):
        return [p for p in super().get_subjects() if not p.is_predefined or p.is_used]

    def row_context(self, subjects):
        return {"sources": _entry_provenance(subjects)}

    def build_row(self, profile, findings, sources):
        return {
            "profile": profile,
            "kind": profile.get_kind_display(),
            "scope": profile.get_namespace_type_display(),
            "owner": profile.appliance_group.name if profile.appliance_group_id else str(profile.enforcement_point),
            "severities": [
                {"blocked": profile.critical_blocked, "detail": profile.critical_detail},
                {"blocked": profile.high_blocked, "detail": profile.high_detail},
                {"blocked": profile.medium_blocked, "detail": profile.medium_detail},
            ],
            "used_by": profile.referrers[:self.REFERRERS_SHOWN],
            "more_referrers": max(0, len(profile.referrers) - self.REFERRERS_SHOWN),
            "provenance": sources.get(profile.pk, ""),
            "findings": findings,
        }


class AdminUserListView(DeviceTabListView):
    """Administrator accounts and every control that assesses one. PAN-AUTH-019, 021, 022.

    There is no MFA column, deliberately. It used to show the bound profile's Factors list, and
    ambered accounts without one - so `oep-mfa-admin`, whose factor PAN-OS never invokes for an
    administrator, read as the protected account on the page. Nothing in the configuration can
    say whether an administrator has MFA, so a column claiming to is the one thing this page
    must not carry. The declared factor is still visible on Authentication Profiles, where
    PAN-AAA-011 reports it as inert.

    The row carries what each control READ rather than its verdict: the role, the superuser
    total the role belongs to, and the credentials the account actually holds. An engineer
    reading "PAN-AUTH-019 high" needs to see that the account has a password and no profile
    before they can act, and all three findings land on the same row because there is one
    object to remediate.

    "Nothing" and "Local database" are written out. A blank credentials cell would be the
    account with no credential at all - a real state, and one worth reading as a fact rather
    than as a rendering gap.
    """

    template_name = "assessments/admin_user_list.html"
    tab_title = "Administrators"
    all_label = "All accounts"
    has_provenance_toggle = True
    subject_model = AdminUser
    subject_order = ("appliance__hostname", "name")
    finding_model = AdminUserFinding
    finding_subject_field = "admin_user"
    finding_controls = ADMIN_USER_CONTROLS
    finding_order = ("control__control_id",)

    COLUMNS = (
        Column("Appliance"),
        Column("Account"),
        Column("Role"),
        Column("Superusers"),
        Column("Authentication"),
        Column("Credentials"),
        Column("Password Profile"),
        Column("Findings"),
        Column("Collected"),
    )

    @staticmethod
    def _credentials(user):
        held = [label for present, label in ((user.has_password, "Password"),
                                             (user.has_public_key, "SSH key")) if present]
        if user.client_certificate_only:
            held.append("Client cert only (web)")
        return ", ".join(held) if held else "Nothing"

    def row_context(self, subjects):
        return {
            "sources": _entry_provenance(subjects),
            "auth_sources": _entry_provenance(subjects, "authentication_profile_name"),
        }

    def build_row(self, user, findings, sources, auth_sources):
        binding_none = AdminUser.AuthenticationBinding.NONE
        return {
            "user": user,
            "role": user.get_role_type_display(),
            "role_scope": user.role_scope or user.custom_role_profile,
            # 0 is not "no superusers on this appliance", it is "this account is not one of
            # them" - so the cell says what the column means rather than printing the number.
            "superusers": user.superuser_cohort_size if user.is_superuser else "",
            "authentication": user.effective_authentication_profile or "Local database",
            "external": user.authentication_is_external,
            # Blank when nothing is bound: the cell above already says "Local database", and
            # repeating the binding's own label under it reads as two facts, not one. Where a
            # profile IS bound, the sub-line says whether it actually reaches an external
            # service - "corp-tacacs / Per-account" reads as centralized and may not be.
            "binding": ("" if user.authentication_binding == binding_none else
                        f"{user.get_authentication_binding_display()}"
                        f"{' - sequence' if user.authentication_sequence else ''}"
                        f"{'' if user.authentication_is_external else ' - not external'}"),
            "auth_provenance": auth_sources.get(user.pk, ""),
            "credentials": self._credentials(user),
            "local_only": not user.centrally_authenticated,
            "password_profile": user.password_profile_name or "None",
            "provenance": sources.get(user.pk, ""),
            "findings": findings,
        }


class ServerProfileListView(DeviceTabListView):
    """AAA server profiles of every kind, with the setting each control reads. PAN-AAA-*.

    ONE TABLE, SIX KINDS, so the Settings column is per-kind rather than one column per field:
    six kinds by four settings is twenty-four columns of which twenty are blank on any row. What
    an engineer needs is the profile, what type it is, and the value to change.

    Settings are rendered in the words of the screen they live on, because the reader is going
    to that screen next.
    """

    template_name = "assessments/server_profile_list.html"
    tab_title = "AAA Server Profiles"
    all_label = "All profiles"
    has_provenance_toggle = True
    subject_model = ServerProfile
    subject_order = ("appliance__hostname", "kind", "name")
    finding_model = ServerProfileFinding
    finding_subject_field = "server_profile"
    finding_controls = SERVER_PROFILE_CONTROLS
    finding_order = ("control__control_id",)

    COLUMNS = (
        Column("Appliance"),
        Column("Profile"),
        Column("Type"),
        Column("Servers"),
        Column("Settings"),
        Column("Referenced By"),
        Column("Findings"),
        Column("Collected"),
    )

    @staticmethod
    def _settings(profile):
        """[(label, value, is_weak)] for this kind, in the words of its own screen."""
        kind = profile.kind
        if kind == ServerProfile.Kind.LDAP:
            return [("SSL/TLS", "on" if profile.ldap_ssl else "off", not profile.ldap_ssl),
                    ("Verify certificate",
                     "on" if profile.ldap_verify_server_certificate else "off",
                     not profile.ldap_verify_server_certificate)]
        if kind in (ServerProfile.Kind.RADIUS, ServerProfile.Kind.TACPLUS):
            weak = (profile.protocol in ("PAP", "CHAP")
                    if kind == ServerProfile.Kind.RADIUS else profile.protocol == "PAP")
            return [("Protocol", profile.protocol or "unset", weak)]
        if kind == ServerProfile.Kind.SAML_IDP:
            return [("Validate IdP certificate",
                     "on" if profile.saml_validate_idp_certificate else "off",
                     not profile.saml_validate_idp_certificate),
                    ("Sign messages",
                     "on" if profile.saml_want_auth_requests_signed else "off",
                     not profile.saml_want_auth_requests_signed)]
        if kind == ServerProfile.Kind.MFA:
            return [("Vendor", profile.mfa_vendor_type or "unset", False)]
        if kind == ServerProfile.Kind.UNKNOWN:
            return [("Unrecognised type", profile.raw_kind or "unknown", True)]
        return []

    def row_context(self, subjects):
        return {"sources": _entry_provenance(subjects)}

    def build_row(self, profile, findings, sources):
        return {
            "profile": profile,
            "kind": profile.get_kind_display(),
            "scope": (profile.scope if profile.scope == "shared"
                      else f"{profile.scope} {profile.vsys_name}"),
            "servers": ", ".join(profile.server_addresses) or "none",
            "settings": self._settings(profile),
            "certificate": profile.certificate_reference,
            "admin_use_only": profile.admin_use_only,
            # "Nothing" rather than 0: a bare zero in a reference column reads as "not counted"
            # exactly where it means "counted, and the answer was none".
            "referrers": (f"{profile.referrer_count} place(s)" if profile.referrer_count
                          else "Nothing"),
            "referrer_paths": profile.referrer_paths,
            "unused": profile.referrer_count == 0,
            "provenance": sources.get(profile.pk, ""),
            "findings": findings,
        }


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

        return {
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
            "columns": spec.columns,
            "rows": [spec.row(item) for item in rows],
            "total_count": total,
            "shown_count": rows.count() if node is not None else total,
            "search_query": node,
            "search_summary": describe_search_node(node),
            "search_payload": json.dumps(node) if node else "",
            "search_error": error,
            "edit_search_open": self.request.GET.get("edit_search") == "1",
            "edit_search_close_url": build_query_string_without(self.request, "edit_search"),
            "clear_search_url": build_query_string_without(
                self.request, "search_state", "control_query", "edit_search"),
        }


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
            "findings_href": (reverse(active.findings_url_name)
                              if active.findings_url_name else ""),
        },
    }


class ConfigurationIndexView(View):
    """`/assessments/configuration/` - redirect to the landing object rather than render.

    A category index page would be a fourth thing to design and would be passed through without
    being read. The explorer's first screen should be an object.
    """

    def get(self, request, *args, **kwargs):
        obj = config_nav.landing()
        return HttpResponseRedirect(reverse(
            "assessment_configuration_object",
            args=[config_nav.category_slug(obj.category), obj.slug]))
