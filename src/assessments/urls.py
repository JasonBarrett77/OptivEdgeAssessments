from django.urls import path

from assessments.catalog_views import (
    CatalogApplyView,
    CatalogCreateFromCurrentControlsView,
    CatalogDownloadView,
    CatalogListView,
    CatalogRefreshSeedView,
    CatalogSeedDownloadView,
)
from assessments.plain_language.views import PlainLanguageSecurityRuleQueryView
from assessments.views import (
    ControlCreateView,
    SystemView,
    ControlDeleteView,
    ControlDetailView,
    ControlListView,
    FindingsDomainView,
    FindingsSummaryView,
    FindingsWorkbookView,
    ControlQueryCreateView,
    ControlQueryDeleteView,
    ControlQueryUpdateView,
    ControlRunFindingsView,
    ControlUpdateView,
    ConfigurationObjectView,
    ConfigurationIndexView,
)


urlpatterns = [
    path(
        "findings/",
        FindingsSummaryView.as_view(),
        name="assessment_findings_summary",
    ),
    # Before the slug route, which would otherwise swallow "workbook" and 404 on a domain
    # that does not exist.
    path(
        "findings/workbook/",
        FindingsWorkbookView.as_view(),
        name="assessment_findings_workbook",
    ),
    path(
        "findings/<slug:slug>/",
        FindingsDomainView.as_view(),
        name="assessment_findings_domain",
    ),
    path(
        "catalogs/",
        CatalogListView.as_view(),
        name="assessment_catalog_list",
    ),
    path(
        "catalogs/export-seed/",
        CatalogSeedDownloadView.as_view(),
        name="assessment_catalog_seed_download",
    ),
    path(
        "catalogs/create-from-current/",
        CatalogCreateFromCurrentControlsView.as_view(),
        name="assessment_catalog_create_from_current",
    ),
    path(
        "catalogs/refresh-seed/",
        CatalogRefreshSeedView.as_view(),
        name="assessment_catalog_refresh_seed",
    ),
    path(
        "catalogs/<int:pk>/apply/",
        CatalogApplyView.as_view(),
        name="assessment_catalog_apply",
    ),
    path(
        "catalogs/<int:pk>/download/",
        CatalogDownloadView.as_view(),
        name="assessment_catalog_download",
    ),
    path(
        "controls/",
        ControlListView.as_view(),
        name="assessment_control_list",
    ),
    path(
        "controls/create/",
        ControlCreateView.as_view(),
        name="assessment_control_create",
    ),
    path(
        "controls/run-findings/",
        ControlRunFindingsView.as_view(),
        name="assessment_control_run_findings",
    ),
    path(
        "system/",
        SystemView.as_view(),
        name="assessment_system",
    ),
    # The configuration explorer. Two segments, both the vendor's own vocabulary - the PAN-OS
    # top-level tab, then the object as its left rail names it - so a URL reads as the place an
    # engineer would click to. `configuration/` alone is the dashboard: what the explorer holds,
    # which controls read each object, and the queries built over them.
    path(
        "configuration/",
        ConfigurationIndexView.as_view(),
        name="assessment_configuration_index",
    ),
    path(
        "configuration/<slug:category>/<slug:slug>/",
        ConfigurationObjectView.as_view(),
        name="assessment_configuration_object",
    ),
    path(
        "controls/<int:pk>/",
        ControlDetailView.as_view(),
        name="assessment_control_detail",
    ),
    path(
        "control-queries/create/",
        ControlQueryCreateView.as_view(),
        name="assessment_control_query_create",
    ),
    path(
        "controls/<int:pk>/edit/",
        ControlUpdateView.as_view(),
        name="assessment_control_update",
    ),
    path(
        "controls/<int:pk>/queries/<int:query_pk>/edit/",
        ControlQueryUpdateView.as_view(),
        name="assessment_control_query_update",
    ),
    path(
        "controls/<int:pk>/queries/<int:query_pk>/delete/",
        ControlQueryDeleteView.as_view(),
        name="assessment_control_query_delete",
    ),
    path(
        "controls/<int:pk>/delete/",
        ControlDeleteView.as_view(),
        name="assessment_control_delete",
    ),
    path(
        "security-rules/plain-language/",
        PlainLanguageSecurityRuleQueryView.as_view(),
        name="assessment_security_rule_plain_language",
    ),
]
