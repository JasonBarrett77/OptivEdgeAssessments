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
    RemediationWorkbookBuildView,
    WorkbookBuildView,
    DownloadsView,
    ArtifactDownloadView,
    ArtifactDeleteView,
    ArtifactBuildStatusView,
    ControlQueryCreateView,
    ControlQueryDeleteView,
    ControlQueryUpdateView,
    ControlRunFindingsView,
    ControlRunFindingsStatusView,
    ControlUpdateView,
    ConfigurationObjectView,
    ConfigurationIndexView,
    RemediationIndexView,
    RemediationGroupView,
)


urlpatterns = [
    path(
        "findings/",
        FindingsSummaryView.as_view(),
        name="assessment_findings_summary",
    ),
    # Two segments, so `findings/<slug:slug>/` cannot swallow it. The single-segment
    # `findings/workbook/` it replaced had to be ordered before the slug route to avoid that.
    path(
        "findings/workbook/build/",
        WorkbookBuildView.as_view(),
        name="assessment_workbook_build",
    ),
    path(
        "findings/<slug:slug>/",
        FindingsDomainView.as_view(),
        name="assessment_findings_domain",
    ),
    # The findings asked a different question: not what is wrong, but where a change is made and
    # what one change clears. Top level rather than under `findings/` because it is its own
    # sidebar destination and because `findings/<slug>/` would otherwise swallow a single
    # segment under it.
    path(
        "remediation/",
        RemediationIndexView.as_view(),
        name="assessment_remediation_index",
    ),
    # Two segments, so `remediation/<slug>/` could not swallow it even if a one-segment route
    # arrived later - the lesson `findings/workbook/build/` already carries.
    path(
        "remediation/workbook/build/",
        RemediationWorkbookBuildView.as_view(),
        name="assessment_remediation_workbook_build",
    ),
    # `group/` is still in the path although nothing else sits under `remediation/` any more:
    # it was there to keep a one-segment control route from swallowing the slug, and the links
    # to these pages are live in notes and bookmarks, so the segment stays.
    path(
        "remediation/group/<str:slug>/",
        RemediationGroupView.as_view(),
        name="assessment_remediation_group",
    ),
    # A control id rather than a slug: it is what the catalogue, the workbook and every findings
    # row already call a control, so a link from any of them needs no second name.
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
        "controls/run-findings/status/",
        ControlRunFindingsStatusView.as_view(),
        name="assessment_control_run_findings_status",
    ),
    # Built deliverables. Its own prefix rather than under findings/, whose `<slug>` would
    # otherwise have to be kept clear of every name used here.
    path(
        "downloads/",
        DownloadsView.as_view(),
        name="assessment_downloads",
    ),
    path(
        "downloads/status/",
        ArtifactBuildStatusView.as_view(),
        name="assessment_downloads_status",
    ),
    path(
        "downloads/<int:pk>/",
        ArtifactDownloadView.as_view(),
        name="assessment_artifact_download",
    ),
    path(
        "downloads/<int:pk>/delete/",
        ArtifactDeleteView.as_view(),
        name="assessment_artifact_delete",
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
