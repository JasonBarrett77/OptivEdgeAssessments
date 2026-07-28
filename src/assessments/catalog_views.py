"""Views for control catalog management and apply workflows."""

from __future__ import annotations

import json

from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views import View
from django.views.generic import TemplateView

from assessments.controls_catalog.drift import catalog_has_drifted
from assessments.controls_catalog.io.exporters import export_catalog_seed_payload
from assessments.controls_catalog.io.importers import (
    apply_catalog,
    create_catalog_from_current_controls,
    refresh_seeded_catalogs,
    seed_catalogs_if_empty,
)
from assessments.environment import get_application_environment
from assessments.forms import CatalogCreateForm
from assessments.models import ApplicationEnvironmentCatalogState, Catalog, Control


def build_json_download_response(*, payload: dict, filename: str) -> HttpResponse:
    response = HttpResponse(
        json.dumps(payload, indent=2, sort_keys=True),
        content_type="application/json",
    )
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def _build_catalog_list_context() -> dict:
    seed_catalogs_if_empty()
    application_environment = get_application_environment()
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

    return {
        "application_environment": application_environment,
        "current_catalog_state": current_catalog_state,
        "catalogs": Catalog.objects.order_by("is_snapshot", "-is_seeded", "label", "version", "pk"),
        "live_control_count": Control.objects.count(),
        "catalog_drifted": drifted,
    }


class CatalogListBackgroundMixin:
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(_build_catalog_list_context())
        return context


class RightOverlayMixin:
    overlay_close_url = None
    overlay_panel_class = "w-[32rem] max-w-[calc(100vw-15rem)]"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["overlay_is_open"] = True
        context["overlay_close_url"] = self.overlay_close_url
        context["overlay_panel_class"] = self.overlay_panel_class
        return context


class CatalogListView(TemplateView):
    template_name = "assessments/catalog_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(_build_catalog_list_context())
        return context


class CatalogCreateFromCurrentControlsView(RightOverlayMixin, CatalogListBackgroundMixin, TemplateView):
    template_name = "assessments/catalog_create_from_current.html"
    overlay_close_url = "/assessments/catalogs/"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form"] = kwargs.get("form") or CatalogCreateForm(
            initial={"label": "Current Controls Snapshot", "version": "v1"}
        )
        return context

    def post(self, request, *args, **kwargs):
        form = CatalogCreateForm(request.POST)
        if not form.is_valid():
            return self.render_to_response(self.get_context_data(form=form))
        if not Control.objects.exists():
            messages.error(request, "There are no live controls to export into a catalog.")
            return HttpResponseRedirect(reverse("assessment_catalog_list"))
        catalog = create_catalog_from_current_controls(
            label=form.cleaned_data["label"],
            version=form.cleaned_data["version"],
            description=form.cleaned_data["description"],
        )
        messages.success(
            request,
            f"Created catalog {catalog.label} ({catalog.version}) from the current control state.",
        )
        return HttpResponseRedirect(reverse("assessment_catalog_list"))


class CatalogApplyView(View):
    def post(self, request, *args, **kwargs):
        seed_catalogs_if_empty()
        application_environment = get_application_environment()
        if application_environment is None:
            messages.error(request, "Configure Application Environment before applying a catalog.")
            return HttpResponseRedirect(request.POST.get("next") or reverse("home"))

        catalog = get_object_or_404(Catalog, pk=kwargs["pk"])
        result = apply_catalog(
            catalog=catalog,
            application_environment=application_environment,
        )
        if result.snapshot_catalog is not None:
            messages.success(
                request,
                (
                    f"Applied catalog {catalog.label} ({catalog.version}). "
                    f"Created snapshot {result.snapshot_catalog.label}. "
                    f"Recreated {result.controls_created} controls and {result.queries_created} queries."
                ),
            )
        else:
            messages.success(
                request,
                (
                    f"Applied catalog {catalog.label} ({catalog.version}). "
                    f"Created {result.controls_created} controls and {result.queries_created} queries."
                ),
            )
        if result.assessment_runs_deleted:
            messages.success(
                request,
                f"Removed {result.assessment_runs_deleted} assessment run records. Re-run findings after catalog changes.",
            )
        return HttpResponseRedirect(request.POST.get("next") or reverse("assessment_catalog_list"))


class CatalogRefreshSeedView(View):
    def post(self, request, *args, **kwargs):
        seed_catalogs_if_empty()
        result = refresh_seeded_catalogs()
        if result.catalogs_updated:
            messages.success(
                request,
                (
                    f"Refreshed {result.catalogs_updated} seeded catalog(s) from the bundled "
                    "seed file. Apply the catalog on the Catalogs tab to push these changes "
                    "into live controls."
                ),
            )
        if result.catalogs_created:
            messages.success(
                request,
                f"Created {result.catalogs_created} new seeded catalog(s) from the bundled seed file.",
            )
        if not result.catalogs_updated and not result.catalogs_created:
            messages.error(request, "No catalogs found in the bundled seed file.")
        return HttpResponseRedirect(request.POST.get("next") or reverse("assessment_system"))


class CatalogDownloadView(View):
    def get(self, request, *args, **kwargs):
        seed_catalogs_if_empty()
        catalog = get_object_or_404(Catalog, pk=kwargs["pk"])
        return build_json_download_response(
            payload=catalog.payload,
            filename=f"{catalog.key}-{catalog.version}.json",
        )


class CatalogSeedDownloadView(View):
    def get(self, request, *args, **kwargs):
        seed_catalogs_if_empty()
        payload = export_catalog_seed_payload()
        return build_json_download_response(
            payload=payload,
            filename="control-catalog-seed.json",
        )
