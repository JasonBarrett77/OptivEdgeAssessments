"""Views for control catalog management and apply workflows."""

from __future__ import annotations

import json

from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views import View
from django.views.generic import TemplateView

from assessments.controls_catalog.io.exporters import export_catalog_seed_payload
from assessments.controls_catalog.io.importers import (
    apply_catalog,
    create_catalog_from_current_controls,
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


class CatalogListView(TemplateView):
    template_name = "assessments/catalog_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        seed_catalogs_if_empty()
        application_environment = get_application_environment()
        current_catalog = None
        if application_environment is not None:
            current_catalog = (
                ApplicationEnvironmentCatalogState.objects.filter(
                    application_environment=application_environment,
                )
                .select_related("current_catalog")
                .first()
            )

        context["application_environment"] = application_environment
        context["current_catalog_state"] = current_catalog
        context["catalogs"] = Catalog.objects.order_by("is_snapshot", "-is_seeded", "label", "version", "pk")
        context["catalog_create_form"] = CatalogCreateForm(
            initial={
                "label": "Current Controls Snapshot",
                "version": "v1",
            }
        )
        context["live_control_count"] = Control.objects.count()
        return context


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


class CatalogCreateFromCurrentControlsView(View):
    def post(self, request, *args, **kwargs):
        form = CatalogCreateForm(request.POST)
        if not form.is_valid():
            for field_errors in form.errors.values():
                for error in field_errors:
                    messages.error(request, error)
            return HttpResponseRedirect(reverse("assessment_catalog_list"))
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
