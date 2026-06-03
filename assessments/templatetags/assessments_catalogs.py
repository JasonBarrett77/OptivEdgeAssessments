"""Template tags for rendering catalog status panels."""

from __future__ import annotations

from django import template
from django.core.exceptions import ImproperlyConfigured, ValidationError

from assessments.controls_catalog.io.importers import seed_catalogs_if_empty
from assessments.environment import get_application_environment
from assessments.models import ApplicationEnvironmentCatalogState, Catalog


register = template.Library()


@register.inclusion_tag("assessments/partials/home_catalog_section.html", takes_context=True)
def render_home_catalog_section(context):
    request = context["request"]
    error_message = ""
    try:
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
        catalogs = Catalog.objects.order_by("is_snapshot", "-is_seeded", "label", "version", "pk")
    except (ImproperlyConfigured, ValidationError) as exc:
        application_environment = None
        current_catalog_state = None
        catalogs = Catalog.objects.none()
        error_message = str(exc)

    return {
        "application_environment": application_environment,
        "catalogs": catalogs,
        "current_catalog_state": current_catalog_state,
        "catalog_error_message": error_message,
        "request": request,
    }
