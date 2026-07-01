"""Shared helpers for deployment-scoped environment access."""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured

from optivedge.integrations.models import ApplicationEnvironment


def get_application_environment(*, required: bool = False) -> ApplicationEnvironment | None:
    application_environments = list(ApplicationEnvironment.objects.order_by("pk")[:2])
    if len(application_environments) > 1:
        raise ImproperlyConfigured("Expected a single ApplicationEnvironment record for this deployment.")
    environment = application_environments[0] if application_environments else None
    if required and environment is None:
        raise ImproperlyConfigured("ApplicationEnvironment must be configured before this action.")
    return environment
