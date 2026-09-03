"""Renders the device tab bar from `navigation.DEVICE_TABS`."""

from __future__ import annotations

from django import template

from assessments.navigation import DEVICE_TABS

register = template.Library()


@register.inclusion_tag("assessments/partials/device_tabs.html", takes_context=True)
def device_tabs(context):
    """The bar, with the active tab resolved from the URL rather than passed in.

    `request.resolver_match` is None in a bare RequestFactory render, so a missing match
    highlights nothing rather than raising - a tab bar is not worth a 500.
    """
    request = context.get("request")
    match = getattr(request, "resolver_match", None)
    return {"tabs": DEVICE_TABS, "active_url_name": getattr(match, "url_name", None)}
