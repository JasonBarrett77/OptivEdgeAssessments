"""Renders the device navigation from `navigation.DEVICE_TABS`."""

from __future__ import annotations

from django import template

from assessments.navigation import (
    DEVICE_TABS, SECTIONS, SECTION_BY_URL_NAME, tabs_in)

register = template.Library()


@register.inclusion_tag("assessments/partials/device_tabs.html", takes_context=True)
def device_tabs(context):
    """Two levels: the section strip, and the tabs of the active section only.

    Everything is derived from the current URL. The active tab is the one whose `url_name`
    matches, and the active SECTION is that tab's section - so a page cannot be open in one
    section while another is highlighted, which is what a hand-passed string allows.

    `resolver_match` is None in a bare RequestFactory render, so an unknown URL falls back to
    the first section with no tab highlighted rather than raising. A nav bar is not worth a 500.
    """
    request = context.get("request")
    match = getattr(request, "resolver_match", None)
    active_url_name = getattr(match, "url_name", None)
    active_section = SECTION_BY_URL_NAME.get(active_url_name) or SECTIONS[0]
    return {
        "sections": [
            {
                "name": name,
                "count": len(tabs_in(name)),
                # A section links to its first tab; there is no section landing page.
                "url_name": tabs_in(name)[0].url_name,
                "is_active": name == active_section,
            }
            for name in SECTIONS
        ],
        "tabs": tabs_in(active_section),
        "active_url_name": active_url_name,
    }
