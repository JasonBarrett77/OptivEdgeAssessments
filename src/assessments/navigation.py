"""The device tab bar, in one place, because it is read from two.

The tab bar and the sidebar's `active_names` are the same fact stated twice, and they drifted
the moment they were written apart: every tab added after Login Banner - Management TLS,
SSL/TLS Profiles, Certificate Profiles, Master Key, Certificates, Password Complexity - landed
in `device_tabs.html` and in no `active_names` set, so the sidebar highlighted NOTHING while
those pages were open. Nobody noticed because a sidebar that fails to highlight looks like a
sidebar, and `app_meta.py` is nowhere near the file you touch when adding a tab.

So the list lives here, `app_meta` derives the sidebar entry from it, and the `{% device_tabs %}`
tag renders the bar from it. Adding a tab is one entry in one tuple.

Deliberately free of Django imports. `app_meta` is read during project composition, before the
app registry is ready, so anything reaching a model here would break startup rather than a page.

The active tab is resolved from `request.resolver_match.url_name` rather than passed in by each
view - a hand-passed `active_tab` string is a second thing to keep in step, and it is wrong in
exactly the same way `active_names` was.
"""

from __future__ import annotations

from typing import NamedTuple


class DeviceTab(NamedTuple):
    url_name: str
    label: str
    #: Must exist in OptivEdge's vendored icon set - templates/components/icons/. That set is
    #: small and is NOT lucide's full catalogue; a name that is not there renders a 500.
    icon: str


#: Display order, left to right.
DEVICE_TABS: tuple[DeviceTab, ...] = (
    DeviceTab("assessment_device_configuration_profile_list", "Device Configuration", "monitor"),
    DeviceTab("assessment_management_interface_list", "Management Interfaces", "shield"),
    DeviceTab("assessment_interface_management_profile_list", "Interface Profiles", "list-checks"),
    DeviceTab("assessment_login_banner_list", "Login Banner", "book-marked"),
    DeviceTab("assessment_management_tls_list", "Management TLS", "clipboard-check"),
    DeviceTab("assessment_ssl_tls_service_profile_list", "SSL/TLS Profiles", "settings"),
    DeviceTab("assessment_certificate_profile_list", "Certificate Profiles", "server"),
    DeviceTab("assessment_master_key_list", "Master Key", "refresh-cw"),
    DeviceTab("assessment_certificate_list", "Certificates", "clipboard-check"),
    DeviceTab("assessment_password_complexity_list", "Password Complexity", "eye"),
)

DEVICE_TAB_URL_NAMES = frozenset(tab.url_name for tab in DEVICE_TABS)
