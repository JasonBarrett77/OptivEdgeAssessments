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
    #: Which section holds this tab. Must appear in SECTIONS.
    section: str


#: Section order, left to right.
#:
#: A flat bar was already wrapping at ten tabs, and ten is 30 of 235 controls from 3 of 28
#: domains. The corpus has 43 distinct config subtrees at depth two, and object tabs track
#: subtrees rather than controls, so the flat bar was heading for roughly forty entries.
#: Sections cap what is on screen at the size of one subtree instead of the whole corpus.
#:
#: Sections were originally keyed on where the object's config lives in PAN-OS, so that a tab's
#: section was not a new judgment call. AUTHENTICATION IS THE EXCEPTION, and it is deliberate:
#: the six tabs in it live in three different subtrees - `deviceconfig` (Authentication Settings,
#: Password Complexity), `mgt-config` (Administrators) and `shared` (Authentication Profiles,
#: Password Profiles, AAA Server Profiles) - and keying on the subtree scattered them across a
#: Device section that had grown to eleven tabs. An engineer asking "how do administrators get
#: in here" was reading three of those eleven and had no way to know which three.
#:
#: So the rule is: key on the subtree unless a QUESTION spans several of them, and then key on
#: the question. Anything else lands in Device by default, which is what Device now is - the
#: appliance settings that are nobody else's story.
SECTIONS: tuple[str, ...] = ("Device", "Authentication", "Certificates", "Network")


#: Display order, left to right.
DEVICE_TABS: tuple[DeviceTab, ...] = (
    # Device - the appliance's own settings, mostly one row per appliance.
    DeviceTab("assessment_management_interface_list", "Management Interfaces", "shield", "Device"),
    DeviceTab("assessment_login_banner_list", "Login Banner", "book-marked", "Device"),
    DeviceTab("assessment_management_tls_list", "Management TLS", "clipboard-check", "Device"),
    DeviceTab("assessment_master_key_list", "Master Key", "refresh-cw", "Device"),
    # Authentication - who can log in, how they are challenged, and against what. Ordered as the
    # question is asked: the accounts, the profile each one resolves through, the device-wide
    # settings behind that, the servers it reaches, and the password policy underneath.
    DeviceTab("assessment_admin_user_list", "Administrators", "shield", "Authentication"),
    DeviceTab("assessment_authentication_profile_list", "Authentication Profiles",
              "shield", "Authentication"),
    DeviceTab("assessment_authentication_sequence_list", "Authentication Sequences",
              "list-checks", "Authentication"),
    DeviceTab("assessment_authentication_settings_list", "Authentication Settings",
              "clipboard-check", "Authentication"),
    DeviceTab("assessment_server_profile_list", "AAA Server Profiles", "server", "Authentication"),
    DeviceTab("assessment_password_profile_list", "Password Profiles", "book-marked",
              "Authentication"),
    DeviceTab("assessment_password_complexity_list", "Password Complexity", "eye",
              "Authentication"),
    # Certificates - shared/certificate, certificate-profile, ssl-tls-service-profile. All three
    # are appliance-anchored objects with a scope on the row rather than device settings.
    DeviceTab("assessment_certificate_list", "Certificates", "clipboard-check", "Certificates"),
    DeviceTab("assessment_certificate_profile_list", "Certificate Profiles", "server", "Certificates"),
    DeviceTab("assessment_ssl_tls_service_profile_list", "SSL/TLS Profiles", "settings", "Certificates"),
    # Network - network/profiles/...
    DeviceTab("assessment_interface_management_profile_list", "Interface Profiles", "list-checks", "Network"),
)

DEVICE_TAB_URL_NAMES = frozenset(tab.url_name for tab in DEVICE_TABS)
SECTION_BY_URL_NAME = {tab.url_name: tab.section for tab in DEVICE_TABS}


def tabs_in(section: str) -> tuple[DeviceTab, ...]:
    return tuple(tab for tab in DEVICE_TABS if tab.section == section)
