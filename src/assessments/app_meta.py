"""Assessments app metadata for project composition.

The Device Configuration item derives its `active_names` from `navigation.DEVICE_TABS` rather
than listing them. Written out by hand it fell six tabs behind - the sidebar highlighted nothing
on Management TLS, SSL/TLS Profiles, Certificate Profiles, Master Key, Certificates or Password
Complexity - because this file is nowhere near the one you edit when adding a tab.
"""

from assessments.navigation import DEVICE_TAB_URL_NAMES

URL_MOUNT = {
    "prefix": "assessments/",
    "module": "assessments.urls",
}

SIDEBAR_SECTION = [
    {
        "label": "Assessments",
        "active_names": {
            "assessment_findings_summary",
            "assessment_findings_domain",
            "assessment_catalog_list",
            "assessment_catalog_apply",
            "assessment_catalog_create_from_current",
            "assessment_catalog_download",
            "assessment_catalog_seed_download",
            "assessment_system",
            "assessment_catalog_refresh_seed",
            "assessment_control_run_findings",
            *DEVICE_TAB_URL_NAMES,
            "assessment_control_list",
            "assessment_control_detail",
            "assessment_control_create",
            "assessment_control_update",
            "assessment_control_delete",
            "assessment_control_query_create",
            "assessment_control_query_update",
            "assessment_control_query_delete",
        },
        "items": [
            {
                "label": "Controls",
                "href": "/assessments/controls/",
                "icon": "list-checks",
                "active_names": {
                    "assessment_catalog_list",
                    "assessment_catalog_apply",
                    "assessment_catalog_create_from_current",
                    "assessment_catalog_download",
                    "assessment_catalog_seed_download",
                    "assessment_system",
                    "assessment_catalog_refresh_seed",
                    "assessment_control_run_findings",
                    "assessment_control_list",
                    "assessment_control_detail",
                    "assessment_control_create",
                    "assessment_control_update",
                    "assessment_control_delete",
                    "assessment_control_query_create",
                    "assessment_control_query_update",
                    "assessment_control_query_delete",
                },
            },
            {
                "label": "Device Configuration",
                #: The label names the AREA - the findings tabs - not a page. It used to
                #: open the Device Configuration tab, which was deleted with its model on
                #: 2026-09-11; the first tab left in the Device section is where it lands.
                "href": "/assessments/management-interfaces/",
                "icon": "monitor",
                #: Derived - every tab in navigation.DEVICE_TABS, so a new tab cannot be
                #: added without the sidebar following it.
                "active_names": set(DEVICE_TAB_URL_NAMES),
            },
            {
                #: What the controls found, laid out exactly as the engineer-detail workbook
                #: lays it out - the same table, from `artifacts.build_findings_table`. The
                #: Configuration item below asks the configuration a question; this one
                #: reports the answers the controls already gave.
                "label": "Findings",
                "href": "/assessments/findings/",
                "icon": "flag",
                "active_names": {
                    "assessment_findings_summary",
                    "assessment_findings_domain",
                },
            },
            {
                #: Querying the configuration, organised the way the PAN-OS web interface
                #: is. A DIFFERENT surface from Device Configuration, not its successor: that
                #: item presents what the controls found, this one asks a question of the
                #: configuration and shows what matches. Both stay.
                "label": "Configuration",
                "href": "/assessments/configuration/",
                "icon": "settings",
                "active_names": {
                    "assessment_configuration_index",
                    "assessment_configuration_object",
                },
            },
        ],
    },
    {
        "label": "Experimental",
        "active_names": {
            "assessment_security_rule_plain_language",
            "assessment_legacy_finding_list",
        },
        "items": [
            {
                "label": "Findings (Legacy)",
                "href": "/assessments/findings-legacy/",
                "icon": "flag",
                "active_names": {
                    "assessment_legacy_finding_list",
                },
            },
            {
                "label": "Plain-Language Security Rule Query",
                "href": "/assessments/security-rules/plain-language/",
                "icon": "wand-sparkles",
                "active_names": {
                    "assessment_security_rule_plain_language",
                },
            },
        ],
    },
]
