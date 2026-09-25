"""Assessments app metadata for project composition.

Four items: the controls, what the controls found, what the configuration says, and the
experimental shelf. The Findings item names two routes rather than one per domain - the domain
pages route on a slug, so the list cannot fall behind the way the old Device Configuration
item did, which drifted six tabs behind because this file is nowhere near the one you edit
when adding a tab.
"""


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
        },
        "items": [
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
