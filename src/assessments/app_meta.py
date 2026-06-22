"""Assessments app metadata for project composition."""

URL_MOUNT = {
    "prefix": "assessments/",
    "module": "assessments.urls",
}

SIDEBAR_SECTION = {
    "label": "Assessments",
    "icon": "clipboard-check",
    "active_names": {
        "assessment_catalog_list",
        "assessment_catalog_apply",
        "assessment_catalog_create_from_current",
        "assessment_catalog_download",
        "assessment_catalog_seed_download",
        "assessment_security_rule_list",
        "assessment_security_rule_plain_language",
        "assessment_rule_finding_list",
        "assessment_management_finding_list",
        "assessment_management_plane_profile_list",
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
            "label": "Security Rules",
            "href": "/assessments/security-rules/",
            "icon": "shield",
            "active_names": {
                "assessment_security_rule_list",
            },
        },
        {
            "label": "Plain Language Rules",
            "href": "/assessments/security-rules/plain-language/",
            "icon": "wand-sparkles",
            "active_names": {
                "assessment_security_rule_plain_language",
            },
        },
        {
            "label": "Findings",
            "href": "/assessments/findings/",
            "icon": "flag",
            "active_names": {
                "assessment_rule_finding_list",
            },
        },
        {
            "label": "Management Profiles",
            "href": "/assessments/management-plane-profiles/",
            "icon": "monitor",
            "active_names": {
                "assessment_management_plane_profile_list",
            },
        },
        {
            "label": "Management Findings",
            "href": "/assessments/management-findings/",
            "icon": "triangle-alert",
            "active_names": {
                "assessment_management_finding_list",
            },
        },
    ],
}
