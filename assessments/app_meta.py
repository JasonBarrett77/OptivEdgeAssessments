"""Assessments app metadata for project composition."""

URL_MOUNT = {
    "prefix": "assessments/",
    "module": "assessments.urls",
}

SIDEBAR_SECTION = {
    "label": "Assessments",
    "icon": "clipboard-check",
    "active_names": {
        "assessment_security_rule_list",
        "assessment_security_rule_plain_language",
        "assessment_rule_finding_list",
        "assessment_management_finding_list",
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
            "label": "Security Rules",
            "href": "/assessments/security-rules/",
            "active_names": {
                "assessment_security_rule_list",
            },
        },
        {
            "label": "Plain Language Rules",
            "href": "/assessments/security-rules/plain-language/",
            "active_names": {
                "assessment_security_rule_plain_language",
            },
        },
        {
            "label": "Controls",
            "href": "/assessments/controls/",
            "active_names": {
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
            "label": "Findings",
            "href": "/assessments/findings/",
            "active_names": {
                "assessment_rule_finding_list",
            },
        },
        {
            "label": "Management Findings",
            "href": "/assessments/management-findings/",
            "active_names": {
                "assessment_management_finding_list",
            },
        },
    ],
}
