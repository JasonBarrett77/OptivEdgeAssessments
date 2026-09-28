"""Assessments app metadata for project composition.

Four items, in the order the work runs in: the controls that ask, the configuration they ask
of, what the controls found, and the experimental shelf. The Findings item names two routes
rather than one per domain - the domain pages route on a slug, so the list cannot fall behind
the way the old Device Configuration item did, which drifted six tabs behind because this file
is nowhere near the one you edit when adding a tab.
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
                #: Querying the configuration, organised the way the PAN-OS web interface is.
                #: It shows EVERY object of a type, including the ones nothing is wrong with,
                #: which is the case the deleted device tabs used to answer. Findings, below,
                #: reports only what the controls concluded.
                "label": "Configuration",
                "href": "/assessments/configuration/",
                "icon": "settings",
                "active_names": {
                    "assessment_configuration_index",
                    "assessment_configuration_object",
                },
            },
            {
                #: What the controls found, laid out exactly as the engineer-detail workbook
                #: lays it out - the same table, from `artifacts.build_findings_table`. Last
                #: of the three because that is the order the work runs in: the controls ask,
                #: the configuration answers, the findings are what came of it.
                "label": "Findings",
                "href": "/assessments/findings/",
                "icon": "flag",
                "active_names": {
                    "assessment_findings_summary",
                    "assessment_findings_domain",
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
