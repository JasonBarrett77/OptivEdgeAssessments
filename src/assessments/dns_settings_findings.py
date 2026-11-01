"""Finding generation for the management-resolver control. PAN-SVC-003.

THE SENTENCE HAS TO SAY WHETHER ANYTHING IS RESOLVING AT ALL, because "no resolver chosen" means
two different things and the remediation differs. On a firewall whose management address is
LEASED, the appliance is resolving - through whatever address arrived with the lease, chosen by
whoever runs the DHCP server - and the fix is to name resolvers the organisation picked. On a
firewall with a FIXED address and no resolver, nothing is resolving and the symptom an engineer
sees is a firewall that cannot reach an update server by name.

A DNS PROXY OBJECT COUNTS AS ONE RESOLVER AND NOT AS ITS LIST. The normalizer says why: nothing
in the measured estate binds a proxy object, so the hop into its own server list has never been
exercised, and counting it as one is the direction that cannot reach the compliant rank on the
strength of a list nobody has read. The sentence says so rather than implying a count it did not
take.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_dns_settings_control_queries
from assessments.models import Control, DnsSettingsFinding, DnsSettingsFindingControlQuery
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models.device_services import (
    ManagementResolverPosture,
    ResolverMechanism,
)
from optivedge_integrations.integrations.models import DnsSettings


def _subject(obj) -> str:
    addresses = [a for a in (obj.primary_resolver_address, obj.secondary_resolver_address) if a]
    if obj.resolver_mechanism == ResolverMechanism.DNS_PROXY_OBJECT:
        head = (f"{obj.appliance} resolves management names through the DNS proxy object "
                f"{obj.dns_proxy_object_name}, which this assessment counts as ONE chosen "
                f"resolver - the object's own server list is a hop this reads nothing about")
    elif addresses:
        head = (f"{obj.appliance} names {len(addresses)} management resolver"
                f"{'' if len(addresses) == 1 else 's'} ({', '.join(addresses)})")
    else:
        head = f"{obj.appliance} names no management resolver of its own"

    parts = [head]
    if obj.management_resolver_posture == ManagementResolverPosture.NONE_ON_A_LEASED_ADDRESS:
        parts.append("and its management address is leased, so it IS resolving - through an "
                     "address that arrived with the lease and that nobody here chose")
    elif obj.management_resolver_posture == ManagementResolverPosture.NONE_ON_A_FIXED_ADDRESS:
        parts.append("and its management address is fixed, so nothing is resolving management "
                     "names at all")
    elif obj.management_resolver_posture == ManagementResolverPosture.ONE_RESOLVER_ONLY:
        parts.append("so losing that one resolver leaves the management plane unable to resolve "
                     "a name")

    if obj.resolution_follows_the_management_lease:
        parts.append("the lease's own resolver is what the firewall is using")
    return "; ".join(parts) + "."


def build_dns_settings_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj).rstrip("."), matched_queries)


SPEC = ObjectFindingSpec(
    label="management resolvers",
    control_type=Control.ControlType.DNS_SETTINGS,
    finding_model=DnsSettingsFinding,
    link_model=DnsSettingsFindingControlQuery,
    subject_fk="dns_settings",
    link_fk="dns_settings_finding",
    queryset=lambda: DnsSettings.objects.select_related("appliance"),
    evaluate=evaluate_dns_settings_control_queries,
    summary=build_dns_settings_finding_summary,
    # `DnsSettings` HAS NO `name` FIELD and `ObjectFindingSpec.subject_name` defaults to
    # `obj.name`, which fails at GENERATION time rather than at import - so this is not
    # optional for a device-wide subject.
    subject_name=lambda obj: str(obj.appliance),
)


def generate_dns_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_dns_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
