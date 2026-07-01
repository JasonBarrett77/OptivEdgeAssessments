# Device Configuration Search Spec

## Model

- canonical model: `integrations.DeviceConfigurationProfile`

This model represents appliance-scoped normalized device configuration settings
derived from PAN-OS merged configuration snapshots.

## Supported Fields

- `management_station`
- `hostname`
- `serial_number`
- `appliance_group`
- `ha_required`
- `ha_enabled`
- `ha_state_sync_enabled`
- `ha_link_monitoring_enabled`
- `ntp_primary_server`
- `ntp_secondary_server`
- `http_disabled`
- `https_disabled`
- `telnet_disabled`
- `ssh_disabled`
- `icmp_disabled`
- `snmp_disabled`
- `has_permitted_ip_restrictions`
- `has_unrestricted_permitted_ips`
- `permitted_ip_count`
- `login_banner`
- `idle_timeout_minutes`

## Supported Operators

Boolean fields:
- `eq`

Integer fields:
- `eq`
- `lt`
- `lte`
- `gt`
- `gte`

Text fields:
- `eq`
- `contains`
- `is_empty`

## Current Prototype Assumptions

- HA is considered required when `appliance.appliance_group.group_type == ha_pair`.
- `ha_enabled` defaults to `false` when omitted.
- `ha_state_sync_enabled` defaults to the effective HA-enabled value when omitted.
- `ha_link_monitoring_enabled` defaults to `false` when omitted.
- service disable defaults are currently treated as:
  - `http_disabled = true`
  - `https_disabled = false`
  - `telnet_disabled = true`
  - `ssh_disabled = false`
  - `icmp_disabled = false`
  - `snmp_disabled = true`
- `idle_timeout_minutes` defaults to `60` when omitted.
- `has_unrestricted_permitted_ips` currently means at least one permitted IP entry
  resolves to the full IPv4 space, such as `0.0.0.0/0`.

## Known Limits

- approved NTP-server validation is not implemented yet
- approved management-source validation is not implemented yet
- broad permitted-IP evaluation is currently limited to unrestricted
  full-IPv4-space entries rather than a configurable enterprise policy
