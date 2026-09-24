"""Engineer-detail xlsx, prototype: the Authentication Settings controls, PAN-AUTH-014 to 017.

The second group built on `findings_sheet.DeviceSettingSheet`, and the reason that module exists:
same shape as password complexity - `AuthenticationSettings` is one row per appliance and each
control tests one field - so the sheet is the shared one and only the domain is written here.

WHAT THIS GROUP ADDS THAT THE FIRST DID NOT. Overloaded zeros, in both directions, which is why the
Fires-when cell has to be read rather than assumed:
- `lockout_failed_attempts` 0 means lockout is OFF, the weakest setting, so PAN-AUTH-014 fires on
  0 AND above 5.
- `idle_timeout_minutes` 0 means sessions NEVER expire, so PAN-AUTH-016 fires on 0 and above 10.
- `lockout_time_minutes` 0 runs the other way - locked until an administrator releases the account
  - so PAN-AUTH-015 fires between 1 and 29 and leaves 0 alone.
"""
from __future__ import annotations

from assessments.models import Control

from . import findings as findings_sheet
from ..layout import SheetInfo

SPEC = findings_sheet.DeviceSettingSheet(
    control_types=(Control.ControlType.AUTHENTICATION_SETTINGS,),
    # `AuthenticationSettings` carries the vendor default for an absent key; its docstring
    # lists what each zero means, including idle_timeout defaulting to 60 rather than 0.
    description=("How the firewall protects administrative sessions: lockout after failed logins, "
                 "how long an account stays locked, idle session timeout, and API key lifetime."),
)


def write_sheet(build) -> SheetInfo:
    return findings_sheet.write_sheet(build, SPEC)
