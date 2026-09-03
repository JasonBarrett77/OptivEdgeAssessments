"""Column specs for the device tabs, so a header is declared once rather than typed per cell.

One `<th>` class string appeared 50 times verbatim across ten templates. Worse than the
repetition: the header and the body were two independent lists of columns that had to agree,
and they stopped agreeing once already - removing two model fields left the headers declaring
columns the body no longer rendered, shifting every column after them. That is checklist item
44, and `test_device_tab_tables_are_square` now makes it fail a test rather than a reading.

The cells stay hand-written. A cell here is rarely a value - it is a value, plus a provenance
line, plus a weak/normal decision - and forcing that through a spec would make the templates
worse to read in order to make them shorter.

DELIBERATELY NO GROUPED-HEADER SUPPORT, though two pages have grouped headers. It was built,
then measured against the markup it would have to reproduce, and removed: Device Configuration
and Management Interfaces make per-group alignment choices (the administrative-services group
centres, the NTP group does not), and their group borders are not even consistent with each
other - the five-column sky run has no `border-r` on its last cell where the two-column emerald
run does. A spec could only reproduce that by growing a knob whose sole job is to preserve an
inconsistency. Those two keep their hand-written headers; if a third grouped page appears, that
is the moment to reconsider - and to settle the border question first.
"""

from __future__ import annotations

from typing import NamedTuple


class Column(NamedTuple):
    label: str
