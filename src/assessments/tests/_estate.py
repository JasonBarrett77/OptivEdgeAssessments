"""Build a domain's SUBJECT estate from its stage 6 artifact, through the committed normalisers.

`_seed.py` beside this does the Controls and ControlQueries half. Nothing did the subject half,
and five stage 9 runs - `ike-crypto`, `ipsec-crypto`, `device-id-iot`, `zone-dos-protection`,
`url-filtering` - each wrote and threw away their own. The last of them spent roughly the first
third of its run on it. Eleven domains were left to pay it. Board record P403.

WHAT THIS IS NOT. It does not transcribe subjects by hand. Every one of those five seeders
hand-wrote its domain's PAN-OS entries as Python literals, which is why none of them could be
reused: the transcription WAS the work. This derives the entries from the artifact instead, and
the artifact turns out to carry enough to do it:

    identity.xpath          where the object lives, as a real PAN-OS xpath
    verified.read_back      what the device answered, as {key, value} leaf pairs
    identity.device         which serial it was read from

So a payload is assembled by walking each subject's own xpath and dropping its own read_back at
the end of it. That is domain-independent, and it is the whole reason this is an instrument
rather than a sixth seeder.

THE READ-BACK KEY GRAMMAR, which stage 6 states per subject and nothing else pins down:

    "block"                         a leaf, directly under the entry
    "flood/tcp-syn/enable"          a leaf down a path
    "@name", "@uuid", "@loc"        an attribute
    "network/log-setting/#text"     the text of a node that also carries attributes
    "scan/entry[0]/threshold"       an indexed child of a repeating node
    "network/layer3/member[0]/@src" an indexed member with attributes
    value null                      AN EMPTY TAG - `<action><block/></action>`, not a null leaf
    value [a, b]                    a member list; `{"member": [a, b]}` unless the key already
                                    ends in `member`, in which case it is placed as it stands

The null-is-an-empty-tag rule is what makes PAN-OS choice nodes come out right for free, and it
is why this needed no schema. There is ONE construct the grammar cannot express and it is named
per domain in `CHOICE_NODES` below - see that comment.

THE THREE TRAPS, all three handled in `build_base_estate` and each marked there:

    1. `EnforcementPoint.in_scope` DEFAULTS FALSE. This is worse than "the shared-scope
       normalisers filter on it": `flows.get_in_scope_appliances`,
       `get_in_scope_appliance_groups` and `get_in_scope_enforcement_points` ALL select through
       `enforcement_points.filter(in_scope=True)`, so a hand-seeded estate that leaves it
       default normalises nothing whatsoever and every report tab reads clean. One run lost a
       row count to this and read it as a real finding.
    2. `EnforcementNode` rows are REQUIRED or the workbook refuses to build, on a tab belonging
       to no domain under test. `snapshots.choose_local_appliance` also walks them.
    3. `source_snapshot` is NOT NULL on both subject models.
"""

from __future__ import annotations

import re
from typing import Any

from django.utils import timezone

#: Keys whose read_back VALUE is a tag name rather than text, per domain. The grammar cannot
#: derive this: `credential-enforcement/mode` reads `"ip-user"` in stage6-url-filtering.json,
#: but the device holds `<mode><ip-user/></mode>` - a CHOICE NODE, as the committed
#: `normalization/url_filtering.py` module docstring states at its line 22. Taking the value as
#: text would hand the normaliser `{"mode": "ip-user"}`, which reads as absent.
#:
#: zone-dos-protection needs no entry here, because its artifact spells the same construct the
#: other way: `action/block` with value null, which the grammar already renders as an empty tag.
#: Stage 6's own note on `oep-zdp6-p01` warns that "two earlier waves shipped two different
#: spellings", and this constant is where that disagreement is absorbed. A domain whose artifact
#: uses the null spelling throughout needs nothing added.
CHOICE_NODES: dict[str, tuple[str, ...]] = {
    "url-filtering": ("credential-enforcement/mode",),
}

#: Leaf names that are already member containers, so a list value is placed as it stands rather
#: than wrapped. Everything else wrapping in `member` is PAN-OS's own convention for a list.
_MEMBER_LEAVES = ("member",)

_SEGMENT = re.compile(r"^([^\[]+)(?:\[(?:@name=)?'?([^'\]]*)'?\])?$")


# --------------------------------------------------------------------------- the key grammar

def _split_key(key: str) -> list[tuple[str, int | str | None]]:
    """`"scan/entry[0]/threshold"` -> `[("scan", None), ("entry", 0), ("threshold", None)]`.

    A NAMED predicate is a third kind of segment and this read only the positional one until
    2026-11-02. `portal-config/client-auth/entry[@name='r1']/os` came back as the literal tag
    `"entry[@name='r1']"`, so the reader walking `client-auth` found no `entry` key and counted
    nothing - and because the parent node existed, it read as a committed empty container rather
    than failing. Measured across the 28 stage 6 artifacts on disk: 1,910 read_back keys in
    SEVENTEEN domains carry one, `av-wildfire` alone 692, and the three domains this command was
    proven on carry one between them (`ipsec-crypto`'s single key), which is why it survived.
    A string index is a name, an int is a position; both reach `_descend`.

    SPLIT THE SAME WAY AN XPATH IS, not on a bare `/`. A quoted name may contain a slash -
    `entry[@name='ethernet1/1']` - and `_xpath_segments` already refuses to split inside a
    predicate, with its own measurement of what a naive split costs. A read_back key is the same
    grammar as the xpath tail it hangs off, so it gets the same splitter rather than a second
    one that drifts from it.
    """
    out: list[tuple[str, int | str | None]] = []
    for raw in _xpath_segments(key):
        positional = re.match(r"^(.+?)\[(\d+)\]$", raw)
        if positional:
            out.append((positional.group(1), int(positional.group(2))))
            continue
        named = re.match(r"^(.+?)\[@name='([^']*)'\]$", raw)
        if named:
            out.append((named.group(1), named.group(2)))
            continue
        out.append((raw, None))
    return out


def _descend(node: dict[str, Any], tag: str, index: int | str | None) -> dict[str, Any]:
    """The child dict at `tag` (or at `tag[index]`, or at `tag[@name=index]`), created if absent.

    An indexed segment makes `tag` a LIST and pads it, because stage 6 writes
    `scan/entry[0]/...` before `scan/entry[1]/...` but nothing guarantees that order and a
    sparse list would silently drop an entry.

    A NAMED segment goes through `_named_entry`, which is what the xpath walk uses, so a read_back
    key and an xpath addressing the same entry land on the SAME dict and merge rather than
    producing two shapes of the same node.
    """
    if isinstance(index, str):
        if tag != "entry":
            # The same restriction `_walk` states for an xpath, for the same reason: every
            # named predicate in every stage 6 artifact read so far predicates on `entry`, and
            # inventing a placement for another tag would put configuration where no reader looks.
            raise ValueError(f"read_back key predicates on {tag!r}, not 'entry'")
        return _named_entry(node, index)
    if index is None:
        child = node.get(tag)
        if not isinstance(child, dict):
            child = {}
            node[tag] = child
        return child
    children = node.get(tag)
    if not isinstance(children, list):
        children = [] if children is None else [children]
        node[tag] = children
    while len(children) <= index:
        children.append({})
    if not isinstance(children[index], dict):
        children[index] = {}
    return children[index]


def _place(entry: dict[str, Any], key: str, value: Any) -> None:
    segments = _split_key(key)
    node = entry
    for tag, index in segments[:-1]:
        node = _descend(node, tag, index)
    tag, index = segments[-1]

    if index is not None:
        # `network/layer3/member[0]` with a scalar value: an indexed node whose own content is
        # text. PAN-OS spells that `#text`, and stage 6 does too, so this only has to make the
        # slot exist.
        #
        # A NAMED FINAL SEGMENT LANDS HERE TOO, and making the entry EXIST is the whole point of
        # it: `global-protect-portal/entry[@name='oep-gpp6-a']` with the value `present` is stage
        # 6's PRESENCE CENSUS on a container subject, and an entry count is what every reader of
        # such a container takes. Measured over the 28 artifacts: 13 such keys, 9 valued
        # `present` and 4 null. The census word goes to `#text` under the uniform rule rather
        # than being special-cased out, because no reader looks there and a literal-string
        # exception in a grammar is the thing that drifts.
        leaf = _descend(node, tag, index)
        if value is not None:
            leaf["#text"] = value
        return

    if value is None:
        # AN EMPTY TAG, not a null leaf. `<action><block/></action>`. Never overwrite content
        # already placed under the same path by an earlier key.
        if not isinstance(node.get(tag), (dict, list)):
            node[tag] = {}
        return

    if isinstance(value, list):
        node[tag] = list(value) if tag in _MEMBER_LEAVES else {"member": list(value)}
        return

    existing = node.get(tag)
    if isinstance(existing, dict):
        # The node already carries attributes from another key, so its own value is its text.
        existing["#text"] = value
        return
    node[tag] = value


def entry_from_read_back(read_back, *, choice_nodes=()) -> dict[str, Any]:
    """One subject's `verified.read_back` as the PAN-OS entry dict the normalisers read."""
    entry: dict[str, Any] = {}
    for pair in read_back or []:
        key, value = pair["key"], pair.get("value")
        if key in choice_nodes:
            # The value names a child tag: `mode` = "ip-user" means `<mode><ip-user/></mode>`.
            _place(entry, f"{key}/{value}", None)
            continue
        _place(entry, key, value)
    return entry


# --------------------------------------------------------------------------- xpath placement

def _xpath_segments(xpath: str) -> list[str]:
    """Split on `/` only OUTSIDE a `[...]` predicate.

    A plain `split("/")` is wrong and silently so: PAN-OS interface names contain slashes, so
    `/network/interface/ethernet/entry[@name='ethernet1/1']/layer3` splits inside the quoted
    name and produces the segment `entry[@name='ethernet1`. Measured across the 28 stage 6
    artifacts on disk, that costs `management-services` and `network-hardening` entirely - 112
    subjects and 95 declared verdicts between them - and it fails loudly rather than quietly
    only because the broken segment then does not parse.
    """
    out: list[str] = []
    depth = 0
    current: list[str] = []
    for character in xpath.strip("/"):
        if character == "[":
            depth += 1
        elif character == "]":
            depth -= 1
        if character == "/" and depth == 0:
            out.append("".join(current))
            current = []
            continue
        current.append(character)
    out.append("".join(current))
    return [segment for segment in out if segment]


def _parse_xpath(xpath: str) -> list[tuple[str, str | None]]:
    """`/config/devices/entry[@name='x']/vsys` -> `[("config", None), ("devices", None),
    ("entry", "x"), ("vsys", None)]`."""
    out: list[tuple[str, str | None]] = []
    for raw in _xpath_segments(xpath):
        match = _SEGMENT.match(raw)
        if not match:
            raise ValueError(f"unparsable xpath segment {raw!r} in {xpath!r}")
        tag, name = match.group(1), match.group(2)
        out.append((tag, name))
    return out


def _named_entry(node: dict[str, Any], name: str) -> dict[str, Any]:
    """The `entry` child with this `@name`, created if absent. Entries stay a LIST always, even
    at length one: `ensure_list` in the committed readers accepts both, but a bare dict and a
    one-element list are different shapes to anything that counts them."""
    entries = node.get("entry")
    if not isinstance(entries, list):
        entries = [] if entries is None else [entries]
        node["entry"] = entries
    for candidate in entries:
        if isinstance(candidate, dict) and candidate.get("@name") == name:
            return candidate
    created: dict[str, Any] = {"@name": name}
    entries.append(created)
    return created


def _walk(root: dict[str, Any], segments) -> dict[str, Any]:
    """Follow the xpath, creating the tree as it goes, and return the addressed node."""
    node = root
    for tag, name in segments:
        if name is not None:
            if tag != "entry":
                # Every xpath in every stage 6 artifact read so far predicates on `entry`. A
                # different predicated tag is a shape this has not seen, and inventing a
                # placement for it would put configuration somewhere no reader looks.
                raise ValueError(f"xpath predicates on {tag!r}, not 'entry'")
            node = _named_entry(node, name)
            continue
        child = node.get(tag)
        if not isinstance(child, dict):
            child = {}
            node[tag] = child
        node = child
    return node


class PayloadSet:
    """The snapshot payloads one appliance's subjects land in.

    Four roots, because the committed readers take four different reads and `/config/...` says
    which: a subject's xpath is routed on its FIRST segment after `/config`, so the routing is
    the artifact's own and not a per-domain table.
    """

    def __init__(self, device_name: str = "localhost.localdomain") -> None:
        #: `show_merged_config` - `/config/devices/...` and `/config/shared/...`
        #:
        #: THE DEVICE ENTRY IS PRESENT FROM THE START, even for a serial whose subjects are all
        #: shared-scope or all absences. `device_configuration.device_entry_from_snapshot`
        #: RAISES "merged config does not contain a device entry" on a payload without one, and
        #: it is reached from well over thirty normalisers - so one serial with no device-scoped
        #: subject takes out the whole appliance pass for every domain, not just its own.
        self.merged: dict[str, Any] = {
            "config": {"devices": {"entry": [{"@name": device_name}]}}}
        #: `config_predefined_security_profiles` - `/config/predefined/profiles/...`,
        #: shaped `{"profiles": ...}` as `security_profiles._predefined_root` accepts.
        self.predefined: dict[str, Any] = {}
        #: `show_predefined_url_categories` - not a subject root; filled from the recipe.
        self.url_categories: dict[str, Any] | None = None
        #: `/config/panorama/...`, if a domain's artifact ever places a subject there.
        self.pushed_vsys: dict[str, Any] = {"policy": {"panorama": {}}}

    def ensure_vsys(self, vsys_name: str) -> dict[str, Any]:
        """The named vsys entry of the device, created if the subjects did not create it.

        `common.merged_vsys_entry` matches the point's `vsys_name` against the payload and
        answers {} when it is absent, which every vsys-grain normaliser then reads as an empty
        virtual system. That is indistinguishable from a real one with nothing in it.
        """
        device = self.merged["config"]["devices"]["entry"][0]
        vsys = device.setdefault("vsys", {})
        return _named_entry(vsys, vsys_name)

    def place(self, xpath: str, entry: dict[str, Any]) -> None:
        segments = _parse_xpath(xpath)
        if not segments or segments[0][0] != "config":
            raise ValueError(f"xpath does not start at /config: {xpath!r}")
        rest = segments[1:]
        if not rest:
            raise ValueError(f"xpath addresses /config itself: {xpath!r}")
        head = rest[0][0]
        if head == "predefined":
            root, rest = self.predefined, rest[1:]
        elif head == "panorama":
            root, rest = self.pushed_vsys["policy"]["panorama"], rest[1:]
        else:
            root = self.merged["config"]
        target = _walk(root, rest)
        _merge_into(target, entry)


def _merge_into(target: dict[str, Any], entry: dict[str, Any]) -> None:
    """Entry content onto a node the xpath walk created, keeping the `@name` the walk set.

    DEEP, AND IT WAS A ONE-LEVEL OVERWRITE UNTIL 2026-11-02. Two subjects of one domain can
    address the same node at different grains - a CONTAINER subject whose xpath is a strict
    ANCESTOR of an entry subject's - and `target[key] = value` let whichever was placed second
    destroy the first. Measured on `globalprotect-portal`: `gpp-14` is
    `.../vsys/entry[@name='vsys4']/global-protect` and is an ancestor of the four portal entries
    `gpp-04`, `-06`, `-08`, `-10`; it is placed later because it is later in the artifact's own
    key order, and its census subtree replaced the `global-protect-portal` node the four had
    built. Every portal row in the estate vanished, and the vsys then read as one holding no
    portal at all - which is a real and graded state, so it reconciled as four honest
    `no_finding`s rather than failing.

    Twenty-two of the 28 artifacts on disk carry at least one strict-ancestor subject, so the
    ORDER was deciding what the estate contained. It no longer decides anything: a dict merges
    into a dict, and an `entry` list merges BY `@name` so the same named entry addressed twice
    is one dict rather than two. Where the two genuinely disagree about a leaf the later value
    still wins, which is the old behaviour narrowed to the leaf it is about.
    """
    for key, value in entry.items():
        if key == "@name" and target.get("@name") and value != target.get("@name"):
            # The read_back's own `@name` wins nothing here: the xpath is the address, and for
            # `predefined-default` the two genuinely differ (subject label vs entry name).
            continue
        existing = target.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            _merge_into(existing, value)
            continue
        if (isinstance(existing, list) and isinstance(value, list)
                and all(isinstance(item, dict) for item in existing)
                and all(isinstance(item, dict) for item in value)):
            # An entry list from both sides. Named entries are the same object; anything
            # unnamed is appended, because nothing identifies it to merge onto.
            by_name = {item["@name"]: item for item in existing if item.get("@name") is not None}
            for item in value:
                name = item.get("@name")
                if name is not None and name in by_name:
                    _merge_into(by_name[name], item)
                else:
                    existing.append(item)
            continue
        target[key] = value


# --------------------------------------------------------------------------- subject reading

def device_name_of(subject) -> str | None:
    """The DEVICE entry name of a stage 6 subject, which is not always its artifact label.

    `predefined-default` is stored as `default`; `zz-urlfilt-shared` as `zz_urlfilt_shared`;
    `pushed-cat-ab0826-3` as `optivlib_uc_ab0826_3`. In stage6-ipsec-crypto.json TWENTY-EIGHT of
    the thirty-one subjects are labelled differently from the entry they name. Every thrown-away
    seeder hard-coded the ones it happened to need as if-statements in its reconciler. The xpath
    already carries the mapping, so this reads it off and the mapping is complete by
    construction.

    None when the subject is not entry-grain at all - a device-wide settings node such as
    `/deviceconfig/setting/session`, or a container an absence subject points at. Those have no
    entry name to match a finding's subject against, and returning the enclosing device or vsys
    name (which is what the last `entry[@name=]` in such an xpath is) would match the wrong row.
    """
    xpath = (subject.get("identity") or {}).get("xpath") or ""
    segments = _xpath_segments(xpath)
    if not segments:
        return None
    # Segmented, not `rsplit("/")`: an interface subject ends `entry[@name='ethernet1/1']`, and
    # splitting on the last slash would answer `1']`.
    found = re.match(r"^entry\[@name='([^']*)'\]$", segments[-1])
    return found.group(1) if found else None


def subject_is_absent(subject) -> bool:
    """An ABSENCE subject: stage 6 recorded it to prove nothing of that name exists.

    Read from an empty `verified.read_back`, which is how stage 6 spells "no entry of this name
    in any view". Transcribing it as the absence of a row is what makes its `no_finding` honest,
    so these are placed nowhere at all.
    """
    return not (subject.get("verified") or {}).get("read_back")


def _vsys_of(subject) -> str | None:
    identity = subject.get("identity") or {}
    if identity.get("vsys_name"):
        return identity["vsys_name"]
    found = re.search(r"/vsys/entry\[@name='([^']*)'\]", identity.get("xpath") or "")
    return found.group(1) if found else None


def payloads_from_stage6(stage6, *, choice_nodes=()) -> dict[str, PayloadSet]:
    """{serial: PayloadSet} for every subject the artifact records.

    A subject with no `identity.device` is skipped and named by the caller: without a serial
    there is no appliance to hang its snapshot off, and guessing one would put configuration on
    a device that was never read.
    """
    device_name = device_entry_name_from_stage6(stage6)
    vsys_names = vsys_names_from_stage6(stage6)
    out: dict[str, PayloadSet] = {}
    for serial in set(vsys_names):
        # EVERY serial gets a payload, even one whose subjects are all absences: the device
        # entry has to exist or the appliance pass raises for every domain. The vsys entries go
        # in for the same reason one level down - a point whose vsys is not in the payload
        # normalises nothing and reads as an empty virtual system rather than an unread one.
        payloads = out.setdefault(serial, PayloadSet(device_name))
        for vsys in sorted(vsys_names[serial]):
            payloads.ensure_vsys(vsys)
    for subject in (stage6.get("subjects") or {}).values():
        identity = subject.get("identity") or {}
        serial, xpath = identity.get("device"), identity.get("xpath")
        if not serial or not xpath or subject_is_absent(subject):
            continue
        payloads = out.setdefault(serial, PayloadSet(device_name))
        payloads.place(xpath, entry_from_read_back(
            subject["verified"]["read_back"], choice_nodes=choice_nodes))
    return out


def device_entry_name_from_stage6(stage6) -> str:
    """The `/config/devices/entry[@name=...]` the artifact's own xpaths use.

    Read rather than assumed. It is `localhost.localdomain` on every PAN-OS firewall and on all
    28 artifacts on disk, but it is written in the xpath, and the readers match on it.
    """
    for subject in (stage6.get("subjects") or {}).values():
        xpath = (subject.get("identity") or {}).get("xpath") or ""
        found = re.search(r"^/config/devices/entry\[@name='([^']*)'\]", xpath)
        if found:
            return found.group(1)
    return "localhost.localdomain"


def vsys_names_from_stage6(stage6) -> dict[str, set[str]]:
    """{serial: {vsys_name}} - which enforcement points this estate needs.

    A serial whose subjects are all device-local still gets `vsys1`: the point-grain
    normalisers are selected through `in_scope=True` enforcement points, so an appliance with
    none of them is an appliance nothing normalises.
    """
    out: dict[str, set[str]] = {}
    for subject in (stage6.get("subjects") or {}).values():
        identity = subject.get("identity") or {}
        serial = identity.get("device")
        if not serial:
            continue
        names = out.setdefault(serial, set())
        vsys = _vsys_of(subject)
        if vsys:
            names.add(vsys)
    for serial, names in out.items():
        if not names:
            names.add("vsys1")
    return out


def software_versions_from_stage6(stage6) -> dict[str, str]:
    """{serial: software_version} from the artifact's `devices` block, where it is recorded.

    It is not decoration. `security_profiles.resolve_max_version` grades a decryption profile's
    ceiling against the appliance's own top version, so a blank one moves a verdict.
    """
    out: dict[str, str] = {}
    for serial, device in (stage6.get("devices") or {}).items():
        for key in ("software_version", "sw_version", "version", "panos_version"):
            value = device.get(key) if isinstance(device, dict) else None
            if value:
                out[serial] = str(value)
                break
    return out


# --------------------------------------------------------------------------- the estate

#: Normalisers that `flows.renormalize_in_scope_configuration` does NOT run, by grain.
#:
#: MEASURED, not read off a naming convention. Of the 86 `normalize_*` callables that
#: `normalization/__init__.py` exports, these seven are reachable from `flows.py` NEITHER by
#: their own name NOR through any wrapper that `flows.py` calls. `flows.py` contains the string
#: "ipsec" zero times.
#:
#: The first attempt at this list checked only the `normalize_appliance_*` /
#: `normalize_enforcement_point_*` wrappers and so found two of the seven, which was enough to
#: make `zone-dos-protection` reconcile and left `ipsec-crypto` at 64 mismatches with every one
#: of its subject models empty. The convention is not the contract; reachability is.
#:
#: THIS IS A GAP IN THE COMMITTED COLLECTION FLOW, not in this command: a real collection run
#: writes no zone protection profile, DoS rule, IKE crypto profile, IKE gateway, IPSec crypto
#: profile, IPSec tunnel or monitor profile row either. It is recorded here rather than fixed
#: because OptivEdgeIntegrations is not this command's to change, and it is worth somebody's
#: attention on its own: it spans three pipeline domains.
#:
#: RUN AFTER the renormalisation. `normalize_zone_protection_profiles` resolves
#: `Zone.zone_protection_unresolved` over the zone rows built from the SAME snapshot, so it has
#: to follow the zone pass the flow performs - its own docstring says running it first leaves
#: every zone row at the firing default its normalizer set, which over-reports rather than going
#: quiet. The others depend on nothing in this list: each reads its own subtree of the merged
#: payload directly, including `normalize_ipsec_tunnels`, which resolves the crypto profile and
#: monitor actions a tunnel names out of the PAYLOAD and not out of the rows written above it.
SUPPLEMENTAL_NORMALIZERS: tuple[tuple[str, str], ...] = (
    ("appliance", "normalize_ike_crypto_profiles"),
    ("appliance", "normalize_ike_gateways"),
    ("appliance", "normalize_ipsec_crypto_profiles"),
    ("appliance", "normalize_monitor_profiles"),
    ("appliance", "normalize_ipsec_tunnels"),
    ("appliance", "normalize_appliance_zone_protection_profiles"),
    ("enforcement_point", "normalize_enforcement_point_dos_policy_rules"),
)

#: `show predefined pan-url-categories`, the only auxiliary read no subject can supply, keyed by
#: domain. RECONSTRUCTED, NEVER MEASURED, and the distinction matters: the device's own oracle
#: answered 90 names to the stage 6 run on 691665AC334B458 and no capture of those 90 exists in
#: any repository. Without a catalogue, `category_catalogue_collected` is False and every
#: hostile-category verdict is unanswerable, so PAN-URL-001 fires on all fourteen profiles at
#: its baseline severity - measured here before this constant was filled, as ten reconciliation
#: mismatches.
#:
#: The list is the three confirmed-hostile names, the six risk tiers the model ranks, the
#: predefined profile's own block and alert lists as stage 6 read them back, the predefined names
#: the custom categories name, and real PAN-DB category names as padding. It reaches 89, NOT the
#: device's 90: every name here is a real PAN-DB category, and inventing one to reach the
#: measured count would turn a padded reconstruction into a fabricated measurement. Taken from
#: the `url-filtering` stage 9 run's own seeder, which recorded the same reasoning.
_URL_HOSTILE = ("command-and-control", "malware", "phishing")
_URL_RISK = ("high-risk", "unknown", "medium-risk", "newly-registered-domain", "not-resolved",
             "low-risk")
_URL_PREDEF_BLOCK = ("adult", "questionable", "abused-drugs", "hacking", "gambling", "weapons",
                     "malware", "phishing", "command-and-control", "grayware", "ransomware",
                     "scanning-activity")
_URL_PREDEF_ALERT = ("high-risk", "medium-risk", "newly-registered-domain", "cryptocurrency",
                     "real-time-detection", "artificial-intelligence", "remote-access",
                     "AI-code-assistant", "AI-conversational-assistant", "AI-writing-assistant",
                     "AI-media-service", "AI-data-and-workflow-optimizer", "AI-platform-service",
                     "AI-meeting-assistant", "AI-website-generator", "file-converter",
                     "browser-runtime-attack")
_URL_PADDING = (
    "abortion", "alcohol-and-tobacco", "auctions", "business-and-economy",
    "computer-and-internet-info", "content-delivery-networks", "copyright-infringement",
    "dating", "dynamic-dns", "educational-institutions", "entertainment-and-arts", "extremism",
    "financial-services", "games", "government", "health-and-medicine", "home-and-garden",
    "hunting-and-fishing", "insufficient-content", "internet-communications-and-telephony",
    "internet-portals", "job-search", "legal", "military", "motor-vehicles", "music", "news",
    "nudity", "online-storage-and-backup", "parked", "peer-to-peer", "personal-sites-and-blogs",
    "philosophy-and-political-advocacy", "private-ip-addresses",
    "proxy-avoidance-and-anonymizers", "real-estate", "recreation-and-hobbies",
    "reference-and-research", "religion", "search-engines", "sex-education",
    "shareware-and-freeware", "shopping", "social-networking", "society", "sports",
    "stock-advice-and-tools", "streaming-media", "swimsuits-and-intimate-apparel",
    "training-and-tools", "translation", "travel", "web-advertisements", "web-based-email",
    "web-hosting", "encrypted-dns", "compromised-website",
)


def _url_catalogue() -> tuple[str, ...]:
    out: list[str] = []
    for name in (_URL_HOSTILE + _URL_RISK + _URL_PREDEF_BLOCK + _URL_PREDEF_ALERT
                 + _URL_PADDING):
        if name not in out:
            out.append(name)
    return tuple(out)


AUX_URL_CATEGORIES: dict[str, tuple[str, ...]] = {
    "url-filtering": _url_catalogue(),
}


def run_supplemental_normalizers(station) -> list[tuple[str, str]]:
    """The normalisers `renormalize_in_scope_configuration` leaves out. Returns failures.

    Each gets its own try/except, which is the convention every pass in `flows.py` follows and
    for its reason: one subtree failing must not silently remove another's rows.
    """
    from optivedge_integrations.integrations.platforms.pan_os import normalization
    from optivedge_integrations.integrations.platforms.pan_os.flows import (
        get_in_scope_appliances, get_in_scope_enforcement_points)

    failures: list[tuple[str, str]] = []
    targets = {"appliance": get_in_scope_appliances(station),
               "enforcement_point": get_in_scope_enforcement_points(station)}
    for grain, name in SUPPLEMENTAL_NORMALIZERS:
        normalize = getattr(normalization, name)
        for target in targets[grain]:
            try:
                normalize(target)
            except Exception as exc:  # noqa: BLE001 - one failing must not stop the rest
                failures.append((name, f"{type(exc).__name__}: {exc}"))
    return failures


def build_base_estate(stage6, *, panorama_managed: bool = True):
    """The station, group, appliances, points, nodes and snapshots this domain's subjects need.

    Returns `(station, {serial: appliance}, {(serial, vsys): point})`.

    `panorama_managed` decides `ManagementStation.station_type`, which is the ONE thing
    `snapshots.is_panorama_managed` reads and which therefore decides whether the pushed-policy
    snapshots are required reads or absent ones. It defaults True because stage 6 records
    Panorama-pushed and template-pushed subjects on both proving domains, and because the
    pushed payloads are written below either way: an empty pushed read is a read that answered
    with nothing, which is what the lab's single-vsys PA-VMs actually return.
    """
    from optivedge_integrations.integrations.models import (
        Appliance, ApplianceGroup, EnforcementNode, EnforcementPoint, ManagementStation,
        Snapshot)

    choice_nodes = CHOICE_NODES.get(stage6.get("domain") or "", ())
    payloads = payloads_from_stage6(stage6, choice_nodes=choice_nodes)
    vsys_names = vsys_names_from_stage6(stage6)
    versions = software_versions_from_stage6(stage6)
    catalogue = AUX_URL_CATEGORIES.get(stage6.get("domain") or "")

    station = ManagementStation.objects.create(
        station_type=(ManagementStation.StationType.PAN_PANORAMA if panorama_managed
                      else ManagementStation.StationType.PAN_FIREWALL),
        name="p403-station", hostname="p403-station", username="u", password="p",
        ca_bundle_path="", notes="built by print_findings_table from a stage 6 artifact")

    appliances: dict[str, Any] = {}
    points: dict[tuple[str, str], Any] = {}
    now = timezone.now()

    # ONE APPLIANCE GROUP PER SERIAL, which the schema requires rather than prefers:
    # `EnforcementPoint` is UNIQUE on (appliance_group, vsys_name), because a vsys is a property
    # of the GROUP's namespace and not of one box - that is what lets an HA pair share one. Two
    # serials in one group therefore cannot both have a `vsys1`, and stage 6 artifacts routinely
    # record subjects on two serials: stage6-ipsec-crypto.json uses both lab appliances. So each
    # serial is modelled as its own standalone group, which is also what it is.
    for serial in sorted(set(payloads) | set(vsys_names)):
        group = ApplianceGroup.objects.create(
            management_station=station, name=f"standalone-{serial}",
            discovery_key=f"group:{serial}", notes="")
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            hostname=f"pan-fw-{serial[-4:].lower()}", serial_number=serial, model="PA-VM",
            software_version=versions.get(serial, ""), notes="")
        appliances[serial] = appliance
        # `snapshots.choose_local_appliance` prefers the group's active appliance, so a group
        # whose active appliance is unset falls through to its nodes - set it explicitly rather
        # than relying on that fallback.
        group.active_appliance = appliance
        group.save(update_fields=["active_appliance"])

        payload_set = payloads.get(serial) or PayloadSet(
            device_entry_name_from_stage6(stage6))

        # TRAP 3: `source_snapshot` is NOT NULL on both subject models, so the snapshot has to
        # exist before anything normalises - and the merged one is what every reader anchors to.
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=now, payload=payload_set.merged)
        # The predefined read, written even when empty: `build_normalized_security_profiles`
        # records a normalization ISSUE when it is absent, and an issue is a finding on a tab.
        Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="config_predefined_security_profiles", collected_at=now,
            payload=payload_set.predefined)
        if catalogue is not None:
            Snapshot.objects.create(
                management_station=station, appliance=appliance,
                source_type="show_predefined_url_categories", collected_at=now,
                payload={"result": {"pan-url-categories": {
                    "entry": [{"@name": name} for name in catalogue]}}})

        for vsys in sorted(vsys_names.get(serial) or {"vsys1"}):
            # TRAP 1: `in_scope` DEFAULTS FALSE, and all three of `flows.py`'s in-scope
            # selectors read through it. Default it and this whole command normalises nothing
            # and reports a clean estate.
            point = EnforcementPoint.objects.create(
                management_station=station, appliance_group=group, appliance=appliance,
                vsys_name=vsys, vsys_display_name=vsys, in_scope=True,
                discovery_key=f"{serial}:{vsys}", notes="")
            points[(serial, vsys)] = point
            # TRAP 2: `EnforcementNode` rows are REQUIRED or the workbook refuses to build, on
            # a tab belonging to no domain under test. `choose_local_appliance` walks them too.
            EnforcementNode.objects.create(
                management_station=station, enforcement_point=point, appliance=appliance,
                notes="")
            # The per-point pushed reads. Written for a Panorama-managed station because the
            # committed build RAISES on their absence; an empty payload is "the read answered
            # with nothing", which is what the lab PA-VMs return.
            if panorama_managed:
                Snapshot.objects.create(
                    management_station=station, enforcement_point=point,
                    source_type="show_pushed_shared_policy_vsys", collected_at=now,
                    payload=payload_set.pushed_vsys)
                Snapshot.objects.create(
                    management_station=station, enforcement_point=point,
                    source_type="config_pushed_vsys_profiles", collected_at=now,
                    payload={"profiles": {}})

        if panorama_managed:
            # Per GROUP, not per point - `latest_pushed_shared_snapshot` looks it up by group.
            Snapshot.objects.create(
                management_station=station, appliance_group=group,
                source_type="show_pushed_shared_policy", collected_at=now,
                # `common.pushed_shared` is handed the ALREADY-UNWRAPPED result, so `shared`
                # belongs at the top level. Wrapping it in `result` raises "unrecognised pushed
                # shared payload root", which the committed reader does deliberately rather than
                # answering {} - an unrecognised root must not read as "no shared objects".
                payload={"shared": {}})

    return station, appliances, points


# --------------------------------------------------------------------------- reconciliation

class Verdict:
    """One stage 8 declared verdict, and what this build actually produced for it."""

    __slots__ = ("control_id", "subject", "device_name", "expected_produces",
                 "expected_severity", "got_produces", "got_severity", "agrees", "matched_by")

    def __init__(self, control_id, subject, device_name, expected_produces, expected_severity,
                 got_produces, got_severity, agrees, matched_by):
        self.control_id = control_id
        self.subject = subject
        self.device_name = device_name
        self.expected_produces = expected_produces
        self.expected_severity = expected_severity
        self.got_produces = got_produces
        self.got_severity = got_severity
        self.agrees = agrees
        self.matched_by = matched_by

    @property
    def ok(self) -> bool:
        return (self.got_produces == self.expected_produces
                and (self.got_severity or None) == (self.expected_severity or None))


def object_name_fields() -> dict[str, str]:
    """{control_type: the field its tab's `Object` column reads}.

    NOT a candidate list of attribute names, and not `name`. Only SOME subject models call it
    `name`: `ZoneProtectionProfile` has `profile_name`, `DosPolicyRule` has `rule_name`,
    `IkeCryptoProfile` and `IkeGateway` have `entry_name`, `IpsecTunnel` has `tunnel_name`. A
    reconciler reading `getattr(subject, "name", None)` gets None for every one of those, so
    every named subject fails to claim its own finding - measured on zone-dos-protection as 15
    mismatches with the findings sitting right there unclaimed.

    Taken from each tab's own `subject_columns`, which is the one place that states what a
    subject is PRESENTED as - and stage 6's subject labels name the same thing, because both
    name the device's entry. 20 of the registered finding kinds declare an `Object` column; the
    other 54 are appliance-scoped settings rows with no entry name at all, which is what
    `reconcile`'s second pass is for.
    """
    from assessments.artifacts.domains import DOMAINS

    out: dict[str, str] = {}
    for domain in DOMAINS:
        columns = [c for c in domain.spec.subject_columns if c and c[0] == "Object"]
        if not columns or len(columns[0]) <= 4 or not columns[0][4]:
            continue
        for control_type in domain.spec.control_types:
            out.setdefault(control_type, columns[0][4])
    return out


def findings_by_control() -> dict[str, list[tuple[str | None, Any]]]:
    """{control_id: [(subject name or None, finding)]} across EVERY registered finding model.

    From `finding_registry.FINDING_KINDS`, never from a hand-listed pair of models. The
    `url-filtering` seeder listed the two its domain writes to and was right to; the next domain
    writes to different ones, and a reconciler that lists them cannot move domains. The registry
    exists precisely because "naming two models is indistinguishable from there being two".
    """
    from assessments.finding_registry import FINDING_KINDS

    name_fields = object_name_fields()
    out: dict[str, list[tuple[str | None, Any]]] = {}
    for kind in FINDING_KINDS:
        field_name = name_fields.get(kind.control_type)
        for finding in kind.model.objects.select_related("control").all():
            subject = kind.subject_of(finding)
            found = getattr(subject, field_name, None) if field_name else None
            out.setdefault(finding.control.control_id, []).append((found or None, finding))
    return out


def reconcile(stage6, stage8) -> list[Verdict]:
    """EVERY declared stage 8 verdict against what this build produced.

    This is not an optional check. Without it a run is reading its own seeding mistakes and
    cannot tell them from presentation defects - which is what the `ipsec-crypto` run said after
    reconciling 108 verdicts at zero mismatches, and why it could then trust a single row.

    Stage 8's `actual` is the thing to reproduce, not its `expected`: `actual` is what stage 8
    MEASURED, and on the domains where the two disagree it is stage 8 that was right. `agrees`
    is carried through to the report so a reader can see which rows those were.

    Matching runs in two passes because not every subject is entry-grain. Named subjects claim
    findings by the device entry name their own xpath carries; a device-wide settings subject
    (`/deviceconfig/setting/session`) has no entry name, and claims from what is left over.
    """
    subjects = stage6.get("subjects") or {}
    produced = findings_by_control()
    out: list[Verdict] = []

    for control_id, control in (stage8.get("controls") or {}).items():
        rows = list((control.get("diff") or {}).get("subjects") or [])
        available = list(produced.get(control_id) or [])
        claimed: set[int] = set()
        resolved: dict[int, tuple[str, Any, str]] = {}

        # Pass 1 - entry-grain subjects, by the entry name the xpath carries.
        for index, row in enumerate(rows):
            label = row.get("stage6_subject")
            device_name = device_name_of(subjects.get(label) or {})
            if device_name is None:
                continue
            for position, (found_name, finding) in enumerate(available):
                if position in claimed or found_name != device_name:
                    continue
                claimed.add(position)
                resolved[index] = (device_name, finding, "entry name")
                break
            else:
                resolved[index] = (device_name, None, "entry name")

        # Pass 2 - subjects with no entry name of their own: device-wide settings nodes, and
        # absence subjects pointing at a container. They take an unclaimed finding for this
        # control if one is left, which is the only answer available at that grain: there is one
        # such row per appliance per control, so "a finding for this control that no named
        # subject claimed" is unambiguous.
        for index, row in enumerate(rows):
            if index in resolved:
                continue
            label = row.get("stage6_subject")
            picked = None
            for position, (_found_name, finding) in enumerate(available):
                if position not in claimed:
                    claimed.add(position)
                    picked = finding
                    break
            resolved[index] = (None, picked, "device-wide")

        for index, row in enumerate(rows):
            device_name, finding, matched_by = resolved[index]
            actual = row.get("actual") or {}
            out.append(Verdict(
                control_id=control_id, subject=row.get("stage6_subject"),
                device_name=device_name,
                expected_produces=actual.get("produces"),
                expected_severity=actual.get("severity"),
                got_produces=("finding_at_severity" if finding is not None else "no_finding"),
                got_severity=(finding.severity if finding is not None else None),
                agrees=row.get("agrees", True), matched_by=matched_by))
    return out
