"""Shared parsing machinery for IOS-style configuration dialects.

Arista EOS and Cisco IOS differ in the lines that matter here — `vrrp` versus
`standby`, CIDR versus netmask — but share their overall shape: top-level stanzas
with indented bodies. That shape lives here so a dialect module only has to
describe its differences.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Final

from cassandra.factpack.schema import (
    AddressFamily,
    BgpNeighbor,
    BgpTimers,
    Device,
    DeviceId,
    FhrpGroup,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    Interface,
    InterfaceKind,
    InterfaceName,
    IpAddress,
    IpAssignment,
    Milliseconds,
    StpMode,
    StpTimers,
    TimerScope,
    TimerSource,
    TrackedObject,
    Vlan,
    VlanId,
)

_KINDS: Final = (
    ("Vlan", InterfaceKind.SVI),
    ("Loopback", InterfaceKind.LOOPBACK),
    ("Management", InterfaceKind.MANAGEMENT),
    ("Port-Channel", InterfaceKind.LAG),
    ("Port-channel", InterfaceKind.LAG),
    ("Tunnel", InterfaceKind.TUNNEL),
    ("Ethernet", InterfaceKind.PHYSICAL),
    ("GigabitEthernet", InterfaceKind.PHYSICAL),
    ("TenGigabitEthernet", InterfaceKind.PHYSICAL),
    ("FastEthernet", InterfaceKind.PHYSICAL),
)


def interface_kind(name: str) -> InterfaceKind:
    for prefix, kind in _KINDS:
        if name.startswith(prefix):
            return kind
    return InterfaceKind.UNKNOWN


@dataclass(slots=True)
class Stanza:
    """A top-level config line plus the indented lines beneath it.

    `line` and `body_lines` number the header and each body line from one, so a
    fact can carry the place it was configured. They count lines of the file the
    operator has open, which is why `strip_banners` blanks a banner out rather
    than deleting it.

    `body` is stripped, because for almost everything these dialects write the
    indentation is decoration. It is not decoration inside an IOS `vrrp <n>
    address-family` block, whose commands are ordinary words — `address`,
    `priority`, `shutdown` — that also mean something at the interface level.
    `body_indents` keeps the column each body line started in so a parser that
    needs to tell those two levels apart can, without every other parser having
    to care.
    """

    header: str
    body: list[str] = field(default_factory=list)
    line: int = 0
    body_lines: list[int] = field(default_factory=list)
    body_indents: list[int] = field(default_factory=list)


def stanzas(text: str) -> list[Stanza]:
    out: list[Stanza] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        if raw[0].isspace():
            if out:
                out[-1].body.append(raw.strip())
                out[-1].body_lines.append(number)
                out[-1].body_indents.append(len(raw) - len(raw.lstrip()))
            continue
        out.append(Stanza(header=raw.strip(), line=number))
    return out


@dataclass(slots=True)
class Block:
    """A config line plus the lines indented beneath it, indentation intact.

    The difference from `Stanza` is that `body` is not stripped, so a block can
    be split again at the next level down. `line` and `body_lines` number the
    header and each body line from one exactly as `Stanza` does, and they
    survive that second split, so a construct four levels into a file still
    knows which line it was written on.
    """

    header: str
    body: list[str] = field(default_factory=list)
    line: int = 0
    body_lines: list[int] = field(default_factory=list)


def blocks(lines: list[str], numbers: list[int] | None = None) -> list[Block]:
    """Split `lines` at their shallowest indentation into headers and bodies.

    `Stanza` splits a file once, at column zero, and strips what it finds; that
    is enough for the dialects whose sub-commands are one-liners. It is not
    enough for the dialects where indentation is structure — NX-OS nests an
    `hsrp <n>` block under an interface, and IOS-XR nests `interface` under
    `router vrrp`, `address-family` under that and the group under that again.
    Those need a splitter that can be applied to its own output, which is this
    one: it takes the shallowest indentation present as the header level and
    hands back each body still indented, ready to be split again.

    `numbers` is where each line sits in the file, and a nested split passes the
    enclosing block's `body_lines` so line citations survive the descent.
    Omitted, the lines are numbered from one.
    """
    out: list[Block] = []
    base: int | None = None
    counted = numbers if numbers is not None else list(range(1, len(lines) + 1))
    for number, raw in zip(counted, lines, strict=True):
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        if base is None:
            base = indent
        if indent > base and out:
            out[-1].body.append(raw)
            out[-1].body_lines.append(number)
            continue
        out.append(Block(header=raw.strip(), line=number))
    return out


# 802.1Q: 1 to 4094. Zero is the priority-tag id and 4095 is reserved, so
# neither can be a VLAN a port belongs to, and nothing exists above 4094.
MIN_VLAN_ID: Final = 1
MAX_VLAN_ID: Final = 4094


def vlan_list(spec: str) -> tuple[int, ...]:
    """Expand `14,24,34` and `10-12` into explicit VLAN ids.

    Returns only the ids it could read. Anything it could not is reported by
    `unreadable_vlans` so the caller can list it as unparsed rather than let it
    vanish — a dropped VLAN spec makes the next rule blame the operator for a
    port in a VLAN "that is not declared", when the declaration was there and
    this function could not read it.
    """
    vlans, _ = _read_vlans(spec)
    return vlans


def unreadable_vlans(spec: str) -> tuple[str, ...]:
    """The parts of a VLAN spec that named no usable id."""
    _, rejected = _read_vlans(spec)
    return rejected


def _read_vlans(spec: str) -> tuple[tuple[int, ...], tuple[str, ...]]:
    vlans: list[int] = []
    rejected: list[str] = []
    for raw in spec.split(","):
        part = raw.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if not (lo.isdigit() and hi.isdigit()):
                rejected.append(part)
                continue
            first, last = int(lo), int(hi)
            # Clamped, not expanded. `1-99999999` is a typo, and expanding it
            # allocates until the process is killed; there are only 4094 ids it
            # could have meant.
            low = max(first, MIN_VLAN_ID)
            high = min(last, MAX_VLAN_ID)
            if first > last or high < low:
                rejected.append(part)
                continue
            if first < MIN_VLAN_ID or last > MAX_VLAN_ID:
                rejected.append(part)
            vlans.extend(range(low, high + 1))
        elif part.isdigit():
            value = int(part)
            if MIN_VLAN_ID <= value <= MAX_VLAN_ID:
                vlans.append(value)
            else:
                # A VLAN id outside the standard is not a VLAN. Recording one
                # puts a segment in the topology that cannot exist, and judges
                # interfaces against it.
                rejected.append(part)
        else:
            rejected.append(part)
    return tuple(vlans), tuple(rejected)


# --------------------------------------------------------------------------
# Trunk allowed lists
#
# EOS, IOS and NX-OS spell `switchport trunk allowed vlan` identically, keywords
# included, and an allowed list is very often written across several lines: the
# first states a set and the ones after it add to or subtract from what is
# already there. Three copies of a regex that read only the first form is how the
# `add` keyword came to be unread on all three at once, so the whole command is
# read in one place and the dialects share it.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class TrunkAllowed:
    """What one `switchport trunk allowed vlan` line leaves the trunk permitting.

    `unreadable` carries the parts of the id list that named no usable VLAN, for
    the reason `unreadable_vlans` exists: a trunk quietly missing a VLAN this
    could not read looks exactly like a trunk the operator forgot, and the next
    rule blames them for it.
    """

    vlans: tuple[VlanId, ...]
    unreadable: tuple[str, ...] = ()


def trunk_allowed_vlans(
    current: tuple[VlanId, ...], argument: str
) -> TrunkAllowed | None:
    """Fold one `switchport trunk allowed vlan <argument>` into the allowed set.

    `current` is what earlier lines on the same interface left permitted, because
    that is what the keywords are relative to. The forms all three dialects
    accept:

    * no keyword — the list replaces whatever was there;
    * `add <list>` — union, the normal way to extend a list across several lines;
    * `remove <list>` — subtraction;
    * `none` — nothing is permitted;
    * `all` and `except <list>` — everything, and everything but the list.

    None means the argument is not one of those, which the caller reports. That
    is the important half: a form this does not know must not silently reduce the
    trunk to nothing, because `access-vlan-not-trunked` reads an empty allowed
    list as a port that cannot leave the switch and reports it HIGH.

    `add` and `remove` on a trunk that has stated no list yet are read against
    the empty set rather than against the platform default of "all VLANs". The
    Fact Pack has no way to say "everything except what a later line removes"
    short of expanding 4094 ids, and a `remove` line with no preceding list is
    not a shape any config in this corpus writes; reading it against nothing is
    the conservative direction, since it can only leave the allowed list smaller
    than the device's.
    """
    argument = argument.strip()
    if argument == "none":
        return TrunkAllowed(vlans=())
    if argument == "all":
        return TrunkAllowed(vlans=tuple(range(MIN_VLAN_ID, MAX_VLAN_ID + 1)))
    keyword, _, spec = argument.partition(" ")
    if keyword not in {"add", "remove", "except"}:
        keyword, spec = "", argument
    # An id list is one token — `10,20,30-32` — so anything with a space left in
    # it is a form this does not know rather than a list it cannot read, and the
    # difference decides whether the trunk keeps the VLANs it already had.
    if not spec or " " in spec:
        return None
    listed, rejected = _read_vlans(spec)
    if not listed and not rejected:
        return None
    if keyword == "add":
        vlans = tuple(sorted(set(current) | set(listed)))
    elif keyword == "remove":
        vlans = tuple(vlan for vlan in current if vlan not in set(listed))
    elif keyword == "except":
        excluded = set(listed)
        vlans = tuple(
            vlan for vlan in range(MIN_VLAN_ID, MAX_VLAN_ID + 1) if vlan not in excluded
        )
    else:
        vlans = listed
    return TrunkAllowed(vlans=vlans, unreadable=rejected)


def netmask_to_prefix_length(netmask: str) -> int | None:
    """`255.255.255.0` -> 24. IOS writes masks; the schema stores prefixes."""
    try:
        octets = [int(part) for part in netmask.split(".")]
    except ValueError:
        return None
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        return None
    bits = "".join(f"{octet:08b}" for octet in octets)
    if "01" in bits:  # non-contiguous mask
        return None
    return bits.count("1")


def seconds_to_ms(value: str | None) -> int | None:
    return None if value is None else int(value) * 1000


# --------------------------------------------------------------------------
# IPv6 addressing
#
# All three dialects write `ipv6 address <prefix>` the same way, and all three
# also accept forms that configure an address without stating a subnet anybody
# peers over: `eui-64` fills the host half in from the MAC, `autoconfig` takes
# the whole thing from a router advertisement, and a link-local address is
# scoped to the wire it sits on.
# --------------------------------------------------------------------------

# fe80::/10 is the link-local range. RFC 4291 reserves it for one hop, so it is
# not a subnet in the sense the FACTS rules mean: every IPv6 interface on every
# device has an address in it, whether the operator wrote one or not, and none
# of those addresses says anything about which wire the interface is on.
LINK_LOCAL_V6: Final = ipaddress.IPv6Network("fe80::/10")

# The arguments to `ipv6 address` that configure an address while naming no
# routable subnet. Kept apart from the addresses that do, because the caller has
# to tell "understood, nothing to record" from "not understood" — the second is
# a gap in this parser and belongs in `unparsed_lines`.
#
# `eui-64` is here rather than recorded: the prefix is real, but the address is
# derived from a MAC no configuration file states, so the assignment would have
# to invent a host part. `dhcp` and `autoconfig` state neither half.
_IPV6_NO_SUBNET: Final = re.compile(
    r"(?:autoconfig(?: default)?|dhcp(?: rapid-commit)?|use-link-local-only|"
    r"\S+ link-local|link-local(?: \S+)?|\S+ eui-64(?: \S+)?)"
)


def is_link_local_v6(address: str) -> bool:
    """True for an address in fe80::/10."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.version == 6 and parsed in LINK_LOCAL_V6


def ipv6_states_no_subnet(argument: str) -> bool:
    """True for an `ipv6 address` argument this understands but does not record.

    See `_IPV6_NO_SUBNET`. A line matching this has been read; it simply
    contributes no subnet, so it must not be reported as unparsed. A bare
    `fe80::1/64` counts too — the `link-local` keyword is how EOS writes it and
    the other two leave it off, and the address says what it is either way.
    """
    argument = argument.strip()
    if _IPV6_NO_SUBNET.fullmatch(argument):
        return True
    return is_link_local_v6(argument.split()[0].partition("/")[0] if argument else "")


def ipv6_assignment(argument: str) -> IpAssignment | None:
    """`ipv6 address` arguments -> one assignment, or None.

    None means either "understood and carries no subnet" or "not understood",
    which `ipv6_states_no_subnet` separates. A link-local address is understood
    and deliberately dropped: recording one would put every IPv6 interface in
    the collection into a single fe80::/64 and invent an L3 adjacency between
    every pair of devices in it, which is the opposite of what the addressing
    rules are for.
    """
    parts = argument.strip().split()
    if not parts:
        return None
    address, _, length = parts[0].partition("/")
    if not length.isdigit():
        return None
    if any(part not in {"secondary", "anycast", "preferred"} for part in parts[1:]):
        return None
    try:
        parsed = ipaddress.IPv6Address(address)
    except ValueError:
        return None
    if parsed in LINK_LOCAL_V6:
        return None
    return IpAssignment(
        address=str(parsed),
        prefix=f"{parsed}/{length}",
        family=AddressFamily.IPV6_UNICAST,
        secondary="secondary" in parts[1:],
    )


# --------------------------------------------------------------------------
# FHRP groups
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class FhrpRecord:
    """One device's membership of one FHRP group, as a dialect read it.

    `family` is carried because it is part of the group's identity and not a
    property of the member: VRRPv3 runs a separate virtual router per address
    family, so VRRP 14 for IPv4 and VRRP 14 for IPv6 on one interface elect
    separately and hold different virtual addresses. `interface` names where the
    group was configured, which is what decides the subnet the group belongs to.
    """

    number: int
    protocol: FhrpProtocol
    family: AddressFamily
    member: FhrpMember
    interface: InterfaceName
    virtual: IpAddress | None = None


# --------------------------------------------------------------------------
# Preemption
#
# RFC 3768 section 6.1 and RFC 5798 section 6.1.2 both make `Preempt_Mode`
# default True, and EOS, IOS, NX-OS and IOS-XR all ship VRRP with preemption on.
# HSRP is the exception in the other direction: Cisco's default is off, which is
# why `standby <n> preempt` is a line people write and `vrrp <n> preempt` is
# mostly a line people write to say what was already true.
#
# Every parser used to set the flag only where the word appeared, so a VRRP group
# that simply omits the line — the common case, because the default is what
# people want — was recorded as preempt-off. That is a false
# `fhrp-no-preempt-on-preferred` whose suggested change is a line already in
# effect, and, worse, it switches the TIMING tier off for that group:
# `timing/model.py::_settle` gates every challenger on `member.preempt`, so
# divergence and oscillation go unreported on a config that relies on the
# default.
#
# The default is therefore applied by protocol at construction, and the negation
# forms each dialect writes are read rather than swallowed.
# --------------------------------------------------------------------------

# The key an accumulated settings dict uses for a preemption that was turned off
# explicitly. Deliberately not spelled with a `preempt` prefix: the positive
# settings are recognised by that prefix, so a negation sharing it would read as
# one of them.
NO_PREEMPT_KEY: Final = "no_preempt"

# Preemption as each protocol ships it, absent any configuration.
PREEMPT_DEFAULTS: Final[dict[FhrpProtocol, bool]] = {
    FhrpProtocol.VRRP: True,
    FhrpProtocol.HSRP: False,
    # GLBP follows HSRP: Cisco ships it with preemption off on the AVG election.
    FhrpProtocol.GLBP: False,
}


def preempt_state(
    protocol: FhrpProtocol, settings: Mapping[str, str]
) -> tuple[bool, TimerSource]:
    """Whether one group preempts, and whether the configuration said so.

    The flag stays a bool because everything that reads it — the FACTS rule, the
    timing model, `cassandra facts`, the diagram — asks one yes-or-no question
    and would have to be taught a third state for no benefit. What is new beside
    it is the provenance, which answers the question the bool cannot: a reader of
    the fact pack could not tell "the operator wrote preempt" from "the protocol
    defaults to it", and those two call for different words in a finding.

    `CONFIGURED` covers the negation as well as the assertion. `no vrrp 14
    preempt` is a decision somebody made and is worth exactly as much as writing
    it on; recording it as a platform default would lose the one thing that
    distinguishes it from silence.
    """
    if settings.get(NO_PREEMPT_KEY):
        return False, TimerSource.CONFIGURED
    if any(key.startswith("preempt") for key in settings):
        return True, TimerSource.CONFIGURED
    return PREEMPT_DEFAULTS.get(protocol, False), TimerSource.PLATFORM_DEFAULT


# The keys an accumulated FHRP settings dict uses to say which address families
# its block configured: the virtual address if there is one, and a bare marker if
# the family was named without one.
FAMILY_KEYS: Final[dict[AddressFamily, tuple[str, str]]] = {
    AddressFamily.IPV4_UNICAST: ("virtual_ipv4", "ipv4"),
    AddressFamily.IPV6_UNICAST: ("virtual_ipv6", "ipv6"),
}


def configured_families(
    settings: Mapping[str, str],
) -> list[tuple[AddressFamily, str | None]]:
    """Which families one FHRP block configures, and each one's virtual address.

    For the dialects that write both families in a single block — EOS `vrrp
    <vrid> ipv4|ipv6`, IOS `standby <n> ip|ipv6` — the settings around them are
    stated once and apply to both, so the block yields one record per family and
    they share everything else.

    A family counts as configured when it has a virtual address, and also when
    the block names it without one: `standby 14 ipv6 autoconfig` derives the
    address from the interface prefix and the group's virtual MAC, so no
    configuration file states it and the group is real regardless. A block
    naming neither family is an IPv4 group whose address has not been written,
    which is the case `fhrp-virtual-*` exists to report.
    """
    found = [
        (family, settings.get(virtual))
        for family, (virtual, marker) in FAMILY_KEYS.items()
        if settings.get(virtual) or marker in settings
    ]
    return found or [(AddressFamily.IPV4_UNICAST, None)]


def fhrp_instance(number: int, family: AddressFamily) -> str:
    """What `TimerScope.instance` names for one FHRP group.

    The timer inventory is joined back to its group by device, interface and
    instance, and that join is only unique if the instance names the address
    family as well as the group number — a dual-stack interface has two groups
    numbered 14 and they may be timed differently. IPv4 keeps the bare number so
    the join every existing record relies on is unchanged.
    """
    if family is AddressFamily.IPV6_UNICAST:
        return f"{number} ipv6"
    return str(number)


@dataclass(slots=True)
class ParsedDevice:
    """One device's facts, plus what the parser could not account for."""

    device: Device
    tracked: tuple[TrackedObject, ...]
    timers: tuple[FhrpTimers, ...]
    unparsed_lines: tuple[str, ...]
    vlans: tuple[Vlan, ...] = ()
    fhrp_records: tuple[FhrpRecord, ...] = ()


type _GroupKey = tuple[FhrpProtocol, int, AddressFamily, str]


def assemble_fhrp_groups(devices: Iterable[ParsedDevice]) -> tuple[FhrpGroup, ...]:
    """Every parsed membership, joined into the groups they are members of.

    A group is identified by its protocol, its number, its address family and
    the subnet it runs on. The subnet is there because a group number is scoped
    to its segment — VRRP 1 on 10.10.0.0/24 and VRRP 1 on 10.20.0.0/24 are
    different groups, and merging them loses one virtual address and invents
    members. The family is there for the same reason one level down: a
    dual-stack interface carries two groups numbered 14, and merging those makes
    one device a member of one group twice.

    Tracked objects are defined at the top level of a config and referenced from
    a group, so the join happens here; a reference with nothing behind it keeps
    an empty target, which is what `fhrp-track-undefined` reports.
    """
    members: dict[_GroupKey, list[FhrpMember]] = {}
    virtuals: dict[_GroupKey, str | None] = {}

    for parsed in devices:
        targets = {tracked.id: tracked.target for tracked in parsed.tracked}
        interfaces = {
            interface.name: interface for interface in parsed.device.interfaces
        }
        for record in parsed.fhrp_records:
            subnet = _first_network(interfaces.get(record.interface), record.family)
            key: _GroupKey = (
                record.protocol,
                record.number,
                record.family,
                subnet or "",
            )
            members.setdefault(key, []).append(
                replace(
                    record.member,
                    tracked_objects=tuple(
                        replace(tracked, target=targets.get(tracked.id, ""))
                        for tracked in record.member.tracked_objects
                    ),
                )
            )
            virtuals.setdefault(key, record.virtual)

    return tuple(
        FhrpGroup(
            id=_group_id(key, members),
            protocol=key[0],
            group_number=key[1],
            family=key[2],
            members=tuple(group_members),
            virtual_ipv4=virtuals[key]
            if key[2] is AddressFamily.IPV4_UNICAST
            else None,
            virtual_ipv6=virtuals[key]
            if key[2] is AddressFamily.IPV6_UNICAST
            else None,
            subnet=key[3] or None,
        )
        for key, group_members in sorted(
            members.items(), key=lambda item: (item[0][0].value, *item[0][1:])
        )
    )


def _first_network(interface: Interface | None, family: AddressFamily) -> str | None:
    """The first subnet this interface is addressed in, in the group's family.

    Family-filtered rather than "first address of any family": a dual-stack SVI
    lists its IPv4 address first, so an unfiltered read would file the IPv6
    group under the IPv4 subnet and then compare its virtual address against it.
    """
    if interface is None:
        return None
    for assignment in interface.addresses:
        if assignment.family is not family:
            continue
        try:
            return str(ipaddress.ip_interface(assignment.prefix).network)
        except ValueError:
            continue
    return None


def _group_id(key: _GroupKey, groups: Mapping[_GroupKey, object]) -> str:
    """`vrrp-14`, `vrrp-14-ipv6`, or either with `@<subnet>` when reused.

    The short form is kept where it is unambiguous because it is what a person
    reading a finding expects; the subnet is only added when it is load-bearing.
    """
    protocol, number, family, subnet = key
    name = f"{protocol.value}-{number}"
    if family is AddressFamily.IPV6_UNICAST:
        name = f"{name}-ipv6"
    reused = sum(
        1
        for other in groups
        if other[0] is protocol and other[1] == number and other[2] is family
    )
    if reused > 1 and subnet:
        return f"{name}@{subnet}"
    return name


def declared_vlans_from(device: str, stanza: Stanza) -> list[Vlan]:
    """`vlan 10,20` plus an optional indented `name`, which only binds when the
    stanza declares exactly one id.

    The body is stripped here rather than assumed stripped. `Stanza` hands over
    stripped lines and `Block` does not, and NX-OS is split by the second one, so
    matching `name ` against a raw line meant every NX-OS VLAN name was dropped —
    invisibly, since only `cassandra facts` prints one.
    """
    ids = vlan_list(stanza.header.split(None, 1)[1])
    body = [line.strip() for line in stanza.body]
    name = next(
        (
            line.split(None, 1)[1]
            for line in body
            if line.startswith("name ") and len(line.split(None, 1)) == 2
        ),
        None,
    )
    return [
        Vlan(
            device=device,
            vlan_id=vid,
            name=name if len(ids) == 1 else None,
            config_line=stanza.line or None,
        )
        for vid in ids
    ]


# Top-level configuration domains this tool does not model, by design. They carry
# no fact any tier reads, and listing them as "unparsed" buries the lines that
# genuinely indicate a missing fact under a wall of AAA and SNMP.
#
# Deliberately conservative: anything not listed here is still reported, because
# the cost of a surprising line going unnoticed is higher than the cost of one
# extra line of output.
OUT_OF_SCOPE: Final = re.compile(
    r"^(?:no )?("
    r"aaa|username|role|enable |privilege|tacacs|radius|"
    r"banner|alias|prompt|terminal|"
    r"boot |service |transceiver|hardware|agent |daemon|platform|"
    r"clock|ntp|dns |ip name-server|ip domain|ip host|"
    r"snmp-server|logging|event-handler|sflow|monitor |archive|"
    # `line console` as well as `line con 0`: the word boundary after `con`
    # rejected the long form, so a console stanza and its body leaked into
    # unparsed_lines on every IOS and NX-OS config that spells it out.
    r"management|line (con(sole)?|vty|aux)|"
    r"crypto|certificate|key |pki|ssl|"
    r"ip (prefix-list|access-list|community-list|as-path)|"
    r"mac access-list|route-map|class-map|policy-map|qos |errdisable|"
    r"lldp|cdp|spanning-tree|queue-monitor|load-interval|"
    r"end|exit"
    r")\b"
)


def is_out_of_scope(line: str) -> bool:
    """True for configuration this tool intentionally does not model."""
    return bool(OUT_OF_SCOPE.match(line.strip()))


def strip_banners(text: str) -> str:
    """Remove banner bodies before stanza parsing.

    Banner text sits at column zero and is arbitrary prose, so a stanza parser
    reads every line of it as a separate top-level command. On a real device
    config that is the single largest source of nonsense.

    A removed line is replaced by an empty one rather than dropped. Every stanza
    after a banner would otherwise sit at a lower number than it does in the
    file, and a citation that points a reader at the wrong line is worse than one
    that points at none.
    """
    out: list[str] = []
    in_banner = False
    for line in text.splitlines():
        if not in_banner and line.strip().startswith("banner "):
            in_banner = True
            out.append("")
            continue
        if in_banner:
            # EOS terminates with a lone EOF; IOS uses a delimiter character.
            if line.strip() in {"EOF", "!", ""} or line.strip().startswith("^"):
                in_banner = False
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


# --------------------------------------------------------------------------
# BGP peerings
# --------------------------------------------------------------------------

# Cisco IOS and NX-OS name a peering's settings with the same words — `remote-as`,
# `description`, `update-source`, `ebgp-multihop` — and differ only in where they
# put them. IOS writes one flat `neighbor <ip> <setting>` line per setting; NX-OS
# indents the same settings under a `neighbor <ip>` block header. That makes the
# setting half genuinely shared and the structural half genuinely not, which is
# where this seam is drawn: the vocabulary lives here, the nesting stays in the
# dialect module.
#
# EOS reads the same way but spells two of these differently (`peer group`,
# `maximum-routes`) and grew its parser first, so it keeps its own copy rather
# than being migrated behind a translation layer that would be longer than the
# duplication.

type BgpPeerSettings = dict[str, str | bool]

# `neighbor <ip> fall-over bfd` on IOS, a bare `bfd` inside the sub-block on
# NX-OS, and the hop-count qualifiers either of them may carry.
_BGP_PEER_BFD: Final = re.compile(
    r"(?:fall-over )?bfd(?: (?:multihop|singlehop|multi-hop|single-hop))?"
)

# Per-neighbour settings that are understood but carry no fact any tier reads
# yet. They are matched rather than ignored because matching them is what keeps
# `unparsed_lines` a list of genuinely unhandled constructs.
_BGP_PEER_UNREAD: Final = re.compile(
    r"(?:activate|additional-paths|advertise-map|advertisement-interval|"
    r"allowas-in|as-override|capability|default-originate|"
    r"disable-connected-check|disable-peer-as-check|distribute-list|"
    r"dont-capability-negotiate|fall-over|filter-list|"
    r"inherit peer-(?:policy|session)|local-as|log-neighbor-changes|"
    r"low-memory|maximum-prefix|maximum-routes|next-hop-self|password|"
    r"prefix-list|remote-private-as|remove-private-as|route-map|"
    r"route-reflector-client|send-community|soft-reconfiguration|"
    r"suppress-inactive|timers|transport|ttl-security|unsuppress-map|"
    r"version|weight)\b.*"
)


def apply_bgp_peer_setting(settings: BgpPeerSettings, setting: str) -> bool:
    """Fold one per-neighbour setting into `settings`; False if unrecognised.

    `setting` is whatever follows `neighbor <ip> ` on IOS, and one line of the
    indented sub-block on NX-OS.

    A setting this understands but does not store still returns True. A peer
    configured only with a password and a route-map is a real peering, and
    losing it would make the reciprocity rule report a one-sided session that
    is not one.
    """
    if m := re.fullmatch(r"remote-as (\S+)", setting):
        settings["remote_as"] = m.group(1)
    elif m := re.fullmatch(r"description (.+)", setting):
        settings["description"] = m.group(1)
    elif m := re.fullmatch(r"update-source (\S+)", setting):
        settings["update_source"] = m.group(1)
    elif re.fullmatch(r"ebgp-multihop(?: \d+)?", setting):
        settings["multihop"] = True
    elif setting == "shutdown":
        settings["shutdown"] = True
    elif setting == "no shutdown":
        settings["shutdown"] = False
    # IOS joins a peer-group by name; NX-OS inherits a peer template. Both name
    # a bag of settings the peer does not restate, resolved by `bgp_neighbors_from`.
    elif m := re.fullmatch(r"(?:peer-group|inherit peer) (\S+)", setting):
        settings["peer_group"] = m.group(1)
    elif _BGP_PEER_BFD.fullmatch(setting):
        settings["bfd"] = True
    elif _BGP_PEER_TIMERS.fullmatch(setting):
        _read_bgp_timers(settings, setting)
    elif _BGP_PEER_UNREAD.fullmatch(setting):
        pass
    else:
        return False
    return True


def register_bgp_peer(
    peers: dict[str, BgpPeerSettings],
    groups: dict[str, BgpPeerSettings],
    token: str,
) -> BgpPeerSettings:
    """The settings `token` names, created if this is the first sight of it.

    An address names a peering; anything else names a peer-group or a peer
    template. Registering on sight rather than once a setting has been
    understood is deliberate — a peering the parser can only half read is still
    a peering, and the reciprocity rule reads the address, not the settings.
    """
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return groups.setdefault(token, {})
    return peers.setdefault(token, {})


def bgp_neighbors_from(
    device: str,
    peers: Mapping[str, BgpPeerSettings],
    groups: Mapping[str, BgpPeerSettings] | None = None,
) -> tuple[BgpNeighbor, ...]:
    """Accumulated settings -> schema records, with peer-groups resolved.

    A peer-group holds what its members do not restate, and `remote-as` is very
    often exactly that, so the group's settings go underneath the member's own
    rather than being dropped — otherwise the AS a config states plainly would
    read as unstated.
    """
    resolved = groups or {}
    out: list[BgpNeighbor] = []
    for address, settings in sorted(peers.items()):
        inherited = settings.get("peer_group")
        merged: BgpPeerSettings = dict(
            resolved.get(inherited, {}) if isinstance(inherited, str) else {}
        )
        merged.update(settings)
        out.append(
            BgpNeighbor(
                device=device,
                address=address,
                remote_as=_text(merged.get("remote_as")),
                description=_text(merged.get("description")),
                update_source=_text(merged.get("update_source")),
                bfd=bool(merged.get("bfd", False)),
                multihop=bool(merged.get("multihop", False)),
                shutdown=bool(merged.get("shutdown", False)),
                peer_group=_text(merged.get("peer_group")),
            )
        )
    return tuple(out)


def _text(value: str | bool | None) -> str | None:
    """Settings are accumulated as `str | bool`; the schema wants only the strings."""
    return value if isinstance(value, str) else None


# --------------------------------------------------------------------------
# BGP timers
#
# All three dialects state the session timers with the same words. The process
# default is `timers bgp <keepalive> <holdtime> [min-holdtime]` and a peering
# overrides it with `timers <keepalive> <holdtime> [min-holdtime]` — flat after
# `neighbor <ip>` on IOS and EOS, indented inside the peer's block on NX-OS.
# Graceful restart differs only in a prefix: IOS writes `bgp graceful-restart
# restart-time 300` where the other two leave the `bgp` off.
#
# The vocabulary is therefore shared even though the nesting is not, which is
# the same seam `apply_bgp_peer_setting` is drawn on.
# --------------------------------------------------------------------------

# The keys an accumulated settings dict uses for the timers it read. Seconds,
# because that is the unit every one of these commands is written in; the
# conversion to the schema's milliseconds happens once, in `bgp_timer_records`.
BGP_KEEPALIVE_KEY: Final = "keepalive_s"
BGP_HOLD_KEY: Final = "hold_s"
BGP_MIN_HOLD_KEY: Final = "min_hold_s"
BGP_RESTART_TIME_KEY: Final = "restart_time_s"
BGP_STALEPATH_TIME_KEY: Final = "stalepath_time_s"

_BGP_TIMER_KEYS: Final = (BGP_KEEPALIVE_KEY, BGP_HOLD_KEY, BGP_MIN_HOLD_KEY)
_BGP_PROCESS_TIMER_KEYS: Final = (
    *_BGP_TIMER_KEYS,
    BGP_RESTART_TIME_KEY,
    BGP_STALEPATH_TIME_KEY,
)

_BGP_PEER_TIMERS: Final = re.compile(r"timers (\d+) (\d+)(?: (\d+))?")


def _read_bgp_timers(settings: BgpPeerSettings, setting: str) -> None:
    """`timers <keepalive> <hold> [min-hold]` -> the three keys, in seconds."""
    m = _BGP_PEER_TIMERS.fullmatch(setting)
    if m is None:
        return
    settings[BGP_KEEPALIVE_KEY] = m.group(1)
    settings[BGP_HOLD_KEY] = m.group(2)
    if m.group(3) is not None:
        settings[BGP_MIN_HOLD_KEY] = m.group(3)


def apply_bgp_process_timer(settings: BgpPeerSettings, line: str) -> bool:
    """Fold one process-wide BGP timer into `settings`; False if it is not one.

    IOS prefixes the graceful-restart timers with `bgp`; EOS and NX-OS do not,
    and all three write `timers bgp <keepalive> <holdtime>` identically. False
    for anything else, so the caller decides what an unread line under `router
    bgp` means — for two dialects that is "already absorbed by the process-level
    filter", and for the third it is "report it".
    """
    if m := re.fullmatch(r"timers bgp (\d+) (\d+)(?: (\d+))?", line):
        settings[BGP_KEEPALIVE_KEY] = m.group(1)
        settings[BGP_HOLD_KEY] = m.group(2)
        if m.group(3) is not None:
            settings[BGP_MIN_HOLD_KEY] = m.group(3)
        return True
    if m := re.fullmatch(r"(?:bgp )?graceful-restart restart-time (\d+)", line):
        settings[BGP_RESTART_TIME_KEY] = m.group(1)
        return True
    if m := re.fullmatch(r"(?:bgp )?graceful-restart stalepath-time (\d+)", line):
        settings[BGP_STALEPATH_TIME_KEY] = m.group(1)
        return True
    return False


def bgp_timer_records(
    *,
    device: DeviceId,
    asn: str,
    process: Mapping[str, str | bool],
    peers: Mapping[str, BgpPeerSettings],
    groups: Mapping[str, BgpPeerSettings] | None = None,
) -> tuple[BgpTimers, ...]:
    """Accumulated BGP settings -> timer records, at both scopes.

    The process record is what `timers bgp` and the graceful-restart timers set
    for every peering. A peering gets its own record when the numbers it runs
    are knowable: either it states them, or the process states them and the
    peering does not — the second case is marked `INHERITED`, so a rule
    comparing two ends of a session can say which end actually wrote the value
    down rather than reporting a disagreement against a number nobody chose.

    A peer-group's timers count as stated. They are written for the peering by
    an operator who chose them for it, and the only thing the peering not
    restating them changes is which line has to be edited — which the evidence
    carries, not the provenance.

    Peerings with nothing stated anywhere get no record at all. A record whose
    every value is `None` says only that the parser ran.
    """
    resolved = groups or {}
    out: list[BgpTimers] = []
    scope = TimerScope(device=device, instance=asn, source=TimerSource.CONFIGURED)

    if any(process.get(key) is not None for key in _BGP_PROCESS_TIMER_KEYS):
        out.append(
            BgpTimers(
                scope=scope,
                keepalive_ms=seconds_to_ms(_text(process.get(BGP_KEEPALIVE_KEY))),
                hold_time_ms=seconds_to_ms(_text(process.get(BGP_HOLD_KEY))),
                min_hold_time_ms=seconds_to_ms(_text(process.get(BGP_MIN_HOLD_KEY))),
                graceful_restart_time_s=_number(process.get(BGP_RESTART_TIME_KEY)),
                stalepath_time_s=_number(process.get(BGP_STALEPATH_TIME_KEY)),
            )
        )

    for address, settings in sorted(peers.items()):
        try:
            ipaddress.ip_address(address)
        except ValueError:
            # A peer-group holds settings for its members rather than running a
            # session of its own, so it is resolved into them and never recorded.
            continue
        inherited = settings.get("peer_group")
        merged: BgpPeerSettings = dict(
            resolved.get(inherited, {}) if isinstance(inherited, str) else {}
        )
        merged.update(settings)
        stated = any(merged.get(key) is not None for key in _BGP_TIMER_KEYS)
        source: Mapping[str, str | bool] = merged if stated else process
        if not any(source.get(key) is not None for key in _BGP_TIMER_KEYS):
            continue
        out.append(
            BgpTimers(
                scope=replace(
                    scope,
                    neighbor=address,
                    source=TimerSource.CONFIGURED if stated else TimerSource.INHERITED,
                ),
                keepalive_ms=seconds_to_ms(_text(source.get(BGP_KEEPALIVE_KEY))),
                hold_time_ms=seconds_to_ms(_text(source.get(BGP_HOLD_KEY))),
                min_hold_time_ms=seconds_to_ms(_text(source.get(BGP_MIN_HOLD_KEY))),
            )
        )
    return tuple(out)


def _number(value: str | bool | None) -> int | None:
    text = _text(value)
    return None if text is None else int(text)


# --------------------------------------------------------------------------
# Spanning tree
#
# Every dialect writes the same three timers and scopes them three ways: for the
# whole device, for a range of VLANs, or for an MST region. The words are shared,
# so the reading is; the units are not, which is the one argument a dialect
# passes in.
# --------------------------------------------------------------------------

STP_MODES: Final[dict[str, StpMode]] = {
    "stp": StpMode.STP,
    "rstp": StpMode.RSTP,
    "pvst": StpMode.PVST,
    "pvst+": StpMode.PVST,
    "rapid-pvst": StpMode.RAPID_PVST,
    "rapid-pvst+": StpMode.RAPID_PVST,
    "mst": StpMode.MST,
    "mstp": StpMode.MST,
    "none": StpMode.NONE,
}

# The three timers, and the field each one fills. `forward-time` is the delay a
# port spends in listening and again in learning, which the schema calls
# `forward_delay_ms` after the standard rather than after the command.
_STP_FIELDS: Final[dict[str, str]] = {
    "hello-time": "hello_time_ms",
    "forward-time": "forward_delay_ms",
    "max-age": "max_age_ms",
}

# The two disjoint ranges a hello time can be written in. IEEE 802.1D-1998
# table 8-3 bounds it to 1-10 seconds, and EOS states the same command in
# milliseconds over the same range. Nothing valid falls in both, which is what
# lets `_stp_ms` read the unit off the number instead of off the dialect.
MIN_STP_HELLO_S: Final = 1
MAX_STP_HELLO_S: Final = 10
MIN_STP_HELLO_MS: Final = 1_000
MAX_STP_HELLO_MS: Final = 10_000

# `spanning-tree vlan 1-100 hello-time 2` on IOS and NX-OS; EOS spells the same
# scope `vlan-id`. Both are accepted everywhere: reading one extra spelling
# costs nothing and mis-scoping a timer to the whole device would be a fact
# stated about VLANs the operator never named.
_STP_VLAN_TIMER: Final = re.compile(
    r"spanning-tree vlan(?:-id)? (\S+) (hello-time|forward-time|max-age) (\d+)"
)
_STP_MST_TIMER: Final = re.compile(
    r"spanning-tree mst (hello-time|forward-time|max-age) (\d+)"
)
_STP_TIMER: Final = re.compile(r"spanning-tree (hello-time|forward-time|max-age) (\d+)")
_STP_MODE: Final = re.compile(r"spanning-tree mode (\S+)")

# What one `spanning-tree` line scopes its timers to: an MST region name, or a
# set of VLAN ids. `(None, ())` is the device-wide line.
type StpKey = tuple[str | None, tuple[VlanId, ...]]


@dataclass(slots=True)
class StpSettings:
    """Every spanning-tree timer one config states, by what it scopes them to.

    Accumulated rather than emitted line by line because the three timers are
    written on three separate lines that mean one set of values, and because a
    per-VLAN line overrides only the timer it names — the rest of that VLAN's
    timing is whatever the device-wide lines said.
    """

    mode: StpMode = StpMode.NONE
    values: dict[StpKey, dict[str, Milliseconds]] = field(default_factory=dict)

    def set(self, key: StpKey, field_name: str, value: Milliseconds) -> None:
        self.values.setdefault(key, {})[field_name] = value


def read_stp_line(settings: StpSettings, line: str) -> bool:
    """Fold one top-level `spanning-tree` line in; False if it states no timer.

    False also for a line that states a timer this cannot read — an unreadable
    VLAN range, or a hello time in neither unit's range. The caller pairs this
    with `states_stp_timer` to tell the two apart, and reports the second, so a
    timer nobody could read reaches `unparsed_lines` rather than the inventory.

    A mode line returns True as well. It states no timer of its own, but it says
    which protocol the timers belong to, and losing it would leave every record
    claiming a mode the device is not running.
    """
    if m := _STP_MODE.fullmatch(line):
        mode = STP_MODES.get(m.group(1))
        if mode is None:
            return False
        settings.mode = mode
        return True
    if m := _STP_VLAN_TIMER.fullmatch(line):
        vlans = vlan_list(m.group(1))
        value = _stp_ms(m.group(2), m.group(3))
        if not vlans or value is None:
            return False
        settings.set((None, vlans), _STP_FIELDS[m.group(2)], value)
        return True
    if m := _STP_MST_TIMER.fullmatch(line):
        value = _stp_ms(m.group(1), m.group(2))
        if value is None:
            return False
        settings.set(("mst", ()), _STP_FIELDS[m.group(1)], value)
        return True
    if m := _STP_TIMER.fullmatch(line):
        value = _stp_ms(m.group(1), m.group(2))
        if value is None:
            return False
        settings.set((None, ()), _STP_FIELDS[m.group(1)], value)
        return True
    return False


def states_stp_timer(line: str) -> bool:
    """True for a `spanning-tree` line naming one of the three timers.

    The separator between "absorbed on purpose" and "dropped by accident". The
    rest of the spanning-tree domain carries no fact any tier reads and is
    filtered wholesale, but a line that names a timer and that `read_stp_line`
    could not read is a timer this parser lost — a VLAN range it could not
    expand, a value it could not parse — and belongs in `unparsed_lines` where
    someone will see it.
    """
    return any(f" {name} " in f"{line} " for name in _STP_FIELDS)


def _stp_ms(name: str, value: str) -> Milliseconds | None:
    """One spanning-tree timer, in milliseconds. None if the unit is unknowable.

    The hello time is the one value the dialects write in different units — EOS
    in milliseconds, IOS and NX-OS in seconds — and this used to be settled by
    asking the dialect. That made the unit a property of which parser ran, and on
    an L2-only switch, which is exactly where spanning-tree timers live, every
    parser explains the file completely and the dialect is decided by a tie-break.
    A coin toss was therefore choosing between 2 seconds and 2 milliseconds.

    It does not have to be asked, because the two ranges do not overlap: 802.1D
    bounds the hello time to 1-10 seconds and EOS accepts the same command as
    1000-10000 milliseconds. A number in one range cannot be a value in the
    other, so it carries its own unit and this reads it rather than trusting the
    caller.

    A number in neither range is not converted to a guess. It is some fourth
    thing — a typo, a platform this tool does not know, a unit nobody here has
    seen — and the house rule for a fact-bearing line a parser cannot be sure
    about is `unparsed_lines`, not the pack. None says so, and `read_stp_line`
    turns it into the False its callers already report.

    Deliberately not applied to the forward delay or the max age. All four
    dialects state both in seconds, so there is no ambiguity to resolve, and
    range-checking them here would reject a value the operator really did
    configure on the strength of a standard the device does not enforce.
    """
    number = int(value)
    if name != "hello-time":
        return number * 1000
    if MIN_STP_HELLO_S <= number <= MAX_STP_HELLO_S:
        return number * 1000
    if MIN_STP_HELLO_MS <= number <= MAX_STP_HELLO_MS:
        return number
    return None


def stp_timer_records(device: DeviceId, settings: StpSettings) -> tuple[StpTimers, ...]:
    """Accumulated spanning-tree settings -> one record per scope they name.

    A scoped record carries the device-wide values it does not override, because
    that is what the VLANs it names actually run: `spanning-tree vlan 1-100
    max-age 20` changes the max age for those VLANs and leaves their hello time
    and forward delay exactly where the device-wide lines put them. A rule
    checking the relationship between the three needs the set that is in effect,
    not the subset one line happened to restate.

    Only scopes with a timer in them are recorded. A device that states a mode
    and no timing has told the inventory nothing to inventory.
    """
    device_wide = settings.values.get((None, ()), {})
    out: list[StpTimers] = []
    for (instance, vlans), values in sorted(
        settings.values.items(), key=lambda item: (item[0][0] or "", item[0][1])
    ):
        merged = (
            {**device_wide, **values} if (instance, vlans) != (None, ()) else values
        )
        if not merged:
            continue
        out.append(
            StpTimers(
                scope=TimerScope(
                    device=device, instance=instance, source=TimerSource.CONFIGURED
                ),
                vlans=vlans,
                mode=settings.mode,
                hello_time_ms=merged.get("hello_time_ms"),
                forward_delay_ms=merged.get("forward_delay_ms"),
                max_age_ms=merged.get("max_age_ms"),
            )
        )
    return tuple(out)
