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
    Device,
    FhrpGroup,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    Interface,
    InterfaceKind,
    InterfaceName,
    IpAddress,
    IpAssignment,
    TrackedObject,
    Vlan,
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
    stanza declares exactly one id."""
    ids = vlan_list(stanza.header.split(None, 1)[1])
    name = next(
        (
            line.split(None, 1)[1]
            for line in stanza.body
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
    r"management|line (con|vty|aux)|"
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
