"""Cisco NX-OS config text -> Fact Pack.

The third dialect, and so the test PROJECT.md §5.2 asks for: where does the shared
machinery in `common.py` stop paying? VLAN ranges, second-to-millisecond
conversion, interface kinds and `ParsedDevice` all carry over unchanged. The
stanza splitter does not, and that is the seam.

NX-OS nests `hsrp <n>` underneath `interface`, with the group's settings indented
below it:

    interface Vlan14
      ip address 10.14.0.2/24
      hsrp 14
        ip 10.14.0.1
        priority 110
        preempt delay minimum 90

Indentation is structure here rather than decoration, and `common.stanzas` strips
it — after which nothing distinguishes an FHRP `ip 10.14.0.1` from an interface
`ip address 10.14.0.2/24`. This module therefore keeps its own indentation-aware
splitter and reuses everything else.

`router bgp` nests the same way and for the same reason: a peer's settings are
indented under a `neighbor <ip>` header and its per-family settings one level
deeper again. The settings themselves are the words IOS uses, so those come from
`common.py` and only the descent is written here.

Other differences from its siblings: addresses are CIDR as in EOS rather than
netmasks as in IOS, protocols are gated by `feature <name>` lines that carry no
fact this tool reads, and interfaces are `Ethernet1/1`, `Vlan14`, `port-channel1`
— the last in lower case, which the shared kind table does not key on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

from cassandra.factpack.builders.common import (
    BgpPeerSettings,
    FhrpRecord,
    ParsedDevice,
    apply_bgp_peer_setting,
    bgp_neighbors_from,
    declared_vlans_from,
    fhrp_instance,
    interface_kind,
    ipv6_assignment,
    ipv6_states_no_subnet,
    is_out_of_scope,
    register_bgp_peer,
    seconds_to_ms,
    strip_banners,
    unreadable_vlans,
    vlan_list,
)
from cassandra.factpack.schema import (
    AddressFamily,
    BgpProcess,
    Device,
    DeviceRole,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    Interface,
    InterfaceKind,
    IpAssignment,
    NosFamily,
    SwitchportMode,
    TimerScope,
    TimerSource,
    TrackedObject,
    TrackedObjectKind,
    Vlan,
)

# An indented `hsrp <n>` block header is the decisive marker: neither IOS nor EOS
# writes FHRP that way. `feature <name>` and the `9.3(10)` version form are
# NX-OS-only too, and appear in configs that happen to have no FHRP at all.
MARKERS: Final = (
    re.compile(r"^\s+hsrp \d+( ipv6)?\s*$", re.M),
    re.compile(r"^(no )?feature \S+\s*$", re.M),
    re.compile(r"^version \d+\.\d+\(\d+\)", re.M),
)

# Lines carrying no fact this tool reads. Matched so `unparsed_lines` stays
# meaningful: a config buried under `feature` and `!` would hide the constructs
# that are genuinely unhandled.
_UNINTERESTING: Final = re.compile(
    r"^(end|!.*|version .*|(no )?feature .*|boot nxos .*|"
    r"no password strength-check|system default switchport|system jumbomtu \d+|"
    r"(no )?ip domain-lookup|(no )?ip routing|spanning-tree .*|"
    r"router ospf .*|router-id \S+|log-adjacency-changes|passive-interface .*|"
    r"medium \S+|(speed|duplex) \S+|logging event .*|"
    r"\s*ip access-group \S+ (in|out)|\s*ipv6 traffic-filter \S+ (in|out)|"
    r"\s*(ip helper-address|ip dhcp relay address) \S+|"
    r"\s*(no )?ip proxy-arp|\s*(no )?ip redirects|"
    r"no ip(v6)? redirects|ip (router ospf|ospf) .*|"
    r"ipv6 link-local \S+|ipv6 nd .*)$"
)

# NX-OS decrements a tracked group's priority by 10 when `decrement` is omitted.
DEFAULT_TRACK_DECREMENT: Final = 10

# Absent `priority`, an HSRP group runs at 100 — the same default the other two
# dialects carry.
DEFAULT_PRIORITY: Final = "100"

# What identifies one `hsrp` block within an interface. HSRP for IPv6 is a
# separate block with its own settings, so the number alone does not name it.
type _GroupKey = tuple[int, AddressFamily]


# `router bgp` lines that are structure or carry no fact any tier reads yet. Kept
# separate from the module-wide list because several of these words mean
# something else outside a BGP process, and because `bgp dampening` is
# deliberately absent: it is a timer this dialect does not read yet, so it has to
# stay visible in `unparsed_lines` rather than be quietly accepted.
_BGP_PROCESS: Final = re.compile(
    r"(?:no )?(?:"
    r"address-family \S+ \S+|template peer-(?:policy|session) \S+|"
    r"bestpath .*|cluster-id \S+|confederation .*|enforce-first-as|"
    r"event-history .*|fast-external-fallover|graceful-restart.*|"
    r"log-neighbor-changes|maximum-paths.*|network \S+( route-map \S+)?|"
    r"nexthop .*|reconnect-interval \d+|redistribute .*|"
    r"suppress-fib-pending|timers .*"
    r")"
)


@dataclass(slots=True)
class NxosDevice(ParsedDevice):
    """`ParsedDevice` plus the fact families only some dialects read.

    Same reasoning as `eos.EosDevice`: the shared record carries what every
    dialect produced when it was written, and `builders/__init__` collects the
    rest by attribute, so a dialect that grows a new family declares it here
    rather than widening the base for parsers that never fill it.
    """

    bgp: tuple[BgpProcess, ...] = ()


def looks_like_nxos(text: str) -> bool:
    return any(marker.search(text) for marker in MARKERS)


@dataclass(slots=True)
class _Block:
    """A config line plus the lines indented beneath it, indentation intact.

    The difference from `common.Stanza` is that `body` is not stripped, so a block
    can be split again at the next level down. `line` and `body_lines` number
    them as `Stanza` does, and survive that second split.
    """

    header: str
    body: list[str] = field(default_factory=list)
    line: int = 0
    body_lines: list[int] = field(default_factory=list)


def _blocks(lines: list[str], numbers: list[int] | None = None) -> list[_Block]:
    """Split `lines` at their shallowest indentation into headers and bodies.

    `numbers` is where each line sits in the file. A nested split passes the
    enclosing block's `body_lines` so an `hsrp <n>` group four levels into a
    config still knows the line it was written on.
    """
    out: list[_Block] = []
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
        out.append(_Block(header=raw.strip(), line=number))
    return out


def _nxos_interface_kind(name: str) -> InterfaceKind:
    """NX-OS writes three kinds in a form the shared table does not key on."""
    if name.startswith("port-channel"):
        return InterfaceKind.LAG
    if name.startswith("mgmt"):
        return InterfaceKind.MANAGEMENT
    if name.startswith("loopback"):
        return InterfaceKind.LOOPBACK
    return interface_kind(name)


def _timer_ms(unit: str | None, value: str) -> int:
    """`timers msec 250 msec 750` is milliseconds; `timers 1 3` is seconds."""
    return int(value) if unit else int(value) * 1000


def _int_or_none(value: str | None) -> int | None:
    return None if value is None else int(value)


def parse_device(text: str, *, device_id: str | None = None) -> NxosDevice:
    text = strip_banners(text)
    hostname = device_id or "unknown"
    interfaces: list[Interface] = []
    tracked: list[TrackedObject] = []
    fhrp: list[FhrpRecord] = []
    timers: list[FhrpTimers] = []
    unparsed: list[str] = []
    declared_vlans: list[Vlan] = []
    bgp_processes: list[BgpProcess] = []

    for block in _blocks(text.splitlines()):
        header = block.header

        if m := re.fullmatch(r"(?:hostname|switchname) (\S+)", header):
            hostname = m.group(1)
            continue

        if m := re.fullmatch(r"vlan (\S+)", header):
            declared_vlans.extend(declared_vlans_from(hostname, block))
            if rejected := unreadable_vlans(m.group(1)):
                # A declaration this could not read is worse than none: the
                # ports in that VLAN then trip `vlan-not-declared`, blaming the
                # operator for a line they did write.
                unparsed.append(f"{header}  [unreadable: {', '.join(rejected)}]")
            continue

        # `track 1 interface Ethernet1/1 line-protocol`
        if m := re.fullmatch(r"track (\S+) interface (\S+) (\S+)", header):
            tracked.append(
                TrackedObject(
                    id=m.group(1),
                    device=hostname,
                    kind=TrackedObjectKind.INTERFACE,
                    target=m.group(2),
                )
            )
            continue

        if m := re.fullmatch(r"interface (\S+)", header):
            iface, iface_fhrp, iface_timers, leftover = _parse_interface(
                hostname, m.group(1), block
            )
            interfaces.append(iface)
            fhrp.extend(iface_fhrp)
            timers.extend(iface_timers)
            unparsed.extend(leftover)
            continue

        if m := re.fullmatch(r"router bgp (\S+)", header):
            process, bgp_unparsed = _parse_router_bgp(hostname, m.group(1), block.body)
            bgp_processes.append(process)
            unparsed.extend(bgp_unparsed)
            continue

        # An out-of-scope section takes its body with it. Reporting the body
        # of a route-map or a management stanza is the same noise as reporting
        # its header, and it is the noise that makes the list unreadable.
        if is_out_of_scope(header):
            continue
        if not _UNINTERESTING.fullmatch(header):
            unparsed.append(header)
        unparsed.extend(
            line.strip()
            for line in block.body
            if not _UNINTERESTING.fullmatch(line.strip())
        )

    return NxosDevice(
        device=Device(
            id=hostname,
            hostname=hostname,
            role=DeviceRole.UNKNOWN,
            nos_family=NosFamily.NX_OS,
            interfaces=tuple(interfaces),
            config_line_count=len(text.splitlines()),
        ),
        fhrp_records=tuple(fhrp),
        tracked=tuple(tracked),
        timers=tuple(timers),
        unparsed_lines=tuple(unparsed),
        vlans=tuple(declared_vlans),
        bgp=tuple(bgp_processes),
    )


def _bgp_leftovers(lines: list[str]) -> list[str]:
    """The lines of a BGP section this parser has no reading for."""
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not _BGP_PROCESS.fullmatch(line) and not _UNINTERESTING.fullmatch(line):
            out.append(line)
    return out


def _parse_bgp_peer_block(settings: BgpPeerSettings, body: list[str]) -> list[str]:
    """One `neighbor <ip>` or `template peer <name>` sub-block.

    A peer's own settings sit directly inside it and its per-family settings one
    level deeper again, under `address-family <afi> <safi>`. Both levels name the
    same vocabulary, so the family header is structure to descend through rather
    than a fact — nothing this tool reads is per-family yet.
    """
    unparsed: list[str] = []
    for block in _blocks(body):
        line = block.header
        if re.fullmatch(r"address-family \S+ \S+", line):
            unparsed.extend(_parse_bgp_peer_block(settings, block.body))
        elif not apply_bgp_peer_setting(settings, line):
            unparsed.extend(_bgp_leftovers([line, *block.body]))
    return unparsed


def _parse_router_bgp(
    device: str, asn: str, body: list[str]
) -> tuple[BgpProcess, list[str]]:
    """`router bgp <asn>`, whose peers are sub-blocks rather than flat lines.

    The result is the same `BgpProcess` the other two dialects build, which is
    the whole point: only the descent is NX-OS-shaped.

    `neighbor <ip>` may still carry its first setting on the header line, and
    `template peer <name>` is a peer-shaped block holding what its members
    inherit rather than restate, so both go through the same accumulation.
    """
    unparsed: list[str] = []
    peers: dict[str, BgpPeerSettings] = {}
    groups: dict[str, BgpPeerSettings] = {}
    router_id: str | None = None

    for block in _blocks(body):
        line = block.header

        if m := re.fullmatch(r"router-id (\S+)", line):
            router_id = m.group(1)
        elif m := re.fullmatch(r"template peer (\S+)", line):
            unparsed.extend(
                _parse_bgp_peer_block(groups.setdefault(m.group(1), {}), block.body)
            )
        elif m := re.fullmatch(r"neighbor (\S+)(?: (.+))?", line):
            settings = register_bgp_peer(peers, groups, m.group(1))
            if m.group(2) is not None and not apply_bgp_peer_setting(
                settings, m.group(2)
            ):
                # The address is registered either way: an unreadable setting is
                # a gap in this parser, not evidence the peering is not there.
                unparsed.append(line)
            unparsed.extend(_parse_bgp_peer_block(settings, block.body))
        else:
            unparsed.extend(_bgp_leftovers([line, *block.body]))

    process = BgpProcess(
        device=device,
        local_as=asn,
        router_id=router_id,
        neighbors=bgp_neighbors_from(device, peers, groups),
    )
    return process, unparsed


def _parse_hsrp_group(
    body: list[str], settings: dict[str, str], tracks: list[tuple[str, int]]
) -> list[str]:
    """Read one `hsrp <n>` or `hsrp <n> ipv6` sub-block into `settings` and `tracks`.

    The settings are the same set the `standby`/`vrrp` one-liners produce in the
    other dialects, so everything downstream of the parser sees one shape. Which
    family the block configures is on its header, not in here — an IPv6 group's
    virtual address is still written `ip <address>`.
    """
    unparsed: list[str] = []
    for raw in body:
        line = raw.strip()
        if line == "ip autoconfig":
            # The virtual address is derived from the interface's own prefix and
            # the group's virtual MAC, so no configuration file states it. The
            # group is real; it simply has no address to check.
            continue
        if m := re.fullmatch(r"ip (\S+)( secondary)?", line):
            settings.setdefault("virtual", m.group(1))
        elif m := re.fullmatch(
            r"priority (\d+)( forwarding-threshold lower \d+ upper \d+)?", line
        ):
            settings["priority"] = m.group(1)
        elif m := re.fullmatch(
            r"preempt( delay( minimum (\d+))?( reload (\d+))?)?", line
        ):
            settings["preempt"] = "true"
            if m.group(3) is not None:
                settings["preempt_delay_minimum_s"] = m.group(3)
            if m.group(5) is not None:
                settings["preempt_delay_reload_s"] = m.group(5)
        elif m := re.fullmatch(r"timers (msec )?(\d+) (msec )?(\d+)", line):
            settings["hello_ms"] = str(_timer_ms(m.group(1), m.group(2)))
            settings["hold_ms"] = str(_timer_ms(m.group(3), m.group(4)))
        elif m := re.fullmatch(r"track (\S+)( decrement (\d+))?", line):
            decrement = m.group(3)
            tracks.append(
                (
                    m.group(1),
                    DEFAULT_TRACK_DECREMENT if decrement is None else int(decrement),
                )
            )
        elif re.fullmatch(r"(name|authentication|mac-address) .*", line):
            continue
        elif not _UNINTERESTING.fullmatch(line):
            unparsed.append(line)
    return unparsed


def _parse_interface(
    device: str, name: str, stanza: _Block
) -> tuple[Interface, list[FhrpRecord], list[FhrpTimers], list[str]]:
    description: str | None = None
    enabled = True
    mtu: int | None = None
    mode = SwitchportMode.NONE
    access_vlan: int | None = None
    native_vlan: int | None = None
    allowed: tuple[int, ...] = ()
    vrf: str | None = None
    lag_member_of: str | None = None
    version: int | None = None
    addresses: list[IpAssignment] = []
    unparsed: list[str] = []

    # (group number, family) -> accumulated HSRP settings. The family is part of
    # the key because `hsrp 14` and `hsrp 14 ipv6` are two blocks with their own
    # priority, preempt and timers, and they elect independently.
    groups: dict[_GroupKey, dict[str, str]] = {}
    group_tracks: dict[_GroupKey, list[tuple[str, int]]] = {}
    # group -> the line its sub-block opens on, which is where a reader looking
    # for the group should be sent.
    group_lines: dict[_GroupKey, int] = {}

    for block in _blocks(stanza.body, stanza.body_lines):
        line = block.header

        if m := re.fullmatch(r"hsrp (\d+)( ipv6)?", line):
            key: _GroupKey = (
                int(m.group(1)),
                AddressFamily.IPV6_UNICAST
                if m.group(2)
                else AddressFamily.IPV4_UNICAST,
            )
            group_lines.setdefault(key, block.line)
            unparsed.extend(
                _parse_hsrp_group(
                    block.body,
                    groups.setdefault(key, {}),
                    group_tracks.setdefault(key, []),
                )
            )
            continue

        # Only `hsrp <n>` nests. Anything else that does is unhandled structure,
        # and saying so is the whole point of `unparsed_lines`.
        unparsed.extend(
            inner.strip()
            for inner in block.body
            if not _UNINTERESTING.fullmatch(inner.strip())
        )

        if m := re.fullmatch(r"description (.+)", line):
            description = m.group(1)
        elif line == "shutdown":
            enabled = False
        elif line == "no shutdown":
            enabled = True
        elif m := re.fullmatch(r"mtu (\d+)", line):
            mtu = int(m.group(1))
        elif line == "no switchport":
            mode = SwitchportMode.ROUTED
        elif line == "switchport":
            # Bare `switchport` makes the port L2; access is its default mode, and
            # a later `switchport mode trunk` overrides this.
            mode = SwitchportMode.ACCESS
        elif line == "switchport mode trunk":
            mode = SwitchportMode.TRUNK
        elif line == "switchport mode access":
            mode = SwitchportMode.ACCESS
        elif m := re.fullmatch(r"switchport access vlan (\d+)", line):
            access_vlan = int(m.group(1))
        elif m := re.fullmatch(r"switchport trunk native vlan (\d+)", line):
            native_vlan = int(m.group(1))
        elif m := re.fullmatch(r"switchport trunk allowed vlan (\S+)", line):
            allowed = vlan_list(m.group(1))
            if rejected := unreadable_vlans(m.group(1)):
                # The line is reported rather than silently reduced: a trunk
                # missing a VLAN this could not read looks exactly like a trunk
                # the operator forgot, and the next rule blames them for it.
                unparsed.append(f"{line}  [unreadable: {', '.join(rejected)}]")
        elif m := re.fullmatch(r"vrf member (\S+)", line):
            vrf = m.group(1)
        elif m := re.fullmatch(r"channel-group (\d+)( mode (\S+))?", line):
            lag_member_of = f"port-channel{m.group(1)}"
        elif m := re.fullmatch(r"hsrp version (\d+)", line):
            version = int(m.group(1))
        elif m := re.fullmatch(r"ip address (\S+?)/(\d+)( secondary)?", line):
            addresses.append(
                IpAssignment(
                    address=m.group(1),
                    prefix=f"{m.group(1)}/{m.group(2)}",
                    family=AddressFamily.IPV4_UNICAST,
                    secondary=bool(m.group(3)),
                )
            )
        elif m := re.fullmatch(r"ipv6 address (.+)", line):
            if assignment := ipv6_assignment(m.group(1)):
                addresses.append(assignment)
            elif not ipv6_states_no_subnet(m.group(1)):
                unparsed.append(line)
        elif not _UNINTERESTING.fullmatch(line):
            unparsed.append(line)

    interface = Interface(
        device=device,
        name=name,
        kind=_nxos_interface_kind(name),
        description=description,
        admin_enabled=enabled,
        mtu_bytes=mtu,
        switchport_mode=mode,
        access_vlan=access_vlan,
        allowed_vlans=allowed,
        native_vlan=native_vlan,
        vrf=vrf,
        addresses=tuple(addresses),
        lag_member_of=lag_member_of,
        config_line=stanza.line or None,
    )

    members: list[FhrpRecord] = []
    timers: list[FhrpTimers] = []
    for (number, family), settings in sorted(groups.items()):
        member = FhrpMember(
            device=device,
            interface=name,
            priority=int(settings.get("priority", DEFAULT_PRIORITY)),
            preempt=any(key.startswith("preempt") for key in settings),
            tracked_objects=tuple(
                TrackedObject(
                    id=track_id,
                    device=device,
                    kind=TrackedObjectKind.INTERFACE,
                    target="",
                    decrement=decrement,
                )
                for track_id, decrement in group_tracks.get((number, family), [])
            ),
            version=version,
            config_line=group_lines.get((number, family)),
        )
        members.append(
            FhrpRecord(
                number=number,
                protocol=FhrpProtocol.HSRP,
                family=family,
                member=member,
                interface=name,
                virtual=settings.get("virtual"),
            )
        )
        timers.append(
            FhrpTimers(
                scope=TimerScope(
                    device=device,
                    interface=name,
                    instance=fhrp_instance(number, family),
                    source=TimerSource.CONFIGURED,
                ),
                protocol=FhrpProtocol.HSRP,
                hello_interval_ms=_int_or_none(settings.get("hello_ms")),
                hold_time_ms=_int_or_none(settings.get("hold_ms")),
                preempt_delay_ms=seconds_to_ms(settings.get("preempt_delay_minimum_s")),
                preempt_delay_reload_ms=seconds_to_ms(
                    settings.get("preempt_delay_reload_s")
                ),
            )
        )
    return interface, members, timers, unparsed
