"""Cisco IOS-XR config text -> Fact Pack.

The fourth dialect, and the one PROJECT.md §5.2 calls *less similar*. That is the
reason to write it: the first three all state a fact roughly where the other two
do, so none of them tested the claim that the parser is the only dialect-aware
component. IOS-XR does.

Three differences carry the weight.

**Addressing is a different word.** `ipv4 address 10.0.0.1 255.255.255.0` under
the interface, not `ip address`. The netmask half is IOS-shaped and the keyword
half is not, so `netmask_to_prefix_length` carries over and the line regex does
not.

**FHRP is somewhere else entirely.** The other three write a group inside the
interface that runs it. IOS-XR writes a top-level `router vrrp` / `router hsrp`
block, and nests `interface <name>` -> `address-family ipv4` -> `vrrp <n>`
underneath it:

    router vrrp
     interface BVI14
      address-family ipv4
       vrrp 14
        priority 110
        preempt delay 30
        address 10.14.0.1

The same fact therefore reaches the pack from the opposite end of the file, and
nothing downstream notices: `FhrpRecord` names the interface it belongs to by
name, and `assemble_fhrp_groups` resolves the subnet from the device's
interfaces afterwards. Which stanza the membership was read out of was never
part of the join.

**Nesting is four levels deep.** `common.stanzas` splits a file once at column
zero and strips what it finds, which cannot represent any of the above.
`common.blocks` splits at the shallowest indentation and hands the bodies back
still indented, so it can be applied to its own output; this module descends
with it and reuses the rest of `common.py` unchanged.

What is deliberately not read is recorded in `unparsed_lines` rather than
dropped, as everywhere else: an IOS-XR construct this parser has no field for is
a visible gap, not a silent one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from cassandra.factpack.builders.common import (
    NO_PREEMPT_KEY,
    BgpPeerSettings,
    Block,
    FhrpRecord,
    ParsedDevice,
    apply_bgp_peer_setting,
    apply_bgp_process_timer,
    bgp_neighbors_from,
    bgp_timer_records,
    blocks,
    fhrp_instance,
    interface_kind,
    ipv6_assignment,
    ipv6_states_no_subnet,
    is_link_local_v6,
    netmask_to_prefix_length,
    preempt_state,
    register_bgp_peer,
    seconds_to_ms,
    strip_banners,
)
from cassandra.factpack.schema import (
    AddressFamily,
    BfdTimers,
    BgpProcess,
    BgpTimers,
    Device,
    DeviceRole,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    IgpHelloTimers,
    IgpProtocol,
    Interface,
    InterfaceKind,
    IpAssignment,
    NosFamily,
    SwitchportMode,
    TimerScope,
    TimerSource,
    TrackedObject,
    TrackedObjectKind,
)

# Decisive markers, in the sense `builders/__init__` means it: a line none of the
# other three dialects can produce.
#
# `router vrrp` and `router hsrp` at column zero exist nowhere else — the other
# three configure FHRP inside the interface. `ipv4 address` is IOS-XR's spelling
# of a line all three siblings write as `ip address`. `Bundle-Ether`, `TenGigE`
# and the rest are IOS-XR interface names; IOS writes `Port-channel` and
# `TenGigabitEthernet`, EOS and NX-OS write `Ethernet` and `port-channel`.
# `BVI` is deliberately absent: IOS-XE has bridge-group virtual interfaces of its
# own by that name, so it is not decisive.
MARKERS: Final = (
    re.compile(r"^!! IOS XR Configuration", re.M),
    re.compile(r"^RP/\d+/\S+/CPU\d+:\S*\s*[#>]", re.M),
    re.compile(r"^router (?:vrrp|hsrp)\s*$", re.M),
    re.compile(r"^\s+ipv4 address \d+\.\d+\.\d+\.\d+", re.M),
    re.compile(
        r"^interface (?:Bundle-Ether|Bundle-POS|TenGigE|TwentyFiveGigE|"
        r"FortyGigE|HundredGigE|FourHundredGigE|MgmtEth)\S*\s*$",
        re.M,
    ),
)

# IOS-XR decrements a tracked group's priority by 10 when the decrement is
# omitted, as its siblings do. Reading a bare `track interface X` as a decrement
# of zero turns real failover into tracking that does nothing, and the tool then
# calls the group stable — a miss, which is the expensive direction to be wrong
# in.
DEFAULT_TRACK_DECREMENT: Final = 10

# Absent `priority`, a group runs at 100 on both protocols.
DEFAULT_PRIORITY: Final = "100"

# Interface names IOS-XR writes that the shared kind table does not key on.
# Ordered longest-distinguishing-prefix first is unnecessary here because no
# entry is a prefix of another.
_XR_KINDS: Final[tuple[tuple[str, InterfaceKind], ...]] = (
    ("Bundle-Ether", InterfaceKind.LAG),
    ("Bundle-POS", InterfaceKind.LAG),
    # A BVI is the routed interface of a bridge domain — structurally what an SVI
    # is on the other three, which is why it is filed the same way. Its number is
    # a bridge-domain id and not a VLAN id, and the two places that read a VLAN
    # out of an SVI name both require the literal `Vlan` prefix, so nothing
    # mistakes one for the other.
    ("BVI", InterfaceKind.SVI),
    ("MgmtEth", InterfaceKind.MANAGEMENT),
    ("TenGigE", InterfaceKind.PHYSICAL),
    ("TwentyFiveGigE", InterfaceKind.PHYSICAL),
    ("FortyGigE", InterfaceKind.PHYSICAL),
    ("HundredGigE", InterfaceKind.PHYSICAL),
    ("FourHundredGigE", InterfaceKind.PHYSICAL),
    ("tunnel-", InterfaceKind.TUNNEL),
)

# Lines that are not configuration at all. A config captured from a terminal
# carries the prompt that asked for it, the timestamp the box printed back, and
# the `commit` / `end` that closed the session. None of them is a stanza, and a
# stanza splitter reads every one of them as a top-level command.
_NOT_CONFIGURATION: Final = re.compile(
    r"(?:!.*|commit(?: .*)?|end|exit|root|configure(?: terminal)?|"
    r"Building configuration\.\.\.|RP/\d+/\S+/CPU\d+:.*|"
    # The timestamp the box prints back before the configuration itself. Anchored
    # to the whole line and to a day-month-date-time-zone shape, so it cannot
    # match a command; no IOS-XR command begins with a weekday.
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \w{3} +\d{1,2} "
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)? \S+)"
)

# Lines carrying no fact any tier reads. Matched rather than ignored so
# `unparsed_lines` stays a list of genuinely unhandled constructs.
_UNINTERESTING: Final = re.compile(
    r"(?:end|exit|commit|!.*|"
    r"(?:no )?(?:shutdown|negotiation auto|proxy-arp|"
    r"cdp|lldp|nsr|log adjacency changes(?: .*)?|"
    r"bandwidth \d+|load-interval \d+|(?:speed|duplex) \S+|"
    r"transceiver .*|"
    r"service-policy .*|flow (?:ipv4|ipv6) monitor .*|"
    r"ipv4 (?:unreachables|redirects|directed-broadcast) disable|"
    r"ipv6 (?:unreachables|redirects) disable|ipv6 nd .*|"
    r"ipv4 access-group .*|ipv6 access-group .*|"
    r"logging events .*|description .*))"
)

# `router bgp` lines that are structure or carry no fact any tier reads yet.
# Separate from the module-wide list because several of these words mean
# something else outside a BGP process.
_BGP_PROCESS: Final = re.compile(
    r"(?:no )?(?:"
    r"address-family \S+ \S+|af-group \S+ address-family \S+ \S+|"
    r"bgp (?:bestpath|cluster-id|log|redistribute-internal|"
    r"graceful-restart.*|scan-time.*|auto-policy-soft-reset.*)\b.*|"
    r"ibgp policy out enforce-modifications|"
    r"maximum-paths .*|nsr|network \S+(?: route-policy \S+)?|"
    r"redistribute .*|socket .*|update .*"
    r")"
)

# Per-neighbour settings IOS-XR spells its own way that carry no fact any tier
# reads yet. The shared vocabulary is `common.apply_bgp_peer_setting`; this is
# only what that list does not already cover.
_BGP_PEER_UNREAD: Final = re.compile(
    r"(?:no )?(?:route-policy .*|graceful-restart.*|egress-engineering|"
    r"ignore-connected-check|ebgp-recv-extcommunity-dmz|"
    r"send-(?:community|extended-community)-ebgp|origin-as .*|"
    r"session-open-mode \S+|address-family \S+ \S+|"
    r"bmp-activate .*|dmz-link-bandwidth|internal-vpn-client)"
)

# Top-level domains this tool does not model, in IOS-XR's spelling, and complete
# rather than a supplement to `common.is_out_of_scope`.
#
# That is deliberate and it is load-bearing for detection, not a style choice.
# When no marker is decisive, `builders.parse` picks the dialect that leaves
# least of the file unexplained, so "explained" has to mean "this dialect could
# have written it". The shared list names domains in the spelling the *other*
# three use — `spanning-tree`, `route-map`, `ip access-list`, `errdisable` —
# several of which IOS-XR does not implement at all. Absorbing them here would
# let this parser claim to understand an EOS or IOS config it had read nothing
# out of, and win a file that is not its own. So the shared entries IOS-XR also
# writes are restated here and the rest are left out, where they are reported
# like any other line this parser does not recognise.
#
# Deliberately conservative in the same direction the shared list is: anything
# not named here is still reported.
_OUT_OF_SCOPE: Final = re.compile(
    r"(?:no )?("
    r"aaa|username|group |tacacs|radius|banner|alias|"
    r"boot |clock|ntp|domain|snmp-server|logging|"
    r"line (con(sole)?|vty|aux)|line template|vty-pool|"
    r"crypto|key |pki|ssh|telnet|xml agent|netconf-yang|grpc|call-home|"
    r"route-policy|prefix-set|community-set|extcommunity-set|as-path-set|"
    r"rd-set|object-group|end-(policy|set|group)|"
    r"ipv4 access-list|ipv6 access-list|ethernet-services access-list|"
    r"class-map|policy-map|sampler-map|flow |"
    r"rsvp|mpls|segment-routing|l2vpn|evpn|bfd|ipsla|"
    r"performance-measurement|multicast-routing|"
    r"vrf |hw-module|lpts|control-plane|http|nv |"
    r"router (isis|ospfv3|rip|static|igmp|pim|mld)"
    r")\b"
)

# The keys a peering's accumulated settings use for the BFD values it stated.
# Milliseconds, because that is the unit `bfd minimum-interval` is written in.
# They sit in the same dict as the rest of a peering's settings so a
# neighbour-group's values are inherited by its members through the merge that
# already resolves `remote-as`.
_BFD_INTERVAL_KEY: Final = "bfd_interval_ms"
_BFD_MULTIPLIER_KEY: Final = "bfd_multiplier"

# What identifies one FHRP group inside a `router vrrp` / `router hsrp` block:
# the interface it runs on, its number, and the address family whose
# `address-family` header it was written under.
type _GroupKey = tuple[str, int, AddressFamily]


@dataclass(slots=True)
class IosXrDevice(ParsedDevice):
    """`ParsedDevice` plus the fact families only some dialects read.

    Same reasoning as `eos.EosDevice`: the shared record carries what every
    dialect produced when it was written, and `builders/__init__` collects the
    rest by attribute, so a dialect that grows a new family declares it here
    rather than widening the base for parsers that never fill it. Spanning tree
    and BGP dampening are absent because this parser reads neither.
    """

    bfd: tuple[BfdTimers, ...] = ()
    igp_hello: tuple[IgpHelloTimers, ...] = ()
    bgp: tuple[BgpProcess, ...] = ()
    bgp_timers: tuple[BgpTimers, ...] = ()


def looks_like_iosxr(text: str) -> bool:
    return any(marker.search(text) for marker in MARKERS)


def strip_session_noise(text: str) -> str:
    """Blank out the lines of a captured session that are not configuration.

    A removed line is replaced by an empty one rather than deleted, for the
    reason `strip_banners` gives: every stanza after it would otherwise sit at a
    lower number than it does in the file, and a citation pointing a reader at
    the wrong line is worse than one pointing at none.

    `!` is the load-bearing case. The other three dialects write it only at
    column zero, where a stanza splitter ignores it as a comment; IOS-XR writes
    one at the indentation of every block it closes, where an indentation-aware
    splitter would read it as a sibling header and cut the block short.
    """
    return "\n".join(
        "" if _NOT_CONFIGURATION.fullmatch(line.strip()) else line
        for line in text.splitlines()
    )


def _iosxr_interface_kind(name: str) -> InterfaceKind:
    """`TenGigE0/0/0/0`, `Bundle-Ether1`, `BVI100`, `GigabitEthernet0/0/0/0.100`.

    A dot in the name is a subinterface on this dialect and on no other one this
    tool parses, so it is decided before the prefix table — `GigabitEthernet0/0/0/0.100`
    is a subinterface, not the physical port it is carved out of.
    """
    if "." in name:
        return InterfaceKind.SUBINTERFACE
    for prefix, kind in _XR_KINDS:
        if name.startswith(prefix):
            return kind
    return interface_kind(name)


def _int_or_none(value: str | None) -> int | None:
    return None if value is None else int(value)


def _timer_ms(unit: str | None, value: str) -> int:
    """`timer msec 250` is milliseconds; `timer 1` is seconds."""
    return int(value) if unit else int(value) * 1000


def _leftovers(block: Block) -> list[str]:
    """A block this parser has no reading for, header and body, minus the noise."""
    lines = [block.header, *(line.strip() for line in block.body)]
    return [line for line in lines if not _UNINTERESTING.fullmatch(line)]


def parse_device(text: str, *, device_id: str | None = None) -> IosXrDevice:
    text = strip_banners(text)
    hostname = device_id or "unknown"
    interfaces: list[Interface] = []
    tracked: list[TrackedObject] = []
    fhrp: list[FhrpRecord] = []
    timers: list[FhrpTimers] = []
    bfd: list[BfdTimers] = []
    igp_hello: list[IgpHelloTimers] = []
    bgp_processes: list[BgpProcess] = []
    bgp_timers: list[BgpTimers] = []
    unparsed: list[str] = []

    for block in blocks(strip_session_noise(text).splitlines()):
        header = block.header

        if m := re.fullmatch(r"hostname (\S+)", header):
            hostname = m.group(1)
            continue

        if m := re.fullmatch(r"interface (\S+)", header):
            iface, leftover = _parse_interface(hostname, m.group(1), block)
            interfaces.append(iface)
            unparsed.extend(leftover)
            continue

        # `track <name>` defines an object the FHRP blocks below reference by
        # name. Read here so `assemble_fhrp_groups` can resolve the reference;
        # an unresolved one is reported as `fhrp-track-undefined`, which would be
        # a false accusation against a config that did define it.
        if m := re.fullmatch(r"track (\S+)", header):
            entry, leftover = _parse_track(hostname, m.group(1), block)
            if entry is not None:
                tracked.append(entry)
            unparsed.extend(leftover)
            continue

        if m := re.fullmatch(r"router (vrrp|hsrp)", header):
            protocol = FhrpProtocol.VRRP if m.group(1) == "vrrp" else FhrpProtocol.HSRP
            records, group_timers, synthetic, leftover = _parse_router_fhrp(
                hostname, protocol, block
            )
            fhrp.extend(records)
            timers.extend(group_timers)
            tracked.extend(synthetic)
            unparsed.extend(leftover)
            continue

        if m := re.fullmatch(r"router ospf (\S+)", header):
            process_igp, process_bfd, leftover = _parse_router_ospf(
                hostname, m.group(1), block
            )
            igp_hello.extend(process_igp)
            bfd.extend(process_bfd)
            unparsed.extend(leftover)
            continue

        if m := re.fullmatch(r"router bgp (\S+)", header):
            process, process_timers, peer_bfd, leftover = _parse_router_bgp(
                hostname, m.group(1), block
            )
            bgp_processes.append(process)
            bgp_timers.extend(process_timers)
            bfd.extend(peer_bfd)
            unparsed.extend(leftover)
            continue

        # An out-of-scope section takes its body with it. Reporting the body of a
        # route-policy or an access list is the same noise as reporting its
        # header, and it is the noise that makes the list unreadable.
        if _OUT_OF_SCOPE.match(header):
            continue
        unparsed.extend(_leftovers(block))

    return IosXrDevice(
        device=Device(
            id=hostname,
            hostname=hostname,
            role=DeviceRole.UNKNOWN,
            nos_family=NosFamily.IOS_XR,
            interfaces=tuple(interfaces),
            config_line_count=len(text.splitlines()),
        ),
        fhrp_records=tuple(fhrp),
        tracked=tuple(tracked),
        timers=tuple(timers),
        unparsed_lines=tuple(unparsed),
        bfd=tuple(bfd),
        igp_hello=tuple(igp_hello),
        bgp=tuple(bgp_processes),
        bgp_timers=tuple(bgp_timers),
    )


# --------------------------------------------------------------------------
# Interfaces
# --------------------------------------------------------------------------


def _parse_interface(
    device: str, name: str, block: Block
) -> tuple[Interface, list[str]]:
    """One `interface <name>` stanza.

    No FHRP is read here — see `_parse_router_fhrp` for where this dialect puts it.
    """
    description: str | None = None
    enabled = True
    mtu: int | None = None
    vrf: str | None = None
    lag_member_of: str | None = None
    dot1q: int | None = None
    addresses: list[IpAssignment] = []
    unparsed: list[str] = []

    for line in (raw.strip() for raw in block.body):
        if m := re.fullmatch(r"description (.+)", line):
            description = m.group(1)
        elif line == "shutdown":
            enabled = False
        elif line == "no shutdown":
            enabled = True
        elif m := re.fullmatch(r"mtu (\d+)", line):
            mtu = int(m.group(1))
        elif m := re.fullmatch(r"vrf (\S+)", line):
            vrf = m.group(1)
        elif m := re.fullmatch(r"bundle id (\d+)(?: mode \S+)?", line):
            lag_member_of = f"Bundle-Ether{m.group(1)}"
        elif m := re.fullmatch(r"encapsulation dot1q (\d+)", line):
            dot1q = int(m.group(1))
        elif m := re.fullmatch(
            r"ipv4 address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)( secondary)?",
            line,
        ):
            length = netmask_to_prefix_length(m.group(2))
            if length is None:
                unparsed.append(line)
            else:
                addresses.append(
                    IpAssignment(
                        address=m.group(1),
                        prefix=f"{m.group(1)}/{length}",
                        family=AddressFamily.IPV4_UNICAST,
                        secondary=bool(m.group(3)),
                    )
                )
        # Newer releases accept the prefix form of the same line.
        elif m := re.fullmatch(r"ipv4 address (\S+?)/(\d+)( secondary)?", line):
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
        kind=_iosxr_interface_kind(name),
        description=description,
        admin_enabled=enabled,
        mtu_bytes=mtu,
        # IOS-XR has no `switchport`: an interface is routed unless it is put
        # into a bridge domain with `l2transport`, which this parser does not
        # read and therefore reports rather than guesses at.
        switchport_mode=SwitchportMode.NONE,
        vrf=vrf,
        addresses=tuple(addresses),
        parent=name.partition(".")[0] if "." in name else None,
        lag_member_of=lag_member_of,
        dot1q_vlan=dot1q,
        config_line=block.line or None,
    )
    return interface, unparsed


# --------------------------------------------------------------------------
# Tracked objects
# --------------------------------------------------------------------------


def _parse_track(
    device: str, name: str, block: Block
) -> tuple[TrackedObject | None, list[str]]:
    """`track <name>`, whose type and target are nested beneath it.

        track uplink-1
         type line-protocol state
          interface TenGigE0/0/0/0

    Returns nothing for a track whose target this cannot name — a route, a BGP
    session, a list of other objects. The reference from the FHRP group is then
    unresolved and reported as such, which is the honest answer: recording an
    object with an empty target would claim the config defines something this
    parser can reason about when it does not.
    """
    target: str | None = None
    unparsed: list[str] = []
    for line in (raw.strip() for raw in block.body):
        if m := re.fullmatch(r"interface (\S+)", line):
            target = m.group(1)
        elif re.fullmatch(r"type (?:line-protocol|interface) state", line):
            continue
        elif not _UNINTERESTING.fullmatch(line):
            unparsed.append(line)
    if target is None:
        return None, [block.header, *unparsed]
    return (
        TrackedObject(
            id=name,
            device=device,
            kind=TrackedObjectKind.INTERFACE,
            target=target,
        ),
        unparsed,
    )


# --------------------------------------------------------------------------
# FHRP
#
# The interesting half of this dialect. `router vrrp` and `router hsrp` are
# top-level blocks that name the interfaces they configure, so a membership
# arrives from the far end of the file from where its interface was declared.
# Nothing downstream cares: `FhrpRecord` names the interface, and the subnet is
# resolved by `assemble_fhrp_groups` once every interface on the device is known.
# --------------------------------------------------------------------------


def _parse_router_fhrp(
    device: str, protocol: FhrpProtocol, block: Block
) -> tuple[list[FhrpRecord], list[FhrpTimers], list[TrackedObject], list[str]]:
    """`router vrrp` / `router hsrp` -> one record and one timer per group."""
    keyword = protocol.value
    settings: dict[_GroupKey, dict[str, str]] = {}
    tracks: dict[_GroupKey, list[tuple[str, int]]] = {}
    lines: dict[_GroupKey, int] = {}
    synthetic: dict[str, TrackedObject] = {}
    unparsed: list[str] = []

    for iface_block in blocks(block.body, block.body_lines):
        interface = re.fullmatch(r"interface (\S+)", iface_block.header)
        if interface is None:
            unparsed.extend(_leftovers(iface_block))
            continue
        name = interface.group(1)

        for af_block in blocks(iface_block.body, iface_block.body_lines):
            family_match = re.fullmatch(
                r"address-family (ipv4|ipv6)(?: unicast)?", af_block.header
            )
            if family_match is None:
                unparsed.extend(_leftovers(af_block))
                continue
            family = (
                AddressFamily.IPV6_UNICAST
                if family_match.group(1) == "ipv6"
                else AddressFamily.IPV4_UNICAST
            )

            for group_block in blocks(af_block.body, af_block.body_lines):
                group = re.fullmatch(
                    rf"{keyword} (\d+)(?: version (\d+))?", group_block.header
                )
                if group is None:
                    unparsed.extend(_leftovers(group_block))
                    continue
                key: _GroupKey = (name, int(group.group(1)), family)
                values = settings.setdefault(key, {})
                lines.setdefault(key, group_block.line)
                if group.group(2) is not None:
                    values["version"] = group.group(2)
                unparsed.extend(
                    _parse_fhrp_group(
                        values,
                        tracks.setdefault(key, []),
                        synthetic,
                        device,
                        group_block.body,
                    )
                )

    records: list[FhrpRecord] = []
    group_timers: list[FhrpTimers] = []
    for key in sorted(settings, key=lambda k: (k[0], k[1], k[2].value)):
        interface_name, number, family = key
        values = settings[key]
        preempt, preempt_source = preempt_state(protocol, values)
        member = FhrpMember(
            device=device,
            interface=interface_name,
            priority=int(values.get("priority", DEFAULT_PRIORITY)),
            preempt=preempt,
            preempt_source=preempt_source,
            tracked_objects=tuple(
                TrackedObject(
                    id=track_id,
                    device=device,
                    kind=TrackedObjectKind.INTERFACE,
                    target="",
                    decrement=decrement,
                )
                for track_id, decrement in tracks.get(key, [])
            ),
            version=_int_or_none(values.get("version")),
            config_line=lines.get(key),
        )
        records.append(
            FhrpRecord(
                number=number,
                protocol=protocol,
                family=family,
                member=member,
                interface=interface_name,
                virtual=values.get("virtual"),
            )
        )
        group_timers.append(
            FhrpTimers(
                scope=TimerScope(
                    device=device,
                    interface=interface_name,
                    instance=fhrp_instance(number, family),
                    source=TimerSource.CONFIGURED,
                ),
                protocol=protocol,
                hello_interval_ms=_int_or_none(values.get("hello_ms")),
                hold_time_ms=_int_or_none(values.get("hold_ms")),
                preempt_delay_ms=seconds_to_ms(values.get("preempt_delay_s")),
            )
        )
    return records, group_timers, list(synthetic.values()), unparsed


def _parse_fhrp_group(
    settings: dict[str, str],
    tracks: list[tuple[str, int]],
    synthetic: dict[str, TrackedObject],
    device: str,
    body: list[str],
) -> list[str]:
    """One `vrrp <n>` / `hsrp <n>` sub-block, into the settings its group runs.

    `track interface <name> <decrement>` names its target inline rather than
    referring to a `track` object defined elsewhere, so the object is
    manufactured here under the interface's own name. That keeps one join —
    membership to tracked object by id — rather than two shapes of tracking for
    the rest of the tool to tell apart.

    An IPv6 group states a link-local virtual address as well as a global one,
    and the global one is kept in preference: every interface is on fe80::/10
    whether anyone configured it or not, so a link-local virtual address is not
    a claim about which segment the group serves.
    """
    unparsed: list[str] = []
    for line in (raw.strip() for raw in body):
        if m := re.fullmatch(r"address (\S+)(?: secondary)?", line):
            held = settings.get("virtual")
            if held is None or (
                is_link_local_v6(held) and not is_link_local_v6(m.group(1))
            ):
                settings["virtual"] = m.group(1)
        elif re.fullmatch(r"address (?:linklocal )?autoconfig", line):
            # Derived from the interface prefix and the group's virtual MAC, so
            # no configuration file states it. The group is real; it simply has
            # no address to check.
            continue
        elif m := re.fullmatch(r"priority (\d+)", line):
            settings["priority"] = m.group(1)
        elif line == "preempt":
            settings["preempt"] = "true"
        elif m := re.fullmatch(r"preempt delay (\d+)", line):
            settings["preempt_delay_s"] = m.group(1)
        elif re.fullmatch(r"preempt disable(?:d)?", line):
            # Recorded, not discarded. The comment that used to sit here said
            # off is what an unstated preempt already reads as — which is exactly
            # backwards for IOS-XR: `router vrrp` preempts by default, so this
            # line is the only thing in the block that turns it off, and throwing
            # it away made a group that does not preempt indistinguishable from
            # every group that does.
            settings[NO_PREEMPT_KEY] = "true"
        elif m := re.fullmatch(r"timer (msec )?(\d+)", line):
            settings["hello_ms"] = str(_timer_ms(m.group(1), m.group(2)))
        elif m := re.fullmatch(r"timers (msec )?(\d+) (msec )?(\d+)", line):
            settings["hello_ms"] = str(_timer_ms(m.group(1), m.group(2)))
            settings["hold_ms"] = str(_timer_ms(m.group(3), m.group(4)))
        elif m := re.fullmatch(r"track interface (\S+)(?: (\d+))?", line):
            target = m.group(1)
            tracks.append((target, _decrement(m.group(2))))
            synthetic.setdefault(
                target,
                TrackedObject(
                    id=target,
                    device=device,
                    kind=TrackedObjectKind.INTERFACE,
                    target=target,
                ),
            )
        elif m := re.fullmatch(r"track object (\S+)(?: (\d+))?", line):
            tracks.append((m.group(1), _decrement(m.group(2))))
        elif re.fullmatch(r"(?:name|text-authentication|authentication) .*", line):
            continue
        elif not _UNINTERESTING.fullmatch(line):
            unparsed.append(line)
    return unparsed


def _decrement(value: str | None) -> int:
    return DEFAULT_TRACK_DECREMENT if value is None else int(value)


# --------------------------------------------------------------------------
# OSPF
# --------------------------------------------------------------------------


def _parse_router_ospf(
    device: str, process: str, block: Block
) -> tuple[list[IgpHelloTimers], list[BfdTimers], list[str]]:
    """`router ospf <n>` -> `area <n>` -> `interface <name>` -> the timers.

    Only the per-interface timers are read. IOS-XR also accepts `hello-interval`
    at the process and the area level, where it sets the value every interface
    below inherits — a real fact, and one this parser deliberately does not
    claim, because recording it would mean writing an interface's timers from a
    line that does not name that interface. Such a line is reported rather than
    dropped, so the gap is visible.
    """
    igp: list[IgpHelloTimers] = []
    bfd: list[BfdTimers] = []
    unparsed: list[str] = []

    for area_block in blocks(block.body, block.body_lines):
        area = re.fullmatch(r"area (\S+)", area_block.header)
        if area is None:
            if not _OSPF_PROCESS.fullmatch(area_block.header):
                unparsed.extend(_leftovers(area_block))
            continue
        for iface_block in blocks(area_block.body, area_block.body_lines):
            interface = re.fullmatch(r"interface (\S+)", iface_block.header)
            if interface is None:
                if not _OSPF_PROCESS.fullmatch(iface_block.header):
                    unparsed.extend(_leftovers(iface_block))
                continue
            name = interface.group(1)
            ospf: dict[str, str] = {}
            bfd_settings: dict[str, str] = {}
            for line in (raw.strip() for raw in iface_block.body):
                if m := re.fullmatch(r"(hello|dead)-interval (\d+)", line):
                    ospf[f"{m.group(1)}_s"] = m.group(2)
                elif m := re.fullmatch(r"bfd minimum-interval (\d+)", line):
                    bfd_settings["tx"] = m.group(1)
                elif m := re.fullmatch(r"bfd multiplier (\d+)", line):
                    bfd_settings["multiplier"] = m.group(1)
                elif re.fullmatch(r"bfd fast-detect(?: .*)?", line):
                    bfd_settings["client"] = "ospf"
                elif not _OSPF_INTERFACE.fullmatch(line) and not (
                    _UNINTERESTING.fullmatch(line)
                ):
                    unparsed.append(line)
            scope = TimerScope(
                device=device, interface=name, source=TimerSource.CONFIGURED
            )
            if ospf:
                igp.append(
                    IgpHelloTimers(
                        scope=scope,
                        protocol=IgpProtocol.OSPFV2,
                        hello_interval_ms=seconds_to_ms(ospf.get("hello_s")),
                        dead_interval_ms=seconds_to_ms(ospf.get("dead_s")),
                        ospf_area=area.group(1),
                    )
                )
            # A session with no interval and no multiplier states no timing, and
            # a record whose every value is None says only that the parser ran.
            if "tx" in bfd_settings or "multiplier" in bfd_settings:
                bfd.append(
                    BfdTimers(
                        scope=scope,
                        desired_min_tx_ms=_int_or_none(bfd_settings.get("tx")),
                        required_min_rx_ms=_int_or_none(bfd_settings.get("tx")),
                        detect_multiplier=_int_or_none(bfd_settings.get("multiplier")),
                        clients=("ospf",) if "client" in bfd_settings else (),
                    )
                )
    return igp, bfd, unparsed


# `router ospf` lines that state no timer this reads. Kept narrow: everything not
# named here is reported.
_OSPF_PROCESS: Final = re.compile(
    r"(?:no )?(?:router-id \S+|log adjacency changes(?: .*)?|nsr|"
    r"address-family \S+ \S+|distribute .*|redistribute .*|"
    r"maximum .*|auto-cost .*|mpls .*|area \S+ .*)"
)
_OSPF_INTERFACE: Final = re.compile(
    r"(?:no )?(?:network \S+|cost \d+|priority \d+|passive (?:enable|disable)|"
    r"mtu-ignore(?: .*)?|authentication .*|message-digest-key .*|"
    r"transmit-delay \d+|retransmit-interval \d+|demand-circuit(?: .*)?)"
)


# --------------------------------------------------------------------------
# BGP
# --------------------------------------------------------------------------


def _parse_router_bgp(
    device: str, asn: str, block: Block
) -> tuple[BgpProcess, tuple[BgpTimers, ...], list[BfdTimers], list[str]]:
    """`router bgp <asn>`, whose peers are sub-blocks as they are on NX-OS.

    The settings inside a peer are the words IOS writes, so they come from
    `common.py`; what is IOS-XR's own is the descent, `use neighbor-group` in
    place of a peer-group name, and BFD stated as `bfd fast-detect` plus its own
    interval and multiplier.
    """
    peers: dict[str, BgpPeerSettings] = {}
    groups: dict[str, BgpPeerSettings] = {}
    process_settings: BgpPeerSettings = {}
    router_id: str | None = None
    bfd: list[BfdTimers] = []
    unparsed: list[str] = []

    for peer_block in blocks(block.body, block.body_lines):
        line = peer_block.header

        if m := re.fullmatch(r"(?:bgp )?router-id (\S+)", line):
            router_id = m.group(1)
        elif apply_bgp_process_timer(process_settings, line):
            # `timers bgp` and the graceful-restart timers are read here rather
            # than left to `_BGP_PROCESS`, which still absorbs the rest of both
            # families — `bgp graceful-restart` on its own turns the capability
            # on and states no duration.
            pass
        elif m := re.fullmatch(r"(?:neighbor|session|af)-group (\S+)", line):
            unparsed.extend(
                _parse_bgp_peer_block(groups.setdefault(m.group(1), {}), peer_block)
            )
        elif m := re.fullmatch(r"neighbor (\S+)", line):
            settings = register_bgp_peer(peers, groups, m.group(1))
            unparsed.extend(_parse_bgp_peer_block(settings, peer_block))
        elif not _BGP_PROCESS.fullmatch(line):
            unparsed.extend(_leftovers(peer_block))

    bfd.extend(_bfd_sessions(device=device, asn=asn, peers=peers, groups=groups))

    process = BgpProcess(
        device=device,
        local_as=asn,
        router_id=router_id,
        neighbors=bgp_neighbors_from(device, peers, groups),
    )
    return (
        process,
        bgp_timer_records(
            device=device,
            asn=asn,
            process=process_settings,
            peers=peers,
            groups=groups,
        ),
        bfd,
        unparsed,
    )


def _bfd_sessions(
    *,
    device: str,
    asn: str,
    peers: dict[str, BgpPeerSettings],
    groups: dict[str, BgpPeerSettings],
) -> list[BfdTimers]:
    """One BFD record per peering whose timing is knowable.

    IOS-XR states BFD inside the peering rather than on the interface, which is
    the only dialect here that does, so the session is scoped by neighbour
    address instead of by interface name. A neighbour-group's values are
    inherited exactly as its other settings are: an operator who wrote
    `bfd minimum-interval 300` once for a group of twenty peers wrote it for all
    twenty, and dropping it would leave twenty sessions claiming no timing.

    A peering with no interval and no multiplier gets no record — a record whose
    every value is None says only that the parser ran.
    """
    out: list[BfdTimers] = []
    for address, settings in sorted(peers.items()):
        inherited = settings.get("peer_group")
        merged: BgpPeerSettings = dict(
            groups.get(inherited, {}) if isinstance(inherited, str) else {}
        )
        merged.update(settings)
        interval = merged.get(_BFD_INTERVAL_KEY)
        multiplier = merged.get(_BFD_MULTIPLIER_KEY)
        if interval is None and multiplier is None:
            continue
        out.append(
            BfdTimers(
                scope=TimerScope(
                    device=device,
                    neighbor=address,
                    instance=asn,
                    source=TimerSource.CONFIGURED,
                ),
                # IOS-XR negotiates one interval in both directions, so the
                # single configured value is both halves rather than a transmit
                # rate with an unstated receive rate beside it.
                desired_min_tx_ms=_int_or_none(_text(interval)),
                required_min_rx_ms=_int_or_none(_text(interval)),
                detect_multiplier=_int_or_none(_text(multiplier)),
                clients=("bgp",) if merged.get("bfd") else (),
            )
        )
    return out


def _text(value: str | bool | None) -> str | None:
    """Settings are accumulated as `str | bool`; the numbers here are the strings."""
    return value if isinstance(value, str) else None


def _parse_bgp_peer_block(settings: BgpPeerSettings, block: Block) -> list[str]:
    """One `neighbor <ip>` or `neighbor-group <name>` sub-block.

    A peer's own settings sit directly inside it and its per-family settings one
    level deeper again, under `address-family <afi> <safi>`. Both levels name the
    same vocabulary, so the family header is structure to descend through rather
    than a fact — nothing this tool reads is per-family yet.
    """
    unparsed: list[str] = []
    for inner in blocks(block.body, block.body_lines):
        line = inner.header
        if re.fullmatch(r"address-family \S+ \S+", line):
            unparsed.extend(_parse_bgp_peer_block(settings, inner))
        elif _apply_iosxr_peer_setting(settings, line):
            unparsed.extend(
                sub.strip()
                for sub in inner.body
                if not _UNINTERESTING.fullmatch(sub.strip())
            )
        else:
            unparsed.extend(_leftovers(inner))
    return unparsed


def _apply_iosxr_peer_setting(settings: BgpPeerSettings, line: str) -> bool:
    """Fold one per-neighbour line in; False if it is not one this understands.

    IOS-XR's own spellings first, then the vocabulary `common.py` already holds
    for IOS and NX-OS. The shared reader is asked last rather than extended,
    because `bfd fast-detect` and `use neighbor-group` are words no other dialect
    writes and teaching the shared list to accept them would change what the
    other parsers make of a line they should still be reporting.
    """
    if re.fullmatch(r"bfd fast-detect(?: .*)?", line):
        settings["bfd"] = True
    elif m := re.fullmatch(r"bfd minimum-interval (\d+)", line):
        settings[_BFD_INTERVAL_KEY] = m.group(1)
    elif m := re.fullmatch(r"bfd multiplier (\d+)", line):
        settings[_BFD_MULTIPLIER_KEY] = m.group(1)
    elif m := re.fullmatch(r"use (?:neighbor|session|af)-group (\S+)", line):
        settings["peer_group"] = m.group(1)
    elif _BGP_PEER_UNREAD.fullmatch(line):
        # Understood and carrying no fact any tier reads yet. Still True: a peer
        # configured only with a route-policy is a real peering, and losing it
        # would make the reciprocity rule report a one-sided session that is not
        # one.
        pass
    else:
        return apply_bgp_peer_setting(settings, line)
    return True
