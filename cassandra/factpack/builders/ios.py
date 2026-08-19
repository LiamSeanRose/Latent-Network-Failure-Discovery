"""Cisco IOS / IOS-XE config text -> Fact Pack.

The dialect the original outage was written in. Differences from EOS that matter:
HSRP is configured with `standby` rather than `vrrp`, addresses are written as an
address plus a netmask rather than a prefix, and tracked objects are numbered.

HSRP and VRRP are modelled as the same shape deliberately. They differ in defaults
and on the wire, but the questions this tool asks — who holds the group, what
decrements the priority, how long preemption waits — have the same answers in both.
Where they diverge, the protocol is on the group and a rule can branch on it.

BGP peerings read the same way: `router bgp` writes one flat `neighbor <ip>
<setting>` line per setting, so the setting half comes from `common.py` and only
the flat-versus-nested difference lives here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from cassandra.factpack.builders.common import (
    BgpPeerSettings,
    ParsedDevice,
    apply_bgp_peer_setting,
    bgp_neighbors_from,
    declared_vlans_from,
    interface_kind,
    is_out_of_scope,
    netmask_to_prefix_length,
    register_bgp_peer,
    seconds_to_ms,
    stanzas,
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
    IpAssignment,
    NosFamily,
    SwitchportMode,
    TimerScope,
    TimerSource,
    TrackedObject,
    TrackedObjectKind,
    Vlan,
)

# IOS decrements a tracked group's priority by 10 when `decrement` is omitted.
# Reading a bare `standby N track X` as a decrement of zero turns real failover
# into a track that does nothing, and the tool then calls the group stable — a
# miss, which is the expensive direction to be wrong in.
DEFAULT_TRACK_DECREMENT: Final = 10

# `standby` is the giveaway; so is a netmask-form address. Either is enough to
# prefer this dialect over EOS.
MARKERS = (
    re.compile(r"^\s*standby \d+ ", re.M),
    re.compile(r"^\s*ip address \d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+", re.M),
)

_UNINTERESTING = re.compile(
    r"^(end|!.*|version .*|service .*|ip cef|no ip domain.lookup|"
    r"line (con|vty) .*|\s*(login|transport input|exec-timeout|logging|"
    r"negotiation auto|duplex .*|speed .*|no shutdown|description .*|"
    r"delay (up|down) \d+)\s*.*|router ospf .*|\s*network .*|\s*router-id .*|"
    r"\s*passive-interface .*|spanning-tree .*|\s*spanning-tree .*)$"
)


# `router bgp` lines that are structure or carry no fact any tier reads yet. Kept
# separate from the module-wide list because several of these words mean
# something else outside a BGP process — `timers` on an interface is an FHRP
# setting, and `bgp dampening` is a timer this dialect does not read yet and so
# must stay visible in `unparsed_lines`.
_BGP_PROCESS: Final = re.compile(
    r"(?:no )?(?:"
    r"address-family .*|exit-address-family|"
    r"aggregate-address .*|auto-summary|synchronization|"
    r"bgp (?:additional-paths|always-compare-med|bestpath|deterministic-med|"
    r"graceful-restart|listen|log-neighbor-changes|redistribute-internal)\b.*|"
    r"default-information .*|distance bgp .*|maximum-paths .*|"
    r"redistribute .*|timers bgp .*"
    r")"
)


@dataclass(slots=True)
class IosDevice(ParsedDevice):
    """`ParsedDevice` plus the fact families only some dialects read.

    Same reasoning as `eos.EosDevice`: the shared record carries what every
    dialect produced when it was written, and `builders/__init__` collects the
    rest by attribute, so a dialect that grows a new family declares it here
    rather than widening the base for parsers that never fill it.
    """

    bgp: tuple[BgpProcess, ...] = ()


def looks_like_ios(text: str) -> bool:
    return any(marker.search(text) for marker in MARKERS)


def parse_device(text: str, *, device_id: str | None = None) -> IosDevice:
    text = strip_banners(text)
    hostname = device_id or "unknown"
    interfaces: list[Interface] = []
    tracked: list[TrackedObject] = []
    fhrp: list[tuple[int, FhrpProtocol, FhrpMember, str, str | None]] = []
    timers: list[FhrpTimers] = []
    unparsed: list[str] = []
    declared_vlans: list[Vlan] = []
    bgp_processes: list[BgpProcess] = []

    for stanza in stanzas(text):
        header = stanza.header

        if m := re.fullmatch(r"hostname (\S+)", header):
            hostname = m.group(1)
            continue

        if m := re.fullmatch(r"vlan (\S+)", header):
            declared_vlans.extend(declared_vlans_from(hostname, stanza))
            if rejected := unreadable_vlans(m.group(1)):
                # A declaration this could not read is worse than none: the
                # ports in that VLAN then trip `vlan-not-declared`, blaming the
                # operator for a line they did write.
                unparsed.append(f"{header}  [unreadable: {', '.join(rejected)}]")
            continue

        # `track 1 interface GigabitEthernet0/0 line-protocol`
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
                hostname, m.group(1), stanza.body
            )
            interfaces.append(iface)
            fhrp.extend(iface_fhrp)
            timers.extend(iface_timers)
            unparsed.extend(leftover)
            continue

        if m := re.fullmatch(r"router bgp (\S+)", header):
            process, bgp_unparsed = _parse_router_bgp(hostname, m.group(1), stanza.body)
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
            line
            for line in stanza.body
            if not _UNINTERESTING.fullmatch(line) and not is_out_of_scope(line)
        )

    return IosDevice(
        device=Device(
            id=hostname,
            hostname=hostname,
            role=DeviceRole.UNKNOWN,
            nos_family=NosFamily.IOS_XE,
            interfaces=tuple(interfaces),
            config_line_count=len(text.splitlines()),
        ),
        fhrp=tuple(fhrp),
        tracked=tuple(tracked),
        timers=tuple(timers),
        unparsed_lines=tuple(unparsed),
        vlans=tuple(declared_vlans),
        bgp=tuple(bgp_processes),
    )


def _parse_router_bgp(
    device: str, asn: str, body: list[str]
) -> tuple[BgpProcess, list[str]]:
    """`router bgp <asn>` and the peerings it declares.

    Peer settings arrive one flat line at a time, so they accumulate per address
    and the neighbour is assembled at the end — the same shape `eos.py` uses,
    with the setting vocabulary shared from `common.py` instead of restated.

    Two IOS-only wrinkles. `neighbor <name> peer-group` with nothing after it
    *defines* a peer-group rather than configuring a peering, and everything
    subsequently set on that name belongs to the group. And `address-family`
    sections are indented under `router bgp`, which `common.stanzas` has already
    flattened into this body, so their headers are structure to step over rather
    than facts to read.
    """
    unparsed: list[str] = []
    peers: dict[str, BgpPeerSettings] = {}
    groups: dict[str, BgpPeerSettings] = {}
    router_id: str | None = None

    for line in body:
        if m := re.fullmatch(r"(?:bgp )?router-id (\S+)", line):
            router_id = m.group(1)
        elif m := re.fullmatch(r"neighbor (\S+) peer-group", line):
            groups.setdefault(m.group(1), {})
        elif m := re.fullmatch(r"neighbor (\S+)(?: (.+))?", line):
            settings = register_bgp_peer(peers, groups, m.group(1))
            if m.group(2) is not None and not apply_bgp_peer_setting(
                settings, m.group(2)
            ):
                # The address is registered either way: an unreadable setting is
                # a gap in this parser, not evidence the peering is not there.
                unparsed.append(line)
        elif not _BGP_PROCESS.fullmatch(line) and not _UNINTERESTING.fullmatch(line):
            unparsed.append(line)

    process = BgpProcess(
        device=device,
        local_as=asn,
        router_id=router_id,
        neighbors=bgp_neighbors_from(device, peers, groups),
    )
    return process, unparsed


def _parse_interface(
    device: str, name: str, body: list[str]
) -> tuple[
    Interface,
    list[tuple[int, FhrpProtocol, FhrpMember, str, str | None]],
    list[FhrpTimers],
    list[str],
]:
    description: str | None = None
    enabled = True
    mtu: int | None = None
    mode = SwitchportMode.NONE
    access_vlan: int | None = None
    allowed: tuple[int, ...] = ()
    addresses: list[IpAssignment] = []
    unparsed: list[str] = []
    groups: dict[int, dict[str, str]] = {}
    group_tracks: dict[int, list[tuple[str, int]]] = {}

    for line in body:
        if m := re.fullmatch(r"description (.+)", line):
            description = m.group(1)
        elif line == "shutdown":
            enabled = False
        elif m := re.fullmatch(r"mtu (\d+)", line):
            mtu = int(m.group(1))
        elif line == "no switchport":
            mode = SwitchportMode.ROUTED
        elif line == "switchport mode trunk":
            mode = SwitchportMode.TRUNK
        elif line == "switchport mode access":
            mode = SwitchportMode.ACCESS
        elif m := re.fullmatch(r"switchport access vlan (\d+)", line):
            access_vlan = int(m.group(1))
        elif m := re.fullmatch(r"switchport trunk allowed vlan (\S+)", line):
            allowed = vlan_list(m.group(1))
            if rejected := unreadable_vlans(m.group(1)):
                # The line is reported rather than silently reduced: a trunk
                # missing a VLAN this could not read looks exactly like a trunk
                # the operator forgot, and the next rule blames them for it.
                unparsed.append(f"{line}  [unreadable: {', '.join(rejected)}]")
        elif m := re.fullmatch(
            r"ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)( secondary)?", line
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
        elif m := re.fullmatch(r"standby (\d+) (.+)", line):
            group = int(m.group(1))
            rest = m.group(2)
            settings = groups.setdefault(group, {})
            if t := re.fullmatch(r"track (\S+)( decrement (\d+))?", rest):
                decrement = t.group(3)
                group_tracks.setdefault(group, []).append(
                    (
                        t.group(1),
                        DEFAULT_TRACK_DECREMENT
                        if decrement is None
                        else int(decrement),
                    )
                )
            elif t := re.fullmatch(r"ip (\S+)( secondary)?", rest):
                settings.setdefault("virtual_ipv4", t.group(1))
            elif t := re.fullmatch(r"priority (\d+)", rest):
                settings["priority"] = t.group(1)
            elif rest == "preempt":
                settings["preempt"] = "true"
            elif t := re.fullmatch(r"preempt delay minimum (\d+)", rest):
                settings["preempt_delay_minimum_s"] = t.group(1)
            elif t := re.fullmatch(r"preempt delay reload (\d+)", rest):
                settings["preempt_delay_reload_s"] = t.group(1)
            elif t := re.fullmatch(r"timers (\d+) (\d+)", rest):
                settings["hello_s"], settings["hold_s"] = t.group(1), t.group(2)
            elif re.fullmatch(r"(name|authentication|version|mac-address) .*", rest):
                continue
            else:
                unparsed.append(line)
        elif not _UNINTERESTING.fullmatch(line):
            unparsed.append(line)

    interface = Interface(
        device=device,
        name=name,
        kind=interface_kind(name),
        description=description,
        admin_enabled=enabled,
        mtu_bytes=mtu,
        switchport_mode=mode,
        access_vlan=access_vlan,
        allowed_vlans=allowed,
        addresses=tuple(addresses),
    )

    members: list[tuple[int, FhrpProtocol, FhrpMember, str, str | None]] = []
    timers: list[FhrpTimers] = []
    for group, settings in sorted(groups.items()):
        member = FhrpMember(
            device=device,
            interface=name,
            priority=int(settings.get("priority", "100")),
            preempt=any(key.startswith("preempt") for key in settings),
            tracked_objects=tuple(
                TrackedObject(
                    id=track_id,
                    device=device,
                    kind=TrackedObjectKind.INTERFACE,
                    target="",
                    decrement=decrement,
                )
                for track_id, decrement in group_tracks.get(group, [])
            ),
        )
        members.append(
            (group, FhrpProtocol.HSRP, member, name, settings.get("virtual_ipv4"))
        )
        timers.append(
            FhrpTimers(
                scope=TimerScope(
                    device=device,
                    interface=name,
                    instance=str(group),
                    source=TimerSource.CONFIGURED,
                ),
                protocol=FhrpProtocol.HSRP,
                hello_interval_ms=seconds_to_ms(settings.get("hello_s")),
                hold_time_ms=seconds_to_ms(settings.get("hold_s")),
                preempt_delay_ms=seconds_to_ms(settings.get("preempt_delay_minimum_s")),
                preempt_delay_reload_ms=seconds_to_ms(
                    settings.get("preempt_delay_reload_s")
                ),
            )
        )
    return interface, members, timers, unparsed
