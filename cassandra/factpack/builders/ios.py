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
    NO_PREEMPT_KEY,
    BgpPeerSettings,
    FhrpRecord,
    ParsedDevice,
    Stanza,
    StpSettings,
    apply_bgp_peer_setting,
    apply_bgp_process_timer,
    bgp_neighbors_from,
    bgp_timer_records,
    configured_families,
    declared_vlans_from,
    dot1q_vlan,
    fhrp_instance,
    interface_kind,
    ipv6_assignment,
    ipv6_states_no_subnet,
    is_link_local_v6,
    is_out_of_scope,
    netmask_to_prefix_length,
    preempt_state,
    read_stp_line,
    read_stp_priority,
    register_bgp_peer,
    seconds_to_ms,
    stanzas,
    states_stp_timer,
    stp_timer_records,
    strip_banners,
    trunk_allowed_vlans,
    unreadable_vlans,
)
from cassandra.factpack.schema import (
    AddressFamily,
    BgpProcess,
    BgpTimers,
    Device,
    DeviceRole,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    Interface,
    IpAssignment,
    NosFamily,
    StpTimers,
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

# `no vrrp <n> preempt` is deliberately absent from this parser. It is legacy
# VRRPv2 syntax, and this module reads no legacy VRRPv2 group at all — only the
# `vrrp <n> address-family <af>` blocks VRRPv3 writes — so the line names a group
# that never reaches the fact pack. Recording its preemption would put a
# membership's flag in the pack with no membership under it, so the line stays in
# `unparsed_lines`, where it says plainly that a construct was not read.

# `standby` is the giveaway; so is a netmask-form address. Either is enough to
# prefer this dialect over EOS.
MARKERS = (
    re.compile(r"^\s*standby \d+ ", re.M),
    re.compile(r"^\s*ip address \d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+", re.M),
)

_UNINTERESTING = re.compile(
    r"^(end|!.*|version .*|service .*|ip cef|no ip domain.lookup|"
    r"(no )?ipv6 unicast-routing|(no )?ipv6 cef|"
    r"line (con|vty) .*|\s*(login|transport input|exec-timeout|logging|"
    r"negotiation auto|duplex .*|speed .*|no shutdown|description .*|"
    r"delay (up|down) \d+)\s*.*|router ospf .*|\s*network .*|\s*router-id .*|"
    r"\s*passive-interface .*|spanning-tree .*|\s*spanning-tree .*|"
    r"\s*ip access-group \S+ (in|out)|\s*ipv6 traffic-filter \S+ (in|out)|"
    r"\s*(ip helper-address|ip dhcp relay address) \S+|"
    r"\s*(no )?ip proxy-arp|\s*(no )?ip redirects|"
    r"\s*standby version \d+|\s*switchport trunk encapsulation \S+|"
    r"\s*(no )?ipv6 enable|\s*ipv6 nd .*)$"
)


# What identifies one FHRP group configured on an interface. The address family
# is in it because VRRPv3 runs a separate virtual router per family — `vrrp 14
# address-family ipv4` and `vrrp 14 address-family ipv6` are two elections — and
# because HSRP's IPv6 groups derive their own virtual MAC from the same number.
type _GroupKey = tuple[FhrpProtocol, int, AddressFamily]

# The commands that only exist inside a `vrrp <n> address-family <af>` block.
# `common.stanzas` strips indentation, so a sub-mode line arrives looking like an
# interface line; where the config indents the block — `show running-config`
# always does — the indentation decides, and this is the fallback for one that
# does not. `shutdown` and `description` are deliberately absent: both mean
# something at the interface level too, and mistaking an interface `shutdown` for
# a group one would report a live device as isolated.
_VRRP_SUBMODE: Final = re.compile(
    r"(?:no )?(?:address .*|priority \d+|preempt(?: delay minimum \d+)?|"
    r"timers advertise .*|track .*|vrrs .*|match-address)"
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
    bgp_timers: tuple[BgpTimers, ...] = ()
    stp: tuple[StpTimers, ...] = ()


def looks_like_ios(text: str) -> bool:
    return any(marker.search(text) for marker in MARKERS)


def parse_device(text: str, *, device_id: str | None = None) -> IosDevice:
    text = strip_banners(text)
    hostname = device_id or "unknown"
    interfaces: list[Interface] = []
    tracked: list[TrackedObject] = []
    fhrp: list[FhrpRecord] = []
    timers: list[FhrpTimers] = []
    unparsed: list[str] = []
    declared_vlans: list[Vlan] = []
    bgp_processes: list[BgpProcess] = []
    bgp_timers: list[BgpTimers] = []
    stp = StpSettings()

    for stanza in stanzas(text):
        header = stanza.header

        if m := re.fullmatch(r"hostname (\S+)", header):
            hostname = m.group(1)
            continue

        # Spanning tree is otherwise out of scope, and the timers and the
        # bridge priorities are the only parts of it any tier reads. The rest
        # of the domain — port types, the MST region and its body — is absorbed
        # here rather than reported, exactly as it was when the whole domain was
        # filtered.
        if header.startswith("spanning-tree "):
            read_stp_priority(stp, header)
            if not read_stp_line(stp, header) and states_stp_timer(header):
                # A line naming a timer this could not read is a timer the fact
                # pack has lost, not one it chose not to keep.
                unparsed.append(header)
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
                hostname, m.group(1), stanza
            )
            interfaces.append(iface)
            fhrp.extend(iface_fhrp)
            timers.extend(iface_timers)
            unparsed.extend(leftover)
            continue

        if m := re.fullmatch(r"router bgp (\S+)", header):
            process, process_timers, bgp_unparsed = _parse_router_bgp(
                hostname, m.group(1), stanza.body
            )
            bgp_processes.append(process)
            bgp_timers.extend(process_timers)
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
        fhrp_records=tuple(fhrp),
        tracked=tuple(tracked),
        timers=tuple(timers),
        unparsed_lines=tuple(unparsed),
        vlans=tuple(declared_vlans),
        bgp=tuple(bgp_processes),
        bgp_timers=tuple(bgp_timers),
        stp=stp_timer_records(hostname, stp),
        stp_priorities=tuple(sorted(stp.priorities.items())),
        stp_priorities_complete=not stp.priority_unreadable,
        stp_mode=stp.mode,
    )


def _parse_router_bgp(
    device: str, asn: str, body: list[str]
) -> tuple[BgpProcess, tuple[BgpTimers, ...], list[str]]:
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
    process_settings: BgpPeerSettings = {}
    router_id: str | None = None

    for line in body:
        if m := re.fullmatch(r"(?:bgp )?router-id (\S+)", line):
            router_id = m.group(1)
        elif apply_bgp_process_timer(process_settings, line):
            # `timers bgp` and the graceful-restart timers are read here rather
            # than left to `_BGP_PROCESS`, which still absorbs the rest of both
            # families — `bgp graceful-restart` on its own turns the capability
            # on and states no duration.
            pass
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
    return (
        process,
        bgp_timer_records(
            device=device,
            asn=asn,
            process=process_settings,
            peers=peers,
            groups=groups,
        ),
        unparsed,
    )


def _parse_interface(
    device: str, name: str, stanza: Stanza
) -> tuple[Interface, list[FhrpRecord], list[FhrpTimers], list[str]]:
    description: str | None = None
    enabled = True
    mtu: int | None = None
    mode = SwitchportMode.NONE
    access_vlan: int | None = None
    allowed: tuple[int, ...] = ()
    allowed_stated = False
    tagged: int | None = None
    addresses: list[IpAssignment] = []
    unparsed: list[str] = []

    # HSRP accumulates per group number rather than per family: `standby 14 ip`
    # and `standby 14 ipv6` are one block of settings serving two virtual
    # addresses, and which families it ended up naming is only known once every
    # line has been read. VRRPv3 states the family on the block header and gives
    # each one its own priority, preempt and timers, so it accumulates per group.
    standby: dict[int, dict[str, str]] = {}
    standby_tracks: dict[int, list[tuple[str, int]]] = {}
    # group -> the first line that configures it, which is where a reader looking
    # for the group should be sent. The later lines are the same group.
    standby_lines: dict[int, int] = {}
    vrrp: dict[_GroupKey, dict[str, str]] = {}
    vrrp_tracks: dict[_GroupKey, list[tuple[str, int]]] = {}
    vrrp_lines: dict[_GroupKey, int] = {}

    # The `vrrp <n> address-family <af>` block currently open, and the column its
    # header started in.
    open_group: _GroupKey | None = None
    open_indent = 0

    for number, indent, line in zip(
        stanza.body_lines, stanza.body_indents, stanza.body, strict=True
    ):
        if m := re.fullmatch(r"vrrp (\d+) address-family (ipv4|ipv6)", line):
            open_group = (
                FhrpProtocol.VRRP,
                int(m.group(1)),
                AddressFamily.IPV6_UNICAST
                if m.group(2) == "ipv6"
                else AddressFamily.IPV4_UNICAST,
            )
            open_indent = indent
            vrrp.setdefault(open_group, {})
            vrrp_tracks.setdefault(open_group, [])
            vrrp_lines.setdefault(open_group, number)
            continue
        if open_group is not None and (
            indent > open_indent or _VRRP_SUBMODE.fullmatch(line)
        ):
            if not _vrrp_setting(vrrp[open_group], vrrp_tracks[open_group], line):
                unparsed.append(line)
            continue
        open_group = None

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
        elif (vlan := dot1q_vlan(line)) is not None:
            tagged = vlan
        elif line == "switchport mode access":
            mode = SwitchportMode.ACCESS
        elif m := re.fullmatch(r"switchport access vlan (\d+)", line):
            access_vlan = int(m.group(1))
        elif m := re.fullmatch(r"switchport trunk allowed vlan (.+)", line):
            update = trunk_allowed_vlans(allowed, m.group(1))
            if update is None:
                # A form this cannot read must not reduce the trunk to nothing:
                # an empty allowed list is what `access-vlan-not-trunked` reports
                # HIGH, so a guess here becomes an accusation there.
                unparsed.append(line)
            else:
                allowed = update.vlans
                # Stated, even when it states nothing: `allowed vlan none` is a
                # decision and an unread line is not.
                allowed_stated = True
                if update.unreadable:
                    # The line is reported rather than silently reduced: a trunk
                    # missing a VLAN this could not read looks exactly like a
                    # trunk the operator forgot, and the next rule blames them.
                    unparsed.append(
                        f"{line}  [unreadable: {', '.join(update.unreadable)}]"
                    )
        elif m := re.fullmatch(
            r"ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)( secondary)?",
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
        elif m := re.fullmatch(r"ipv6 address (.+)", line):
            if assignment := ipv6_assignment(m.group(1)):
                addresses.append(assignment)
            elif not ipv6_states_no_subnet(m.group(1)):
                unparsed.append(line)
        elif m := re.fullmatch(r"no standby (\d+) preempt", line):
            # HSRP defaults preemption off, so this line usually restates the
            # default — but it is a decision somebody wrote down, and the fact
            # pack now separates the two. It used to reach `unparsed_lines`.
            group = int(m.group(1))
            standby.setdefault(group, {})[NO_PREEMPT_KEY] = "true"
            standby_lines.setdefault(group, number)
        elif m := re.fullmatch(r"standby (\d+) (.+)", line):
            group = int(m.group(1))
            settings = standby.setdefault(group, {})
            standby_lines.setdefault(group, number)
            if not _standby_setting(
                settings, standby_tracks.setdefault(group, []), m.group(2)
            ):
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
        trunk_allowed_stated=allowed_stated,
        dot1q_vlan=tagged,
        addresses=tuple(addresses),
        config_line=stanza.line or None,
    )

    members: list[FhrpRecord] = []
    timers: list[FhrpTimers] = []
    for group, settings in sorted(standby.items()):
        for family, virtual in configured_families(settings):
            record, timer = _group_facts(
                device=device,
                interface=name,
                protocol=FhrpProtocol.HSRP,
                number=group,
                family=family,
                settings=settings,
                tracks=standby_tracks.get(group, []),
                config_line=standby_lines.get(group),
                virtual=virtual,
            )
            members.append(record)
            timers.append(timer)
    for (protocol, group, family), settings in sorted(
        vrrp.items(), key=lambda item: (item[0][1], item[0][2].value)
    ):
        record, timer = _group_facts(
            device=device,
            interface=name,
            protocol=protocol,
            number=group,
            family=family,
            settings=settings,
            tracks=vrrp_tracks.get((protocol, group, family), []),
            config_line=vrrp_lines.get((protocol, group, family)),
            virtual=settings.get("virtual"),
        )
        members.append(record)
        timers.append(timer)
    return interface, members, timers, unparsed


def _standby_setting(
    settings: dict[str, str], tracks: list[tuple[str, int]], rest: str
) -> bool:
    """Fold one `standby <n> ...` setting into `settings`; False if unrecognised.

    `ipv6` is a second virtual address on the same group rather than a second
    group's worth of settings — priority, preempt and timers are stated once —
    so it is recorded beside the IPv4 one and `configured_families` splits the
    two out. `ipv6 autoconfig` names the family with no address: the virtual
    address is derived from the interface prefix and the group's virtual MAC, so
    it is marked as configured rather than dropped.
    """
    if m := re.fullmatch(r"track (\S+)( decrement (\d+))?", rest):
        decrement = m.group(3)
        tracks.append(
            (
                m.group(1),
                DEFAULT_TRACK_DECREMENT if decrement is None else int(decrement),
            )
        )
    elif m := re.fullmatch(r"ip (\S+)( secondary)?", rest):
        settings.setdefault("virtual_ipv4", m.group(1))
    elif rest == "ipv6 autoconfig":
        settings["ipv6"] = "true"
    elif m := re.fullmatch(r"ipv6 (\S+)", rest):
        settings.setdefault("virtual_ipv6", m.group(1))
    elif m := re.fullmatch(r"priority (\d+)", rest):
        settings["priority"] = m.group(1)
    elif rest == "preempt":
        settings["preempt"] = "true"
    elif m := re.fullmatch(r"preempt delay minimum (\d+)", rest):
        settings["preempt_delay_minimum_s"] = m.group(1)
    elif m := re.fullmatch(r"preempt delay reload (\d+)", rest):
        settings["preempt_delay_reload_s"] = m.group(1)
    elif m := re.fullmatch(r"timers (\d+) (\d+)", rest):
        settings["hello_s"], settings["hold_s"] = m.group(1), m.group(2)
    elif not re.fullmatch(r"(name|authentication|version|mac-address) .*", rest):
        return False
    return True


def _vrrp_setting(
    settings: dict[str, str], tracks: list[tuple[str, int]], line: str
) -> bool:
    """Fold one line of a `vrrp <n> address-family <af>` block in; False if unread.

    An IPv6 group states two addresses: a link-local one, which RFC 5798 makes
    the primary because that is what hosts point their default route at, and
    usually a global one as well. The global one is kept in preference because
    it is the one that can be checked against the subnet the interface is on —
    every interface is on fe80::/10 whether anyone configured it or not, so a
    link-local virtual address is not a claim about which segment the group
    serves.
    """
    if m := re.fullmatch(r"address (\S+)( primary| secondary)?", line):
        held = settings.get("virtual")
        if held is None or (
            is_link_local_v6(held) and not is_link_local_v6(m.group(1))
        ):
            settings["virtual"] = m.group(1)
    elif m := re.fullmatch(r"priority (\d+)", line):
        settings["priority"] = m.group(1)
    elif line == "preempt":
        settings["preempt"] = "true"
    elif line == "no preempt":
        # This was matched and thrown away, which read as "understood, nothing to
        # record" and meant the opposite: VRRPv3 preempts by default, so this is
        # the only line in the block that changes anything about preemption, and
        # discarding it left the group indistinguishable from one that never
        # mentioned it — a group that does preempt.
        settings[NO_PREEMPT_KEY] = "true"
    elif m := re.fullmatch(r"preempt delay minimum (\d+)", line):
        settings["preempt_delay_minimum_s"] = m.group(1)
    elif m := re.fullmatch(r"timers advertise (\d+)", line):
        settings["hello_s"] = m.group(1)
    elif m := re.fullmatch(r"track (\S+) decrement (\d+)", line):
        tracks.append((m.group(1), int(m.group(2))))
    elif m := re.fullmatch(r"track (\S+)( shutdown)?", line):
        tracks.append((m.group(1), DEFAULT_TRACK_DECREMENT))
    elif not re.fullmatch(r"(vrrs .*|match-address)", line):
        return False
    return True


def _group_facts(
    *,
    device: str,
    interface: str,
    protocol: FhrpProtocol,
    number: int,
    family: AddressFamily,
    settings: dict[str, str],
    tracks: list[tuple[str, int]],
    config_line: int | None,
    virtual: str | None,
) -> tuple[FhrpRecord, FhrpTimers]:
    """One group's membership record and its timer record, from its settings."""
    preempt, preempt_source = preempt_state(protocol, settings)
    member = FhrpMember(
        device=device,
        interface=interface,
        priority=int(settings.get("priority", "100")),
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
            for track_id, decrement in tracks
        ),
        config_line=config_line,
    )
    record = FhrpRecord(
        number=number,
        protocol=protocol,
        family=family,
        member=member,
        interface=interface,
        virtual=virtual,
    )
    timer = FhrpTimers(
        scope=TimerScope(
            device=device,
            interface=interface,
            instance=fhrp_instance(number, family),
            source=TimerSource.CONFIGURED,
        ),
        protocol=protocol,
        hello_interval_ms=seconds_to_ms(settings.get("hello_s")),
        hold_time_ms=seconds_to_ms(settings.get("hold_s")),
        preempt_delay_ms=seconds_to_ms(settings.get("preempt_delay_minimum_s")),
        preempt_delay_reload_ms=seconds_to_ms(settings.get("preempt_delay_reload_s")),
    )
    return record, timer
