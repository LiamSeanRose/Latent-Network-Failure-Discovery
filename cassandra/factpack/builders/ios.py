"""Cisco IOS / IOS-XE config text -> Fact Pack.

The dialect the original outage was written in. Differences from EOS that matter:
HSRP is configured with `standby` rather than `vrrp`, addresses are written as an
address plus a netmask rather than a prefix, and tracked objects are numbered.

HSRP and VRRP are modelled as the same shape deliberately. They differ in defaults
and on the wire, but the questions this tool asks — who holds the group, what
decrements the priority, how long preemption waits — have the same answers in both.
Where they diverge, the protocol is on the group and a rule can branch on it.
"""

from __future__ import annotations

import re

from cassandra.factpack.builders.common import (
    ParsedDevice,
    interface_kind,
    netmask_to_prefix_length,
    seconds_to_ms,
    stanzas,
    vlan_list,
)
from cassandra.factpack.schema import (
    AddressFamily,
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
)

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


def looks_like_ios(text: str) -> bool:
    return any(marker.search(text) for marker in MARKERS)


def parse_device(text: str, *, device_id: str | None = None) -> ParsedDevice:
    hostname = device_id or "unknown"
    interfaces: list[Interface] = []
    tracked: list[TrackedObject] = []
    fhrp: list[tuple[int, FhrpProtocol, FhrpMember, str, str | None]] = []
    timers: list[FhrpTimers] = []
    unparsed: list[str] = []

    for stanza in stanzas(text):
        header = stanza.header

        if m := re.fullmatch(r"hostname (\S+)", header):
            hostname = m.group(1)
            continue

        if m := re.fullmatch(r"vlan (\S+)", header):
            vlan_list(m.group(1))
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

        if not _UNINTERESTING.fullmatch(header):
            unparsed.append(header)
        unparsed.extend(
            line for line in stanza.body if not _UNINTERESTING.fullmatch(line)
        )

    return ParsedDevice(
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
    )


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
            if t := re.fullmatch(r"track (\S+) decrement (\d+)", rest):
                group_tracks.setdefault(group, []).append((t.group(1), int(t.group(2))))
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
