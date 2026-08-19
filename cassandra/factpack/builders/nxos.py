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
    ParsedDevice,
    declared_vlans_from,
    interface_kind,
    is_out_of_scope,
    seconds_to_ms,
    strip_banners,
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
    re.compile(r"^\s+hsrp \d+\s*$", re.M),
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
    r"no ip(v6)? redirects|ip (router ospf|ospf) .*)$"
)

# NX-OS decrements a tracked group's priority by 10 when `decrement` is omitted.
DEFAULT_TRACK_DECREMENT: Final = 10

# Absent `priority`, an HSRP group runs at 100 — the same default the other two
# dialects carry.
DEFAULT_PRIORITY: Final = "100"


def looks_like_nxos(text: str) -> bool:
    return any(marker.search(text) for marker in MARKERS)


@dataclass(slots=True)
class _Block:
    """A config line plus the lines indented beneath it, indentation intact.

    The difference from `common.Stanza` is that `body` is not stripped, so a block
    can be split again at the next level down.
    """

    header: str
    body: list[str] = field(default_factory=list)


def _blocks(lines: list[str]) -> list[_Block]:
    """Split `lines` at their shallowest indentation into headers and bodies."""
    out: list[_Block] = []
    base: int | None = None
    for raw in lines:
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        if base is None:
            base = indent
        if indent > base and out:
            out[-1].body.append(raw)
            continue
        out.append(_Block(header=raw.strip()))
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


def parse_device(text: str, *, device_id: str | None = None) -> ParsedDevice:
    text = strip_banners(text)
    hostname = device_id or "unknown"
    interfaces: list[Interface] = []
    tracked: list[TrackedObject] = []
    fhrp: list[tuple[int, FhrpProtocol, FhrpMember, str, str | None]] = []
    timers: list[FhrpTimers] = []
    unparsed: list[str] = []
    declared_vlans: list[Vlan] = []

    for block in _blocks(text.splitlines()):
        header = block.header

        if m := re.fullmatch(r"(?:hostname|switchname) (\S+)", header):
            hostname = m.group(1)
            continue

        if m := re.fullmatch(r"vlan (\S+)", header):
            declared_vlans.extend(declared_vlans_from(hostname, block))
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
                hostname, m.group(1), block.body
            )
            interfaces.append(iface)
            fhrp.extend(iface_fhrp)
            timers.extend(iface_timers)
            unparsed.extend(leftover)
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

    return ParsedDevice(
        device=Device(
            id=hostname,
            hostname=hostname,
            role=DeviceRole.UNKNOWN,
            nos_family=NosFamily.NX_OS,
            interfaces=tuple(interfaces),
            config_line_count=len(text.splitlines()),
        ),
        fhrp=tuple(fhrp),
        tracked=tuple(tracked),
        timers=tuple(timers),
        unparsed_lines=tuple(unparsed),
        vlans=tuple(declared_vlans),
    )


def _parse_hsrp_group(
    body: list[str], settings: dict[str, str], tracks: list[tuple[str, int]]
) -> list[str]:
    """Read one `hsrp <n>` sub-block into `settings` and `tracks`.

    The settings are the same set the `standby`/`vrrp` one-liners produce in the
    other dialects, so everything downstream of the parser sees one shape.
    """
    unparsed: list[str] = []
    for raw in body:
        line = raw.strip()
        if m := re.fullmatch(r"ip (\S+)( secondary)?", line):
            settings.setdefault("virtual_ipv4", m.group(1))
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
    native_vlan: int | None = None
    allowed: tuple[int, ...] = ()
    vrf: str | None = None
    lag_member_of: str | None = None
    version: int | None = None
    addresses: list[IpAssignment] = []
    unparsed: list[str] = []

    # group -> accumulated HSRP settings
    groups: dict[int, dict[str, str]] = {}
    group_tracks: dict[int, list[tuple[str, int]]] = {}

    for block in _blocks(body):
        line = block.header

        if m := re.fullmatch(r"hsrp (\d+)", line):
            group = int(m.group(1))
            unparsed.extend(
                _parse_hsrp_group(
                    block.body,
                    groups.setdefault(group, {}),
                    group_tracks.setdefault(group, []),
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
    )

    members: list[tuple[int, FhrpProtocol, FhrpMember, str, str | None]] = []
    timers: list[FhrpTimers] = []
    for group, settings in sorted(groups.items()):
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
                for track_id, decrement in group_tracks.get(group, [])
            ),
            version=version,
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
                hello_interval_ms=_int_or_none(settings.get("hello_ms")),
                hold_time_ms=_int_or_none(settings.get("hold_ms")),
                preempt_delay_ms=seconds_to_ms(settings.get("preempt_delay_minimum_s")),
                preempt_delay_reload_ms=seconds_to_ms(
                    settings.get("preempt_delay_reload_s")
                ),
            )
        )
    return interface, members, timers, unparsed
