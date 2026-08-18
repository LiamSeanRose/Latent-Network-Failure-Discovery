"""Arista EOS config text -> Fact Pack.

Line-oriented and deliberately narrow. The tool needs interfaces, addressing,
VLANs, FHRP, tracking and timers — not RIB computation — so this parses the
constructs the FACTS and TIMING tiers actually read and ignores everything else
rather than failing on it.

Ignoring the rest is a choice with a cost: a construct this does not understand is
invisible, not flagged. `unparsed_lines` on the result exists so that cost is
visible instead of silent, and so a corpus can be checked for constructs worth
adding.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from cassandra.factpack.schema import (
    AddressFamily,
    Device,
    DeviceRole,
    FactPackMeta,
    FhrpGroup,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    Interface,
    InterfaceKind,
    IpAssignment,
    NosFamily,
    StaticFactPack,
    SwitchportMode,
    TimerInventory,
    TimerScope,
    TimerSource,
    TrackedObject,
    TrackedObjectKind,
)

SCHEMA_VERSION: Final = 1

_KINDS: Final = (
    ("Vlan", InterfaceKind.SVI),
    ("Loopback", InterfaceKind.LOOPBACK),
    ("Management", InterfaceKind.MANAGEMENT),
    ("Port-Channel", InterfaceKind.LAG),
    ("Tunnel", InterfaceKind.TUNNEL),
    ("Ethernet", InterfaceKind.PHYSICAL),
)

# Lines that carry no fact this tool reads. Matched to keep `unparsed_lines`
# meaningful — a long list of `end` and `!` would hide the constructs that matter.
_UNINTERESTING: Final = re.compile(
    r"^(end|!.*|no ip routing|ip routing|spanning-tree portfast|"
    r"router ospf .*|\s*(network|router-id|passive-interface|max-lsa) .*|"
    r"\s*ip ospf network .*|\s*description .*|\s*no switchport)$"
)


def interface_kind(name: str) -> InterfaceKind:
    for prefix, kind in _KINDS:
        if name.startswith(prefix):
            return kind
    return InterfaceKind.UNKNOWN


@dataclass(slots=True)
class _Stanza:
    """A top-level config line plus the indented lines beneath it."""

    header: str
    body: list[str] = field(default_factory=list)


def _stanzas(text: str) -> list[_Stanza]:
    out: list[_Stanza] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if raw[0].isspace():
            if out:
                out[-1].body.append(raw.strip())
            continue
        out.append(_Stanza(header=raw.strip()))
    return out


def _vlan_list(spec: str) -> tuple[int, ...]:
    """Expand `14,24,34` and `10-12` into explicit VLAN ids."""
    vlans: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit():
                vlans.extend(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            vlans.append(int(part))
    return tuple(vlans)


@dataclass(slots=True)
class ParsedDevice:
    """One device's facts, plus what the parser could not account for."""

    device: Device
    fhrp: tuple[tuple[int, FhrpProtocol, FhrpMember, str, str | None], ...]
    tracked: tuple[TrackedObject, ...]
    timers: tuple[FhrpTimers, ...]
    unparsed_lines: tuple[str, ...]


def parse_device(text: str, *, device_id: str | None = None) -> ParsedDevice:
    hostname = device_id or "unknown"
    interfaces: list[Interface] = []
    tracked: list[TrackedObject] = []
    fhrp: list[tuple[int, FhrpProtocol, FhrpMember, str, str | None]] = []
    timers: list[FhrpTimers] = []
    unparsed: list[str] = []
    vlans: set[int] = set()

    for stanza in _stanzas(text):
        header = stanza.header

        if m := re.fullmatch(r"hostname (\S+)", header):
            hostname = m.group(1)
            continue

        if m := re.fullmatch(r"vlan (\S+)", header):
            vlans.update(_vlan_list(m.group(1)))
            continue

        # EOS: `track <name> interface <intf> line-protocol`
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
            name = m.group(1)
            iface, iface_fhrp, iface_timers, iface_unparsed = _parse_interface(
                hostname, name, stanza.body
            )
            interfaces.append(iface)
            fhrp.extend(iface_fhrp)
            timers.extend(iface_timers)
            unparsed.extend(iface_unparsed)
            continue

        if not _UNINTERESTING.fullmatch(header):
            unparsed.append(header)
        unparsed.extend(
            line for line in stanza.body if not _UNINTERESTING.fullmatch(line)
        )

    device = Device(
        id=hostname,
        hostname=hostname,
        role=DeviceRole.UNKNOWN,
        nos_family=NosFamily.EOS,
        interfaces=tuple(interfaces),
        config_line_count=len(text.splitlines()),
    )
    return ParsedDevice(
        device=device,
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

    # group -> accumulated VRRP settings
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
            allowed = _vlan_list(m.group(1))
        elif m := re.fullmatch(r"ip address (\S+?)/(\d+)( secondary)?", line):
            addresses.append(
                IpAssignment(
                    address=m.group(1),
                    prefix=f"{m.group(1)}/{m.group(2)}",
                    family=AddressFamily.IPV4_UNICAST,
                    secondary=bool(m.group(3)),
                )
            )
        elif m := re.fullmatch(r"vrrp (\d+) (.+)", line):
            group = int(m.group(1))
            rest = m.group(2)
            settings = groups.setdefault(group, {})
            if t := re.fullmatch(r"tracked-object (\S+) decrement (\d+)", rest):
                group_tracks.setdefault(group, []).append((t.group(1), int(t.group(2))))
            elif t := re.fullmatch(r"ipv4 (\S+)", rest):
                settings["virtual_ipv4"] = t.group(1)
            elif t := re.fullmatch(r"priority-level (\d+)", rest):
                settings["priority"] = t.group(1)
            elif rest == "preempt":
                settings["preempt"] = "true"
            elif t := re.fullmatch(r"preempt delay minimum (\d+)", rest):
                settings["preempt_delay_minimum_s"] = t.group(1)
            elif t := re.fullmatch(r"preempt delay reload (\d+)", rest):
                settings["preempt_delay_reload_s"] = t.group(1)
            elif t := re.fullmatch(r"advertisement interval (\d+)", rest):
                settings["advertisement_interval_s"] = t.group(1)
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
        scope = TimerScope(
            device=device,
            interface=name,
            instance=str(group),
            source=TimerSource.CONFIGURED,
        )
        member = FhrpMember(
            device=device,
            interface=name,
            priority=int(settings.get("priority", "100")),
            preempt="preempt" in settings
            or "preempt_delay_minimum_s" in settings
            or "preempt_delay_reload_s" in settings,
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
            (group, FhrpProtocol.VRRP, member, name, settings.get("virtual_ipv4"))
        )
        timers.append(
            FhrpTimers(
                scope=scope,
                protocol=FhrpProtocol.VRRP,
                hello_interval_ms=_seconds_to_ms(
                    settings.get("advertisement_interval_s")
                ),
                preempt_delay_ms=_seconds_to_ms(
                    settings.get("preempt_delay_minimum_s")
                ),
                preempt_delay_reload_ms=_seconds_to_ms(
                    settings.get("preempt_delay_reload_s")
                ),
            )
        )
    return interface, members, timers, unparsed


def _seconds_to_ms(value: str | None) -> int | None:
    return None if value is None else int(value) * 1000


def build_fact_pack(
    config_dir: Path,
) -> tuple[StaticFactPack, dict[str, tuple[str, ...]]]:
    """Parse every `.cfg` in a directory into one Fact Pack.

    Returns the pack and, per device, the lines the parser did not account for.
    """
    devices: list[Device] = []
    groups: dict[tuple[FhrpProtocol, int], list[FhrpMember]] = {}
    virtuals: dict[tuple[FhrpProtocol, int], str | None] = {}
    fhrp_timers: list[FhrpTimers] = []
    unparsed: dict[str, tuple[str, ...]] = {}
    digest = hashlib.sha256()

    for path in sorted(config_dir.glob("*.cfg")):
        text = path.read_text()
        digest.update(text.encode())
        parsed = parse_device(text, device_id=path.stem)
        devices.append(parsed.device)
        fhrp_timers.extend(parsed.timers)
        unparsed[parsed.device.id] = parsed.unparsed_lines

        # Attach each tracked object's real target, which is defined at top level.
        targets = {t.id: t.target for t in parsed.tracked}
        for number, protocol, member, _interface, virtual in parsed.fhrp:
            resolved = FhrpMember(
                device=member.device,
                interface=member.interface,
                priority=member.priority,
                preempt=member.preempt,
                tracked_objects=tuple(
                    TrackedObject(
                        id=obj.id,
                        device=obj.device,
                        kind=obj.kind,
                        target=targets.get(obj.id, ""),
                        decrement=obj.decrement,
                    )
                    for obj in member.tracked_objects
                ),
            )
            groups.setdefault((protocol, number), []).append(resolved)
            virtuals.setdefault((protocol, number), virtual)

    pack = StaticFactPack(
        meta=FactPackMeta(
            fact_pack_id=f"fp_{digest.hexdigest()[:12]}",
            schema_version=SCHEMA_VERSION,
            config_digest=digest.hexdigest(),
            source_snapshot=str(config_dir),
            generated_at=datetime.now(UTC),
            device_count=len(devices),
        ),
        devices=tuple(devices),
        fhrp_groups=tuple(
            FhrpGroup(
                id=f"{protocol.value}-{number}",
                protocol=protocol,
                group_number=number,
                members=tuple(members),
                virtual_ipv4=virtuals[(protocol, number)],
            )
            for (protocol, number), members in sorted(
                groups.items(), key=lambda kv: (kv[0][0].value, kv[0][1])
            )
        ),
        timers=TimerInventory(fhrp=tuple(fhrp_timers)),
    )
    return pack, unparsed
