"""Config text -> Fact Pack, dialect chosen automatically.

The user should not have to tell the tool what wrote their configs. Detection
tries the dialect whose markers appear, then falls back to whichever parser
accounts for more of the file — a parser that leaves half a config unexplained is
the wrong parser, and that is measurable rather than a guess.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Final

from cassandra.factpack import topology
from cassandra.factpack.builders import eos, ios, nxos
from cassandra.factpack.builders.common import ParsedDevice
from cassandra.factpack.schema import (
    BfdTimers,
    BgpProcess,
    DampeningProfile,
    Device,
    FactPackMeta,
    FhrpGroup,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    IgpHelloTimers,
    Interface,
    StaticFactPack,
    TimerInventory,
    TrackedObject,
    Vlan,
)

SCHEMA_VERSION: Final = 1
DIALECTS: Final[tuple[ModuleType, ...]] = (ios, eos, nxos)


def parse(text: str, *, device_id: str | None = None) -> ParsedDevice:
    """Parse with the best-fitting dialect."""
    # NX-OS is checked first: its `hsrp <n>` block is distinctive, whereas an
    # NX-OS config could otherwise be mistaken for EOS on addressing alone.
    if nxos.looks_like_nxos(text):
        return nxos.parse_device(text, device_id=device_id)
    if ios.looks_like_ios(text):
        return ios.parse_device(text, device_id=device_id)

    # No decisive marker: run both and keep whichever explains more of the file.
    candidates = [module.parse_device(text, device_id=device_id) for module in DIALECTS]
    return min(candidates, key=lambda parsed: len(parsed.unparsed_lines))


def build_fact_pack(
    config_dir: Path,
) -> tuple[StaticFactPack, dict[str, tuple[str, ...]]]:
    """Parse every `.cfg` in a directory into one Fact Pack.

    Returns the pack and, per device, the lines no parser accounted for.
    """
    devices: list[Device] = []
    # Keyed by subnet as well as number. An FHRP group number is scoped to its
    # segment: VRRP 1 on 10.10.0.0/24 and VRRP 1 on 10.20.0.0/24 are different
    # groups, and merging them loses one virtual address and invents members,
    # which produced false "virtual address outside its own subnet" findings on
    # entirely valid configuration.
    GroupKey = tuple[FhrpProtocol, int, str]
    groups: dict[GroupKey, list[FhrpMember]] = {}
    virtuals: dict[GroupKey, str | None] = {}
    fhrp_timers: list[FhrpTimers] = []
    # Dialects that parse them attach these; IOS and NX-OS return the base
    # ParsedDevice without them, hence getattr with a default below.
    bfd_timers: list[BfdTimers] = []
    igp_timers: list[IgpHelloTimers] = []
    dampening: list[DampeningProfile] = []
    vlans: list[Vlan] = []
    bgp: list[BgpProcess] = []
    unparsed: dict[str, tuple[str, ...]] = {}
    digest = hashlib.sha256()

    for path in sorted(config_dir.glob("*.cfg")):
        text = path.read_text()
        digest.update(text.encode())
        parsed = parse(text, device_id=path.stem)
        devices.append(parsed.device)
        fhrp_timers.extend(parsed.timers)
        bfd_timers.extend(getattr(parsed, "bfd", ()))
        igp_timers.extend(getattr(parsed, "igp_hello", ()))
        dampening.extend(getattr(parsed, "dampening", ()))
        vlans.extend(parsed.vlans)
        bgp.extend(getattr(parsed, "bgp", ()))
        unparsed[parsed.device.id] = parsed.unparsed_lines

        # Tracked objects are defined at top level; join them to the groups that
        # reference them, or a decrement has nothing to watch.
        targets = {tracked.id: tracked.target for tracked in parsed.tracked}
        subnets = {
            interface.name: _first_network(interface)
            for interface in parsed.device.interfaces
        }
        for number, protocol, member, interface_name, virtual in parsed.fhrp:
            key: GroupKey = (protocol, number, subnets.get(interface_name) or "")
            groups.setdefault(key, []).append(
                FhrpMember(
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
            )
            virtuals.setdefault(key, virtual)

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
        vlans=tuple(vlans),
        **topology.derive(devices, vlans),
        bgp=tuple(bgp),
        fhrp_groups=tuple(
            FhrpGroup(
                id=_group_id(key, groups),
                protocol=key[0],
                group_number=key[1],
                members=tuple(members),
                virtual_ipv4=virtuals[key],
                subnet=key[2] or None,
            )
            for key, members in sorted(
                groups.items(),
                key=lambda item: (item[0][0].value, item[0][1], item[0][2]),
            )
        ),
        timers=TimerInventory(
            fhrp=tuple(fhrp_timers),
            bfd=tuple(bfd_timers),
            igp_hello=tuple(igp_timers),
            dampening=tuple(dampening),
        ),
    )
    return pack, unparsed


def _first_network(interface: Interface) -> str | None:
    for assignment in interface.addresses:
        try:
            return str(ipaddress.ip_interface(assignment.prefix).network)
        except ValueError:
            continue
    return None


def _group_id(
    key: tuple[FhrpProtocol, int, str],
    groups: dict[tuple[FhrpProtocol, int, str], list[FhrpMember]],
) -> str:
    """`vrrp-14`, or `vrrp-14@10.20.0.0/24` when that number is reused.

    The short form is kept where it is unambiguous because it is what a person
    reading a finding expects; the subnet is only added when it is load-bearing.
    """
    protocol, number, subnet = key
    reused = sum(1 for other in groups if other[0] is protocol and other[1] == number)
    if reused > 1 and subnet:
        return f"{protocol.value}-{number}@{subnet}"
    return f"{protocol.value}-{number}"
