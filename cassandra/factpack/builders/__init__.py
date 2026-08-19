"""Config text -> Fact Pack, dialect chosen automatically.

The user should not have to tell the tool what wrote their configs. Detection
tries the dialect whose markers appear, then falls back to whichever parser
accounts for more of the file — a parser that leaves half a config unexplained is
the wrong parser, and that is measurable rather than a guess.

Which files to read is a separate question with its own answer in
`cassandra.factpack.discovery`, and the two meet here: discovery decides what is
a config and what each one is provisionally called, and this module decides what
the resulting devices are called once their contents are known.
"""

from __future__ import annotations

import hashlib
import ipaddress
import warnings
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Final

# Imported as a module, not by name: `discovery` reads `builders.common` for
# the banner stripper, so binding names here would make the two modules'
# import order load-bearing.
from cassandra.factpack import discovery, topology
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

# A parsed file with no hostname of its own and fewer than two interfaces has
# told us nothing: it names no device and forms no adjacency, so it can only
# add an empty row to the inventory and empty entries to every rule that
# iterates devices. Files like this are what survives a sniff on something that
# was never a config, so they are dropped rather than carried — and reported,
# because a config silently missing from the pack is the bug this module was
# rewritten to remove.
MIN_INTERFACES_WITHOUT_HOSTNAME: Final = 2


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
    """Parse every config in a directory tree into one Fact Pack.

    Which files those are is `discovery.discover`: the tree is walked, not
    globbed, and a file becomes a device only if its name and its first
    kilobytes both say it is configuration. Anything discovery passed over that
    a person would want to hear about, and any file that parsed to nothing, is
    raised as a `discovery.ConfigDiscoveryWarning` — the return type is fixed by its
    callers, so the alternative to a warning is silence.

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
    # Dialects attach these on their own record type; getattr keeps the
    # collector working for any dialect that does not carry a given family.
    bfd_timers: list[BfdTimers] = []
    igp_timers: list[IgpHelloTimers] = []
    dampening: list[DampeningProfile] = []
    vlans: list[Vlan] = []
    bgp: list[BgpProcess] = []
    unparsed: dict[str, tuple[str, ...]] = {}
    digest = hashlib.sha256()

    found = discovery.discover(config_dir)
    notes: list[str] = list(found.notes())
    parsed_files: list[tuple[discovery.ConfigFile, ParsedDevice]] = []
    for config in found.configs:
        digest.update(config.text.encode())
        parsed = parse(config.text, device_id=config.device_id)
        if _is_empty_of_facts(config, parsed):
            notes.append(
                f"{config.path}: reads as configuration but declares no hostname "
                f"and fewer than {MIN_INTERFACES_WITHOUT_HOSTNAME} interfaces; "
                "not treated as a device"
            )
            continue
        parsed_files.append((config, parsed))

    for parsed in _with_unique_ids(parsed_files, notes):
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

    for note in notes:
        warnings.warn(note, discovery.ConfigDiscoveryWarning, stacklevel=2)

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


def _is_empty_of_facts(config: discovery.ConfigFile, parsed: ParsedDevice) -> bool:
    """Did this file yield anything that could be a device?

    Deliberately two independent signals rather than one. A config with a
    hostname and no interfaces is a real device that happens to be a stub, and a
    config with several interfaces and no hostname is a real device whose name
    the backup tool put in the filename. Only the file that has neither is
    indistinguishable from something that was never a config.
    """
    return (
        config.declared_hostname is None
        and len(parsed.device.interfaces) < MIN_INTERFACES_WITHOUT_HOSTNAME
    )


def _with_unique_ids(
    parsed_files: list[tuple[discovery.ConfigFile, ParsedDevice]],
    notes: list[str],
) -> list[ParsedDevice]:
    """Give every device an id no other device in the pack has.

    A config names itself with `hostname`, and that name is what an operator
    recognises, so it wins wherever it is unique — which is why a flat directory
    of well-formed configs keeps exactly the ids it has always had. When two
    files declare the same hostname, neither can keep it without merging two
    devices into one, so *both* fall back to their path-derived ids rather than
    one of them keeping the name and the other being renamed on the basis of
    which was read first.
    """
    claims = Counter(parsed.device.id for _, parsed in parsed_files)
    taken: set[str] = set()
    out: list[ParsedDevice] = []
    for config, parsed in parsed_files:
        declared = parsed.device.id
        wanted = declared if claims[declared] == 1 else config.device_id
        unique = _unused(wanted, taken)
        taken.add(unique)
        if unique != declared:
            notes.append(
                f"{config.path}: hostname {declared!r} is declared by more than "
                f"one config; this one is {unique!r} in the fact pack"
            )
            parsed = _renamed(parsed, unique)
        out.append(parsed)
    return out


def _unused(wanted: str, taken: set[str]) -> str:
    """`wanted`, or the first `wanted~2`, `wanted~3` nobody has.

    Only reachable when a hostname collides with another file's path-derived id,
    which is rare enough that a suffix is a better answer than a scheme.
    """
    if wanted not in taken:
        return wanted
    suffix = 2
    while f"{wanted}~{suffix}" in taken:
        suffix += 1
    return f"{wanted}~{suffix}"


def _renamed(parsed: ParsedDevice, device_id: str) -> ParsedDevice:
    """Rewrite every reference this record makes to its own device.

    The id is threaded through interfaces, VLANs, tracked objects, FHRP members
    and every timer scope, and a half-renamed device is worse than a collided
    one: its interfaces would join the topology under a name its device no
    longer has. `hostname` is deliberately left alone — it records what the
    config called itself, which is still true and is now the only place that
    fact survives.
    """
    device = replace(
        parsed.device,
        id=device_id,
        interfaces=tuple(
            replace(interface, device=device_id)
            for interface in parsed.device.interfaces
        ),
    )
    changes: dict[str, object] = {
        "device": device,
        "tracked": tuple(
            replace(tracked, device=device_id) for tracked in parsed.tracked
        ),
        "timers": tuple(_rescoped(timer, device_id) for timer in parsed.timers),
        "vlans": tuple(replace(vlan, device=device_id) for vlan in parsed.vlans),
        "fhrp": tuple(
            (number, protocol, _member_of(member, device_id), interface, virtual)
            for number, protocol, member, interface, virtual in parsed.fhrp
        ),
    }
    for family in ("bfd", "igp_hello", "dampening"):
        records = getattr(parsed, family, ())
        if records:
            changes[family] = tuple(_rescoped(record, device_id) for record in records)
    processes = getattr(parsed, "bgp", ())
    if processes:
        changes["bgp"] = tuple(
            replace(process, device=device_id) for process in processes
        )
    return replace(parsed, **changes)


def _member_of(member: FhrpMember, device_id: str) -> FhrpMember:
    return replace(
        member,
        device=device_id,
        tracked_objects=tuple(
            replace(tracked, device=device_id) for tracked in member.tracked_objects
        ),
    )


def _rescoped[T: (BfdTimers, DampeningProfile, FhrpTimers, IgpHelloTimers)](
    record: T, device_id: str
) -> T:
    return replace(record, scope=replace(record.scope, device=device_id))


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
