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
from cassandra.factpack.builders import eos, ios, iosxr, nxos
from cassandra.factpack.builders.common import ParsedDevice, assemble_fhrp_groups
from cassandra.factpack.schema import (
    BfdTimers,
    BgpProcess,
    BgpTimers,
    DampeningProfile,
    Device,
    FactPackMeta,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    IgpHelloTimers,
    Interface,
    StaticFactPack,
    StpMode,
    StpTimers,
    TimerInventory,
    Vlan,
)

SCHEMA_VERSION: Final = 1
DIALECTS: Final[tuple[ModuleType, ...]] = (ios, eos, nxos, iosxr)

# A parsed file with no hostname of its own and fewer than two interfaces has
# told us nothing: it names no device and forms no adjacency, so it can only
# add an empty row to the inventory and empty entries to every rule that
# iterates devices. Files like this are what survives a sniff on something that
# was never a config, so they are dropped rather than carried — and reported,
# because a config silently missing from the pack is the bug this module was
# rewritten to remove.
MIN_INTERFACES_WITHOUT_HOSTNAME: Final = 2


def parse(text: str, *, device_id: str | None = None) -> ParsedDevice:
    """Parse with the best-fitting dialect.

    A marker decides where one is decisive. Otherwise every parser runs and the
    one that leaves least of the file unexplained wins, which is a measurement
    rather than a guess — right up until two of them explain all of it, and then
    it used to be a coin toss resolved by `DIALECTS` order.

    A tie happens constantly, and it is not by itself a defect: on an L2-only
    switch, IOS, EOS and NX-OS genuinely share every line they need, so a tie
    often means the file contains nothing that distinguishes them. Seven of the
    eighteen configs shipped with this tool are decided that way. What matters is
    what the tie was allowed to decide.

    Units used to ride on it. `spanning-tree hello-time` is milliseconds on EOS
    and seconds on its two siblings, and spanning-tree timers live on exactly the
    L2-only switch where every parser ties, so list order was choosing between
    2 seconds and 2 milliseconds. That is fixed where it belongs, in
    `common._stp_ms`, which reads the unit off the number rather than off the
    dialect. Nothing about a fact's *value* now depends on which of two tied
    parsers won.

    What still depends on it is which facts get read at all, and that is the half
    worth resolving rather than tossing for. Leftover lines measure a parse from
    one side only — what the parser could not account for — and every dialect also
    has a list of lines it absorbs as carrying no fact. Two parsers can therefore
    both account for the whole file while one of them quietly threw away a timer
    the other kept: `ip ospf hello-interval 5` is an IGP hello record to the EOS
    parser and an uninteresting line to the NX-OS one, and both report nothing
    unparsed. So a tie is broken by what was actually read out of the file, most
    facts first, with `DIALECTS` order — oldest first — still deciding between
    parsers that read the same amount. A parser that understood more of a file is
    not tied with one that understood less; it only looked that way from the
    leftovers.

    What is left after that — same leftovers, same number of facts — is not
    reported, and the reason is worth writing down because it is a property of
    these four parsers rather than a principle. Wherever two of them differ, one
    of them almost always *reports* the line rather than absorbing it, so equal
    leftovers plus equal fact counts has meant identical facts every time it
    occurs, on all eighteen shipped configs and every fixture in the suite. There
    is nothing to tell the reader: every reading of the file was the same
    reading, and the only thing the choice decided was the label, which is on the
    device as `nos_family` for anyone who wants it. A fifth dialect could break
    that, and the place to notice would be here.

    Deliberately not done: inventing a `looks_like_eos` to break ties by marker.
    EOS is the one dialect with no marker function, and giving it one would be a
    rule about which dialect a marker-free file *probably* is — a guess dressed as
    a measurement, and one that would silently re-label files this tool already
    reads correctly.
    """
    # IOS-XR is checked first, ahead of the marker it would otherwise lose to.
    # NX-OS is recognised by an indented `hsrp <n>` header, and IOS-XR writes one
    # of those too — four levels inside `router hsrp` rather than inside an
    # interface, which a search for the line cannot tell apart. Its own markers
    # are words no other dialect writes at all (`router vrrp` at column zero,
    # `ipv4 address`, `Bundle-Ether`), so testing them first costs the other
    # three nothing.
    if iosxr.looks_like_iosxr(text):
        return iosxr.parse_device(text, device_id=device_id)
    # NX-OS is checked next: its `hsrp <n>` block is distinctive, whereas an
    # NX-OS config could otherwise be mistaken for EOS on addressing alone.
    if nxos.looks_like_nxos(text):
        return nxos.parse_device(text, device_id=device_id)
    if ios.looks_like_ios(text):
        return ios.parse_device(text, device_id=device_id)

    # No decisive marker: run them all and rank them by how much of the file each
    # one accounted for — fewest leftovers first, then most facts read, then
    # `DIALECTS` order, which is oldest first so a dialect added later only wins
    # where it is strictly better.
    candidates = [module.parse_device(text, device_id=device_id) for module in DIALECTS]
    return min(candidates, key=_fit)


def _fit(parsed: ParsedDevice) -> tuple[int, int]:
    """How well one parser accounted for a file. Lower is better.

    Two numbers because leftovers alone see half of it. A parser explains a file
    by reading its lines into facts *and* by knowing which lines carry none, and
    the second half is a per-dialect list of absorbed constructs — so a parser
    that absorbs a line another one reads as a timer scores identically on
    leftovers while having taken less out of the file. The fact count is negated
    so that "more facts" sorts alongside "fewer leftovers" as better.
    """
    return len(parsed.unparsed_lines), -sum(len(family) for family in _facts_of(parsed))


# Every fact family `build_fact_pack` collects off a parsed device, which is the
# whole of what a dialect choice can decide. `nos_family` is the deliberate
# omission: it is the label the choice puts on the device rather than anything
# read out of the file.
_FACT_FAMILIES: Final = (
    "vlans",
    "tracked",
    "timers",
    "fhrp_records",
    "bfd",
    "igp_hello",
    "dampening",
    "bgp_timers",
    "stp",
    "bgp",
)


def _facts_of(parsed: ParsedDevice) -> tuple[tuple[object, ...], ...]:
    """Every fact one parse claims, family by family."""
    return (
        parsed.device.interfaces,
        *(tuple(getattr(parsed, family, ())) for family in _FACT_FAMILIES),
    )


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
    parsed_devices: list[ParsedDevice] = []
    fhrp_timers: list[FhrpTimers] = []
    # Dialects attach these on their own record type; getattr keeps the
    # collector working for any dialect that does not carry a given family.
    bfd_timers: list[BfdTimers] = []
    igp_timers: list[IgpHelloTimers] = []
    dampening: list[DampeningProfile] = []
    bgp_timers: list[BgpTimers] = []
    stp_timers: list[StpTimers] = []
    # Bridge priorities are not timers and never enter the timer inventory:
    # they are only meaningful against the other bridges in a broadcast domain,
    # so they go to `topology` and reach the pack on the segment they decide.
    bridge_priorities: dict[str, topology.BridgePriorities] = {}
    stp_modes: dict[str, StpMode] = {}
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
        # The file is stored relative to the directory that was checked. A
        # finding travels — into a baseline, a report, a ticket — and an absolute
        # path from whichever machine ran the check means nothing to whoever
        # reads it next.
        parsed = replace(
            parsed, device=replace(parsed.device, config_path=config.relative)
        )
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
        parsed_devices.append(parsed)
        fhrp_timers.extend(parsed.timers)
        bfd_timers.extend(getattr(parsed, "bfd", ()))
        igp_timers.extend(getattr(parsed, "igp_hello", ()))
        dampening.extend(getattr(parsed, "dampening", ()))
        bgp_timers.extend(getattr(parsed, "bgp_timers", ()))
        stp_timers.extend(getattr(parsed, "stp", ()))
        bridge_priorities[parsed.device.id] = topology.BridgePriorities(
            stated=parsed.stp_priorities, complete=parsed.stp_priorities_complete
        )
        stp_modes[parsed.device.id] = parsed.stp_mode
        vlans.extend(parsed.vlans)
        bgp.extend(getattr(parsed, "bgp", ()))
        unparsed[parsed.device.id] = parsed.unparsed_lines

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
        **topology.derive(
            devices,
            vlans,
            stp_modes=stp_modes,
            bridge_priorities=bridge_priorities,
        ),
        bgp=tuple(bgp),
        # Assembly lives with the parsers because it is a parsing concern: a
        # group's identity includes its address family, and only the record the
        # parser produced knows which family a membership belongs to.
        fhrp_groups=assemble_fhrp_groups(parsed_devices),
        timers=TimerInventory(
            fhrp=tuple(fhrp_timers),
            bfd=tuple(bfd_timers),
            igp_hello=tuple(igp_timers),
            dampening=tuple(dampening),
            bgp=tuple(bgp_timers),
            stp=tuple(stp_timers),
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
        # The membership carries the device id, and so does every tracked
        # object hanging off it. A half-renamed device leaves its groups
        # answering to a name it no longer has.
        "fhrp_records": tuple(
            replace(record, member=_member_of(record.member, device_id))
            for record in parsed.fhrp_records
        ),
    }
    for family in ("bfd", "igp_hello", "dampening", "bgp_timers", "stp"):
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


def _rescoped[
    T: (BfdTimers, BgpTimers, DampeningProfile, FhrpTimers, IgpHelloTimers, StpTimers)
](record: T, device_id: str) -> T:
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
