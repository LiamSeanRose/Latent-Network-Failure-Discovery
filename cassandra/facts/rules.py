"""FACTS tier — deterministic assertions over the Fact Pack.

No lab, no model, no ambiguity: everything here is decidable from the configs
alone, so a finding is either true of the text or it is a bug in a rule.

Each rule states what it checked and what would remove the finding, because a
finding the user cannot act on is noise (PROJECT.md §5.4).
"""

from __future__ import annotations

import ipaddress
import itertools
from collections.abc import Callable, Iterator
from typing import Final

from cassandra.factpack.schema import (
    FhrpGroup,
    FhrpMember,
    Interface,
    InterfaceKind,
    StaticFactPack,
    TrackedObjectKind,
    VlanId,
    VrfName,
)
from cassandra.findings import Finding, Severity, Tier

Rule = Callable[[StaticFactPack], Iterator[Finding]]
RULES: list[Rule] = []

type Network = ipaddress.IPv4Network | ipaddress.IPv6Network
type SubnetKey = tuple[VrfName | None, Network]

# A /30 or /31 with one end in the corpus is far more often a link to something
# the user did not hand us — a carrier handoff, a firewall, a server — than a
# real isolation defect, so the isolation rule stops there.
POINT_TO_POINT_PREFIXLEN: Final = 30

# A trunk permitting hundreds of VLANs is a bulk-permit policy, not a per-VLAN
# assertion, and reading intent into it produces noise rather than findings.
BULK_TRUNK_VLANS: Final = 64

# VLAN 1 exists whether or not anyone configured it.
DEFAULT_VLAN: Final[VlanId] = 1

# Kinds that are isolated by construction, so isolation says nothing about them.
OFF_THE_WIRE: Final = frozenset(
    {
        InterfaceKind.LOOPBACK,
        InterfaceKind.MANAGEMENT,
        InterfaceKind.TUNNEL,
        InterfaceKind.UNKNOWN,
    }
)


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


def _interfaces(pack: StaticFactPack) -> dict[tuple[str, str], Interface]:
    return {
        (device.id, interface.name): interface
        for device in pack.devices
        for interface in device.interfaces
    }


def _networks(interface: Interface) -> list[ipaddress.IPv4Network]:
    nets = []
    for assignment in interface.addresses:
        try:
            nets.append(ipaddress.ip_interface(assignment.prefix).network)
        except ValueError:
            continue
    return nets


@rule
def virtual_address_outside_subnet(pack: StaticFactPack) -> Iterator[Finding]:
    """A virtual address outside every subnet the member interface is on.

    Hosts reach their gateway by ARPing for an address on their own subnet. One
    outside it is unreachable from the segment it is supposed to serve, and the
    group otherwise looks healthy: it elects, it advertises, and nothing uses it.

    Silent when the interface has no address at all, since there is then no
    subnet to be outside of.
    """
    interfaces = _interfaces(pack)
    for group in pack.fhrp_groups:
        if not group.virtual_ipv4:
            continue
        virtual = ipaddress.ip_address(group.virtual_ipv4)
        for member in group.members:
            interface = interfaces.get((member.device, member.interface))
            if interface is None:
                continue
            nets = _networks(interface)
            if nets and not any(virtual in net for net in nets):
                yield Finding(
                    rule="fhrp-virtual-outside-subnet",
                    tier=Tier.FACTS,
                    severity=Severity.HIGH,
                    device=member.device,
                    title=f"{group.protocol.value.upper()} {group.group_number} "
                    f"virtual address is outside its own subnet",
                    detail=f"{group.virtual_ipv4} is not in "
                    + ", ".join(str(n) for n in nets),
                    evidence=(f"{member.device}:{member.interface}",),
                    remedy="move the virtual address into the interface subnet",
                )


@rule
def virtual_address_collides(pack: StaticFactPack) -> Iterator[Finding]:
    """A virtual address a real interface on the same pair already owns.

    The virtual address is meant to be answered by whichever member is master.
    When one member also carries it as its own interface address, that member
    answers for it whether or not it holds the group, so failover moves the
    group without moving the traffic.
    """
    interfaces = _interfaces(pack)
    for group in pack.fhrp_groups:
        for member in group.members:
            interface = interfaces.get((member.device, member.interface))
            if interface is None:
                continue
            for assignment in interface.addresses:
                if assignment.address == group.virtual_ipv4:
                    yield Finding(
                        rule="fhrp-virtual-collides",
                        tier=Tier.FACTS,
                        severity=Severity.HIGH,
                        device=member.device,
                        title=f"{group.protocol.value.upper()} "
                        f"{group.group_number} virtual address collides with a "
                        f"real interface address",
                        detail=f"{group.virtual_ipv4} is also configured on "
                        f"{member.interface}",
                        evidence=(f"{member.device}:{member.interface}",),
                        remedy="give the group a virtual address no device owns",
                    )


@rule
def group_has_no_redundancy(pack: StaticFactPack) -> Iterator[Finding]:
    """A redundancy group with fewer than two members in the collection.

    Either the peer's configuration is not in the directory — in which case the
    finding is telling you the analysis is incomplete, which is worth knowing —
    or the group really is configured on one device, and the virtual address is
    a second name for a single point of failure.
    """
    for group in pack.fhrp_groups:
        if len(group.members) < 2:
            device = group.members[0].device if group.members else "?"
            yield Finding(
                rule="fhrp-no-redundancy",
                tier=Tier.FACTS,
                severity=Severity.MEDIUM,
                device=device,
                title=f"{group.protocol.value.upper()} {group.group_number} has "
                f"only {len(group.members)} member",
                detail="a redundancy group with one member provides no redundancy",
                remedy="configure the group on the peer device, or remove it",
            )


@rule
def priority_tie(pack: StaticFactPack) -> Iterator[Finding]:
    """Members sharing the top priority, so nothing decides the master.

    The protocols break the tie on address comparison, which is deterministic
    but not chosen: the master is whichever device happens to have the higher
    interface address. That holds until a reboot changes who advertises first,
    and then the placement people have been assuming quietly stops being true.
    """
    for group in pack.fhrp_groups:
        if len(group.members) < 2:
            continue
        top = max(m.priority for m in group.members)
        tied = [m for m in group.members if m.priority == top]
        if len(tied) > 1:
            yield Finding(
                rule="fhrp-priority-tie",
                tier=Tier.FACTS,
                severity=Severity.MEDIUM,
                device=tied[0].device,
                title=f"{group.protocol.value.upper()} {group.group_number} has no "
                f"preferred master",
                detail=f"{len(tied)} members share priority {top}, so the master is "
                f"decided by address comparison and can change on reboot",
                evidence=tuple(f"{m.device}:{m.interface}" for m in tied),
                remedy="give the intended master a higher priority",
            )


@rule
def tracked_object_unresolved(pack: StaticFactPack) -> Iterator[Finding]:
    """A group that decrements its priority for a track nobody defined.

    The intent is legible — the operator meant this group to step aside when
    something fails — and the configuration will not do it. Nothing complains,
    because a track that does not exist simply never fires, so the group holds
    its priority through exactly the failure the track was written for.

    High severity for a rule about an absent line: this is failover that looks
    configured and is not.
    """
    for group in pack.fhrp_groups:
        for member in group.members:
            for tracked in member.tracked_objects:
                if not tracked.target:
                    yield Finding(
                        rule="fhrp-track-undefined",
                        tier=Tier.FACTS,
                        severity=Severity.HIGH,
                        device=member.device,
                        title=f"tracked object {tracked.id!r} is referenced but "
                        f"never defined",
                        detail="the group references it, so the decrement is "
                        "configured but can never fire — the failover it is meant "
                        "to cause will not happen",
                        evidence=(
                            f"{member.device}:{member.interface} "
                            f"{group.protocol.value} {group.group_number}",
                        ),
                        remedy=f"define {tracked.id!r} or remove the reference",
                    )


@rule
def tracking_cannot_change_the_outcome(pack: StaticFactPack) -> Iterator[Finding]:
    """A decrement too small to lose the election is tracking that does nothing.

    This is the quiet one: the config looks correct, the intent is visible, and
    the failover silently never happens.
    """
    for group in pack.fhrp_groups:
        if len(group.members) < 2:
            continue
        for member in group.members:
            if not member.tracked_objects:
                continue
            total = sum(t.decrement or 0 for t in member.tracked_objects)
            rivals = [m.priority for m in group.members if m is not member]
            if not rivals:
                continue
            if member.priority - total > max(rivals):
                yield Finding(
                    rule="fhrp-track-ineffective",
                    tier=Tier.FACTS,
                    severity=Severity.MEDIUM,
                    device=member.device,
                    title=f"{group.protocol.value.upper()} {group.group_number} "
                    f"tracking can never cause a failover",
                    detail=f"priority {member.priority} minus the total decrement "
                    f"{total} is {member.priority - total}, still above the highest "
                    f"peer priority {max(rivals)}",
                    evidence=tuple(
                        f"{t.id}->{t.target} -{t.decrement}"
                        for t in member.tracked_objects
                    ),
                    remedy=f"increase the decrement past "
                    f"{member.priority - max(rivals)}",
                )


@rule
def svi_vlan_missing_from_every_trunk(pack: StaticFactPack) -> Iterator[Finding]:
    """An addressed SVI for a VLAN no trunk on the device carries.

    The interface is up and has an address, so the device can route for the
    VLAN; nothing can reach it, because the VLAN leaves on no uplink. It is the
    shape a VLAN takes after it is removed from a trunk's allowed list during
    some unrelated cleanup and the SVI is left behind.

    Only checked on devices that have at least one trunk. A device with none is
    not carrying VLANs anywhere, which is a different thing entirely.
    """
    for device in pack.devices:
        trunks = [i for i in device.interfaces if i.allowed_vlans]
        if not trunks:
            continue
        carried = {vlan for trunk in trunks for vlan in trunk.allowed_vlans}
        for interface in device.interfaces:
            if not interface.name.startswith("Vlan"):
                continue
            vlan_id = interface.name.removeprefix("Vlan")
            if not vlan_id.isdigit() or int(vlan_id) in carried:
                continue
            yield Finding(
                rule="svi-vlan-not-trunked",
                tier=Tier.FACTS,
                severity=Severity.MEDIUM,
                device=device.id,
                title=f"{interface.name} has no trunk carrying VLAN {vlan_id}",
                detail="the interface is up and addressed but the VLAN reaches no "
                "neighbour, so anything relying on it is isolated",
                evidence=tuple(f"{device.id}:{t.name}" for t in trunks),
                remedy=f"add VLAN {vlan_id} to the relevant trunk",
            )


@rule
def duplicate_addresses(pack: StaticFactPack) -> Iterator[Finding]:
    """One IPv4 address configured on two interfaces in the collection.

    Whichever device answers first wins, and which one that is depends on ARP
    timing rather than on anything written down. The usual cause is a config
    copied between devices and edited everywhere except the address, so the
    duplicate is often on the device that was working yesterday.

    Compares addresses, not prefixes: the same address with two different masks
    is still one address two devices claim.
    """
    seen: dict[str, str] = {}
    for device in pack.devices:
        for interface in device.interfaces:
            for assignment in interface.addresses:
                where = f"{device.id}:{interface.name}"
                if (previous := seen.get(assignment.address)) is not None:
                    yield Finding(
                        rule="duplicate-address",
                        tier=Tier.FACTS,
                        severity=Severity.HIGH,
                        device=device.id,
                        title=f"{assignment.address} is configured twice",
                        detail=f"also on {previous}",
                        evidence=(previous, where),
                        remedy="renumber one of them",
                    )
                seen[assignment.address] = where


@rule
def preferred_master_will_not_reclaim(pack: StaticFactPack) -> Iterator[Finding]:
    """The highest-priority member has preempt off, so it never takes back.

    After the first failover the group stays on the backup for good. That is a
    legitimate choice — it avoids a second interruption to move back — but it
    means the priorities in the configuration no longer describe where traffic
    is, and the next person to read them will be wrong about the current state.

    Low severity because it is a defensible configuration. It is reported so the
    choice is visible rather than assumed.
    """
    for group in pack.fhrp_groups:
        if len(group.members) < 2:
            continue
        top = max(m.priority for m in group.members)
        for member in group.members:
            if member.priority == top and not member.preempt:
                yield Finding(
                    rule="fhrp-no-preempt-on-preferred",
                    tier=Tier.FACTS,
                    severity=Severity.LOW,
                    device=member.device,
                    title=f"{group.protocol.value.upper()} {group.group_number} will "
                    f"not return to its preferred master",
                    detail=f"{member.device} has the highest priority ({top}) but "
                    f"preempt is off, so after any failover the group stays on the "
                    f"backup indefinitely",
                    evidence=(f"{member.device}:{member.interface}",),
                    remedy="enable preempt, or accept the placement is not "
                    "deterministic",
                )


# --------------------------------------------------------------------------
# Subnet-shaped rules
#
# The Fact Pack does not ship an L3 adjacency graph yet, so these derive one
# the only way the configs allow: two addressed interfaces are on the same
# wire when their prefixes reduce to the same network in the same VRF. That is
# an assumption, and it is the same assumption the operator made when they
# typed the addresses.
# --------------------------------------------------------------------------


def _subnets(pack: StaticFactPack) -> dict[SubnetKey, list[Interface]]:
    index: dict[SubnetKey, list[Interface]] = {}
    for device in pack.devices:
        for interface in device.interfaces:
            for net in _networks(interface):
                members = index.setdefault((interface.vrf, net), [])
                if interface not in members:
                    members.append(interface)
    return index


def _ordered_subnets(pack: StaticFactPack) -> list[tuple[SubnetKey, list[Interface]]]:
    """Stable ordering, so two runs over one directory report the same list."""
    return sorted(_subnets(pack).items(), key=lambda item: str(item[0]))


def _svi_vlan(interface: Interface) -> VlanId | None:
    if interface.kind is not InterfaceKind.SVI:
        return None
    suffix = interface.name.removeprefix("Vlan").removeprefix("vlan")
    return int(suffix) if suffix.isdigit() else None


@rule
def mtu_mismatch_across_a_subnet(pack: StaticFactPack) -> Iterator[Finding]:
    """Neighbours that disagree about how large a frame may be.

    Only explicitly configured values are compared. An unset MTU is a platform
    default this tool does not claim to know, and guessing one would invent
    findings rather than report them.
    """
    for (_vrf, net), members in _ordered_subnets(pack):
        sized = [i for i in members if i.mtu_bytes is not None]
        values: set[int] = {i.mtu_bytes for i in sized if i.mtu_bytes is not None}
        if len(sized) < 2 or len(values) < 2:
            continue
        smallest = min(values)
        yield Finding(
            rule="mtu-mismatch",
            tier=Tier.FACTS,
            severity=Severity.HIGH,
            device=sized[0].device,
            title=f"MTU is not agreed across {net}",
            detail="interfaces sharing this subnet are configured with "
            + " and ".join(str(v) for v in sorted(values))
            + f" bytes; anything larger than {smallest} is dropped without an "
            "ICMP hint on a bridged path, and OSPF will not leave ExStart",
            evidence=tuple(f"{i.device}:{i.name} mtu {i.mtu_bytes}" for i in sized),
            remedy=f"set one MTU for the subnet — {smallest} everywhere, or raise "
            f"the smaller interface to match",
        )


@rule
def trunk_carries_a_vlan_nothing_terminates(pack: StaticFactPack) -> Iterator[Finding]:
    """A VLAN permitted on a trunk that no device in the topology terminates.

    Terminating means an SVI or an access port somewhere in the corpus. A VLAN
    with neither is carried, learned and flooded for nothing — usually the
    residue of a service that was decommissioned at the edges and left on the
    trunks.
    """
    terminated: set[VlanId] = set()
    for device in pack.devices:
        for interface in device.interfaces:
            if (vlan := _svi_vlan(interface)) is not None:
                terminated.add(vlan)
            if interface.access_vlan is not None:
                terminated.add(interface.access_vlan)
    if not terminated:
        # Nothing in the corpus terminates anything: this is a set of configs
        # the rule cannot reason about, not a topology full of dead VLANs.
        return

    for device in pack.devices:
        for interface in device.interfaces:
            allowed = interface.allowed_vlans
            if not allowed or len(allowed) > BULK_TRUNK_VLANS:
                continue
            dead = sorted(
                {v for v in allowed if v not in terminated and v != DEFAULT_VLAN}
            )
            if not dead:
                continue
            listed = ", ".join(str(v) for v in dead)
            yield Finding(
                rule="trunk-vlan-dead",
                tier=Tier.FACTS,
                severity=Severity.LOW,
                device=device.id,
                title=f"{interface.name} trunks VLAN {listed}, which nothing "
                f"terminates",
                detail="no device in these configs has an SVI or an access port in "
                f"VLAN {listed}, so the trunk carries broadcast and MAC-learning "
                "load for a broadcast domain with no members",
                evidence=(f"{device.id}:{interface.name} allowed {listed}",),
                remedy=f"remove VLAN {listed} from the trunk, or add the access "
                f"ports and SVIs that were meant to use it",
            )


@rule
def isolated_l3_interface(pack: StaticFactPack) -> Iterator[Finding]:
    """An addressed interface on a subnet no other device shares.

    INFO, not a defect: a subnet whose other end is a server, a firewall, or a
    device outside the directory looks exactly like this. It is reported because
    the alternative — a typo in one octet that quietly split a working subnet in
    two — looks exactly like this too, and only the operator can tell them apart.
    """
    if len(pack.devices) < 2:
        # One device is isolated from nothing; every subnet would qualify.
        return

    subnets = _ordered_subnets(pack)
    # Isolation is only meaningful relative to a topology the device belongs to.
    # A device that shares no subnet at all with any other — configs from a
    # second site dropped into the same directory, say — would otherwise have
    # every one of its interfaces reported, which says nothing about any of them.
    attached = {
        interface.device
        for _key, members in subnets
        if len({i.device for i in members}) > 1
        for interface in members
    }

    for (_vrf, net), members in subnets:
        if net.prefixlen >= POINT_TO_POINT_PREFIXLEN:
            continue
        if len({i.device for i in members}) > 1:
            continue
        for interface in members:
            if interface.kind in OFF_THE_WIRE or interface.device not in attached:
                continue
            yield Finding(
                rule="l3-interface-isolated",
                tier=Tier.FACTS,
                severity=Severity.INFO,
                device=interface.device,
                title=f"{interface.name} is the only interface on {net}",
                detail="no other device in these configs is addressed in this "
                "subnet, so nothing here can be an IGP, BFD or FHRP peer of it",
                evidence=(f"{interface.device}:{interface.name}",),
                remedy="confirm the far end is outside these configs; if it is not, "
                "check the address for a wrong octet or prefix length",
            )


# --------------------------------------------------------------------------
# Further FHRP rules
# --------------------------------------------------------------------------


@rule
def virtual_address_is_network_or_broadcast(pack: StaticFactPack) -> Iterator[Finding]:
    """A virtual address that is not a host address at all.

    Distinct from `fhrp-virtual-outside-subnet`: this address *is* inside the
    subnet, which is why that rule stays quiet, but no host may hold it.
    """
    interfaces = _interfaces(pack)
    for group in pack.fhrp_groups:
        if not group.virtual_ipv4:
            continue
        try:
            virtual = ipaddress.ip_address(group.virtual_ipv4)
        except ValueError:
            continue
        for member in group.members:
            interface = interfaces.get((member.device, member.interface))
            if interface is None:
                continue
            for net in _networks(interface):
                # A /31 or /32 has neither a network nor a broadcast host, so
                # the question does not arise there.
                if net.version != virtual.version or net.prefixlen >= 31:
                    continue
                if virtual not in net:
                    continue
                if virtual == net.network_address:
                    role = "network address"
                elif virtual == net.broadcast_address:
                    role = "broadcast address"
                else:
                    continue
                yield Finding(
                    rule="fhrp-virtual-not-a-host-address",
                    tier=Tier.FACTS,
                    severity=Severity.HIGH,
                    device=member.device,
                    title=f"{group.protocol.value.upper()} {group.group_number} "
                    f"virtual address is the {role} of its subnet",
                    detail=f"{group.virtual_ipv4} is the {role} of {net}; hosts "
                    "will not ARP for it as a gateway and stacks routinely refuse "
                    "to configure it as a default route",
                    evidence=(f"{member.device}:{member.interface} {net}",),
                    remedy=f"choose a host address inside {net}",
                )
                break


@rule
def duplicate_group_member(pack: StaticFactPack) -> Iterator[Finding]:
    """One device holding two memberships of the same group on one subnet.

    Group numbers are legitimately reused across unrelated subnets — group 1 on
    every SVI is ordinary practice — so the subnet is what makes this decidable.
    Two memberships of one group in one subnet on one device means the device
    contends with itself: it sends advertisements from two interfaces, and which
    of them holds the virtual address is not something the config decides.
    """
    interfaces = _interfaces(pack)
    for group in pack.fhrp_groups:
        by_device: dict[str, list[FhrpMember]] = {}
        for member in group.members:
            by_device.setdefault(member.device, []).append(member)
        for device, members in sorted(by_device.items()):
            if len(members) < 2:
                continue
            for first, second in itertools.combinations(members, 2):
                a = interfaces.get((device, first.interface))
                b = interfaces.get((device, second.interface))
                if a is None or b is None:
                    continue
                shared = sorted(set(_networks(a)) & set(_networks(b)), key=str)
                if not shared:
                    continue
                yield Finding(
                    rule="fhrp-duplicate-member",
                    tier=Tier.FACTS,
                    severity=Severity.HIGH,
                    device=device,
                    title=f"{device} is a member of {group_summary(group)} twice on "
                    f"{shared[0]}",
                    detail=f"{first.interface} and {second.interface} both run "
                    f"{group_summary(group)} in the same subnet, so the device "
                    "competes with itself and one of the two interfaces silently "
                    "loses the election",
                    evidence=(
                        f"{device}:{first.interface} priority {first.priority}",
                        f"{device}:{second.interface} priority {second.priority}",
                    ),
                    remedy=f"remove {group_summary(group)} from one of the two "
                    f"interfaces, or renumber one group",
                )


@rule
def virtual_address_shared_by_two_groups(pack: StaticFactPack) -> Iterator[Finding]:
    """Two groups on one interface answering for the same virtual address.

    Each group derives its own virtual MAC from its group number, so one address
    resolves to two MACs and every host's ARP entry follows whichever advertised
    last.
    """
    by_address: dict[str, list[FhrpGroup]] = {}
    for group in pack.fhrp_groups:
        if group.virtual_ipv4:
            by_address.setdefault(group.virtual_ipv4, []).append(group)

    for address, groups in sorted(by_address.items()):
        if len(groups) < 2:
            continue
        for first, second in itertools.combinations(groups, 2):
            shared = {(m.device, m.interface) for m in first.members} & {
                (m.device, m.interface) for m in second.members
            }
            for device, interface in sorted(shared):
                yield Finding(
                    rule="fhrp-virtual-shared",
                    tier=Tier.FACTS,
                    severity=Severity.HIGH,
                    device=device,
                    title=f"two groups on {interface} claim {address}",
                    detail=f"{group_summary(first)} and {group_summary(second)} are "
                    f"both configured with virtual address {address}; each has its "
                    "own virtual MAC, so hosts resolve the gateway to whichever "
                    "group advertised most recently",
                    evidence=(
                        f"{device}:{interface} {group_summary(first)}",
                        f"{device}:{interface} {group_summary(second)}",
                    ),
                    remedy="give each group its own virtual address, or collapse "
                    "them into one group",
                )


@rule
def tracked_interface_is_shut_down(pack: StaticFactPack) -> Iterator[Finding]:
    """A track whose target is administratively down.

    The track is down for as long as the config stands, so the decrement is not
    a response to a failure — it is the steady state, and the group can never
    return to its configured priority.
    """
    interfaces = _interfaces(pack)
    reported: set[tuple[str, str]] = set()
    for group in pack.fhrp_groups:
        for member in group.members:
            for tracked in member.tracked_objects:
                if tracked.kind is not TrackedObjectKind.INTERFACE:
                    continue
                if not tracked.target:
                    continue
                target = interfaces.get((member.device, tracked.target))
                if target is None or target.admin_enabled:
                    continue
                key = (member.device, tracked.id)
                if key in reported:
                    continue
                reported.add(key)
                decrement = tracked.decrement or 0
                yield Finding(
                    rule="fhrp-track-target-shutdown",
                    tier=Tier.FACTS,
                    severity=Severity.HIGH,
                    device=member.device,
                    title=f"tracked object {tracked.id!r} watches {tracked.target}, "
                    f"which is shut down",
                    detail=f"{tracked.target} is administratively down, so the track "
                    f"is down permanently and the {decrement}-point decrement "
                    f"applies at all times; {member.device} runs "
                    f"{group_summary(group)} at "
                    f"{member.priority - decrement}, not {member.priority}, and "
                    "nothing short of a config change restores it",
                    evidence=(
                        f"{member.device}:{tracked.target} shutdown",
                        f"{member.device}:{member.interface} {group_summary(group)} "
                        f"priority {member.priority} -{decrement}",
                    ),
                    remedy=f"bring {tracked.target} up, or point the track at the "
                    f"interface that is actually carrying the traffic",
                )


def evaluate(pack: StaticFactPack) -> list[Finding]:
    return [finding for rule_fn in RULES for finding in rule_fn(pack)]


def group_summary(group: FhrpGroup) -> str:
    return f"{group.protocol.value} {group.group_number}"


@rule
def vlan_used_but_not_declared(pack: StaticFactPack) -> Iterator[Finding]:
    """A port assigned to a VLAN the device never creates.

    On most platforms the port stays down or blackholes rather than erroring, so
    the config reads as correct and the traffic goes nowhere. Only devices that
    declare VLANs at all are checked — a pure L3 router declares none and is not
    doing anything wrong.
    """
    for device in pack.devices:
        declared = {vlan.vlan_id for vlan in pack.vlans if vlan.device == device.id}
        if not declared:
            continue
        for interface in device.interfaces:
            used: list[tuple[int, str]] = []
            if interface.access_vlan is not None:
                used.append((interface.access_vlan, "access VLAN"))
            if interface.name.startswith("Vlan"):
                suffix = interface.name.removeprefix("Vlan")
                if suffix.isdigit():
                    used.append((int(suffix), "SVI"))
            for vlan_id, kind in used:
                if vlan_id in declared:
                    continue
                yield Finding(
                    rule="vlan-not-declared",
                    tier=Tier.FACTS,
                    severity=Severity.HIGH,
                    device=device.id,
                    title=f"{interface.name} uses VLAN {vlan_id}, which "
                    f"{device.id} does not declare",
                    detail=f"the {kind} references a VLAN that is not created on "
                    f"this device, so the port does not forward and the "
                    f"configuration still reads as correct",
                    evidence=(
                        f"{device.id}:{interface.name}",
                        "declared: " + ", ".join(str(v) for v in sorted(declared)),
                    ),
                    remedy=f"add `vlan {vlan_id}` to {device.id}, or point the "
                    f"interface at a VLAN that exists",
                )


def _address_owner(pack: StaticFactPack) -> dict[str, str]:
    """Which device owns each configured address, for resolving peerings."""
    return {
        assignment.address: device.id
        for device in pack.devices
        for interface in device.interfaces
        for assignment in interface.addresses
    }


@rule
def bgp_session_configured_on_one_side(pack: StaticFactPack) -> Iterator[Finding]:
    """A peering only one end knows about.

    Decidable only when both devices are present, so it stays silent on a
    single-device pack or a peer outside the corpus — an upstream provider is
    not a defect.
    """
    owner = _address_owner(pack)
    local_addresses = {
        device.id: {a.address for i in device.interfaces for a in i.addresses}
        for device in pack.devices
    }
    configured: dict[tuple[str, str], str] = {}
    for process in pack.bgp:
        for neighbor in process.neighbors:
            configured[(process.device, neighbor.address)] = neighbor.address

    for process in pack.bgp:
        for neighbor in process.neighbors:
            peer_device = owner.get(neighbor.address)
            if peer_device is None or peer_device == process.device:
                continue
            reciprocated = any(
                address in local_addresses[process.device]
                for (device, address) in configured
                if device == peer_device
            )
            if reciprocated:
                continue
            yield Finding(
                rule="bgp-session-one-sided",
                tier=Tier.FACTS,
                severity=Severity.HIGH,
                device=process.device,
                title=f"BGP peering with {peer_device} is configured on one side only",
                detail=f"{process.device} peers to {neighbor.address}, but "
                f"{peer_device} has no neighbor statement back. The session "
                f"never establishes and the config looks complete on this device",
                evidence=(
                    f"{process.device} AS {process.local_as} -> {neighbor.address}",
                ),
                remedy=f"add the reciprocal neighbor on {peer_device}, or remove "
                f"this one",
            )


@rule
def bgp_remote_as_disagrees(pack: StaticFactPack) -> Iterator[Finding]:
    """One end expects an AS the other does not use."""
    owner = _address_owner(pack)
    local_as = {process.device: process.local_as for process in pack.bgp}

    for process in pack.bgp:
        for neighbor in process.neighbors:
            peer_device = owner.get(neighbor.address)
            if peer_device is None or neighbor.remote_as is None:
                continue
            actual = local_as.get(peer_device)
            if actual is None or actual == neighbor.remote_as:
                continue
            yield Finding(
                rule="bgp-remote-as-mismatch",
                tier=Tier.FACTS,
                severity=Severity.HIGH,
                device=process.device,
                title=f"BGP expects {peer_device} to be AS {neighbor.remote_as}, "
                f"but it runs AS {actual}",
                detail="the OPEN is rejected on AS mismatch, so the session stays "
                "down while both configurations look reasonable in isolation",
                evidence=(
                    f"{process.device}: neighbor {neighbor.address} "
                    f"remote-as {neighbor.remote_as}",
                    f"{peer_device}: router bgp {actual}",
                ),
                remedy=f"correct the remote-as on {process.device} to {actual}, or "
                f"the local AS on {peer_device}",
            )


@rule
def bgp_peer_on_no_local_subnet(pack: StaticFactPack) -> Iterator[Finding]:
    """A directly-connected peer address that is on none of this device's subnets.

    Skipped when the peering is explicitly not directly connected — an
    update-source or ebgp-multihop says the operator meant it.
    """
    for process in pack.bgp:
        device = next((d for d in pack.devices if d.id == process.device), None)
        if device is None:
            continue
        networks = [
            net for interface in device.interfaces for net in _networks(interface)
        ]
        if not networks:
            continue
        for neighbor in process.neighbors:
            if neighbor.update_source or neighbor.multihop or neighbor.shutdown:
                continue
            try:
                address = ipaddress.ip_address(neighbor.address)
            except ValueError:
                continue
            if any(address in net for net in networks):
                continue
            yield Finding(
                rule="bgp-peer-off-subnet",
                tier=Tier.FACTS,
                severity=Severity.MEDIUM,
                device=process.device,
                title=f"BGP peer {neighbor.address} is not on any subnet "
                f"{process.device} has",
                detail="the peering is neither multihop nor sourced from a "
                "loopback, so it is meant to be directly connected — and the "
                "address is not reachable on any interface here",
                evidence=(
                    f"{process.device} AS {process.local_as}",
                    *(f"local: {net}" for net in networks[:4]),
                ),
                remedy="correct the peer address, or add update-source / "
                "ebgp-multihop if the peering really is not direct",
            )
