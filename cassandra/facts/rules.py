"""FACTS tier — deterministic assertions over the Fact Pack.

No lab, no model, no ambiguity: everything here is decidable from the configs
alone, so a finding is either true of the text or it is a bug in a rule.

Each rule states what it checked and what would remove the finding, because a
finding the user cannot act on is noise (PROJECT.md §5.4).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterator

from cassandra.factpack.schema import (
    FhrpGroup,
    Interface,
    StaticFactPack,
)
from cassandra.findings import Finding, Severity, Tier

Rule = Callable[[StaticFactPack], Iterator[Finding]]
RULES: list[Rule] = []


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


def evaluate(pack: StaticFactPack) -> list[Finding]:
    return [finding for rule_fn in RULES for finding in rule_fn(pack)]


def group_summary(group: FhrpGroup) -> str:
    return f"{group.protocol.value} {group.group_number}"
