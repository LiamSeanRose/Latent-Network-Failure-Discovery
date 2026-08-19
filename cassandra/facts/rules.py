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

from cassandra import dialect
from cassandra.factpack.schema import (
    AddressFamily,
    BgpNeighbor,
    BgpProcess,
    FhrpGroup,
    FhrpMember,
    Interface,
    InterfaceKind,
    StaticFactPack,
    SwitchportMode,
    TrackedObjectKind,
    VlanId,
    VrfName,
)
from cassandra.findings import Finding, Severity, Tier

Rule = Callable[[StaticFactPack], Iterator[Finding]]
RULES: list[Rule] = []

type Network = ipaddress.IPv4Network | ipaddress.IPv6Network
type Address = ipaddress.IPv4Interface | ipaddress.IPv6Interface
type Host = ipaddress.IPv4Address | ipaddress.IPv6Address
type SubnetKey = tuple[VrfName | None, Network]

# A /30 or /31 with one end in the corpus is far more often a link to something
# the user did not hand us — a carrier handoff, a firewall, a server — than a
# real isolation defect, so the isolation rule stops there.
POINT_TO_POINT_PREFIXLEN: Final = 30

# The same judgement in IPv6, where the numbers are not the same ones. A /64 is
# the ordinary LAN, not a point-to-point link, so reusing the IPv4 threshold
# would exempt every IPv6 subnet there is and the isolation rule would have
# nothing left to say about a dual-stack network. RFC 6164 makes /127 the
# inter-router link.
POINT_TO_POINT_PREFIXLEN_V6: Final = 127

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


def _networks(interface: Interface) -> list[Network]:
    """Every subnet this interface is addressed in, both families together.

    Both families, because most callers ask "is this address on one of them?"
    and `ipaddress` answers that across families for them: an IPv4 address is
    never in an IPv6 network. A caller that instead reports the list, or counts
    it, has to say which family it means — see `_networks_in`.
    """
    nets: list[Network] = []
    for assignment in interface.addresses:
        try:
            nets.append(ipaddress.ip_interface(assignment.prefix).network)
        except ValueError:
            continue
    return nets


def _networks_in(interface: Interface, family: AddressFamily) -> list[Network]:
    """The subnets this interface is addressed in, in one address family.

    What makes a rule about an FHRP group's virtual address family-aware. A
    dual-stack SVI is on an IPv4 subnet and an IPv6 one; asking whether an IPv6
    virtual address is inside "the interface's subnets" and finding the IPv4 one
    there is not an answer, and reporting the IPv4 subnet as the one the address
    should have been inside is a finding about nothing.
    """
    version = 6 if family is AddressFamily.IPV6_UNICAST else 4
    return [net for net in _networks(interface) if net.version == version]


def _host(value: str | None) -> Host | None:
    """`value` as an address, or None when it does not name one.

    Every rule that compares addresses goes through this rather than comparing
    the strings a config happened to spell them with. IPv6 has many spellings of
    one address — `2001:db8::1` and `2001:0DB8:0:0:0:0:0:1` are the same
    gateway — so a string comparison finds a duplicate only when two operators
    typed it the same way, which is the case where it was least likely to be an
    accident.
    """
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _canonical(address: str) -> str:
    """One spelling per address, so two configs that wrote it differently match.

    Falls back to the text as written when it names no address at all, which
    keeps a malformed value comparable with itself — two groups sharing one
    typo are still sharing it — and leaves reporting it to the rule whose job
    that is.
    """
    return str(_host(address) or address)


@rule
def virtual_address_outside_subnet(pack: StaticFactPack) -> Iterator[Finding]:
    """A virtual address outside every subnet the member interface is on.

    Hosts reach their gateway by ARPing for an address on their own subnet. One
    outside it is unreachable from the segment it is supposed to serve, and the
    group otherwise looks healthy: it elects, it advertises, and nothing uses it.

    Silent when the interface has no address at all, since there is then no
    subnet to be outside of, and silent when it has no address in the group's
    own family: an IPv6 group on an interface that is only numbered for IPv4 is
    missing an address, not holding one in the wrong place, and comparing its
    virtual address against the IPv4 subnet would report every dual-stack group
    on a half-numbered interface.

    Silent, too, for an IPv6 virtual address in fe80::/10. RFC 5798 makes the
    link-local address a VRRPv3 group's primary virtual address precisely
    because every interface on the segment already has one, so there is no
    subnet for it to be outside of.
    """
    interfaces = _interfaces(pack)
    for group in pack.fhrp_groups:
        # A mistyped octet is the commonest malformation there is, and the
        # parsers accept any token here. `fhrp-virtual-not-an-address` is the
        # rule that reports it; this one has nothing to say about a string that
        # names no address, and crashing the whole run over it would take every
        # other finding down with it.
        virtual = _host(group.virtual_address)
        if virtual is None or virtual.is_link_local:
            continue
        for member in group.members:
            interface = interfaces.get((member.device, member.interface))
            if interface is None:
                continue
            nets = _networks_in(interface, group.family)
            if nets and not any(virtual in net for net in nets):
                yield Finding(
                    rule="fhrp-virtual-outside-subnet",
                    tier=Tier.FACTS,
                    severity=Severity.HIGH,
                    device=member.device,
                    title=f"{group.label} virtual address is outside its own subnet",
                    detail=f"{group.virtual_address} is not in "
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
        virtual = group.virtual_address
        if not virtual:
            continue
        for member in group.members:
            interface = interfaces.get((member.device, member.interface))
            if interface is None:
                continue
            for assignment in interface.addresses:
                if _canonical(assignment.address) == _canonical(virtual):
                    yield Finding(
                        rule="fhrp-virtual-collides",
                        tier=Tier.FACTS,
                        severity=Severity.HIGH,
                        device=member.device,
                        title=f"{group.label} virtual address collides "
                        f"with a real interface address",
                        detail=f"{virtual} is also configured on {member.interface}",
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
                title=f"{group.label} has only {len(group.members)} member",
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
                title=f"{group.label} has no preferred master",
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
                    title=f"{group.label} tracking can never cause a failover",
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
    """One address configured on two interfaces in the collection.

    Whichever device answers first wins, and which one that is depends on ARP
    timing rather than on anything written down. The usual cause is a config
    copied between devices and edited everywhere except the address, so the
    duplicate is often on the device that was working yesterday.

    Compares addresses, not prefixes: the same address with two different masks
    is still one address two devices claim. Compares them as addresses rather
    than as text, because IPv6 has many spellings of one address and two
    configs that wrote `2001:db8::1` and `2001:0DB8:0:0:0:0:0:1` have made
    exactly this mistake.

    Scoped per VRF, like every other subnet-shaped rule in this module. Two VRFs
    reusing an address is the reason VRFs exist, and the mechanism this rule
    describes — whoever answers ARP first wins — cannot happen between segments
    that never see each other's ARP.
    """
    seen: dict[tuple[VrfName | None, str], str] = {}
    for device in pack.devices:
        for interface in device.interfaces:
            for assignment in interface.addresses:
                where = f"{device.id}:{interface.name}"
                key = (interface.vrf, _canonical(assignment.address))
                if (previous := seen.get(key)) is not None:
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
                seen[key] = where


@rule
def preferred_master_will_not_reclaim(pack: StaticFactPack) -> Iterator[Finding]:
    """The highest-priority member has preempt off, so it never takes back.

    After the first failover the group stays on the backup for good. That is a
    legitimate choice — it avoids a second interruption to move back — but it
    means the priorities in the configuration no longer describe where traffic
    is, and the next person to read them will be wrong about the current state.

    Low severity because it is a defensible configuration. It is reported so the
    choice is visible rather than assumed.

    Silent when the top priority is shared. There is then no preferred master to
    fail to reclaim — firing once per tied member would state, twice and
    contradictorily, that each of them is the preferred one. `fhrp-priority-tie`
    is the finding for that group.
    """
    for group in pack.fhrp_groups:
        if len(group.members) < 2:
            continue
        top = max(m.priority for m in group.members)
        if sum(1 for m in group.members if m.priority == top) > 1:
            continue
        for member in group.members:
            if member.priority == top and not member.preempt:
                yield Finding(
                    rule="fhrp-no-preempt-on-preferred",
                    tier=Tier.FACTS,
                    severity=Severity.LOW,
                    device=member.device,
                    change=dialect.fhrp_change(pack, group, member.device, "preempt"),
                    title=f"{group.label} will not return to its preferred master",
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


def _point_to_point(net: Network) -> bool:
    """True for a prefix too narrow for a missing far end to mean anything."""
    limit = (
        POINT_TO_POINT_PREFIXLEN_V6 if net.version == 6 else POINT_TO_POINT_PREFIXLEN
    )
    return net.prefixlen >= limit


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

    Reported once per set of interfaces rather than once per subnet. A
    dual-stack link is one wire in two subnets and its MTU is one setting, so
    naming it twice would tell the reader they have two problems to fix when
    one edit fixes both.
    """
    reported: set[frozenset[tuple[str, str]]] = set()
    for (_vrf, net), members in _ordered_subnets(pack):
        sized = [i for i in members if i.mtu_bytes is not None]
        values: set[int] = {i.mtu_bytes for i in sized if i.mtu_bytes is not None}
        if len(sized) < 2 or len(values) < 2:
            continue
        who = frozenset((i.device, i.name) for i in sized)
        if who in reported:
            continue
        reported.add(who)
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
        if _point_to_point(net):
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
def virtual_address_is_not_an_address(pack: StaticFactPack) -> Iterator[Finding]:
    """A virtual address that is not an IP address at all.

    A mistyped octet — `10.14.0.300` — is the commonest malformation a config
    has, and the parsers accept whatever token follows the keyword rather than
    guessing at what was meant. Every other rule about the virtual address
    skips a group it cannot read, so without this one the group would be
    checked by nothing and reported as healthy.
    """
    for group in pack.fhrp_groups:
        configured = group.virtual_address
        if configured and _host(configured) is None:
            yield Finding(
                rule="fhrp-virtual-not-an-address",
                tier=Tier.FACTS,
                severity=Severity.HIGH,
                device=group.members[0].device if group.members else "?",
                title=f"{group.label} virtual address is not an address",
                detail=f"{configured!r} does not name an IP address, so "
                f"the group has no gateway to answer for and every other check "
                f"on it was skipped",
                evidence=tuple(f"{m.device}:{m.interface}" for m in group.members),
                remedy="correct the address",
            )


@rule
def virtual_address_is_network_or_broadcast(pack: StaticFactPack) -> Iterator[Finding]:
    """A virtual address that is not a host address at all.

    Distinct from `fhrp-virtual-outside-subnet`: this address *is* inside the
    subnet, which is why that rule stays quiet, but no host may hold it.
    """
    interfaces = _interfaces(pack)
    for group in pack.fhrp_groups:
        virtual = _host(group.virtual_address)
        if virtual is None:
            continue
        for member in group.members:
            interface = interfaces.get((member.device, member.interface))
            if interface is None:
                continue
            for net in _networks_in(interface, group.family):
                # A /31 or /32 — a /127 or /128 in IPv6 — has neither a network
                # nor a broadcast host, so the question does not arise there.
                if net.version != virtual.version:
                    continue
                if net.prefixlen >= net.max_prefixlen - 1:
                    continue
                if virtual not in net:
                    continue
                if virtual == net.network_address:
                    # IPv6 has no broadcast address, and the all-zeros host is
                    # the Subnet-Router anycast rather than a plain unusable
                    # one. Naming it correctly matters: an operator told their
                    # gateway is a "network address" in IPv6 will go looking for
                    # a concept the protocol does not have.
                    role = (
                        "subnet-router anycast address"
                        if net.version == 6
                        else "network address"
                    )
                elif net.version == 4 and virtual == net.broadcast_address:
                    role = "broadcast address"
                else:
                    # The last address of an IPv6 prefix is an ordinary host
                    # address. Reading IPv4's broadcast rule onto it would
                    # condemn a perfectly usable gateway.
                    continue
                yield Finding(
                    rule="fhrp-virtual-not-a-host-address",
                    tier=Tier.FACTS,
                    severity=Severity.HIGH,
                    device=member.device,
                    title=f"{group.label} virtual address is the {role} of its subnet",
                    detail=f"{group.virtual_address} is the {role} of {net}; hosts "
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
    every SVI is ordinary practice — so the subnet is what makes this decidable,
    and the subnet is read in the group's own address family: a dual-stack pair
    of interfaces shares an IPv4 subnet and an IPv6 one, and an IPv6 group's
    two memberships are only in contention if they share the IPv6 one.
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
                shared = sorted(
                    set(_networks_in(a, group.family))
                    & set(_networks_in(b, group.family)),
                    key=str,
                )
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
        if virtual := group.virtual_address:
            by_address.setdefault(_canonical(virtual), []).append(group)

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
    """The lower-case form of a group's label, for use inside a sentence."""
    return group.label.lower()


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
        _canonical(assignment.address): device.id
        for device in pack.devices
        for interface in device.interfaces
        for assignment in interface.addresses
    }


def _reciprocal_neighbor(
    pack: StaticFactPack,
    process: BgpProcess,
    peer_device: str,
    neighbor: BgpNeighbor,
) -> tuple[str, ...]:
    """The neighbor statement the far end is missing.

    Every value in it is already known: the address this device peers from, the
    AS it runs, and the AS the far end runs. What is not known — a description,
    a password, an update-source, a route-map — is left out rather than invented,
    so the line is the minimum that brings the session up and nothing more.
    """
    nos = dialect.nos_of(pack, peer_device)
    if nos is None or not process.local_as:
        return ()
    back = next(
        (
            assignment.address
            for device in pack.devices
            if device.id == process.device
            for interface in device.interfaces
            for assignment in interface.addresses
            if _same_subnet_as(pack, peer_device, assignment.address)
        ),
        None,
    )
    if back is None:
        return ()
    far_as = next((p.local_as for p in pack.bgp if p.device == peer_device), None)
    if not far_as:
        return ()
    return (
        f"router bgp {far_as}",
        f"   neighbor {back} remote-as {process.local_as}",
    )


def _same_subnet_as(pack: StaticFactPack, device: str, address: str) -> bool:
    """Is `address` on a subnet `device` is also addressed in?

    The reciprocal statement has to name an address the far end can actually
    reach, and a device with several interfaces has several candidates.
    """
    try:
        target = ipaddress.ip_address(address)
    except ValueError:
        return False
    for entry in pack.devices:
        if entry.id != device:
            continue
        for interface in entry.interfaces:
            for net in _networks(interface):
                if net.version == target.version and target in net:
                    return True
    return False


@rule
def bgp_session_configured_on_one_side(pack: StaticFactPack) -> Iterator[Finding]:
    """A peering only one end knows about.

    Decidable only when both devices are present, so it stays silent on a
    single-device pack or a peer outside the corpus — an upstream provider is
    not a defect.
    """
    owner = _address_owner(pack)
    local_addresses = {
        device.id: {
            _canonical(a.address) for i in device.interfaces for a in i.addresses
        }
        for device in pack.devices
    }
    configured: dict[tuple[str, str], str] = {}
    for process in pack.bgp:
        for neighbor in process.neighbors:
            address = _canonical(neighbor.address)
            configured[(process.device, address)] = address

    for process in pack.bgp:
        for neighbor in process.neighbors:
            peer_device = owner.get(_canonical(neighbor.address))
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
                # The far end's own address is the one it must peer back to, and
                # both AS numbers are already known — there is nothing left to
                # guess, which is why this rule can state a line and most cannot.
                change=_reciprocal_neighbor(pack, process, peer_device, neighbor),
            )


@rule
def bgp_remote_as_disagrees(pack: StaticFactPack) -> Iterator[Finding]:
    """One end expects an AS the other does not use."""
    owner = _address_owner(pack)
    local_as = {process.device: process.local_as for process in pack.bgp}

    for process in pack.bgp:
        for neighbor in process.neighbors:
            peer_device = owner.get(_canonical(neighbor.address))
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


# --------------------------------------------------------------------------
# Addressing agreement, layer-2 edges, and what a shutdown takes with it
#
# These read parts of the Fact Pack the rules above never touch: the derived
# L3 adjacency graph, `admin_enabled`, `native_vlan`, and `BgpProcess.router_id`.
# --------------------------------------------------------------------------


def _addressed(pack: StaticFactPack) -> list[tuple[Interface, Address]]:
    """Every interface address that makes a claim about a shared segment.

    Host addresses and the kinds in `OFF_THE_WIRE` are excluded: a /32 is a
    routing identity rather than a statement about a wire, and a loopback shares
    a segment with nothing by construction.
    """
    out: list[tuple[Interface, Address]] = []
    for device in pack.devices:
        for interface in device.interfaces:
            if interface.kind in OFF_THE_WIRE:
                continue
            for assignment in interface.addresses:
                try:
                    address = ipaddress.ip_interface(assignment.prefix)
                except ValueError:
                    continue
                if address.network.prefixlen == address.network.max_prefixlen:
                    continue
                out.append((interface, address))
    return out


@rule
def prefix_length_disagreement(pack: StaticFactPack) -> Iterator[Finding]:
    """Two devices on one wire that disagree about how wide the wire is.

    One address falls inside the other's subnet, so by the operator's own
    arithmetic the two interfaces are on one segment — but the masks differ, so
    the ends hold different beliefs about which destinations are local. The end
    with the wider mask ARPs for addresses the end with the narrower mask sends
    to its default gateway, and the range where they disagree is reachable in
    one direction only. Every ping between the two interface addresses succeeds,
    which is what lets this survive for years.

    Silent when the prefix lengths agree, and when neither address is inside the
    other's subnet — two unrelated subnets are not a disagreement about one.
    Silent on loopbacks and host addresses, which describe no segment, and
    across VRFs, where two devices sharing a subnet is the point of the VRF.
    """
    for (a_interface, a), (b_interface, b) in itertools.combinations(
        _addressed(pack), 2
    ):
        if a_interface.device == b_interface.device:
            continue
        if a_interface.vrf != b_interface.vrf or a.version != b.version:
            continue
        if a.network.prefixlen == b.network.prefixlen:
            continue
        if a.ip not in b.network and b.ip not in a.network:
            continue
        wider, narrower = sorted((a.network, b.network), key=lambda net: net.prefixlen)
        yield Finding(
            rule="subnet-mask-disagreement",
            tier=Tier.FACTS,
            severity=Severity.HIGH,
            device=a_interface.device,
            title=f"{a_interface.device} and {b_interface.device} share a segment "
            f"with different masks",
            detail=f"{a} and {b} overlap — one of them is inside the other's "
            f"subnet — so the two interfaces are on one wire with two different "
            f"ideas of how far it reaches; the addresses in {wider} but outside "
            f"{narrower} are local to one end and remote to the other, so traffic "
            f"to them is delivered in one direction only",
            evidence=(
                f"{a_interface.device}:{a_interface.name} {a}",
                f"{b_interface.device}:{b_interface.name} {b}",
            ),
            remedy=f"agree one mask for the segment: /{narrower.prefixlen} at both "
            f"ends, or /{wider.prefixlen} at both",
        )


@rule
def device_reachable_only_through_shutdown_interfaces(
    pack: StaticFactPack,
) -> Iterator[Finding]:
    """A device whose every link into these configs is administratively down.

    The device is addressed in a subnet another device also uses, and every one
    of its own interfaces in such a subnet is shut. Nothing here can be an IGP,
    BGP, BFD or FHRP neighbour of it, so it is off the network while its
    configuration still reads as a fully connected device — the shape a box
    takes after a maintenance shutdown nobody undid.

    Reads the derived L3 adjacency graph, which already omits shut interfaces,
    and then asks whether re-admitting them would connect the device. Silent for
    a device that has a live neighbour, for a device that shares no subnet with
    anything in the pack — a peer outside the corpus is an incomplete collection
    rather than a defect — and for a pure layer-2 switch, which has no addresses
    to share in the first place.
    """
    if len(pack.devices) < 2:
        return
    connected = {ref.device for adj in pack.l3_adjacencies for ref in adj.members}
    shared = [
        (net, members)
        for (_vrf, net), members in _ordered_subnets(pack)
        if len({i.device for i in members}) > 1
    ]
    for device in pack.devices:
        if device.id in connected:
            continue
        stranded = [
            (interface, net)
            for net, members in shared
            for interface in members
            if interface.device == device.id and not interface.admin_enabled
        ]
        if not stranded:
            continue
        subnets = ", ".join(str(net) for _interface, net in stranded)
        yield Finding(
            rule="device-isolated-by-shutdown",
            tier=Tier.FACTS,
            severity=Severity.HIGH,
            device=device.id,
            title=f"every interface joining {device.id} to these configs is shut down",
            detail=f"{device.id} is addressed in {subnets}, which other devices "
            f"here also use, but each of its own interfaces in those subnets is "
            f"administratively down; no neighbour in this collection can reach it "
            f"and none of its adjacencies can come up",
            evidence=tuple(
                f"{interface.device}:{interface.name} {net} shutdown"
                for interface, net in stranded
            ),
            remedy="bring one of those interfaces up, or take the device out of "
            "the collection if it is genuinely decommissioned",
        )


@rule
def access_vlan_leaves_on_no_trunk(pack: StaticFactPack) -> Iterator[Finding]:
    """An access port in a VLAN that cannot leave the switch it is on.

    The port's VLAN is used elsewhere — another device has an SVI or an access
    port in it — but on this device no trunk permits it and no SVI terminates
    it. Whatever is plugged in comes up, learns MAC addresses from nothing, and
    reaches neither its gateway nor any other member of the VLAN. The usual
    cause is a port moved into a service VLAN that the uplink's allowed list was
    never extended to carry.

    Silent when a trunk on the device permits the VLAN, when the device has an
    SVI for it, and when the device has no trunk at all — a standalone switch is
    not failing to forward anywhere. Silent, too, when the VLAN appears nowhere
    else in the collection: unused ports parked in a spare VLAN look exactly
    like this and are deliberate.
    """
    terminated: dict[VlanId, set[str]] = {}
    for device in pack.devices:
        for interface in device.interfaces:
            if (vlan := _svi_vlan(interface)) is not None:
                terminated.setdefault(vlan, set()).add(device.id)
            if interface.access_vlan is not None:
                terminated.setdefault(interface.access_vlan, set()).add(device.id)

    for device in pack.devices:
        trunks = [i for i in device.interfaces if i.allowed_vlans]
        if not trunks:
            continue
        carried = {vlan for trunk in trunks for vlan in trunk.allowed_vlans}
        svis = {
            vlan
            for interface in device.interfaces
            if (vlan := _svi_vlan(interface)) is not None
        }
        for interface in device.interfaces:
            vlan = interface.access_vlan
            if vlan is None or not interface.admin_enabled:
                continue
            if vlan in carried or vlan in svis:
                continue
            elsewhere = sorted(terminated.get(vlan, set()) - {device.id})
            if not elsewhere:
                continue
            yield Finding(
                rule="access-vlan-not-trunked",
                tier=Tier.FACTS,
                severity=Severity.HIGH,
                device=device.id,
                title=f"{interface.name} is in VLAN {vlan}, which leaves "
                f"{device.id} on no trunk",
                detail=f"VLAN {vlan} is terminated on "
                + ", ".join(elsewhere)
                + f", but no trunk on {device.id} permits it and there is no SVI "
                f"for it here, so anything on {interface.name} is confined to this "
                f"switch and has no route to its gateway",
                evidence=(
                    f"{device.id}:{interface.name} access vlan {vlan}",
                    *(
                        f"{device.id}:{trunk.name} allowed "
                        + ",".join(str(v) for v in trunk.allowed_vlans)
                        for trunk in trunks
                    ),
                ),
                remedy=f"add VLAN {vlan} to the trunk that carries this switch's "
                f"uplink, or move the port to a VLAN the uplink already carries",
            )


@rule
def native_vlan_not_permitted_on_the_trunk(pack: StaticFactPack) -> Iterator[Finding]:
    """A trunk whose native VLAN is missing from its own allowed list.

    The native VLAN is the one the trunk sends and expects untagged. When the
    allowed list does not contain it the untagged traffic is discarded at both
    ends, silently and in both directions — the trunk comes up, every tagged
    VLAN on it works, and only the one service that was never tagged fails.

    Only checked where both facts are present: a trunk stating no allowed list
    permits everything on real hardware, and the Fact Pack does not distinguish
    that from a construct the parser did not read, so it is left alone.
    """
    for device in pack.devices:
        for interface in device.interfaces:
            native = interface.native_vlan
            if native is None or not interface.allowed_vlans:
                continue
            if interface.switchport_mode is not SwitchportMode.TRUNK:
                continue
            if native in interface.allowed_vlans:
                continue
            allowed = ",".join(str(v) for v in interface.allowed_vlans)
            yield Finding(
                rule="trunk-native-vlan-not-allowed",
                tier=Tier.FACTS,
                severity=Severity.MEDIUM,
                device=device.id,
                title=f"{interface.name} is native in VLAN {native} but does not "
                f"permit it",
                detail=f"the trunk sends VLAN {native} untagged and its allowed "
                f"list is {allowed}, so every untagged frame on the link is "
                f"dropped while the tagged VLANs keep working",
                evidence=(
                    f"{device.id}:{interface.name} native vlan {native}",
                    f"{device.id}:{interface.name} allowed {allowed}",
                ),
                remedy=f"add VLAN {native} to the allowed list, or make a "
                f"permitted VLAN the native one",
                change=dialect.under_interface(
                    nos, interface.name, f"switchport trunk allowed vlan add {native}"
                )
                if (nos := dialect.nos_of(pack, device.id))
                else (),
            )


@rule
def fhrp_members_addressed_on_different_subnets(
    pack: StaticFactPack,
) -> Iterator[Finding]:
    """A redundancy group whose two halves are not on the same subnet.

    Two devices run the same protocol, the same group number and the same
    virtual address, which is as explicit as intent gets — and their interfaces
    are addressed in different subnets, so the Fact Pack holds them as two
    separate one-member groups rather than one pair. Each device is master of
    its own group, neither backs the other up, and the failover the numbers
    describe does not exist. A wrong octet or a wrong mask on one side produces
    exactly this, and both configurations look correct read on their own.

    Requires the group number *and* the virtual address to match, so reusing
    group 1 on every SVI — ordinary practice — stays silent. Silent, too, when
    the members share a subnet, which is the case where the group really is one
    group, and across address families: a group's IPv4 half being on
    10.14.0.0/24 while its IPv6 half is on 2001:db8:14::/64 is what a dual-stack
    segment looks like, not a split.
    """
    by_intent: dict[tuple[str, int, str, str], list[FhrpGroup]] = {}
    for group in pack.fhrp_groups:
        virtual = group.virtual_address
        if virtual and group.subnet:
            key = (
                group.protocol.value,
                group.group_number,
                group.family.value,
                virtual,
            )
            by_intent.setdefault(key, []).append(group)

    for (_protocol, _number, _family, virtual), groups in sorted(by_intent.items()):
        subnets = sorted({group.subnet for group in groups if group.subnet})
        devices = sorted({m.device for group in groups for m in group.members})
        if len(subnets) < 2 or len(devices) < 2:
            continue
        label = groups[0].label
        yield Finding(
            rule="fhrp-members-on-different-subnets",
            tier=Tier.FACTS,
            severity=Severity.HIGH,
            device=devices[0],
            title=f"{label} is split across " + " and ".join(subnets),
            detail=", ".join(devices)
            + f" all run {label.lower()} with virtual address {virtual}, but "
            f"their interfaces are addressed in different subnets, so they are not "
            f"members of one group: each is master of its own and none of them "
            f"backs up any other",
            evidence=tuple(
                f"{member.device}:{member.interface} {group.subnet} "
                f"priority {member.priority}"
                for group in groups
                for member in group.members
            ),
            remedy=f"put every member of {label.lower()} in one subnet, or "
            f"give the groups that are genuinely separate their own numbers and "
            f"virtual addresses",
        )


@rule
def bgp_peer_behind_a_shutdown_interface(pack: StaticFactPack) -> Iterator[Finding]:
    """A peering that can only run over an interface that is shut down.

    Two shapes, one consequence. The peer address is on a subnet this device
    reaches through shut interfaces only, or the session's update source is
    itself shut. Either way the session cannot open, and the configuration reads
    as a healthy peering — the neighbour statement is present, the remote AS is
    right, and there is no `shutdown` under the BGP process to explain it.

    Silent when the neighbour is explicitly shut, which says the operator meant
    it, and when any interface carrying the peer's subnet is up. Silent when the
    peer address is on no local subnet at all: an update source, a multihop
    session or a plain typo are somebody else's finding.
    """
    for process in pack.bgp:
        device = next((d for d in pack.devices if d.id == process.device), None)
        if device is None:
            continue
        by_name = {interface.name: interface for interface in device.interfaces}
        for neighbor in process.neighbors:
            if neighbor.shutdown:
                continue
            source = by_name.get(neighbor.update_source or "")
            if source is not None and not source.admin_enabled:
                yield Finding(
                    rule="bgp-peer-behind-shutdown",
                    tier=Tier.FACTS,
                    severity=Severity.HIGH,
                    device=process.device,
                    title=f"BGP peering with {neighbor.address} is sourced from "
                    f"{source.name}, which is shut down",
                    detail="the session takes its local address from an interface "
                    "that is administratively down, so it has no source address "
                    "and never leaves Idle",
                    evidence=(
                        f"{process.device} AS {process.local_as} -> {neighbor.address}",
                        f"{process.device}:{source.name} shutdown",
                    ),
                    remedy=f"bring {source.name} up, or source the session from an "
                    f"interface that is",
                )
                continue
            if neighbor.update_source or neighbor.multihop:
                continue
            try:
                address = ipaddress.ip_address(neighbor.address)
            except ValueError:
                continue
            carrying = [
                interface
                for interface in device.interfaces
                if any(address in net for net in _networks(interface))
            ]
            if not carrying or any(i.admin_enabled for i in carrying):
                continue
            yield Finding(
                rule="bgp-peer-behind-shutdown",
                tier=Tier.FACTS,
                severity=Severity.HIGH,
                device=process.device,
                title=f"BGP peer {neighbor.address} is only reachable over an "
                f"interface that is shut down",
                detail="every interface on this device addressed in the peer's "
                "subnet is administratively down, so the TCP session cannot be "
                "established and the peering stays in Idle or Active",
                evidence=(
                    f"{process.device} AS {process.local_as} -> {neighbor.address}",
                    *(
                        f"{process.device}:{interface.name} shutdown"
                        for interface in carrying
                    ),
                ),
                remedy="bring the interface up, or move the peering to one that is "
                "carrying traffic",
            )


@rule
def bgp_router_id_duplicated(pack: StaticFactPack) -> Iterator[Finding]:
    """One BGP router-id claimed by two devices.

    The router-id is the BGP identifier in the OPEN message and the tie-breaker
    in best-path selection, and it has to be unique. Two devices sharing one
    cannot peer with each other at all — the OPEN is rejected as a collision —
    and where they peer with a common neighbour instead, that neighbour treats
    the second session as a duplicate of the first and the two routers take
    turns holding it.

    Silent for a device that states no router-id, since the platform then
    derives one from an interface address this tool cannot predict, and silent
    where one device declares the same id twice, which is one router, not two.
    """
    by_id: dict[str, list[BgpProcess]] = {}
    for process in pack.bgp:
        if process.router_id:
            by_id.setdefault(process.router_id, []).append(process)

    for router_id, processes in sorted(by_id.items()):
        devices = sorted({process.device for process in processes})
        if len(devices) < 2:
            continue
        yield Finding(
            rule="bgp-router-id-duplicate",
            tier=Tier.FACTS,
            severity=Severity.HIGH,
            device=devices[0],
            title=f"BGP router-id {router_id} is claimed by " + " and ".join(devices),
            detail="the router-id is the BGP identifier and has to be unique; two "
            "devices carrying the same one cannot peer with each other, and a "
            "common neighbour sees the second session as a duplicate of the first",
            evidence=tuple(
                f"{process.device}: router bgp {process.local_as} router-id {router_id}"
                for process in processes
            ),
            remedy="give each device its own router-id, conventionally its "
            "loopback address",
        )
