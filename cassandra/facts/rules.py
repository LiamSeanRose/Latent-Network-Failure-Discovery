"""FACTS tier — deterministic assertions over the Fact Pack.

No lab, no model, no ambiguity: everything here is decidable from the configs
alone, so a finding is either true of the text or it is a bug in a rule.

Each rule states what it checked and what would remove the finding, because a
finding the user cannot act on is noise (PROJECT.md §5.4).
"""

from __future__ import annotations

import ipaddress
import itertools
from collections.abc import Callable, Iterable, Iterator
from typing import Final

from cassandra import dialect
from cassandra.factpack.schema import (
    AddressFamily,
    BgpNeighbor,
    BgpProcess,
    Device,
    FhrpGroup,
    FhrpMember,
    Interface,
    InterfaceKind,
    L2Segment,
    StaticFactPack,
    StpMode,
    SwitchportMode,
    TimerSource,
    TrackedObjectKind,
    VlanId,
    VrfName,
)
from cassandra.factpack.topology import DEFAULT_BRIDGE_PRIORITY
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

    "Too small" includes landing exactly on the best rival: both VRRP and HSRP
    need a strictly greater priority to displace a live master, which is the
    same protocol fact `cassandra.timing.model._settle` encodes as A6. A
    decrement to equality is therefore no failover either, and it is the shape
    an operator most easily writes by subtracting the difference itself.

    It says nothing about *when* the failover happens, only that it can. A
    decrement large enough to lose the election on a peer that does not preempt,
    or preempts late, is the TIMING tier's subject and not this rule's.
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
            # A6: an equal priority never displaces a live master, so equality
            # is as ineffective as staying above the rival.
            if member.priority - total >= max(rivals):
                yield Finding(
                    rule="fhrp-track-ineffective",
                    tier=Tier.FACTS,
                    severity=Severity.MEDIUM,
                    device=member.device,
                    title=f"{group.label} tracking can never cause a failover",
                    detail=f"priority {member.priority} minus the total decrement "
                    f"{total} is {member.priority - total}, which does not fall "
                    f"below the highest peer priority {max(rivals)}",
                    evidence=tuple(
                        f"{t.id}->{t.target} -{t.decrement}"
                        for t in member.tracked_objects
                    ),
                    # A6 again: the decrement has to land the priority *below*
                    # the rival, so the smallest one that works is one more than
                    # the gap, not the gap itself.
                    remedy=f"increase the total decrement to at least "
                    f"{member.priority - max(rivals) + 1}",
                )


@rule
def svi_vlan_missing_from_every_trunk(pack: StaticFactPack) -> Iterator[Finding]:
    """An addressed SVI for a VLAN no trunk on the device carries.

    The interface is up and has an address, so the device can route for the
    VLAN; nothing can reach it, because the VLAN leaves on no uplink. It is the
    shape a VLAN takes after it is removed from a trunk's allowed list during
    some unrelated cleanup and the SVI is left behind.

    Both halves of that sentence are checked, not assumed. An SVI with no
    address routes for nothing and a shut one forwards nothing, so neither can
    exhibit the failure described above — and an SVI left shut and unaddressed
    is what a decommissioned VLAN usually looks like in a config that was
    tidied only halfway.

    Only checked on devices that have at least one trunk. A device with none is
    not carrying VLANs anywhere, which is a different thing entirely.

    Silent where an access port on the device sits in the VLAN, and where a
    subinterface tags it. Whatever is plugged into an access port is in that
    broadcast domain, so "the VLAN reaches no neighbour" is not something this
    can say — the far end may be a host, and it may be the other gateway on a
    cable somebody ran between two access ports. A subinterface puts the VLAN on
    the wire with no switchport involved at all. Both cases were reported for a
    while, in a sentence asserting isolation the configuration contradicted.

    It says nothing about whether the neighbour behind the trunk carries the
    VLAN either: one trunk on this device permitting it is enough to silence
    the rule, because pruning at the far end is a different defect.
    """
    for device in pack.devices:
        # A trunk that states `allowed vlan none` is a trunk, and one carrying
        # nothing on purpose is exactly the shape this rule is about — it was
        # excluded for having an empty list, which made writing `none` turn the
        # check off.
        trunks = [
            i for i in device.interfaces if i.allowed_vlans or i.trunk_allowed_stated
        ]
        if not trunks:
            continue
        carried = {vlan for trunk in trunks for vlan in trunk.allowed_vlans}
        # Every other way this device puts the VLAN on a wire. An access port
        # reaches whatever is plugged into it; a subinterface tags the VLAN off
        # the box with no switchport involved, so a trunk list says nothing
        # about it. Either makes "the VLAN reaches no neighbour" untrue.
        reaching = {
            i.access_vlan
            for i in device.interfaces
            if i.admin_enabled
            and i.access_vlan
            and i.switchport_mode is not SwitchportMode.TRUNK
        } | {
            i.dot1q_vlan for i in device.interfaces if i.admin_enabled and i.dot1q_vlan
        }
        for interface in device.interfaces:
            if not interface.name.startswith("Vlan"):
                continue
            vlan_id = interface.name.removeprefix("Vlan")
            if not vlan_id.isdigit():
                continue
            # Each precondition its own statement, so `cassandra/coverage.py`
            # can tell which one a silent run stopped at.
            if not interface.addresses:
                continue
            if not interface.admin_enabled:
                continue
            if int(vlan_id) in carried:
                continue
            if int(vlan_id) in reaching:
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

    How it got that way changes what the finding means, and `preempt_source`
    carries the difference. A line that says `no preempt` is a decision
    somebody made, and this reports it so the decision is visible rather than
    assumed. An HSRP group that simply never turned preemption on inherited the
    protocol's default, and the priorities were very likely written by somebody
    who believed the higher one would win — which is a different sentence, a
    different remedy, and the commoner of the two.

    Low either way. The group works; what is wrong is a belief about where it
    will be. Raising the second case would be claiming to know which of the two
    the operator meant, and the configuration does not say.

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
            if member.priority != top or member.preempt:
                continue
            deliberate = member.preempt_source is TimerSource.CONFIGURED
            how = (
                "preempt is turned off on it"
                if deliberate
                else f"nothing turns preempt on and {group.protocol.value.upper()} "
                f"defaults it off"
            )
            yield Finding(
                rule="fhrp-no-preempt-on-preferred",
                tier=Tier.FACTS,
                severity=Severity.LOW,
                device=member.device,
                change=dialect.fhrp_change(pack, group, member.device, "preempt"),
                title=f"{group.label} will not return to its preferred master",
                detail=f"{member.device} has the highest priority ({top}) but "
                f"{how}, so after any failover the group stays on the backup "
                f"indefinitely"
                + (
                    ""
                    if deliberate
                    else " — the priorities say which device was meant to hold "
                    "it and nothing makes that happen"
                ),
                evidence=(f"{member.device}:{member.interface}",),
                # The same edit either way, because the positive form of the
                # command is what cancels the negative one on every dialect
                # here — so the suggested change is right in both cases and
                # only the sentence around it moves.
                remedy=(
                    "accept that the placement is not deterministic, or turn "
                    "preempt back on"
                )
                if deliberate
                else "enable preempt, or lower this device's priority to the "
                "one that is actually going to hold the group",
            )


# --------------------------------------------------------------------------
# Subnet-shaped rules
#
# These index the subnets themselves rather than reading `l3_adjacencies`: two
# addressed interfaces are on the same wire when their prefixes reduce to the
# same network in the same VRF, which is an assumption, and the same one the
# operator made when they typed the addresses. The derived graph makes it too,
# and drops every shut interface on the way — which is exactly what
# `device-isolated-by-shutdown` has to be able to see, so it reads this index
# and the graph both.
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
        # A trunk that states `allowed vlan none` is a trunk, and one carrying
        # nothing on purpose is exactly the shape this rule is about — it was
        # excluded for having an empty list, which made writing `none` turn the
        # check off.
        trunks = [
            i for i in device.interfaces if i.allowed_vlans or i.trunk_allowed_stated
        ]
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


# --------------------------------------------------------------------------
# Broadcast domains
#
# Everything below reads `l2_segments` and `l2_adjacencies`, which no rule above
# opens. A segment lists one VLAN's members; the adjacencies say which of those
# members can hear each other. Together they answer "are these two gateways on
# one wire?", where the rules above can only ask "does this device mention the
# VLAN?" and take the answer per device.
#
# Which direction the derivation errs in is what makes that safe.
# `topology.py` builds `l2_adjacencies` from co-membership rather than from
# cabling, so it claims *more* connectivity than the text can prove: every trunk
# permitting VLAN 20 is joined to every other trunk permitting VLAN 20, cable or
# no cable. Two devices the graph leaves in separate components are therefore
# separated under the most generous reading the pack allows, which is the only
# direction in which a missing edge is safe to reason from. The cost is a split
# that needs layer-1 data to see — two islands that both trunk the VLAN and are
# not cabled to each other — and that one stays invisible here rather than being
# guessed at.
# --------------------------------------------------------------------------


def _broadcast_domains(
    pack: StaticFactPack,
) -> dict[VlanId, dict[str, frozenset[str]]]:
    """Per VLAN, the set of devices each device in its segment can hear.

    A device that reaches nobody maps to a set holding only itself, so the
    caller never has to distinguish "no entry" from "alone".
    """
    return {
        segment.vlan_id: _components(
            {ref.device for ref in segment.members},
            (
                (adjacency.a.device, adjacency.b.device)
                for adjacency in pack.l2_adjacencies
                if segment.vlan_id in adjacency.vlans
            ),
        )
        for segment in pack.l2_segments
        if segment.vlan_id is not None
    }


def _components(
    devices: set[str], edges: Iterable[tuple[str, str]]
) -> dict[str, frozenset[str]]:
    """Connected components, as a lookup from a device to the one it is in."""
    groups: dict[str, set[str]] = {device: {device} for device in devices}
    for a, b in edges:
        if a not in groups or b not in groups or groups[a] is groups[b]:
            continue
        joined = groups[a] | groups[b]
        # One set object shared by every member, so the next edge that touches
        # any of them merges the whole component rather than one device of it.
        for device in joined:
            groups[device] = joined
    return {device: frozenset(group) for device, group in groups.items()}


def _vlan_cannot_leave(device: Device, vlan_id: VlanId) -> bool:
    """Is it certain that nothing on this device puts `vlan_id` on a wire?

    This is the guard that decides whether a split may be reported at all, and
    it is deliberately asymmetric: it answers False both for a device that
    carries the VLAN and for a device the pack cannot account for, because an
    incomplete capture must not make a neighbour look partitioned. A directory
    is almost never the whole network, and a rule that reads absence of evidence
    as evidence of absence reports every partial collection as a broken one.

    Four things make the answer unknown rather than no:

    * The device has no trunk at all. It is then a router terminating a VLAN it
      does not bridge — the reading `svi-vlan-not-trunked` already gives that
      shape — or a switch whose uplink nothing parsed.
    * A live trunk states no allowed list. Real hardware permits every VLAN on
      such a trunk, and an empty `allowed_vlans` in the fact pack is equally
      consistent with a construct no parser read;
      `trunk-native-vlan-not-allowed` declines to read it for the same reason.
      `switchport trunk allowed vlan none` is *not* that case and must not be
      confused with it: it permits nothing on purpose, `trunk_allowed_stated`
      is what tells the two apart, and reading the deliberate one as unknown
      made the strictly worse configuration produce strictly fewer findings.
    * A subinterface tags the VLAN off the box. `dot1q_vlan` puts a VLAN on the
      wire with no switchport involved, so a trunk list says nothing about it.
    * An access port sits in the VLAN. Whatever is plugged into it is in that
      broadcast domain, and a configuration does not say what — a host, or the
      other gateway on the far end of a cable somebody ran between two access
      ports. This one was found by an adversarial read after the rule shipped:
      two gateways joined by exactly that link were reported as a split subnet,
      in a HIGH finding whose text asserted two broadcast domains where there
      was one.

      The cost of it is stated rather than hidden: a gateway with ordinary host
      access ports in the VLAN now silences the rule, and that is the shape a
      real split often has. It is the right trade because the alternative is a
      finding that claims proof it does not have. `access-vlan-not-trunked`
      still reports the per-port half of the same cut, which is decidable
      without knowing what is on the other end of the cable.

    Counted over live interfaces only. A device whose every trunk is shut really
    cannot carry the VLAN, and this still declines to say so: everything about
    such a box is off the network, `device-isolated-by-shutdown` says that in
    one finding, and repeating it once per VLAN would bury it.
    """
    live = [interface for interface in device.interfaces if interface.admin_enabled]
    trunks = [
        interface
        for interface in live
        if interface.switchport_mode is SwitchportMode.TRUNK or interface.allowed_vlans
    ]
    if not trunks:
        return False
    if any(
        not trunk.allowed_vlans and not trunk.trunk_allowed_stated for trunk in trunks
    ):
        return False
    if any(vlan_id in trunk.allowed_vlans for trunk in trunks):
        return False
    if any(
        interface.access_vlan == vlan_id
        for interface in live
        if interface.switchport_mode is not SwitchportMode.TRUNK
    ):
        return False
    return not any(interface.dot1q_vlan == vlan_id for interface in live)


def _svi_gateways(
    pack: StaticFactPack,
) -> dict[tuple[VrfName | None, Network, VlanId], dict[str, str]]:
    """Every live, addressed SVI, indexed by the subnet and VLAN it serves.

    Keyed per VRF like every other subnet-shaped rule in this module, and host
    prefixes are left out: a /32 on an SVI is a routing identity rather than a
    claim about a broadcast domain.
    """
    index: dict[tuple[VrfName | None, Network, VlanId], dict[str, str]] = {}
    for device in pack.devices:
        for interface in device.interfaces:
            vlan_id = _svi_vlan(interface)
            if vlan_id is None or not interface.admin_enabled:
                continue
            for net in _networks(interface):
                if net.prefixlen == net.max_prefixlen:
                    continue
                index.setdefault((interface.vrf, net, vlan_id), {})[device.id] = (
                    interface.name
                )
    return index


def _halves(
    devices: Iterable[str], domains: dict[str, frozenset[str]]
) -> list[list[str]]:
    """The devices grouped by broadcast domain, largest group first.

    A device the segment does not hold is its own group. That happens only for a
    caller asking about a device with no interface in the VLAN at all, and
    answering "alone" rather than raising keeps the question decidable.
    """
    parts: dict[frozenset[str], list[str]] = {}
    for device in sorted(devices):
        parts.setdefault(domains.get(device, frozenset({device})), []).append(device)
    return sorted(parts.values(), key=lambda part: (-len(part), part[0]))


def _cut_off(part: list[str], devices: dict[str, Device], vlan_id: VlanId) -> bool:
    """May this whole group of devices be said to be sealed off from the VLAN?

    Every device in it has to be, and a device the pack does not hold counts
    against: one member with an unread uplink is a path for the whole group.
    """
    return all(
        device in devices and _vlan_cannot_leave(devices[device], vlan_id)
        for device in part
    )


def _add_vlan_to_the_only_trunk(
    pack: StaticFactPack, device: Device, vlan_id: VlanId
) -> tuple[str, ...]:
    """The edit, but only where the device has one trunk it could go on.

    Which uplink a VLAN belongs on is a decision about the VLAN plan, and a
    device with two trunks has two answers this tool cannot choose between —
    so it says nothing there, as `cassandra.dialect` requires of everything
    that writes a line.
    """
    nos = dialect.nos_of(pack, device.id)
    trunks = [i for i in device.interfaces if i.admin_enabled and i.allowed_vlans]
    if nos is None or len(trunks) != 1:
        return ()
    return dialect.under_interface(
        nos, trunks[0].name, f"switchport trunk allowed vlan add {vlan_id}"
    )


@rule
def vlan_broadcast_domain_is_split(pack: StaticFactPack) -> Iterator[Finding]:
    """One subnet on one VLAN, in two broadcast domains that cannot hear each other.

    Two devices are addressed in the same subnet on the same VLAN, both SVIs are
    up, and nothing in the segment carries that VLAN between them. Each half
    resolves ARP among its own members and behaves as though it were the whole
    subnet: hosts get an answer, the answer is the gateway on their own side,
    and every frame addressed across the divide is flooded into a domain the
    destination is not in and discarded. The two configurations read as correct
    on their own, and the halves only ever meet in a traceroute nobody ran.

    HIGH because the loss is silent, total between the halves, and invisible to
    every device involved: the interfaces are up, the VLAN is declared, the
    addresses are inside the subnet, and no counter increments. Whatever the
    subnet was carrying — an IGP adjacency, a BGP session, an FHRP election,
    hosts talking to each other — is down for as long as the trunk list stands.

    `access-vlan-not-trunked` reports the same cut where an access port is what
    is stranded, and reports it per port; this reports it per subnet, between
    the two gateways that were meant to be one. `svi-vlan-not-trunked` reports
    one device's half of it without knowing whether anything is on the other
    side. Both stay quiet on a device with no trunks, and so does this.

    Silent unless one side provably cannot carry the VLAN off itself at all: a
    device with no trunk, a device with a trunk that states no allowed list, and
    a device with a subinterface tagging the VLAN each leave the question open
    rather than answered, and an open question is not a finding. Silent,
    therefore, on a collection that is missing the switch in the middle — the
    halves are joined as long as both ends permit the VLAN on a trunk, so an
    uncaptured device between two well-configured ones produces nothing.

    Silent when only one device is addressed in the subnet, which is
    `l3-interface-isolated`'s subject and not a split; when the SVI is shut or
    unaddressed, since a broadcast domain it is not in cannot be divided by it;
    and across VRFs, where two devices holding one subnet is the point.
    """
    devices = {device.id: device for device in pack.devices}
    domains = _broadcast_domains(pack)
    for (_vrf, net, vlan_id), gateways in sorted(_svi_gateways(pack).items(), key=str):
        if len(gateways) < 2:
            continue
        parts = _halves(gateways, domains.get(vlan_id, {}))
        if len(parts) < 2:
            continue
        home, *rest = parts
        for part in rest:
            # Whichever side is provably sealed off is the side to name: it is
            # the one whose trunks have to change, and the claim that the two
            # cannot reach each other rests on its configuration alone. A sealed
            # part is always one device — a second device in it would need a
            # trunk permitting the VLAN, which is what being sealed rules out.
            if _cut_off(part, devices, vlan_id):
                blamed, far = part, home
            elif _cut_off(home, devices, vlan_id):
                blamed, far = home, part
            else:
                continue
            device = blamed[0]
            interface = gateways[device]
            trunks = [
                i
                for i in devices[device].interfaces
                if i.admin_enabled and i.allowed_vlans
            ]
            yield Finding(
                rule="vlan-segment-split",
                tier=Tier.FACTS,
                severity=Severity.HIGH,
                device=device,
                title=f"{net} is split in two: {device}:{interface} is alone in "
                f"VLAN {vlan_id}",
                detail=", ".join(far)
                + f" {'is' if len(far) == 1 else 'are'} addressed in {net} too, and "
                f"no trunk carries VLAN {vlan_id} between "
                f"{'it' if len(far) == 1 else 'them'} and {device}, so the "
                f"subnet is two broadcast domains rather than one; each half "
                f"resolves ARP among its own members and answers as the whole "
                f"subnet, and traffic across the divide is flooded into a domain "
                f"the destination is not in and dropped without an error anywhere",
                evidence=(
                    *(
                        f"{device}:{trunk.name} allowed "
                        + ",".join(str(v) for v in trunk.allowed_vlans)
                        for trunk in trunks
                    ),
                    *(f"{other}:{gateways[other]} {net}" for other in far),
                ),
                remedy=f"add VLAN {vlan_id} to the trunk carrying {device}'s "
                f"uplink, or move the SVI onto a VLAN that trunk already permits",
                change=_add_vlan_to_the_only_trunk(pack, devices[device], vlan_id),
            )


@rule
def fhrp_members_in_different_broadcast_domains(
    pack: StaticFactPack,
) -> Iterator[Finding]:
    """A redundancy group whose members cannot hear each other's advertisements.

    Every member of the group runs an SVI for the same VLAN in the same subnet —
    which is what makes them one group — and the segment carries that VLAN
    between none of them. FHRP elects by listening: a member that hears nothing
    from a higher priority is master, so each of them is master, and the virtual
    address is live on every device at once. So is the virtual MAC, which both
    protocols derive from the group number rather than from the device, so the
    duplication the operator would eventually see in an ARP table is not even
    two MACs to tell apart.

    HIGH, and the argument is what happens next rather than what happens now.
    While the halves stay apart each side has a working gateway and nothing is a
    backup: the failover the priorities describe cannot happen, because the
    device that would take over is not listening to the one that would fail. The
    moment the VLAN is carried between them — a trunk edited, a cable moved, a
    port unshut — the two masters hear each other, one stands down, and every
    host that had resolved the loser's gateway is off the network until its ARP
    entry expires. A redundancy group is the one thing in a config bought
    specifically to survive an event, and this is it failing at the event.

    `fhrp-members-on-different-subnets` is the layer-3 form of the same
    accident, where the addressing itself disagrees; here the addressing agrees
    exactly and the wire does not.

    Silent when any member sits on an interface the pack cannot place in a
    broadcast domain — an IOS-XR BVI, a dot1q subinterface, a routed port. The
    VLAN an interface belongs to has to be read off its name, so a naming
    convention this tool does not know produces no claim rather than a guess.

    Silent when the members are on SVIs for different VLAN ids, which is
    `subnet-spans-two-vlans`, and silent on a one-member group, which is
    `fhrp-no-redundancy`. Silent, like `vlan-segment-split`, unless the stranded
    member's device provably cannot carry the VLAN off itself, so a collection
    missing the switch between two members produces nothing.
    """
    devices = {device.id: device for device in pack.devices}
    domains = _broadcast_domains(pack)
    interfaces = _interfaces(pack)
    for group in pack.fhrp_groups:
        if len(group.members) < 2:
            continue
        placed: dict[str, str] = {}
        vlan_ids: set[VlanId] = set()
        for member in group.members:
            interface = interfaces.get((member.device, member.interface))
            vlan_id = _svi_vlan(interface) if interface is not None else None
            if interface is None or vlan_id is None or not interface.admin_enabled:
                vlan_ids = set()
                break
            placed[member.device] = member.interface
            vlan_ids.add(vlan_id)
        if len(vlan_ids) != 1 or len(placed) < 2:
            continue
        vlan_id = vlan_ids.pop()
        parts = _halves(placed, domains.get(vlan_id, {}))
        if len(parts) < 2:
            continue
        home, *rest = parts
        for part in rest:
            if _cut_off(part, devices, vlan_id):
                blamed, far = part, home
            elif _cut_off(home, devices, vlan_id):
                blamed, far = home, part
            else:
                continue
            device = blamed[0]
            virtual = group.virtual_address or "the virtual address"
            yield Finding(
                rule="fhrp-members-in-different-segments",
                tier=Tier.FACTS,
                severity=Severity.HIGH,
                device=device,
                title=f"{group.label} has a member in a broadcast domain of its "
                f"own on {device}:{placed[device]}",
                detail=f"no trunk carries VLAN {vlan_id} between {device} and "
                + ", ".join(far)
                + f", so no member of {group_summary(group)} hears another's "
                f"advertisements and each of them is master: {virtual} and the "
                f"virtual MAC the group number derives from are live on every "
                f"device at once. Nothing is a backup, so the failover the "
                f"priorities describe cannot happen; and when the VLAN is "
                f"carried between them again the two masters meet, one stands "
                f"down, and every host holding the loser's gateway is stranded "
                f"until its ARP entry expires",
                evidence=tuple(
                    f"{member.device}:{member.interface} {group_summary(group)} "
                    f"priority {member.priority}"
                    for member in group.members
                ),
                remedy=f"add VLAN {vlan_id} to the trunk carrying {device}'s "
                f"uplink, so the members are on one segment before relying on "
                f"the election between them",
                change=_add_vlan_to_the_only_trunk(pack, devices[device], vlan_id),
            )


@rule
def subnet_terminated_on_two_vlans(pack: StaticFactPack) -> Iterator[Finding]:
    """One subnet whose gateways are SVIs for different VLANs.

    The addressing says these interfaces share a wire — that is what an L3
    adjacency in the Fact Pack is — and each of them puts its traffic on a
    different VLAN. A frame leaving one arrives tagged with an id the other does
    not terminate, so the two never exchange a packet: an SVI addressed in a
    subnet whose broadcast domain it is not a member of. The usual cause is a
    VLAN plan that renumbered on one side of a link, or an SVI created by
    copying a neighbour's stanza and editing the address but not the number.

    HIGH, on the same argument as `vlan-segment-split` and for the same traffic:
    hosts on each side resolve their own gateway and reach nothing on the other,
    the IGP or FHRP the subnet was meant to carry never comes up, and nothing on
    either device reports a fault. It is worse than a pruned trunk in one
    respect — no trunk edit fixes it, because the two ends disagree about what
    the VLAN *is* — and that is what the remedy has to say.

    Read off `L3Adjacency.over_l2_segment`, which is unset precisely when the
    members of a subnet are not all SVIs for one VLAN.

    Silent unless every member of the subnet is an SVI this tool can place. A
    routed link, a dot1q subinterface or a BVI carries no VLAN id in its name,
    and a subnet with one of those in it is a subnet whose tagging the pack does
    not know — not one it knows to be inconsistent.

    Silent when either VLAN is the native VLAN of a live trunk on the device
    that holds it. Untagged frames leave such a trunk with no id at all and land
    in whatever the far end calls native, so two different numbers can genuinely
    be one broadcast domain, and the configuration does not say whether they are.

    Silent, of course, when every member is an SVI for the same VLAN, which is
    the ordinary case and the one `over_l2_segment` names.
    """
    devices = {device.id: device for device in pack.devices}
    interfaces = _interfaces(pack)
    for adjacency in pack.l3_adjacencies:
        if adjacency.over_l2_segment is not None:
            continue
        placed: dict[VlanId, list[tuple[str, str]]] = {}
        for ref in adjacency.members:
            interface = interfaces.get((ref.device, ref.interface))
            vlan_id = _svi_vlan(interface) if interface is not None else None
            if vlan_id is None:
                placed = {}
                break
            placed.setdefault(vlan_id, []).append((ref.device, ref.interface))
        if len(placed) < 2:
            continue
        if any(
            trunk.native_vlan in placed
            for device_id, _name in itertools.chain.from_iterable(placed.values())
            if device_id in devices
            for trunk in devices[device_id].interfaces
            if trunk.admin_enabled and trunk.switchport_mode is SwitchportMode.TRUNK
        ):
            continue
        # The odd one out is the smallest group: the one SVI numbered
        # differently from the rest of the subnet is the line that has to move.
        odd, *others = sorted(placed.items(), key=lambda item: (len(item[1]), item[0]))
        vlan_id, members = odd
        device, interface = members[0]
        elsewhere = ", ".join(
            f"{other} puts it on VLAN {number}"
            for number, holders in others
            for other, _name in holders
        )
        yield Finding(
            rule="subnet-spans-two-vlans",
            tier=Tier.FACTS,
            severity=Severity.HIGH,
            device=device,
            title=f"{adjacency.prefix} is terminated on two VLANs: "
            f"{device}:{interface} is in VLAN {vlan_id}",
            detail=f"{device} puts {adjacency.prefix} on VLAN {vlan_id} and "
            f"{elsewhere}; the addressing says they share a wire, and each side "
            f"tags its traffic with a VLAN the other does not terminate, so no "
            f"frame crosses between them: hosts on each side resolve the gateway "
            f"on their own side and reach nothing on the other, and no adjacency "
            f"over this subnet can come up",
            evidence=tuple(
                f"{holder}:{name} vlan {number} {adjacency.prefix}"
                for number, holders in sorted(placed.items())
                for holder, name in holders
            ),
            remedy="put both ends on one VLAN — renumber whichever SVI is on the "
            "wrong one — or give this half a subnet of its own",
        )


# --------------------------------------------------------------------------
# Spanning tree
#
# Where the root of a VLAN's tree lands decides which ports block, which path
# every frame in that broadcast domain takes, and whose timers govern how long
# a reconvergence lasts — and none of it appears anywhere in the running
# configuration of the bridge it happens to. The election is the one fact in
# this file that no single device states: it is a comparison between the
# bridges in a segment, so it can only be read off the segment.
#
# Two things bound what may be concluded from it, and both are in
# `topology.BridgePriorities` rather than here.
#
# The first is that a priority is recorded for a device only when the parser
# accounted for every line on it that could set one. An MST instance priority
# and a `spanning-tree vlan 10 root primary` macro both set a priority this
# tool cannot turn into a number, and a bridge carrying one of them is left out
# of `bridge_priorities` entirely — because the alternative, treating a bridge
# whose line went unread as a bridge sitting at the default, is what would make
# every rule below report the opposite of the truth on exactly the networks
# that configured spanning tree most carefully.
#
# The second is that every rule here requires the whole segment: a segment
# whose members are not all in `bridge_priorities` is one where a bridge that
# was not read could be lower than any of the ones that were, and the election
# is then not this tool's to call. That leaves the case a directory can never
# rule out — a bridge on the wire whose config nobody collected — and the
# rules answer it the way the rest of this module does, by naming the bridges
# they compared so a reader can see the collection the claim rests on.
# --------------------------------------------------------------------------


def _bridges(segment: L2Segment) -> list[str]:
    """The devices bridging one segment, once each, in a stable order."""
    return sorted({ref.device for ref in segment.members})


def _svis_in(pack: StaticFactPack, vlan_id: VlanId) -> dict[str, str]:
    """Every device with a live, addressed SVI for one VLAN, and its name.

    Addressed, because an SVI with no address terminates nothing and is not a
    gateway for anybody; live, because a shut one is not on the network at all.
    """
    found: dict[str, str] = {}
    for device in pack.devices:
        for interface in device.interfaces:
            if (
                _svi_vlan(interface) == vlan_id
                and interface.admin_enabled
                and interface.addresses
            ):
                found[device.id] = interface.name
    return found


def _modes_in_the_inventory(pack: StaticFactPack) -> dict[str, StpMode]:
    """The spanning-tree mode each device states, as far as the pack carries it.

    A mode reaches the Fact Pack on a `StpTimers` record and nowhere else, so
    this sees a bridge only if that bridge also retimed its spanning tree.
    `L2Segment.stp_mode` is derived from what *every* device stated, which is
    the wider set — deliberately, because a fact about a broadcast domain
    should not depend on which of its members happened to change a timer — and
    the gap between the two is why the rule below can be silent about a
    disagreement the segment already knows is there. It reports what it can
    attribute to a device; the segment records what is true.

    `StpMode.NONE` is left out. It is what an unwritten mode line and an
    explicit `spanning-tree mode none` both arrive as, and naming a bridge as
    running neither protocol on the strength of a line nobody wrote is the one
    thing this section will not do.
    """
    seen: dict[str, set[StpMode]] = {}
    for timers in pack.timers.stp:
        if timers.mode is not StpMode.NONE:
            seen.setdefault(timers.scope.device, set()).add(timers.mode)
    return {device: modes.pop() for device, modes in seen.items() if len(modes) == 1}


def _election(segment: L2Segment) -> dict[str, int] | None:
    """The whole root election for one segment, or None if it is not settled.

    None whenever a bridge in the segment has no priority in
    `bridge_priorities`, which is the single guard every rule in this section
    depends on: a partial election is not a weaker answer, it is a different
    one, because the bridge that was left out is exactly the bridge that could
    have won.
    """
    bridges = _bridges(segment)
    priorities = dict(segment.bridge_priorities)
    if not bridges or set(priorities) != set(bridges):
        return None
    return priorities


@rule
def stp_root_election_is_a_tie(pack: StaticFactPack) -> Iterator[Finding]:
    """Two bridges configured to the same lowest priority, so neither is root.

    A priority below the default is the operator writing down which bridge
    should be the root of this VLAN's tree, and here it has been written down
    twice. IEEE 802.1D then settles it on the bridge MAC address, so the root
    is whichever of the two was manufactured first — a fact about a purchase
    order rather than about the network — and every port that blocks in this
    broadcast domain blocks because of it.

    MEDIUM, on the same argument `fhrp-priority-tie` makes about an FHRP
    master. Nothing is down while the tie stands: the tree converges, traffic
    flows, and the topology is merely not the one that was drawn. What earns
    the finding is that it moves with no configuration change behind it —
    replace either bridge and the new chassis brings a new MAC address into the
    comparison — and the VLAN's forwarding path, its blocked ports and the
    timers that govern its reconvergence all move at once, on a day whose
    change record says "swapped a switch". Not HIGH, because the tie itself
    loses no traffic; not LOW, because it defeats a placement somebody chose
    and wrote down.

    Silent unless every bridge in the segment has a priority this tool read.
    A bridge whose priority was set by an MST instance or by a `root primary`
    macro is one the parser declines to guess at, and a bridge that might be
    lower than both of these is a bridge that makes the finding wrong.

    Silent when the shared lowest priority is the default one. Every bridge in
    a segment sitting on 32768 is a root nobody chose, which is real and is a
    different claim: it rests on reading an absence as a decision, one
    uncollected bridge with a priority makes it false, and whether an arbitrary
    root costs anything at all depends on there being a second path between
    the bridges — which needs the layer-1 data this tool refuses to invent.

    Silent, of course, when one bridge is strictly lowest, which is an election
    with a winner and the subject of `stp-root-is-not-the-gateway` instead.
    """
    for segment in pack.l2_segments:
        election = _election(segment)
        if segment.vlan_id is None or election is None or len(election) < 2:
            continue
        lowest = min(election.values())
        if lowest >= DEFAULT_BRIDGE_PRIORITY:
            continue
        tied = sorted(device for device, value in election.items() if value == lowest)
        if len(tied) < 2:
            continue
        yield Finding(
            rule="stp-root-tie",
            tier=Tier.FACTS,
            severity=Severity.MEDIUM,
            device=tied[0],
            title=f"VLAN {segment.vlan_id} has no chosen root bridge: "
            + " and ".join(tied)
            + f" both hold priority {lowest}",
            detail=f"{len(tied)} bridges in VLAN {segment.vlan_id} share the "
            f"lowest bridge priority {lowest}, so the root is decided by "
            f"whichever of them has the lower MAC address — which is not a "
            f"thing anyone configured and not a thing this file records. The "
            f"tree, the ports it blocks and the timers that govern its "
            f"reconvergence all belong to whichever bridge wins, and they move "
            f"to the other one the day either device is replaced",
            evidence=tuple(
                f"{device} VLAN {segment.vlan_id} bridge priority {value}"
                for device, value in sorted(election.items())
            ),
            # The command, but only where there is a step left below the tie.
            # Two bridges already sharing priority 0 have nowhere lower to go,
            # and a suggestion to set the value they are both on would be
            # worse than the sentence that replaces it.
            remedy=(
                f"lower the priority of the bridge that should be the root — "
                f"`spanning-tree vlan {segment.vlan_id} priority {lowest - 4096}` — "
                f"so the election states the placement instead of inheriting it"
                if lowest >= 4096
                else "raise the priority of every bridge that should not be the "
                "root, so the election states the placement instead of "
                "inheriting it"
            ),
        )


@rule
def stp_root_holds_no_gateway(pack: StaticFactPack) -> Iterator[Finding]:
    """The bridge that wins this VLAN's root election holds no address in it.

    Somebody configured priorities here — an election with a single winner is
    one where at least one bridge was moved off the default — and the winner is
    a bridge with no SVI in the VLAN while another member of the segment has
    one. The tree for this VLAN is therefore built around a device that carries
    none of its routed traffic: every port that blocks does so to make the
    paths to *that* device loop-free, and the gateway's own links are as
    eligible to be blocked as anything else in the domain.

    LOW, and the boundary is worth stating precisely. Nothing is unreachable
    and nothing flaps: spanning tree converges, hosts resolve their gateway and
    reach it, and the cost is a path that is longer and less symmetric than the
    addressing implies, plus a reconvergence on every topology change computed
    around a device with no stake in the VLAN. How much longer that path is
    depends on the cabling, and `L1Link` is empty on purpose, so this does not
    say — reporting a hop count derived from an invented cable would be worth
    less than reporting nothing. What it does say is that the root and the
    gateway are different devices, which is the part somebody has to confirm
    was meant.

    Silent unless the election is settled: every bridge in the segment needs a
    priority this tool read, and one of them has to be strictly lowest. Two
    bridges tied at the lowest priority have no root to be in the wrong place,
    and that is `stp-root-tie`.

    Silent when the root bridge holds an SVI in the VLAN, which is the
    arrangement this rule exists to ask for, and silent when no member of the
    segment holds one — a VLAN with no gateway in the collection is either a
    pure layer-2 domain or one whose gateway was not collected, and neither is
    a root in the wrong place.
    """
    for segment in pack.l2_segments:
        root = segment.root_bridge
        if segment.vlan_id is None or root is None or _election(segment) is None:
            continue
        gateways = _svis_in(pack, segment.vlan_id)
        if not gateways or root in gateways:
            continue
        held = sorted(gateways)
        yield Finding(
            rule="stp-root-is-not-the-gateway",
            tier=Tier.FACTS,
            severity=Severity.LOW,
            device=root,
            title=f"the root bridge for VLAN {segment.vlan_id} is {root}, which "
            f"has no address in it",
            detail=f"{root} wins the root election for VLAN {segment.vlan_id} on "
            f"bridge priority, and terminates none of the VLAN's traffic; "
            + ", ".join(f"{device}:{gateways[device]}" for device in held)
            + f" {'does' if len(held) == 1 else 'do'}. The tree for this VLAN is "
            f"built around {root}, so the ports that block are the ones that "
            f"would have made a path to {root} a loop — the gateway's links "
            f"among them — and every topology change in the VLAN reconverges "
            f"around a device with no stake in it",
            evidence=(
                *(
                    f"{device} VLAN {segment.vlan_id} bridge priority {value}"
                    for device, value in sorted(segment.bridge_priorities)
                ),
                *(
                    f"{device}:{gateways[device]} terminates VLAN {segment.vlan_id}"
                    for device in held
                ),
            ),
            remedy=f"give the gateway for VLAN {segment.vlan_id} the lowest bridge "
            f"priority in the segment, or confirm that the root belongs on "
            f"{root} and that the gateway's uplinks are the ones meant to forward",
        )


@rule
def stp_modes_disagree(pack: StaticFactPack) -> Iterator[Finding]:
    """One broadcast domain bridged by two different spanning-tree protocols.

    Two members of a segment state different modes — rapid-PVST on one and MST
    on the other is the pairing that happens, usually because a switch was
    added from a template written for a different part of the estate. The two
    do not exchange comparable BPDUs: an MST bridge advertises one tree for its
    whole region and a per-VLAN bridge advertises one per VLAN, so each
    computes a topology the other neither contributes to nor honours, and a
    port one of them decides to block is a port the other has already decided
    to forward.

    MEDIUM, and the reason it is not HIGH is the reason it survives review for
    years: with one path between the bridges nothing whatever happens. Both
    forward, there is no loop to break, and every counter is clean. It becomes
    a broadcast storm on the day a second path appears — a link added for
    redundancy, a patch lead put back in the wrong port, a bundle member that
    comes up alone — because the two bridges cannot agree which of the two
    paths to block. That is a loop on a broadcast domain, which takes a site
    down rather than a link, and whether this segment has that second path is
    exactly what needs `L1Link` and is therefore not something this tool knows.
    So it is reported as the latent condition it is, with the trigger stated.

    Silent about a device that states a mode and no spanning-tree timer. A mode
    reaches the Fact Pack attached to a timer record and nowhere else, so a
    bridge configured with `spanning-tree mode mst` and no timing of its own is
    one this rule can see the effect of — `L2Segment.stp_mode` falls back to
    "no one mode here" — and cannot name. Naming is the whole finding, so it
    stays quiet rather than reporting a disagreement between two devices it
    would have to leave unidentified.

    Silent about a bridge whose mode is `none`. A configuration that says
    `spanning-tree mode none` and one that says nothing about the mode at all
    reach the pack as the same value, and reporting a bridge as having spanning
    tree switched off on the strength of a line nobody wrote would be the guess
    this whole section is built to avoid. Two bridges in one segment where one
    is protecting a VLAN the other is not is a real defect and it is not
    decidable here.
    """
    stated = _modes_in_the_inventory(pack)
    for segment in pack.l2_segments:
        if segment.vlan_id is None or segment.stp_mode is not StpMode.NONE:
            continue
        running = {
            device: stated[device] for device in _bridges(segment) if device in stated
        }
        if len(set(running.values())) < 2:
            continue
        named = sorted(running.items())
        yield Finding(
            rule="stp-mode-disagreement",
            tier=Tier.FACTS,
            severity=Severity.MEDIUM,
            device=named[0][0],
            title=f"VLAN {segment.vlan_id} is bridged by "
            + " and ".join(sorted({mode.value for mode in running.values()}))
            + " at once",
            detail=", ".join(f"{device} runs {mode.value}" for device, mode in named)
            + f", and every one of them bridges VLAN {segment.vlan_id}. The two "
            f"protocols do not compare the same BPDUs, so each bridge computes "
            f"a tree the other does not honour, and neither can be relied on to "
            f"block the port the other is forwarding on",
            trigger=f"a second path between these bridges in VLAN "
            f"{segment.vlan_id} — a link added for redundancy, or a patch lead "
            f"put back in the wrong port",
            evidence=tuple(
                f"{device} spanning-tree mode {mode.value}" for device, mode in named
            ),
            remedy="put every bridge in the broadcast domain in one mode before "
            "a second path between them exists",
        )
