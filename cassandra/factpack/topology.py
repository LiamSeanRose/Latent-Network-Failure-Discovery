"""Topology derived from configuration text alone.

`StaticFactPack` (PROJECT.md §3) has carried L1, L2 and L3 topology fields since
the schema was written, and nothing has ever populated them. This module fills
the three that a configuration actually determines, and deliberately leaves the
two it does not.

Derived here:

* `L3Adjacency` — interfaces whose addresses fall in one subnet, in one VRF.
  Addressing is the operator's own statement about who shares a wire, so this is
  the strongest topology claim config text supports. It is also what decides who
  *could* be an IGP, BGP, BFD or FHRP peer of whom.
* `L2Segment` — one broadcast domain per VLAN id, listing every interface that
  carries it: an access port in that VLAN, a trunk permitting it, or an SVI
  named for it. Also where the spanning-tree root election that governs that
  domain is written down: the bridge priorities the configurations state, the
  mode they say they are running, and the root itself where those settle it.
  A priority is only ever recorded for a device whose configuration accounts
  for every line that could set one — see `BridgePriorities` — because the
  whole value of the field is that a device missing from it is a device whose
  priority is unknown, rather than one assumed to be at the default.
* `L2Adjacency` — trunks on different devices that permit the same VLAN id.
  Read the relation precisely: it says both ends can carry that VLAN tagged, not
  that a cable joins them. Without layer-1 data it cannot distinguish two
  trunks facing each other from two trunks three hops apart, and it does not
  survive VLAN-id reuse across fabrics that are not connected to each other.
  It is also pairwise, so a flat VLAN spanning n trunks produces n²/2 of them
  and the `L2Segment` for that VLAN says the same thing in n. Ask the segment
  who is in a broadcast domain; ask these pairs only who faces whom.

Refused here, because config text does not contain it:

* `L1Link`. A configuration never says what an interface is plugged into. The
  tempting heuristic — exactly two addresses in a /30 or /31 must be cabled
  together — is refuted by the corpus this tool ships with: `agg-a Vlan99` and
  `agg-b Vlan99` are the only two addresses in 10.99.0.0/30, and they are SVIs
  that reach each other through the access switch between them, over two cables
  and a device. `L1Link` is what failure analysis reads to decide that downing
  one end downs the other, so an invented cable does not weaken a result, it
  inverts one. Interface descriptions are not evidence either: they are prose,
  they go stale silently, and a topology that trusts them is a topology that
  reports last year's wiring.
* Cross-device LAG membership. `LinkAggregationGroup.peer_device` names the far
  end of a bundle, which is layer 1 under another name.

Both stay empty until something that observes the wire — LLDP, an inventory
export, a hand-written layer-1 file — supplies them.

Where the text is ambiguous this module claims less rather than more, because a
wrong edge is worse than a missing one for everything downstream that reads a
topology. Two consequences worth knowing:

* A trunk carrying no `switchport trunk allowed vlan` line permits every VLAN on
  real hardware, but an empty `allowed_vlans` in the fact pack is equally
  consistent with a construct no parser read. It therefore claims membership of
  nothing rather than membership of everything, which is also how the FACTS
  rules already read that field.
* An administratively shut interface is in the configuration and not on the
  network, so it joins no segment and no adjacency.
* A root bridge is named only where every member device's priority is known and
  one of them is strictly lowest. Two bridges sharing the lowest priority are
  separated by their MAC addresses, which a configuration does not contain, so
  the segment carries no root rather than the first of the two — and a rule
  reporting that tie is reading exactly the ambiguity this leaves behind.
"""

from __future__ import annotations

import ipaddress
import itertools
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, TypedDict

from cassandra.factpack.schema import (
    AddressFamily,
    Device,
    DeviceId,
    Interface,
    InterfaceKind,
    InterfaceRef,
    L2Adjacency,
    L2Segment,
    L3Adjacency,
    SegmentId,
    StpMode,
    SwitchportMode,
    Vlan,
    VlanId,
    VrfName,
)

type Network = ipaddress.IPv4Network | ipaddress.IPv6Network
type SubnetKey = tuple[VrfName | None, Network]

# `Vlan99`, and not `Vlan99.4` or `Vlan` — an SVI names exactly one broadcast
# domain or it is not an SVI this module can place.
_SVI_NAME: Final = re.compile(r"[Vv]lan(\d+)")

# What a bridge runs when nobody has said otherwise: IEEE 802.1D-1998 table 8-4.
# Every dialect this tool parses ships it, and every dialect adds the VLAN id to
# it for the extended system identifier — so the number on the wire for VLAN 10
# is 32778, not 32768. That is left out on purpose. It is added identically by
# every bridge in the same VLAN, so it cancels out of the only comparison
# anything here makes, and carrying it would put a number in a finding that
# matches no line in any configuration.
DEFAULT_BRIDGE_PRIORITY: Final = 32768


@dataclass(frozen=True, slots=True, kw_only=True)
class BridgePriorities:
    """One device's bridge priorities, as far as its configuration settles them.

    `stated` holds the VLANs a priority was actually read for. `complete` is the
    load-bearing half: it says the parser accounted for every line on this
    device that could set a priority, and therefore that a VLAN missing from
    `stated` really is running the default rather than a value nobody read.

    The two are separate because the distinction they draw is the one a root
    election turns on. "This bridge is at 32768 because that is what it ships
    with" and "this bridge's priority is unknown" lead to opposite answers about
    who wins, and only the parser that saw the lines can tell them apart — a
    device whose dialect has no spanning tree to read, or one whose priority was
    set by an MST instance or a `root primary` macro, is the second and must not
    be counted as the first.
    """

    stated: tuple[tuple[VlanId, int], ...] = ()
    complete: bool = False

    def of(self, vlan_id: VlanId) -> int | None:
        """This device's bridge priority in one VLAN, or None if unknown."""
        for stated_vlan, priority in self.stated:
            if stated_vlan == vlan_id:
                return priority
        return DEFAULT_BRIDGE_PRIORITY if self.complete else None


class Topology(TypedDict):
    """The three Fact Pack fields this module owns.

    A mapping keyed by `StaticFactPack` field names rather than a record, so the
    builder can splat it into the constructor in one line and gain a field here
    without being edited again.
    """

    l2_segments: tuple[L2Segment, ...]
    l2_adjacencies: tuple[L2Adjacency, ...]
    l3_adjacencies: tuple[L3Adjacency, ...]


def derive(
    devices: Sequence[Device],
    vlans: Sequence[Vlan],
    *,
    stp_modes: Mapping[DeviceId, StpMode] | None = None,
    bridge_priorities: Mapping[DeviceId, BridgePriorities] | None = None,
) -> Topology:
    """Everything the configuration determines about how the devices connect.

    `stp_modes` and `bridge_priorities` are what the parsers read of the
    spanning-tree domain, per device, and both are optional: a caller that has
    neither gets segments with no election in them rather than an election over
    invented numbers.

    Output ordering is total and stable: two runs over one directory produce
    identical topology, which is what lets a fact pack be diffed and digested.
    """
    return Topology(
        l2_segments=_l2_segments(
            devices, vlans, stp_modes or {}, bridge_priorities or {}
        ),
        l2_adjacencies=_l2_adjacencies(devices),
        l3_adjacencies=_l3_adjacencies(devices),
    )


def segment_id(vlan_id: VlanId) -> SegmentId:
    """The id of the broadcast domain for one VLAN.

    Public because `L2Adjacency.segment` and `L3Adjacency.over_l2_segment` are
    joins onto it, and a caller holding a VLAN id should not have to guess the
    spelling.
    """
    return f"vlan-{vlan_id}"


# --------------------------------------------------------------------------
# Layer 2
# --------------------------------------------------------------------------


def _l2_segments(
    devices: Sequence[Device],
    vlans: Sequence[Vlan],
    modes: Mapping[DeviceId, StpMode],
    priorities: Mapping[DeviceId, BridgePriorities],
) -> tuple[L2Segment, ...]:
    """One segment per VLAN id that something actually carries.

    A VLAN declared on a device but reaching no interface is left out: a
    broadcast domain with no members is not a place anything can be, and a
    trunk permitting a VLAN nothing terminates is already a FACTS finding.
    """
    instances = _stp_instances(vlans)
    segments: list[L2Segment] = []
    for vlan_id, members in sorted(_members_by_vlan(devices).items()):
        bridges = _member_devices(members)
        stated = _bridge_priorities(bridges, vlan_id, priorities)
        segments.append(
            L2Segment(
                id=segment_id(vlan_id),
                vlan_id=vlan_id,
                members=tuple(members),
                stp_mode=_segment_mode(bridges, modes),
                stp_instance=instances.get(vlan_id),
                root_bridge=_root_bridge(bridges, stated),
                bridge_priorities=stated,
            )
        )
    return tuple(segments)


def _member_devices(members: Sequence[InterfaceRef]) -> list[DeviceId]:
    """The devices bridging one segment, once each, in the members' own order."""
    seen: list[DeviceId] = []
    for ref in members:
        if ref.device not in seen:
            seen.append(ref.device)
    return seen


def _segment_mode(
    bridges: Sequence[DeviceId], modes: Mapping[DeviceId, StpMode]
) -> StpMode:
    """The one mode every member that states one agrees on, or `NONE`.

    Only a mode a device positively stated counts. `StpMode.NONE` is what both
    `spanning-tree mode none` and an unwritten mode line arrive as, and the two
    mean opposite things — a bridge not running spanning tree at all, and a
    bridge running whatever it ships with — so a member carrying it is passed
    over rather than recorded as either.

    `NONE` on the way out therefore carries three cases at once: nobody said,
    the members disagree, and a member really has it switched off. That is the
    field's shape rather than this function's choice — `StpMode` has one value
    for "no mode here" and none for "two" — and the consequence belongs in the
    open: a rule wanting to tell a disagreement from a silence cannot get it
    from here, and has to compare the devices itself.
    """
    stated = {modes[device] for device in bridges if device in modes}
    stated.discard(StpMode.NONE)
    return stated.pop() if len(stated) == 1 else StpMode.NONE


def _bridge_priorities(
    bridges: Sequence[DeviceId],
    vlan_id: VlanId,
    priorities: Mapping[DeviceId, BridgePriorities],
) -> tuple[tuple[DeviceId, int], ...]:
    """Every member bridge whose priority in this VLAN the configs settle.

    A device that is absent from the result is a device whose priority is
    unknown, and that is the entire contract: nothing downstream may read the
    result as the whole election unless it holds every member of the segment.
    """
    return tuple(
        sorted(
            (device, priority)
            for device in set(bridges)
            if (priority := priorities.get(device, BridgePriorities()).of(vlan_id))
            is not None
        )
    )


def _root_bridge(
    bridges: Sequence[DeviceId], stated: Sequence[tuple[DeviceId, int]]
) -> DeviceId | None:
    """The bridge that wins this segment's root election, where one does.

    Three things have to hold, and the missing one is the usual reason this is
    None. Every member's priority has to be known, or a bridge nobody read could
    be lower than all of them. The lowest has to be unique, because the tie
    below it is broken by MAC address and a configuration does not contain one.
    And there has to be a member at all.

    Still only a claim about the devices in the directory. A broadcast domain
    reaches as far as the cabling does, and a bridge whose config was not
    collected is not in `bridges` — which is the same exposure every rule over a
    partial capture carries, and is why the finding that reads this says which
    bridges it compared.
    """
    if not bridges or len(stated) != len(set(bridges)):
        return None
    lowest = min(priority for _device, priority in stated)
    winners = [device for device, priority in stated if priority == lowest]
    return winners[0] if len(winners) == 1 else None


def _members_by_vlan(devices: Sequence[Device]) -> dict[VlanId, list[InterfaceRef]]:
    index: dict[VlanId, list[InterfaceRef]] = {}
    for ref, interface in _live(devices):
        for vlan_id in _vlans_carried(interface):
            members = index.setdefault(vlan_id, [])
            if ref not in members:
                members.append(ref)
    return {
        vlan_id: sorted(members, key=_ref_key) for vlan_id, members in index.items()
    }


def _vlans_carried(interface: Interface) -> tuple[VlanId, ...]:
    """Every VLAN id this one interface puts on the wire."""
    if (svi := _svi_vlan(interface)) is not None:
        return (svi,)
    if interface.switchport_mode is SwitchportMode.TRUNK:
        # The native VLAN needs no special case: it forwards only when the
        # allowed list permits it, in which case it is already here.
        return tuple(sorted(set(interface.allowed_vlans)))
    if interface.switchport_mode is SwitchportMode.ROUTED:
        return ()
    # A port with an access VLAN and no explicit mode is an access port on every
    # dialect this tool parses.
    if interface.access_vlan is not None:
        return (interface.access_vlan,)
    return ()


def _svi_vlan(interface: Interface) -> VlanId | None:
    match = _SVI_NAME.fullmatch(interface.name)
    return int(match.group(1)) if match else None


def _stp_instances(vlans: Sequence[Vlan]) -> dict[VlanId, int]:
    """The STP instance of a VLAN, where every device that names one agrees.

    Disagreement is a defect for a rule to report, not a value to pick a winner
    from, so the segment carries no instance rather than one device's opinion.
    """
    seen: dict[VlanId, set[int]] = {}
    for vlan in vlans:
        if vlan.stp_instance is not None:
            seen.setdefault(vlan.vlan_id, set()).add(vlan.stp_instance)
    return {
        vlan_id: instances.pop()
        for vlan_id, instances in seen.items()
        if len(instances) == 1
    }


def _l2_adjacencies(devices: Sequence[Device]) -> tuple[L2Adjacency, ...]:
    """Trunk pairs on different devices permitting at least one common VLAN.

    Both ends must state an allowed list. A trunk that states none is the
    ambiguous case described in the module docstring and pairs with nothing.
    """
    trunks = sorted(
        (
            (ref, interface, frozenset(interface.allowed_vlans))
            for ref, interface in _live(devices)
            if interface.switchport_mode is SwitchportMode.TRUNK
            and interface.allowed_vlans
        ),
        key=lambda trunk: _ref_key(trunk[0]),
    )
    adjacencies: list[L2Adjacency] = []
    # Every pair is considered, so the VLAN sets are built once each rather than
    # once per pair, and sorting the trunks first means `combinations` already
    # yields each pair in (a, b) order.
    for (a_ref, a, a_vlans), (b_ref, b, b_vlans) in itertools.combinations(trunks, 2):
        if a_ref.device == b_ref.device:
            continue
        shared = tuple(sorted(a_vlans & b_vlans))
        if not shared:
            continue
        adjacencies.append(
            L2Adjacency(
                a=a_ref,
                b=b_ref,
                vlans=shared,
                # One shared VLAN names one broadcast domain; several name
                # several, and the field holds one. Both ends permit the VLAN,
                # so the segment it names is always one this module emitted.
                segment=segment_id(shared[0]) if len(shared) == 1 else None,
                over_lag=InterfaceKind.LAG in (a.kind, b.kind),
            )
        )
    return tuple(
        sorted(adjacencies, key=lambda adj: (_ref_key(adj.a), _ref_key(adj.b)))
    )


# --------------------------------------------------------------------------
# Layer 3
# --------------------------------------------------------------------------


def _l3_adjacencies(devices: Sequence[Device]) -> tuple[L3Adjacency, ...]:
    """Interfaces sharing a subnet in one VRF, across at least two devices.

    Same subnet in different VRFs is not an adjacency — that is the entire point
    of a VRF — and one device's interfaces sharing a subnet with each other is a
    duplicate-address defect rather than a link, so both are excluded.
    """
    index: dict[SubnetKey, list[tuple[InterfaceRef, Interface]]] = {}
    for ref, interface in _live(devices):
        for net in _networks(interface):
            members = index.setdefault((interface.vrf, net), [])
            if all(seen != ref for seen, _ in members):
                members.append((ref, interface))

    adjacencies: list[L3Adjacency] = []
    for (vrf, net), members in sorted(index.items(), key=lambda kv: _subnet_key(kv[0])):
        ordered = sorted(members, key=lambda member: _ref_key(member[0]))
        if len({ref.device for ref, _ in ordered}) < 2:
            continue
        adjacencies.append(
            L3Adjacency(
                prefix=str(net),
                family=(
                    AddressFamily.IPV6_UNICAST
                    if net.version == 6
                    else AddressFamily.IPV4_UNICAST
                ),
                vrf=vrf,
                members=tuple(ref for ref, _ in ordered),
                over_l2_segment=_shared_svi_segment(i for _, i in ordered),
            )
        )
    return tuple(adjacencies)


def _networks(interface: Interface) -> list[Network]:
    """Every subnet this interface is addressed in, secondaries included."""
    nets: list[Network] = []
    for assignment in interface.addresses:
        try:
            net = ipaddress.ip_interface(assignment.prefix).network
        except ValueError:
            continue
        if net not in nets:
            nets.append(net)
    return nets


def _shared_svi_segment(interfaces: Iterable[Interface]) -> SegmentId | None:
    """The broadcast domain an all-SVI adjacency rides, when there is one.

    An SVI in VLAN 14 is in VLAN 14's broadcast domain by definition, so when
    every member of a subnet is an SVI for the same VLAN the L3 adjacency runs
    over that segment. A routed link rides no VLAN and gets nothing.
    """
    vlan_ids = {_svi_vlan(interface) for interface in interfaces}
    if len(vlan_ids) != 1:
        return None
    vlan_id = vlan_ids.pop()
    return None if vlan_id is None else segment_id(vlan_id)


# --------------------------------------------------------------------------
# Shared
# --------------------------------------------------------------------------


def _live(devices: Sequence[Device]) -> Iterator[tuple[InterfaceRef, Interface]]:
    """Every interface that can carry traffic, with a reference to it.

    The reference is built from `Device.id` rather than `Interface.device` so it
    always points back into the device list it came from.
    """
    for device in devices:
        for interface in device.interfaces:
            if interface.admin_enabled:
                yield (
                    InterfaceRef(device=device.id, interface=interface.name),
                    interface,
                )


def _ref_key(ref: InterfaceRef) -> tuple[str, str]:
    return (ref.device, ref.interface)


def _subnet_key(key: SubnetKey) -> tuple[str, int, bytes, int]:
    """Total order over subnets, across address families and VRFs alike."""
    vrf, net = key
    return (vrf or "", net.version, net.network_address.packed, net.prefixlen)
