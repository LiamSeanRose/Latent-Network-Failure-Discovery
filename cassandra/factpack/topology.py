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
  named for it.
* `L2Adjacency` — trunks on different devices that permit the same VLAN id.
  Read the relation precisely: it says both ends can carry that VLAN tagged, not
  that a cable joins them. Without layer-1 data it cannot distinguish two
  trunks facing each other from two trunks three hops apart, and it does not
  survive VLAN-id reuse across fabrics that are not connected to each other.

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
"""

from __future__ import annotations

import ipaddress
import itertools
import re
from collections.abc import Iterable, Iterator, Sequence
from typing import Final, TypedDict

from cassandra.factpack.schema import (
    AddressFamily,
    Device,
    Interface,
    InterfaceKind,
    InterfaceRef,
    L2Adjacency,
    L2Segment,
    L3Adjacency,
    SegmentId,
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


class Topology(TypedDict):
    """The three Fact Pack fields this module owns.

    A mapping keyed by `StaticFactPack` field names rather than a record, so the
    builder can splat it into the constructor in one line and gain a field here
    without being edited again.
    """

    l2_segments: tuple[L2Segment, ...]
    l2_adjacencies: tuple[L2Adjacency, ...]
    l3_adjacencies: tuple[L3Adjacency, ...]


def derive(devices: Sequence[Device], vlans: Sequence[Vlan]) -> Topology:
    """Everything the configuration determines about how the devices connect.

    Output ordering is total and stable: two runs over one directory produce
    identical topology, which is what lets a fact pack be diffed and digested.
    """
    return Topology(
        l2_segments=_l2_segments(devices, vlans),
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
    devices: Sequence[Device], vlans: Sequence[Vlan]
) -> tuple[L2Segment, ...]:
    """One segment per VLAN id that something actually carries.

    A VLAN declared on a device but reaching no interface is left out: a
    broadcast domain with no members is not a place anything can be, and a
    trunk permitting a VLAN nothing terminates is already a FACTS finding.
    """
    instances = _stp_instances(vlans)
    return tuple(
        L2Segment(
            id=segment_id(vlan_id),
            vlan_id=vlan_id,
            members=tuple(members),
            stp_instance=instances.get(vlan_id),
        )
        for vlan_id, members in sorted(_members_by_vlan(devices).items())
    )


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
    trunks = [
        (ref, interface)
        for ref, interface in _live(devices)
        if interface.switchport_mode is SwitchportMode.TRUNK and interface.allowed_vlans
    ]
    adjacencies: list[L2Adjacency] = []
    for left, right in itertools.combinations(trunks, 2):
        (a_ref, a), (b_ref, b) = sorted(
            (left, right), key=lambda pair: _ref_key(pair[0])
        )
        if a_ref.device == b_ref.device:
            continue
        shared = tuple(sorted(set(a.allowed_vlans) & set(b.allowed_vlans)))
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
