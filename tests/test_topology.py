"""Topology derivation: what the configs determine, and what they do not.

Two halves. The first runs the derivation over the shipped corpus and pins every
edge it produces, because a topology view is only as good as its worst wrong
edge. The second is the refusal half: subnets that do not overlap, VRFs that do
not meet, interfaces that are shut, and the point-to-point subnet that would fool
anything trying to guess cabling from addressing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.builders.common import interface_kind
from cassandra.factpack.schema import (
    AddressFamily,
    Device,
    FactPackMeta,
    Interface,
    IpAssignment,
    L2Segment,
    L3Adjacency,
    StaticFactPack,
    SwitchportMode,
    Vlan,
)
from cassandra.factpack.topology import Topology, derive, segment_id

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)


# --------------------------------------------------------------------------
# Construction helpers
# --------------------------------------------------------------------------


def port(
    device: str,
    name: str,
    *,
    addresses: tuple[str, ...] = (),
    vrf: str | None = None,
    mode: SwitchportMode = SwitchportMode.NONE,
    access_vlan: int | None = None,
    allowed: tuple[int, ...] = (),
    enabled: bool = True,
) -> Interface:
    return Interface(
        device=device,
        name=name,
        kind=interface_kind(name),
        admin_enabled=enabled,
        switchport_mode=mode,
        access_vlan=access_vlan,
        allowed_vlans=allowed,
        vrf=vrf,
        addresses=tuple(
            IpAssignment(
                address=prefix.split("/")[0],
                prefix=prefix,
                family=(
                    AddressFamily.IPV6_UNICAST
                    if ":" in prefix
                    else AddressFamily.IPV4_UNICAST
                ),
                secondary=index > 0,
            )
            for index, prefix in enumerate(addresses)
        ),
    )


def box(name: str, *interfaces: Interface) -> Device:
    return Device(id=name, hostname=name, interfaces=interfaces)


def l3_edges(topology: Topology) -> dict[str, list[str]]:
    """Prefix -> members, for the common case of one VRF."""
    return {
        adjacency.prefix: refs(adjacency) for adjacency in topology["l3_adjacencies"]
    }


def refs(adjacency: L3Adjacency | L2Segment) -> list[str]:
    return [f"{ref.device}:{ref.interface}" for ref in adjacency.members]


def l2_edges(topology: Topology) -> dict[tuple[str, str], tuple[int, ...]]:
    return {
        (f"{adj.a.device}:{adj.a.interface}", f"{adj.b.device}:{adj.b.interface}"): (
            adj.vlans
        )
        for adj in topology["l2_adjacencies"]
    }


def segments(topology: Topology) -> dict[str, list[str]]:
    return {segment.id: refs(segment) for segment in topology["l2_segments"]}


@pytest.fixture(scope="module")
def corpus() -> Topology:
    pack, _ = build_fact_pack(CORPUS)
    return derive(pack.devices, pack.vlans)


# --------------------------------------------------------------------------
# The shipped corpus
# --------------------------------------------------------------------------


def test_corpus_l3_adjacencies_are_exactly_the_shared_subnets(corpus: Topology) -> None:
    assert l3_edges(corpus) == {
        # The two /31 uplinks, each seen from both ends.
        "10.0.0.0/31": ["agg-a:Ethernet1", "core1:Ethernet1"],
        "10.0.0.2/31": ["agg-b:Ethernet1", "core1:Ethernet2"],
        # The client, voice and management VLANs.
        "10.14.0.0/24": ["agg-a:Vlan14", "agg-b:Vlan14"],
        "10.24.0.0/24": ["agg-a:Vlan24", "agg-b:Vlan24"],
        "10.34.0.0/24": ["agg-a:Vlan34", "agg-b:Vlan34"],
        # The transit between the aggregation pair.
        "10.99.0.0/30": ["agg-a:Vlan99", "agg-b:Vlan99"],
    }


def test_loopbacks_are_not_adjacent_to_anything(corpus: Topology) -> None:
    """Three /32s, three subnets of one member each, no edges."""
    assert not [
        adjacency
        for adjacency in corpus["l3_adjacencies"]
        if any("Loopback" in ref.interface for ref in adjacency.members)
    ]


def test_svi_adjacencies_name_the_segment_they_ride(corpus: Topology) -> None:
    over = {
        adjacency.prefix: adjacency.over_l2_segment
        for adjacency in corpus["l3_adjacencies"]
    }
    assert over["10.14.0.0/24"] == "vlan-14"
    assert over["10.99.0.0/30"] == "vlan-99"
    # A routed link rides no VLAN.
    assert over["10.0.0.0/31"] is None


def test_every_l3_adjacency_is_ipv4_and_in_the_default_vrf(corpus: Topology) -> None:
    for adjacency in corpus["l3_adjacencies"]:
        assert adjacency.family is AddressFamily.IPV4_UNICAST
        assert adjacency.vrf is None


def test_corpus_l2_segments_carry_every_interface_in_the_vlan(
    corpus: Topology,
) -> None:
    assert segments(corpus) == {
        "vlan-14": [
            # Both access-switch trunks, the client port, both aggregation
            # trunks, and both SVIs.
            "acc1:Ethernet1",
            "acc1:Ethernet2",
            "acc1:Ethernet3",
            "agg-a:Ethernet2",
            "agg-a:Vlan14",
            "agg-b:Ethernet2",
            "agg-b:Vlan14",
        ],
        "vlan-24": [
            "acc1:Ethernet1",
            "acc1:Ethernet2",
            "agg-a:Ethernet2",
            "agg-a:Vlan24",
            "agg-b:Ethernet2",
            "agg-b:Vlan24",
        ],
        "vlan-34": [
            "acc1:Ethernet1",
            "acc1:Ethernet2",
            "agg-a:Ethernet2",
            "agg-a:Vlan34",
            "agg-b:Ethernet2",
            "agg-b:Vlan34",
        ],
        "vlan-99": [
            "acc1:Ethernet1",
            "acc1:Ethernet2",
            "agg-a:Ethernet2",
            "agg-a:Vlan99",
            "agg-b:Ethernet2",
            "agg-b:Vlan99",
        ],
    }


def test_corpus_l2_adjacencies_pair_every_trunk_permitting_a_common_vlan(
    corpus: Topology,
) -> None:
    """Co-membership of a VLAN, not cabling.

    agg-a and agg-b are not cabled to each other, and the pair below says only
    that both trunks carry the same VLANs — which they do, through acc1. The
    module refuses to turn that into a link, and this test is what holds it to
    the weaker claim.
    """
    every = (14, 24, 34, 99)
    assert l2_edges(corpus) == {
        ("acc1:Ethernet1", "agg-a:Ethernet2"): every,
        ("acc1:Ethernet1", "agg-b:Ethernet2"): every,
        ("acc1:Ethernet2", "agg-a:Ethernet2"): every,
        ("acc1:Ethernet2", "agg-b:Ethernet2"): every,
        ("agg-a:Ethernet2", "agg-b:Ethernet2"): every,
    }


def test_no_layer_one_is_claimed(corpus: Topology) -> None:
    """The derivation owns three fields and does not guess cabling.

    10.99.0.0/30 holds exactly two addresses, which is the shape every
    "two ends of a /30 must be cabled together" heuristic keys on. Both are
    SVIs, reaching each other through the access switch, so the heuristic would
    have invented a link that does not exist.
    """
    assert set(corpus) == {"l2_segments", "l2_adjacencies", "l3_adjacencies"}
    transit = next(
        adjacency
        for adjacency in corpus["l3_adjacencies"]
        if adjacency.prefix == "10.99.0.0/30"
    )
    assert len(transit.members) == 2
    assert transit.over_l2_segment == "vlan-99"


def test_derivation_is_stable_across_runs(corpus: Topology) -> None:
    pack, _ = build_fact_pack(CORPUS)
    assert derive(pack.devices, pack.vlans) == corpus


def test_the_result_populates_a_fact_pack_in_one_line(corpus: Topology) -> None:
    """The keys are `StaticFactPack` field names, so the builder can splat them."""
    pack, _ = build_fact_pack(CORPUS)
    filled = StaticFactPack(
        meta=pack.meta,
        devices=pack.devices,
        vlans=pack.vlans,
        **derive(pack.devices, pack.vlans),
    )
    assert filled.l3_adjacencies == corpus["l3_adjacencies"]
    assert filled.l2_segments == corpus["l2_segments"]
    assert filled.l2_adjacencies == corpus["l2_adjacencies"]
    assert filled.l1_links == ()
    assert filled.lags == ()


# --------------------------------------------------------------------------
# What must produce nothing
# --------------------------------------------------------------------------


def test_no_devices_derives_nothing() -> None:
    assert derive([], []) == Topology(
        l2_segments=(), l2_adjacencies=(), l3_adjacencies=()
    )


def test_a_single_device_is_adjacent_to_no_one() -> None:
    """Its VLANs are still broadcast domains; nothing is a peer of anything."""
    devices = [
        box(
            "solo",
            port("solo", "Ethernet1", addresses=("10.0.0.1/31",)),
            port("solo", "Ethernet2", mode=SwitchportMode.TRUNK, allowed=(14,)),
            port("solo", "Vlan14", addresses=("10.14.0.1/24",)),
        )
    ]
    topology = derive(devices, [Vlan(device="solo", vlan_id=14)])
    assert topology["l3_adjacencies"] == ()
    assert topology["l2_adjacencies"] == ()
    assert segments(topology) == {"vlan-14": ["solo:Ethernet2", "solo:Vlan14"]}


def test_devices_with_no_addresses_produce_no_l3_topology(tmp_path: Path) -> None:
    for name in ("sw1", "sw2"):
        (tmp_path / f"{name}.cfg").write_text(
            f"hostname {name}\n"
            "vlan 10\n"
            "interface Ethernet1\n"
            "   switchport mode trunk\n"
            "   switchport trunk allowed vlan 10\n"
        )
    pack, _ = build_fact_pack(tmp_path)
    topology = derive(pack.devices, pack.vlans)
    assert topology["l3_adjacencies"] == ()
    # The L2 half is unaffected: addressing is not what makes a broadcast domain.
    assert segments(topology) == {"vlan-10": ["sw1:Ethernet1", "sw2:Ethernet1"]}


def test_subnets_that_do_not_overlap_produce_no_adjacency() -> None:
    devices = [
        box("a", port("a", "Ethernet1", addresses=("10.0.0.1/31",))),
        box("b", port("b", "Ethernet1", addresses=("10.1.1.1/31",))),
    ]
    assert derive(devices, [])["l3_adjacencies"] == ()


def test_neighbouring_prefixes_of_different_lengths_do_not_meet() -> None:
    """`10.0.0.1/31` and `10.0.0.1/24` are one address in two different subnets.

    A containment test would call these adjacent. They are not: the /24 host
    would ARP for a /31 peer that does not answer, which is a defect to report
    rather than a link to draw.
    """
    devices = [
        box("a", port("a", "Ethernet1", addresses=("10.0.0.1/31",))),
        box("b", port("b", "Ethernet1", addresses=("10.0.0.2/24",))),
    ]
    assert derive(devices, [])["l3_adjacencies"] == ()


def test_one_devices_interfaces_sharing_a_subnet_are_not_an_adjacency() -> None:
    devices = [
        box(
            "a",
            port("a", "Ethernet1", addresses=("10.0.0.1/24",)),
            port("a", "Ethernet2", addresses=("10.0.0.2/24",)),
        )
    ]
    assert derive(devices, [])["l3_adjacencies"] == ()


def test_the_same_subnet_in_two_vrfs_is_two_networks() -> None:
    devices = [
        box("a", port("a", "Ethernet1", addresses=("10.0.0.1/24",), vrf="red")),
        box("b", port("b", "Ethernet1", addresses=("10.0.0.2/24",), vrf="blue")),
        box("c", port("c", "Ethernet1", addresses=("10.0.0.3/24",), vrf="red")),
    ]
    adjacencies = derive(devices, [])["l3_adjacencies"]
    assert [(adj.vrf, refs(adj)) for adj in adjacencies] == [
        ("red", ["a:Ethernet1", "c:Ethernet1"])
    ]


def test_shut_interfaces_join_nothing() -> None:
    devices = [
        box(
            "a",
            port("a", "Ethernet1", addresses=("10.0.0.1/31",), enabled=False),
            port(
                "a",
                "Ethernet2",
                mode=SwitchportMode.TRUNK,
                allowed=(14,),
                enabled=False,
            ),
        ),
        box(
            "b",
            port("b", "Ethernet1", addresses=("10.0.0.0/31",)),
            port("b", "Ethernet2", mode=SwitchportMode.TRUNK, allowed=(14,)),
        ),
    ]
    topology = derive(devices, [])
    assert topology["l3_adjacencies"] == ()
    assert topology["l2_adjacencies"] == ()
    assert segments(topology) == {"vlan-14": ["b:Ethernet2"]}


def test_a_trunk_with_no_allowed_list_claims_nothing() -> None:
    """Real hardware permits every VLAN; an empty tuple is too ambiguous to say so.

    It is equally consistent with a `switchport trunk allowed vlan` line no
    parser read, and inventing membership of every VLAN in the corpus from it
    would connect everything to everything.
    """
    devices = [
        box("a", port("a", "Ethernet1", mode=SwitchportMode.TRUNK)),
        box("b", port("b", "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(14,))),
    ]
    topology = derive(devices, [])
    assert topology["l2_adjacencies"] == ()
    assert segments(topology) == {"vlan-14": ["b:Ethernet1"]}


def test_trunks_sharing_no_vlan_are_not_adjacent() -> None:
    devices = [
        box("a", port("a", "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(14, 24))),
        box("b", port("b", "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(34,))),
    ]
    assert derive(devices, [])["l2_adjacencies"] == ()


# --------------------------------------------------------------------------
# Membership details
# --------------------------------------------------------------------------


def test_an_access_port_joins_its_vlan_and_a_routed_port_joins_none() -> None:
    devices = [
        box(
            "a",
            port("a", "Ethernet1", mode=SwitchportMode.ACCESS, access_vlan=14),
            # An access VLAN left behind on a port that was later made a trunk
            # or routed is not in use, and must not place the port.
            port(
                "a",
                "Ethernet2",
                mode=SwitchportMode.TRUNK,
                access_vlan=24,
                allowed=(34,),
            ),
            port(
                "a",
                "Ethernet3",
                mode=SwitchportMode.ROUTED,
                access_vlan=44,
                addresses=("10.0.0.1/31",),
            ),
        )
    ]
    assert segments(derive(devices, [])) == {
        "vlan-14": ["a:Ethernet1"],
        "vlan-34": ["a:Ethernet2"],
    }


def test_a_single_shared_vlan_names_the_segment_on_the_adjacency() -> None:
    devices = [
        box("a", port("a", "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(14, 24))),
        box("b", port("b", "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(24, 34))),
    ]
    (adjacency,) = derive(devices, [])["l2_adjacencies"]
    assert adjacency.vlans == (24,)
    assert adjacency.segment == segment_id(24)
    assert adjacency.over_lag is False


def test_an_adjacency_over_port_channels_is_marked_as_such() -> None:
    devices = [
        box("a", port("a", "Port-Channel1", mode=SwitchportMode.TRUNK, allowed=(14,))),
        box("b", port("b", "Port-Channel1", mode=SwitchportMode.TRUNK, allowed=(14,))),
    ]
    (adjacency,) = derive(devices, [])["l2_adjacencies"]
    assert adjacency.over_lag is True


def test_several_shared_vlans_leave_the_segment_unset() -> None:
    devices = [
        box("a", port("a", "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(14, 24))),
        box("b", port("b", "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(14, 24))),
    ]
    (adjacency,) = derive(devices, [])["l2_adjacencies"]
    assert adjacency.vlans == (14, 24)
    assert adjacency.segment is None


def test_a_secondary_address_is_its_own_subnet() -> None:
    devices = [
        box("a", port("a", "Vlan14", addresses=("10.14.0.2/24", "10.15.0.2/24"))),
        box("b", port("b", "Vlan14", addresses=("10.15.0.3/24",))),
    ]
    assert l3_edges(derive(devices, [])) == {"10.15.0.0/24": ["a:Vlan14", "b:Vlan14"]}


def test_ipv6_neighbours_are_derived_and_kept_apart_from_ipv4() -> None:
    devices = [
        box("a", port("a", "Ethernet1", addresses=("10.0.0.1/31", "2001:db8::1/64"))),
        box("b", port("b", "Ethernet1", addresses=("10.0.0.0/31", "2001:db8::2/64"))),
    ]
    adjacencies = derive(devices, [])["l3_adjacencies"]
    assert [(adj.prefix, adj.family) for adj in adjacencies] == [
        ("10.0.0.0/31", AddressFamily.IPV4_UNICAST),
        ("2001:db8::/64", AddressFamily.IPV6_UNICAST),
    ]


def test_an_unparsable_address_is_skipped_rather_than_raising() -> None:
    devices = [
        box("a", port("a", "Ethernet1", addresses=("not-an-address", "10.0.0.1/31"))),
        box("b", port("b", "Ethernet1", addresses=("10.0.0.0/31",))),
    ]
    assert list(l3_edges(derive(devices, []))) == ["10.0.0.0/31"]


def test_a_vlan_every_device_agrees_on_carries_its_stp_instance() -> None:
    devices = [
        box("a", port("a", "Ethernet1", mode=SwitchportMode.ACCESS, access_vlan=14)),
        box("b", port("b", "Ethernet1", mode=SwitchportMode.ACCESS, access_vlan=24)),
    ]
    vlans = [
        Vlan(device="a", vlan_id=14, stp_instance=1),
        Vlan(device="b", vlan_id=14, stp_instance=1),
        # Disagreement is a defect for a rule to report, not a value to pick.
        Vlan(device="a", vlan_id=24, stp_instance=1),
        Vlan(device="b", vlan_id=24, stp_instance=2),
    ]
    instances = {
        segment.id: segment.stp_instance
        for segment in derive(devices, vlans)["l2_segments"]
    }
    assert instances == {"vlan-14": 1, "vlan-24": None}


def test_a_declared_vlan_nothing_carries_gets_no_segment() -> None:
    devices = [box("a", port("a", "Ethernet1", addresses=("10.0.0.1/31",)))]
    vlans = [Vlan(device="a", vlan_id=999)]
    assert derive(devices, vlans)["l2_segments"] == ()


def test_meta_is_untouched_by_derivation() -> None:
    """Nothing here reads or writes identity; it is a pure function of the inputs."""
    meta = FactPackMeta(
        fact_pack_id="fp_0",
        schema_version=1,
        config_digest="0" * 64,
        source_snapshot="none",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    pack = StaticFactPack(meta=meta, **derive([], []))
    assert pack.meta is meta
