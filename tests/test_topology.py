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
    StpMode,
    SwitchportMode,
    Vlan,
)
from cassandra.factpack.topology import (
    DEFAULT_BRIDGE_PRIORITY,
    BridgePriorities,
    Topology,
    derive,
    segment_id,
)

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


def test_a_segment_can_hold_members_no_adjacency_reaches() -> None:
    """The property the broadcast-domain rules in `cassandra.facts.rules` rest on.

    Membership of a segment and reachability inside it are two different claims,
    and the derivation keeps them apart: `b` terminates VLAN 14 on an SVI while
    trunking only VLAN 24, so it is a member of VLAN 14's segment and no
    adjacency carrying VLAN 14 touches it. A rule reading the segment alone
    would call the two devices one broadcast domain; the adjacencies are what
    say they are two.
    """
    devices = [
        box(
            "a",
            port("a", "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(14, 24)),
            port("a", "Vlan14", addresses=("192.0.2.2/24",)),
        ),
        box(
            "b",
            port("b", "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(24,)),
            port("b", "Vlan14", addresses=("192.0.2.3/24",)),
        ),
    ]
    topology = derive(devices, [])
    assert segments(topology)["vlan-14"] == ["a:Ethernet1", "a:Vlan14", "b:Vlan14"]
    assert [adjacency.vlans for adjacency in topology["l2_adjacencies"]] == [(24,)]
    # And the addressing still says the two SVIs share a subnet, which is the
    # disagreement `vlan-segment-split` reports.
    assert l3_edges(topology) == {"192.0.2.0/24": ["a:Vlan14", "b:Vlan14"]}


# --------------------------------------------------------------------------
# The spanning-tree election
#
# The half of a segment that is a comparison rather than a list. Every test
# here is really about one distinction: what a configuration states, and what
# may be inferred from its silence.
# --------------------------------------------------------------------------


def switch(name: str) -> Device:
    """A bridge with one trunk in VLAN 10 and no address anywhere."""
    return box(name, port(name, "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(10,)))


def elect(
    *,
    priorities: dict[str, BridgePriorities] | None = None,
    modes: dict[str, StpMode] | None = None,
    names: tuple[str, ...] = ("acc1", "agg-a", "agg-b"),
) -> L2Segment:
    """VLAN 10's segment, derived over the spanning-tree facts given."""
    topology = derive(
        [switch(name) for name in names],
        [Vlan(device=names[0], vlan_id=10)],
        stp_modes=modes,
        bridge_priorities=priorities,
    )
    (segment,) = topology["l2_segments"]
    return segment


def priced(**priorities: int) -> dict[str, BridgePriorities]:
    """Bridges that each state a priority for VLAN 10, and nothing else."""
    return {
        device: BridgePriorities(stated=((10, priority),), complete=True)
        for device, priority in priorities.items()
    }


def test_a_caller_with_no_spanning_tree_facts_gets_no_election() -> None:
    """The derivation is optional in both arguments, and the alternative to an
    election over invented numbers is no election at all."""
    segment = elect()
    assert segment.bridge_priorities == ()
    assert segment.root_bridge is None
    assert segment.stp_mode is StpMode.NONE


def test_a_bridge_that_states_no_priority_runs_the_default() -> None:
    """`complete` is the parser saying it accounted for every line on the device
    that could set a priority, which is what makes the absence of one a fact
    rather than a gap. 32768 is IEEE 802.1D-1998 table 8-4."""
    segment = elect(
        priorities={
            "acc1": BridgePriorities(complete=True),
            "agg-a": BridgePriorities(stated=((10, 4096),), complete=True),
            "agg-b": BridgePriorities(complete=True),
        }
    )
    assert dict(segment.bridge_priorities) == {
        "acc1": DEFAULT_BRIDGE_PRIORITY,
        "agg-a": 4096,
        "agg-b": DEFAULT_BRIDGE_PRIORITY,
    }
    assert segment.root_bridge == "agg-a"


def test_a_bridge_whose_priority_lines_were_not_all_read_states_nothing() -> None:
    """The distinction the whole field exists for. A device the parser could not
    account for is left out entirely rather than recorded at the default, which
    is the difference between "nobody changed this" and "nobody read this"."""
    segment = elect(
        priorities={
            "acc1": BridgePriorities(complete=False),
            "agg-a": BridgePriorities(stated=((10, 4096),), complete=True),
            "agg-b": BridgePriorities(complete=True),
        }
    )
    assert "acc1" not in dict(segment.bridge_priorities)
    # And with a member unaccounted for, the election is not this tool's to
    # call: the bridge left out is exactly the one that could have won it.
    assert segment.root_bridge is None


def test_a_priority_stated_for_another_vlan_does_not_reach_this_one() -> None:
    """A per-VLAN line is per VLAN. VLAN 20's priority says nothing about VLAN
    10 beyond what the device-wide default already said."""
    segment = elect(
        priorities={
            name: BridgePriorities(stated=((20, 4096),), complete=True)
            for name in ("acc1", "agg-a", "agg-b")
        }
    )
    assert set(dict(segment.bridge_priorities).values()) == {DEFAULT_BRIDGE_PRIORITY}


def test_the_lowest_priority_wins_and_a_tie_names_nobody() -> None:
    """The tie is broken on the bridge MAC address, which a configuration does
    not contain — so the segment carries no root rather than the first of two."""
    won = elect(
        priorities=priced(acc1=32768, **{"agg-a": 8192}), names=("acc1", "agg-a")
    )
    assert won.root_bridge == "agg-a"
    tied = elect(priorities=priced(acc1=32768, **{"agg-a": 8192, "agg-b": 8192}))
    assert tied.root_bridge is None
    assert dict(tied.bridge_priorities)["agg-b"] == 8192


def test_the_mode_is_the_one_every_member_that_states_one_agrees_on() -> None:
    segment = elect(
        modes={"acc1": StpMode.RAPID_PVST, "agg-a": StpMode.RAPID_PVST},
        names=("acc1", "agg-a"),
    )
    assert segment.stp_mode is StpMode.RAPID_PVST


def test_members_that_disagree_about_the_mode_leave_the_segment_with_none() -> None:
    """`StpMode` has one value for "no mode here" and none for "two", so a
    disagreement and a silence arrive as the same value. That is the field's
    shape, and a rule that needs to tell them apart has to compare the devices
    itself."""
    segment = elect(
        modes={"acc1": StpMode.MST, "agg-a": StpMode.RAPID_PVST},
        names=("acc1", "agg-a"),
    )
    assert segment.stp_mode is StpMode.NONE


def test_a_member_stating_no_mode_does_not_contradict_one_that_does() -> None:
    """A device with no `spanning-tree mode` line is running whatever it ships
    with, and reads out of the parser as `NONE` — the same value as one with
    spanning tree switched off. Neither reading may be treated as a mode, so
    the member is passed over rather than counted as a second opinion."""
    segment = elect(
        modes={"acc1": StpMode.NONE, "agg-a": StpMode.MST}, names=("acc1", "agg-a")
    )
    assert segment.stp_mode is StpMode.MST


def test_a_bridge_outside_the_segment_is_not_in_its_election() -> None:
    """A priority is only ever compared against the bridges in the same
    broadcast domain: VLAN 10's election does not include a switch that has no
    interface in VLAN 10, whatever it states."""
    devices = [
        switch("agg-a"),
        box(
            "agg-b",
            port("agg-b", "Ethernet1", mode=SwitchportMode.TRUNK, allowed=(20,)),
        ),
    ]
    topology = derive(
        devices,
        [Vlan(device="agg-a", vlan_id=10), Vlan(device="agg-b", vlan_id=20)],
        bridge_priorities=priced(**{"agg-a": 32768, "agg-b": 4096}),
    )
    vlan10 = next(s for s in topology["l2_segments"] if s.vlan_id == 10)
    assert dict(vlan10.bridge_priorities) == {"agg-a": DEFAULT_BRIDGE_PRIORITY}
    assert vlan10.root_bridge == "agg-a"
