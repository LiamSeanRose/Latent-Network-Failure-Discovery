"""Cisco IOS dialect, and the claim that the tiers above it are dialect-agnostic.

The headline test is `test_timing_tier_finds_the_same_failure_in_hsrp`: the same
asymmetry written in IOS with HSRP instead of EOS with VRRP produces the same
finding. If that holds, the parser is the only dialect-aware part of the system,
which is the design.

The BGP section at the foot makes the same claim for peerings: the three rules
that read across both ends of a session were written against EOS configs and are
exercised here against IOS ones, unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack, parse
from cassandra.factpack.builders.common import netmask_to_prefix_length
from cassandra.factpack.builders.ios import parse_device
from cassandra.factpack.schema import (
    BgpNeighbor,
    BgpProcess,
    FhrpProtocol,
    InterfaceKind,
    NosFamily,
)
from cassandra.facts.rules import evaluate
from cassandra.timing.sequences import analyse

IOS_TEMPLATE: Final = """!
version 15.2
hostname {name}
!
interface GigabitEthernet0/0
 description uplink to core
 ip address 10.0.0.{p2p} 255.255.255.254
 negotiation auto
!
interface Vlan14
 ip address 10.14.0.{host} 255.255.255.0
 standby 14 ip 10.14.0.1
 standby 14 priority {priority}
 standby 14 preempt
{g14}!
interface Vlan24
 ip address 10.24.0.{host} 255.255.255.0
 standby 24 ip 10.24.0.1
 standby 24 priority {priority}
 standby 24 preempt
{g24}!
track 1 interface GigabitEthernet0/0 line-protocol
!
end
"""

TRACK14: Final = " standby 14 track 1 decrement 40\n"
TRACK24: Final = " standby 24 track 1 decrement 40\n"
DELAY24: Final = " standby 24 preempt delay minimum 90\n"


def build(tmp_path: Path, *, g14: str = "", g24: str = "") -> object:
    (tmp_path / "dist-a.cfg").write_text(
        IOS_TEMPLATE.format(
            name="dist-a", p2p=1, host=2, priority=110, g14=g14, g24=g24
        )
    )
    (tmp_path / "dist-b.cfg").write_text(
        IOS_TEMPLATE.format(name="dist-b", p2p=3, host=3, priority=100, g14="", g24="")
    )
    pack, unparsed = build_fact_pack(tmp_path)
    return pack, unparsed


@pytest.mark.parametrize(
    ("netmask", "expected"),
    [
        ("255.255.255.0", 24),
        ("255.255.255.254", 31),
        ("255.255.0.0", 16),
        ("255.255.255.255", 32),
        ("0.0.0.0", 0),
        ("255.0.255.0", None),  # non-contiguous
        ("not.a.mask", None),
        ("255.255.255", None),
    ],
)
def test_netmask_conversion(netmask: str, expected: int | None) -> None:
    assert netmask_to_prefix_length(netmask) == expected


def test_dialect_is_detected_without_being_told(tmp_path: Path) -> None:
    ios_text = IOS_TEMPLATE.format(
        name="dist-a", p2p=1, host=2, priority=110, g14="", g24=""
    )
    assert parse(ios_text).device.nos_family is NosFamily.IOS_XE

    eos_text = "hostname sw1\ninterface Vlan14\n   ip address 10.14.0.2/24\n"
    assert parse(eos_text).device.nos_family is NosFamily.EOS


def test_ios_config_is_fully_accounted_for(tmp_path: Path) -> None:
    _, unparsed = build(tmp_path, g14=TRACK14, g24=TRACK24 + DELAY24)
    leftovers = {device: lines for device, lines in unparsed.items() if lines}
    assert not leftovers, f"unaccounted IOS lines: {leftovers}"


def test_hsrp_groups_and_addressing(tmp_path: Path) -> None:
    pack, _ = build(tmp_path, g14=TRACK14, g24=TRACK24 + DELAY24)
    groups = {g.group_number: g for g in pack.fhrp_groups}
    assert set(groups) == {14, 24}
    assert groups[14].protocol is FhrpProtocol.HSRP
    assert groups[14].virtual_ipv4 == "10.14.0.1"
    assert {m.device for m in groups[14].members} == {"dist-a", "dist-b"}

    dist_a = next(d for d in pack.devices if d.id == "dist-a")
    vlan14 = next(i for i in dist_a.interfaces if i.name == "Vlan14")
    assert vlan14.kind is InterfaceKind.SVI
    assert vlan14.addresses[0].prefix == "10.14.0.2/24"
    uplink = next(i for i in dist_a.interfaces if i.name == "GigabitEthernet0/0")
    assert uplink.kind is InterfaceKind.PHYSICAL
    assert uplink.addresses[0].prefix == "10.0.0.1/31"


def test_numbered_track_objects_resolve(tmp_path: Path) -> None:
    """IOS tracks are numbered rather than named; the join must still work."""
    pack, _ = build(tmp_path, g14=TRACK14)
    group14 = next(g for g in pack.fhrp_groups if g.group_number == 14)
    member = next(m for m in group14.members if m.device == "dist-a")
    tracked = member.tracked_objects[0]
    assert tracked.id == "1"
    assert tracked.target == "GigabitEthernet0/0"
    assert tracked.decrement == 40


def test_timing_tier_finds_the_same_failure_in_hsrp(tmp_path: Path) -> None:
    """The point of the dialect work: one parser changes, nothing above it does."""
    pack, _ = build(tmp_path, g14=TRACK14, g24=TRACK24 + DELAY24)
    divergences = [f for f in analyse(pack) if f.rule == "fhrp-divergence"]
    assert divergences, "the timing tier found nothing in the HSRP configs"
    assert "HSRP 14" in divergences[0].title
    assert "HSRP 24" in divergences[0].title
    assert divergences[0].trigger and "GigabitEthernet0/0" in divergences[0].trigger


def test_facts_rules_apply_to_hsrp_too(tmp_path: Path) -> None:
    pack, _ = build(tmp_path, g14=" standby 14 track 1 decrement 5\n")
    fired = {f.rule for f in evaluate(pack)}
    assert "fhrp-track-ineffective" in fired


def test_hsrp_timers_are_read(tmp_path: Path) -> None:
    (tmp_path / "r.cfg").write_text(
        "hostname r\ninterface Vlan14\n ip address 10.14.0.2 255.255.255.0\n"
        " standby 14 ip 10.14.0.1\n standby 14 timers 3 10\n"
    )
    pack, _ = build_fact_pack(tmp_path)
    timer = pack.timers.fhrp[0]
    assert timer.hello_interval_ms == 3000
    assert timer.hold_time_ms == 10_000


# --------------------------------------------------------------------------
# BGP peerings
# --------------------------------------------------------------------------

IOS_BGP: Final = """hostname dist-a
!
interface Loopback0
 ip address 10.255.0.1 255.255.255.255
!
interface GigabitEthernet0/0
 ip address 10.0.0.0 255.255.255.254
!
router bgp 65000
 bgp router-id 10.255.0.1
 bgp log-neighbor-changes
 no synchronization
 no auto-summary
 timers bgp 10 30
 network 10.14.0.0 mask 255.255.255.0
 maximum-paths 4
 neighbor CORE peer-group
 neighbor CORE remote-as 65001
 neighbor CORE update-source Loopback0
 neighbor 10.0.0.1 remote-as 65001
 neighbor 10.0.0.1 description core1 uplink
 neighbor 10.0.0.1 update-source GigabitEthernet0/0
 neighbor 10.0.0.1 fall-over bfd
 neighbor 10.0.0.3 peer-group CORE
 neighbor 10.0.0.5 password 7 070C285F4D06
 neighbor 10.0.0.5 maximum-prefix 1000 80
 neighbor 10.0.0.5 timers 10 30
 neighbor 10.0.0.7 remote-as 65004
 neighbor 10.0.0.7 ebgp-multihop 2
 neighbor 10.0.0.9 remote-as 65005
 neighbor 10.0.0.9 shutdown
 address-family ipv4
  neighbor 10.0.0.1 activate
  neighbor 10.0.0.1 next-hop-self
  neighbor 10.0.0.1 send-community
  neighbor 10.0.0.1 soft-reconfiguration inbound
  neighbor 10.0.0.1 route-map RM-IN in
 exit-address-family
!
end
"""


@pytest.fixture(scope="module")
def bgp() -> BgpProcess:
    parsed = parse_device(IOS_BGP)
    assert len(parsed.bgp) == 1
    return parsed.bgp[0]


def peer(process: BgpProcess, address: str) -> BgpNeighbor:
    return next(n for n in process.neighbors if n.address == address)


def test_the_bgp_block_leaves_nothing_unaccounted_for() -> None:
    """The failure mode of a permissive parser is silence, so this is the test
    that has to hold before any of the field assertions mean anything."""
    parsed = parse_device(IOS_BGP)
    assert parsed.unparsed_lines == (), (
        f"unaccounted BGP lines: {parsed.unparsed_lines}"
    )


def test_the_process_carries_its_asn_and_router_id(bgp: BgpProcess) -> None:
    assert bgp.local_as == "65000"
    assert bgp.router_id == "10.255.0.1"


def test_peer_settings_are_read(bgp: BgpProcess) -> None:
    core = peer(bgp, "10.0.0.1")
    assert core.remote_as == "65001"
    assert core.description == "core1 uplink"
    assert core.update_source == "GigabitEthernet0/0"
    assert core.bfd


def test_ebgp_multihop_and_shutdown_are_read(bgp: BgpProcess) -> None:
    assert peer(bgp, "10.0.0.7").multihop
    assert peer(bgp, "10.0.0.9").shutdown
    assert not peer(bgp, "10.0.0.1").shutdown


def test_a_peer_known_only_by_settings_we_do_not_read_is_still_a_peering(
    bgp: BgpProcess,
) -> None:
    """The one that matters for the reciprocity rule: a neighbour configured
    only with a password, a prefix limit and timers is a real session, and
    dropping it would report the far end as one-sided when it is not."""
    quiet = peer(bgp, "10.0.0.5")
    assert quiet.remote_as is None
    assert not quiet.shutdown


def test_a_peer_group_definition_is_not_a_peering(bgp: BgpProcess) -> None:
    """`neighbor CORE peer-group` names a bag of settings, not a neighbour."""
    assert [n.address for n in bgp.neighbors] == [
        "10.0.0.1",
        "10.0.0.3",
        "10.0.0.5",
        "10.0.0.7",
        "10.0.0.9",
    ]


def test_peer_group_settings_reach_the_member(bgp: BgpProcess) -> None:
    """A great many IOS configs state remote-as once, on the group."""
    member = peer(bgp, "10.0.0.3")
    assert member.peer_group == "CORE"
    assert member.remote_as == "65001"
    assert member.update_source == "Loopback0"


def test_a_members_own_setting_beats_the_groups() -> None:
    parsed = parse_device(
        "hostname r\nrouter bgp 65000\n neighbor CORE peer-group\n"
        " neighbor CORE remote-as 65001\n neighbor 10.0.0.1 peer-group CORE\n"
        " neighbor 10.0.0.1 remote-as 65009\n"
    )
    assert parsed.bgp[0].neighbors[0].remote_as == "65009"


def test_an_unhandled_bgp_line_is_reported_rather_than_dropped() -> None:
    """`bgp dampening` is a timer this dialect does not read yet. It has to stay
    visible, because an unhandled construct that reports nothing is invisible."""
    parsed = parse_device(
        "hostname r\nrouter bgp 65000\n bgp dampening 15 750 2000 60\n"
    )
    assert parsed.unparsed_lines == ("bgp dampening 15 750 2000 60",)


def test_an_unreadable_peer_setting_still_leaves_the_peering() -> None:
    """Reported, because the parser did not understand the line — and registered,
    because not understanding a setting is not evidence the peer is absent."""
    parsed = parse_device(
        "hostname r\nrouter bgp 65000\n neighbor 10.0.0.1 invented-setting 4\n"
    )
    assert parsed.unparsed_lines == ("neighbor 10.0.0.1 invented-setting 4",)
    assert [n.address for n in parsed.bgp[0].neighbors] == ["10.0.0.1"]


# --------------------------------------------------------------------------
# End to end: the cross-device rules, on IOS syntax
# --------------------------------------------------------------------------

IOS_BGP_PAIR: Final = """hostname {name}
!
interface GigabitEthernet0/0
 ip address 10.0.0.{addr} 255.255.255.254
!
router bgp {local_as}
 bgp router-id 10.255.0.{rid}
{neighbors}!
end
"""


def bgp_pair(
    tmp_path: Path,
    *,
    a_neighbors: str,
    b_neighbors: str = "",
    b_as: str = "65002",
) -> object:
    (tmp_path / "dist-a.cfg").write_text(
        IOS_BGP_PAIR.format(
            name="dist-a", addr=0, local_as="65000", rid=1, neighbors=a_neighbors
        )
    )
    (tmp_path / "dist-b.cfg").write_text(
        IOS_BGP_PAIR.format(
            name="dist-b", addr=1, local_as=b_as, rid=2, neighbors=b_neighbors
        )
    )
    pack, unparsed = build_fact_pack(tmp_path)
    assert not any(unparsed.values()), f"unaccounted lines: {unparsed}"
    return pack


def test_ios_bgp_reaches_the_cross_device_rules(tmp_path: Path) -> None:
    """Two devices, IOS syntax, and both rules that read across the pair fire —
    which is only possible if the fact pack collected the processes."""
    pack = bgp_pair(
        tmp_path,
        a_neighbors=(
            " neighbor 10.0.0.1 remote-as 65001\n"
            " neighbor 10.0.0.1 description dist-b\n"
            " neighbor 10.0.0.1 fall-over bfd\n"
        ),
    )
    assert pack.devices[0].nos_family is NosFamily.IOS_XE
    fired = {f.rule for f in evaluate(pack)}
    assert "bgp-remote-as-mismatch" in fired
    assert "bgp-session-one-sided" in fired


def test_ios_reciprocated_bgp_session_is_silent(tmp_path: Path) -> None:
    pack = bgp_pair(
        tmp_path,
        a_neighbors=" neighbor 10.0.0.1 remote-as 65002\n",
        b_neighbors=" neighbor 10.0.0.0 remote-as 65000\n",
    )
    fired = {f.rule for f in evaluate(pack)}
    assert "bgp-remote-as-mismatch" not in fired
    assert "bgp-session-one-sided" not in fired


def test_a_far_end_known_only_by_a_password_is_not_a_one_sided_session(
    tmp_path: Path,
) -> None:
    """The peering the far end states without a remote-as is still a peering."""
    pack = bgp_pair(
        tmp_path,
        a_neighbors=" neighbor 10.0.0.1 remote-as 65002\n",
        b_neighbors=" neighbor 10.0.0.0 password 7 070C285F4D06\n",
    )
    assert "bgp-session-one-sided" not in {f.rule for f in evaluate(pack)}


def test_ios_peer_off_every_local_subnet(tmp_path: Path) -> None:
    pack = bgp_pair(tmp_path, a_neighbors=" neighbor 192.0.2.9 remote-as 65001\n")
    assert "bgp-peer-off-subnet" in {f.rule for f in evaluate(pack)}
