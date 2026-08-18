"""Cisco IOS dialect, and the claim that the tiers above it are dialect-agnostic.

The headline test is `test_timing_tier_finds_the_same_failure_in_hsrp`: the same
asymmetry written in IOS with HSRP instead of EOS with VRRP produces the same
finding. If that holds, the parser is the only dialect-aware part of the system,
which is the design.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack, parse
from cassandra.factpack.builders.common import netmask_to_prefix_length
from cassandra.factpack.schema import FhrpProtocol, InterfaceKind, NosFamily
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
