"""The EOS parser, against the corpus it has to handle.

Phase 1's "done when" is that the parser round-trips every construct in
`scenarios/site14_vrrp_lockstep/configs/`. These are the assertions that make that
objective rather than a feeling — including one that fails if the parser silently
skips something, which is the failure mode a permissive parser has.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders.eos import build_fact_pack, parse_device
from cassandra.factpack.schema import FhrpProtocol, InterfaceKind, SwitchportMode

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)


@pytest.fixture(scope="module")
def built() -> tuple[object, dict[str, tuple[str, ...]]]:
    return build_fact_pack(CORPUS)


def test_every_device_parsed(built: tuple) -> None:
    pack, _ = built
    assert {d.id for d in pack.devices} == {"core1", "agg-a", "agg-b", "acc1"}
    assert all(d.hostname == d.id for d in pack.devices)


def test_nothing_in_the_corpus_is_silently_skipped(built: tuple) -> None:
    """A permissive parser's failure mode is invisibility, not error. If this
    fails, the listed lines are constructs the fact pack does not know about."""
    _, unparsed = built
    leftovers = {device: lines for device, lines in unparsed.items() if lines}
    assert not leftovers, f"unaccounted config lines: {leftovers}"


def test_interface_kinds_and_addressing(built: tuple) -> None:
    pack, _ = built
    agg_a = next(d for d in pack.devices if d.id == "agg-a")
    by_name = {i.name: i for i in agg_a.interfaces}

    assert by_name["Vlan14"].kind is InterfaceKind.SVI
    assert by_name["Ethernet1"].kind is InterfaceKind.PHYSICAL
    assert by_name["Loopback0"].kind is InterfaceKind.LOOPBACK

    assert by_name["Vlan14"].addresses[0].prefix == "10.14.0.2/24"
    assert by_name["Ethernet1"].switchport_mode is SwitchportMode.ROUTED
    assert by_name["Ethernet2"].switchport_mode is SwitchportMode.TRUNK
    assert by_name["Ethernet2"].allowed_vlans == (14, 24, 34, 99)


def test_access_port_and_l2_only_device(built: tuple) -> None:
    pack, _ = built
    acc1 = next(d for d in pack.devices if d.id == "acc1")
    client_port = next(i for i in acc1.interfaces if i.name == "Ethernet3")
    assert client_port.switchport_mode is SwitchportMode.ACCESS
    assert client_port.access_vlan == 14
    assert not any(i.addresses for i in acc1.interfaces)


def test_fhrp_groups_span_both_devices(built: tuple) -> None:
    pack, _ = built
    groups = {g.group_number: g for g in pack.fhrp_groups}
    assert set(groups) == {14, 24, 34}
    for number, group in groups.items():
        assert group.protocol is FhrpProtocol.VRRP
        assert {m.device for m in group.members} == {"agg-a", "agg-b"}
        assert group.virtual_ipv4 == f"10.{number}.0.1"


def test_priorities_and_preempt_are_read_per_member(built: tuple) -> None:
    pack, _ = built
    group14 = next(g for g in pack.fhrp_groups if g.group_number == 14)
    priorities = {m.device: m.priority for m in group14.members}
    assert priorities == {"agg-a": 110, "agg-b": 100}
    assert all(m.preempt for m in group14.members)


def test_tracked_objects_resolve_to_their_target_interface(built: tuple) -> None:
    """The decrement lives on the group; the interface it watches is defined in a
    separate top-level stanza. A fact pack that does not join them cannot answer
    what happens when that interface goes down."""
    pack, _ = built
    group14 = next(g for g in pack.fhrp_groups if g.group_number == 14)
    agg_a = next(m for m in group14.members if m.device == "agg-a")
    assert len(agg_a.tracked_objects) == 1
    tracked = agg_a.tracked_objects[0]
    assert tracked.id == "UPLINK"
    assert tracked.decrement == 40
    assert tracked.target == "Ethernet1"

    agg_b = next(m for m in group14.members if m.device == "agg-b")
    assert agg_b.tracked_objects == ()


def test_the_asymmetry_survives_into_the_fact_pack(built: tuple) -> None:
    """The whole point of the corpus: group 34 tracks nothing, and group 24 waits
    where group 14 does not. If the fact pack loses that, the TIMING tier has
    nothing to find."""
    pack, _ = built
    tracked_by_group = {
        g.group_number: sum(len(m.tracked_objects) for m in g.members)
        for g in pack.fhrp_groups
    }
    assert tracked_by_group == {14: 1, 24: 1, 34: 0}

    delays = {
        t.scope.instance: t.preempt_delay_ms
        for t in pack.timers.fhrp
        if t.scope.device == "agg-a"
    }
    assert delays == {"14": None, "24": 90_000, "34": 90_000}


def test_timers_are_scoped_to_device_and_group(built: tuple) -> None:
    pack, _ = built
    assert len(pack.timers.fhrp) == 6
    for timer in pack.timers.fhrp:
        assert timer.scope.device in {"agg-a", "agg-b"}
        assert timer.scope.instance in {"14", "24", "34"}
        assert timer.hello_interval_ms == 1000


def test_meta_identifies_the_configs_it_came_from(built: tuple) -> None:
    pack, _ = built
    assert pack.meta.device_count == 4
    assert len(pack.meta.config_digest) == 64
    assert pack.meta.fact_pack_id.startswith("fp_")


def test_digest_changes_when_a_config_changes(tmp_path: Path) -> None:
    for name in ("a.cfg", "b.cfg"):
        (tmp_path / name).write_text("hostname x\n")
    first, _ = build_fact_pack(tmp_path)
    (tmp_path / "b.cfg").write_text("hostname x\ninterface Ethernet9\n   mtu 9214\n")
    second, _ = build_fact_pack(tmp_path)
    assert first.meta.config_digest != second.meta.config_digest


def test_vlan_ranges_expand() -> None:
    parsed = parse_device("hostname r\nvlan 10-12,20\n")
    assert parsed.unparsed_lines == ()
