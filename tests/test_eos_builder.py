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

from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.builders.eos import EosDevice, parse_device
from cassandra.factpack.schema import (
    DampeningKind,
    FhrpProtocol,
    IgpProtocol,
    InterfaceKind,
    SwitchportMode,
    TimerSource,
)
from cassandra.facts.rules import evaluate

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


# --------------------------------------------------------------------------
# Timer inventory beyond FHRP: BFD, IGP hello/dead, and BGP dampening
# --------------------------------------------------------------------------

ROUTED: Final = """hostname agg-a
interface Ethernet1
   no switchport
   ip address 10.0.0.1/31
{extra}"""


def routed(*lines: str, trailer: str = "") -> EosDevice:
    body = "".join(f"   {line}\n" for line in lines)
    return parse_device(ROUTED.format(extra=body) + trailer, device_id="agg-a")


def test_bfd_interval_line_becomes_a_session() -> None:
    parsed = routed("bfd interval 300 min_rx 300 multiplier 3")
    assert len(parsed.bfd) == 1
    session = parsed.bfd[0]
    assert session.desired_min_tx_ms == 300
    assert session.required_min_rx_ms == 300
    assert session.detect_multiplier == 3
    assert session.scope.device == "agg-a"
    assert session.scope.interface == "Ethernet1"
    assert session.scope.source is TimerSource.CONFIGURED
    assert parsed.unparsed_lines == ()


def test_bfd_accepts_the_hyphenated_min_rx_spelling() -> None:
    parsed = routed("bfd interval 300 min-rx 300 multiplier 3")
    assert parsed.bfd[0].required_min_rx_ms == 300
    assert parsed.unparsed_lines == ()


def test_a_session_with_nothing_registered_has_no_clients() -> None:
    """The empty tuple is the fact the analysis reads, so it has to be real
    absence rather than something the parser never looked for."""
    parsed = routed("bfd interval 300 min_rx 300 multiplier 3")
    assert parsed.bfd[0].clients == ()


def test_interface_protocols_register_as_bfd_clients() -> None:
    parsed = routed(
        "bfd interval 300 min_rx 300 multiplier 3", "ip ospf bfd", "isis bfd"
    )
    assert parsed.bfd[0].clients == ("isis", "ospf")
    assert parsed.unparsed_lines == ()


def test_a_bgp_neighbour_registers_by_address() -> None:
    parsed = routed(
        "bfd interval 300 min_rx 300 multiplier 3",
        trailer="router bgp 65001\n   neighbor 10.0.0.0 bfd\n",
    )
    assert parsed.bfd[0].clients == ("bgp",)


def test_a_bgp_neighbour_off_the_subnet_registers_nothing() -> None:
    parsed = routed(
        "bfd interval 300 min_rx 300 multiplier 3",
        trailer="router bgp 65001\n   neighbor 198.51.100.9 bfd\n",
    )
    assert parsed.bfd[0].clients == ()


def test_bfd_default_under_a_process_registers_that_process() -> None:
    parsed = routed(
        "bfd interval 300 min_rx 300 multiplier 3",
        trailer="router ospf 1\n   bfd default\n",
    )
    assert parsed.bfd[0].clients == ("ospf",)


def test_ospf_hello_and_dead_intervals_are_read_in_milliseconds() -> None:
    parsed = routed("ip ospf hello-interval 10", "ip ospf dead-interval 40")
    assert len(parsed.igp_hello) == 1
    timers = parsed.igp_hello[0]
    assert timers.protocol is IgpProtocol.OSPFV2
    assert timers.hello_interval_ms == 10_000
    assert timers.dead_interval_ms == 40_000
    assert timers.scope.interface == "Ethernet1"
    assert parsed.unparsed_lines == ()


def test_ospf_area_is_kept_when_the_interface_states_it() -> None:
    parsed = routed("ip ospf area 0.0.0.0", "ip ospf hello-interval 10")
    assert parsed.igp_hello[0].ospf_area == "0.0.0.0"


def test_isis_records_the_multiplier_rather_than_a_derived_hold_time() -> None:
    """The hold time is hello x multiplier, and deriving it here would hide which
    of the two an operator actually wrote."""
    parsed = routed("isis hello-interval 3", "isis hello-multiplier 3")
    timers = parsed.igp_hello[0]
    assert timers.protocol is IgpProtocol.ISIS
    assert timers.hello_interval_ms == 3_000
    assert timers.hello_multiplier == 3
    assert timers.dead_interval_ms is None
    assert timers.hold_time_ms is None


def test_ospf_and_isis_on_one_interface_produce_one_record_each() -> None:
    parsed = routed(
        "ip ospf dead-interval 40", "isis hello-interval 3", "isis hello-multiplier 3"
    )
    assert {t.protocol for t in parsed.igp_hello} == {
        IgpProtocol.OSPFV2,
        IgpProtocol.ISIS,
    }


def test_bgp_dampening_is_stated_in_minutes_and_stored_in_seconds() -> None:
    parsed = parse_device(
        "hostname agg-a\nrouter bgp 65001\n"
        "   bgp dampening half-life 15 reuse 750 suppress 2000 max-suppress-time 60\n",
        device_id="agg-a",
    )
    assert len(parsed.dampening) == 1
    profile = parsed.dampening[0]
    assert profile.kind is DampeningKind.BGP_ROUTE
    assert profile.half_life_s == 900
    assert profile.reuse_threshold == 750
    assert profile.suppress_threshold == 2000
    assert profile.max_suppress_s == 3600
    assert profile.scope.instance == "65001"
    assert profile.scope.source is TimerSource.CONFIGURED
    assert parsed.unparsed_lines == ()


def test_bare_bgp_dampening_records_the_platform_defaults() -> None:
    """A bare `bgp dampening` is not an absence of timers — it selects an
    hour-long suppression window, and the provenance says it was inherited."""
    parsed = parse_device(
        "hostname agg-a\nrouter bgp 65001\n   bgp dampening\n", device_id="agg-a"
    )
    profile = parsed.dampening[0]
    assert profile.max_suppress_s == 3600
    assert profile.half_life_s == 900
    assert profile.scope.source is TimerSource.PLATFORM_DEFAULT


def test_the_longer_limit_spellings_are_the_same_thresholds() -> None:
    parsed = parse_device(
        "hostname agg-a\nrouter bgp 65001\n"
        "   bgp dampening half-life 5 reuse-limit 750 suppress-limit 2000 "
        "max-suppress-time 20\n",
        device_id="agg-a",
    )
    profile = parsed.dampening[0]
    assert (profile.reuse_threshold, profile.suppress_threshold) == (750, 2000)
    assert profile.max_suppress_s == 1200


def test_an_unrecognised_dampening_argument_is_surfaced_not_guessed() -> None:
    parsed = parse_device(
        "hostname agg-a\nrouter bgp 65001\n   bgp dampening route-map DAMP\n",
        device_id="agg-a",
    )
    assert parsed.dampening == ()
    assert parsed.unparsed_lines == ("bgp dampening route-map DAMP",)


def test_the_corpus_still_produces_no_timers_it_does_not_configure(
    built: tuple,
) -> None:
    """Silence is a parser result too: inventing a BFD session or a dampening
    profile the configs never mention would make every finding over them false."""
    pack, _ = built
    assert pack.timers.bfd == ()
    assert pack.timers.dampening == ()
    # Neither BGP session timing nor spanning-tree timing is stated anywhere in
    # this corpus. The corpus is pinned by digest and by finding set, so a
    # parser that started inventing either would change what the scenario is
    # evidence of without changing a line of it.
    assert pack.timers.bgp == ()
    assert pack.timers.stp == ()


REUSED_GROUP: Final = """hostname {name}
vlan 10,20
interface Vlan10
   ip address 10.10.0.{host}/24
   vrrp 1 ipv4 10.10.0.1
   vrrp 1 priority-level {priority}
   vrrp 1 preempt
interface Vlan20
   ip address 10.20.0.{host}/24
   vrrp 1 ipv4 10.20.0.1
   vrrp 1 priority-level {priority}
   vrrp 1 preempt
"""


def test_a_group_number_reused_on_another_subnet_is_a_separate_group(
    tmp_path: Path,
) -> None:
    """Reusing a group number per VLAN is ordinary configuration.

    Keying groups on number alone merged them, which threw away the second
    subnet's virtual address and doubled the member list. That produced three
    findings on a config with nothing wrong with it — a virtual address
    "outside its own subnet" twice, and a bogus priority tie. False positives
    are the fastest way to make the tool worth ignoring, so this is a
    regression test rather than a unit test.
    """
    for name, host, priority in (("sw-a", 2, 110), ("sw-b", 3, 100)):
        (tmp_path / f"{name}.cfg").write_text(
            REUSED_GROUP.format(name=name, host=host, priority=priority)
        )
    pack, _ = build_fact_pack(tmp_path)

    assert len(pack.fhrp_groups) == 2, "group 1 on two subnets must stay two groups"
    by_virtual = {g.virtual_ipv4: g for g in pack.fhrp_groups}
    assert set(by_virtual) == {"10.10.0.1", "10.20.0.1"}
    for group in pack.fhrp_groups:
        assert group.group_number == 1
        assert len(group.members) == 2, "one member per device, not four"
        assert {m.device for m in group.members} == {"sw-a", "sw-b"}

    # Ids stay disambiguated so a finding can name which group it means.
    assert len({g.id for g in pack.fhrp_groups}) == 2


def test_an_unreused_group_number_keeps_the_short_id() -> None:
    """The subnet only appears in an id when it is doing work."""
    pack, _ = build_fact_pack(CORPUS)
    assert {g.id for g in pack.fhrp_groups} == {"vrrp-14", "vrrp-24", "vrrp-34"}


# --------------------------------------------------------------------------
# `switchport trunk allowed vlan` is a command, not a list
#
# All three switching dialects accept `add`, `remove`, `none`, `all` and
# `except`, and all three matched only a bare id list. The `add` form — the
# normal way to extend an allowed list across several lines — therefore read as
# nothing, the VLAN went missing from `allowed_vlans`, and
# `access-vlan-not-trunked` fired HIGH on a trunk that permits it.
# --------------------------------------------------------------------------

ADDED_VLAN: Final = """hostname acc1
!
vlan 10
!
vlan 20
!
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 10
   switchport trunk allowed vlan add 20
!
interface Ethernet2
   switchport mode access
   switchport access vlan 20
"""


def test_an_added_vlan_joins_the_allowed_list() -> None:
    parsed = parse_device(ADDED_VLAN, device_id="acc1")
    trunk = next(i for i in parsed.device.interfaces if i.name == "Ethernet1")
    assert trunk.allowed_vlans == (10, 20)
    assert parsed.unparsed_lines == ()


def test_a_trunk_that_permits_the_access_vlan_by_add_is_not_reported(
    tmp_path: Path,
) -> None:
    """A trunk permits a VLAN however its allowed list was written. VLAN 20
    reaches this switch's uplink through `switchport trunk allowed vlan add 20`
    exactly as it would through a longer single line, so the access port reaches
    its gateway and there is nothing to report. Reading only the first form
    turned that into a HIGH finding against a correct trunk."""
    (tmp_path / "acc1.cfg").write_text(ADDED_VLAN)
    (tmp_path / "agg1.cfg").write_text(
        "hostname agg1\n"
        "!\n"
        "vlan 20\n"
        "!\n"
        "interface Vlan20\n"
        "   ip address 198.51.100.1/24\n"
        "!\n"
        "interface Ethernet1\n"
        "   switchport mode trunk\n"
        "   switchport trunk allowed vlan 20\n"
    )
    pack, unparsed = build_fact_pack(tmp_path)
    assert not any(unparsed.values())
    assert "access-vlan-not-trunked" not in {f.rule for f in evaluate(pack)}


@pytest.mark.parametrize(
    ("lines", "expected"),
    [
        (["switchport trunk allowed vlan 10,20"], (10, 20)),
        (
            [
                "switchport trunk allowed vlan 10",
                "switchport trunk allowed vlan add 20",
            ],
            (10, 20),
        ),
        (
            [
                "switchport trunk allowed vlan 10,20",
                "switchport trunk allowed vlan remove 10",
            ],
            (20,),
        ),
        (
            [
                "switchport trunk allowed vlan 10,20",
                "switchport trunk allowed vlan none",
            ],
            (),
        ),
        (
            [
                "switchport trunk allowed vlan add 30",
                "switchport trunk allowed vlan 10",
            ],
            (10,),
        ),
    ],
)
def test_every_keyword_of_the_command_is_read(
    lines: list[str], expected: tuple[int, ...]
) -> None:
    """`add` unions, `remove` subtracts, `none` empties, and a list with no
    keyword replaces whatever came before it."""
    body = "".join(f"   {line}\n" for line in lines)
    parsed = parse_device(
        f"hostname sw1\ninterface Ethernet1\n   switchport mode trunk\n{body}",
        device_id="sw1",
    )
    (trunk,) = parsed.device.interfaces
    assert trunk.allowed_vlans == expected
    assert parsed.unparsed_lines == ()


def test_except_is_the_complement_within_the_standard_range() -> None:
    """`except 10` permits every VLAN 802.1Q defines but that one, which is 4093
    of them — not an unreadable list, and not an empty one."""
    parsed = parse_device(
        "hostname sw1\n"
        "interface Ethernet1\n"
        "   switchport mode trunk\n"
        "   switchport trunk allowed vlan except 10\n",
        device_id="sw1",
    )
    (trunk,) = parsed.device.interfaces
    assert len(trunk.allowed_vlans) == 4093
    assert 10 not in trunk.allowed_vlans
    assert trunk.allowed_vlans[0] == 1 and trunk.allowed_vlans[-1] == 4094


def test_a_keyword_this_cannot_read_leaves_the_trunk_alone() -> None:
    """The direction that matters. Reducing the allowed list to nothing on a form
    this parser does not know turns a gap in the parser into a HIGH finding
    against the operator, so an unreadable line is reported and the list the
    previous lines built is kept."""
    parsed = parse_device(
        "hostname sw1\n"
        "interface Ethernet1\n"
        "   switchport mode trunk\n"
        "   switchport trunk allowed vlan 10,20\n"
        "   switchport trunk allowed vlan attach 30\n",
        device_id="sw1",
    )
    (trunk,) = parsed.device.interfaces
    assert trunk.allowed_vlans == (10, 20)
    assert parsed.unparsed_lines == ("switchport trunk allowed vlan attach 30",)


def test_an_unreadable_id_inside_an_add_is_still_reported() -> None:
    """The `unreadable_vlans` reporting the bare-list form already had, kept on
    the whole command: a VLAN silently dropped from a trunk looks exactly like a
    VLAN the operator forgot."""
    parsed = parse_device(
        "hostname sw1\n"
        "interface Ethernet1\n"
        "   switchport mode trunk\n"
        "   switchport trunk allowed vlan 10\n"
        "   switchport trunk allowed vlan add 20,LEGACY\n",
        device_id="sw1",
    )
    (trunk,) = parsed.device.interfaces
    assert trunk.allowed_vlans == (10, 20)
    assert parsed.unparsed_lines == (
        "switchport trunk allowed vlan add 20,LEGACY  [unreadable: LEGACY]",
    )


# --------------------------------------------------------------------------
# Preemption defaults to on
#
# RFC 3768 section 6.1 and RFC 5798 make `Preempt_Mode` default True, and EOS
# ships VRRP that way. The parser set the flag only where the word appeared, so a
# group that simply omits the line — the common case, because the default is what
# people want — reached the pack as preempt-off.
# --------------------------------------------------------------------------

VRRP_SILENT_ON_PREEMPT: Final = """hostname agg-a
!
vlan 14
!
interface Vlan14
   ip address 198.51.100.2/24
   vrrp 14 ipv4 198.51.100.1
   vrrp 14 priority-level 110
"""


def test_a_vrrp_group_that_says_nothing_about_preempt_preempts() -> None:
    parsed = parse_device(VRRP_SILENT_ON_PREEMPT, device_id="agg-a")
    (record,) = parsed.fhrp_records
    assert record.member.preempt is True
    assert record.member.preempt_source is TimerSource.PLATFORM_DEFAULT


def test_a_vrrp_group_that_writes_preempt_is_marked_as_having_said_so() -> None:
    """The provenance the bool cannot carry. Both groups preempt; only one of
    them has an operator behind that."""
    parsed = parse_device(
        VRRP_SILENT_ON_PREEMPT + "   vrrp 14 preempt\n", device_id="agg-a"
    )
    (record,) = parsed.fhrp_records
    assert record.member.preempt is True
    assert record.member.preempt_source is TimerSource.CONFIGURED


def test_no_vrrp_preempt_turns_it_off_instead_of_going_unparsed() -> None:
    """The negation used to fall through to `unparsed_lines` while the group it
    names was recorded as preempt-off regardless — the right answer by accident,
    which meant it was no answer at all."""
    parsed = parse_device(
        VRRP_SILENT_ON_PREEMPT + "   no vrrp 14 preempt\n", device_id="agg-a"
    )
    (record,) = parsed.fhrp_records
    assert record.member.preempt is False
    assert record.member.preempt_source is TimerSource.CONFIGURED
    assert parsed.unparsed_lines == ()
