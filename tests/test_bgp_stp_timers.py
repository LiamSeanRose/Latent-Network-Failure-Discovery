"""BGP and spanning-tree timers, from the config line to the finding.

Two whole timer families were declared in the schema and filled by nobody, and
the lines that would have filled them were being absorbed rather than reported —
`neighbor <ip> timers 3 9` by the recognised-but-unread peer settings, `timers
bgp` by the process filter, every `spanning-tree` line by the out-of-scope
matcher. An empty inventory looked exactly like a network that configures none
of it, which is why the gap survived.

These tests hold the whole path: what each dialect writes, what the schema keeps,
and both directions of every rule the facts made possible. The pack is built from
config text through `build_fact_pack` rather than from hand-made dataclasses, so
a parser that stops producing a timer fails here instead of quietly emptying the
analysis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack, eos, ios, nxos, parse
from cassandra.factpack.schema import BgpTimers, StaticFactPack, StpMode, TimerSource
from cassandra.timing.timer_rules import analyse

ROOT: Final = Path(__file__).resolve().parents[1]

# The three corpora that ship with the tool. They are pinned elsewhere by digest
# and by finding set, so a new rule that fires on one of them has changed what
# the documentation says the tool does.
SHIPPED: Final[tuple[Path, ...]] = (
    ROOT / "scenarios" / "site14_vrrp_lockstep" / "configs",
    ROOT / "scenarios" / "hsrp_preempt_split" / "configs",
    ROOT / "examples" / "two-site",
)


def build(tmp_path: Path, **configs: str) -> StaticFactPack:
    """Write configs to a directory and build the pack every tier reads.

    Nothing in this file may leave a line unparsed. These configs are small and
    written here, so an unparsed line means a construct under test was dropped
    rather than read, and every assertion after it would be about a fact that is
    missing for the wrong reason.
    """
    for name, text in configs.items():
        (tmp_path / f"{name}.cfg").write_text(text)
    pack, unparsed = build_fact_pack(tmp_path)
    leftovers = {device: lines for device, lines in unparsed.items() if lines}
    assert not leftovers, f"unaccounted config lines: {leftovers}"
    return pack


def rules_fired(pack: StaticFactPack) -> set[str]:
    return {finding.rule for finding in analyse(pack)}


def bgp_timers(
    pack: StaticFactPack, device: str, neighbor: str | None = None
) -> BgpTimers:
    """The one BGP timer record for a device's process, or for one of its peers."""
    found = [
        timers
        for timers in pack.timers.bgp
        if timers.scope.device == device and timers.scope.neighbor == neighbor
    ]
    assert len(found) == 1, f"{device}/{neighbor}: {found}"
    return found[0]


# --------------------------------------------------------------------------
# What each dialect writes
# --------------------------------------------------------------------------

EOS: Final = """hostname eos1
!
spanning-tree mode rapid-pvst
spanning-tree forward-time 15
spanning-tree vlan-id 10,20 hello-time 2000
spanning-tree vlan-id 10,20 max-age 20
!
interface Ethernet1
   no switchport
   ip address 10.0.0.1/31
!
router bgp 65001
   timers bgp 30 90
   graceful-restart restart-time 300
   graceful-restart stalepath-time 600
   neighbor 10.0.0.0 remote-as 65002
   neighbor 10.0.0.0 timers 10 30
   neighbor 10.0.1.0 remote-as 65003
!
end
"""

IOS: Final = """hostname ios1
!
spanning-tree mode rapid-pvst
spanning-tree forward-time 15
spanning-tree vlan 10,20 hello-time 2
spanning-tree vlan 10,20 max-age 20
!
interface GigabitEthernet0/1
 no switchport
 ip address 10.0.0.1 255.255.255.254
!
router bgp 65001
 timers bgp 30 90
 bgp graceful-restart restart-time 300
 bgp graceful-restart stalepath-time 600
 neighbor 10.0.0.0 remote-as 65002
 neighbor 10.0.0.0 timers 10 30
 neighbor 10.0.1.0 remote-as 65003
!
end
"""

NXOS: Final = """hostname nx1
feature bgp
!
spanning-tree mode rapid-pvst
spanning-tree forward-time 15
spanning-tree vlan 10,20 hello-time 2
spanning-tree vlan 10,20 max-age 20
!
interface Ethernet1/1
  no switchport
  ip address 10.0.0.1/31
!
router bgp 65001
  timers bgp 30 90
  graceful-restart restart-time 300
  graceful-restart stalepath-time 600
  neighbor 10.0.0.0
    remote-as 65002
    timers 10 30
  neighbor 10.0.1.0
    remote-as 65003
"""

DIALECTS: Final[dict[str, tuple[str, str]]] = {
    "eos": (EOS, "eos1"),
    "ios": (IOS, "ios1"),
    "nxos": (NXOS, "nx1"),
}


@pytest.mark.parametrize("dialect", sorted(DIALECTS))
def test_every_dialect_reads_the_same_bgp_timers(dialect: str, tmp_path: Path) -> None:
    """The three write `timers bgp` and `timers` identically and differ only in
    where they put the per-peer line — flat on EOS and IOS, indented under the
    peer on NX-OS. The fact pack must not be able to tell them apart."""
    text, device = DIALECTS[dialect]
    pack = build(tmp_path, config=text)
    process = bgp_timers(pack, device)
    assert (process.keepalive_ms, process.hold_time_ms) == (30_000, 90_000)
    assert process.scope.instance == "65001"
    assert process.scope.source is TimerSource.CONFIGURED

    override = bgp_timers(pack, device, "10.0.0.0")
    assert (override.keepalive_ms, override.hold_time_ms) == (10_000, 30_000)


@pytest.mark.parametrize("dialect", sorted(DIALECTS))
def test_a_peering_that_states_nothing_inherits_and_says_so(
    dialect: str, tmp_path: Path
) -> None:
    """A rule reporting a disagreement has to know which end wrote the number
    down. `10.0.1.0` states no timers of its own and runs the process default,
    which is a real configured value and a different line to change."""
    text, device = DIALECTS[dialect]
    pack = build(tmp_path, config=text)
    inherited = bgp_timers(pack, device, "10.0.1.0")
    assert (inherited.keepalive_ms, inherited.hold_time_ms) == (30_000, 90_000)
    assert inherited.scope.source is TimerSource.INHERITED
    assert bgp_timers(pack, device, "10.0.0.0").scope.source is TimerSource.CONFIGURED


@pytest.mark.parametrize("dialect", sorted(DIALECTS))
def test_graceful_restart_timers_stay_on_the_process_record(
    dialect: str, tmp_path: Path
) -> None:
    """None of the three dialects states them per peering, so repeating them onto
    every peer would invent a scope the configuration does not have."""
    text, device = DIALECTS[dialect]
    pack = build(tmp_path, config=text)
    process = bgp_timers(pack, device)
    assert (process.graceful_restart_time_s, process.stalepath_time_s) == (300, 600)
    for neighbor in ("10.0.0.0", "10.0.1.0"):
        peering = bgp_timers(pack, device, neighbor)
        assert peering.graceful_restart_time_s is None
        assert peering.stalepath_time_s is None


@pytest.mark.parametrize("dialect", sorted(DIALECTS))
def test_every_dialect_reads_the_same_stp_timers(dialect: str, tmp_path: Path) -> None:
    """EOS states the hello time in milliseconds and its two siblings state it in
    seconds, while all three state the forward delay and max age in seconds. The
    inventory is milliseconds throughout, so the three configs — which describe
    the same switch — have to produce the same numbers."""
    text, device = DIALECTS[dialect]
    pack = build(tmp_path, config=text)
    (record,) = [t for t in pack.timers.stp if t.vlans]
    assert record.scope.device == device
    assert record.vlans == (10, 20)
    assert record.mode is StpMode.RAPID_PVST
    assert record.hello_time_ms == 2_000
    assert record.max_age_ms == 20_000


@pytest.mark.parametrize("dialect", sorted(DIALECTS))
def test_a_vlan_scoped_record_carries_the_device_wide_values(
    dialect: str, tmp_path: Path
) -> None:
    """`spanning-tree vlan 10,20 max-age 20` changes the max age for those VLANs
    and leaves their forward delay where the device-wide line put it. A rule
    checking the three against each other needs the set that is in effect, not
    the subset one line restated."""
    text, _ = DIALECTS[dialect]
    pack = build(tmp_path, config=text)
    (scoped,) = [t for t in pack.timers.stp if t.vlans]
    assert scoped.forward_delay_ms == 15_000

    (device_wide,) = [t for t in pack.timers.stp if not t.vlans]
    assert device_wide.forward_delay_ms == 15_000
    assert device_wide.hello_time_ms is None


def test_a_vlan_range_is_one_record_rather_than_one_per_vlan() -> None:
    """`1-4094` is a line the operator wrote once. Expanding it into a record per
    VLAN would put four thousand near-identical entries in the inventory and say
    nothing the range does not."""
    parsed = parse(
        "hostname sw1\nspanning-tree vlan 1-4094 hello-time 2\n", device_id="sw1"
    )
    (record,) = parsed.stp
    assert len(record.vlans) == 4094
    assert record.vlans[0] == 1 and record.vlans[-1] == 4094


def test_an_mst_region_is_scoped_by_instance_rather_than_by_vlan() -> None:
    parsed = parse(
        "hostname sw1\n"
        "spanning-tree mode mst\n"
        "spanning-tree mst hello-time 2\n"
        "spanning-tree mst forward-time 15\n"
        "spanning-tree mst max-age 20\n",
        device_id="sw1",
    )
    (record,) = parsed.stp
    assert record.scope.instance == "mst"
    assert record.vlans == ()
    assert record.mode is StpMode.MST


def test_a_peer_group_states_the_timers_its_members_do_not_restate() -> None:
    """A peering that joins a group runs the group's timers, and the operator
    chose them for it. Dropping them would make a session whose timing is
    written down read as one that states nothing."""
    parsed = parse(
        "hostname nx1\n"
        "feature bgp\n"
        "router bgp 65001\n"
        "  template peer FABRIC\n"
        "    timers 5 15\n"
        "  neighbor 10.0.0.0\n"
        "    inherit peer FABRIC\n",
        device_id="nx1",
    )
    (peering,) = [t for t in parsed.bgp_timers if t.scope.neighbor]
    assert (peering.keepalive_ms, peering.hold_time_ms) == (5_000, 15_000)
    assert peering.scope.source is TimerSource.CONFIGURED


def test_an_eos_peer_group_states_the_timers_its_members_join(tmp_path: Path) -> None:
    """The same claim in the dialect that writes peer groups flat. EOS keeps a
    group's settings alongside the peerings', under its name rather than an
    address, and a member joining it runs its timing."""
    pack = build(
        tmp_path,
        eos1="hostname eos1\n"
        "router bgp 65001\n"
        "   timers bgp 30 90\n"
        "   neighbor PEERS timers 5 15\n"
        "   neighbor 10.0.0.0 peer group PEERS\n"
        "   neighbor 10.0.0.0 remote-as 65002\n",
    )
    peering = bgp_timers(pack, "eos1", "10.0.0.0")
    assert (peering.keepalive_ms, peering.hold_time_ms) == (5_000, 15_000)
    assert peering.scope.source is TimerSource.CONFIGURED


def test_a_peer_group_is_not_itself_a_peering() -> None:
    """It holds settings for its members rather than running a session, so a
    timer record for it would be a session that does not exist."""
    parsed = parse(
        "hostname nx1\n"
        "feature bgp\n"
        "router bgp 65001\n"
        "  template peer FABRIC\n"
        "    timers 5 15\n",
        device_id="nx1",
    )
    assert [t.scope.neighbor for t in parsed.bgp_timers] == []


def test_a_process_that_states_no_timing_produces_no_record() -> None:
    """A record whose every value is None says only that the parser ran."""
    parsed = parse(
        "hostname eos1\nrouter bgp 65001\n   neighbor 10.0.0.0 remote-as 65002\n",
        device_id="eos1",
    )
    assert parsed.bgp_timers == ()


def test_a_device_that_states_a_mode_and_no_timing_produces_no_record() -> None:
    parsed = parse("hostname sw1\nspanning-tree mode rapid-pvst\n", device_id="sw1")
    assert parsed.stp == ()


# --------------------------------------------------------------------------
# What is recognised and deliberately not recorded
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "spanning-tree mode rapid-pvst",
        "spanning-tree vlan 1-100 priority 4096",
        "spanning-tree transmit hold-count 6",
        "spanning-tree pathcost method long",
        "spanning-tree loopguard default",
    ],
)
def test_spanning_tree_lines_that_carry_no_timer_are_absorbed(line: str) -> None:
    """The domain was filtered wholesale before any of it was read, and reading
    the timer lines must not turn the rest of it into a wall of unparsed output —
    that filter exists because such a wall hides the one line that matters."""
    parsed = parse(f"hostname sw1\n{line}\n", device_id="sw1")
    assert parsed.unparsed_lines == ()


def test_an_mst_region_block_takes_its_body_with_it() -> None:
    parsed = parse(
        "hostname sw1\n"
        "spanning-tree mst configuration\n"
        "  name REGION-A\n"
        "  revision 3\n"
        "  instance 1 vlan 10,20\n",
        device_id="sw1",
    )
    assert parsed.unparsed_lines == ()


def test_a_spanning_tree_timer_this_cannot_scope_is_still_reported() -> None:
    """The filter must not hide a real gap. A line naming a timer that could not
    be read is a timer the fact pack has lost, which is exactly what the unparsed
    list exists to make visible — and it is the failure the wholesale filter would
    otherwise have buried."""
    parsed = parse(
        "hostname sw1\nspanning-tree vlan LEGACY hello-time 2\n", device_id="sw1"
    )
    assert parsed.unparsed_lines == ("spanning-tree vlan LEGACY hello-time 2",)


def test_graceful_restart_without_a_duration_is_still_reported() -> None:
    """`graceful-restart` on its own turns the capability on and states no timer.
    Nothing in the schema records whether graceful restart is enabled, so the
    line is a fact this tool does not keep and says so rather than reading as
    understood."""
    parsed = eos.parse_device(
        "hostname eos1\nrouter bgp 65001\n   graceful-restart\n", device_id="eos1"
    )
    assert parsed.unparsed_lines == ("graceful-restart",)


# --------------------------------------------------------------------------
# bgp-hold-under-three-keepalives
# --------------------------------------------------------------------------

TIGHT_HOLD: Final = """hostname eos1
router bgp 65001
   timers bgp 60 90
   neighbor 10.0.0.0 remote-as 65002
"""

RATIO_HOLD: Final = """hostname eos1
router bgp 65001
   timers bgp 30 90
   neighbor 10.0.0.0 remote-as 65002
"""

NO_KEEPALIVES: Final = """hostname eos1
router bgp 65001
   timers bgp 0 0
   neighbor 10.0.0.0 remote-as 65002
"""


def test_a_hold_time_under_three_keepalives_is_reported(tmp_path: Path) -> None:
    pack = build(tmp_path, eos1=TIGHT_HOLD)
    (finding,) = [
        f for f in analyse(pack) if f.rule == "bgp-hold-under-three-keepalives"
    ]
    assert finding.device == "eos1"
    assert "1.5 keepalives" in finding.title


def test_a_hold_time_of_exactly_three_keepalives_is_not_reported(
    tmp_path: Path,
) -> None:
    """Three is the floor RFC 4271 builds the protocol on, not a target to
    exceed, so the value the protocol itself derives is not a defect."""
    pack = build(tmp_path, eos1=RATIO_HOLD)
    assert "bgp-hold-under-three-keepalives" not in rules_fired(pack)


def test_keepalives_turned_off_altogether_are_not_a_ratio(tmp_path: Path) -> None:
    """`timers bgp 0 0` is the documented way to run a session with no keepalives
    at all. It is a different decision with different consequences, and reporting
    it as a bad ratio would describe it wrongly."""
    pack = build(tmp_path, eos1=NO_KEEPALIVES)
    assert "bgp-hold-under-three-keepalives" not in rules_fired(pack)


# --------------------------------------------------------------------------
# bgp-timers-disagree
# --------------------------------------------------------------------------

SLOW_END: Final = """hostname agg-a
interface Ethernet1
   no switchport
   ip address 10.0.0.1/31
router bgp 65001
   timers bgp 30 90
   neighbor 10.0.0.0 remote-as 65002
"""

FAST_END: Final = """hostname agg-b
interface Ethernet1
   no switchport
   ip address 10.0.0.0/31
router bgp 65002
   neighbor 10.0.0.1 remote-as 65001
   neighbor 10.0.0.1 timers 10 30
"""

MATCHED_END: Final = """hostname agg-b
interface Ethernet1
   no switchport
   ip address 10.0.0.0/31
router bgp 65002
   neighbor 10.0.0.1 remote-as 65001
   neighbor 10.0.0.1 timers 30 90
"""


def test_two_ends_asking_for_different_timing_are_reported(tmp_path: Path) -> None:
    pack = build(tmp_path, agg_a=SLOW_END, agg_b=FAST_END)
    (finding,) = [f for f in analyse(pack) if f.rule == "bgp-timers-disagree"]
    assert finding.device == "agg-a"
    assert "30s" in finding.detail


def test_the_disagreement_says_which_end_wrote_the_number_down(
    tmp_path: Path,
) -> None:
    """The two ends need different edits: one restates the value on the peering,
    the other inherits it from a `timers bgp` line that every other peering of
    that process is also running."""
    pack = build(tmp_path, agg_a=SLOW_END, agg_b=FAST_END)
    (finding,) = [f for f in analyse(pack) if f.rule == "bgp-timers-disagree"]
    assert "agg-a inherits" in finding.detail
    assert "agg-b states" in finding.detail
    assert any("(inherited from the process)" in line for line in finding.evidence)


def test_two_ends_that_agree_are_not_reported(tmp_path: Path) -> None:
    """Timers stated on one end and inherited on the other are not a
    disagreement. Both numbers were chosen, they are the same number, and where
    each was written is a question about tidiness rather than about timing."""
    pack = build(tmp_path, agg_a=SLOW_END, agg_b=MATCHED_END)
    assert "bgp-timers-disagree" not in rules_fired(pack)


def test_a_peering_whose_far_end_is_not_in_the_corpus_is_not_reported(
    tmp_path: Path,
) -> None:
    """One end of a peering says nothing about the other. A transit provider, or
    a device whose config was not gathered, is an incomplete collection rather
    than a defect, and a rule that guessed at the missing end would report the
    gap in the capture as a fault in the network."""
    pack = build(tmp_path, agg_a=SLOW_END)
    assert "bgp-timers-disagree" not in rules_fired(pack)


# --------------------------------------------------------------------------
# bgp-stalepath-under-restart-time
# --------------------------------------------------------------------------

SHORT_STALEPATH: Final = """hostname eos1
router bgp 65001
   graceful-restart restart-time 300
   graceful-restart stalepath-time 120
   neighbor 10.0.0.0 remote-as 65002
"""

LONG_STALEPATH: Final = """hostname eos1
router bgp 65001
   graceful-restart restart-time 120
   graceful-restart stalepath-time 300
   neighbor 10.0.0.0 remote-as 65002
"""

RESTART_ONLY: Final = """hostname eos1
router bgp 65001
   graceful-restart restart-time 300
   neighbor 10.0.0.0 remote-as 65002
"""


def test_holding_stale_paths_for_less_than_the_restart_window_is_reported(
    tmp_path: Path,
) -> None:
    pack = build(tmp_path, eos1=SHORT_STALEPATH)
    (finding,) = [
        f for f in analyse(pack) if f.rule == "bgp-stalepath-under-restart-time"
    ]
    assert finding.device == "eos1"
    assert "180s" in finding.detail


def test_a_stalepath_timer_longer_than_the_restart_window_is_not_reported(
    tmp_path: Path,
) -> None:
    """This is the ordering every platform ships with: the router stops holding
    the routes after it has stopped waiting for the peer, not before."""
    pack = build(tmp_path, eos1=LONG_STALEPATH)
    assert "bgp-stalepath-under-restart-time" not in rules_fired(pack)


def test_one_graceful_restart_timer_alone_is_not_a_comparison(tmp_path: Path) -> None:
    """The other value is then a platform default, and filling it in to compare
    against would be checking this tool's memory rather than the configuration."""
    pack = build(tmp_path, eos1=RESTART_ONLY)
    assert "bgp-stalepath-under-restart-time" not in rules_fired(pack)


# --------------------------------------------------------------------------
# stp-timers-outside-the-standard
# --------------------------------------------------------------------------

FAST_FORWARD: Final = """hostname sw1
spanning-tree mode rapid-pvst
spanning-tree vlan 10 hello-time 2
spanning-tree vlan 10 forward-time 4
spanning-tree vlan 10 max-age 20
"""

SLOW_HELLO: Final = """hostname sw1
spanning-tree mode rapid-pvst
spanning-tree vlan 10 hello-time 10
spanning-tree vlan 10 forward-time 30
spanning-tree vlan 10 max-age 20
"""

STANDARD: Final = """hostname sw1
spanning-tree mode rapid-pvst
spanning-tree vlan 10 hello-time 2
spanning-tree vlan 10 forward-time 15
spanning-tree vlan 10 max-age 20
"""

HALF_STATED: Final = """hostname sw1
spanning-tree mode rapid-pvst
spanning-tree vlan 10 max-age 40
"""


def test_a_forward_delay_too_short_for_the_max_age_is_reported(
    tmp_path: Path,
) -> None:
    pack = build(tmp_path, sw1=FAST_FORWARD)
    (finding,) = [
        f for f in analyse(pack) if f.rule == "stp-timers-outside-the-standard"
    ]
    assert finding.device == "sw1"
    assert "vlan 10" in finding.title
    assert "forward delay of at least 11s" in finding.detail


def test_a_max_age_too_short_for_the_hello_time_is_reported(tmp_path: Path) -> None:
    pack = build(tmp_path, sw1=SLOW_HELLO)
    (finding,) = [
        f for f in analyse(pack) if f.rule == "stp-timers-outside-the-standard"
    ]
    assert "max age of at least 22s" in finding.detail


def test_the_standard_default_timers_are_not_reported(tmp_path: Path) -> None:
    """2s / 15s / 20s is what every bridge ships with and what both inequalities
    are written around, so the rule firing on it would mean the arithmetic is
    inverted."""
    pack = build(tmp_path, sw1=STANDARD)
    assert "stp-timers-outside-the-standard" not in rules_fired(pack)


def test_timers_only_half_stated_are_not_measured_against_defaults(
    tmp_path: Path,
) -> None:
    """A relationship between three values cannot be checked from one of them.
    Filling the other two in from the standard would report a number this tool
    supplied rather than one the operator did."""
    pack = build(tmp_path, sw1=HALF_STATED)
    assert "stp-timers-outside-the-standard" not in rules_fired(pack)


# --------------------------------------------------------------------------
# The shipped corpora
# --------------------------------------------------------------------------


@pytest.mark.parametrize("corpus", SHIPPED, ids=lambda p: p.parent.name)
def test_no_new_rule_fires_on_a_shipped_corpus(corpus: Path) -> None:
    """These three are pinned by digest and by finding set, and the tutorial and
    both scenario READMEs quote what they produce. A rule that fires on one of
    them has changed what the documentation says the tool does — silently, since
    the digest they are pinned by would not move.

    None of the three configures a BGP or spanning-tree timer, so the correct
    result is silence rather than a clean bill of health.
    """
    pack, _ = build_fact_pack(corpus)
    assert "bgp-hold-under-three-keepalives" not in rules_fired(pack)
    assert "bgp-timers-disagree" not in rules_fired(pack)
    assert "bgp-stalepath-under-restart-time" not in rules_fired(pack)
    assert "stp-timers-outside-the-standard" not in rules_fired(pack)


# --------------------------------------------------------------------------
# The hello time carries its own unit
#
# `spanning-tree hello-time N` is milliseconds on EOS and seconds on IOS and
# NX-OS. The unit used to be chosen by whichever dialect the file was parsed as,
# and on an L2-only switch — which is where spanning-tree timers live — every
# parser accounts for the whole file, so the dialect was decided by a tie-break.
# A standard EOS switch stating a two-second hello landed in the pack as
# 2 000 000 ms and tripped `stp-timers-outside-the-standard` MEDIUM on timers
# that are correct.
# --------------------------------------------------------------------------

L2_ONLY_SWITCH: Final = """hostname l2sw
!
vlan 10
   name clients
!
spanning-tree mode rapid-pvst
spanning-tree hello-time 2000
spanning-tree forward-time 15
spanning-tree max-age 20
!
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 10
!
interface Ethernet2
   switchport mode access
   switchport access vlan 10
"""


def test_every_parser_accounts_for_an_l2_only_switch() -> None:
    """The precondition for the defect, asserted so the test cannot rot into
    passing because the tie stopped happening.

    An L2-only switch states nothing that distinguishes IOS, EOS and NX-OS, so
    all three explain the file completely and the dialect is a tie-break.
    """
    counts = {
        name: len(module.parse_device(L2_ONLY_SWITCH, device_id="l2sw").unparsed_lines)
        for name, module in (("ios", ios), ("eos", eos), ("nxos", nxos))
    }
    assert counts == {"ios": 0, "eos": 0, "nxos": 0}
    assert not ios.looks_like_ios(L2_ONLY_SWITCH)
    assert not nxos.looks_like_nxos(L2_ONLY_SWITCH)


def test_a_millisecond_hello_time_is_read_as_milliseconds(tmp_path: Path) -> None:
    """802.1D bounds the hello time to 1-10 seconds and EOS states the same
    command as 1000-10000 milliseconds, so the ranges are disjoint and 2000 can
    only be two seconds. The unit is read off the number rather than off whichever
    parser won the tie."""
    pack = build(tmp_path, l2sw=L2_ONLY_SWITCH)
    (record,) = pack.timers.stp
    assert record.hello_time_ms == 2_000
    assert record.forward_delay_ms == 15_000
    assert record.max_age_ms == 20_000


def test_correct_timers_on_an_l2_only_switch_produce_no_finding(
    tmp_path: Path,
) -> None:
    """2s / 15s / 20s satisfies both of the standard's inequalities. The rule
    fired on it anyway, because the hello time reached it a thousand times too
    large — a MEDIUM finding against the values every bridge ships with."""
    pack = build(tmp_path, l2sw=L2_ONLY_SWITCH)
    assert "stp-timers-outside-the-standard" not in rules_fired(pack)


def test_a_hello_time_in_neither_unit_is_reported_rather_than_guessed() -> None:
    """Between the two ranges the number says nothing about its unit, and the
    house rule for a fact-bearing line this parser cannot be sure of is
    `unparsed_lines` rather than a guess in the pack. 500 is neither a legal
    number of seconds nor a legal number of milliseconds."""
    parsed = parse("hostname sw1\nspanning-tree hello-time 500\n", device_id="sw1")
    assert parsed.stp == ()
    assert parsed.unparsed_lines == ("spanning-tree hello-time 500",)


@pytest.mark.parametrize(
    ("written", "expected_ms"),
    [("2", 2_000), ("2000", 2_000), ("10", 10_000), ("10000", 10_000)],
)
def test_the_same_hello_time_in_either_unit_reads_the_same(
    written: str, expected_ms: int
) -> None:
    """The whole point of reading the unit off the number: the two spellings of
    one switch's timing have to reach the inventory as one value."""
    parsed = parse(
        f"hostname sw1\nspanning-tree hello-time {written}\n", device_id="sw1"
    )
    (record,) = parsed.stp
    assert record.hello_time_ms == expected_ms


def test_a_tie_is_broken_by_what_each_parser_read_not_by_list_order() -> None:
    """The other half of the tie-break, and the reason it is no longer a toss.

    Leftovers measure a parse from one side only. Every dialect also carries a
    list of lines it absorbs as stating no fact, and those lists differ: `ip ospf
    hello-interval 5` is an IGP hello record to the EOS parser and an
    uninteresting line to the NX-OS one. Both account for the whole file, so on
    leftovers alone they tie and `DIALECTS` order picks one — and picking the
    wrong one silently drops a timer from the inventory rather than reporting it.
    """
    text = (
        "hostname sw1\n"
        "vlan 10\n"
        "interface Ethernet1\n"
        "   no switchport\n"
        "   ip address 198.51.100.1/31\n"
        "   ip ospf hello-interval 5\n"
    )
    assert len(eos.parse_device(text, device_id="sw1").unparsed_lines) == 0
    assert len(nxos.parse_device(text, device_id="sw1").unparsed_lines) == 0
    # The NX-OS record type has no IGP hello family at all: the line was
    # absorbed, so there is nothing for it to have been read into.
    assert not getattr(nxos.parse_device(text, device_id="sw1"), "igp_hello", ())

    parsed = parse(text, device_id="sw1")
    (hello,) = parsed.igp_hello
    assert hello.hello_interval_ms == 5_000
