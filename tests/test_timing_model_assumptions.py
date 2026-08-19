"""One test per assumption in `docs/timing-model.md`.

The register says what the timing model claims about real routers. These tests
say whether the model actually behaves the way the register claims — which is a
different question, and the only one that can be answered without a lab. Nothing
here validates the model against firmware; PROJECT.md §2.3 is what would.

Two consequences for how these are written:

* Each test is named for its assumption (`test_a7_...`) and asserts the specific
  observable behaviour the entry describes, so an entry that drifts away from the
  code fails here rather than quietly becoming fiction.
* Fact packs are constructed directly rather than parsed from config text. A
  parser change must not be able to silently rewrite what an assumption test is
  testing, and several of these assumptions are about inputs no dialect can
  currently produce.

`test_the_register_and_the_code_agree` closes the loop: every entry needs a test
or an explicit reason it cannot have one, and every `A<n>` cited in the model must
be an entry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from cassandra.factpack.schema import (
    AddressFamily,
    CarrierDelayTimers,
    Device,
    FactPackMeta,
    FhrpGroup,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    Interface,
    InterfaceKind,
    IpAssignment,
    StaticFactPack,
    TimerInventory,
    TimerScope,
    TrackedObject,
    TrackedObjectKind,
)
from cassandra.timing.model import (
    DEFAULT_ADVERT_MS,
    MASTER_DOWN_INTERVAL_MS,
    SAMPLE_INTERVAL_MS,
    Event,
    EventKind,
    Placement,
    simulate,
)

REGISTER: Final = Path(__file__).resolve().parents[1] / "docs" / "timing-model.md"
SEQUENCES: Final = (
    Path(__file__).resolve().parents[1] / "cassandra" / "timing" / "sequences.py"
)
MODEL: Final = Path(__file__).resolve().parents[1] / "cassandra" / "timing" / "model.py"
UPLINK: Final = "Ethernet1"


# --------------------------------------------------------------------------
# Fact pack construction
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class MemberSpec:
    device: str
    priority: int
    preempt: bool = True
    preempt_delay_ms: int | None = None
    reload_delay_ms: int | None = None
    hello_ms: int | None = None
    tracks: tuple[tuple[str, int | None], ...] = ()
    address: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class GroupSpec:
    number: int
    members: tuple[MemberSpec, ...]
    protocol: FhrpProtocol = FhrpProtocol.VRRP
    interface: str | None = None
    kind: TrackedObjectKind = TrackedObjectKind.INTERFACE

    @property
    def svi(self) -> str:
        return self.interface or f"Vlan{self.number}"

    @property
    def id(self) -> str:
        return f"{self.protocol.value}-{self.number}"


@dataclass(slots=True)
class _Built:
    interfaces: dict[str, dict[str, Interface]] = field(default_factory=dict)
    timers: list[FhrpTimers] = field(default_factory=list)


def _interface(device: str, name: str, address: str | None) -> Interface:
    addresses = (
        (
            IpAssignment(
                address=address,
                prefix=f"{address}/24",
                family=AddressFamily.IPV4_UNICAST,
            ),
        )
        if address
        else ()
    )
    return Interface(
        device=device,
        name=name,
        kind=InterfaceKind.SVI if name.startswith("Vlan") else InterfaceKind.PHYSICAL,
        addresses=addresses,
    )


def fact_pack(
    *groups: GroupSpec,
    carrier_delay: tuple[str, str, int] | None = None,
) -> StaticFactPack:
    """A minimal synthetic pack holding exactly the groups described."""
    built = _Built()

    def interface_of(device: str, name: str, address: str | None = None) -> None:
        by_name = built.interfaces.setdefault(device, {})
        if name not in by_name or (address and not by_name[name].addresses):
            by_name[name] = _interface(device, name, address)

    fhrp_groups: list[FhrpGroup] = []
    for group in groups:
        members: list[FhrpMember] = []
        for spec in group.members:
            interface_of(spec.device, group.svi, spec.address)
            for target, _ in spec.tracks:
                interface_of(spec.device, target)
            members.append(
                FhrpMember(
                    device=spec.device,
                    interface=group.svi,
                    priority=spec.priority,
                    preempt=spec.preempt,
                    tracked_objects=tuple(
                        TrackedObject(
                            id=f"TRACK-{target}",
                            device=spec.device,
                            kind=group.kind,
                            target=target,
                            decrement=decrement,
                        )
                        for target, decrement in spec.tracks
                    ),
                )
            )
            built.timers.append(
                FhrpTimers(
                    scope=TimerScope(
                        device=spec.device,
                        interface=group.svi,
                        instance=str(group.number),
                    ),
                    protocol=group.protocol,
                    hello_interval_ms=spec.hello_ms,
                    preempt_delay_ms=spec.preempt_delay_ms,
                    preempt_delay_reload_ms=spec.reload_delay_ms,
                )
            )
        fhrp_groups.append(
            FhrpGroup(
                id=group.id,
                protocol=group.protocol,
                group_number=group.number,
                members=tuple(members),
            )
        )

    carrier: tuple[CarrierDelayTimers, ...] = ()
    if carrier_delay is not None:
        device, interface, value = carrier_delay
        carrier = (
            CarrierDelayTimers(
                scope=TimerScope(device=device, interface=interface),
                carrier_delay_up_ms=value,
                carrier_delay_down_ms=value,
            ),
        )

    return StaticFactPack(
        meta=FactPackMeta(
            fact_pack_id="assumptions",
            schema_version=1,
            config_digest="synthetic",
            source_snapshot="synthetic",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        devices=tuple(
            Device(
                id=device,
                hostname=device,
                interfaces=tuple(by_name[name] for name in sorted(by_name)),
            )
            for device, by_name in sorted(built.interfaces.items())
        ),
        fhrp_groups=tuple(fhrp_groups),
        timers=TimerInventory(fhrp=tuple(built.timers), carrier_delay=carrier),
    )


def down(device: str, interface: str, *, at_ms: int) -> Event:
    return Event(
        at_ms=at_ms, kind=EventKind.LINK_DOWN, device=device, interface=interface
    )


def up(device: str, interface: str, *, at_ms: int) -> Event:
    return Event(
        at_ms=at_ms, kind=EventKind.LINK_UP, device=device, interface=interface
    )


def holders(timeline: list[Placement], group_id: str) -> dict[int, str | None]:
    return {sample.at_ms: sample.masters[group_id] for sample in timeline}


# The recurring shape: one tracked uplink, a preferred device, a plain backup.
def tracked_pair(
    *,
    decrement: int | None = 40,
    preempt_delay_ms: int | None = None,
    reload_delay_ms: int | None = None,
    hello_ms: int | None = None,
    target: str = UPLINK,
    number: int = 10,
    protocol: FhrpProtocol = FhrpProtocol.VRRP,
) -> GroupSpec:
    return GroupSpec(
        number=number,
        protocol=protocol,
        members=(
            MemberSpec(
                device="agg-a",
                priority=110,
                tracks=((target, decrement),),
                preempt_delay_ms=preempt_delay_ms,
                reload_delay_ms=reload_delay_ms,
                hello_ms=hello_ms,
                address="10.0.10.2",
            ),
            MemberSpec(
                device="agg-b", priority=100, hello_ms=hello_ms, address="10.0.10.3"
            ),
        ),
    )


# --------------------------------------------------------------------------
# Timing and time resolution
# --------------------------------------------------------------------------


def test_a1_the_configured_advertisement_interval_is_ignored() -> None:
    """A1: the model advertises once a second whatever the inventory says."""
    slow = fact_pack(tracked_pair(hello_ms=4000))
    fast = fact_pack(tracked_pair(hello_ms=1000))
    events = [down("agg-a", "Vlan10", at_ms=0)]

    slow_line = holders(simulate(slow, events, until_ms=10_000), "vrrp-10")
    fast_line = holders(simulate(fast, events, until_ms=10_000), "vrrp-10")

    assert slow_line == fast_line
    # And the detection interval is derived from the hardcoded advert, not 4s.
    assert slow_line[MASTER_DOWN_INTERVAL_MS] == "agg-b"


def test_a2_events_take_effect_at_the_next_sample() -> None:
    """A2: an event between samples is rounded up to the next one."""
    pack = fact_pack(tracked_pair())
    timeline = simulate(pack, [down("agg-a", UPLINK, at_ms=2500)], until_ms=6000)
    line = holders(timeline, "vrrp-10")

    assert [sample.at_ms for sample in timeline] == [
        0,
        1000,
        2000,
        3000,
        4000,
        5000,
        6000,
    ]
    assert line[2000] == "agg-a", "the event has not happened yet"
    assert line[3000] == "agg-b", "and lands at the next sample, not at 2500"


def test_a3_a_silent_master_leaves_the_group_vacant_for_three_adverts() -> None:
    """A3: nobody holds the group for the master-down interval."""
    pack = fact_pack(tracked_pair())
    timeline = simulate(pack, [down("agg-a", "Vlan10", at_ms=0)], until_ms=10_000)
    line = holders(timeline, "vrrp-10")

    assert line[0] is None
    for at_ms in range(0, MASTER_DOWN_INTERVAL_MS, SAMPLE_INTERVAL_MS):
        assert line[at_ms] is None, f"someone claimed the group at {at_ms}ms"
    assert line[MASTER_DOWN_INTERVAL_MS] == "agg-b"
    assert MASTER_DOWN_INTERVAL_MS == 3 * DEFAULT_ADVERT_MS


def test_a4_preemption_lands_in_the_same_sample_as_the_priority_change() -> None:
    """A4: no advertisement has to arrive first."""
    pack = fact_pack(tracked_pair())
    events = [down("agg-a", UPLINK, at_ms=1000), up("agg-a", UPLINK, at_ms=5000)]
    line = holders(simulate(pack, events, until_ms=10_000), "vrrp-10")

    assert line[0] == "agg-a"
    assert line[1000] == "agg-b", "loses it in the sample the priority drops"
    assert line[5000] == "agg-a", "and takes it back in the sample it recovers"


# --------------------------------------------------------------------------
# Election
# --------------------------------------------------------------------------


def test_a5_only_the_current_down_set_decides_the_election() -> None:
    """A5: no history, no penalty accumulation, no hold-down."""
    pack = fact_pack(tracked_pair())
    once = [down("agg-a", UPLINK, at_ms=20_000)]
    after_three_flaps = [
        down("agg-a", UPLINK, at_ms=0),
        up("agg-a", UPLINK, at_ms=2000),
        down("agg-a", UPLINK, at_ms=4000),
        up("agg-a", UPLINK, at_ms=6000),
        down("agg-a", UPLINK, at_ms=20_000),
    ]

    quiet = holders(simulate(pack, once, until_ms=40_000), "vrrp-10")
    flapped = holders(simulate(pack, after_three_flaps, until_ms=40_000), "vrrp-10")
    assert quiet[40_000] == flapped[40_000] == "agg-b"
    assert quiet[30_000] == flapped[30_000], "the flaps left no residue"


def test_a6_equal_priority_does_not_displace_the_master() -> None:
    """A6: strictly greater is required to preempt."""
    pack = fact_pack(tracked_pair(decrement=10))
    line = holders(
        simulate(pack, [down("agg-a", UPLINK, at_ms=1000)], until_ms=10_000), "vrrp-10"
    )

    assert line[0] == "agg-a"
    assert line[10_000] == "agg-a", "110 - 10 equals agg-b's 100, so agg-a keeps it"


def test_a7_equal_priority_is_broken_by_the_higher_address() -> None:
    """A7: highest primary IPv4, not the alphabetically first hostname."""
    group = GroupSpec(
        number=10,
        members=(
            MemberSpec(device="agg-a", priority=100, address="10.0.10.5"),
            MemberSpec(device="agg-z", priority=100, address="10.0.10.9"),
        ),
    )
    line = holders(simulate(fact_pack(group), [], until_ms=2000), "vrrp-10")
    assert line[0] == "agg-z", "the higher address wins even though it sorts last"


def test_a7_without_addresses_the_tie_break_falls_back_to_the_device_name() -> None:
    """A7: the fallback has no counterpart in firmware and is only reachable
    when the fact pack has no address for the member."""
    group = GroupSpec(
        number=10,
        members=(
            MemberSpec(device="agg-a", priority=100),
            MemberSpec(device="agg-z", priority=100),
        ),
    )
    line = holders(simulate(fact_pack(group), [], until_ms=2000), "vrrp-10")
    assert line[0] == "agg-a"


def test_a8_decrements_are_additive_and_clamped() -> None:
    """A8: two tracks sum, and the result never goes below 1."""
    additive = GroupSpec(
        number=10,
        members=(
            MemberSpec(
                device="agg-a",
                priority=130,
                tracks=(("Ethernet1", 20), ("Ethernet2", 20)),
                address="10.0.10.2",
            ),
            MemberSpec(device="agg-b", priority=100, address="10.0.10.3"),
        ),
    )
    pack = fact_pack(additive)
    one = holders(
        simulate(pack, [down("agg-a", "Ethernet1", at_ms=1000)], until_ms=5000),
        "vrrp-10",
    )
    assert one[5000] == "agg-a", "130 - 20 still beats 100"

    both = holders(
        simulate(
            pack,
            [
                down("agg-a", "Ethernet1", at_ms=1000),
                down("agg-a", "Ethernet2", at_ms=1000),
            ],
            until_ms=5000,
        ),
        "vrrp-10",
    )
    assert both[5000] == "agg-b", "130 - 20 - 20 loses to 100"

    # Clamping: agg-a bottoms out at 1, which ties agg-b and so keeps the group
    # (A6). Without the clamp it would be negative and would lose it.
    clamped = fact_pack(
        GroupSpec(
            number=10,
            members=(
                MemberSpec(
                    device="agg-a",
                    priority=50,
                    tracks=((UPLINK, 100),),
                    address="10.0.10.2",
                ),
                MemberSpec(device="agg-b", priority=1, address="10.0.10.3"),
            ),
        )
    )
    line = holders(
        simulate(clamped, [down("agg-a", UPLINK, at_ms=1000)], until_ms=5000), "vrrp-10"
    )
    assert line[5000] == "agg-a"


def test_a9_a_missing_decrement_is_inert() -> None:
    """A9: a tracked object with no recorded decrement changes nothing, which is
    how a bare IOS `track` (worth 10 on real firmware) becomes invisible."""
    inert = fact_pack(tracked_pair(decrement=None))
    live = fact_pack(tracked_pair(decrement=40))
    events = [down("agg-a", UPLINK, at_ms=1000)]

    assert holders(simulate(inert, events, until_ms=5000), "vrrp-10")[5000] == "agg-a"
    assert holders(simulate(live, events, until_ms=5000), "vrrp-10")[5000] == "agg-b"


def test_a9_a_non_interface_track_is_treated_as_an_interface_track() -> None:
    """A9: the tracked object's kind is never consulted, so a route track only
    ever fires if a link event happens to name the same string."""
    pack = fact_pack(
        GroupSpec(
            number=10,
            kind=TrackedObjectKind.ROUTE,
            members=(
                MemberSpec(
                    device="agg-a",
                    priority=110,
                    tracks=(("10.0.0.0/8", 40),),
                    address="10.0.10.2",
                ),
                MemberSpec(device="agg-b", priority=100, address="10.0.10.3"),
            ),
        )
    )
    events = [down("agg-a", "10.0.0.0/8", at_ms=1000)]
    assert holders(simulate(pack, events, until_ms=5000), "vrrp-10")[5000] == "agg-b"


def test_a10_interface_names_match_exactly() -> None:
    """A10: no case folding, no abbreviation expansion."""
    pack = fact_pack(tracked_pair())
    for name in ("ethernet1", "Et1", "Ethernet1.0"):
        line = holders(
            simulate(pack, [down("agg-a", name, at_ms=1000)], until_ms=5000), "vrrp-10"
        )
        assert line[5000] == "agg-a", f"{name} must not match {UPLINK}"


# --------------------------------------------------------------------------
# Preemption and preempt delay
# --------------------------------------------------------------------------


def test_a11_preempt_delay_runs_from_recovery_not_from_priority_restoration() -> None:
    """A11: the clock starts when the interface comes back, so a 90s delay after
    a 10s outage keeps the group away until t=100s, not t=90s."""
    pack = fact_pack(tracked_pair(preempt_delay_ms=90_000))
    events = [down("agg-a", UPLINK, at_ms=0), up("agg-a", UPLINK, at_ms=10_000)]
    line = holders(simulate(pack, events, until_ms=120_000), "vrrp-10")

    assert line[10_000] == "agg-b", "priority is restored but the delay is not spent"
    assert line[90_000] == "agg-b", "the delay is measured from recovery, not from t=0"
    assert line[99_000] == "agg-b"
    assert line[100_000] == "agg-a"


def test_a12_an_untouched_group_keeps_its_preempt_clock() -> None:
    """A12: an event on an interface the member neither runs on nor tracks does
    not restart its preempt delay."""
    pack = fact_pack(tracked_pair(preempt_delay_ms=90_000))
    events = [
        down("agg-a", UPLINK, at_ms=0),
        up("agg-a", UPLINK, at_ms=10_000),
        up("agg-a", "Ethernet9", at_ms=50_000),  # nothing tracks this
    ]
    line = holders(simulate(pack, events, until_ms=160_000), "vrrp-10")

    assert line[100_000] == "agg-a", "the unrelated recovery must not push the clock"


def test_a13_a_vacant_group_ignores_preempt_and_delay() -> None:
    """A13: claiming an empty group is not preemption."""
    group = GroupSpec(
        number=10,
        members=(
            MemberSpec(device="agg-a", priority=110, address="10.0.10.2"),
            MemberSpec(
                device="agg-b",
                priority=100,
                preempt=False,
                preempt_delay_ms=90_000,
                tracks=((UPLINK, 10),),
                address="10.0.10.3",
            ),
        ),
    )
    events = [
        # agg-b's delay is restarted at 1s, so it is nowhere near eligible.
        down("agg-b", UPLINK, at_ms=0),
        up("agg-b", UPLINK, at_ms=1000),
        down("agg-a", "Vlan10", at_ms=2000),
    ]
    line = holders(simulate(fact_pack(group), events, until_ms=20_000), "vrrp-10")

    assert line[2000] is None
    assert line[2000 + MASTER_DOWN_INTERVAL_MS] == "agg-b", (
        "a backup with preempt disabled and a pending delay still claims a "
        "group nobody is holding"
    )


def test_a14_the_reload_delay_is_not_read() -> None:
    """A14: only `preempt_delay_ms` reaches the model, and t=0 is never delayed."""
    pack = fact_pack(tracked_pair(reload_delay_ms=90_000))
    events = [down("agg-a", UPLINK, at_ms=0), up("agg-a", UPLINK, at_ms=10_000)]
    line = holders(simulate(pack, events, until_ms=30_000), "vrrp-10")

    assert line[0] == "agg-b", "the initial election settles with no delay at all"
    assert line[10_000] == "agg-a", "the reload delay does not hold it back"


# --------------------------------------------------------------------------
# What a member is
# --------------------------------------------------------------------------


def test_a15_a_member_with_its_own_interface_down_cannot_hold_the_group() -> None:
    """A15: availability is exactly 'the interface the group runs on is up'."""
    pack = fact_pack(tracked_pair())
    events = [down("agg-a", "Vlan10", at_ms=0), up("agg-a", "Vlan10", at_ms=60_000)]
    line = holders(simulate(pack, events, until_ms=90_000), "vrrp-10")

    assert line[30_000] == "agg-b", "agg-a cannot serve the group while its SVI is down"
    assert line[60_000] == "agg-a", "and takes it back when the SVI returns"


def test_a15_nothing_but_an_explicit_event_makes_a_member_unavailable() -> None:
    """A15: the SVI of a member whose every tracked interface is down is still
    'up', because only an event naming the SVI can down it."""
    pack = fact_pack(tracked_pair(decrement=0))
    line = holders(
        simulate(pack, [down("agg-a", UPLINK, at_ms=1000)], until_ms=5000), "vrrp-10"
    )
    assert line[5000] == "agg-a", "a dead uplink does not make the member unavailable"


def test_a17_the_simulation_is_deterministic() -> None:
    """A17: no loss, no jitter — the same inputs give the same timeline."""
    pack = fact_pack(tracked_pair(preempt_delay_ms=30_000))
    events = [
        down("agg-a", UPLINK, at_ms=0),
        up("agg-a", UPLINK, at_ms=10_000),
        down("agg-a", UPLINK, at_ms=20_000),
        up("agg-a", UPLINK, at_ms=30_000),
    ]
    first = simulate(pack, events, until_ms=120_000)
    second = simulate(pack, events, until_ms=120_000)

    assert [(s.at_ms, s.masters) for s in first] == [
        (s.at_ms, s.masters) for s in second
    ]


def test_a18_carrier_delay_is_ignored() -> None:
    """A18: a debounce long enough to hide the flap from real firmware does not
    change the model's answer at all."""
    plain = fact_pack(tracked_pair())
    debounced = fact_pack(tracked_pair(), carrier_delay=("agg-a", UPLINK, 5000))
    events = [down("agg-a", UPLINK, at_ms=1000), up("agg-a", UPLINK, at_ms=2000)]

    assert holders(simulate(plain, events, until_ms=10_000), "vrrp-10") == holders(
        simulate(debounced, events, until_ms=10_000), "vrrp-10"
    )
    assert holders(simulate(debounced, events, until_ms=10_000), "vrrp-10")[1000] == (
        "agg-b"
    ), "a 1s flap behind a 5s debounce still moves the group"


def test_a19_delay_lookup_is_per_protocol_not_just_group_number() -> None:
    """A19: HSRP 14 and VRRP 14 on one device must not share a preempt delay."""
    pack = fact_pack(
        tracked_pair(number=14, preempt_delay_ms=90_000),
        tracked_pair(number=14, protocol=FhrpProtocol.HSRP, preempt_delay_ms=None),
    )
    events = [down("agg-a", UPLINK, at_ms=0), up("agg-a", UPLINK, at_ms=10_000)]
    timeline = simulate(pack, events, until_ms=120_000)

    assert holders(timeline, "hsrp-14")[10_000] == "agg-a", "no delay configured"
    assert holders(timeline, "vrrp-14")[10_000] == "agg-b", "90s delay configured"
    assert holders(timeline, "vrrp-14")[100_000] == "agg-a"


def test_a20_groups_only_interact_through_tracked_interfaces() -> None:
    """A20: a group that tracks nothing cannot be moved by another group's event."""
    pack = fact_pack(
        tracked_pair(number=10),
        GroupSpec(
            number=20,
            members=(
                MemberSpec(device="agg-a", priority=110, address="10.0.20.2"),
                MemberSpec(device="agg-b", priority=100, address="10.0.20.3"),
            ),
        ),
    )
    timeline = simulate(pack, [down("agg-a", UPLINK, at_ms=1000)], until_ms=10_000)

    assert holders(timeline, "vrrp-10")[10_000] == "agg-b"
    assert set(holders(timeline, "vrrp-20").values()) == {"agg-a"}


# --------------------------------------------------------------------------
# The interface of simulate()
# --------------------------------------------------------------------------


def test_a21_an_event_for_an_unknown_device_is_a_silent_no_op() -> None:
    """A21: a mistyped device or interface name produces a healthy simulation
    rather than an error, which is the risk worth knowing about."""
    pack = fact_pack(tracked_pair())
    quiet = holders(simulate(pack, [], until_ms=10_000), "vrrp-10")

    for event in (down("typo-a", UPLINK, at_ms=1000), down("agg-a", "Eth99", at_ms=1)):
        assert holders(simulate(pack, [event], until_ms=10_000), "vrrp-10") == quiet


def test_a22_simultaneous_events_resolve_in_list_order() -> None:
    """A22: the sort is stable, so the caller's order breaks the tie."""
    pack = fact_pack(tracked_pair())
    down_last = [up("agg-a", UPLINK, at_ms=1000), down("agg-a", UPLINK, at_ms=1000)]
    up_last = [down("agg-a", UPLINK, at_ms=1000), up("agg-a", UPLINK, at_ms=1000)]

    assert holders(simulate(pack, down_last, until_ms=5000), "vrrp-10")[5000] == "agg-b"
    assert holders(simulate(pack, up_last, until_ms=5000), "vrrp-10")[5000] == "agg-a"


def test_a23_the_horizon_is_inclusive_and_rounds_up() -> None:
    """A23: samples cover 0..until_ms, rounding up to the grid."""
    pack = fact_pack(tracked_pair())

    exact = simulate(pack, [], until_ms=10_000)
    assert exact[0].at_ms == 0
    assert exact[-1].at_ms == 10_000

    ragged = simulate(pack, [], until_ms=10_500)
    assert ragged[-1].at_ms == 11_000 >= 10_500

    assert simulate(pack, [], until_ms=0) == [
        Placement(at_ms=0, masters={"vrrp-10": "agg-a"})
    ]


def test_a24_no_available_member_means_no_master() -> None:
    """A24: a group nobody can serve reads as `None`, and one member always wins."""
    pack = fact_pack(tracked_pair())
    both_down = [
        down("agg-a", "Vlan10", at_ms=0),
        down("agg-b", "Vlan10", at_ms=0),
    ]
    line = holders(simulate(pack, both_down, until_ms=30_000), "vrrp-10")
    assert set(line.values()) == {None}, "a total outage is not a divergence"

    lonely = fact_pack(
        GroupSpec(
            number=10,
            members=(MemberSpec(device="agg-a", priority=1, address="10.0.10.2"),),
        )
    )
    assert holders(simulate(lonely, [], until_ms=2000), "vrrp-10")[0] == "agg-a"

    empty = fact_pack(GroupSpec(number=10, members=()))
    assert holders(simulate(empty, [], until_ms=2000), "vrrp-10")[0] is None


# --------------------------------------------------------------------------
# The register itself
# --------------------------------------------------------------------------

ENTRY: Final = re.compile(r"^### (A\d+) — (.+)$", re.M)
TEST_FIELD: Final = re.compile(r"^\*\*Test:\*\* (.+)$", re.M)
CITATION: Final = re.compile(r"(?<![A-Za-z0-9])A(\d+)(?![0-9])")


def _defined_tests() -> set[str]:
    """Every test function name in the suite.

    The register started out pinning claims about `model.py`, whose tests all
    live in this file. It now also carries claims about the enumeration in
    `sequences.py`, whose tests do not — so the lookup is over the suite rather
    than over this module's globals, or an entry would have to name a test in
    the wrong file to satisfy the check.
    """
    return {
        name
        for path in Path(__file__).parent.glob("test_*.py")
        for name in re.findall(r"^def (test_[a-z0-9_]+)", path.read_text(), re.M)
    }


def _entries() -> list[tuple[str, str]]:
    """Each register entry with the body that follows it."""
    text = REGISTER.read_text()
    marks = [(m.group(1), m.start()) for m in ENTRY.finditer(text)]
    return [
        (identifier, text[start : marks[i + 1][1] if i + 1 < len(marks) else len(text)])
        for i, (identifier, start) in enumerate(marks)
    ]


def test_the_register_and_the_code_agree() -> None:
    """The register is only worth having if it cannot rot quietly.

    Three ways it could: an entry stops being tested, an entry claims a test that
    does not exist, or the model cites an assumption number nobody wrote down.
    """
    entries = _entries()
    assert len(entries) > 15, "the register parser found almost nothing"

    identifiers = [identifier for identifier, _ in entries]
    assert identifiers == sorted(identifiers, key=lambda a: int(a[1:])), (
        "entries are out of order"
    )
    assert len(set(identifiers)) == len(identifiers), "duplicate entry"

    for identifier, body in entries:
        field_match = TEST_FIELD.search(body)
        assert field_match, f"{identifier} has no Test field"
        claim = field_match.group(1).strip()
        if claim.startswith("none"):
            assert len(claim) > len("none — "), (
                f"{identifier} says it cannot be tested without saying why"
            )
            continue
        defined_tests = _defined_tests()
        for name in re.findall(r"`([a-z0-9_]+)`", claim):
            assert name in defined_tests, (
                f"{identifier} names a test that does not exist: {name}"
            )

    defined = set(identifiers)
    # Both files that carry A-markers: the model states the claims, and the
    # enumeration states which of them a sequence relies on.
    cited = {
        f"A{number}"
        for source in (MODEL, SEQUENCES)
        for number in CITATION.findall(source.read_text())
    }
    assert cited <= defined, (
        f"the code cites unregistered assumptions: {cited - defined}"
    )


def test_every_assumption_test_belongs_to_an_entry() -> None:
    """The other direction: a test named for an assumption that was deleted from
    the register is testing something nobody is claiming."""
    defined = {identifier for identifier, _ in _entries()}
    for name in globals():
        match = re.fullmatch(r"test_(a\d+)_.*", name)
        if match:
            assert match.group(1).upper() in defined, f"{name} has no register entry"
