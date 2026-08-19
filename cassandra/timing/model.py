"""A discrete-event model of FHRP election under interface events.

**This tier can lie, and everything about it is built to make that visible.** It
models timer interaction, not protocol implementations: priorities, tracked-object
decrements, preemption and preempt delay, advanced through a sequence of link
events. Real firmware has message loss, jitter, hold-downs and startup behaviour
this does not.

So every prediction carries the exact sequence that produced it, and PROJECT.md
§4.2 Phase 4 exists to check the model against real implementations in CI. A
timing model nobody has validated is a guess with good formatting.

Scope is deliberately narrow (§5.1): FHRP election and interface tracking. Widen
only where validation shows the model already agrees with reality.

**Every behavioural claim this module makes is registered in
`docs/timing-model.md`.** Each entry there carries what the model does, what real
firmware is believed to do, how confident that belief is, and the specific
observation that would falsify it — the checklist for whoever eventually boots a
lab. The `A<n>` markers in the comments below are that register's identifiers, so
a claim in the document and the line of code that implements it can be found from
each other. `tests/test_timing_model_assumptions.py` asserts the model really
behaves the way the register says.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Collection
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from cassandra.factpack.builders.common import fhrp_instance
from cassandra.factpack.schema import (
    AddressFamily,
    FhrpGroup,
    FhrpProtocol,
    StaticFactPack,
)

# --------------------------------------------------------------------------
# Assumptions expressed as constants
#
# Every number below is a claim about real routers. Named, so that changing one
# is a visible edit rather than arithmetic buried in a loop, and so the register
# entry that argues for it can be found by its A-number.
# --------------------------------------------------------------------------

# A1. How often a group advertises, when its own configuration does not say.
# VRRP's default is one second and HSRP's hello is three, so the default is per
# protocol; a group that states an interval gets the one it states, read from
# `FhrpTimers.hello_interval_ms`. Confidence: documented per protocol.
DEFAULT_ADVERT_MS: Final[int] = 1000
DEFAULT_HSRP_HELLO_MS: Final[int] = 3000

# A2. The timeline is sampled on a fixed grid rather than event-stepped, because
# the questions asked of it are about durations (§2.2) and a uniform grid makes
# those directly measurable. One sample per advertisement interval: nothing in
# the modelled dynamics can resolve finer than one advert, so a finer grid would
# imply a precision the model does not have. Cost: every event is rounded up to
# the next sample, and every duration read off the timeline carries up to one
# sample of error at each edge.
SAMPLE_INTERVAL_MS: Final[int] = DEFAULT_ADVERT_MS

# A3. A backup declares the master gone after three missed advertisements. This
# is the RFC 5798 master-down interval without its skew term, and it applies
# only to a master that has *stopped advertising* — in this model, one whose own
# FHRP interface went down (A15). Confidence: documented, minus the skew.
MASTER_DOWN_MULTIPLIER: Final[int] = 3
MASTER_DOWN_INTERVAL_MS: Final[int] = MASTER_DOWN_MULTIPLIER * DEFAULT_ADVERT_MS


def advert_interval_ms(pack: StaticFactPack, group: FhrpGroup) -> int:
    """How often this group advertises (A1).

    The configured interval if any member states one, and the protocol's own
    default otherwise — one second for VRRP, three for HSRP. Modelling every
    group at one second made every HSRP group detect failure three times faster
    than it does, which is the direction that hides a real outage rather than
    inventing one.

    The longest stated interval wins where two members disagree: the group is
    only as fast as the member that has to notice.
    """
    # Indexed rather than scanned. This is called once per group per simulation
    # and the simulation is run once per candidate sequence, so a linear pass
    # over every FHRP timer in the pack for every one of them is quadratic in a
    # collection's size — which was measurable at eighty devices and dominant at
    # two hundred.
    hellos = _cached_hellos(pack)
    instance = fhrp_instance(group.group_number, group.family)
    stated = [
        interval
        for member in group.members
        if (interval := hellos.get((member.device, member.interface, instance)))
    ]
    if stated:
        return max(stated)
    return (
        DEFAULT_HSRP_HELLO_MS
        if group.protocol is FhrpProtocol.HSRP
        else DEFAULT_ADVERT_MS
    )


def master_down_interval_ms(pack: StaticFactPack, group: FhrpGroup) -> int:
    """How long a backup waits before declaring the master gone (A3)."""
    return MASTER_DOWN_MULTIPLIER * advert_interval_ms(pack, group)


# A8. Tracking cannot drive a priority below this. VRRP encodes priority in one
# octet where 0 means "the master is resigning" and 255 means "address owner",
# so a decremented priority that lands at or below zero is not representable on
# the wire. Vendors clamp; the model clamps to the same floor.
MIN_EFFECTIVE_PRIORITY: Final[int] = 1

# A9. A tracked object whose decrement the parser did not record contributes
# nothing. That is a silent no-op, not a neutral default: a bare `standby N
# track X` on IOS decrements by 10 on real firmware.
MISSING_DECREMENT: Final[int] = 0

# A19. A member with no preempt-delay record in the timer inventory preempts
# with no delay at all.
DEFAULT_PREEMPT_DELAY_MS: Final[int] = 0


class EventKind(StrEnum):
    LINK_DOWN = "link_down"
    LINK_UP = "link_up"


@dataclass(frozen=True, slots=True, kw_only=True)
class Event:
    at_ms: int
    kind: EventKind
    device: str
    interface: str

    def describe(self) -> str:
        verb = "down" if self.kind is EventKind.LINK_DOWN else "up"
        return f"t={self.at_ms // 1000}s {self.device}:{self.interface} {verb}"


@dataclass(frozen=True, slots=True, kw_only=True)
class Placement:
    """Which device holds each group at one instant.

    A15/A16: one device per group, or `None` while no member can serve it. Two
    masters for one group is not representable here — see the register.
    """

    at_ms: int
    masters: dict[str, str | None]


@dataclass(slots=True)
class _MemberState:
    device: str
    interface: str
    base_priority: int
    preempt: bool
    preempt_delay_ms: int
    tracks: tuple[tuple[str, int], ...]  # (watched interface, decrement)
    tie_break_ip: int | None  # A7: primary IPv4 of the FHRP interface
    down_interfaces: set[str] = field(default_factory=set)
    eligible_from_ms: int = 0

    def priority(self) -> int:
        """A5/A8: current priority is the configured value less every decrement
        whose tracked interface is currently down, with no memory of how it got
        there and no floor below `MIN_EFFECTIVE_PRIORITY`."""
        lost = sum(
            decrement
            for watched, decrement in self.tracks
            if watched in self.down_interfaces
        )
        return max(MIN_EFFECTIVE_PRIORITY, self.base_priority - lost)

    def available(self) -> bool:
        """A15: a member can serve the group exactly when the interface the
        group is configured on is up. Nothing else — peer reachability, the L2
        path between members, protocol adjacency — is modelled."""
        return self.interface not in self.down_interfaces

    def touched_by(self, interface: str) -> bool:
        """A10/A12/A21: an event reaches a member only if it names, by exact
        string, the interface the group runs on or an interface the member
        tracks. Everything else on the device is irrelevant to it."""
        return interface == self.interface or any(
            watched == interface for watched, _ in self.tracks
        )


@dataclass(slots=True)
class _GroupState:
    members: list[_MemberState]
    master: str | None = None
    # A3: when the group was left without a master, so the detection interval
    # can be measured from it. None means "not currently vacant".
    vacant_since_ms: int | None = None
    # A1/A3: this group's own detection interval, three times whatever it
    # advertises at. Held per group because HSRP and VRRP do not agree on it and
    # a configuration may override either.
    master_down_ms: int = MASTER_DOWN_INTERVAL_MS


def _primary_ipv4s(pack: StaticFactPack) -> dict[tuple[str, str], int]:
    """First non-secondary IPv4 of every interface, as an integer.

    A7: the tie-break key. Absent for an interface the fact pack has no address
    for, which is the case the fallback exists for.
    """
    addresses: dict[tuple[str, str], int] = {}
    for device in pack.devices:
        for interface in device.interfaces:
            for assignment in interface.addresses:
                if assignment.family is not AddressFamily.IPV4_UNICAST:
                    continue
                if assignment.secondary:
                    continue
                try:
                    value = int(ipaddress.IPv4Address(assignment.address))
                except ValueError:
                    continue
                addresses.setdefault((device.id, interface.name), value)
                break
    return addresses


def _preempt_delays(pack: StaticFactPack) -> dict[tuple[str, str, FhrpProtocol], int]:
    """Preempt delay per (device, group number, protocol).

    A19: keyed on the protocol as well as the number, because `scope.instance`
    carries the group *number* and HSRP 14 and VRRP 14 can both exist on one
    device. `preempt_delay_reload_ms` is deliberately not read (A14).
    """
    return {
        (timer.scope.device, timer.scope.instance or "", timer.protocol): (
            timer.preempt_delay_ms or DEFAULT_PREEMPT_DELAY_MS
        )
        for timer in pack.timers.fhrp
    }


# The two whole-pack lookups below are rebuilt for every group of every
# simulation, and the sequence enumeration runs one simulation per device. That
# made analysing a site quadratic in the size of the collection it happened to be
# filed in — an eight-device site cost eight times more inside a fifty-site
# directory than on its own.
#
# Keyed on identity, not on the fact pack id: that id is content-addressed only
# when `build_fact_pack` produced it, and a hand-built pack can carry any string
# at all. The pack is held in the value and compared with `is`, so a recycled id
# cannot produce a wrong answer. Bounded to two entries, which is also the bound
# on how many packs this keeps alive.
type _Delays = dict[tuple[str, str, FhrpProtocol], int]
type _Addresses = dict[tuple[str, str], int]
type _Hellos = dict[tuple[str, str, str], int]

_LOOKUPS: dict[int, tuple[StaticFactPack, _Delays, _Addresses, _Hellos]] = {}


def _cached_lookups(pack: StaticFactPack) -> tuple[_Delays, _Addresses, _Hellos]:
    cached = _LOOKUPS.get(id(pack))
    if cached is not None and cached[0] is pack:
        return cached[1], cached[2], cached[3]
    if len(_LOOKUPS) >= 2:
        _LOOKUPS.clear()
    built = (_preempt_delays(pack), _primary_ipv4s(pack), _hello_intervals(pack))
    _LOOKUPS[id(pack)] = (pack, *built)
    return built


def _cached_hellos(pack: StaticFactPack) -> _Hellos:
    return _cached_lookups(pack)[2]


def _hello_intervals(pack: StaticFactPack) -> _Hellos:
    """Every stated advertisement interval, by the scope that states it.

    Two records on one scope keep the larger, which is the same rule
    `advert_interval_ms` applies across members and for the same reason: a group
    is only as fast as the member that has to notice. A dict built without it
    would silently keep whichever record the inventory happened to list last,
    turning a duplicate into a coin toss.
    """
    intervals: _Hellos = {}
    for timer in pack.timers.fhrp:
        if not timer.hello_interval_ms:
            continue
        key = (timer.scope.device, timer.scope.interface, timer.scope.instance)
        intervals[key] = max(intervals.get(key, 0), timer.hello_interval_ms)
    return intervals


def _members(group: FhrpGroup, pack: StaticFactPack) -> list[_MemberState]:
    delays, addresses, _ = _cached_lookups(pack)
    return [
        _MemberState(
            device=member.device,
            interface=member.interface,
            base_priority=member.priority,
            preempt=member.preempt,
            preempt_delay_ms=delays.get(
                (
                    member.device,
                    fhrp_instance(group.group_number, group.family),
                    group.protocol,
                ),
                DEFAULT_PREEMPT_DELAY_MS,
            ),
            # A9: every tracked object is treated as an interface track,
            # whatever its kind, and a missing decrement is worth nothing.
            tracks=tuple(
                (tracked.target, tracked.decrement or MISSING_DECREMENT)
                for tracked in member.tracked_objects
                if tracked.target
            ),
            tie_break_ip=addresses.get((member.device, member.interface)),
        )
        for member in group.members
    ]


def simulate(
    pack: StaticFactPack,
    events: list[Event],
    *,
    until_ms: int,
    only: Collection[str] | None = None,
) -> list[Placement]:
    """Advance every FHRP group through the events and sample the placement.

    Sampling rather than event-stepping because the questions being asked are
    about *durations* — how long two groups sat on different devices — and a
    uniform grid makes those directly measurable (A2). Samples run from 0 to
    `until_ms` inclusive, rounded up to the grid (A23).

    A20: groups are advanced independently. Two groups on the same pair share
    fate only through the interfaces their members track; nothing else couples
    them — not a shared virtual MAC, not a common VLAN, not the peer link.

    `only` narrows the simulation to the named groups. A20 is what makes that
    safe: the result for a named group is identical either way, and the rest
    contribute nothing but time. Asking about one site's groups on a fifty-site
    pack should not cost the other forty-nine.
    """
    wanted = None if only is None else set(only)
    states = {
        group.id: _GroupState(
            members=_members(group, pack),
            master_down_ms=master_down_interval_ms(pack, group),
        )
        for group in pack.fhrp_groups
        if wanted is None or group.id in wanted
    }

    # A14: settle the initial election before anything happens. No preempt delay
    # applies to it — a cold start is not modelled, so `preempt delay reload`
    # has nowhere to act.
    for state in states.values():
        _settle(state, now_ms=0)

    timeline: list[Placement] = []
    # A22: stable sort, so events written at the same instant are applied in the
    # order the caller listed them.
    pending = sorted(events, key=lambda event: event.at_ms)
    index = 0

    for now_ms in range(0, until_ms + SAMPLE_INTERVAL_MS, SAMPLE_INTERVAL_MS):
        while index < len(pending) and pending[index].at_ms <= now_ms:
            event = pending[index]
            index += 1
            for state in states.values():
                for member in state.members:
                    _apply(member, event, now_ms=now_ms)

        for state in states.values():
            _settle(state, now_ms=now_ms)
        timeline.append(
            Placement(
                at_ms=now_ms,
                masters={gid: state.master for gid, state in states.items()},
            )
        )

    return timeline


def _apply(member: _MemberState, event: Event, *, now_ms: int) -> None:
    """Fold one link event into one member's view of the world."""
    if member.device != event.device or not member.touched_by(event.interface):
        return
    if event.kind is EventKind.LINK_DOWN:
        member.down_interfaces.add(event.interface)
        return
    member.down_interfaces.discard(event.interface)
    # A11/A12: the preempt delay is measured from the moment the interface
    # recovers — not from when the priority is restored, not from entering
    # backup — and only for a member this event actually touches. This is the
    # mechanism that lets groups on one pair drift apart, and it is the single
    # assumption most of the tool's headline findings rest on.
    member.eligible_from_ms = now_ms + member.preempt_delay_ms


def _settle(state: _GroupState, *, now_ms: int) -> None:
    """Bring one group's mastership up to date at this instant."""
    incumbent = next((m for m in state.members if m.device == state.master), None)

    if incumbent is not None and not incumbent.available():
        # A3/A15: the master cannot serve any more. Backups only learn this by
        # missing advertisements, so the group is genuinely masterless for the
        # detection interval rather than handing over instantly.
        state.master = None
        state.vacant_since_ms = now_ms
        incumbent = None

    live = [member for member in state.members if member.available()]
    if not live:
        # A24: no member can serve, so nobody holds the group.
        state.master = None
        return

    if incumbent is None:
        if (
            state.vacant_since_ms is not None
            and now_ms < state.vacant_since_ms + state.master_down_ms
        ):
            return
        # A13: claiming a vacant group is not preemption, so neither `preempt`
        # nor a preempt delay gates it.
        state.master = _best(live).device
        state.vacant_since_ms = None
        return

    state.vacant_since_ms = None
    challengers = [
        member
        for member in live
        if member is not incumbent
        # A6: strictly greater. An equal priority never displaces a live master.
        and member.priority() > incumbent.priority()
        # A11: preemption requires it to be configured and any delay expired.
        and member.preempt
        and now_ms >= member.eligible_from_ms
    ]
    if challengers:
        # A4: takeover lands in the same sample as the priority change. No
        # advertisement-propagation latency is modelled on this path.
        state.master = _best(challengers).device


def _best(members: list[_MemberState]) -> _MemberState:
    """Highest priority wins; A7 breaks the tie."""
    best = members[0]
    for member in members[1:]:
        if member.priority() > best.priority():
            best = member
        elif member.priority() == best.priority() and _prefers(member, best):
            best = member
    return best


def _prefers(challenger: _MemberState, holder: _MemberState) -> bool:
    """A7: at equal priority, the higher primary IPv4 wins — the rule both VRRP
    and HSRP use. Where the fact pack has no address for one of the interfaces
    the model falls back to the lower device name, which is deterministic (so
    the model never invents a flap) and has no counterpart in any firmware."""
    if challenger.tie_break_ip is not None and holder.tie_break_ip is not None:
        if challenger.tie_break_ip != holder.tie_break_ip:
            return challenger.tie_break_ip > holder.tie_break_ip
    return challenger.device < holder.device
