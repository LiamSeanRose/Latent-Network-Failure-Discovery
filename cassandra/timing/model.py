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
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from cassandra.factpack.schema import FhrpGroup, StaticFactPack

# VRRP masters advertise every advertisement interval; a backup takes over after
# roughly three missed adverts. One second is the common default.
DEFAULT_ADVERT_MS: Final = 1000
FAILOVER_MS: Final = 3 * DEFAULT_ADVERT_MS


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
    """Which device holds each group at one instant."""

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
    down_interfaces: set[str] = field(default_factory=set)
    eligible_from_ms: int = 0

    def priority(self) -> int:
        lost = sum(
            decrement
            for watched, decrement in self.tracks
            if watched in self.down_interfaces
        )
        return self.base_priority - lost


def _members(group: FhrpGroup, pack: StaticFactPack) -> list[_MemberState]:
    delays = {
        (t.scope.device, t.scope.instance): t.preempt_delay_ms or 0
        for t in pack.timers.fhrp
    }
    return [
        _MemberState(
            device=member.device,
            interface=member.interface,
            base_priority=member.priority,
            preempt=member.preempt,
            preempt_delay_ms=delays.get((member.device, str(group.group_number)), 0),
            tracks=tuple(
                (tracked.target, tracked.decrement or 0)
                for tracked in member.tracked_objects
                if tracked.target
            ),
        )
        for member in group.members
    ]


def simulate(
    pack: StaticFactPack, events: list[Event], *, until_ms: int
) -> list[Placement]:
    """Advance every FHRP group through the events and sample the placement.

    Sampling rather than event-stepping because the questions being asked are
    about *durations* — how long two groups sat on different devices — and a
    uniform grid makes those directly measurable.
    """
    groups = {group.id: group for group in pack.fhrp_groups}
    states = {gid: _members(group, pack) for gid, group in groups.items()}
    holder: dict[str, str | None] = {}

    # Settle the initial election before anything happens.
    for gid, members in states.items():
        holder[gid] = _elect(members, holder.get(gid), now_ms=0)

    timeline: list[Placement] = []
    pending = sorted(events, key=lambda e: e.at_ms)
    step_ms = DEFAULT_ADVERT_MS
    index = 0

    for now_ms in range(0, until_ms + step_ms, step_ms):
        while index < len(pending) and pending[index].at_ms <= now_ms:
            event = pending[index]
            index += 1
            for members in states.values():
                for member in members:
                    if member.device != event.device:
                        continue
                    if event.kind is EventKind.LINK_DOWN:
                        member.down_interfaces.add(event.interface)
                    else:
                        member.down_interfaces.discard(event.interface)
                        # Recovery restarts the preempt delay: this is the
                        # mechanism that lets groups on one pair drift apart.
                        member.eligible_from_ms = now_ms + member.preempt_delay_ms

        for gid, members in states.items():
            holder[gid] = _elect(members, holder[gid], now_ms=now_ms)
        timeline.append(Placement(at_ms=now_ms, masters=dict(holder)))

    return timeline


def _elect(
    members: list[_MemberState], current: str | None, *, now_ms: int
) -> str | None:
    if not members:
        return None
    incumbent = next((m for m in members if m.device == current), None)

    best = incumbent
    for member in members:
        if member is incumbent:
            continue
        if incumbent is not None:
            # Taking over from a live master requires preemption, a higher
            # priority, and any preempt delay to have expired.
            if member.priority() <= incumbent.priority():
                continue
            if not member.preempt or now_ms < member.eligible_from_ms:
                continue
        if best is None or member.priority() > best.priority():
            best = member
        elif best is not incumbent and member.priority() == best.priority():
            # Deterministic tie-break so the model does not invent a flap.
            best = min([best, member], key=lambda m: m.device)
    return best.device if best else None
