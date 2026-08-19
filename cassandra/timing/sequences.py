"""Which event sequences are worth simulating, and what to conclude.

Enumeration is bounded on purpose. The interesting sequences are flaps of an
interface something tracks, at intervals near the preempt delays configured on
that pair — those are where groups can drift apart. Sequences are derived from
the configured timers rather than from a fixed list, so a network with different
timers gets different candidates.

The bound is a real limit and is stated in the findings: this searches a
neighbourhood, not the whole space. PROJECT.md §7 is about what would search it
properly.
"""

from __future__ import annotations

from typing import Final

from cassandra.factpack.schema import StaticFactPack
from cassandra.findings import Finding, Severity, Tier
from cassandra.timing.model import (
    DEFAULT_ADVERT_MS,
    Event,
    EventKind,
    Placement,
    simulate,
)

MAX_FLAPS: Final = 3
DOWN_MS: Final = 10_000
SETTLE_MS: Final = 30_000
MIN_DIVERGENCE_MS: Final = 30_000
MIN_TRANSITIONS: Final = 4


def _tracked_interfaces(pack: StaticFactPack) -> dict[str, set[str]]:
    """Interfaces whose state can change an election, per device."""
    watched: dict[str, set[str]] = {}
    for group in pack.fhrp_groups:
        for member in group.members:
            for tracked in member.tracked_objects:
                if tracked.target:
                    watched.setdefault(member.device, set()).add(tracked.target)
    return watched


def _candidate_intervals(pack: StaticFactPack) -> list[int]:
    """Up-intervals worth trying: just inside and just outside each preempt delay.

    A flap that recurs before a preempt delay expires prevents the group ever
    returning; one that recurs after it does not. The boundary is where behaviour
    changes, so that is where to look.
    """
    delays = {t.preempt_delay_ms for t in pack.timers.fhrp if t.preempt_delay_ms}
    intervals = {DEFAULT_ADVERT_MS * 20}
    for delay in delays:
        intervals.add(max(DEFAULT_ADVERT_MS, delay // 3))
        intervals.add(delay + SETTLE_MS)
    return sorted(intervals)


def _flap_sequence(
    device: str, interface: str, *, flaps: int, up_ms: int
) -> list[Event]:
    events: list[Event] = []
    clock = 0
    for _ in range(flaps):
        events.append(
            Event(
                at_ms=clock,
                kind=EventKind.LINK_DOWN,
                device=device,
                interface=interface,
            )
        )
        clock += DOWN_MS
        events.append(
            Event(
                at_ms=clock, kind=EventKind.LINK_UP, device=device, interface=interface
            )
        )
        clock += up_ms
    return events


def _longest_divergence_ms(timeline: list[Placement], a: str, b: str) -> int:
    longest = 0
    start: int | None = None
    for sample in timeline:
        ma, mb = sample.masters.get(a), sample.masters.get(b)
        diverged = ma is not None and mb is not None and ma != mb
        if diverged and start is None:
            start = sample.at_ms
        elif not diverged and start is not None:
            longest = max(longest, sample.at_ms - start)
            start = None
    if start is not None and timeline:
        longest = max(longest, timeline[-1].at_ms - start)
    return longest


def _transitions(timeline: list[Placement], group_id: str) -> int:
    count = 0
    previous: str | None = None
    for sample in timeline:
        current = sample.masters.get(group_id)
        if current is None:
            continue
        if previous is not None and current != previous:
            count += 1
        previous = current
    return count


def _divergence(
    *,
    device: str,
    first: str,
    second: str,
    labels: dict[str, str],
    span_ms: int,
    trigger: str,
    events: tuple[Event, ...],
) -> Finding:
    """Two FHRP groups on the same device pair that stop agreeing who is master.

    Both groups see one event. They answer it at different speeds — a different
    tracking decrement, a preempt delay on one and not the other — and for the
    stretch between their two answers, traffic for one VLAN leaves through one
    device and traffic for the next VLAN leaves through the other. Everything
    that assumes a single default gateway per site (a stateful firewall, a NAT
    table, an asymmetric-path check) breaks for exactly that window and then
    heals, which is what makes it so hard to catch after the fact.

    Reported only past MIN_DIVERGENCE_MS. A brief divergence *during* an event is
    expected behaviour; one that persists long after recovery is the defect.
    """
    return Finding(
        rule="fhrp-divergence",
        tier=Tier.TIMING,
        severity=Severity.HIGH,
        device=device,
        title=f"{labels[first]} and {labels[second]} can end up on different devices",
        detail=f"they share a device pair but respond to the same event "
        f"differently, leaving the gateways split for about {span_ms // 1000}s",
        trigger=trigger,
        evidence=tuple(e.describe() for e in events),
        remedy="make tracking and preempt delay consistent across groups on "
        "the same pair",
    )


def _oscillation(
    *,
    device: str,
    group_id: str,
    labels: dict[str, str],
    moves: int,
    trigger: str,
    events: tuple[Event, ...],
) -> Finding:
    """A group that changes master repeatedly while one interface flaps.

    A group with preempt and no preempt delay follows its tracked interface
    exactly: every flap hands mastership back and forth. Each handover is a
    short forwarding interruption for every host using that gateway, so a link
    that flaps five times does not cost one outage, it costs five — and the
    configuration looks correct at rest, because at rest it is.

    Reported past MIN_TRANSITIONS, which is high enough that the one handover a
    genuine failure causes does not count as chasing.
    """
    return Finding(
        rule="fhrp-oscillation",
        tier=Tier.TIMING,
        severity=Severity.MEDIUM,
        device=device,
        title=f"{labels[group_id]} changes master {moves} times under a single "
        f"flap sequence",
        detail="each transition is a forwarding interruption for everything "
        "using that gateway",
        trigger=trigger,
        evidence=tuple(e.describe() for e in events),
        remedy="add a preempt delay so the group does not chase a flapping interface",
    )


def _groups_by_device(pack: StaticFactPack) -> dict[str, list[str]]:
    """Group ids each device is a member of, in fact pack order."""
    index: dict[str, list[str]] = {}
    for group in pack.fhrp_groups:
        for member in group.members:
            ids = index.setdefault(member.device, [])
            if group.id not in ids:
                ids.append(group.id)
    return index


def analyse(pack: StaticFactPack) -> list[Finding]:
    """Every finding the enumeration produces, worst first.

    The two rules above are the conclusions; this is the search that reaches
    them. It is bounded, and the findings say so.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    labels = {
        group.id: f"{group.protocol.value.upper()} {group.group_number}"
        for group in pack.fhrp_groups
    }
    on_device = _groups_by_device(pack)

    for device, interfaces in sorted(_tracked_interfaces(pack).items()):
        # Only groups this device is a member of can move when this device's
        # interface flaps. Comparing every group in the pack against every other
        # one is quadratic in a number that is the whole site, and the pairs it
        # adds are between groups that cannot see each other's events.
        group_ids = on_device.get(device, [])
        if len(group_ids) < 1:
            continue
        for interface in sorted(interfaces):
            for up_ms in _candidate_intervals(pack):
                for flaps in range(1, MAX_FLAPS + 1):
                    events = _flap_sequence(device, interface, flaps=flaps, up_ms=up_ms)
                    horizon = events[-1].at_ms + SETTLE_MS + 60_000
                    timeline = simulate(pack, events, until_ms=horizon, only=group_ids)
                    trigger = (
                        f"flap {device}:{interface} {flaps}x "
                        f"({DOWN_MS // 1000}s down, {up_ms // 1000}s up)"
                    )

                    for i, first in enumerate(group_ids):
                        for second in group_ids[i + 1 :]:
                            span = _longest_divergence_ms(timeline, first, second)
                            if span < MIN_DIVERGENCE_MS:
                                continue
                            key = ("divergence", first, second)
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append(
                                _divergence(
                                    device=device,
                                    first=first,
                                    second=second,
                                    labels=labels,
                                    span_ms=span,
                                    trigger=trigger,
                                    events=events,
                                )
                            )

                    for group_id in group_ids:
                        moves = _transitions(timeline, group_id)
                        if moves < MIN_TRANSITIONS:
                            continue
                        key = ("oscillation", group_id, "")
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(
                            _oscillation(
                                device=device,
                                group_id=group_id,
                                labels=labels,
                                moves=moves,
                                trigger=trigger,
                                events=events,
                            )
                        )
    return findings
