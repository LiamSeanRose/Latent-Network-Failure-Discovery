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

# PROJECT.md §2.4. The controls are written there for the emulation tier, and
# two of the three are just as cheap and just as necessary here.
#
# The no-trigger control asks whether the sequence caused the observation at all.
# If two groups sit apart with no events, the trigger explains nothing and the
# finding is at best mislabelled — the FACTS tier owns a configuration that is
# split at rest.
#
# The perturbation control asks whether the observation survives the interval
# being slightly different. A divergence that appears at exactly ninety seconds
# and nowhere near it is an artifact of this model's one-second sampling grid,
# not a property of the configuration, and reporting it would spend the reader's
# trust on a number the model invented.
#
# Repetition, the third control, does not apply: this model is deterministic, so
# three runs of one sequence are one run three times. It is the emulator that
# needs it.
PERTURBATION: Final = 0.2
PERTURBED_RUNS: Final = 3
MIN_CONFIRMATIONS: Final = 2


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


def _control_note(held: int) -> str:
    """What the controls established, in the evidence where it can be weighed."""
    return (
        f"held in {held} of {PERTURBED_RUNS} runs at "
        f"±{int(PERTURBATION * 100)}% of the interval; absent with no events"
    )


def _divergence(
    *,
    device: str,
    first: str,
    second: str,
    labels: dict[str, str],
    span_ms: int,
    trigger: str,
    events: tuple[Event, ...],
    held: int = PERTURBED_RUNS,
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

    Silent unless the split survives the flap interval being twenty percent
    either side of the one that produced it, and silent if the same split is
    there with no events at all. Those two controls are what separate a property
    of the configuration from an artifact of the model's sampling grid.
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
        evidence=(*(e.describe() for e in events), _control_note(held)),
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
    held: int = PERTURBED_RUNS,
    delay_ms: int = 0,
) -> Finding:
    """A group that changes master repeatedly while one interface flaps.

    A group with preempt and no preempt delay follows its tracked interface
    exactly: every flap hands mastership back and forth. Each handover is a
    short forwarding interruption for every host using that gateway, so a link
    that flaps five times does not cost one outage, it costs five — and the
    configuration looks correct at rest, because at rest it is.

    Reported past MIN_TRANSITIONS, which is high enough that the one handover a
    genuine failure causes does not count as chasing.

    Silent unless the chasing survives the flap interval being twenty percent
    either side, and silent if the group moves that often with no events at all.

    The finding names the group's own preempt delay, because two groups on one
    device can both chase and need different flap intervals to do it — and
    without the delays written down, two findings whose only visible difference
    is a number in the trigger look like the same finding printed twice.
    """
    return Finding(
        rule="fhrp-oscillation",
        tier=Tier.TIMING,
        severity=Severity.MEDIUM,
        device=device,
        title=f"{labels[group_id]} changes master {moves} times under a single "
        f"flap sequence",
        detail="each transition is a forwarding interruption for everything "
        "using that gateway"
        + (
            f"; this group waits {delay_ms // 1000}s before preempting, so it "
            f"chases flaps spaced further apart than that"
            if delay_ms
            else "; this group has no preempt delay, so it follows the "
            "interface immediately"
        ),
        trigger=trigger,
        evidence=(*(e.describe() for e in events), _control_note(held)),
        remedy=(
            f"raise the preempt delay past {delay_ms // 1000}s, or damp the "
            f"interface so it stops flapping"
            if delay_ms
            # Telling someone to add a delay they already have is the fastest
            # way to lose them.
            else "add a preempt delay so the group does not chase a flapping interface"
        ),
    )


def _intervals_around(up_ms: int) -> tuple[int, ...]:
    """The nominal interval and one either side of it, clamped to the grid.

    Twenty percent, per §2.4. Sub-sample perturbations collapse back onto the
    nominal run, which would turn the control into three copies of the same
    thing agreeing with itself.
    """
    low = max(DEFAULT_ADVERT_MS, round(up_ms * (1 - PERTURBATION)))
    high = round(up_ms * (1 + PERTURBATION))
    return (up_ms, low, high)


def _preempt_delays(pack: StaticFactPack) -> dict[str, int]:
    """The longest preempt delay configured on each group, in milliseconds.

    Group ids are per subnet; timer records are per device and interface. The
    longest wins because it is the one that decides how far apart flaps have to
    be before the group stops chasing them.
    """
    by_interface: dict[tuple[str, str | None], int] = {}
    for timer in pack.timers.fhrp:
        if timer.preempt_delay_ms:
            key = (timer.scope.device, timer.scope.interface)
            by_interface[key] = max(by_interface.get(key, 0), timer.preempt_delay_ms)
    delays: dict[str, int] = {}
    for group in pack.fhrp_groups:
        for member in group.members:
            found = by_interface.get((member.device, member.interface))
            if found:
                delays[group.id] = max(delays.get(group.id, 0), found)
    return delays


def _run(
    pack: StaticFactPack,
    device: str,
    interface: str,
    flaps: int,
    up_ms: int,
    group_ids: list[str],
) -> tuple[tuple[Event, ...], list[Placement]]:
    """One flap sequence and the timeline it produces."""
    events = _flap_sequence(device, interface, flaps=flaps, up_ms=up_ms)
    horizon = events[-1].at_ms + SETTLE_MS + 60_000
    return events, simulate(pack, events, until_ms=horizon, only=group_ids)


def _control_timeline(pack: StaticFactPack, group_ids: list[str]) -> list[Placement]:
    """The same window with nothing happening in it.

    §2.4's no-trigger control, with its criterion inverted rather than skipped:
    an observation present here was not caused by any trigger.
    """
    horizon = DOWN_MS * MAX_FLAPS + SETTLE_MS + 60_000
    return simulate(pack, [], until_ms=horizon, only=group_ids)


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
    delays = _preempt_delays(pack)

    for device, interfaces in sorted(_tracked_interfaces(pack).items()):
        # Only groups this device is a member of can move when this device's
        # interface flaps. Comparing every group in the pack against every other
        # one is quadratic in a number that is the whole site, and the pairs it
        # adds are between groups that cannot see each other's events.
        group_ids = on_device.get(device, [])
        if len(group_ids) < 1:
            continue
        for interface in sorted(interfaces):
            control = _control_timeline(pack, group_ids)
            for up_ms in _candidate_intervals(pack):
                for flaps in range(1, MAX_FLAPS + 1):
                    runs = [
                        _run(pack, device, interface, flaps, interval, group_ids)
                        for interval in _intervals_around(up_ms)
                    ]
                    events, timeline = runs[0]
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
                            held = sum(
                                _longest_divergence_ms(t, first, second)
                                >= MIN_DIVERGENCE_MS
                                for _, t in runs
                            )
                            if held < MIN_CONFIRMATIONS:
                                continue
                            if (
                                _longest_divergence_ms(control, first, second)
                                >= MIN_DIVERGENCE_MS
                            ):
                                # Split with no events at all. The sequence did
                                # not cause it, so reporting it under this
                                # trigger would point at the wrong thing.
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
                                    held=held,
                                )
                            )

                    for group_id in group_ids:
                        moves = _transitions(timeline, group_id)
                        if moves < MIN_TRANSITIONS:
                            continue
                        key = ("oscillation", group_id, "")
                        if key in seen:
                            continue
                        held = sum(
                            _transitions(t, group_id) >= MIN_TRANSITIONS
                            for _, t in runs
                        )
                        if held < MIN_CONFIRMATIONS:
                            continue
                        if _transitions(control, group_id) >= MIN_TRANSITIONS:
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
                                held=held,
                                delay_ms=delays.get(group_id, 0),
                            )
                        )
    return findings
