"""Timer arithmetic — the questions answerable by comparing two numbers.

Two of the questions PROJECT.md §1.4 files under TIMING carry a time quantity but
no event ordering: whether BFD detects a failure before or after the IGP would
have noticed anyway, and whether route dampening suppresses a prefix for longer
than an SLA allows. Both are settled by arithmetic over configured values, which
is why they live beside the discrete-event model rather than inside it — the
subject is timers, but nothing here simulates anything.

That distinction decides the tier. `model.py` produces candidates that could be
wrong because a model stands between the facts and the finding (§2.2); these
findings stand or fall on the configured numbers alone, so they carry
`Tier.FACTS` and say exactly which arithmetic produced them.

Everything reads the timer inventory, never the topology, so a rule here works on
any dialect whose builder populates the same records (§5.2).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Final

from cassandra.factpack.schema import (
    BfdTimers,
    DampeningProfile,
    IgpHelloTimers,
    Milliseconds,
    Seconds,
    StaticFactPack,
    TimerSource,
)
from cassandra.findings import Finding, Severity, Tier


@dataclass(frozen=True, slots=True, kw_only=True)
class Limits:
    """The thresholds a finding is measured against.

    An SLA is the user's number, not ours. The default is the shortest outage
    most people would still call an outage; a site with a tighter or looser
    commitment passes its own.
    """

    sla_max_suppress_s: Seconds = 300


DEFAULT_LIMITS: Final = Limits()

Rule = Callable[[StaticFactPack, Limits], Iterator[Finding]]
RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


# --------------------------------------------------------------------------
# Arithmetic
# --------------------------------------------------------------------------


def bfd_detection_ms(session: BfdTimers) -> Milliseconds | None:
    """How long the session takes to declare a neighbour down.

    `desired_min_tx * detect_multiplier`, which is the local half of the
    negotiation. The session actually runs at the slower of the two ends, so
    this is a lower bound on detection time — a bound that is already too slow
    is unambiguously too slow.
    """
    if session.desired_min_tx_ms is None or session.detect_multiplier is None:
        return None
    return session.desired_min_tx_ms * session.detect_multiplier


def igp_dead_ms(timers: IgpHelloTimers) -> Milliseconds | None:
    """How long the IGP takes to drop the adjacency on its own.

    Only configured values are used. OSPF states the dead interval directly;
    IS-IS states a hello interval and a multiplier whose product is the hold
    time. Nothing is filled in from a platform default, because a comparison
    against a value nobody configured is a comparison against a guess.
    """
    if timers.dead_interval_ms is not None:
        return timers.dead_interval_ms
    if timers.hold_time_ms is not None:
        return timers.hold_time_ms
    if timers.hello_interval_ms is not None and timers.hello_multiplier is not None:
        return timers.hello_interval_ms * timers.hello_multiplier
    return None


def _where(device: str, interface: str | None) -> str:
    return f"{device}:{interface}" if interface else device


def _ms(value: Milliseconds) -> str:
    if value < 1000:
        return f"{value}ms"
    seconds = value / 1000
    return f"{seconds:g}s"


def _duration(seconds: Seconds) -> str:
    if seconds < 120:
        return f"{seconds}s"
    minutes, rest = divmod(seconds, 60)
    return f"{seconds}s ({minutes}m)" if not rest else f"{seconds}s (~{minutes}m)"


def _bfd_line(session: BfdTimers) -> str:
    parts = [f"{_where(session.scope.device, session.scope.interface)}  bfd"]
    if session.desired_min_tx_ms is not None:
        parts.append(f"interval {session.desired_min_tx_ms}")
    if session.required_min_rx_ms is not None:
        parts.append(f"min_rx {session.required_min_rx_ms}")
    if session.detect_multiplier is not None:
        parts.append(f"multiplier {session.detect_multiplier}")
    return " ".join(parts)


def _igp_line(timers: IgpHelloTimers) -> str:
    parts = [
        f"{_where(timers.scope.device, timers.scope.interface)}  "
        f"{timers.protocol.value}"
    ]
    if timers.hello_interval_ms is not None:
        parts.append(f"hello {_ms(timers.hello_interval_ms)}")
    if timers.dead_interval_ms is not None:
        parts.append(f"dead {_ms(timers.dead_interval_ms)}")
    if timers.hello_multiplier is not None:
        parts.append(f"multiplier {timers.hello_multiplier}")
    return " ".join(parts)


def _dampening_line(profile: DampeningProfile) -> str:
    parts = [f"{profile.scope.device}  {profile.kind.value} dampening"]
    if profile.half_life_s is not None:
        parts.append(f"half-life {profile.half_life_s}s")
    if profile.reuse_threshold is not None:
        parts.append(f"reuse {profile.reuse_threshold}")
    if profile.suppress_threshold is not None:
        parts.append(f"suppress {profile.suppress_threshold}")
    if profile.max_suppress_s is not None:
        parts.append(f"max-suppress {profile.max_suppress_s}s")
    return " ".join(parts)


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


@rule
def bfd_detects_no_sooner_than_the_igp(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """BFD exists to detect faster than the IGP. One that does not is decoration.

    The cost is not neutral. The session is configured, monitored and believed,
    and every design decision downstream of it assumes sub-second detection that
    the numbers say cannot happen.
    """
    del limits
    igp_by_interface: dict[tuple[str, str | None], list[IgpHelloTimers]] = {}
    for timers in pack.timers.igp_hello:
        key = (timers.scope.device, timers.scope.interface)
        igp_by_interface.setdefault(key, []).append(timers)

    for session in pack.timers.bfd:
        detection = bfd_detection_ms(session)
        if detection is None:
            continue
        key = (session.scope.device, session.scope.interface)
        where = _where(session.scope.device, session.scope.interface)
        for timers in igp_by_interface.get(key, []):
            dead = igp_dead_ms(timers)
            if dead is None or detection < dead:
                continue
            yield Finding(
                rule="bfd-no-faster-than-igp",
                tier=Tier.FACTS,
                severity=Severity.MEDIUM,
                device=session.scope.device,
                title=f"BFD detection ({_ms(detection)}) is no faster than the "
                f"{timers.protocol.value.upper()} dead interval ({_ms(dead)})",
                detail=f"{session.desired_min_tx_ms}ms x "
                f"{session.detect_multiplier} = {_ms(detection)}, and the "
                f"adjacency drops on its own after {_ms(dead)}. The session "
                f"accelerates nothing, so the fast failure detection the config "
                f"implies does not exist.",
                trigger=f"loss of {where}",
                evidence=(_bfd_line(session), _igp_line(timers)),
                remedy=f"lower the BFD interval or multiplier so detection is well "
                f"under {_ms(dead)}, or drop the session and rely on the IGP",
            )


@rule
def bfd_session_has_no_clients(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """A session nothing registered against comes up, runs, and is never asked.

    `BfdTimers.clients` is populated by the builder from the protocols that
    reference the session. Empty means no protocol on this device asked BFD to
    tell it anything, so the detection time — however fast — reaches no
    decision.
    """
    del limits
    for session in pack.timers.bfd:
        if session.clients:
            continue
        detection = bfd_detection_ms(session)
        measured = f" ({_ms(detection)})" if detection is not None else ""
        where = _where(session.scope.device, session.scope.interface)
        yield Finding(
            rule="bfd-no-clients",
            tier=Tier.FACTS,
            severity=Severity.MEDIUM,
            device=session.scope.device,
            title=f"BFD session on {where} has no registered client",
            detail=f"the session is configured{measured} but no protocol is "
            f"registered against it, so nothing reacts when it goes down — the "
            f"detection time buys nothing",
            trigger=f"loss of {where}",
            evidence=(_bfd_line(session),),
            remedy="register a client (for example `ip ospf bfd` on the "
            "interface, or `neighbor <peer> bfd` under the BGP process), or "
            "remove the session",
        )


@rule
def dampening_outlasts_the_sla(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """Max-suppress bounds how long a prefix stays withdrawn after the fault ends.

    That window is invisible to steady-state analysis — every device is healthy,
    every adjacency is up, and the route is still gone — which is exactly why it
    reaches production.
    """
    for profile in pack.timers.dampening:
        if profile.max_suppress_s is None:
            continue
        if profile.max_suppress_s <= limits.sla_max_suppress_s:
            continue
        inherited = profile.scope.source is TimerSource.PLATFORM_DEFAULT
        provenance = (
            " These are the platform defaults, so the window was inherited "
            "rather than chosen."
            if inherited
            else ""
        )
        yield Finding(
            rule="dampening-exceeds-sla",
            tier=Tier.FACTS,
            severity=Severity.HIGH,
            device=profile.scope.device,
            title=f"{profile.kind.value} dampening can suppress a prefix for "
            f"{_duration(profile.max_suppress_s)}",
            detail=f"max-suppress is {_duration(profile.max_suppress_s)} against "
            f"an SLA of {_duration(limits.sla_max_suppress_s)}. A prefix that "
            f"reaches the suppress threshold stays withdrawn for that long after "
            f"the network is otherwise healthy.{provenance}",
            trigger="a prefix flapping enough to reach the suppress threshold",
            evidence=(_dampening_line(profile),),
            remedy=f"lower max-suppress-time below "
            f"{_duration(limits.sla_max_suppress_s)}, or remove dampening",
        )


def analyse(pack: StaticFactPack, *, limits: Limits = DEFAULT_LIMITS) -> list[Finding]:
    return [finding for rule_fn in RULES for finding in rule_fn(pack, limits)]
