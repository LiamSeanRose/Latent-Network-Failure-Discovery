"""Timer arithmetic — the questions answerable by comparing two numbers.

Several of the questions PROJECT.md §1.4 files under TIMING carry a time quantity
but no event ordering: whether BFD detects a failure before or after the IGP
would have noticed anyway, whether route dampening suppresses a prefix for longer
than an SLA allows, whether two ends of a link agree on how often they will speak
and how long they will wait. All are settled by arithmetic over configured
values, which is why they live beside the discrete-event model rather than inside
it — the subject is timers, but nothing here simulates anything.

That distinction decides the tier. `model.py` produces candidates that could be
wrong because a model stands between the facts and the finding (§2.2); these
findings stand or fall on the configured numbers alone, so they carry
`Tier.FACTS` and say exactly which arithmetic produced them.

Everything reads the timer inventory, and — where a defect is only visible with
both ends of a link in hand — the L3 adjacencies and FHRP groups that say which
timer records face each other. Nothing reads a dialect, so a rule here works on
any parser that populates the same records (§5.2). A rule needing two ends stays
silent when only one is present: a device missing from the collection is an
incomplete capture, not a defect.
"""

from __future__ import annotations

import ipaddress
import itertools
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Final

from cassandra.factpack.builders.common import fhrp_instance
from cassandra.factpack.schema import (
    BfdTimers,
    BgpTimers,
    DampeningProfile,
    FhrpTimers,
    IgpHelloTimers,
    IgpProtocol,
    Milliseconds,
    Seconds,
    StaticFactPack,
    StpTimers,
    TimerSource,
    VlanId,
)
from cassandra.findings import Finding, Severity, Tier


@dataclass(frozen=True, slots=True, kw_only=True)
class Limits:
    """The thresholds a finding is measured against.

    An SLA is the user's number, not ours. The default is the shortest outage
    most people would still call an outage; a site with a tighter or looser
    commitment passes its own.

    `bfd_min_detection_ms` is the same idea applied downwards: 150ms is three
    50ms intervals, the floor most platforms document for a session the
    forwarding hardware maintains. A site running BFD in software wants a higher
    floor, and a site whose linecards genuinely offload it may want a lower one.
    """

    sla_max_suppress_s: Seconds = 300
    bfd_min_detection_ms: Milliseconds = 150


DEFAULT_LIMITS: Final = Limits()

# The IGP and every FHRP protocol are built around losing hellos without losing
# the neighbour: IS-IS defaults to a multiplier of 3, OSPF to a dead interval of
# four hellos, HSRP to a hold of 3.3 times its hello, and VRRP fixes its
# master-down interval at three advertisements. Three is not a preference, it is
# the floor every one of those defaults sits on or above, so it is not offered as
# a limit for the user to move.
MIN_HELLOS_BEFORE_DOWN: Final = 3

# BGP is built the same way, and says so: RFC 4271 clause 10 sets the KeepaliveTimer
# to a third of the negotiated hold time, which is the same three losses of
# tolerance the IGP and every FHRP protocol allow. It is the protocol's own
# arithmetic rather than a preference, so it is not offered as a limit either.
MIN_KEEPALIVES_BEFORE_DOWN: Final = 3

# IEEE 802.1D-1998 clause 8.10.2 makes the three spanning-tree timers one set rather
# than three numbers: the max age has to fit inside the two forward-delay
# intervals that follow it, and has to leave room for hellos to be missed
# before it expires. Both bounds carry a one-second allowance for propagation
# across the diameter of the network.
STP_TIMER_ALLOWANCE_MS: Final = 1000

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


# The schema spells these for machines. A finding is read by a person, who does
# not write OSPFV2 or ISIS.
_PROTOCOL_NAMES: Final[dict[IgpProtocol, str]] = {
    IgpProtocol.OSPFV2: "OSPFv2",
    IgpProtocol.OSPFV3: "OSPFv3",
    IgpProtocol.ISIS: "IS-IS",
}


def _protocol(protocol: IgpProtocol) -> str:
    return _PROTOCOL_NAMES.get(protocol, protocol.value.upper())


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


def _fhrp_line(timers: FhrpTimers) -> str:
    parts = [
        f"{_where(timers.scope.device, timers.scope.interface)}  "
        f"{timers.protocol.value} {timers.scope.instance or ''}".rstrip()
    ]
    if timers.hello_interval_ms is not None:
        parts.append(f"hello {_ms(timers.hello_interval_ms)}")
    if timers.hold_time_ms is not None:
        parts.append(f"hold {_ms(timers.hold_time_ms)}")
    return " ".join(parts)


def _bgp_line(timers: BgpTimers) -> str:
    """One BGP timer record, as the line that configured it would read.

    A peering record names the peer and says whether the numbers were written
    against it or inherited from the process, because that is what decides which
    line someone has to change.
    """
    scope = timers.scope
    head = f"{scope.device}  bgp {scope.instance or ''}".rstrip()
    if scope.neighbor:
        head = f"{head} neighbor {scope.neighbor}"
    parts = [head]
    if timers.keepalive_ms is not None:
        parts.append(f"keepalive {_ms(timers.keepalive_ms)}")
    if timers.hold_time_ms is not None:
        parts.append(f"hold {_ms(timers.hold_time_ms)}")
    if timers.graceful_restart_time_s is not None:
        parts.append(f"restart-time {_duration(timers.graceful_restart_time_s)}")
    if timers.stalepath_time_s is not None:
        parts.append(f"stalepath-time {_duration(timers.stalepath_time_s)}")
    if scope.source is TimerSource.INHERITED:
        parts.append("(inherited from the process)")
    return " ".join(parts)


def _vlan_scope(vlans: tuple[VlanId, ...]) -> str:
    """`vlan 1-100`, `vlan 10,20`, or the device-wide phrasing for no range.

    Contiguous ids are collapsed back into the range the operator wrote, because
    a finding that lists a hundred VLAN numbers is a finding nobody reads.
    """
    if not vlans:
        return "every VLAN"
    spans: list[tuple[int, int]] = []
    for vlan in sorted(set(vlans)):
        if spans and vlan == spans[-1][1] + 1:
            spans[-1] = (spans[-1][0], vlan)
        else:
            spans.append((vlan, vlan))
    return "vlan " + ",".join(
        str(low) if low == high else f"{low}-{high}" for low, high in spans
    )


def _stp_line(timers: StpTimers) -> str:
    parts = [f"{timers.scope.device}  {timers.mode.value} {_vlan_scope(timers.vlans)}"]
    if timers.hello_time_ms is not None:
        parts.append(f"hello-time {_ms(timers.hello_time_ms)}")
    if timers.forward_delay_ms is not None:
        parts.append(f"forward-time {_ms(timers.forward_delay_ms)}")
    if timers.max_age_ms is not None:
        parts.append(f"max-age {_ms(timers.max_age_ms)}")
    return " ".join(parts)


def _address(text: str) -> str:
    """One spelling per address, so two configs that wrote it differently match."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _bgp_peerings(pack: StaticFactPack) -> Iterator[tuple[BgpTimers, BgpTimers]]:
    """Timer records for the two ends of every peering wholly inside the pack.

    A peering is two one-sided statements, and only the pair says anything: the
    record on one device names an address, and the device that owns that address
    has to have a record naming an address back. A peer outside the collection —
    a transit provider, a device whose config was not gathered — yields nothing,
    because an incomplete capture is not a defect (§2.4 applies the same rule to
    a control that never ran).

    Each pair is yielded once, in device-name order, so a rule reporting on one
    does not report on it again from the other side.
    """
    owner: dict[str, str] = {
        _address(assignment.address): device.id
        for device in pack.devices
        for interface in device.interfaces
        for assignment in interface.addresses
    }
    by_device: dict[str, list[BgpTimers]] = {}
    for timers in pack.timers.bgp:
        if timers.scope.neighbor is None:
            continue
        by_device.setdefault(timers.scope.device, []).append(timers)

    for device, records in sorted(by_device.items()):
        for here in records:
            peer = owner.get(_address(here.scope.neighbor or ""))
            if peer is None or peer <= device:
                continue
            for there in by_device.get(peer, []):
                if owner.get(_address(there.scope.neighbor or "")) == device:
                    yield here, there


def _bgp_differences(
    a: BgpTimers, b: BgpTimers
) -> tuple[tuple[str, Milliseconds, Milliseconds], ...]:
    """The session timers these two ends both state and state differently.

    A value only one end has is not a disagreement: the other end is then on a
    platform default this tool does not know, and calling that a mismatch would
    invent the number it was compared against.
    """
    return tuple(
        (label, left, right)
        for label, left, right in (
            ("keepalive", a.keepalive_ms, b.keepalive_ms),
            ("hold time", a.hold_time_ms, b.hold_time_ms),
        )
        if left is not None and right is not None and left != right
    )


def _stated(timers: BgpTimers) -> str:
    """How a finding says where one end's numbers were written."""
    if timers.scope.source is TimerSource.INHERITED:
        return "inherits"
    return "states"


def _igp_index(
    pack: StaticFactPack,
) -> dict[tuple[str, str | None], list[IgpHelloTimers]]:
    """IGP timer records by the interface they were configured on."""
    index: dict[tuple[str, str | None], list[IgpHelloTimers]] = {}
    for timers in pack.timers.igp_hello:
        index.setdefault((timers.scope.device, timers.scope.interface), []).append(
            timers
        )
    return index


def _fhrp_index(
    pack: StaticFactPack,
) -> dict[tuple[str, str | None, str | None], FhrpTimers]:
    """FHRP timer records by device, interface and group number.

    `TimerScope.instance` holds the group number for this family, which is what
    joins a record to the `FhrpGroup` it belongs to — one member of one group on
    one interface, so the key is unique.
    """
    return {
        (timers.scope.device, timers.scope.interface, timers.scope.instance): timers
        for timers in pack.timers.fhrp
    }


def _hellos_before_down(hello_ms: Milliseconds, down_ms: Milliseconds) -> str:
    """How many hellos fit in a down interval, as an operator would say it."""
    return f"{down_ms / hello_ms:g}"


def _interval_differences(
    a: IgpHelloTimers, b: IgpHelloTimers
) -> tuple[tuple[str, Milliseconds, Milliseconds], ...]:
    """The named intervals these two records both state and state differently.

    A value only one end configures is not a disagreement. The other end is then
    running a platform default this tool does not know, and calling that a
    mismatch would be inventing the number it was compared against.
    """
    return tuple(
        (label, left, right)
        for label, left, right in (
            ("hello", a.hello_interval_ms, b.hello_interval_ms),
            ("dead", a.dead_interval_ms, b.dead_interval_ms),
        )
        if left is not None and right is not None and left != right
    )


def _dampening_ceiling(profile: DampeningProfile) -> float | None:
    """The largest penalty a prefix can carry, or None when a term is missing.

    `reuse * 2 ** (max-suppress / half-life)`. Max-suppress is a promise that a
    prefix is released after that long however hard it flapped, and a penalty
    halves every half-life. The only way to keep the promise is to clamp the
    penalty at the value which decays to the reuse threshold in exactly
    max-suppress, which is what implementations do — so the product is a
    ceiling no amount of flapping climbs above, and the suppress threshold has
    to sit under it to ever be reached.
    """
    if (
        profile.reuse_threshold is None
        or profile.max_suppress_s is None
        or profile.half_life_s is None
        or profile.half_life_s <= 0
    ):
        return None
    return profile.reuse_threshold * 2 ** (profile.max_suppress_s / profile.half_life_s)


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
    igp_by_interface = _igp_index(pack)
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
                f"{_protocol(timers.protocol)} dead interval ({_ms(dead)})",
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


@rule
def ospf_timers_disagree_across_a_subnet(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """OSPF refuses an adjacency whose hello and dead intervals do not match.

    Both values ride in every hello packet and both are checked on receipt, so a
    disagreement is not a slower adjacency, it is no adjacency. Each device reads
    perfectly well on its own — the defect exists only in the pair — and nothing
    alarms about a neighbour it never had, so this survives change windows that
    look successful from either console.

    IS-IS is deliberately excluded. It advertises its own hold time inside each
    hello and the receiver honours what it is told, so two IS-IS routers on one
    wire need not agree on anything here, and reporting the difference would be
    reporting the protocol working as designed.

    Silent unless both ends state the same interval and state it differently. One
    end configured and the other left on its platform default is a comparison
    against a number this tool does not have.
    """
    del limits
    index = _igp_index(pack)
    for adjacency in pack.l3_adjacencies:
        records = [
            timers
            for ref in adjacency.members
            for timers in index.get((ref.device, ref.interface), ())
            if timers.protocol is not IgpProtocol.ISIS
        ]
        for a, b in itertools.combinations(records, 2):
            if a.scope.device == b.scope.device or a.protocol is not b.protocol:
                continue
            differences = _interval_differences(a, b)
            if not differences:
                continue
            summary = ", ".join(
                f"{label} {_ms(left)} against {_ms(right)}"
                for label, left, right in differences
            )
            here = _where(a.scope.device, a.scope.interface)
            there = _where(b.scope.device, b.scope.interface)
            yield Finding(
                rule="ospf-timers-disagree",
                tier=Tier.FACTS,
                severity=Severity.HIGH,
                device=a.scope.device,
                title=f"{_protocol(a.protocol)} timers on {here} and {there} "
                f"disagree across {adjacency.prefix}",
                detail=f"{summary}. Both values are carried in every hello and "
                f"checked by the receiver, so the two never reach a full "
                f"adjacency and neither device reports losing a neighbour it "
                f"never had. Whatever routes over {adjacency.prefix} is "
                f"reaching its destination another way, or not at all.",
                evidence=(_igp_line(a), _igp_line(b)),
                remedy=f"make the hello and dead intervals identical on both "
                f"ends of {adjacency.prefix}",
            )


@rule
def igp_dead_interval_leaves_too_few_hellos(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """A dead interval worth fewer than three hellos drops healthy adjacencies.

    The ratio, not the interval, is what buys tolerance: every default in the
    business — four hellos for OSPF, three for IS-IS — exists so that a lost
    packet costs a retransmission rather than a reconvergence. Below three, one
    dropped hello and ordinary jitter are enough to tear down an adjacency that
    was never broken, and the SPF run, the route churn and the traffic loss that
    follow are all caused by the timer rather than by any fault.

    Silent when only one of the two numbers is configured, because the ratio
    cannot be computed from a value nobody wrote down.
    """
    del limits
    for timers in pack.timers.igp_hello:
        hello = timers.hello_interval_ms
        down = igp_dead_ms(timers)
        if hello is None or hello <= 0 or down is None:
            continue
        if down >= hello * MIN_HELLOS_BEFORE_DOWN:
            continue
        where = _where(timers.scope.device, timers.scope.interface)
        yield Finding(
            rule="igp-dead-under-three-hellos",
            tier=Tier.FACTS,
            severity=Severity.MEDIUM,
            device=timers.scope.device,
            title=f"{_protocol(timers.protocol)} on {where} gives up after "
            f"{_hellos_before_down(hello, down)} hellos",
            detail=f"the adjacency drops after {_ms(down)} of silence while "
            f"hellos are sent every {_ms(hello)}, so fewer than "
            f"{MIN_HELLOS_BEFORE_DOWN} may be lost before the neighbour is "
            f"declared dead. Every default in this space allows at least "
            f"{MIN_HELLOS_BEFORE_DOWN} for the reason that transient loss is "
            f"normal and reconvergence is expensive.",
            trigger=f"a single lost hello on {where}",
            evidence=(_igp_line(timers),),
            remedy=f"raise the dead interval to at least "
            f"{_ms(hello * MIN_HELLOS_BEFORE_DOWN)}, or lower the hello "
            f"interval to keep the detection time and regain the margin",
        )


@rule
def igp_dead_interval_is_not_a_multiple_of_the_hello(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """A dead interval that is not a whole number of hellos wastes its remainder.

    Adjacency loss is only ever detected on a hello that does not arrive, so the
    part of the dead interval past the last whole hello is time in which nothing
    can be learned. A router configured `hello 10` and `dead 35` tolerates three
    lost hellos, exactly as `dead 30` would, and then waits five more seconds
    before acting on it.

    Reported as low because nothing fails: the adjacency works and the detection
    time is merely not the one the ratio implies. It is almost always a typo in
    one of the two numbers, which is worth seeing before someone tunes the other
    one to match it.

    Silent below three hellos, where the ratio itself is the defect and
    `igp-dead-under-three-hellos` says so instead.
    """
    del limits
    for timers in pack.timers.igp_hello:
        hello = timers.hello_interval_ms
        down = igp_dead_ms(timers)
        if hello is None or hello <= 0 or down is None:
            continue
        remainder = down % hello
        if remainder == 0 or down < hello * MIN_HELLOS_BEFORE_DOWN:
            continue
        whole = down // hello
        where = _where(timers.scope.device, timers.scope.interface)
        yield Finding(
            rule="igp-dead-not-a-multiple-of-hello",
            tier=Tier.FACTS,
            severity=Severity.LOW,
            device=timers.scope.device,
            title=f"{_protocol(timers.protocol)} on {where} waits {_ms(down)} "
            f"for hellos sent every {_ms(hello)}",
            detail=f"that is {whole} whole hellos and {_ms(remainder)} in which "
            f"no further hello is due, so the adjacency tolerates the same "
            f"{whole} losses a dead interval of {_ms(hello * whole)} would and "
            f"detects the failure {_ms(remainder)} later. One of the two "
            f"numbers is not the one that was meant.",
            evidence=(_igp_line(timers),),
            remedy=f"set the dead interval to a whole multiple of the hello — "
            f"{_ms(hello * whole)} keeps the current tolerance, "
            f"{_ms(hello * (whole + 1))} keeps the current detection time",
        )


@rule
def bfd_detection_is_below_the_safe_floor(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """A BFD session too fast to survive a control-plane pause takes the IGP down.

    BFD failing over in tens of milliseconds is only useful if nothing else on
    the box ever stops for that long. A supervisor switchover, a software
    upgrade, a route-processor spike or a large table churn all pause packet
    handling for longer than a handful of milliseconds, and the session that
    notices drops every client protocol registered against it. The outage is
    manufactured by the detection rather than found by it, and it recurs on
    exactly the maintenance events that were supposed to be non-disruptive.

    The floor is `Limits.bfd_min_detection_ms`, so a site whose platform genuinely
    maintains the session in forwarding hardware can lower it.

    Silent when either the interval or the multiplier is unconfigured — the
    detection time is then a platform default this tool refuses to guess.
    """
    for session in pack.timers.bfd:
        detection = bfd_detection_ms(session)
        if detection is None or detection >= limits.bfd_min_detection_ms:
            continue
        where = _where(session.scope.device, session.scope.interface)
        yield Finding(
            rule="bfd-detection-below-floor",
            tier=Tier.FACTS,
            severity=Severity.MEDIUM,
            device=session.scope.device,
            title=f"BFD on {where} declares the neighbour down after {_ms(detection)}",
            detail=f"{session.desired_min_tx_ms}ms x "
            f"{session.detect_multiplier} = {_ms(detection)}, under the "
            f"{_ms(limits.bfd_min_detection_ms)} a session is expected to "
            f"survive an ordinary control-plane pause at. Anything that stops "
            f"packet handling for longer than that — a supervisor switchover, "
            f"an upgrade, a CPU spike — drops the session and every protocol "
            f"registered against it, on a link that never failed.",
            trigger=f"any control-plane pause on either end of {where} longer "
            f"than {_ms(detection)}",
            evidence=(_bfd_line(session),),
            remedy=f"raise the interval or the multiplier so detection is at "
            f"least {_ms(limits.bfd_min_detection_ms)}",
        )


@rule
def bfd_multiplier_leaves_no_margin(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """A detect multiplier of 1 makes one lost packet a routing event.

    The multiplier is the whole tolerance a BFD session has: it is how many
    control packets may go missing before the neighbour is declared down. At 1
    there is none. A single frame lost to a CRC error, a microburst drop or a
    queue overrun tears down the session and every client protocol registered
    against it, and does it again the next time — which on a link with any loss
    at all is a permanently flapping adjacency whose interface counters look
    clean.

    Silent when no multiplier is configured, since the platform default is not a
    number this tool invents.
    """
    del limits
    for session in pack.timers.bfd:
        if session.detect_multiplier != 1:
            continue
        where = _where(session.scope.device, session.scope.interface)
        interval = (
            f" every {_ms(session.desired_min_tx_ms)}"
            if session.desired_min_tx_ms is not None
            else ""
        )
        yield Finding(
            rule="bfd-multiplier-of-one",
            tier=Tier.FACTS,
            severity=Severity.HIGH,
            device=session.scope.device,
            title=f"BFD on {where} has a detect multiplier of 1",
            detail=f"control packets are sent{interval} and exactly one may not "
            f"arrive before the session is declared down, so a single dropped "
            f"frame is a routing event. Packet loss that would otherwise be "
            f"invisible becomes a reconvergence, repeatedly.",
            trigger=f"one lost BFD control packet on {where}",
            evidence=(_bfd_line(session),),
            remedy="set the detect multiplier to 3, the value every platform "
            "defaults to, and shorten the interval instead if the detection "
            "time has to stay where it is",
        )


@rule
def fhrp_hold_time_leaves_too_few_hellos(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """An FHRP hold time worth fewer than three hellos fails the gateway over on
    one lost advertisement.

    A standby that gives up after two advertisements is one dropped frame away
    from taking the virtual address, and on a group with preempt configured it
    hands it straight back — so the cost is not one failover but a pair of them,
    plus whatever the ARP caches on the segment do in between. HSRP's own
    default holds for 3.3 hellos and VRRP fixes its master-down interval at
    three advertisements, for exactly this reason.

    Silent when the hold time is not in the fact pack: VRRP on some platforms
    states only the advertisement interval and derives the rest, and a hold time
    this tool did not read is not a hold time it can measure.
    """
    del limits
    for timers in pack.timers.fhrp:
        hello = timers.hello_interval_ms
        hold = timers.hold_time_ms
        if hello is None or hello <= 0 or hold is None:
            continue
        if hold >= hello * MIN_HELLOS_BEFORE_DOWN:
            continue
        where = _where(timers.scope.device, timers.scope.interface)
        group = f"{timers.protocol.value} {timers.scope.instance}"
        yield Finding(
            rule="fhrp-hold-under-three-hellos",
            tier=Tier.FACTS,
            severity=Severity.MEDIUM,
            device=timers.scope.device,
            title=f"{group} on {where} holds for only "
            f"{_hellos_before_down(hello, hold)} hellos",
            detail=f"advertisements are sent every {_ms(hello)} and the group "
            f"declares the active gone after {_ms(hold)}, so fewer than "
            f"{MIN_HELLOS_BEFORE_DOWN} may be lost before the standby claims "
            f"the virtual address. Every default in this space allows at least "
            f"{MIN_HELLOS_BEFORE_DOWN}, because a gateway that moves on one "
            f"dropped frame moves for no reason.",
            trigger=f"a single lost advertisement on {where}",
            evidence=(_fhrp_line(timers),),
            remedy=f"raise the hold time to at least "
            f"{_ms(hello * MIN_HELLOS_BEFORE_DOWN)}, or lower the hello "
            f"interval to keep the failover time and regain the margin",
        )


@rule
def fhrp_hold_time_is_shorter_than_a_peer_hello(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """A member that gives up before its peer is next due to speak is not a
    standby, it is a second active gateway.

    FHRP timers have to match across a group, and the way a mismatch bites is
    arithmetical: if one member's hold time is no longer than another member's
    advertisement interval, the on-time advertisement arrives after the timer it
    was meant to reset has already expired. The member takes the virtual address
    while the peer still holds it, both answer for the same IP and MAC, and the
    segment gets duplicate replies until something flaps. Each device on its own
    is configured with a hold longer than its own hello, so the defect is
    invisible one config at a time.

    Silent when only one member of the group is in the collection, and silent for
    timers that merely differ — mismatched values whose arithmetic still works
    are untidy, not broken.
    """
    del limits
    index = _fhrp_index(pack)
    for group in pack.fhrp_groups:
        members = [
            (member, timers)
            for member in group.members
            if (
                timers := index.get(
                    (
                        member.device,
                        member.interface,
                        fhrp_instance(group.group_number, group.family),
                    )
                )
            )
            is not None
        ]
        for (here, a), (there, b) in itertools.permutations(members, 2):
            if here.device == there.device:
                continue
            if a.hold_time_ms is None or b.hello_interval_ms is None:
                continue
            if a.hold_time_ms > b.hello_interval_ms:
                continue
            virtual = group.virtual_address or "the virtual address"
            yield Finding(
                rule="fhrp-hold-under-peer-hello",
                tier=Tier.FACTS,
                severity=Severity.HIGH,
                device=here.device,
                title=f"{group.id}: {here.device} holds for "
                f"{_ms(a.hold_time_ms)} while {there.device} advertises every "
                f"{_ms(b.hello_interval_ms)}",
                detail=f"{here.device} declares the group's active gone after "
                f"{_ms(a.hold_time_ms)}, which is no later than "
                f"{there.device}'s next advertisement is due. When "
                f"{there.device} is holding the group, every advertisement it "
                f"sends arrives after {here.device} has already timed it out, "
                f"so both answer for {virtual} at once.",
                trigger=f"{there.device} holding {group.id}",
                evidence=(_fhrp_line(a), _fhrp_line(b)),
                remedy=f"configure the same hello and hold time on every member "
                f"of {group.id}",
            )


@rule
def dampening_can_never_suppress(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """A dampening profile whose suppress threshold is above its own penalty
    ceiling never suppresses anything.

    The four values are not independent. A penalty halves every half-life and is
    abandoned altogether after max-suppress, so the most a prefix can ever
    accumulate is `reuse x 2 ^ (max-suppress / half-life)`. Set the suppress
    threshold above that and no amount of flapping reaches it: the profile is
    configured, shows up in review, is believed to be protecting the RIB, and
    does nothing at all.

    This is the opposite failure to `dampening-exceeds-sla` and they cannot both
    be true of one profile. That one reports dampening that holds a prefix down
    too long; this one reports dampening that was never going to hold anything.

    Silent when any of the four values is absent, since the ceiling is a product
    of all of them.
    """
    del limits
    for profile in pack.timers.dampening:
        ceiling = _dampening_ceiling(profile)
        if ceiling is None or profile.suppress_threshold is None:
            continue
        if profile.suppress_threshold <= ceiling:
            continue
        yield Finding(
            rule="dampening-never-suppresses",
            tier=Tier.FACTS,
            severity=Severity.MEDIUM,
            device=profile.scope.device,
            title=f"{profile.kind.value} dampening on {profile.scope.device} "
            f"can never reach its suppress threshold",
            detail=f"a penalty cannot exceed {profile.reuse_threshold} x 2 ^ "
            f"({profile.max_suppress_s}s / {profile.half_life_s}s) = "
            f"{ceiling:,.0f}, and suppression begins at "
            f"{profile.suppress_threshold}. No sequence of flaps reaches that "
            f"number, so no prefix is ever dampened and the protection the "
            f"profile appears to provide does not exist.",
            evidence=(_dampening_line(profile),),
            remedy=f"lower the suppress threshold below {ceiling:,.0f}, or "
            f"raise max-suppress-time or the reuse threshold until the ceiling "
            f"clears it",
        )


@rule
def bgp_hold_time_leaves_too_few_keepalives(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """A BGP hold time worth fewer than three keepalives drops healthy sessions.

    RFC 4271 clause 10 has the session send a keepalive every third of the hold time
    precisely so that two may go missing and the peering survives. Configure the
    hold below three keepalives and that margin is gone: one keepalive lost to a
    control-plane pause, a policy push or ordinary queueing takes the session
    down, every prefix it carried is withdrawn, and the reconvergence that
    follows was caused by the timer rather than by anything failing. It comes
    back, so the only evidence left is a flap counter.

    Both scopes are checked. A process-wide `timers bgp` sets this for every
    peering that does not override it, and a peering that does override it can
    get it wrong on its own. A peering that inherits is not reported again — the
    numbers are the process's, the process record already carries them, and one
    line wrongly configured should produce one finding rather than one per peer
    that happens to be on it.

    Silent when either number is missing, and silent when the hold time is zero
    — that is the documented way to turn keepalives off altogether, which is a
    different decision with different consequences and not this rule's subject.
    """
    del limits
    for timers in pack.timers.bgp:
        if timers.scope.source is TimerSource.INHERITED:
            continue
        keepalive = timers.keepalive_ms
        hold = timers.hold_time_ms
        if keepalive is None or hold is None or keepalive <= 0 or hold <= 0:
            continue
        if hold >= keepalive * MIN_KEEPALIVES_BEFORE_DOWN:
            continue
        where = timers.scope.neighbor or timers.scope.device
        subject = (
            f"the peering with {timers.scope.neighbor}"
            if timers.scope.neighbor
            else f"every peering of AS {timers.scope.instance}"
        )
        yield Finding(
            rule="bgp-hold-under-three-keepalives",
            tier=Tier.FACTS,
            severity=Severity.MEDIUM,
            device=timers.scope.device,
            title=f"BGP on {timers.scope.device} holds {subject} for only "
            f"{_hellos_before_down(keepalive, hold)} keepalives",
            detail=f"keepalives are sent every {_ms(keepalive)} and the session "
            f"is torn down after {_ms(hold)} of silence, so fewer than "
            f"{MIN_KEEPALIVES_BEFORE_DOWN} may be lost before every prefix the "
            f"peering carries is withdrawn. RFC 4271 derives the keepalive "
            f"interval from the hold time as a third of it for exactly this "
            f"margin, and it is not here.",
            trigger=f"a single lost keepalive on the session with {where}",
            evidence=(_bgp_line(timers),),
            remedy=f"raise the hold time to at least "
            f"{_ms(keepalive * MIN_KEEPALIVES_BEFORE_DOWN)}, or lower the "
            f"keepalive interval to keep the detection time and regain the "
            f"margin",
        )


@rule
def bgp_timers_disagree_across_a_peering(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """Two ends of a peering that asked for different session timing.

    BGP does not refuse the session over this — it negotiates, and RFC 4271
    clause 4.2 makes the hold time the smaller of the two values offered — which is
    what makes it worth reporting rather than obvious. Nothing alarms, nothing
    logs, and the end that asked for the longer hold silently runs the shorter
    one. Every number derived from it downstream is then wrong on that end: the
    convergence budget, the comparison against a BFD session covering the same
    path, the length of a maintenance window somebody believed the session would
    survive.

    The finding names which end stated its values on the peering and which end
    inherited them from `timers bgp` on the process, because those are different
    lines to change and only one of them affects the other peerings too.

    Reported low. The session comes up, carries traffic and stays up; what is
    wrong is a belief, not the network. Silent when only one end of the peering
    is in the collection, and silent for a value only one end states — the other
    is then on a platform default this tool will not guess at.
    """
    del limits
    for here, there in _bgp_peerings(pack):
        differences = _bgp_differences(here, there)
        if not differences:
            continue
        summary = ", ".join(
            f"{label} {_ms(left)} against {_ms(right)}"
            for label, left, right in differences
        )
        effective = min(
            value
            for value in (here.hold_time_ms, there.hold_time_ms)
            if value is not None
        )
        yield Finding(
            rule="bgp-timers-disagree",
            tier=Tier.FACTS,
            severity=Severity.LOW,
            device=here.scope.device,
            title=f"BGP timers on the {here.scope.device} to "
            f"{there.scope.device} peering disagree",
            detail=f"{summary}. The session negotiates the smaller hold time, "
            f"so both ends run {_ms(effective)} whatever they asked for, and "
            f"the end that configured the longer one is not getting it. "
            f"{here.scope.device} {_stated(here)} its values and "
            f"{there.scope.device} {_stated(there)} its own.",
            evidence=(_bgp_line(here), _bgp_line(there)),
            remedy=f"configure the same keepalive and hold time on both ends of "
            f"the {here.scope.device} to {there.scope.device} peering, or "
            f"accept {_ms(effective)} and write it down on both",
        )


@rule
def graceful_restart_outlives_the_stalepath_timer(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """A router that waits longer for a restarting peer than it will hold that
    peer's routes.

    The two timers are one mechanism. `restart-time` is how long the router is
    willing to wait for a graceful-restart-capable peer to come back before
    treating the session as genuinely gone; `stalepath-time` is how long it will
    keep that peer's paths marked stale while it waits. Set the stalepath timer
    shorter and the router deletes the routes it was waiting to reuse, part-way
    through a restart it had already decided to tolerate — so the restart is
    graceful for the first part of the window and a full withdrawal for the
    rest, which is the outage graceful restart was configured to prevent.

    The failure is invisible from steady state and from either timer alone. Both
    are configured, both look reasonable, and the traffic loss only happens when
    a restart runs longer than the shorter of the two.

    Silent when either timer is absent. Every platform defaults the pair to a
    combination that satisfies this, so a config stating neither is not
    configured wrongly — it is not configured at all, and inventing the defaults
    to check them against each other would be checking this tool's memory.
    """
    del limits
    for timers in pack.timers.bgp:
        restart = timers.graceful_restart_time_s
        stalepath = timers.stalepath_time_s
        if restart is None or stalepath is None or stalepath >= restart:
            continue
        yield Finding(
            rule="bgp-stalepath-under-restart-time",
            tier=Tier.FACTS,
            severity=Severity.MEDIUM,
            device=timers.scope.device,
            title=f"graceful restart on {timers.scope.device} waits "
            f"{_duration(restart)} for a peer whose routes it keeps for "
            f"{_duration(stalepath)}",
            detail=f"stale paths from a restarting peer are deleted after "
            f"{_duration(stalepath)}, and the session is given "
            f"{_duration(restart)} to come back. A restart that takes longer "
            f"than {_duration(stalepath)} therefore loses the routes graceful "
            f"restart exists to preserve, for the "
            f"{_duration(restart - stalepath)} between the two timers, while "
            f"the router is still waiting rather than reconverging.",
            trigger=f"a peer restart lasting longer than {_duration(stalepath)}",
            evidence=(_bgp_line(timers),),
            remedy=f"raise stalepath-time above {_duration(restart)}, or lower "
            f"restart-time to {_duration(stalepath)} so the router stops "
            f"waiting when it stops holding",
        )


@rule
def stp_timers_break_the_standard_relationship(
    pack: StaticFactPack, limits: Limits
) -> Iterator[Finding]:
    """Spanning-tree timers that the standard's own inequalities reject.

    IEEE 802.1D-1998 clause 8.10.2 does not treat the three timers as independent
    knobs. It requires `2 x (forward delay - 1s) >= max age` and
    `max age >= 2 x (hello time + 1s)`, and each bound protects against a
    different failure. Break the first and a port can finish listening and
    learning and start forwarding while a stale topology somewhere else in the
    network has not yet aged out — a forwarding loop, on a broadcast domain,
    which is the failure mode that takes a whole site down rather than a link.
    Break the second and a bridge ages out a root it is still hearing from,
    reconverging the tree over ordinary packet loss.

    The timers a VLAN runs are the root bridge's, not each bridge's own, so this
    is reported medium rather than high: it takes this device winning the
    election for its numbers to govern anything. That is also exactly why it
    survives review — the values are harmless while some other bridge is root,
    and become the network's the moment that bridge is replaced or reloaded.

    Silent unless all three timers are stated for the same scope. The standard's
    defaults satisfy both inequalities, and filling an unstated timer in from
    them would be checking a value this tool supplied rather than one the
    operator did.
    """
    del limits
    for timers in pack.timers.stp:
        hello = timers.hello_time_ms
        forward = timers.forward_delay_ms
        max_age = timers.max_age_ms
        if hello is None or forward is None or max_age is None:
            continue
        forward_bound = 2 * (forward - STP_TIMER_ALLOWANCE_MS)
        hello_bound = 2 * (hello + STP_TIMER_ALLOWANCE_MS)
        broken = []
        if max_age > forward_bound:
            broken.append(
                f"a max age of {_ms(max_age)} needs a forward delay of at least "
                f"{_ms(max_age // 2 + STP_TIMER_ALLOWANCE_MS)}, not {_ms(forward)}"
            )
        if max_age < hello_bound:
            broken.append(
                f"a hello time of {_ms(hello)} needs a max age of at least "
                f"{_ms(hello_bound)}, not {_ms(max_age)}"
            )
        if not broken:
            continue
        scope = _vlan_scope(timers.vlans)
        yield Finding(
            rule="stp-timers-outside-the-standard",
            tier=Tier.FACTS,
            severity=Severity.MEDIUM,
            device=timers.scope.device,
            title=f"spanning-tree timers on {timers.scope.device} for {scope} "
            f"break the relationship the standard requires",
            detail=f"{'; and '.join(broken)}. IEEE 802.1D ties the three "
            f"together so that a port cannot begin forwarding before stale "
            f"information elsewhere has aged out, and so that a bridge cannot "
            f"age out a root it is still hearing from. These values are the "
            f"whole network's whenever {timers.scope.device} is the root "
            f"bridge for {scope}.",
            trigger=f"{timers.scope.device} winning the root election for {scope}",
            evidence=(_stp_line(timers),),
            remedy="set the three timers as one set — the standard's own "
            "2s / 15s / 20s satisfies both bounds, and any tuning has to keep "
            "them satisfied",
        )


def analyse(pack: StaticFactPack, *, limits: Limits = DEFAULT_LIMITS) -> list[Finding]:
    return [finding for rule_fn in RULES for finding in rule_fn(pack, limits)]
