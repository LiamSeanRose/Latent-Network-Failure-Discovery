"""Timer arithmetic, in both directions.

Every rule here gets a configuration that must produce it and a neighbouring one
that must not. A rule that only ever fires is indistinguishable from a rule that
always fires, and the second kind is what makes a tool unusable.

The pack is assembled from parsed config text rather than hand-built dataclasses
wherever possible, so a parser that stops producing a timer breaks these tests
rather than quietly emptying the analysis.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.builders.eos import parse_device
from cassandra.factpack.schema import (
    BfdTimers,
    DampeningKind,
    DampeningProfile,
    FactPackMeta,
    IgpHelloTimers,
    IgpProtocol,
    StaticFactPack,
    TimerInventory,
    TimerScope,
    TimerSource,
)
from cassandra.findings import Severity, Tier
from cassandra.timing.timer_rules import (
    Limits,
    analyse,
    bfd_detection_ms,
    igp_dead_ms,
)

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)

# A routed uplink is the shape both BFD rules care about: one interface, one
# adjacency, and whatever protocols choose to lean on it.
UPLINK: Final = """hostname agg-a
interface Ethernet1
   no switchport
   ip address 10.0.0.1/31
{extra}"""


DAMPENED: Final = "hostname agg-a\nrouter bgp 65001\n   bgp dampening {profile}\n"
WIDE: Final = "half-life 15 reuse 750 suppress 2000 max-suppress-time 60"
NARROW: Final = "half-life 1 reuse 750 suppress 2000 max-suppress-time 4"


def pack_from(text: str, *, device_id: str = "agg-a") -> StaticFactPack:
    """Parse one config and carry every timer family it produced into a pack."""
    parsed = parse_device(text, device_id=device_id)
    return StaticFactPack(
        meta=FactPackMeta(
            fact_pack_id="fp_test",
            schema_version=1,
            config_digest="0" * 64,
            source_snapshot="test",
            generated_at=datetime.now(UTC),
            device_count=1,
        ),
        devices=(parsed.device,),
        timers=TimerInventory(
            fhrp=parsed.timers,
            bfd=parsed.bfd,
            igp_hello=parsed.igp_hello,
            dampening=parsed.dampening,
        ),
    )


def uplink(*lines: str) -> StaticFactPack:
    return pack_from(UPLINK.format(extra="".join(f"   {line}\n" for line in lines)))


def rules_fired(pack: StaticFactPack, **kwargs: object) -> set[str]:
    return {finding.rule for finding in analyse(pack, **kwargs)}  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# The arithmetic itself
# --------------------------------------------------------------------------


def test_bfd_detection_is_interval_times_multiplier() -> None:
    scope = TimerScope(device="agg-a", interface="Ethernet1")
    session = BfdTimers(
        scope=scope,
        desired_min_tx_ms=300,
        required_min_rx_ms=300,
        detect_multiplier=3,
    )
    assert bfd_detection_ms(session) == 900


def test_bfd_detection_is_unknown_without_both_halves() -> None:
    scope = TimerScope(device="agg-a", interface="Ethernet1")
    assert bfd_detection_ms(BfdTimers(scope=scope, desired_min_tx_ms=300)) is None
    assert bfd_detection_ms(BfdTimers(scope=scope, detect_multiplier=3)) is None


def test_igp_dead_prefers_the_configured_value_then_the_product() -> None:
    scope = TimerScope(device="agg-a", interface="Ethernet1")
    ospf = IgpHelloTimers(
        scope=scope,
        protocol=IgpProtocol.OSPFV2,
        hello_interval_ms=10_000,
        dead_interval_ms=40_000,
    )
    assert igp_dead_ms(ospf) == 40_000

    isis = IgpHelloTimers(
        scope=scope,
        protocol=IgpProtocol.ISIS,
        hello_interval_ms=3_000,
        hello_multiplier=3,
    )
    assert igp_dead_ms(isis) == 9_000


def test_igp_dead_is_never_invented() -> None:
    """A hello interval alone is not a dead interval, and guessing one would make
    every finding downstream a guess too."""
    bare = IgpHelloTimers(
        scope=TimerScope(device="agg-a", interface="Ethernet1"),
        protocol=IgpProtocol.OSPFV2,
        hello_interval_ms=10_000,
    )
    assert igp_dead_ms(bare) is None


# --------------------------------------------------------------------------
# BFD slower than the IGP
# --------------------------------------------------------------------------


def test_bfd_slower_than_the_ospf_dead_interval_is_reported() -> None:
    pack = uplink(
        "bfd interval 15000 min_rx 15000 multiplier 3",
        "ip ospf bfd",
        "ip ospf hello-interval 10",
        "ip ospf dead-interval 40",
    )
    assert "bfd-no-faster-than-igp" in rules_fired(pack)


def test_fast_bfd_alongside_the_same_igp_is_silent() -> None:
    pack = uplink(
        "bfd interval 300 min_rx 300 multiplier 3",
        "ip ospf bfd",
        "ip ospf hello-interval 10",
        "ip ospf dead-interval 40",
    )
    assert rules_fired(pack) == set()


def test_bfd_exactly_equal_to_the_dead_interval_still_accelerates_nothing() -> None:
    pack = uplink(
        "bfd interval 10000 min_rx 10000 multiplier 4",
        "ip ospf bfd",
        "ip ospf dead-interval 40",
    )
    assert "bfd-no-faster-than-igp" in rules_fired(pack)


def test_isis_hold_time_comes_from_hello_times_multiplier() -> None:
    pack = uplink(
        "bfd interval 5000 min_rx 5000 multiplier 3",
        "isis bfd",
        "isis hello-interval 3",
        "isis hello-multiplier 3",
    )
    assert "bfd-no-faster-than-igp" in rules_fired(pack)


def test_no_igp_on_the_interface_means_nothing_to_compare_against() -> None:
    """Silence over a guess: without a configured dead interval there is no
    second number, and inventing one would fabricate the finding."""
    pack = uplink(
        "bfd interval 15000 min_rx 15000 multiplier 3",
        "ip ospf bfd",
        "ip ospf hello-interval 10",
    )
    assert "bfd-no-faster-than-igp" not in rules_fired(pack)


def test_the_finding_names_both_numbers_it_compared() -> None:
    pack = uplink(
        "bfd interval 15000 min_rx 15000 multiplier 3",
        "ip ospf bfd",
        "ip ospf dead-interval 40",
    )
    finding = next(f for f in analyse(pack) if f.rule == "bfd-no-faster-than-igp")
    assert "45s" in finding.title and "40s" in finding.title
    assert any("bfd interval 15000" in line for line in finding.evidence)
    assert any("dead 40s" in line for line in finding.evidence)


# --------------------------------------------------------------------------
# BFD with nothing registered against it
# --------------------------------------------------------------------------


def test_bfd_without_a_client_is_reported() -> None:
    pack = uplink("bfd interval 300 min_rx 300 multiplier 3")
    assert "bfd-no-clients" in rules_fired(pack)


def test_an_ospf_client_on_the_interface_silences_it() -> None:
    pack = uplink("bfd interval 300 min_rx 300 multiplier 3", "ip ospf bfd")
    assert "bfd-no-clients" not in rules_fired(pack)


def test_a_bgp_peer_in_the_subnet_counts_as_a_client() -> None:
    """BGP registers by peer address, not by interface name. A session the peer
    sits on top of has a client even though no interface line says so."""
    text = UPLINK.format(extra="   bfd interval 300 min_rx 300 multiplier 3\n") + (
        "router bgp 65001\n   neighbor 10.0.0.0 bfd\n"
    )
    pack = pack_from(text)
    session = pack.timers.bfd[0]
    assert session.clients == ("bgp",)
    assert "bfd-no-clients" not in rules_fired(pack)


def test_a_bgp_peer_in_a_different_subnet_does_not() -> None:
    text = UPLINK.format(extra="   bfd interval 300 min_rx 300 multiplier 3\n") + (
        "router bgp 65001\n   neighbor 192.0.2.7 bfd\n"
    )
    assert "bfd-no-clients" in rules_fired(pack_from(text))


def test_a_session_with_no_clients_and_no_timers_still_reports() -> None:
    """Detection time is unknown, but 'nothing is listening' does not depend on
    it — the finding drops the number rather than the finding."""
    pack = StaticFactPack(
        meta=FactPackMeta(
            fact_pack_id="fp_test",
            schema_version=1,
            config_digest="0" * 64,
            source_snapshot="test",
            generated_at=datetime.now(UTC),
        ),
        timers=TimerInventory(
            bfd=(BfdTimers(scope=TimerScope(device="agg-a", interface="Ethernet1")),)
        ),
    )
    finding = next(f for f in analyse(pack) if f.rule == "bfd-no-clients")
    assert "Ethernet1" in finding.title


# --------------------------------------------------------------------------
# Dampening against the SLA
# --------------------------------------------------------------------------


def test_dampening_longer_than_the_sla_is_reported() -> None:
    pack = pack_from(DAMPENED.format(profile=WIDE))
    assert pack.timers.dampening[0].max_suppress_s == 3600
    assert "dampening-exceeds-sla" in rules_fired(pack)


def test_dampening_inside_the_sla_is_silent() -> None:
    pack = pack_from(DAMPENED.format(profile=NARROW))
    assert pack.timers.dampening[0].max_suppress_s == 240
    assert rules_fired(pack) == set()


def test_bare_dampening_inherits_an_hour_long_window() -> None:
    """`bgp dampening` with no arguments is the common case and the worst one."""
    pack = pack_from("hostname agg-a\nrouter bgp 65001\n   bgp dampening\n")
    finding = next(f for f in analyse(pack) if f.rule == "dampening-exceeds-sla")
    assert finding.severity is Severity.HIGH
    assert "inherited" in finding.detail


def test_the_sla_is_the_users_number() -> None:
    pack = pack_from(DAMPENED.format(profile=NARROW))
    assert rules_fired(pack) == set()
    assert "dampening-exceeds-sla" in rules_fired(
        pack, limits=Limits(sla_max_suppress_s=60)
    )


def test_a_profile_without_a_max_suppress_is_not_guessed_at() -> None:
    pack = StaticFactPack(
        meta=FactPackMeta(
            fact_pack_id="fp_test",
            schema_version=1,
            config_digest="0" * 64,
            source_snapshot="test",
            generated_at=datetime.now(UTC),
        ),
        timers=TimerInventory(
            dampening=(
                DampeningProfile(
                    scope=TimerScope(
                        device="agg-a", source=TimerSource.CONFIGURED, instance="65001"
                    ),
                    kind=DampeningKind.BGP_ROUTE,
                    half_life_s=900,
                ),
            )
        ),
    )
    assert rules_fired(pack) == set()


# --------------------------------------------------------------------------
# Shape of the output
# --------------------------------------------------------------------------


def test_every_finding_carries_a_remedy_and_its_evidence() -> None:
    """A finding the user cannot act on is noise (PROJECT.md §5.4)."""
    text = (
        UPLINK.format(
            extra="   bfd interval 15000 min_rx 15000 multiplier 3\n"
            "   ip ospf dead-interval 40\n"
        )
        + "router bgp 65001\n   bgp dampening\n"
    )
    findings = analyse(pack_from(text))
    assert {f.rule for f in findings} == {
        "bfd-no-faster-than-igp",
        "bfd-no-clients",
        "dampening-exceeds-sla",
    }
    for finding in findings:
        assert finding.remedy, f"{finding.rule} has no remedy"
        assert finding.evidence, f"{finding.rule} has no evidence"
        assert finding.device
        assert finding.detail


def test_these_are_certain_rather_than_modelled() -> None:
    """Arithmetic over configured values needs no timing model, so nothing here
    carries the caveat that the TIMING tier's model-derived findings do (§2.2)."""
    text = (
        UPLINK.format(
            extra="   bfd interval 15000 min_rx 15000 multiplier 3\n"
            "   ip ospf dead-interval 40\n"
        )
        + "router bgp 65001\n   bgp dampening\n"
    )
    findings = analyse(pack_from(text))
    assert findings
    assert all(f.tier is Tier.FACTS for f in findings)


def test_silent_on_a_corpus_with_no_bfd_and_no_dampening() -> None:
    """The strongest silence test available: real configs, no invented timers."""
    pack, _ = build_fact_pack(CORPUS)
    assert analyse(pack) == []


@pytest.mark.parametrize("multiplier", [1, 3, 5])
def test_multiplier_scales_detection_linearly(multiplier: int) -> None:
    session = BfdTimers(
        scope=TimerScope(device="agg-a", interface="Ethernet1"),
        desired_min_tx_ms=300,
        detect_multiplier=multiplier,
    )
    assert bfd_detection_ms(session) == 300 * multiplier


# --------------------------------------------------------------------------
# Deliberate silence
#
# The dampening rule compares two numbers, so the ways it can be wrong are the
# near misses around that comparison: a window that is long but bounded, one
# that lands exactly on the limit, and one the site's own commitment allows.
# --------------------------------------------------------------------------

# 5 minutes, which is `Limits.sla_max_suppress_s` exactly.
AT_THE_LIMIT: Final = "half-life 1 reuse 750 suppress 2000 max-suppress-time 5"


def test_a_bounded_suppression_window_inside_the_sla() -> None:
    """Dampening is not itself a defect — a prefix that flaps hard should be held
    down. What is reported is a hold-down longer than the outage the site has
    committed to, and a max-suppress under that limit is the feature working."""
    pack = pack_from(DAMPENED.format(profile=NARROW))
    assert "dampening-exceeds-sla" not in rules_fired(pack)


def test_a_suppression_window_landing_exactly_on_the_sla() -> None:
    """A window equal to the commitment is inside it. The finding claims the
    prefix stays withdrawn for longer than the SLA allows, and at the boundary
    that claim is not yet true."""
    pack = pack_from(DAMPENED.format(profile=AT_THE_LIMIT))
    assert pack.timers.dampening[0].max_suppress_s == 300
    assert "dampening-exceeds-sla" not in rules_fired(pack)


def test_an_hour_long_window_a_looser_sla_permits() -> None:
    """The threshold is the operator's number, not the tool's. The same hour-long
    max-suppress that breaks a five-minute commitment is a deliberate, documented
    hold-down on a site that allows two hours."""
    pack = pack_from(DAMPENED.format(profile=WIDE))
    assert "dampening-exceeds-sla" not in rules_fired(
        pack, limits=Limits(sla_max_suppress_s=7200)
    )


# --------------------------------------------------------------------------
# Two ends of one wire
#
# The rules below need both devices. Their packs are therefore built from a
# directory of configs rather than from one parsed device, so the join that
# pairs the two — the L3 adjacency, or the FHRP group — is the same one the
# tool performs on a real collection.
# --------------------------------------------------------------------------

# A routed pair addressed out of one /31, with whatever protocol timers the test
# is about hung off each end.
ROUTED_PAIR: Final = """hostname {host}
interface Ethernet1
   no switchport
   ip address 10.0.0.{address}/31
{extra}"""

# One HSRP group across two devices in the same VLAN, in the dialect that states
# both halves of the FHRP timer pair.
GATEWAY: Final = """hostname {host}
interface Vlan14
 ip address 10.14.0.{address} 255.255.255.0
 standby 14 ip 10.14.0.1
{extra}"""


def site(tmp_path: Path, **configs: str) -> StaticFactPack:
    """Build a pack from a directory of configs, the way the CLI does."""
    for name, text in configs.items():
        (tmp_path / f"{name}.cfg").write_text(text)
    pack, _ = build_fact_pack(tmp_path)
    return pack


def routed_pair(tmp_path: Path, here: str, there: str) -> StaticFactPack:
    """Two routers facing each other on 10.0.0.0/31, timers as given."""
    return site(
        tmp_path,
        rtr_a=ROUTED_PAIR.format(host="rtr-a", address=1, extra=_indented(here)),
        rtr_b=ROUTED_PAIR.format(host="rtr-b", address=0, extra=_indented(there)),
    )


def gateways(tmp_path: Path, here: str, there: str) -> StaticFactPack:
    """Two members of HSRP group 14, timers as given."""
    return site(
        tmp_path,
        gw_a=GATEWAY.format(host="gw-a", address=2, extra=_indented(here, indent=" ")),
        gw_b=GATEWAY.format(host="gw-b", address=3, extra=_indented(there, indent=" ")),
    )


def _indented(lines: str, *, indent: str = "   ") -> str:
    return "".join(f"{indent}{line}\n" for line in lines.splitlines() if line.strip())


# --------------------------------------------------------------------------
# OSPF timers that disagree across a subnet
# --------------------------------------------------------------------------

SLOW_OSPF: Final = "ip ospf hello-interval 10\nip ospf dead-interval 40"
FAST_OSPF: Final = "ip ospf hello-interval 5\nip ospf dead-interval 20"


def test_ospf_hello_and_dead_disagreeing_across_the_wire_is_reported(
    tmp_path: Path,
) -> None:
    pack = routed_pair(tmp_path, SLOW_OSPF, FAST_OSPF)
    assert "ospf-timers-disagree" in rules_fired(pack)


def test_the_disagreement_names_both_ends_and_both_numbers(tmp_path: Path) -> None:
    pack = routed_pair(tmp_path, SLOW_OSPF, FAST_OSPF)
    finding = next(f for f in analyse(pack) if f.rule == "ospf-timers-disagree")
    assert finding.severity is Severity.HIGH
    assert "hello 10s against 5s" in finding.detail
    assert "dead 40s against 20s" in finding.detail
    assert len(finding.evidence) == 2
    assert "10.0.0.0/31" in finding.title


def test_two_ends_that_agree_are_silent(tmp_path: Path) -> None:
    """The rule reports a disagreement, not the presence of tuned timers. Two
    routers running the same non-default hello and dead form an adjacency
    exactly as a pair on the defaults would."""
    pack = routed_pair(tmp_path, FAST_OSPF, FAST_OSPF)
    assert "ospf-timers-disagree" not in rules_fired(pack)


def test_one_end_tuned_and_the_other_silent_is_not_a_disagreement(
    tmp_path: Path,
) -> None:
    """A device that states no hello interval is running its platform default,
    which this tool has not read. The pair may well be misconfigured, but saying
    so would mean comparing the configured value against an invented one."""
    pack = routed_pair(tmp_path, FAST_OSPF, "")
    assert "ospf-timers-disagree" not in rules_fired(pack)


def test_isis_hellos_that_differ_are_the_protocol_working(tmp_path: Path) -> None:
    """IS-IS carries its hold time inside every hello and the receiver honours
    what it is told, so two IS-IS routers on one wire are under no obligation to
    use the same interval. Reporting the difference would be reporting a
    correctly configured link."""
    pack = routed_pair(
        tmp_path,
        "isis hello-interval 10\nisis hello-multiplier 3",
        "isis hello-interval 3\nisis hello-multiplier 3",
    )
    assert "ospf-timers-disagree" not in rules_fired(pack)


def test_a_neighbour_missing_from_the_collection_reports_nothing(
    tmp_path: Path,
) -> None:
    """Half a link is an incomplete capture, not a defect. One router with tuned
    OSPF timers and nothing else in the directory says nothing about whether the
    device at the far end agrees with it."""
    pack = site(
        tmp_path,
        rtr_a=ROUTED_PAIR.format(host="rtr-a", address=1, extra=_indented(FAST_OSPF)),
    )
    assert "ospf-timers-disagree" not in rules_fired(pack)


# --------------------------------------------------------------------------
# Dead interval against its own hello
# --------------------------------------------------------------------------


def test_a_dead_interval_of_two_hellos_is_reported() -> None:
    pack = uplink("ip ospf hello-interval 10", "ip ospf dead-interval 20")
    assert "igp-dead-under-three-hellos" in rules_fired(pack)


def test_an_isis_multiplier_of_two_is_the_same_defect() -> None:
    """IS-IS states the ratio directly rather than as a second interval, and the
    tolerance it buys is the same number of lost hellos either way."""
    pack = uplink("isis hello-interval 3", "isis hello-multiplier 2")
    assert "igp-dead-under-three-hellos" in rules_fired(pack)


def test_a_dead_interval_of_exactly_three_hellos_is_silent() -> None:
    """Three is the floor every default in this space sits on or above, so a
    dead interval landing exactly on it is inside the margin the rule asks for,
    not one short of it."""
    pack = uplink("ip ospf hello-interval 10", "ip ospf dead-interval 30")
    assert "igp-dead-under-three-hellos" not in rules_fired(pack)


def test_sub_second_hellos_are_judged_on_the_ratio_not_the_interval() -> None:
    """An aggressively tuned IGP is a design decision, and the rule does not have
    an opinion about it. Hellos every 250ms with a dead interval of a second
    still tolerate four losses, which is what the check is about."""
    pack = uplink("isis hello-interval 1", "isis hello-multiplier 4")
    assert "igp-dead-under-three-hellos" not in rules_fired(pack)


def test_a_dead_interval_that_is_not_a_whole_number_of_hellos_is_reported() -> None:
    pack = uplink("ip ospf hello-interval 10", "ip ospf dead-interval 35")
    finding = next(
        f for f in analyse(pack) if f.rule == "igp-dead-not-a-multiple-of-hello"
    )
    assert finding.severity is Severity.LOW
    assert "3 whole hellos and 5s" in finding.detail


def test_the_conventional_four_hellos_is_silent() -> None:
    """`hello 10` with `dead 40` is the OSPF default written out. Every second of
    the dead interval is one in which a hello was due, so nothing is wasted."""
    pack = uplink("ip ospf hello-interval 10", "ip ospf dead-interval 40")
    assert "igp-dead-not-a-multiple-of-hello" not in rules_fired(pack)


def test_an_aggressive_ratio_is_left_to_the_rule_about_ratios() -> None:
    """`hello 10` with `dead 25` is both a fraction of a hello and too few
    hellos, and the second is the finding worth acting on. Reporting the
    remainder as well would be two findings about one pair of numbers."""
    pack = uplink("ip ospf hello-interval 10", "ip ospf dead-interval 25")
    assert "igp-dead-not-a-multiple-of-hello" not in rules_fired(pack)
    assert "igp-dead-under-three-hellos" in rules_fired(pack)


# --------------------------------------------------------------------------
# BFD tuned past what the control plane can survive
# --------------------------------------------------------------------------


def test_a_sixty_millisecond_detection_time_is_reported() -> None:
    pack = uplink("bfd interval 20 min_rx 20 multiplier 3", "ip ospf bfd")
    assert "bfd-detection-below-floor" in rules_fired(pack)


def test_detection_landing_exactly_on_the_floor_is_silent() -> None:
    """Three 50ms intervals is the fastest session platforms document as
    survivable, and the finding claims the session is below what a control-plane
    pause allows. At the floor that claim is not yet true."""
    pack = uplink("bfd interval 50 min_rx 50 multiplier 3", "ip ospf bfd")
    assert "bfd-detection-below-floor" not in rules_fired(pack)


def test_the_floor_is_the_operators_number() -> None:
    """A platform that genuinely maintains the session in forwarding hardware
    survives what a software implementation cannot, and the same 60ms session is
    then a deliberate choice rather than a fragile one."""
    pack = uplink("bfd interval 20 min_rx 20 multiplier 3", "ip ospf bfd")
    assert "bfd-detection-below-floor" not in rules_fired(
        pack, limits=Limits(bfd_min_detection_ms=50)
    )


def test_a_multiplier_of_one_is_reported() -> None:
    pack = uplink("bfd interval 300 min_rx 300 multiplier 1", "ip ospf bfd")
    finding = next(f for f in analyse(pack) if f.rule == "bfd-multiplier-of-one")
    assert finding.severity is Severity.HIGH
    assert "every 300ms" in finding.detail


def test_a_multiplier_of_two_still_has_a_margin() -> None:
    """The rule is about the absence of tolerance, not about how thin it is. A
    multiplier of two is aggressive, and it still survives the single lost
    packet that a multiplier of one turns into a reconvergence."""
    pack = uplink("bfd interval 300 min_rx 300 multiplier 2", "ip ospf bfd")
    assert "bfd-multiplier-of-one" not in rules_fired(pack)


# --------------------------------------------------------------------------
# FHRP hold times
# --------------------------------------------------------------------------


def test_a_hold_time_of_two_hellos_is_reported(tmp_path: Path) -> None:
    pack = gateways(tmp_path, "standby 14 timers 1 2", "standby 14 timers 1 2")
    assert "fhrp-hold-under-three-hellos" in rules_fired(pack)


def test_a_hold_time_of_exactly_three_hellos_is_silent(tmp_path: Path) -> None:
    """Three advertisements is what VRRP fixes its master-down interval at and
    what HSRP's own default exceeds. A group holding for exactly that long has
    the margin the rule asks for."""
    pack = gateways(tmp_path, "standby 14 timers 1 3", "standby 14 timers 1 3")
    assert "fhrp-hold-under-three-hellos" not in rules_fired(pack)


def test_a_group_with_no_hold_time_in_the_pack_is_silent() -> None:
    """VRRP as this dialect writes it states an advertisement interval and
    derives the rest, so there is no configured hold time to measure. The ratio
    would have to be assumed, and an assumed ratio is not a finding."""
    pack = uplink("vrrp 14 ipv4 10.0.0.9", "vrrp 14 advertisement interval 1")
    assert pack.timers.fhrp[0].hold_time_ms is None
    assert "fhrp-hold-under-three-hellos" not in rules_fired(pack)


def test_a_hold_shorter_than_the_peers_advertisement_interval_is_reported(
    tmp_path: Path,
) -> None:
    pack = gateways(tmp_path, "standby 14 timers 1 3", "standby 14 timers 3 10")
    finding = next(f for f in analyse(pack) if f.rule == "fhrp-hold-under-peer-hello")
    assert finding.severity is Severity.HIGH
    assert finding.device == "gw-a"
    assert "10.14.0.1" in finding.detail


def test_mismatched_timers_whose_arithmetic_still_works_are_silent(
    tmp_path: Path,
) -> None:
    """Members of one group ought to share their timers, and untidy is not the
    same as broken. A hold of 4s against a peer advertising every 3s still
    resets on every advertisement that arrives on time, so no member ever
    declares a live gateway dead."""
    pack = gateways(tmp_path, "standby 14 timers 1 4", "standby 14 timers 3 10")
    assert "fhrp-hold-under-peer-hello" not in rules_fired(pack)


def test_one_member_of_a_group_says_nothing_about_its_peer(tmp_path: Path) -> None:
    """A hold time is only short relative to somebody else's hello. With one
    member of the group in the collection the comparison has no second term, and
    the missing device is a gap in the capture rather than evidence about it."""
    pack = site(
        tmp_path,
        gw_a=GATEWAY.format(host="gw-a", address=2, extra=" standby 14 timers 1 3\n"),
    )
    assert "fhrp-hold-under-peer-hello" not in rules_fired(pack)


# --------------------------------------------------------------------------
# Dampening that cannot reach its own threshold
# --------------------------------------------------------------------------

# reuse 750 doubling once over the 4 minutes it is allowed to suppress: a
# ceiling of 1500, well under the 6000 at which suppression would begin.
UNREACHABLE: Final = "half-life 4 reuse 750 suppress 6000 max-suppress-time 4"
# The same thresholds, decaying four times as fast: the ceiling is 12000.
REACHABLE: Final = "half-life 1 reuse 750 suppress 6000 max-suppress-time 4"


def test_a_suppress_threshold_above_the_penalty_ceiling_is_reported() -> None:
    pack = pack_from(DAMPENED.format(profile=UNREACHABLE))
    finding = next(f for f in analyse(pack) if f.rule == "dampening-never-suppresses")
    assert "1,500" in finding.detail
    assert finding.severity is Severity.MEDIUM


def test_a_threshold_the_penalty_can_reach_is_silent() -> None:
    """The rule reports dampening that cannot act, not dampening that is set
    high. With the same thresholds and a shorter half-life the penalty climbs to
    12000, so a prefix that keeps flapping is suppressed as intended."""
    pack = pack_from(DAMPENED.format(profile=REACHABLE))
    assert "dampening-never-suppresses" not in rules_fired(pack)


def test_the_platform_defaults_are_coherent() -> None:
    """A bare `bgp dampening` inherits values that work: an hour of suppression
    against a fifteen-minute half-life puts the ceiling at sixteen times the
    reuse limit, far above the threshold. The inherited profile has a different
    problem, and `dampening-exceeds-sla` is the rule that reports it."""
    pack = pack_from("hostname agg-a\nrouter bgp 65001\n   bgp dampening\n")
    assert "dampening-never-suppresses" not in rules_fired(pack)


def test_a_profile_missing_a_term_of_the_product_is_silent() -> None:
    """The ceiling is a product of the reuse limit, the half-life and the
    max-suppress time. Any one of them absent makes it unknowable, and a rule
    that filled in the gap would be reporting its own default."""
    pack = StaticFactPack(
        meta=FactPackMeta(
            fact_pack_id="fp_test",
            schema_version=1,
            config_digest="0" * 64,
            source_snapshot="test",
            generated_at=datetime.now(UTC),
        ),
        timers=TimerInventory(
            dampening=(
                DampeningProfile(
                    scope=TimerScope(device="agg-a", source=TimerSource.CONFIGURED),
                    kind=DampeningKind.BGP_ROUTE,
                    half_life_s=900,
                    suppress_threshold=2000,
                ),
            )
        ),
    )
    assert "dampening-never-suppresses" not in rules_fired(pack)


# --------------------------------------------------------------------------
# The shipped corpus
# --------------------------------------------------------------------------


def test_the_shipped_corpus_trips_none_of_these_rules() -> None:
    """The site-14 configs are a working network apart from one preempt delay:
    the VRRP groups advertise every second and agree with each other, no
    interface carries BFD or per-interface OSPF timers, and no BGP process
    dampens anything. Every rule here is measuring something that corpus does
    correctly, so a finding on it would be a false positive rather than a
    discovery."""
    pack, _ = build_fact_pack(CORPUS)
    assert "ospf-timers-disagree" not in rules_fired(pack)
    assert "igp-dead-under-three-hellos" not in rules_fired(pack)
    assert "igp-dead-not-a-multiple-of-hello" not in rules_fired(pack)
    assert "bfd-detection-below-floor" not in rules_fired(pack)
    assert "bfd-multiplier-of-one" not in rules_fired(pack)
    assert "fhrp-hold-under-three-hellos" not in rules_fired(pack)
    assert "fhrp-hold-under-peer-hello" not in rules_fired(pack)
    assert "dampening-never-suppresses" not in rules_fired(pack)
