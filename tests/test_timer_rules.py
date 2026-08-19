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
