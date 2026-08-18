"""FACTS tier rules, each against a config that should trip it.

Phase 2's "done when" is two-sided: the rules must fire on a deliberately broken
corpus and stay silent on the good one. Both halves are here, because a rule set
that never fires and a rule set that always fires are equally useless.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack
from cassandra.facts.rules import evaluate
from cassandra.findings import Severity, Tier

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)

GOOD_PAIR: Final = """hostname {name}
vlan 14
interface Ethernet1
   no switchport
   ip address 10.0.0.{p2p}/31
interface Ethernet2
   switchport mode trunk
   switchport trunk allowed vlan 14
interface Vlan14
   ip address 10.14.0.{host}/24
   vrrp 14 ipv4 10.14.0.1
   vrrp 14 priority-level {priority}
   vrrp 14 preempt
"""


def pack_from(tmp_path: Path, **configs: str) -> StaticFactPack:
    for name, text in configs.items():
        (tmp_path / f"{name}.cfg").write_text(text)
    pack, _ = build_fact_pack(tmp_path)
    return pack


def rules_fired(pack: StaticFactPack) -> set[str]:
    return {finding.rule for finding in evaluate(pack)}


def pair(tmp_path: Path, a_extra: str = "", b_extra: str = "") -> StaticFactPack:
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110) + a_extra
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100) + b_extra
    return pack_from(tmp_path, **{"agg-a": a, "agg-b": b})


def test_clean_pair_produces_nothing(tmp_path: Path) -> None:
    assert rules_fired(pair(tmp_path)) == set()


def test_real_corpus_produces_nothing() -> None:
    """The shipped corpus is well-formed apart from its timing asymmetry, which is
    the TIMING tier's job. If a FACTS rule fires here it is a false positive."""
    pack, _ = build_fact_pack(CORPUS)
    assert evaluate(pack) == []


def test_virtual_address_outside_subnet(tmp_path: Path) -> None:
    broken = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
        "vrrp 14 ipv4 10.14.0.1", "vrrp 14 ipv4 10.99.0.1"
    )
    pack = pack_from(tmp_path, **{"agg-a": broken})
    assert "fhrp-virtual-outside-subnet" in rules_fired(pack)


def test_virtual_address_colliding_with_a_real_address(tmp_path: Path) -> None:
    broken = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
        "vrrp 14 ipv4 10.14.0.1", "vrrp 14 ipv4 10.14.0.2"
    )
    pack = pack_from(tmp_path, **{"agg-a": broken})
    assert "fhrp-virtual-collides" in rules_fired(pack)


def test_single_member_group(tmp_path: Path) -> None:
    pack = pack_from(
        tmp_path,
        **{"agg-a": GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)},
    )
    assert "fhrp-no-redundancy" in rules_fired(pack)


def test_priority_tie_has_no_preferred_master(tmp_path: Path) -> None:
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=100)
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "fhrp-priority-tie" in rules_fired(pack)


def test_tracked_object_referenced_but_never_defined(tmp_path: Path) -> None:
    pack = pair(tmp_path, a_extra="   vrrp 14 tracked-object GHOST decrement 40\n")
    fired = {f.rule: f for f in evaluate(pack)}
    assert "fhrp-track-undefined" in fired
    assert fired["fhrp-track-undefined"].severity is Severity.HIGH


def test_decrement_too_small_to_ever_lose_the_election(tmp_path: Path) -> None:
    """The quiet one: valid config, visible intent, failover that never happens."""
    a = (
        GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
        + "   vrrp 14 tracked-object UPLINK decrement 5\n"
        + "track UPLINK interface Ethernet1 line-protocol\n"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    findings = {f.rule: f for f in evaluate(pack)}
    assert "fhrp-track-ineffective" in findings
    assert "105" in findings["fhrp-track-ineffective"].detail


def test_sufficient_decrement_does_not_fire(tmp_path: Path) -> None:
    a = (
        GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
        + "   vrrp 14 tracked-object UPLINK decrement 40\n"
        + "track UPLINK interface Ethernet1 line-protocol\n"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "fhrp-track-ineffective" not in rules_fired(pack)


def test_svi_vlan_carried_by_no_trunk(tmp_path: Path) -> None:
    broken = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
        "switchport trunk allowed vlan 14", "switchport trunk allowed vlan 24"
    )
    pack = pack_from(tmp_path, **{"agg-a": broken})
    assert "svi-vlan-not-trunked" in rules_fired(pack)


def test_duplicate_address_across_devices(tmp_path: Path) -> None:
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=2, priority=100)
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "duplicate-address" in rules_fired(pack)


def test_preferred_master_without_preempt(tmp_path: Path) -> None:
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
        "   vrrp 14 preempt\n", ""
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "fhrp-no-preempt-on-preferred" in rules_fired(pack)


def test_every_finding_carries_a_remedy(tmp_path: Path) -> None:
    """A finding the user cannot act on is noise (PROJECT.md §5.4)."""
    a = (
        GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=100)
        + "   vrrp 14 tracked-object GHOST decrement 1\n"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=2, priority=100)
    findings = evaluate(pack_from(tmp_path, **{"agg-a": a, "agg-b": b}))
    assert findings
    for finding in findings:
        assert finding.remedy, f"{finding.rule} has no remedy"
        assert finding.tier is Tier.FACTS
        assert finding.device


@pytest.mark.parametrize("severity", list(Severity))
def test_severity_values_are_usable_labels(severity: Severity) -> None:
    assert severity.value.islower()
