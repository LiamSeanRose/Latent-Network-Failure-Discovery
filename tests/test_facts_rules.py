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


# ---------------------------------------------------------------------------
# Subnet-shaped rules
# ---------------------------------------------------------------------------


def test_mtu_mismatch_between_two_interfaces_on_one_subnet(tmp_path: Path) -> None:
    pack = pair(tmp_path, a_extra="   mtu 9214\n", b_extra="   mtu 1500\n")
    findings = {f.rule: f for f in evaluate(pack)}
    assert "mtu-mismatch" in findings
    assert findings["mtu-mismatch"].severity is Severity.HIGH
    assert "1500" in findings["mtu-mismatch"].detail


def test_matching_mtu_does_not_fire(tmp_path: Path) -> None:
    pack = pair(tmp_path, a_extra="   mtu 9214\n", b_extra="   mtu 9214\n")
    assert "mtu-mismatch" not in rules_fired(pack)


def test_one_configured_mtu_is_not_a_mismatch(tmp_path: Path) -> None:
    """An unset MTU is a platform default the tool does not claim to know."""
    pack = pair(tmp_path, a_extra="   mtu 9214\n")
    assert "mtu-mismatch" not in rules_fired(pack)


def test_trunk_carrying_a_vlan_nothing_terminates(tmp_path: Path) -> None:
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
        "switchport trunk allowed vlan 14", "switchport trunk allowed vlan 14,77"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    findings = {
        f.rule: f for f in evaluate(pack_from(tmp_path, **{"agg-a": a, "agg-b": b}))
    }
    assert "trunk-vlan-dead" in findings
    assert findings["trunk-vlan-dead"].severity is Severity.LOW
    assert "77" in findings["trunk-vlan-dead"].title


def test_trunk_vlan_with_an_access_port_somewhere_is_alive(tmp_path: Path) -> None:
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
        "switchport trunk allowed vlan 14", "switchport trunk allowed vlan 14,77"
    )
    b = (
        GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
        + "interface Ethernet3\n   switchport mode access\n"
        "   switchport access vlan 77\n"
    )
    assert "trunk-vlan-dead" not in rules_fired(
        pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    )


def test_trunk_vlan_with_an_svi_somewhere_is_alive(tmp_path: Path) -> None:
    assert "trunk-vlan-dead" not in rules_fired(pair(tmp_path))


def test_isolated_l3_interface_is_reported_as_info(tmp_path: Path) -> None:
    pack = pair(tmp_path, a_extra="interface Vlan55\n   ip address 10.55.0.1/24\n")
    findings = {f.rule: f for f in evaluate(pack)}
    assert "l3-interface-isolated" in findings
    assert findings["l3-interface-isolated"].severity is Severity.INFO
    assert findings["l3-interface-isolated"].device == "agg-a"


def test_shared_subnet_is_not_isolated(tmp_path: Path) -> None:
    assert "l3-interface-isolated" not in rules_fired(pair(tmp_path))


def test_point_to_point_link_off_the_corpus_is_not_isolated(tmp_path: Path) -> None:
    """A /30 or /31 whose far end is not in the directory is the normal case."""
    pack = pair(tmp_path, a_extra="interface Vlan98\n   ip address 10.98.0.1/30\n")
    assert "l3-interface-isolated" not in rules_fired(pack)


def test_a_device_sharing_no_subnet_at_all_is_not_reported_interface_by_interface(
    tmp_path: Path,
) -> None:
    """Configs from a second site in the same directory share nothing with the
    first. Reporting every one of their interfaces says nothing about any of them."""
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    elsewhere = "hostname far1\ninterface Vlan70\n   ip address 10.70.0.1/24\n"
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b, "far1": elsewhere})
    isolated = [f for f in evaluate(pack) if f.rule == "l3-interface-isolated"]
    assert isolated == []


def test_loopback_is_not_isolated(tmp_path: Path) -> None:
    pack = pair(tmp_path, a_extra="interface Loopback0\n   ip address 10.255.1.1/32\n")
    assert "l3-interface-isolated" not in rules_fired(pack)


# ---------------------------------------------------------------------------
# Further FHRP rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("virtual", ["10.14.0.0", "10.14.0.255"])
def test_virtual_address_is_network_or_broadcast(tmp_path: Path, virtual: str) -> None:
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
        "vrrp 14 ipv4 10.14.0.1", f"vrrp 14 ipv4 {virtual}"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100).replace(
        "vrrp 14 ipv4 10.14.0.1", f"vrrp 14 ipv4 {virtual}"
    )
    fired = rules_fired(pack_from(tmp_path, **{"agg-a": a, "agg-b": b}))
    assert "fhrp-virtual-not-a-host-address" in fired
    # It is inside the subnet, so the outside-subnet rule must stay quiet.
    assert "fhrp-virtual-outside-subnet" not in fired


def test_host_virtual_address_is_not_flagged(tmp_path: Path) -> None:
    assert "fhrp-virtual-not-a-host-address" not in rules_fired(pair(tmp_path))


def test_same_device_twice_in_one_group_on_one_subnet(tmp_path: Path) -> None:
    pack = pair(
        tmp_path,
        a_extra="interface Vlan114\n   ip address 10.14.0.4/24\n"
        "   vrrp 14 ipv4 10.14.0.1\n   vrrp 14 priority-level 90\n",
    )
    findings = {f.rule: f for f in evaluate(pack)}
    assert "fhrp-duplicate-member" in findings
    assert findings["fhrp-duplicate-member"].severity is Severity.HIGH
    assert findings["fhrp-duplicate-member"].device == "agg-a"


def test_group_number_reused_on_another_subnet_is_not_a_duplicate(
    tmp_path: Path,
) -> None:
    """Group 14 on two unrelated subnets is ordinary practice, not a defect."""
    pack = pair(
        tmp_path,
        a_extra="interface Vlan24\n   ip address 10.24.0.2/24\n"
        "   vrrp 14 ipv4 10.14.0.1\n   vrrp 14 priority-level 90\n",
    )
    assert "fhrp-duplicate-member" not in rules_fired(pack)


def test_two_groups_on_one_interface_claiming_one_address(tmp_path: Path) -> None:
    pack = pair(
        tmp_path,
        a_extra="   vrrp 15 ipv4 10.14.0.1\n   vrrp 15 priority-level 90\n",
    )
    findings = {f.rule: f for f in evaluate(pack)}
    assert "fhrp-virtual-shared" in findings
    assert "10.14.0.1" in findings["fhrp-virtual-shared"].title


def test_distinct_virtual_addresses_are_not_shared(tmp_path: Path) -> None:
    pack = pair(
        tmp_path,
        a_extra="   vrrp 15 ipv4 10.14.0.9\n   vrrp 15 priority-level 90\n",
    )
    assert "fhrp-virtual-shared" not in rules_fired(pack)


def test_tracked_interface_that_is_shut_down(tmp_path: Path) -> None:
    """A track on an admin-down interface is down for good: it never recovers."""
    a = (
        GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
            "   ip address 10.0.0.1/31", "   ip address 10.0.0.1/31\n   shutdown"
        )
        + "   vrrp 14 tracked-object UPLINK decrement 40\n"
        + "track UPLINK interface Ethernet1 line-protocol\n"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    findings = {
        f.rule: f for f in evaluate(pack_from(tmp_path, **{"agg-a": a, "agg-b": b}))
    }
    assert "fhrp-track-target-shutdown" in findings
    assert findings["fhrp-track-target-shutdown"].severity is Severity.HIGH
    assert "Ethernet1" in findings["fhrp-track-target-shutdown"].title


def test_tracked_interface_that_is_up_does_not_fire(tmp_path: Path) -> None:
    a = (
        GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
        + "   vrrp 14 tracked-object UPLINK decrement 40\n"
        + "track UPLINK interface Ethernet1 line-protocol\n"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    assert "fhrp-track-target-shutdown" not in rules_fired(
        pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    )


def test_widened_rules_all_carry_a_remedy(tmp_path: Path) -> None:
    """The remedy guarantee (PROJECT.md §5.4) extended to the widened tier: one
    config that trips several of the new rules at once, all of them actionable."""
    a = (
        GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
            "switchport trunk allowed vlan 14", "switchport trunk allowed vlan 14,77"
        )
        + "   mtu 9214\n"
        + "   vrrp 15 ipv4 10.14.0.1\n"
        + "   vrrp 15 priority-level 90\n"
        + "interface Vlan55\n   ip address 10.55.0.1/24\n"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100) + "   mtu 1500\n"
    findings = evaluate(pack_from(tmp_path, **{"agg-a": a, "agg-b": b}))
    fired = {f.rule for f in findings}
    assert {
        "mtu-mismatch",
        "trunk-vlan-dead",
        "l3-interface-isolated",
        "fhrp-virtual-shared",
    } <= fired
    for finding in findings:
        assert finding.remedy, f"{finding.rule} has no remedy"
        assert finding.tier is Tier.FACTS
        assert finding.device


def test_access_vlan_not_declared_on_the_device(tmp_path: Path) -> None:
    """The rule the fact pack could not previously support: VLANs were parsed
    and thrown away, so nothing could check what a port referenced."""
    (tmp_path / "sw.cfg").write_text(
        "hostname sw\n"
        "vlan 10\n"
        "interface Ethernet1\n"
        "   switchport mode access\n"
        "   switchport access vlan 99\n"
    )
    pack, _ = build_fact_pack(tmp_path)
    findings = {f.rule: f for f in evaluate(pack)}
    assert "vlan-not-declared" in findings
    assert "99" in findings["vlan-not-declared"].title


def test_declared_access_vlan_is_silent(tmp_path: Path) -> None:
    (tmp_path / "sw.cfg").write_text(
        "hostname sw\n"
        "vlan 10,99\n"
        "interface Ethernet1\n"
        "   switchport mode access\n"
        "   switchport access vlan 99\n"
    )
    pack, _ = build_fact_pack(tmp_path)
    assert "vlan-not-declared" not in rules_fired(pack)


def test_svi_without_a_declared_vlan(tmp_path: Path) -> None:
    (tmp_path / "sw.cfg").write_text(
        "hostname sw\nvlan 10\ninterface Vlan20\n   ip address 10.20.0.1/24\n"
    )
    pack, _ = build_fact_pack(tmp_path)
    assert "vlan-not-declared" in rules_fired(pack)


def test_a_router_declaring_no_vlans_is_not_flagged(tmp_path: Path) -> None:
    """A pure L3 device declares no VLANs and is doing nothing wrong."""
    (tmp_path / "r.cfg").write_text(
        "hostname r\ninterface Ethernet1\n   no switchport\n   ip address 10.0.0.1/31\n"
    )
    pack, _ = build_fact_pack(tmp_path)
    assert "vlan-not-declared" not in rules_fired(pack)


BGP_PAIR: Final = """hostname {name}
interface Ethernet1
   no switchport
   ip address 10.0.0.{addr}/31
router bgp {local_as}
   router-id 10.255.0.{rid}
{neighbors}"""


def bgp_pair(
    tmp_path: Path,
    *,
    a_neighbors: str = "   neighbor 10.0.0.1 remote-as 65001\n",
    b_neighbors: str = "   neighbor 10.0.0.0 remote-as 65000\n",
    b_as: str = "65001",
) -> StaticFactPack:
    (tmp_path / "r0.cfg").write_text(
        BGP_PAIR.format(
            name="r0", addr=0, local_as="65000", rid=1, neighbors=a_neighbors
        )
    )
    (tmp_path / "r1.cfg").write_text(
        BGP_PAIR.format(name="r1", addr=1, local_as=b_as, rid=2, neighbors=b_neighbors)
    )
    pack, _ = build_fact_pack(tmp_path)
    return pack


def test_reciprocated_bgp_session_is_silent(tmp_path: Path) -> None:
    assert rules_fired(bgp_pair(tmp_path)) == set()


def test_bgp_session_configured_on_one_side_only(tmp_path: Path) -> None:
    """The session never establishes, and each config looks complete alone."""
    pack = bgp_pair(tmp_path, b_neighbors="")
    assert "bgp-session-one-sided" in rules_fired(pack)


def test_bgp_remote_as_mismatch(tmp_path: Path) -> None:
    pack = bgp_pair(tmp_path, b_as="65999")
    findings = {f.rule: f for f in evaluate(pack)}
    assert "bgp-remote-as-mismatch" in findings
    assert "65999" in findings["bgp-remote-as-mismatch"].title


def test_bgp_peer_not_on_any_local_subnet(tmp_path: Path) -> None:
    pack = bgp_pair(tmp_path, a_neighbors="   neighbor 192.0.2.9 remote-as 65001\n")
    assert "bgp-peer-off-subnet" in rules_fired(pack)


def test_multihop_peer_off_subnet_is_intentional(tmp_path: Path) -> None:
    """update-source or ebgp-multihop says the operator meant it."""
    pack = bgp_pair(
        tmp_path,
        a_neighbors=(
            "   neighbor 192.0.2.9 remote-as 65001\n"
            "   neighbor 192.0.2.9 ebgp-multihop 2\n"
        ),
    )
    assert "bgp-peer-off-subnet" not in rules_fired(pack)


def test_peer_outside_the_corpus_is_not_a_one_sided_session(tmp_path: Path) -> None:
    """An upstream provider is not in your config directory and is not a defect."""
    (tmp_path / "edge.cfg").write_text(
        "hostname edge\n"
        "interface Ethernet1\n"
        "   no switchport\n"
        "   ip address 198.51.100.2/30\n"
        "router bgp 65000\n"
        "   neighbor 198.51.100.1 remote-as 64500\n"
    )
    pack, _ = build_fact_pack(tmp_path)
    fired = rules_fired(pack)
    assert "bgp-session-one-sided" not in fired
    assert "bgp-remote-as-mismatch" not in fired
