"""FACTS tier rules, each against a config that should trip it.

Phase 2's "done when" is two-sided: the rules must fire on a deliberately broken
corpus and stay silent on the good one. Both halves are here, because a rule set
that never fires and a rule set that always fires are equally useless.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack, StpMode
from cassandra.facts.rules import evaluate
from cassandra.findings import Finding, Severity, Tier, locate
from cassandra.timing.model import Event, EventKind, simulate

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


# One HSRP member, in the dialect that writes HSRP flat. HSRP is the one protocol
# whose preemption defaults off, so a group here that states no `preempt` line
# genuinely will not reclaim — the case `fhrp-no-preempt-on-preferred` exists for.
HSRP_MEMBER: Final = """hostname {name}
vlan 14
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan 14
interface Vlan14
 ip address 10.14.0.{host} 255.255.255.0
 standby 14 ip 10.14.0.1
 standby 14 priority {priority}
"""


TWO_VLAN_PAIR: Final = """hostname {name}
vlan 14,24
interface Ethernet1
   no switchport
   ip address 10.0.0.{p2p}/31
interface Ethernet2
   switchport mode trunk
   switchport trunk allowed vlan 14,24
interface Vlan14
   ip address 10.14.0.{host}/24
   vrrp {first} ipv4 10.14.0.1
   vrrp {first} priority-level {p1}
   vrrp {first} preempt
interface Vlan24
   ip address 10.24.0.{host}/24
   vrrp {second} ipv4 10.24.0.1
   vrrp {second} priority-level {p2}
   vrrp {second} preempt
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


def two_vlan_pair(
    tmp_path: Path,
    *,
    first: int = 14,
    second: int = 24,
    a: tuple[int, int] = (110, 110),
    b: tuple[int, int] = (100, 100),
) -> StaticFactPack:
    """A pair carrying two VLANs, each with its own group, priorities per device."""
    return pack_from(
        tmp_path,
        **{
            "agg-a": TWO_VLAN_PAIR.format(
                name="agg-a",
                p2p=1,
                host=2,
                first=first,
                second=second,
                p1=a[0],
                p2=a[1],
            ),
            "agg-b": TWO_VLAN_PAIR.format(
                name="agg-b",
                p2p=3,
                host=3,
                first=first,
                second=second,
                p1=b[0],
                p2=b[1],
            ),
        },
    )


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


def tracked_pair(tmp_path: Path, decrement: int) -> StaticFactPack:
    """The 110/100 pair, with agg-a decrementing by `decrement` on its uplink."""
    a = (
        GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
        + f"   vrrp 14 tracked-object UPLINK decrement {decrement}\n"
        + "track UPLINK interface Ethernet1 line-protocol\n"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    return pack_from(tmp_path, **{"agg-a": a, "agg-b": b})


def holds_the_group_with_the_uplink_down(pack: StaticFactPack) -> bool:
    """Whether agg-a still holds VRRP 14 long after its tracked uplink fails.

    The FACTS tier claims a decrement can never cause a failover; this asks the
    timing model the same question about the same configs, so the two tiers are
    held to one answer rather than each to its own.
    """
    events = [
        Event(
            at_ms=5_000, kind=EventKind.LINK_DOWN, device="agg-a", interface="Ethernet1"
        )
    ]
    final = simulate(pack, events, until_ms=60_000)[-1]
    return final.masters["vrrp-14"] == "agg-a"


def test_a_decrement_landing_exactly_on_the_peer_priority(tmp_path: Path) -> None:
    """110 minus 10 is 100, and 100 does not displace 100: both VRRP and HSRP
    need a strictly greater priority to take a group from a live master, which
    the timing model states as A6. Tracking that lands on equality is tracking
    that does nothing, which is precisely what this rule is for."""
    pack = tracked_pair(tmp_path, decrement=10)
    finding = _found(pack, "fhrp-track-ineffective")
    assert "100" in finding.detail
    assert holds_the_group_with_the_uplink_down(pack)


def test_the_remedy_names_a_decrement_that_moves_the_group(tmp_path: Path) -> None:
    """The rule goes quiet once its own remedy is applied, and the network it
    describes actually changes. A remedy is a number the operator will type, so
    one that lands the priority *on* the peer's rather than below it silences
    nothing and leaves the failover exactly as absent (PROJECT.md §5.4)."""
    ineffective = tracked_pair(tmp_path, decrement=5)
    finding = _found(ineffective, "fhrp-track-ineffective")
    assert holds_the_group_with_the_uplink_down(ineffective)

    suggested = int(re.findall(r"\d+", finding.remedy)[-1])
    fixed = tracked_pair(tmp_path, decrement=suggested)
    assert "fhrp-track-ineffective" not in rules_fired(fixed)
    assert not holds_the_group_with_the_uplink_down(fixed)


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


def test_a_vrrp_preferred_master_that_states_no_preempt_line_is_not_reported(
    tmp_path: Path,
) -> None:
    """RFC 3768 section 6.1 and RFC 5798 make `Preempt_Mode` default True, and
    every platform this tool parses ships VRRP that way. A group that omits the
    line is a group that preempts, so this rule firing on it would be a finding
    about a failover that does happen, whose suggested change is a line already
    in effect."""
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
        "   vrrp 14 preempt\n", ""
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "fhrp-no-preempt-on-preferred" not in rules_fired(pack)


def test_a_vrrp_preferred_master_that_turns_preempt_off_is_reported(
    tmp_path: Path,
) -> None:
    """The rule is not dead, its trigger moved. On VRRP the only way to reach the
    configuration it describes is to write the negation, and that is a decision
    worth surfacing precisely because it contradicts the protocol's default."""
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
        "   vrrp 14 preempt\n", "   no vrrp 14 preempt\n"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "fhrp-no-preempt-on-preferred" in rules_fired(pack)


def test_an_hsrp_preferred_master_that_never_turned_preempt_on_is_reported(
    tmp_path: Path,
) -> None:
    """HSRP is the protocol that defaults preemption off, which is why
    `standby <n> preempt` is a line people write and `vrrp <n> preempt` mostly
    is not. Saying nothing here really does mean the group never comes back, so
    this is where the rule earns its place."""
    pack = pack_from(
        tmp_path,
        **{
            "dist-1": HSRP_MEMBER.format(name="dist-1", host=2, priority=110),
            "dist-2": HSRP_MEMBER.format(name="dist-2", host=3, priority=100),
        },
    )
    finding = _found(pack, "fhrp-no-preempt-on-preferred")
    assert finding.device == "dist-1"


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


# ---------------------------------------------------------------------------
# Deliberate silence
#
# Each of these is a configuration that resembles the defect the named rule
# hunts and is not one. They are the half of the rule that a clean run rests
# on: a rule broken into permanent quiet still passes every test that only
# checks it fires.
# ---------------------------------------------------------------------------


def test_a_virtual_address_written_on_both_members(tmp_path: Path) -> None:
    """Both members of a group name the same virtual address — that is what makes
    them one group. Only an address configured on an interface is claimed by a
    device, so a virtual address repeated across the pair is not a duplicate."""
    assert "duplicate-address" not in rules_fired(pair(tmp_path))


# FAILING ON PURPOSE — this records a defect in `duplicate_addresses`, not a
# defect in the test. The rule indexes on the address alone, so it reports two
# VRFs on one device as a collision and tells the operator to renumber one of
# them. Overlapping address space is the reason VRFs exist, and the subnet-shaped
# rules in the same module already key on (VRF, network). Do not relax this test
# to match the behaviour; fix the rule.
def test_the_same_address_in_two_vrfs_on_one_device(tmp_path: Path) -> None:
    """Two VRFs are two separate address spaces, so the same address in each is a
    deliberate design rather than a collision. Nothing on either segment ever sees
    the other's ARP, which is the mechanism the rule is written about."""
    pack = pack_from(
        tmp_path,
        edge1="""hostname edge1
feature interface-vlan
feature hsrp
vlan 14,24
interface Ethernet1/1
  no switchport
  ip address 10.0.0.1/31
interface Ethernet1/2
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 14,24
interface Vlan14
  vrf member tenant-red
  ip address 10.14.0.2/24
interface Vlan24
  vrf member tenant-blue
  ip address 10.14.0.2/24
""",
    )
    assert "duplicate-address" not in rules_fired(pack)


def test_a_track_defined_above_the_group_that_references_it(tmp_path: Path) -> None:
    """A tracked object is resolved wherever in the file it is written, so a
    definition that precedes the group referencing it is as good as one that
    follows. Only a name nothing defines anywhere is a dangling reference."""
    a = (
        "track UPLINK interface Ethernet1 line-protocol\n"
        + GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
        + "   vrrp 14 tracked-object UPLINK decrement 40\n"
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "fhrp-track-undefined" not in rules_fired(pack)


def test_both_devices_defining_their_own_copy_of_a_track_name(
    tmp_path: Path,
) -> None:
    """Tracked objects are device-local: each member resolves the definition in its
    own configuration. A pair that both use the name UPLINK for their own uplink is
    the normal way a symmetric pair is written, not one device borrowing the
    other's track."""
    track = (
        "   vrrp 14 tracked-object UPLINK decrement 40\n"
        "track UPLINK interface Ethernet1 line-protocol\n"
    )
    pack = pair(tmp_path, a_extra=track, b_extra=track)
    assert "fhrp-track-undefined" not in rules_fired(pack)


def test_both_members_advertising_the_same_virtual_address(tmp_path: Path) -> None:
    """Every member of a group is configured with the identical virtual address; a
    group whose members disagreed about it would not be a group. The collision is
    a member owning that address as its own interface address, which is a
    different line entirely."""
    assert "fhrp-virtual-collides" not in rules_fired(pair(tmp_path))


def test_a_virtual_address_beside_a_secondary_on_the_same_subnet(
    tmp_path: Path,
) -> None:
    """A member interface may carry several real addresses on the segment it serves.
    Sharing the subnet with the virtual address is the requirement, not the defect —
    only an interface configured with the virtual address itself answers for it
    while it is backup."""
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110).replace(
        "   ip address 10.14.0.2/24\n",
        "   ip address 10.14.0.2/24\n   ip address 10.14.0.66/24 secondary\n",
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "fhrp-virtual-collides" not in rules_fired(pack)


def test_members_of_one_group_on_differently_named_interfaces(
    tmp_path: Path,
) -> None:
    """Membership is decided by group number and subnet, not by interface name: an
    SVI on one device and a routed port on the other are still each other's peer,
    and the group has the second device it needs."""
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
    b = """hostname agg-b
interface Ethernet1
   no switchport
   ip address 10.0.0.3/31
interface Ethernet5
   no switchport
   ip address 10.14.0.3/24
   vrrp 14 ipv4 10.14.0.1
   vrrp 14 priority-level 100
   vrrp 14 preempt
"""
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "fhrp-no-redundancy" not in rules_fired(pack)


def test_one_group_number_reused_on_a_second_subnet(tmp_path: Path) -> None:
    """Reusing a group number on another VLAN is ordinary practice, and each subnet
    keeps its own pair of members. Counting members by group number alone would
    split them into single-member groups that do not exist."""
    pack = two_vlan_pair(tmp_path, first=14, second=14)
    assert "fhrp-no-redundancy" not in rules_fired(pack)


def test_equal_priorities_in_two_different_groups(tmp_path: Path) -> None:
    """The tie that matters is between peers contending for one virtual address.
    Two groups on two VLANs may use whatever priorities they like, including the
    same numbers, because they never stand in the same election."""
    pack = two_vlan_pair(tmp_path, a=(110, 100), b=(100, 110))
    assert "fhrp-priority-tie" not in rules_fired(pack)


def test_a_tie_below_the_top_priority(tmp_path: Path) -> None:
    """Only the members contending for master can be tied. A third device sharing
    the backup's priority decides nothing: the group still has one member above
    both of them, so who holds it is not left to address comparison."""
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=120)
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    c = """hostname agg-c
vlan 14
interface Ethernet2
   switchport mode trunk
   switchport trunk allowed vlan 14
interface Vlan14
   ip address 10.14.0.4/24
   vrrp 14 ipv4 10.14.0.1
   vrrp 14 priority-level 100
   vrrp 14 preempt
"""
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b, "agg-c": c})
    assert "fhrp-priority-tie" not in rules_fired(pack)


def test_an_svi_on_a_device_that_trunks_nothing(tmp_path: Path) -> None:
    """A router terminating a VLAN it does not bridge onward has no trunks to omit
    it from. The rule is about a VLAN that leaves on no uplink; a device with no
    uplinks carrying VLANs at all is a different design, not a broken one."""
    pack = pack_from(
        tmp_path,
        core1="""hostname core1
vlan 14
interface Ethernet1
   no switchport
   ip address 10.0.0.5/31
interface Vlan14
   ip address 10.14.0.9/24
""",
    )
    assert "svi-vlan-not-trunked" not in rules_fired(pack)


def test_a_vlan_carried_on_one_trunk_but_not_another(tmp_path: Path) -> None:
    """A VLAN needs one trunk that carries it, not every trunk. Trunks are pruned
    to what the neighbour behind them needs, so a VLAN absent from a trunk to a
    device that has no use for it is the allowed list doing its job."""
    pack = pack_from(
        tmp_path,
        acc1="""hostname acc1
vlan 14,24
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 14
interface Ethernet2
   switchport mode trunk
   switchport trunk allowed vlan 24
interface Vlan14
   ip address 10.14.0.5/24
interface Vlan24
   ip address 10.24.0.5/24
""",
    )
    assert "svi-vlan-not-trunked" not in rules_fired(pack)


def svi_device(tmp_path: Path, svi_body: str) -> StaticFactPack:
    """One switch trunking VLAN 10 only, plus a Vlan99 written by the caller."""
    return pack_from(
        tmp_path,
        acc1="""hostname acc1
vlan 10,99
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 10
interface Vlan10
   ip address 10.10.0.5/24
interface Vlan99
"""
        + svi_body,
    )


def test_an_svi_with_no_address(tmp_path: Path) -> None:
    """The finding says the device can route for the VLAN and nothing can reach
    it. An SVI with no address routes for nothing, so the first half is false and
    there is no isolation to report — only an interface that does nothing."""
    pack = svi_device(tmp_path, "   description held for a future tenant\n")
    assert "svi-vlan-not-trunked" not in rules_fired(pack)


def test_an_svi_left_shut(tmp_path: Path) -> None:
    """A shut SVI forwards nothing whether or not a trunk carries its VLAN, so
    the trunk's allowed list is not what is keeping it silent. Reporting it would
    tell the operator to change a trunk to fix an interface they turned off."""
    pack = svi_device(tmp_path, "   ip address 10.99.0.5/24\n   shutdown\n")
    assert "svi-vlan-not-trunked" not in rules_fired(pack)


def test_a_decommissioned_svi_left_shut_and_unaddressed(tmp_path: Path) -> None:
    """Both preconditions absent at once, which is what decommissioning a VLAN
    halfway actually leaves behind: the SVI shut and stripped, the VLAN pulled
    from the trunk, and nothing wrong. It is the commonest shape in a real config
    that this rule must not fire on."""
    pack = svi_device(tmp_path, "   description decommissioned\n   shutdown\n")
    assert "svi-vlan-not-trunked" not in rules_fired(pack)


def test_preempt_left_off_on_the_backup(tmp_path: Path) -> None:
    """Preempt on a backup governs nothing: it never has a higher priority to
    reclaim with. Only the highest-priority member can fail to take the group
    back, so the setting is reported there and nowhere else."""
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100).replace(
        "   vrrp 14 preempt\n", ""
    )
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "fhrp-no-preempt-on-preferred" not in rules_fired(pack)


# FAILING ON PURPOSE — this records a defect in `preferred_master_will_not_reclaim`,
# not a defect in the test. Every member ties for the top priority, so the rule
# reports each of them as "the highest priority" member that will not return to
# itself, contradicting `fhrp-priority-tie`, which has already said the group has
# no preferred master. Do not relax this test to match the behaviour; the rule
# needs to require a single member at the top before it claims one is preferred.
def test_every_member_sharing_one_priority_has_no_master_to_reclaim(
    tmp_path: Path,
) -> None:
    """With every member at the same priority there is no preferred master to fail
    to return to — whoever wins the address comparison is entitled to keep the
    group. The tie is worth reporting, and `fhrp-priority-tie` is what reports
    it."""
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=100).replace(
        "   vrrp 14 preempt\n", ""
    )
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100).replace(
        "   vrrp 14 preempt\n", ""
    )
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "fhrp-no-preempt-on-preferred" not in rules_fired(pack)


# ---------------------------------------------------------------------------
# Addressing agreement, layer-2 edges, and what a shutdown takes with it
# ---------------------------------------------------------------------------


def test_two_ends_of_a_segment_with_different_masks(tmp_path: Path) -> None:
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100).replace(
        "ip address 10.14.0.3/24", "ip address 10.14.0.3/25"
    )
    findings = {
        f.rule: f for f in evaluate(pack_from(tmp_path, **{"agg-a": a, "agg-b": b}))
    }
    assert "subnet-mask-disagreement" in findings
    assert findings["subnet-mask-disagreement"].severity is Severity.HIGH
    assert "10.14.0.0/25" in findings["subnet-mask-disagreement"].detail


def test_a_host_address_inside_another_subnet_is_not_a_mask_disagreement(
    tmp_path: Path,
) -> None:
    """A /32 states a routing identity, not the width of a wire, so a loopback
    numbered out of a LAN prefix is not two devices disagreeing about a segment."""
    pack = pair(tmp_path, b_extra="interface Loopback0\n   ip address 10.14.0.9/32\n")
    assert "subnet-mask-disagreement" not in rules_fired(pack)


def test_unrelated_subnets_with_different_masks_are_not_a_disagreement(
    tmp_path: Path,
) -> None:
    """Neither address falls inside the other's subnet, so the two interfaces make
    no competing claim about one segment and there is nothing to reconcile."""
    pack = pair(tmp_path, a_extra="interface Vlan55\n   ip address 10.55.0.1/25\n")
    assert "subnet-mask-disagreement" not in rules_fired(pack)


def test_device_whose_only_shared_subnet_is_shut_down(tmp_path: Path) -> None:
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100).replace(
        "interface Vlan14\n", "interface Vlan14\n   shutdown\n"
    )
    findings = {
        f.rule: f for f in evaluate(pack_from(tmp_path, **{"agg-a": a, "agg-b": b}))
    }
    assert "device-isolated-by-shutdown" in findings
    assert findings["device-isolated-by-shutdown"].device == "agg-b"
    assert findings["device-isolated-by-shutdown"].severity is Severity.HIGH


def test_one_shut_interface_beside_a_live_one_does_not_isolate_a_device(
    tmp_path: Path,
) -> None:
    """The rule is about a device with no way in at all, not about any shut
    interface: a second subnet that is up still carries every adjacency."""
    a = (
        GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
        + "interface Vlan99\n   ip address 10.99.0.1/30\n"
    )
    b = (
        GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100).replace(
            "interface Vlan14\n", "interface Vlan14\n   shutdown\n"
        )
        + "interface Vlan99\n   ip address 10.99.0.2/30\n"
    )
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    assert "device-isolated-by-shutdown" not in rules_fired(pack)


def test_a_layer_two_switch_is_not_isolated(tmp_path: Path) -> None:
    """A device with no addresses shares no subnet with anything, so there is no
    adjacency for a shutdown to have taken away."""
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100)
    acc = (
        "hostname acc1\nvlan 14\ninterface Ethernet1\n"
        "   switchport mode trunk\n   switchport trunk allowed vlan 14\n"
    )
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b, "acc1": acc})
    assert "device-isolated-by-shutdown" not in rules_fired(pack)


ACCESS_AGG: Final = """hostname agg-a
vlan 14,24
interface Ethernet2
   switchport mode trunk
   switchport trunk allowed vlan 14,24
interface Vlan14
   ip address 10.14.0.2/24
interface Vlan24
   ip address 10.24.0.2/24
"""

ACCESS_EDGE: Final = """hostname acc1
vlan 14,24
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan {allowed}
interface Ethernet3
   switchport mode access
   switchport access vlan 24
"""


def test_access_port_whose_vlan_leaves_on_no_trunk(tmp_path: Path) -> None:
    pack = pack_from(
        tmp_path,
        **{"agg-a": ACCESS_AGG, "acc1": ACCESS_EDGE.format(allowed="14")},
    )
    findings = {f.rule: f for f in evaluate(pack)}
    assert "access-vlan-not-trunked" in findings
    assert findings["access-vlan-not-trunked"].device == "acc1"
    assert findings["access-vlan-not-trunked"].severity is Severity.HIGH
    assert "Ethernet3" in findings["access-vlan-not-trunked"].title


def test_access_vlan_the_uplink_carries_is_silent(tmp_path: Path) -> None:
    """A VLAN the trunk permits leaves the switch, which is the whole of what the
    rule asks: the port is in a live broadcast domain and reaches its gateway."""
    pack = pack_from(
        tmp_path,
        **{"agg-a": ACCESS_AGG, "acc1": ACCESS_EDGE.format(allowed="14,24")},
    )
    assert "access-vlan-not-trunked" not in rules_fired(pack)


def test_a_vlan_used_nowhere_else_is_a_parking_vlan_not_a_defect(
    tmp_path: Path,
) -> None:
    """Spare ports parked in a VLAN nothing else terminates are deliberate, and
    indistinguishable from this rule's defect except by that fact."""
    edge = (
        "hostname acc1\nvlan 14,999\ninterface Ethernet1\n"
        "   switchport mode trunk\n   switchport trunk allowed vlan 14\n"
        "interface Ethernet3\n   switchport mode access\n"
        "   switchport access vlan 999\n"
    )
    pack = pack_from(tmp_path, **{"agg-a": ACCESS_AGG, "acc1": edge})
    assert "access-vlan-not-trunked" not in rules_fired(pack)


NXOS_TRUNK: Final = """version 9.3(10) Bios:version 05.47
hostname nx1
feature interface-vlan
vlan 14,24,99
interface Ethernet1/1
  switchport
  switchport mode trunk
  switchport trunk native vlan {native}
  switchport trunk allowed vlan 14,24
"""


def test_trunk_native_vlan_missing_from_its_own_allowed_list(tmp_path: Path) -> None:
    pack = pack_from(tmp_path, **{"nx1": NXOS_TRUNK.format(native=99)})
    findings = {f.rule: f for f in evaluate(pack)}
    assert "trunk-native-vlan-not-allowed" in findings
    assert findings["trunk-native-vlan-not-allowed"].severity is Severity.MEDIUM
    assert "99" in findings["trunk-native-vlan-not-allowed"].title


def test_native_vlan_inside_the_allowed_list_is_silent(tmp_path: Path) -> None:
    """A native VLAN the trunk also permits is the ordinary configuration: the
    untagged frames belong to a VLAN the link is allowed to carry."""
    pack = pack_from(tmp_path, **{"nx1": NXOS_TRUNK.format(native=14)})
    assert "trunk-native-vlan-not-allowed" not in rules_fired(pack)


def test_group_members_addressed_in_different_subnets(tmp_path: Path) -> None:
    a = GOOD_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)
    b = GOOD_PAIR.format(name="agg-b", p2p=3, host=3, priority=100).replace(
        "ip address 10.14.0.3/24", "ip address 10.14.0.3/25"
    )
    findings = {
        f.rule: f for f in evaluate(pack_from(tmp_path, **{"agg-a": a, "agg-b": b}))
    }
    assert "fhrp-members-on-different-subnets" in findings
    assert findings["fhrp-members-on-different-subnets"].severity is Severity.HIGH
    assert "10.14.0.0/25" in findings["fhrp-members-on-different-subnets"].title


def test_one_group_number_on_two_subnets_with_its_own_address_each(
    tmp_path: Path,
) -> None:
    """Group 14 reused on an unrelated subnet with its own virtual address is
    ordinary practice: the intent to pair two devices is what the matching virtual
    address establishes, and it is absent here."""
    pack = pair(
        tmp_path,
        a_extra="interface Vlan24\n   ip address 10.24.0.2/24\n"
        "   vrrp 14 ipv4 10.24.0.1\n   vrrp 14 priority-level 110\n",
    )
    assert "fhrp-members-on-different-subnets" not in rules_fired(pack)


SHUT_PEER: Final = """hostname {name}
interface Loopback0
   ip address 10.255.0.{rid}/32
interface Ethernet1
   no switchport
   ip address 10.0.0.{addr}/31
{shutdown}router bgp {local_as}
   router-id 10.255.0.{rid}
   neighbor {peer} remote-as {remote_as}
{extra}"""


def bgp_shutdown_pair(
    tmp_path: Path,
    *,
    shutdown: str = "",
    extra: str = "",
    a_rid: int = 1,
    b_rid: int = 2,
) -> StaticFactPack:
    return pack_from(
        tmp_path,
        r0=SHUT_PEER.format(
            name="r0",
            rid=a_rid,
            addr=0,
            local_as="65000",
            peer="10.0.0.1",
            remote_as="65001",
            shutdown=shutdown,
            extra=extra,
        ),
        r1=SHUT_PEER.format(
            name="r1",
            rid=b_rid,
            addr=1,
            local_as="65001",
            peer="10.0.0.0",
            remote_as="65000",
            shutdown="",
            extra="",
        ),
    )


def test_bgp_peer_only_reachable_over_a_shut_interface(tmp_path: Path) -> None:
    pack = bgp_shutdown_pair(tmp_path, shutdown="   shutdown\n")
    findings = {f.rule: f for f in evaluate(pack)}
    assert "bgp-peer-behind-shutdown" in findings
    assert findings["bgp-peer-behind-shutdown"].device == "r0"
    assert findings["bgp-peer-behind-shutdown"].severity is Severity.HIGH


def test_bgp_update_source_that_is_shut_down(tmp_path: Path) -> None:
    pack = pack_from(
        tmp_path,
        r0=(
            "hostname r0\n"
            "interface Loopback0\n   ip address 10.255.0.1/32\n   shutdown\n"
            "interface Ethernet1\n   no switchport\n   ip address 10.0.0.0/31\n"
            "router bgp 65000\n"
            "   router-id 10.255.0.1\n"
            "   neighbor 10.255.0.2 remote-as 65000\n"
            "   neighbor 10.255.0.2 update-source Loopback0\n"
        ),
        r1=(
            "hostname r1\n"
            "interface Loopback0\n   ip address 10.255.0.2/32\n"
            "interface Ethernet1\n   no switchport\n   ip address 10.0.0.1/31\n"
            "router bgp 65000\n"
            "   router-id 10.255.0.2\n"
            "   neighbor 10.255.0.1 remote-as 65000\n"
            "   neighbor 10.255.0.1 update-source Loopback0\n"
        ),
    )
    findings = {f.rule: f for f in evaluate(pack)}
    assert "bgp-peer-behind-shutdown" in findings
    assert "Loopback0" in findings["bgp-peer-behind-shutdown"].title


def test_bgp_peer_over_a_live_interface_is_silent(tmp_path: Path) -> None:
    """The interface carrying the peer's subnet is up, so nothing about the
    peering is prevented by administrative state and the rule has no claim."""
    assert "bgp-peer-behind-shutdown" not in rules_fired(bgp_shutdown_pair(tmp_path))


def test_a_deliberately_shut_neighbour_is_not_a_broken_peering(
    tmp_path: Path,
) -> None:
    """`neighbor ... shutdown` says the operator meant the session to be down, so
    the interface underneath it being down as well is not news."""
    pack = bgp_shutdown_pair(
        tmp_path,
        shutdown="   shutdown\n",
        extra="   neighbor 10.0.0.1 shutdown\n",
    )
    assert "bgp-peer-behind-shutdown" not in rules_fired(pack)


def test_two_devices_claiming_one_bgp_router_id(tmp_path: Path) -> None:
    pack = bgp_shutdown_pair(tmp_path, a_rid=1, b_rid=1)
    findings = {f.rule: f for f in evaluate(pack)}
    assert "bgp-router-id-duplicate" in findings
    assert findings["bgp-router-id-duplicate"].severity is Severity.HIGH
    assert "10.255.0.1" in findings["bgp-router-id-duplicate"].title


def test_distinct_router_ids_are_silent(tmp_path: Path) -> None:
    """Two devices with router-ids of their own collide over nothing; the rule is
    about the identifier being shared, not about it being configured."""
    assert "bgp-router-id-duplicate" not in rules_fired(bgp_pair(tmp_path))


def test_the_shipped_corpus_stays_quiet_under_the_new_rules() -> None:
    """The corpus is valid apart from the timing asymmetry the TIMING tier owns, so
    every one of these rules firing on it would be a false positive."""
    pack, _ = build_fact_pack(CORPUS)
    for rule_id in (
        "subnet-mask-disagreement",
        "device-isolated-by-shutdown",
        "access-vlan-not-trunked",
        "trunk-native-vlan-not-allowed",
        "fhrp-members-on-different-subnets",
        "bgp-peer-behind-shutdown",
        "bgp-router-id-duplicate",
    ):
        assert rule_id not in rules_fired(pack)


# ---------------------------------------------------------------------------
# Malformed input that used to be read as healthy
# ---------------------------------------------------------------------------


def test_a_virtual_address_that_is_not_an_address_is_reported(tmp_path: Path) -> None:
    pack = pack_from(
        tmp_path,
        r1="""hostname r1
vlan 14
interface Vlan14
   ip address 10.14.0.2/24
   vrrp 14 ipv4 10.14.0.300
   vrrp 14 priority-level 110
""",
    )
    assert "fhrp-virtual-not-an-address" in rules_fired(pack)


def test_a_mistyped_virtual_address_does_not_take_the_run_down(
    tmp_path: Path,
) -> None:
    """Every other rule about the virtual address skips a group it cannot read.

    One of them used to raise instead, which cost the reader every finding on
    every other device as well.
    """
    pack = pack_from(
        tmp_path,
        r1="""hostname r1
vlan 14
interface Vlan14
   ip address 10.14.0.2/24
   vrrp 14 ipv4 not-an-address
""",
        r2="""hostname r2
vlan 24
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 24
interface Ethernet2
   switchport access vlan 99
""",
    )
    fired = rules_fired(pack)
    assert "fhrp-virtual-not-an-address" in fired
    assert "vlan-not-declared" in fired, "the other device still got checked"


def test_a_readable_virtual_address_is_not_reported_as_unreadable(
    tmp_path: Path,
) -> None:
    """The rule exists for a string that names no address, not for one that
    names an address someone dislikes."""
    pack = pair(tmp_path)
    assert "fhrp-virtual-not-an-address" not in rules_fired(pack)


# ---------------------------------------------------------------------------
# The change a finding carries, where a rule can state one (PROJECT.md §5.4)
# ---------------------------------------------------------------------------


def _found(pack: StaticFactPack, rule_id: str) -> Finding:
    return next(f for f in evaluate(pack) if f.rule == rule_id)


def test_a_one_sided_peering_carries_the_statement_the_far_end_needs(
    tmp_path: Path,
) -> None:
    """Every value in it is known: the address this device peers from and both
    AS numbers. Nothing is left to guess, which is why this rule can say it."""
    examples = Path(__file__).resolve().parents[1] / "examples" / "two-site"
    pack, _ = build_fact_pack(examples)
    finding = _found(pack, "bgp-session-one-sided")
    assert finding.change
    assert finding.change[0].startswith("router bgp ")
    assert "remote-as" in finding.change[-1]


def test_a_preferred_master_carries_the_line_that_makes_it_reclaim(
    tmp_path: Path,
) -> None:
    """`no vrrp 14 preempt` rather than an omitted `preempt`, because VRRP
    preempts by default and the omission does not reach this rule at all. The
    negation is what actually produces a preferred master that will not come
    back, and it is the configuration the suggested change has to undo."""
    without = pack_from(
        tmp_path,
        r1="""hostname r1
vlan 14
interface Vlan14
   ip address 10.14.0.2/24
   vrrp 14 ipv4 10.14.0.1
   vrrp 14 priority-level 110
   no vrrp 14 preempt
""",
        r2="""hostname r2
vlan 14
interface Vlan14
   ip address 10.14.0.3/24
   vrrp 14 ipv4 10.14.0.1
   vrrp 14 priority-level 100
""",
    )
    finding = _found(without, "fhrp-no-preempt-on-preferred")
    # Content, not padding: the indentation is the dialect's business and these
    # fragments do not state which dialect they are.
    assert finding.change[0] == "interface Vlan14"
    assert finding.change[-1].strip().endswith("preempt")


def test_a_native_vlan_carries_the_line_that_permits_it(tmp_path: Path) -> None:
    pack = pack_from(
        tmp_path,
        r1="""hostname r1
vlan 10,20
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 10
   switchport trunk native vlan 20
""",
    )
    finding = _found(pack, "trunk-native-vlan-not-allowed")
    assert finding.change[0] == "interface Ethernet1"
    assert finding.change[-1].strip() == "switchport trunk allowed vlan add 20"


def test_no_rule_suggests_a_change_it_cannot_state(tmp_path: Path) -> None:
    """A suggestion that is wrong half the time is worse than none.

    Every change a rule emits must name an interface or a process block and
    nothing else — a bare setting with no context is not something anyone can
    paste.
    """
    examples = Path(__file__).resolve().parents[1] / "examples" / "two-site"
    pack, _ = build_fact_pack(examples)
    for finding in evaluate(pack):
        if not finding.change:
            continue
        head = finding.change[0]
        assert head.startswith(("interface ", "router bgp ")), head
        assert len(finding.change) > 1, finding.rule


def test_the_two_ways_of_not_preempting_read_differently(tmp_path: Path) -> None:
    """A line that says `no preempt` and a protocol that defaults it off are
    the same flag and two different situations.

    The first is a decision somebody made and this reports it so the decision is
    visible. The second is a default nobody looked at, and the priorities were
    very likely written by someone who believed the higher one would win — which
    is a different remedy and the commoner of the two. The flag alone cannot
    tell them apart, which is what `preempt_source` is for.
    """
    hsrp = (
        "hostname {name}\n!\nvlan 14\n!\ninterface Vlan14\n"
        " ip address 198.51.100.{host} 255.255.255.0\n"
        " standby 14 ip 198.51.100.1\n"
        " standby 14 priority {priority}\n{extra}!\n"
    )

    def build(extra: str) -> Finding:
        directory = tmp_path / ("off" if extra else "default")
        directory.mkdir()
        (directory / "dist-1.cfg").write_text(
            hsrp.format(name="dist-1", host=2, priority=120, extra=extra)
        )
        (directory / "dist-2.cfg").write_text(
            hsrp.format(name="dist-2", host=3, priority=100, extra="")
        )
        pack, _ = build_fact_pack(directory)
        found = [f for f in evaluate(pack) if f.rule == "fhrp-no-preempt-on-preferred"]
        assert len(found) == 1, f"expected one finding, got {found}"
        return found[0]

    inherited = build("")
    deliberate = build(" no standby 14 preempt\n")

    assert "defaults it off" in inherited.detail
    assert "turned off on it" in deliberate.detail
    assert inherited.remedy != deliberate.remedy
    assert "lower this device's priority" in (inherited.remedy or "")
    # The suggested change is the same either way, and correctly so: the
    # positive form of the command is what cancels the negative one on every
    # dialect here, so it is the edit for a group that turned preempt off as
    # much as for one that never turned it on. Only the sentence moves.
    assert deliberate.change == inherited.change
    assert inherited.change[-1].strip().endswith("preempt")


# ---------------------------------------------------------------------------
# Broadcast domains — what `l2_segments` and `l2_adjacencies` decide
# ---------------------------------------------------------------------------

REPO: Final = Path(__file__).resolve().parents[1]

# Every corpus this repository ships, all of which are meant to be free of
# layer-2 partitions. RFC 5737 documentation space throughout, like the fixtures.
SHIPPED: Final = (
    REPO / "examples" / "two-site",
    REPO / "examples" / "xr-metro",
    REPO / "scenarios" / "site14_vrrp_lockstep" / "configs",
    REPO / "scenarios" / "hsrp_preempt_split" / "configs",
)

BROADCAST_AGG: Final = """hostname {name}
vlan 10,20
interface Ethernet1
   description uplink
   switchport mode trunk
   switchport trunk allowed vlan {allowed}
interface Vlan20
   ip address 192.0.2.{host}/24
{extra}"""

GROUP_MEMBER: Final = """   vrrp 20 ipv4 192.0.2.1
   vrrp 20 priority-level {priority}
   vrrp 20 preempt
"""


def broadcast_pair(
    tmp_path: Path,
    *,
    a_allowed: str = "10,20",
    b_allowed: str = "10,20",
    a_extra: str = "",
    b_extra: str = "",
) -> StaticFactPack:
    """Two gateways with an SVI in VLAN 20, each trunking what it is told to.

    Both are addressed in 192.0.2.0/24, so the pack holds them as one subnet
    whatever their trunks say — which is the disagreement these rules read.
    """
    return pack_from(
        tmp_path,
        **{
            "agg-a": BROADCAST_AGG.format(
                name="agg-a", allowed=a_allowed, host=2, extra=a_extra
            ),
            "agg-b": BROADCAST_AGG.format(
                name="agg-b", allowed=b_allowed, host=3, extra=b_extra
            ),
        },
    )


def test_a_subnet_whose_two_halves_cannot_reach_each_other(tmp_path: Path) -> None:
    pack = broadcast_pair(tmp_path, b_allowed="10")
    finding = _found(pack, "vlan-segment-split")
    assert finding.severity is Severity.HIGH
    # The half that provably cannot carry the VLAN is the one named, because it
    # is the one whose trunk has to change.
    assert finding.device == "agg-b"
    assert "192.0.2.0/24" in finding.title
    assert "agg-b:Vlan20" in finding.title
    assert finding.change == (
        "interface Ethernet1",
        "   switchport trunk allowed vlan add 20",
    )


def test_a_split_subnet_is_cited_at_the_svi_that_is_stranded(tmp_path: Path) -> None:
    """The finding has to send a reader to a line (PROJECT.md §5.4), and the SVI
    is the one stanza that is unambiguously about this VLAN on this device."""
    pack = broadcast_pair(tmp_path, b_allowed="10")
    finding = next(
        f for f in locate(evaluate(pack), pack) if f.rule == "vlan-segment-split"
    )
    assert finding.source is not None
    assert finding.source.file == "agg-b.cfg"
    assert finding.source.line is not None


def test_a_vlan_both_uplinks_permit_is_one_broadcast_domain(tmp_path: Path) -> None:
    """The ordinary configuration: both ends trunk the VLAN, so the co-membership
    graph joins them and there is one broadcast domain to be in."""
    assert "vlan-segment-split" not in rules_fired(broadcast_pair(tmp_path))


def test_a_switch_missing_from_the_directory_does_not_split_its_neighbours(
    tmp_path: Path,
) -> None:
    """The failure mode that would make these rules useless: a real directory is
    almost never the whole network, and the switch between two gateways is the
    device most often left out of one. Both gateways permit VLAN 20 on a trunk,
    so they are joined whether or not what is between them was collected."""
    pack = broadcast_pair(tmp_path)
    assert [d.id for d in pack.devices] == ["agg-a", "agg-b"]
    assert "vlan-segment-split" not in rules_fired(pack)


def test_a_trunk_that_states_no_allowed_list_is_not_a_split(tmp_path: Path) -> None:
    """A trunk with no allowed list permits every VLAN on real hardware, and an
    empty `allowed_vlans` in the pack is equally consistent with a construct no
    parser read. Either way the device may well be carrying VLAN 20."""
    bare = """hostname agg-b
vlan 10,20
interface Ethernet1
   switchport mode trunk
interface Vlan20
   ip address 192.0.2.3/24
"""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": BROADCAST_AGG.format(
                name="agg-a", allowed="10,20", host=2, extra=""
            ),
            "agg-b": bare,
        },
    )
    assert "vlan-segment-split" not in rules_fired(pack)


def test_a_device_with_no_trunk_at_all_is_not_half_a_segment(tmp_path: Path) -> None:
    """A router terminating a VLAN it does not bridge has no trunk to omit it
    from — the same reading `svi-vlan-not-trunked` gives that shape — and a
    switch whose uplink nothing parsed looks exactly like one."""
    router = """hostname rtr1
vlan 20
interface Vlan20
   ip address 192.0.2.3/24
"""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": BROADCAST_AGG.format(
                name="agg-a", allowed="10,20", host=2, extra=""
            ),
            "rtr1": router,
        },
    )
    assert "vlan-segment-split" not in rules_fired(pack)


def test_the_only_gateway_in_a_subnet_is_not_a_half_of_one(tmp_path: Path) -> None:
    """One device addressed in the subnet is `l3-interface-isolated`'s subject:
    there is no second half for it to be cut off from, and the far end being
    outside the directory is the commonest reason for it."""
    pack = pack_from(
        tmp_path,
        **{"agg-b": BROADCAST_AGG.format(name="agg-b", allowed="10", host=3, extra="")},
    )
    assert "vlan-segment-split" not in rules_fired(pack)


def test_a_shut_svi_is_not_a_stranded_half(tmp_path: Path) -> None:
    """An SVI that is administratively down is in no broadcast domain, so it is
    not in one that has been divided. Reporting it would tell the operator to
    edit a trunk to repair an interface they turned off."""
    pack = broadcast_pair(tmp_path, b_allowed="10", b_extra="   shutdown\n")
    assert "vlan-segment-split" not in rules_fired(pack)


def test_an_unaddressed_svi_is_not_a_stranded_half(tmp_path: Path) -> None:
    """The finding is about a subnet with gateways on both sides of a divide. An
    SVI with no address is on neither side of anything."""
    bare = """hostname agg-b
vlan 10,20
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 10
interface Vlan20
   description held for a future tenant
"""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": BROADCAST_AGG.format(
                name="agg-a", allowed="10,20", host=2, extra=""
            ),
            "agg-b": bare,
        },
    )
    assert "vlan-segment-split" not in rules_fired(pack)


def test_a_subinterface_tagging_the_vlan_off_the_box_is_not_a_split(
    tmp_path: Path,
) -> None:
    """A dot1q subinterface puts a VLAN on the wire with no switchport involved,
    so the trunk lists do not describe every way the VLAN can leave. Written by
    editing the fact pack because the dialect that populates `dot1q_vlan` names
    its SVIs `BVI<n>`, which is placed in no segment — the guard is nonetheless
    the one thing standing between this rule and a false positive on any parser
    that learns subinterfaces."""
    pack = broadcast_pair(tmp_path, b_allowed="10")
    assert "vlan-segment-split" in rules_fired(pack)
    tagged = replace(
        pack,
        devices=tuple(
            device
            if device.id != "agg-b"
            else replace(
                device,
                interfaces=tuple(
                    interface
                    if interface.name != "Ethernet1"
                    else replace(interface, dot1q_vlan=20)
                    for interface in device.interfaces
                ),
            )
            for device in pack.devices
        ),
    )
    assert "vlan-segment-split" not in rules_fired(tagged)


def test_a_group_whose_members_cannot_hear_each_other(tmp_path: Path) -> None:
    pack = broadcast_pair(
        tmp_path,
        b_allowed="10",
        a_extra=GROUP_MEMBER.format(priority=110),
        b_extra=GROUP_MEMBER.format(priority=100),
    )
    finding = _found(pack, "fhrp-members-in-different-segments")
    assert finding.severity is Severity.HIGH
    assert finding.device == "agg-b"
    assert "VRRP 20" in finding.title
    assert "192.0.2.1" in finding.detail
    assert finding.change[0] == "interface Ethernet1"


def test_members_on_one_segment_are_not_split(tmp_path: Path) -> None:
    """Both ends trunk the VLAN their SVIs are in, which is the whole of what the
    rule asks: the advertisements have a path between the two members."""
    pack = broadcast_pair(
        tmp_path,
        a_extra=GROUP_MEMBER.format(priority=110),
        b_extra=GROUP_MEMBER.format(priority=100),
    )
    assert "fhrp-members-in-different-segments" not in rules_fired(pack)


def test_a_group_on_interfaces_the_pack_cannot_place(tmp_path: Path) -> None:
    """IOS-XR names its SVIs `BVI14`, so the VLAN a member is in cannot be read
    off the interface name and the pack places it in no broadcast domain. The
    rule has nothing to compare and says nothing, rather than reading "not in a
    segment" as "not in the same segment"."""
    pack, _ = build_fact_pack(REPO / "examples" / "xr-metro")
    assert [group.label for group in pack.fhrp_groups]
    assert "fhrp-members-in-different-segments" not in rules_fired(pack)


def test_a_group_split_across_two_vlan_ids_is_the_other_rule(tmp_path: Path) -> None:
    """Members on Vlan20 and Vlan30 sharing a subnet are in different broadcast
    domains because the numbers differ, not because a trunk prunes one, and the
    remedy is a renumbering rather than a trunk edit. `subnet-spans-two-vlans`
    is the finding for that, and it fires here."""
    a = BROADCAST_AGG.format(
        name="agg-a",
        allowed="10,20,30",
        host=2,
        extra=GROUP_MEMBER.format(priority=110),
    )
    b = BROADCAST_AGG.format(
        name="agg-b",
        allowed="10,20,30",
        host=3,
        extra=GROUP_MEMBER.format(priority=100),
    ).replace("interface Vlan20", "interface Vlan30")
    pack = pack_from(tmp_path, **{"agg-a": a, "agg-b": b})
    fired = rules_fired(pack)
    assert "fhrp-members-in-different-segments" not in fired
    assert "subnet-spans-two-vlans" in fired


def test_a_one_member_group_is_not_a_split_one(tmp_path: Path) -> None:
    """A group with one member has nothing to be separated from, and
    `fhrp-no-redundancy` is what reports it."""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": BROADCAST_AGG.format(
                name="agg-a",
                allowed="10",
                host=2,
                extra=GROUP_MEMBER.format(priority=110),
            )
        },
    )
    assert "fhrp-members-in-different-segments" not in rules_fired(pack)


def two_vlan_subnet(
    tmp_path: Path, *, native: str = "", far: str = ""
) -> StaticFactPack:
    """One subnet, an SVI at each end, and the far end numbered VLAN 30."""
    a = BROADCAST_AGG.format(
        name="agg-a", allowed="10,20,30", host=2, extra=""
    ).replace(
        "   switchport trunk allowed vlan 10,20,30\n",
        f"   switchport trunk allowed vlan 10,20,30\n{native}",
    )
    b = BROADCAST_AGG.format(
        name="agg-b", allowed="10,20,30", host=3, extra=""
    ).replace("interface Vlan20", "interface Vlan30")
    return pack_from(tmp_path, **{"agg-a": a, "agg-b": b + far})


def test_one_subnet_terminated_on_two_different_vlans(tmp_path: Path) -> None:
    pack = two_vlan_subnet(tmp_path)
    finding = _found(pack, "subnet-spans-two-vlans")
    assert finding.severity is Severity.HIGH
    assert "192.0.2.0/24" in finding.title
    assert "VLAN 30" in finding.detail
    # No change: which of the two numbers was meant is a VLAN plan the
    # configuration does not contain.
    assert finding.change == ()


def test_a_subnet_whose_gateways_share_a_vlan_is_silent(tmp_path: Path) -> None:
    """Both SVIs in VLAN 20 is the ordinary case, and the one the derived
    `over_l2_segment` names: the subnet rides a broadcast domain both are in."""
    assert "subnet-spans-two-vlans" not in rules_fired(broadcast_pair(tmp_path))


def test_a_native_vlan_can_join_two_ids_so_nothing_is_claimed(tmp_path: Path) -> None:
    """Untagged frames leave a trunk with no id at all and land in whatever the
    far end calls native, so a VLAN that is native somewhere can genuinely be one
    broadcast domain with a differently numbered one. The configuration does not
    say whether it is, so the rule does not either."""
    pack = two_vlan_subnet(tmp_path, native="   switchport trunk native vlan 20\n")
    assert "subnet-spans-two-vlans" not in rules_fired(pack)


def test_a_routed_interface_in_the_subnet_leaves_the_tagging_unknown(
    tmp_path: Path,
) -> None:
    """A routed port carries no VLAN id in its name, so a subnet with one in it
    is a subnet whose tagging the pack does not know — not one it knows to be
    inconsistent."""
    router = """hostname rtr1
interface Ethernet5
   no switchport
   ip address 192.0.2.9/24
"""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": BROADCAST_AGG.format(
                name="agg-a", allowed="10,20", host=2, extra=""
            ),
            "rtr1": router,
        },
    )
    assert "subnet-spans-two-vlans" not in rules_fired(pack)


@pytest.mark.parametrize("corpus", SHIPPED, ids=lambda path: path.parent.name)
def test_the_shipped_corpora_hold_no_broadcast_domain_defects(corpus: Path) -> None:
    """Every corpus in this repository is a connected layer 2 by construction, so
    each of these rules firing on one would be a false positive — and the
    xr-metro configs, whose SVIs the segment builder cannot place at all, are the
    case where staying quiet is the entire point."""
    pack, _ = build_fact_pack(corpus)
    fired = rules_fired(pack)
    for rule_id in (
        "vlan-segment-split",
        "fhrp-members-in-different-segments",
        "subnet-spans-two-vlans",
    ):
        assert rule_id not in fired


# --------------------------------------------------------------------------
# Spanning tree
#
# The election these read is a comparison between bridges, so every fixture is
# a whole segment rather than one config: what a bridge is running only means
# something next to what the other bridges in its broadcast domain are.
# --------------------------------------------------------------------------

STP_BRIDGE: Final = """hostname {name}
{stp}vlan 10
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 10
interface Ethernet2
   switchport mode trunk
   switchport trunk allowed vlan 10
{svi}"""

STP_SVI: Final = """interface Vlan10
   ip address 192.0.2.{host}/24
"""

# Enough spanning-tree timing to make a device state one, and correct by
# 802.1D so `stp-timers-outside-the-standard` has nothing to say about a
# fixture written for a different rule. The mode rule needs these: a mode
# reaches the pack attached to a timer record and nowhere else.
RAPID_PVST: Final = """spanning-tree mode rapid-pvst
spanning-tree vlan 10 hello-time 2
spanning-tree vlan 10 forward-time 15
spanning-tree vlan 10 max-age 20
"""

MST: Final = """spanning-tree mode mst
spanning-tree mst hello-time 2
spanning-tree mst forward-time 15
spanning-tree mst max-age 20
"""


def bridge(name: str, *, stp: str = "", host: int | None = None) -> str:
    """One switch in VLAN 10's broadcast domain, with or without a gateway."""
    return STP_BRIDGE.format(
        name=name, stp=stp, svi="" if host is None else STP_SVI.format(host=host)
    )


def segment(tmp_path: Path, **bridges: str) -> StaticFactPack:
    return pack_from(tmp_path, **bridges)


def test_two_bridges_configured_to_the_same_lowest_priority(tmp_path: Path) -> None:
    pack = segment(
        tmp_path,
        **{
            "acc1": bridge("acc1"),
            "agg-a": bridge("agg-a", stp="spanning-tree vlan 10 priority 8192\n"),
            "agg-b": bridge("agg-b", stp="spanning-tree vlan 10 priority 8192\n"),
        },
    )
    finding = _found(pack, "stp-root-tie")
    assert finding.severity is Severity.MEDIUM
    assert finding.device == "agg-a"
    assert "agg-a and agg-b" in finding.title
    assert "VLAN 10" in finding.title
    assert "8192" in finding.title
    # The whole election, not only the tied half: a reader has to be able to
    # see that the bridge left at the default was compared and lost.
    assert finding.evidence == (
        "acc1 VLAN 10 bridge priority 32768",
        "agg-a VLAN 10 bridge priority 8192",
        "agg-b VLAN 10 bridge priority 8192",
    )


def test_a_tied_root_election_is_cited_at_the_vlan_it_is_about(
    tmp_path: Path,
) -> None:
    """A finding has to send a reader to a line (PROJECT.md §5.4). The VLAN
    declaration is the one stanza on the device that this finding is about —
    the priority itself is a top-level line no `config_line` records."""
    pack = segment(
        tmp_path,
        **{
            "agg-a": bridge("agg-a", stp="spanning-tree vlan 10 priority 8192\n"),
            "agg-b": bridge("agg-b", stp="spanning-tree vlan 10 priority 8192\n"),
        },
    )
    finding = next(f for f in locate(evaluate(pack), pack) if f.rule == "stp-root-tie")
    assert finding.source is not None
    assert finding.source.file == "agg-a.cfg"
    assert finding.source.line is not None


def test_a_priority_this_tool_did_not_read_leaves_the_election_open(
    tmp_path: Path,
) -> None:
    """The failure mode that would make this rule useless. `spanning-tree mst 0
    priority 4096` sets a priority whose VLANs are in a block nothing parses, so
    acc1 might be lower than either of the two that are tied — and a bridge
    whose line went unread must not be counted as one sitting at the default."""
    pack = segment(
        tmp_path,
        **{
            "acc1": bridge("acc1", stp="spanning-tree mst 0 priority 4096\n"),
            "agg-a": bridge("agg-a", stp="spanning-tree vlan 10 priority 8192\n"),
            "agg-b": bridge("agg-b", stp="spanning-tree vlan 10 priority 8192\n"),
        },
    )
    assert dict(pack.l2_segments[0].bridge_priorities) == {"agg-a": 8192, "agg-b": 8192}
    assert "stp-root-tie" not in rules_fired(pack)


def test_a_root_primary_macro_is_a_priority_and_not_a_number(tmp_path: Path) -> None:
    """The other form of the same withdrawal. `root primary` lands on a value
    that depends on what the current root was advertising when it was typed, so
    the one thing that can be said is that this bridge is not at the default —
    which is exactly the inference the rest of the segment would have needed."""
    pack = segment(
        tmp_path,
        **{
            "acc1": bridge("acc1", stp="spanning-tree vlan 10 root primary\n"),
            "agg-a": bridge("agg-a", stp="spanning-tree vlan 10 priority 8192\n"),
            "agg-b": bridge("agg-b", stp="spanning-tree vlan 10 priority 8192\n"),
        },
    )
    assert "acc1" not in dict(pack.l2_segments[0].bridge_priorities)
    assert "stp-root-tie" not in rules_fired(pack)


def test_a_segment_where_nobody_chose_a_root_is_not_a_tie(tmp_path: Path) -> None:
    """Every bridge on 32768 is a root nobody chose, which is real and is a
    different claim: it rests on reading an absence as a decision, and one
    uncollected bridge with a priority on it makes it false."""
    pack = segment(
        tmp_path, **{"acc1": bridge("acc1"), "agg-a": bridge("agg-a", host=2)}
    )
    assert dict(pack.l2_segments[0].bridge_priorities) == {
        "acc1": 32768,
        "agg-a": 32768,
    }
    assert "stp-root-tie" not in rules_fired(pack)


def test_an_election_with_one_winner_is_not_a_tie(tmp_path: Path) -> None:
    """One bridge strictly lowest is a root that was chosen, which is the whole
    point of writing a priority down."""
    pack = segment(
        tmp_path,
        **{
            "agg-a": bridge(
                "agg-a", stp="spanning-tree vlan 10 priority 4096\n", host=2
            ),
            "agg-b": bridge(
                "agg-b", stp="spanning-tree vlan 10 priority 8192\n", host=3
            ),
        },
    )
    assert pack.l2_segments[0].root_bridge == "agg-a"
    assert "stp-root-tie" not in rules_fired(pack)


def test_the_root_bridge_holds_no_address_in_the_vlan(tmp_path: Path) -> None:
    pack = segment(
        tmp_path,
        **{
            "acc1": bridge("acc1", stp="spanning-tree vlan 10 priority 4096\n"),
            "agg-a": bridge("agg-a", host=2),
            "agg-b": bridge("agg-b", host=3),
        },
    )
    finding = _found(pack, "stp-root-is-not-the-gateway")
    assert finding.severity is Severity.LOW
    assert finding.device == "acc1"
    assert "VLAN 10" in finding.title
    assert "acc1" in finding.title
    assert "agg-a:Vlan10" in finding.detail
    assert "acc1 VLAN 10 bridge priority 4096" in finding.evidence


def test_a_root_that_holds_the_gateway_is_the_arrangement_asked_for(
    tmp_path: Path,
) -> None:
    """The rule exists to ask for this, so finding it is silence by definition."""
    pack = segment(
        tmp_path,
        **{
            "acc1": bridge("acc1"),
            "agg-a": bridge(
                "agg-a", stp="spanning-tree vlan 10 priority 4096\n", host=2
            ),
        },
    )
    assert pack.l2_segments[0].root_bridge == "agg-a"
    assert "stp-root-is-not-the-gateway" not in rules_fired(pack)


def test_a_vlan_with_no_gateway_has_no_misplaced_root(tmp_path: Path) -> None:
    """A pure layer-2 domain, or one whose gateway was not collected. Neither is
    a root in the wrong place, and the second is the shape a partial directory
    takes — the missing device must not make the switches look misconfigured."""
    pack = segment(
        tmp_path,
        **{
            "acc1": bridge("acc1", stp="spanning-tree vlan 10 priority 4096\n"),
            "acc2": bridge("acc2"),
        },
    )
    assert pack.l2_segments[0].root_bridge == "acc1"
    assert "stp-root-is-not-the-gateway" not in rules_fired(pack)


def test_a_tied_election_has_no_root_to_be_in_the_wrong_place(
    tmp_path: Path,
) -> None:
    """Two bridges on the lowest priority is `stp-root-tie`, and until the tie
    is broken there is no root whose placement could be reported."""
    pack = segment(
        tmp_path,
        **{
            "acc1": bridge("acc1", stp="spanning-tree vlan 10 priority 4096\n"),
            "acc2": bridge("acc2", stp="spanning-tree vlan 10 priority 4096\n"),
            "agg-a": bridge("agg-a", host=2),
        },
    )
    assert pack.l2_segments[0].root_bridge is None
    assert "stp-root-is-not-the-gateway" not in rules_fired(pack)


def test_two_spanning_tree_modes_in_one_broadcast_domain(tmp_path: Path) -> None:
    pack = segment(
        tmp_path,
        **{"agg-a": bridge("agg-a", stp=MST), "agg-b": bridge("agg-b", stp=RAPID_PVST)},
    )
    finding = _found(pack, "stp-mode-disagreement")
    assert finding.severity is Severity.MEDIUM
    assert "VLAN 10" in finding.title
    assert "mst" in finding.title and "rapid-pvst" in finding.title
    assert finding.trigger is not None
    assert finding.evidence == (
        "agg-a spanning-tree mode mst",
        "agg-b spanning-tree mode rapid-pvst",
    )


def test_one_mode_across_the_whole_segment_is_silent(tmp_path: Path) -> None:
    """The ordinary configuration, and the one the segment records as its own:
    `stp_mode` is the mode every member that states one agrees on."""
    pack = segment(
        tmp_path,
        **{
            "agg-a": bridge("agg-a", stp=RAPID_PVST),
            "agg-b": bridge("agg-b", stp=RAPID_PVST),
        },
    )
    assert pack.l2_segments[0].stp_mode is StpMode.RAPID_PVST
    assert "stp-mode-disagreement" not in rules_fired(pack)


def test_a_bridge_that_states_a_mode_and_no_timer_cannot_be_named(
    tmp_path: Path,
) -> None:
    """A mode reaches the Fact Pack attached to a timer record and nowhere else.
    The segment can see that its members do not agree — `stp_mode` falls back to
    NONE — and the rule cannot say which bridge runs which, so it says nothing
    rather than reporting a disagreement between two unidentified devices."""
    pack = segment(
        tmp_path,
        **{
            "agg-a": bridge("agg-a", stp="spanning-tree mode mst\n"),
            "agg-b": bridge("agg-b", stp=RAPID_PVST),
        },
    )
    assert pack.l2_segments[0].stp_mode is StpMode.NONE
    assert "stp-mode-disagreement" not in rules_fired(pack)


def test_a_bridge_with_no_mode_line_is_not_running_none(tmp_path: Path) -> None:
    """`spanning-tree mode none` and an unwritten mode line arrive as one value,
    so a bridge that simply never said reads exactly like one with spanning tree
    switched off. Reporting either as the other is the guess this refuses."""
    quiet = """spanning-tree hello-time 2
spanning-tree forward-time 15
spanning-tree max-age 20
"""
    pack = segment(
        tmp_path,
        **{"agg-a": bridge("agg-a", stp=quiet), "agg-b": bridge("agg-b", stp=MST)},
    )
    assert pack.l2_segments[0].stp_mode is StpMode.MST
    assert "stp-mode-disagreement" not in rules_fired(pack)


@pytest.mark.parametrize("corpus", SHIPPED, ids=lambda path: path.parent.name)
def test_the_shipped_corpora_hold_no_root_election_defects(corpus: Path) -> None:
    """Not one configuration in this repository states a bridge priority or a
    spanning-tree mode, so every bridge in every segment sits at the default,
    no election has a winner and none of these rules has anything to report.
    A finding here would mean one of them had inferred a decision from silence."""
    pack, _ = build_fact_pack(corpus)
    fired = rules_fired(pack)
    for rule_id in (
        "stp-root-tie",
        "stp-root-is-not-the-gateway",
        "stp-mode-disagreement",
    ):
        assert rule_id not in fired
