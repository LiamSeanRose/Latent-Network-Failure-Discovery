"""IPv6 addressing and IPv6 FHRP, across all three dialects and the FACTS rules.

One file rather than three, because this is one feature that had to land in
three parsers at once: the syntax differs per dialect but the fact it produces —
an `IpAssignment` in the IPv6 family, an `FhrpGroup` whose identity includes its
family — is the same everywhere, and so is every rule that then has to read it.

The rules half is mostly silence. A dual-stack config is the same network
described twice, and the failure mode being guarded against is a rule comparing
one description against the other: an IPv4 virtual address judged against an
IPv6 subnet, one wire's MTU reported once per family, a group's two halves read
as a group split across two subnets. None of those is a defect, and all of them
look like one to a rule written when only IPv4 existed.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Final

from cassandra.factpack.builders import build_fact_pack, parse
from cassandra.factpack.builders.common import assemble_fhrp_groups
from cassandra.factpack.builders.eos import parse_device as parse_eos
from cassandra.factpack.builders.ios import parse_device as parse_ios
from cassandra.factpack.builders.nxos import parse_device as parse_nxos
from cassandra.factpack.schema import AddressFamily, FhrpProtocol, StaticFactPack
from cassandra.facts.rules import evaluate

# Every address here is inside 2001:db8::/32, the RFC 3849 documentation prefix.
EOS_PAIR: Final = """hostname {name}
vlan 14
interface Ethernet1
   no switchport
   ip address 10.0.0.{p2p}/31
   ipv6 address 2001:db8:ff::{p2p}/127
interface Ethernet2
   switchport mode trunk
   switchport trunk allowed vlan 14
interface Vlan14
   ip address 10.14.0.{host}/24
   ipv6 address 2001:db8:14::{host}/64
   vrrp 14 ipv4 10.14.0.1
   vrrp 14 ipv6 2001:db8:14::1
   vrrp 14 priority-level {priority}
   vrrp 14 preempt
"""

IOS_PAIR: Final = """hostname {name}
ipv6 unicast-routing
interface GigabitEthernet0/0
 ip address 10.14.0.{host} 255.255.255.0
 ipv6 address 2001:DB8:14::{host}/64
 ipv6 enable
 vrrp 14 address-family ipv4
  address 10.14.0.1
  priority {priority}
  preempt delay minimum 30
 vrrp 14 address-family ipv6
  address FE80::1 primary
  address 2001:DB8:14::1
  priority {priority}
  preempt delay minimum 90
"""

NXOS_PAIR: Final = """hostname {name}
feature interface-vlan
feature hsrp
vlan 14
interface Vlan14
  no shutdown
  ip address 10.14.0.{host}/24
  ipv6 address 2001:db8:14::{host}/64
  ipv6 link-local fe80::{host}
  hsrp version 2
  hsrp 14
    ip 10.14.0.1
    priority {priority}
    preempt
  hsrp 14 ipv6
    ip 2001:db8:14::1
    priority {priority}
    preempt
"""


def pack_from(tmp_path: Path, **configs: str) -> StaticFactPack:
    """The fact pack these configs build, with its FHRP groups assembled per family.

    `build_fact_pack` still joins memberships into groups on a key that predates
    address families, so it merges each dual-stack pair into one group. Until
    that call site moves to `assemble_fhrp_groups`, replacing the groups here is
    what lets these tests state what the rules do with the groups the assembly
    produces rather than what one caller does with them today.
    """
    for name, text in configs.items():
        (tmp_path / f"{name}.cfg").write_text(text)
    pack, _ = build_fact_pack(tmp_path)
    return replace(
        pack,
        fhrp_groups=assemble_fhrp_groups(parse(text) for text in configs.values()),
    )


def rules_fired(pack: StaticFactPack) -> set[str]:
    return {finding.rule for finding in evaluate(pack)}


def eos_pair(tmp_path: Path) -> StaticFactPack:
    return pack_from(
        tmp_path,
        **{
            "agg-a": EOS_PAIR.format(name="agg-a", p2p=1, host=2, priority=110),
            "agg-b": EOS_PAIR.format(name="agg-b", p2p=3, host=3, priority=100),
        },
    )


def ios_pair(tmp_path: Path) -> StaticFactPack:
    return pack_from(
        tmp_path,
        **{
            "agg-a": IOS_PAIR.format(name="agg-a", host=2, priority=110),
            "agg-b": IOS_PAIR.format(name="agg-b", host=3, priority=100),
        },
    )


def nxos_pair(tmp_path: Path) -> StaticFactPack:
    return pack_from(
        tmp_path,
        **{
            "agg-a": NXOS_PAIR.format(name="agg-a", host=2, priority=110),
            "agg-b": NXOS_PAIR.format(name="agg-b", host=3, priority=100),
        },
    )


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def test_no_dialect_leaves_an_ipv6_line_unaccounted_for(tmp_path: Path) -> None:
    """The gap this closes was total: every IPv6 line landed in `unparsed_lines`,
    so the tool was honest about reading none of it. A parser's failure mode is
    silence, so the whole of each dual-stack config is checked, not the IPv6
    half alone."""
    for name, text in (
        ("eos", EOS_PAIR.format(name="agg-a", p2p=1, host=2, priority=110)),
        ("ios", IOS_PAIR.format(name="agg-a", host=2, priority=110)),
        ("nxos", NXOS_PAIR.format(name="agg-a", host=2, priority=110)),
    ):
        (tmp_path / f"{name}.cfg").write_text(text)
    _, unparsed = build_fact_pack(tmp_path)
    assert {device: lines for device, lines in unparsed.items() if lines} == {}


def test_eos_reads_both_families_off_one_vrrp_block() -> None:
    parsed = parse_eos(EOS_PAIR.format(name="agg-a", p2p=1, host=2, priority=110))
    vlan14 = next(i for i in parsed.device.interfaces if i.name == "Vlan14")
    assert [(a.address, a.family) for a in vlan14.addresses] == [
        ("10.14.0.2", AddressFamily.IPV4_UNICAST),
        ("2001:db8:14::2", AddressFamily.IPV6_UNICAST),
    ]
    assert [(r.number, r.family, r.virtual) for r in parsed.fhrp_records] == [
        (14, AddressFamily.IPV4_UNICAST, "10.14.0.1"),
        (14, AddressFamily.IPV6_UNICAST, "2001:db8:14::1"),
    ]


def test_ios_reads_the_vrrpv3_address_family_sub_mode() -> None:
    """The sub-mode's commands — `address`, `priority`, `preempt` — are the same
    words the interface level uses, so a parser that flattened the block would
    read a group's priority as the interface's."""
    parsed = parse_ios(IOS_PAIR.format(name="agg-a", host=2, priority=110))
    records = {record.family: record for record in parsed.fhrp_records}
    assert records.keys() == {
        AddressFamily.IPV4_UNICAST,
        AddressFamily.IPV6_UNICAST,
    }
    assert all(r.protocol is FhrpProtocol.VRRP for r in records.values())
    assert records[AddressFamily.IPV4_UNICAST].virtual == "10.14.0.1"
    # The link-local address is the RFC 5798 primary and the global one is what
    # a subnet check can be made against, so the global one is what is kept.
    assert records[AddressFamily.IPV6_UNICAST].virtual == "2001:DB8:14::1"


def test_ios_reads_hsrp_for_ipv6_as_a_second_group() -> None:
    parsed = parse_ios(
        "hostname r1\n"
        "interface GigabitEthernet0/0\n"
        " ip address 10.14.0.2 255.255.255.0\n"
        " ipv6 address 2001:DB8:14::2/64\n"
        " standby 14 ip 10.14.0.1\n"
        " standby 14 ipv6 2001:DB8:14::1\n"
        " standby 14 priority 110\n"
    )
    assert [(r.number, r.family, r.virtual) for r in parsed.fhrp_records] == [
        (14, AddressFamily.IPV4_UNICAST, "10.14.0.1"),
        (14, AddressFamily.IPV6_UNICAST, "2001:DB8:14::1"),
    ]
    # The settings are stated once for the group and apply to both families.
    assert {r.member.priority for r in parsed.fhrp_records} == {110}


def test_ios_keeps_an_interface_shutdown_out_of_a_vrrp_sub_mode() -> None:
    """`shutdown` means something in both places and `common.stanzas` strips the
    indentation that tells them apart, so the column each line began in is kept.
    Reading an interface `shutdown` as a group one leaves the interface up, and
    every rule about an isolated device then stays quiet about a dead box."""
    parsed = parse_ios(
        "hostname r1\n"
        "interface GigabitEthernet0/0\n"
        " ip address 10.14.0.2 255.255.255.0\n"
        " vrrp 14 address-family ipv4\n"
        "  address 10.14.0.1\n"
        " shutdown\n"
    )
    assert parsed.device.interfaces[0].admin_enabled is False


def test_nxos_reads_the_ipv6_hsrp_block() -> None:
    parsed = parse_nxos(NXOS_PAIR.format(name="agg-a", host=2, priority=110))
    assert [(r.number, r.family, r.virtual) for r in parsed.fhrp_records] == [
        (14, AddressFamily.IPV4_UNICAST, "10.14.0.1"),
        (14, AddressFamily.IPV6_UNICAST, "2001:db8:14::1"),
    ]


def test_nxos_reads_a_group_whose_address_is_autoconfigured() -> None:
    """`ip autoconfig` derives the virtual address from the prefix and the
    group's virtual MAC, so no configuration file states it. The group is real
    and has to appear; it simply has no address for the address rules to check."""
    parsed = parse_nxos(
        "hostname n1\n"
        "feature hsrp\n"
        "interface Vlan14\n"
        "  ipv6 address 2001:db8:14::2/64\n"
        "  hsrp 14 ipv6\n"
        "    ip autoconfig\n"
        "    priority 110\n"
    )
    assert parsed.unparsed_lines == ()
    assert [(r.family, r.virtual) for r in parsed.fhrp_records] == [
        (AddressFamily.IPV6_UNICAST, None)
    ]


def test_a_link_local_address_is_read_and_deliberately_not_recorded() -> None:
    """fe80::/10 is one hop wide and every IPv6 interface has an address in it
    whether anyone configured one or not. Recorded, it would put every interface
    in the collection into a single subnet, invent an L3 adjacency between every
    pair of devices and make the addressing rules report a network that does not
    exist — so the line is read, and the address is dropped."""
    parsed = parse_eos(
        "hostname r1\n"
        "interface Vlan14\n"
        "   ipv6 address 2001:db8:14::2/64\n"
        "   ipv6 address fe80::2/64 link-local\n"
    )
    assert parsed.unparsed_lines == ()
    assert [a.address for a in parsed.device.interfaces[0].addresses] == [
        "2001:db8:14::2"
    ]


def test_the_two_families_of_one_group_number_are_two_groups(tmp_path: Path) -> None:
    """VRRPv3 runs a separate virtual router per address family, so VRRP 14 for
    IPv4 and VRRP 14 for IPv6 elect independently and can sit on different
    devices. Folded into one group they would hold four members on two devices,
    and every device would be a member of the group twice."""
    pack = eos_pair(tmp_path)
    by_id = {group.id: group for group in pack.fhrp_groups}
    assert set(by_id) == {"vrrp-14", "vrrp-14-ipv6"}
    assert by_id["vrrp-14"].family is AddressFamily.IPV4_UNICAST
    assert by_id["vrrp-14"].virtual_ipv4 == "10.14.0.1"
    assert by_id["vrrp-14"].subnet == "10.14.0.0/24"
    assert by_id["vrrp-14-ipv6"].family is AddressFamily.IPV6_UNICAST
    assert by_id["vrrp-14-ipv6"].virtual_ipv6 == "2001:db8:14::1"
    assert by_id["vrrp-14-ipv6"].subnet == "2001:db8:14::/64"
    assert all(len(group.members) == 2 for group in pack.fhrp_groups)


def test_each_family_gets_its_own_timer_record(tmp_path: Path) -> None:
    """The timer inventory is joined back to a group by device, interface and
    instance. A dual-stack interface has two groups numbered 14 and IOS times
    them separately, so an instance naming only the number would make the join
    ambiguous and one of the two records would silently replace the other."""
    parsed = parse_ios(IOS_PAIR.format(name="agg-a", host=2, priority=110))
    assert {t.scope.instance: t.preempt_delay_ms for t in parsed.timers} == {
        "14": 30_000,
        "14 ipv6": 90_000,
    }


# --------------------------------------------------------------------------
# Rules: what a dual-stack config must not produce
# --------------------------------------------------------------------------


def test_a_clean_dual_stack_eos_pair_produces_nothing(tmp_path: Path) -> None:
    """The whole FACTS tier against a dual-stack pair with nothing wrong with
    it. Every cross-family false positive there is would show up here."""
    assert rules_fired(eos_pair(tmp_path)) == set()


def test_a_clean_dual_stack_ios_pair_produces_nothing(tmp_path: Path) -> None:
    """The same claim for the dialect that writes its IPv6 group in a sub-mode
    rather than on one line, whose virtual address is link-local."""
    assert rules_fired(ios_pair(tmp_path)) == set()


def test_a_clean_dual_stack_nxos_pair_produces_nothing(tmp_path: Path) -> None:
    """The same claim again for HSRP, whose IPv6 group is a separate block with
    its own priority rather than a second address on a shared one."""
    assert rules_fired(nxos_pair(tmp_path)) == set()


def test_an_ipv4_virtual_address_is_not_judged_against_an_ipv6_subnet(
    tmp_path: Path,
) -> None:
    """A dual-stack interface is on two subnets, and a virtual address can only
    be inside one of them. Judged against both, every group on every dual-stack
    interface in the world is outside a subnet it was never meant to be in."""
    pack = eos_pair(tmp_path)
    assert "fhrp-virtual-outside-subnet" not in rules_fired(pack)


def test_an_ipv6_group_on_an_ipv4_only_interface_is_not_outside_its_subnet(
    tmp_path: Path,
) -> None:
    """An IPv6 group whose interface carries no IPv6 address is missing an
    address, not holding one in the wrong place. The interface's IPv4 subnet is
    not a subnet its virtual address could have been inside, so reporting it as
    the one the address should have been in would name an unrelated prefix."""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": "hostname agg-a\nvlan 14\ninterface Vlan14\n"
            "   ip address 10.14.0.2/24\n"
            "   vrrp 14 ipv6 2001:db8:14::1\n",
            "agg-b": "hostname agg-b\nvlan 14\ninterface Vlan14\n"
            "   ip address 10.14.0.3/24\n"
            "   vrrp 14 ipv6 2001:db8:14::1\n",
        },
    )
    assert "fhrp-virtual-outside-subnet" not in rules_fired(pack)


def test_a_link_local_virtual_address_is_not_outside_its_subnet(
    tmp_path: Path,
) -> None:
    """RFC 5798 makes an IPv6 group's primary virtual address link-local, which
    is exactly why the IOS configs here write `address FE80::1 primary`. Every
    interface on the segment is already on fe80::/10, so there is no subnet for
    that address to be outside of and no defect to report."""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": "hostname agg-a\ninterface GigabitEthernet0/0\n"
            " ipv6 address 2001:DB8:14::2/64\n"
            " vrrp 14 address-family ipv6\n"
            "  address FE80::1 primary\n",
            "agg-b": "hostname agg-b\ninterface GigabitEthernet0/0\n"
            " ipv6 address 2001:DB8:14::3/64\n"
            " vrrp 14 address-family ipv6\n"
            "  address FE80::1 primary\n",
        },
    )
    assert "fhrp-virtual-outside-subnet" not in rules_fired(pack)


def test_the_two_families_of_one_group_do_not_collide_or_share(
    tmp_path: Path,
) -> None:
    """The IPv4 and IPv6 halves of one group number hold different virtual
    addresses on the same interfaces. Read without their families they are two
    groups claiming one interface — a device contending with itself, and two
    groups answering for one address."""
    pack = eos_pair(tmp_path)
    fired = rules_fired(pack)
    assert "fhrp-duplicate-member" not in fired
    assert "fhrp-virtual-shared" not in fired
    assert "fhrp-virtual-collides" not in fired


def test_an_ipv6_virtual_address_is_read_as_an_address(tmp_path: Path) -> None:
    """Every rule about a virtual address skips a group whose address it cannot
    read, and `fhrp-virtual-not-an-address` is what stops that being silent. It
    has to look in the field the group's own family uses — reading `virtual_ipv4`
    on an IPv6 group finds nothing there and reports a healthy group as broken,
    or skips it entirely."""
    pack = eos_pair(tmp_path)
    assert "fhrp-virtual-not-an-address" not in rules_fired(pack)


def test_the_last_address_of_an_ipv6_prefix_is_an_ordinary_host_address(
    tmp_path: Path,
) -> None:
    """IPv6 has no broadcast address. The last address of a prefix is a host
    address like any other, and a gateway numbered there is fine; applying
    IPv4's broadcast rule to it would condemn a working configuration."""
    last = "2001:db8:14::ffff:ffff:ffff:ffff"
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": "hostname agg-a\ninterface Vlan14\n"
            "   ipv6 address 2001:db8:14::2/64\n"
            f"   vrrp 14 ipv6 {last}\n",
            "agg-b": "hostname agg-b\ninterface Vlan14\n"
            "   ipv6 address 2001:db8:14::3/64\n"
            f"   vrrp 14 ipv6 {last}\n",
        },
    )
    assert "fhrp-virtual-not-a-host-address" not in rules_fired(pack)


def test_a_group_spanning_two_families_is_not_a_group_split_in_two(
    tmp_path: Path,
) -> None:
    """The IPv4 half of a group is on 10.14.0.0/24 and the IPv6 half on
    2001:db8:14::/64. That is what one dual-stack segment looks like, not two
    devices that were meant to be in one subnet and are not."""
    pack = eos_pair(tmp_path)
    assert "fhrp-members-on-different-subnets" not in rules_fired(pack)


def test_two_families_on_one_interface_are_not_one_address_claimed_twice(
    tmp_path: Path,
) -> None:
    """An interface's IPv4 address and its IPv6 address are two addresses on one
    interface. A rule that indexed them together, or compared them as text
    without knowing which family they belonged to, would report the pair as two
    devices contending for one address."""
    pack = eos_pair(tmp_path)
    assert "duplicate-address" not in rules_fired(pack)


def test_a_dual_stack_wire_whose_ends_agree_reports_no_mtu_mismatch(
    tmp_path: Path,
) -> None:
    """Both ends of the link are 9214 bytes and the link is in two subnets. The
    rule walks subnets, so it looks at this wire twice and has to reach the same
    answer both times."""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": "hostname agg-a\ninterface Ethernet1\n   no switchport\n"
            "   mtu 9214\n   ip address 10.0.0.1/24\n"
            "   ipv6 address 2001:db8:ff::1/64\n",
            "agg-b": "hostname agg-b\ninterface Ethernet1\n   no switchport\n"
            "   mtu 9214\n   ip address 10.0.0.2/24\n"
            "   ipv6 address 2001:db8:ff::2/64\n",
        },
    )
    assert "mtu-mismatch" not in rules_fired(pack)


def test_one_wire_with_two_subnets_reports_its_mtu_once(tmp_path: Path) -> None:
    """A dual-stack link is one wire in two subnets and its MTU is one setting.
    Reported per subnet, a single mismatch reads as two problems and the second
    one has no fix of its own."""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": "hostname agg-a\ninterface Ethernet1\n   no switchport\n"
            "   mtu 9214\n   ip address 10.0.0.1/24\n"
            "   ipv6 address 2001:db8:ff::1/64\n"
            "interface Ethernet2\n   no switchport\n   ip address 10.9.0.1/24\n",
            "agg-b": "hostname agg-b\ninterface Ethernet1\n   no switchport\n"
            "   mtu 1500\n   ip address 10.0.0.2/24\n"
            "   ipv6 address 2001:db8:ff::2/64\n"
            "interface Ethernet2\n   no switchport\n   ip address 10.9.0.2/24\n",
        },
    )
    mismatches = [f for f in evaluate(pack) if f.rule == "mtu-mismatch"]
    assert len(mismatches) == 1


def test_a_shared_ipv6_subnet_is_not_an_isolated_interface(tmp_path: Path) -> None:
    """Both aggregation switches are addressed in 2001:db8:14::/64, so neither
    is alone on it. The IPv4 threshold that decides when a missing far end is
    unremarkable would have exempted every /64 there is, which is the same
    silence for the wrong reason."""
    pack = eos_pair(tmp_path)
    assert "l3-interface-isolated" not in rules_fired(pack)


def test_two_families_on_one_wire_do_not_disagree_about_its_mask(
    tmp_path: Path,
) -> None:
    """A /24 and a /64 on the same pair of interfaces are two masks, and they
    are not a disagreement: they describe different address families. The rule
    only compares addresses of one version, and this is what says so."""
    pack = eos_pair(tmp_path)
    assert "subnet-mask-disagreement" not in rules_fired(pack)


def test_an_ipv6_bgp_peer_is_found_on_its_own_subnet(tmp_path: Path) -> None:
    """A peer address is checked against the subnets the device is addressed in.
    With IPv6 addressing unread those subnets did not exist, so every IPv6
    peering in every config looked like a peer on no local subnet — a defect
    reported wholesale about configurations that were correct."""
    pack = pack_from(
        tmp_path,
        **{
            "edge1": "hostname edge1\ninterface Ethernet1\n   no switchport\n"
            "   ipv6 address 2001:db8:ff::1/64\n"
            "interface Ethernet2\n   no switchport\n   ip address 10.9.0.1/24\n"
            "router bgp 65010\n"
            "   neighbor 2001:db8:ff::2 remote-as 65020\n",
            "edge2": "hostname edge2\ninterface Ethernet1\n   no switchport\n"
            "   ipv6 address 2001:db8:ff::2/64\n"
            "interface Ethernet2\n   no switchport\n   ip address 10.9.0.2/24\n"
            "router bgp 65020\n"
            "   neighbor 2001:db8:ff::1 remote-as 65010\n",
        },
    )
    fired = rules_fired(pack)
    assert "bgp-peer-off-subnet" not in fired
    assert "bgp-session-one-sided" not in fired


# --------------------------------------------------------------------------
# Rules: what a dual-stack config must still produce
# --------------------------------------------------------------------------


def test_an_ipv6_virtual_address_outside_its_subnet_is_reported(
    tmp_path: Path,
) -> None:
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": "hostname agg-a\ninterface Vlan14\n"
            "   ipv6 address 2001:db8:14::2/64\n"
            "   vrrp 14 ipv6 2001:db8:99::1\n",
            "agg-b": "hostname agg-b\ninterface Vlan14\n"
            "   ipv6 address 2001:db8:14::3/64\n"
            "   vrrp 14 ipv6 2001:db8:99::1\n",
        },
    )
    findings = {f.rule: f for f in evaluate(pack)}
    assert "fhrp-virtual-outside-subnet" in findings
    assert "VRRP 14 IPv6" in findings["fhrp-virtual-outside-subnet"].title
    assert "2001:db8:14::/64" in findings["fhrp-virtual-outside-subnet"].detail


def test_the_subnet_router_anycast_address_is_not_a_gateway(tmp_path: Path) -> None:
    """The all-zeros host of an IPv6 prefix is the Subnet-Router anycast address,
    which every router on the link answers for. A group numbered there has no
    address of its own."""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": "hostname agg-a\ninterface Vlan14\n"
            "   ipv6 address 2001:db8:14::2/64\n"
            "   vrrp 14 ipv6 2001:db8:14::\n",
            "agg-b": "hostname agg-b\ninterface Vlan14\n"
            "   ipv6 address 2001:db8:14::3/64\n"
            "   vrrp 14 ipv6 2001:db8:14::\n",
        },
    )
    findings = {f.rule: f for f in evaluate(pack)}
    assert "fhrp-virtual-not-a-host-address" in findings
    assert "subnet-router anycast" in findings["fhrp-virtual-not-a-host-address"].title


def test_a_virtual_address_spelled_unlike_the_interface_address_still_collides(
    tmp_path: Path,
) -> None:
    """IOS writes its addresses in upper case and the parser stores an interface
    address canonically, so the group's `FE80`-style spelling and the
    interface's never match as text even when they are one address. Compared as
    text, the member that answers for the gateway whether or not it holds the
    group goes unreported."""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": "hostname agg-a\ninterface GigabitEthernet0/0\n"
            " ipv6 address 2001:db8:14::1/64\n"
            " vrrp 14 address-family ipv6\n"
            "  address 2001:0DB8:14:0:0:0:0:1\n",
            "agg-b": "hostname agg-b\ninterface GigabitEthernet0/0\n"
            " ipv6 address 2001:db8:14::3/64\n"
            " vrrp 14 address-family ipv6\n"
            "  address 2001:0DB8:14:0:0:0:0:1\n",
        },
    )
    findings = {f.rule: f for f in evaluate(pack)}
    assert "fhrp-virtual-collides" in findings
    assert findings["fhrp-virtual-collides"].device == "agg-a"


def test_one_ipv6_address_spelled_two_ways_is_still_a_duplicate(
    tmp_path: Path,
) -> None:
    """`2001:0DB8:14:0:0:0:0:2` and `2001:db8:14::2` are one address, and two
    devices claiming it is the defect this rule exists for. Compared as text
    they are two, and the rule finds duplicates only where both operators
    happened to type them the same way."""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": "hostname agg-a\ninterface Vlan14\n"
            "   ipv6 address 2001:db8:14::2/64\n",
            "agg-b": "hostname agg-b\ninterface Vlan14\n"
            "   ipv6 address 2001:0DB8:14:0:0:0:0:2/64\n",
        },
    )
    findings = {f.rule: f for f in evaluate(pack)}
    assert "duplicate-address" in findings


def test_an_ipv6_subnet_only_one_device_is_on_is_reported(tmp_path: Path) -> None:
    """A /64 with one end in the collection is the ordinary LAN prefix, not a
    point-to-point link, so the IPv4 rule of thumb that a narrow prefix means
    nothing does not carry over. Reusing it would have exempted every IPv6
    subnet and left this rule with nothing to say about a dual-stack network."""
    pack = pack_from(
        tmp_path,
        **{
            "agg-a": "hostname agg-a\ninterface Ethernet1\n   no switchport\n"
            "   ip address 10.0.0.1/24\n"
            "interface Ethernet2\n   no switchport\n"
            "   ipv6 address 2001:db8:99::1/64\n",
            "agg-b": "hostname agg-b\ninterface Ethernet1\n   no switchport\n"
            "   ip address 10.0.0.2/24\n",
        },
    )
    isolated = [f for f in evaluate(pack) if f.rule == "l3-interface-isolated"]
    assert [f.title for f in isolated] == [
        "Ethernet2 is the only interface on 2001:db8:99::/64"
    ]
