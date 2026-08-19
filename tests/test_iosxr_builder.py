"""The IOS-XR dialect, against a config that exercises every construct it claims.

PROJECT.md §5.2 names IOS-XR as one of the two obvious next dialects and calls it
*less similar*, which is the reason it is worth having: the first three all state
a fact roughly where the other two do, so none of them tested the claim that the
parser is the only dialect-aware component.

Three assertions carry the weight.

`test_every_line_is_accounted_for` is the first, for the same reason it is in the
NX-OS suite: a permissive parser fails by silence rather than by error.

`test_a_group_written_at_the_far_end_of_the_file_lands_on_its_interface` is the
second, and it is the one this dialect exists to prove. IOS-XR writes FHRP in a
top-level `router vrrp` block that names the interface, nowhere near the
interface stanza itself, and the group has to arrive in the Fact Pack indexed by
that interface, carrying its subnet, exactly as a group written inside the
interface does on the other three.

`test_iosxr_is_recognised_even_though_it_also_looks_like_nxos` is the third. NX-OS
is detected by an indented `hsrp <n>` header and IOS-XR writes one of those too,
so the two markers overlap in one direction and the order in `builders.parse` is
load-bearing rather than incidental.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack, parse
from cassandra.factpack.builders.common import FhrpRecord
from cassandra.factpack.builders.iosxr import (
    IosXrDevice,
    looks_like_iosxr,
    parse_device,
)
from cassandra.factpack.builders.nxos import looks_like_nxos
from cassandra.factpack.schema import (
    AddressFamily,
    FhrpProtocol,
    FhrpTimers,
    IgpProtocol,
    Interface,
    InterfaceKind,
    NosFamily,
    StaticFactPack,
    TimerSource,
)
from cassandra.timing import sequences

CORPUS: Final = Path(__file__).resolve().parents[1] / "examples" / "xr-metro"

IOSXR: Final = """RP/0/RSP0/CPU0:metro-a#show running-config
Tue Aug 18 09:14:22.117 UTC
Building configuration...
!! IOS XR Configuration 7.9.2
!! Last configuration change at Tue Aug 18 09:14:22 2026 by netops
!
hostname metro-a
!
vrf CUSTOMER-A
 address-family ipv4 unicast
  import route-target
   64512:100
  !
 !
!
interface Loopback0
 ipv4 address 198.51.100.1 255.255.255.255
!
interface MgmtEth0/RP0/CPU0/0
 description out of band
 ipv4 address 192.0.2.10 255.255.255.0
 shutdown
!
interface TenGigE0/0/0/0
 description to metro-b
 mtu 9192
 ipv4 address 198.51.100.5 255.255.255.252
 ipv6 address 2001:db8:ffff::1/126
 load-interval 30
!
interface TenGigE0/0/0/1
 description bundle member
 bundle id 1 mode active
!
interface Bundle-Ether1
 description to metro-b, second path
 ipv4 address 198.51.100.9 255.255.255.252
!
interface Bundle-Ether1.100
 description customer handoff
 encapsulation dot1q 100
 vrf CUSTOMER-A
 ipv4 address 203.0.113.5 255.255.255.252
!
interface BVI14
 description users-14 gateway
 ipv4 address 203.0.113.130 255.255.255.192
 ipv4 address 203.0.113.190 255.255.255.192 secondary
 ipv6 address 2001:db8:14::2/64
!
interface BVI24
 description users-24 gateway
 ipv4 address 203.0.113.194 255.255.255.192
!
route-policy PASS
  pass
end-policy
!
track uplink-1
 type line-protocol state
  interface TenGigE0/0/0/0
 !
!
router vrrp
 interface BVI14
  address-family ipv4
   vrrp 14
    priority 110
    preempt delay 30
    timer 1
    address 203.0.113.129
    track object uplink-1 40
   !
  !
  address-family ipv6
   vrrp 14
    priority 110
    preempt delay 30
    address linklocal autoconfig
    address 2001:db8:14::1
    track object uplink-1 40
   !
  !
 !
!
router hsrp
 interface BVI24
  address-family ipv4
   hsrp 24 version 2
    priority 120
    preempt delay 90
    timers 1 3
    address 203.0.113.193
    track interface TenGigE0/0/0/0
   !
  !
 !
!
router ospf 1
 router-id 198.51.100.1
 log adjacency changes
 area 0
  interface Loopback0
   passive enable
  !
  interface TenGigE0/0/0/0
   network point-to-point
   cost 100
   hello-interval 3
   dead-interval 9
   bfd fast-detect
   bfd minimum-interval 300
   bfd multiplier 3
  !
 !
!
router bgp 64512
 bgp router-id 198.51.100.1
 timers bgp 30 90
 bgp graceful-restart
 address-family ipv4 unicast
 !
 neighbor-group CORE
  remote-as 64512
  update-source Loopback0
  bfd fast-detect
  bfd minimum-interval 300
  bfd multiplier 3
  address-family ipv4 unicast
   route-policy PASS in
  !
 !
 neighbor 198.51.100.17
  use neighbor-group CORE
  description core-1, outside these configs
 !
 neighbor 198.51.100.6
  remote-as 64513
  description metro-b
  timers 10 30
  address-family ipv4 unicast
   route-policy PASS in
  !
 !
!
end
"""

# One config per sibling dialect, small enough to read and decisive enough to
# detect. They exist so that adding a fourth dialect has to prove it took none of
# the other three's files.
IOS: Final = """hostname dist-a
!
interface Vlan14
 ip address 10.14.0.2 255.255.255.0
 standby 14 ip 10.14.0.1
 standby 14 priority 110
!
end
"""

EOS: Final = """hostname sw1
interface Vlan14
   ip address 10.14.0.2/24
   vrrp 14 ipv4 10.14.0.1
   vrrp 14 priority-level 110
"""

NXOS: Final = """version 9.3(10)
hostname agg-a
feature hsrp
interface Vlan14
  ip address 10.14.0.2/24
  hsrp 14
    ip 10.14.0.1
    priority 110
"""


@pytest.fixture(scope="module")
def parsed() -> IosXrDevice:
    return parse_device(IOSXR)


@pytest.fixture(scope="module")
def pack() -> StaticFactPack:
    built, _ = build_fact_pack(CORPUS)
    return built


def interface(parsed: IosXrDevice, name: str) -> Interface:
    return next(i for i in parsed.device.interfaces if i.name == name)


def record(
    parsed: IosXrDevice,
    number: int,
    family: AddressFamily = AddressFamily.IPV4_UNICAST,
) -> FhrpRecord:
    return next(
        r for r in parsed.fhrp_records if r.number == number and r.family is family
    )


def timers(parsed: IosXrDevice, instance: str) -> FhrpTimers:
    return next(t for t in parsed.timers if t.scope.instance == instance)


def xr(body: str) -> IosXrDevice:
    """A minimal config carrying `body`, for the narrow cases."""
    return parse_device(f"hostname r1\n{body}")


# --------------------------------------------------------------------------
# Dialect detection
# --------------------------------------------------------------------------


def test_iosxr_is_recognised() -> None:
    assert looks_like_iosxr(IOSXR)


def test_other_dialects_are_not_mistaken_for_iosxr() -> None:
    assert not looks_like_iosxr(IOS)
    assert not looks_like_iosxr(EOS)
    assert not looks_like_iosxr(NXOS)


def test_iosxr_is_recognised_even_though_it_also_looks_like_nxos() -> None:
    """The overlap that makes the order in `builders.parse` load-bearing.

    NX-OS is detected by an indented `hsrp <n>` header, and IOS-XR writes one of
    those four levels inside `router hsrp`. A search for the line cannot tell the
    two apart, so IOS-XR is tested first — and this fails the moment that order
    is reversed.
    """
    overlapping = (
        "!! IOS XR Configuration 7.9.2\n"
        "hostname metro-a\n"
        "interface BVI24\n"
        " ipv4 address 203.0.113.194 255.255.255.192\n"
        "router hsrp\n"
        " interface BVI24\n"
        "  address-family ipv4\n"
        "   hsrp 24\n"
        "    priority 120\n"
    )
    assert looks_like_nxos(overlapping)
    assert parse(overlapping).device.nos_family is NosFamily.IOS_XR
    assert parse(IOSXR).device.nos_family is NosFamily.IOS_XR


@pytest.mark.parametrize(
    ("text", "family"),
    [
        (IOS, NosFamily.IOS_XE),
        (EOS, NosFamily.EOS),
        (NXOS, NosFamily.NX_OS),
        (IOSXR, NosFamily.IOS_XR),
    ],
)
def test_each_dialect_still_picks_itself(text: str, family: NosFamily) -> None:
    assert parse(text).device.nos_family is family


@pytest.mark.parametrize(
    "text",
    [
        "!! IOS XR Configuration 7.9.2\n",
        "RP/0/RSP0/CPU0:metro-a#show running-config\n",
        "router vrrp\n interface BVI14\n",
        "router hsrp\n interface BVI24\n",
        "interface GigabitEthernet0/0/0/0\n ipv4 address 10.0.0.1 255.255.255.0\n",
        "interface Bundle-Ether1\n",
        "interface TenGigE0/0/0/0\n",
    ],
)
def test_each_marker_alone_is_enough(text: str) -> None:
    assert looks_like_iosxr(text)


def test_a_sibling_config_with_no_decisive_marker_is_not_taken_by_iosxr() -> None:
    """The tie-break is where a fourth dialect can steal a file it never read.

    With no marker to decide, `builders.parse` keeps whichever parser left least
    of the file unexplained, so a parser that filtered the other three's
    vocabulary would win configs by silence rather than by understanding them.
    IOS-XR has no spanning tree at all, so it has to report this line rather than
    absorb it — and the file has to stay with the dialect that wrote it.
    """
    text = "hostname sw1\nspanning-tree vlan LEGACY hello-time 2\n"
    assert not looks_like_iosxr(text)
    assert parse_device(text).unparsed_lines == (
        "spanning-tree vlan LEGACY hello-time 2",
    )
    assert parse(text, device_id="sw1").device.nos_family is not NosFamily.IOS_XR


def test_a_bvi_alone_is_not_decisive() -> None:
    """IOS-XE has bridge-group virtual interfaces by the same name.

    `BVI` is therefore read as an IOS-XR interface kind and never as evidence of
    the dialect, and this is what stops an IOS config that bridges from being
    taken away from its own parser.
    """
    assert not looks_like_iosxr(
        "interface BVI100\n ip address 10.0.0.1 255.255.255.0\n"
    )


# --------------------------------------------------------------------------
# Coverage of the representative config
# --------------------------------------------------------------------------


def test_every_line_is_accounted_for(parsed: IosXrDevice) -> None:
    leftovers = parsed.unparsed_lines
    assert leftovers == (), f"unaccounted IOS-XR lines: {leftovers}"


def test_device_identity(parsed: IosXrDevice) -> None:
    assert parsed.device.id == "metro-a"
    assert parsed.device.hostname == "metro-a"
    assert parsed.device.nos_family is NosFamily.IOS_XR
    assert parsed.device.config_line_count == len(IOSXR.splitlines())


@pytest.mark.parametrize(
    "line",
    [
        "RP/0/RSP0/CPU0:metro-a#show running-config",
        "Building configuration...",
        "commit",
        "end",
        "!",
    ],
)
def test_session_noise_is_not_configuration(line: str) -> None:
    """A capture carries the prompt, the echo and the commit that closed it.

    None of them is a stanza, and none of them may become one — an unparsed list
    full of prompts is a list nobody reads.
    """
    parsed = parse_device(f"hostname r1\n{line}\ninterface Loopback0\n")
    assert parsed.unparsed_lines == ()
    assert parsed.device.hostname == "r1"


def test_a_closing_bang_does_not_cut_a_block_short() -> None:
    """IOS-XR closes every nested block with an indented `!`.

    An indentation-aware splitter reads one of those as a sibling header unless
    it is removed first, which would end the `vrrp 14` block before its
    `priority` line and leave the group at the default priority.
    """
    parsed = xr(
        "router vrrp\n"
        " interface BVI14\n"
        "  address-family ipv4\n"
        "   vrrp 14\n"
        "    priority 110\n"
        "   !\n"
        "  !\n"
        " !\n"
        "!\n"
    )
    assert parsed.unparsed_lines == ()
    assert record(parsed, 14).member.priority == 110


# --------------------------------------------------------------------------
# Interfaces
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("Loopback0", InterfaceKind.LOOPBACK),
        ("MgmtEth0/RP0/CPU0/0", InterfaceKind.MANAGEMENT),
        ("TenGigE0/0/0/0", InterfaceKind.PHYSICAL),
        ("Bundle-Ether1", InterfaceKind.LAG),
        ("Bundle-Ether1.100", InterfaceKind.SUBINTERFACE),
        ("BVI14", InterfaceKind.SVI),
    ],
)
def test_interface_kinds(parsed: IosXrDevice, name: str, kind: InterfaceKind) -> None:
    assert interface(parsed, name).kind is kind


def test_a_netmask_becomes_a_prefix(parsed: IosXrDevice) -> None:
    """`ipv4 address`, not `ip address` — the keyword differs and the mask does not."""
    addresses = interface(parsed, "TenGigE0/0/0/0").addresses
    assert [(a.address, a.prefix) for a in addresses] == [
        ("198.51.100.5", "198.51.100.5/30"),
        ("2001:db8:ffff::1", "2001:db8:ffff::1/126"),
    ]
    assert addresses[0].family is AddressFamily.IPV4_UNICAST
    assert addresses[1].family is AddressFamily.IPV6_UNICAST


def test_a_secondary_address_is_marked_as_one(parsed: IosXrDevice) -> None:
    addresses = interface(parsed, "BVI14").addresses
    assert [(a.prefix, a.secondary) for a in addresses] == [
        ("203.0.113.130/26", False),
        ("203.0.113.190/26", True),
        ("2001:db8:14::2/64", False),
    ]


def test_the_prefix_form_of_the_address_line_is_read_too() -> None:
    parsed = xr("interface GigabitEthernet0/0/0/0\n ipv4 address 10.0.0.1/31\n")
    assert parsed.unparsed_lines == ()
    assert (
        interface(parsed, "GigabitEthernet0/0/0/0").addresses[0].prefix == "10.0.0.1/31"
    )


def test_a_non_contiguous_mask_is_reported_rather_than_guessed_at() -> None:
    parsed = xr(
        "interface GigabitEthernet0/0/0/0\n ipv4 address 10.0.0.1 255.0.255.0\n"
    )
    assert parsed.unparsed_lines == ("ipv4 address 10.0.0.1 255.0.255.0",)
    assert interface(parsed, "GigabitEthernet0/0/0/0").addresses == ()


def test_interface_attributes(parsed: IosXrDevice) -> None:
    uplink = interface(parsed, "TenGigE0/0/0/0")
    assert uplink.description == "to metro-b"
    assert uplink.mtu_bytes == 9192
    assert uplink.admin_enabled is True
    assert (
        uplink.config_line == IOSXR.splitlines().index("interface TenGigE0/0/0/0") + 1
    )


def test_a_shut_interface_is_recorded_as_shut(parsed: IosXrDevice) -> None:
    assert interface(parsed, "MgmtEth0/RP0/CPU0/0").admin_enabled is False


def test_bundle_membership(parsed: IosXrDevice) -> None:
    """`bundle id 1 mode active` is what the others spell `channel-group`."""
    assert interface(parsed, "TenGigE0/0/0/1").lag_member_of == "Bundle-Ether1"
    assert interface(parsed, "Bundle-Ether1").lag_member_of is None


def test_a_subinterface_carries_its_parent_and_its_tag(parsed: IosXrDevice) -> None:
    sub = interface(parsed, "Bundle-Ether1.100")
    assert sub.parent == "Bundle-Ether1"
    assert sub.dot1q_vlan == 100
    assert sub.vrf == "CUSTOMER-A"


# --------------------------------------------------------------------------
# FHRP — the fact that arrives from the other end of the file
# --------------------------------------------------------------------------


def test_a_group_written_at_the_far_end_of_the_file_lands_on_its_interface(
    parsed: IosXrDevice,
) -> None:
    """The claim this dialect exists to test.

    `router vrrp` is a top-level block that names `interface BVI14` from a
    hundred lines below the interface stanza. The membership still has to arrive
    indexed by that interface, because everything downstream — the subnet join,
    the timer scope, the citation — reads the interface name and nothing else.
    """
    group = record(parsed, 14)
    assert group.interface == "BVI14"
    assert group.member.interface == "BVI14"
    assert group.protocol is FhrpProtocol.VRRP
    assert group.virtual == "203.0.113.129"


def test_vrrp_group_settings(parsed: IosXrDevice) -> None:
    member = record(parsed, 14).member
    assert member.priority == 110
    assert member.preempt is True
    assert [(t.id, t.decrement) for t in member.tracked_objects] == [("uplink-1", 40)]


def test_hsrp_group_settings(parsed: IosXrDevice) -> None:
    """HSRP lives in its own top-level block, and says `timers`, not `timer`."""
    group = record(parsed, 24)
    assert group.protocol is FhrpProtocol.HSRP
    assert group.interface == "BVI24"
    assert group.virtual == "203.0.113.193"
    assert group.member.priority == 120
    assert group.member.version == 2


def test_an_untracked_decrement_defaults_to_ten(parsed: IosXrDevice) -> None:
    """`track interface X` with no number decrements by 10, as on its siblings.

    Reading a bare track as a decrement of zero turns real failover into tracking
    that does nothing, and the tool then calls the group stable.
    """
    tracked = record(parsed, 24).member.tracked_objects
    assert [(t.id, t.decrement) for t in tracked] == [("TenGigE0/0/0/0", 10)]


def test_group_timers(parsed: IosXrDevice) -> None:
    vrrp = timers(parsed, "14")
    assert vrrp.protocol is FhrpProtocol.VRRP
    assert (vrrp.hello_interval_ms, vrrp.hold_time_ms) == (1000, None)
    assert vrrp.preempt_delay_ms == 30000
    assert vrrp.scope.interface == "BVI14"
    assert vrrp.scope.source is TimerSource.CONFIGURED

    hsrp = timers(parsed, "24")
    assert (hsrp.hello_interval_ms, hsrp.hold_time_ms) == (1000, 3000)
    assert hsrp.preempt_delay_ms == 90000


def test_millisecond_timers_are_not_read_as_seconds() -> None:
    parsed = xr(
        "router vrrp\n"
        " interface BVI14\n"
        "  address-family ipv4\n"
        "   vrrp 14\n"
        "    timer msec 250\n"
    )
    assert parsed.unparsed_lines == ()
    assert timers(parsed, "14").hello_interval_ms == 250


def test_the_ipv6_group_is_its_own_group(parsed: IosXrDevice) -> None:
    """VRRPv3 runs a separate virtual router per family, and IOS-XR says so
    structurally: two `address-family` blocks, each with its own `vrrp 14`."""
    v6 = record(parsed, 14, AddressFamily.IPV6_UNICAST)
    assert v6.family is AddressFamily.IPV6_UNICAST
    assert v6.virtual == "2001:db8:14::1"
    assert timers(parsed, "14 ipv6").preempt_delay_ms == 30000


def test_a_link_local_virtual_address_does_not_displace_the_global_one() -> None:
    """Every interface is on fe80::/10 whether anyone configured it or not, so a
    link-local virtual address is not a claim about which segment the group serves."""
    parsed = xr(
        "router vrrp\n"
        " interface BVI14\n"
        "  address-family ipv6\n"
        "   vrrp 14\n"
        "    address fe80::1\n"
        "    address 2001:db8:14::1\n"
    )
    assert parsed.unparsed_lines == ()
    assert record(parsed, 14, AddressFamily.IPV6_UNICAST).virtual == "2001:db8:14::1"


def test_preempt_disable_is_read_and_leaves_preempt_off() -> None:
    parsed = xr(
        "router vrrp\n"
        " interface BVI14\n"
        "  address-family ipv4\n"
        "   vrrp 14\n"
        "    preempt disable\n"
    )
    assert parsed.unparsed_lines == ()
    assert record(parsed, 14).member.preempt is False


def test_a_group_cites_the_line_its_block_opens_on(parsed: IosXrDevice) -> None:
    expected = IOSXR.splitlines().index("   vrrp 14") + 1
    assert record(parsed, 14).member.config_line == expected


# --------------------------------------------------------------------------
# Tracked objects
# --------------------------------------------------------------------------


def test_a_track_block_names_its_target(parsed: IosXrDevice) -> None:
    entry = next(t for t in parsed.tracked if t.id == "uplink-1")
    assert entry.target == "TenGigE0/0/0/0"


def test_an_inline_interface_track_defines_its_own_object(parsed: IosXrDevice) -> None:
    """`track interface X <decrement>` names the target on the spot rather than
    referring to a `track` block, so the object is manufactured under the
    interface's own name — one join for the rest of the tool, not two shapes."""
    entry = next(t for t in parsed.tracked if t.id == "TenGigE0/0/0/0")
    assert entry.target == "TenGigE0/0/0/0"


def test_a_track_whose_target_cannot_be_named_is_reported_not_invented() -> None:
    parsed = xr("track route-1\n type route reachability\n  route ipv4 10.0.0.0/8\n")
    assert parsed.tracked == ()
    assert "track route-1" in parsed.unparsed_lines


# --------------------------------------------------------------------------
# OSPF and BFD
# --------------------------------------------------------------------------


def test_ospf_hello_and_dead_are_read_out_of_the_area_block(
    parsed: IosXrDevice,
) -> None:
    record_ = next(t for t in parsed.igp_hello if t.scope.interface == "TenGigE0/0/0/0")
    assert record_.protocol is IgpProtocol.OSPFV2
    assert (record_.hello_interval_ms, record_.dead_interval_ms) == (3000, 9000)
    assert record_.ospf_area == "0"


def test_an_interface_with_no_ospf_timers_produces_no_record(
    parsed: IosXrDevice,
) -> None:
    """`interface Loopback0` under the area states only `passive enable`, and a
    record whose every value is None says only that the parser ran."""
    assert [t.scope.interface for t in parsed.igp_hello] == ["TenGigE0/0/0/0"]


def test_an_area_level_hello_interval_is_reported_rather_than_inherited() -> None:
    """IOS-XR lets an area state the hello interval every interface below runs.

    Writing an interface's timers from a line that does not name the interface
    would be a derivation, not a reading, so it is refused — and reported, so the
    gap is visible rather than silent.
    """
    parsed = xr("router ospf 1\n area 0\n  hello-interval 3\n")
    assert parsed.igp_hello == ()
    assert parsed.unparsed_lines == ("hello-interval 3",)


def test_bfd_under_an_ospf_interface_becomes_a_session(parsed: IosXrDevice) -> None:
    session = next(s for s in parsed.bfd if s.scope.interface == "TenGigE0/0/0/0")
    assert session.desired_min_tx_ms == 300
    assert session.required_min_rx_ms == 300
    assert session.detect_multiplier == 3
    assert session.clients == ("ospf",)


# --------------------------------------------------------------------------
# BGP
# --------------------------------------------------------------------------


def test_bgp_process(parsed: IosXrDevice) -> None:
    process = parsed.bgp[0]
    assert process.local_as == "64512"
    assert process.router_id == "198.51.100.1"
    assert [n.address for n in process.neighbors] == [
        "198.51.100.17",
        "198.51.100.6",
    ]


def test_a_peer_states_its_own_settings(parsed: IosXrDevice) -> None:
    peer = next(n for n in parsed.bgp[0].neighbors if n.address == "198.51.100.6")
    assert peer.remote_as == "64513"
    assert peer.description == "metro-b"
    assert peer.bfd is False
    assert peer.peer_group is None


def test_a_neighbor_group_is_resolved_into_its_members(parsed: IosXrDevice) -> None:
    """`use neighbor-group CORE` is IOS-XR's peer-group, and the AS it states
    plainly must not read as unstated on the peering that inherits it."""
    peer = next(n for n in parsed.bgp[0].neighbors if n.address == "198.51.100.17")
    assert peer.peer_group == "CORE"
    assert peer.remote_as == "64512"
    assert peer.update_source == "Loopback0"
    assert peer.bfd is True


def test_bgp_timers_at_both_scopes(parsed: IosXrDevice) -> None:
    process = next(t for t in parsed.bgp_timers if t.scope.neighbor is None)
    assert (process.keepalive_ms, process.hold_time_ms) == (30000, 90000)
    assert process.scope.instance == "64512"

    stated = next(t for t in parsed.bgp_timers if t.scope.neighbor == "198.51.100.6")
    assert (stated.keepalive_ms, stated.hold_time_ms) == (10000, 30000)
    assert stated.scope.source is TimerSource.CONFIGURED

    silent = next(t for t in parsed.bgp_timers if t.scope.neighbor == "198.51.100.17")
    assert (silent.keepalive_ms, silent.hold_time_ms) == (30000, 90000)
    assert silent.scope.source is TimerSource.INHERITED


def test_bfd_stated_in_a_neighbor_group_reaches_its_members(
    parsed: IosXrDevice,
) -> None:
    """IOS-XR is the only dialect here that states BFD inside the peering, so its
    sessions are scoped by neighbour rather than by interface — and an operator
    who wrote the interval once for a group wrote it for every member."""
    session = next(s for s in parsed.bfd if s.scope.neighbor == "198.51.100.17")
    assert session.scope.interface is None
    assert session.desired_min_tx_ms == 300
    assert session.detect_multiplier == 3
    assert session.clients == ("bgp",)


def test_a_peering_with_no_bfd_gets_no_session(parsed: IosXrDevice) -> None:
    assert [s.scope.neighbor for s in parsed.bfd if s.scope.neighbor] == [
        "198.51.100.17"
    ]


# --------------------------------------------------------------------------
# What is deliberately not read
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "carrier-delay up 2000 down 0",
        "dampening 30 750 2000 60",
        "l2transport",
        "ipv4 verify unicast source reachable-via rx",
    ],
)
def test_a_fact_this_does_not_read_is_reported_rather_than_dropped(line: str) -> None:
    """The failure mode this repository cares most about is the silent one.

    Every line here states something real that the Fact Pack has no field this
    parser fills — an interface debounce, an interface dampening profile, a port
    put into a bridge domain. None of them may vanish.
    """
    parsed = xr(f"interface TenGigE0/0/0/0\n {line}\n")
    assert parsed.unparsed_lines == (line,)


def test_an_unreadable_line_inside_a_group_block_is_reported() -> None:
    parsed = xr(
        "router vrrp\n"
        " interface BVI14\n"
        "  address-family ipv4\n"
        "   vrrp 14\n"
        "    priority 110\n"
        "    bfd fast-detect peer ipv4 203.0.113.131\n"
    )
    assert parsed.unparsed_lines == ("bfd fast-detect peer ipv4 203.0.113.131",)
    assert record(parsed, 14).member.priority == 110


def test_an_unreadable_line_inside_a_bgp_peer_block_is_reported() -> None:
    parsed = xr(
        "router bgp 64512\n neighbor 198.51.100.6\n"
        "  remote-as 64513\n  dubious-knob 7\n"
    )
    assert parsed.unparsed_lines == ("dubious-knob 7",)
    assert parsed.bgp[0].neighbors[0].remote_as == "64513"


# --------------------------------------------------------------------------
# The whole pipeline, over the shipped corpus
# --------------------------------------------------------------------------


def test_the_corpus_parses_with_nothing_left_over() -> None:
    _, unparsed = build_fact_pack(CORPUS)
    assert unparsed == {"metro-a": (), "metro-b": ()}


def test_the_corpus_builds_two_iosxr_devices(pack: StaticFactPack) -> None:
    assert [(d.id, d.nos_family) for d in pack.devices] == [
        ("metro-a", NosFamily.IOS_XR),
        ("metro-b", NosFamily.IOS_XR),
    ]


def test_groups_written_in_two_top_level_blocks_join_across_devices(
    pack: StaticFactPack,
) -> None:
    """The end of the claim: `assemble_fhrp_groups` resolves the subnet from the
    interfaces, so a membership written in `router vrrp` joins the same group as
    one written inside an interface on any other dialect would."""
    groups = {g.id: g for g in pack.fhrp_groups}
    assert sorted(groups) == ["hsrp-24", "vrrp-14", "vrrp-14-ipv6"]

    vrrp = groups["vrrp-14"]
    assert vrrp.subnet == "203.0.113.128/26"
    assert vrrp.virtual_address == "203.0.113.129"
    assert [(m.device, m.interface, m.priority) for m in vrrp.members] == [
        ("metro-a", "BVI14", 110),
        ("metro-b", "BVI14", 100),
    ]

    v6 = groups["vrrp-14-ipv6"]
    assert v6.subnet == "2001:db8:14::/64"
    assert v6.virtual_address == "2001:db8:14::1"


def test_a_tracked_object_resolves_to_the_interface_it_watches(
    pack: StaticFactPack,
) -> None:
    group = next(g for g in pack.fhrp_groups if g.id == "vrrp-14")
    member = next(m for m in group.members if m.device == "metro-a")
    assert [(t.id, t.target, t.decrement) for t in member.tracked_objects] == [
        ("uplink-1", "TenGigE0/0/0/0", 40)
    ]


def test_the_corpus_is_addressed_only_in_documentation_space(
    pack: StaticFactPack,
) -> None:
    """RFC 5737 and RFC 3849, per `docs/CONVENTIONS.md` rule 4.

    A corpus that drifts into routable space is a corpus that looks like it came
    from somewhere, which is the one thing no fixture in this repository may do.
    """
    allowed = [
        ipaddress.ip_network(net)
        for net in (
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "2001:db8::/32",
        )
    ]
    for device in pack.devices:
        for iface in device.interfaces:
            for assignment in iface.addresses:
                address = ipaddress.ip_address(assignment.address)
                assert any(address in net for net in allowed), (
                    f"{device.id}:{iface.name} {assignment.address}"
                )


def test_the_corpus_still_reports_the_divergence_it_was_written_to_hold(
    pack: StaticFactPack,
) -> None:
    """VRRP 14 preempts back after 30s and HSRP 24 waits 90s, on the same pair of
    devices — the same shape of defect the EOS corpus holds, reached through a
    completely different part of the file."""
    found = {(f.rule, f.device) for f in sequences.analyse(pack)}
    assert ("fhrp-divergence", "metro-a") in found

    delays = {
        t.scope.instance: t.preempt_delay_ms
        for t in pack.timers.fhrp
        if t.scope.device == "metro-a"
    }
    assert delays == {"14": 30000, "14 ipv6": 30000, "24": 90000}
