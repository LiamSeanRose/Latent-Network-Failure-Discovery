"""The NX-OS dialect, against a config that exercises every construct it claims.

The load-bearing assertion is `test_every_line_is_accounted_for`: a permissive
parser fails by silence, not by error, so the representative config below is
checked line for line rather than field by field only.

The second is `test_hsrp_is_read_out_of_its_sub_block`. NX-OS is the first dialect
where indentation carries meaning — `ip 10.14.0.1` under `hsrp 14` is a virtual
address and `ip address 10.14.0.2/24` one level up is not — and a splitter that
flattened the two would still produce a plausible-looking Fact Pack.

The BGP section at the foot is the same claim one level deeper: a peer's settings
nest under `neighbor <ip>` and its per-family settings under that again, and the
three rules that read across both ends of a session were written against flat EOS
configs and are exercised here against nested ones, unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.builders.common import ParsedDevice
from cassandra.factpack.builders.ios import looks_like_ios
from cassandra.factpack.builders.nxos import looks_like_nxos, parse_device
from cassandra.factpack.schema import (
    BgpNeighbor,
    BgpProcess,
    FhrpProtocol,
    InterfaceKind,
    NosFamily,
    StaticFactPack,
    SwitchportMode,
    TimerSource,
)
from cassandra.facts.rules import evaluate

NXOS: Final = """!Command: show running-config
!Time: Tue Aug 18 09:14:22 2026
version 9.3(10) Bios:version 05.47
hostname agg-a
no password strength-check

feature interface-vlan
feature hsrp
feature lacp
feature ospf

vlan 1,14,24
vlan 14
  name users-14
vlan 24
  name users-24

spanning-tree vlan 14 priority 4096

interface mgmt0
  description out of band
  vrf member management
  ip address 192.0.2.10/24

interface Ethernet1/1
  description uplink to core
  no switchport
  mtu 9216
  medium p2p
  no ip redirects
  ip address 10.0.0.1/31
  ip router ospf 1 area 0.0.0.0
  no shutdown

interface Ethernet1/2
  description peer-link member
  switchport
  switchport mode trunk
  switchport trunk native vlan 99
  switchport trunk allowed vlan 14,24
  channel-group 1 mode active
  no shutdown

interface Ethernet1/3
  description spare
  switchport
  switchport mode access
  switchport access vlan 14
  logging event port link-status
  shutdown

interface port-channel1
  description peer-link
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 14,24
  no shutdown

interface Vlan14
  no shutdown
  ip address 10.14.0.2/24
  hsrp version 2
  hsrp 14
    ip 10.14.0.1
    priority 110
    preempt delay minimum 30
    timers 1 3
    track 1 decrement 40

interface Vlan24
  no shutdown
  ip address 10.24.0.2/24
  hsrp version 2
  hsrp 24
    ip 10.24.0.1
    priority 110
    preempt delay minimum 90
    timers 1 3
    track 1 decrement 40

interface loopback0
  ip address 10.255.0.1/32

router ospf 1
  router-id 10.255.0.1
  log-adjacency-changes

track 1 interface Ethernet1/1 line-protocol
"""

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


@pytest.fixture(scope="module")
def parsed() -> ParsedDevice:
    return parse_device(NXOS)


def group(parsed: ParsedDevice, number: int) -> tuple:
    """One group's record, in the positional shape these tests read.

    The parsers carry an `FhrpRecord` now, because a group's identity includes
    its address family. This keeps the tests below reading the way they did.
    """
    record = next(entry for entry in parsed.fhrp_records if entry.number == number)
    return (
        record.number,
        record.protocol,
        record.member,
        record.interface,
        record.virtual,
    )


def hsrp(body: str, *, interface: str = "Vlan14") -> ParsedDevice:
    """One interface carrying one `hsrp 14` sub-block, for the narrow cases."""
    lines = "".join(f"    {line}\n" for line in body.strip().splitlines())
    return parse_device(
        f"hostname r1\ninterface {interface}\n  ip address 10.14.0.2/24\n"
        f"  hsrp 14\n{lines}"
    )


# --------------------------------------------------------------------------
# Dialect detection
# --------------------------------------------------------------------------


def test_nxos_is_recognised() -> None:
    assert looks_like_nxos(NXOS)


def test_other_dialects_are_not_mistaken_for_nxos() -> None:
    assert not looks_like_nxos(IOS)
    assert not looks_like_nxos(EOS)


def test_nxos_is_not_mistaken_for_ios() -> None:
    """NX-OS has no `standby` line and no netmask, so IOS detection stays quiet.

    The two markers are independent, which is what lets detection check either
    order without one dialect stealing the other's configs.
    """
    assert not looks_like_ios(NXOS)


@pytest.mark.parametrize(
    "text",
    [
        "feature hsrp\n",
        "no feature telnet\n",
        "version 9.3(10)\n",
        "interface Vlan14\n  hsrp 14\n    ip 10.14.0.1\n",
    ],
)
def test_each_marker_alone_is_enough(text: str) -> None:
    assert looks_like_nxos(text)


# --------------------------------------------------------------------------
# Coverage of the representative config
# --------------------------------------------------------------------------


def test_every_line_is_accounted_for(parsed: ParsedDevice) -> None:
    leftovers = parsed.unparsed_lines
    assert leftovers == (), f"unaccounted NX-OS lines: {leftovers}"


def test_device_identity(parsed: ParsedDevice) -> None:
    assert parsed.device.id == "agg-a"
    assert parsed.device.hostname == "agg-a"
    assert parsed.device.nos_family is NosFamily.NX_OS
    assert parsed.device.config_line_count == len(NXOS.splitlines())


def test_an_unhandled_line_is_reported_rather_than_dropped() -> None:
    parsed = parse_device(
        "hostname r1\ninterface Vlan14\n  ip address 10.14.0.2/24\n"
        "  ip pim sparse-mode\n"
    )
    assert parsed.unparsed_lines == ("ip pim sparse-mode",)


def test_an_unhandled_line_inside_the_hsrp_block_is_reported() -> None:
    parsed = hsrp("ip 10.14.0.1\nipv6 autoconfig\n")
    assert parsed.unparsed_lines == ("ipv6 autoconfig",)


# --------------------------------------------------------------------------
# Interfaces
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("Ethernet1/1", InterfaceKind.PHYSICAL),
        ("Vlan14", InterfaceKind.SVI),
        ("port-channel1", InterfaceKind.LAG),
        ("loopback0", InterfaceKind.LOOPBACK),
        ("mgmt0", InterfaceKind.MANAGEMENT),
    ],
)
def test_interface_kinds(parsed: ParsedDevice, name: str, kind: InterfaceKind) -> None:
    interface = next(i for i in parsed.device.interfaces if i.name == name)
    assert interface.kind is kind


def test_cidr_addressing(parsed: ParsedDevice) -> None:
    """NX-OS writes prefixes like EOS, not netmasks like IOS."""
    by_name = {i.name: i for i in parsed.device.interfaces}
    assert by_name["Vlan14"].addresses[0].address == "10.14.0.2"
    assert by_name["Vlan14"].addresses[0].prefix == "10.14.0.2/24"
    assert by_name["Ethernet1/1"].addresses[0].prefix == "10.0.0.1/31"
    assert by_name["loopback0"].addresses[0].prefix == "10.255.0.1/32"


def test_the_hsrp_virtual_address_is_not_read_as_an_interface_address(
    parsed: ParsedDevice,
) -> None:
    """`ip 10.14.0.1` lives one level deeper and is not an interface address."""
    vlan14 = next(i for i in parsed.device.interfaces if i.name == "Vlan14")
    assert [a.address for a in vlan14.addresses] == ["10.14.0.2"]


def test_routed_and_switched_ports(parsed: ParsedDevice) -> None:
    by_name = {i.name: i for i in parsed.device.interfaces}
    assert by_name["Ethernet1/1"].switchport_mode is SwitchportMode.ROUTED
    assert by_name["Ethernet1/1"].mtu_bytes == 9216
    assert by_name["Ethernet1/2"].switchport_mode is SwitchportMode.TRUNK
    assert by_name["Ethernet1/2"].allowed_vlans == (14, 24)
    assert by_name["Ethernet1/2"].native_vlan == 99
    assert by_name["Ethernet1/2"].lag_member_of == "port-channel1"
    assert by_name["Ethernet1/3"].switchport_mode is SwitchportMode.ACCESS
    assert by_name["Ethernet1/3"].access_vlan == 14
    assert by_name["port-channel1"].allowed_vlans == (14, 24)
    assert by_name["mgmt0"].vrf == "management"


def test_admin_state(parsed: ParsedDevice) -> None:
    by_name = {i.name: i for i in parsed.device.interfaces}
    assert by_name["Ethernet1/1"].admin_enabled
    assert not by_name["Ethernet1/3"].admin_enabled


def test_bare_switchport_is_an_access_port() -> None:
    parsed = parse_device("hostname r1\ninterface Ethernet1/4\n  switchport\n")
    assert parsed.device.interfaces[0].switchport_mode is SwitchportMode.ACCESS


# --------------------------------------------------------------------------
# HSRP sub-blocks
# --------------------------------------------------------------------------


def test_hsrp_is_read_out_of_its_sub_block(parsed: ParsedDevice) -> None:
    numbers = {record.number for record in parsed.fhrp_records}
    assert numbers == {14, 24}

    _, protocol, member, interface, virtual = group(parsed, 14)
    assert protocol is FhrpProtocol.HSRP
    assert interface == "Vlan14"
    assert virtual == "10.14.0.1"
    assert member.device == "agg-a"
    assert member.priority == 110
    assert member.preempt
    assert member.version == 2


def test_priority_and_preempt_defaults() -> None:
    parsed = hsrp("ip 10.14.0.1\n")
    _, _, member, _, _ = group(parsed, 14)
    assert member.priority == 100
    assert not member.preempt


def test_bare_preempt_without_a_delay() -> None:
    parsed = hsrp("ip 10.14.0.1\npreempt\n")
    _, _, member, _, _ = group(parsed, 14)
    assert member.preempt
    assert parsed.timers[0].preempt_delay_ms is None


def test_preempt_delay_minimum_and_reload_on_one_line() -> None:
    parsed = hsrp("ip 10.14.0.1\npreempt delay minimum 30 reload 120\n")
    timer = parsed.timers[0]
    assert timer.preempt_delay_ms == 30_000
    assert timer.preempt_delay_reload_ms == 120_000


def test_priority_with_forwarding_thresholds() -> None:
    parsed = hsrp("priority 110 forwarding-threshold lower 1 upper 110\n")
    _, _, member, _, _ = group(parsed, 14)
    assert member.priority == 110
    assert parsed.unparsed_lines == ()


def test_preempt_delays_differ_per_group(parsed: ParsedDevice) -> None:
    """The asymmetry the TIMING tier exists to notice, written NX-OS style."""
    delays = {t.scope.instance: t.preempt_delay_ms for t in parsed.timers}
    assert delays == {"14": 30_000, "24": 90_000}


def test_timers_in_seconds(parsed: ParsedDevice) -> None:
    timer = next(t for t in parsed.timers if t.scope.instance == "14")
    assert timer.hello_interval_ms == 1000
    assert timer.hold_time_ms == 3000
    assert timer.scope.device == "agg-a"
    assert timer.scope.interface == "Vlan14"
    assert timer.protocol is FhrpProtocol.HSRP


def test_timers_in_milliseconds() -> None:
    parsed = hsrp("ip 10.14.0.1\ntimers msec 250 msec 750\n")
    assert parsed.timers[0].hello_interval_ms == 250
    assert parsed.timers[0].hold_time_ms == 750


def test_two_groups_on_one_interface_stay_separate() -> None:
    parsed = parse_device(
        "hostname r1\ninterface Vlan14\n  ip address 10.14.0.2/24\n"
        "  hsrp 14\n    ip 10.14.0.1\n    priority 110\n"
        "  hsrp 15\n    ip 10.14.0.9\n    priority 90\n"
    )
    priorities = {
        record.number: record.member.priority for record in parsed.fhrp_records
    }
    assert priorities == {14: 110, 15: 90}
    assert parsed.unparsed_lines == ()


def test_an_interface_line_after_an_hsrp_block_is_still_the_interface_s() -> None:
    """The case a flattening splitter gets wrong: the block ends, the
    interface stanza does not."""
    parsed = parse_device(
        "hostname r1\ninterface Vlan14\n  ip address 10.14.0.2/24\n"
        "  hsrp 14\n    ip 10.14.0.1\n  mtu 9216\n  shutdown\n"
    )
    interface = parsed.device.interfaces[0]
    assert interface.mtu_bytes == 9216
    assert not interface.admin_enabled
    assert parsed.unparsed_lines == ()


# --------------------------------------------------------------------------
# Tracking
# --------------------------------------------------------------------------


def test_top_level_track_definition(parsed: ParsedDevice) -> None:
    assert len(parsed.tracked) == 1
    tracked = parsed.tracked[0]
    assert tracked.id == "1"
    assert tracked.device == "agg-a"
    assert tracked.target == "Ethernet1/1"


def test_group_references_the_track_with_a_decrement(parsed: ParsedDevice) -> None:
    """The group half of the join carries the id and decrement; the target is
    filled in from the top-level definition when the Fact Pack is assembled."""
    _, _, member, _, _ = group(parsed, 14)
    assert len(member.tracked_objects) == 1
    assert member.tracked_objects[0].id == "1"
    assert member.tracked_objects[0].decrement == 40
    assert member.tracked_objects[0].target == ""


def test_track_without_a_decrement_uses_the_platform_default() -> None:
    parsed = hsrp("ip 10.14.0.1\ntrack 1\n")
    _, _, member, _, _ = group(parsed, 14)
    assert member.tracked_objects[0].decrement == 10


def test_several_tracks_on_one_group() -> None:
    parsed = hsrp("ip 10.14.0.1\ntrack 1 decrement 40\ntrack 2 decrement 20\n")
    _, _, member, _, _ = group(parsed, 14)
    assert [(t.id, t.decrement) for t in member.tracked_objects] == [
        ("1", 40),
        ("2", 20),
    ]


# --------------------------------------------------------------------------
# BGP peerings
# --------------------------------------------------------------------------

NXOS_BGP: Final = """version 9.3(10)
hostname agg-a
feature bgp
feature bfd

interface Ethernet1/1
  no switchport
  ip address 10.0.0.0/31

interface loopback0
  ip address 10.255.0.1/32

router bgp 65000
  router-id 10.255.0.1
  log-neighbor-changes
  timers bgp 3 9
  address-family ipv4 unicast
    network 10.14.0.0/24
    maximum-paths 4
  template peer CORE
    remote-as 65001
    update-source loopback0
    address-family ipv4 unicast
      send-community
  neighbor 10.0.0.1
    remote-as 65001
    description core1 uplink
    update-source Ethernet1/1
    bfd
    address-family ipv4 unicast
      send-community
      route-map RM-IN in
      soft-reconfiguration inbound always
      next-hop-self
  neighbor 10.0.0.3
    inherit peer CORE
  neighbor 10.0.0.5
    password 3 0102030405
    maximum-prefix 1000 80
    timers 10 30
  neighbor 10.0.0.7
    remote-as 65004
    ebgp-multihop 2
  neighbor 10.0.0.9
    remote-as 65005
    shutdown
  neighbor 10.0.0.11 remote-as 65006
"""


@pytest.fixture(scope="module")
def bgp() -> BgpProcess:
    parsed = parse_device(NXOS_BGP)
    assert len(parsed.bgp) == 1
    return parsed.bgp[0]


def peer(process: BgpProcess, address: str) -> BgpNeighbor:
    return next(n for n in process.neighbors if n.address == address)


def test_the_bgp_block_leaves_nothing_unaccounted_for() -> None:
    """Same reason as `test_every_line_is_accounted_for`, applied to the block
    that nests three levels deep: silence is how this parser fails."""
    parsed = parse_device(NXOS_BGP)
    assert parsed.unparsed_lines == (), (
        f"unaccounted BGP lines: {parsed.unparsed_lines}"
    )


def test_the_process_carries_its_asn_and_router_id(bgp: BgpProcess) -> None:
    assert bgp.local_as == "65000"
    assert bgp.router_id == "10.255.0.1"


def test_peer_settings_are_read_out_of_the_sub_block(bgp: BgpProcess) -> None:
    """The NX-OS shape: none of these is on the `neighbor` line itself."""
    core = peer(bgp, "10.0.0.1")
    assert core.remote_as == "65001"
    assert core.description == "core1 uplink"
    assert core.update_source == "Ethernet1/1"
    assert core.bfd


def test_ebgp_multihop_and_shutdown_are_read(bgp: BgpProcess) -> None:
    assert peer(bgp, "10.0.0.7").multihop
    assert peer(bgp, "10.0.0.9").shutdown
    assert not peer(bgp, "10.0.0.1").shutdown


def test_a_neighbour_stated_on_one_line_is_read_too(bgp: BgpProcess) -> None:
    """NX-OS accepts the flat IOS form as well as the nested one."""
    assert peer(bgp, "10.0.0.11").remote_as == "65006"


def test_a_peer_known_only_by_settings_we_do_not_read_is_still_a_peering(
    bgp: BgpProcess,
) -> None:
    """The one that matters for the reciprocity rule: a neighbour configured
    only with a password, a prefix limit and timers is a real session, and
    dropping it would report the far end as one-sided when it is not."""
    quiet = peer(bgp, "10.0.0.5")
    assert quiet.remote_as is None
    assert not quiet.shutdown


def test_a_peer_template_is_not_a_peering(bgp: BgpProcess) -> None:
    """`template peer CORE` names a bag of settings, not a neighbour."""
    assert [n.address for n in bgp.neighbors] == [
        "10.0.0.1",
        "10.0.0.11",
        "10.0.0.3",
        "10.0.0.5",
        "10.0.0.7",
        "10.0.0.9",
    ]


def test_an_inherited_template_reaches_the_member(bgp: BgpProcess) -> None:
    member = peer(bgp, "10.0.0.3")
    assert member.peer_group == "CORE"
    assert member.remote_as == "65001"
    assert member.update_source == "loopback0"


def test_a_process_level_line_after_a_neighbour_block_is_still_the_process_s() -> None:
    """The case a flattening splitter gets wrong, in its BGP form: the peer's
    sub-block ends, the `router bgp` stanza does not."""
    parsed = parse_device(
        "feature bgp\nhostname r1\nrouter bgp 65000\n"
        "  neighbor 10.0.0.1\n    remote-as 65001\n"
        "  router-id 10.255.0.1\n"
    )
    assert parsed.bgp[0].router_id == "10.255.0.1"
    assert parsed.bgp[0].neighbors[0].remote_as == "65001"
    assert parsed.unparsed_lines == ()


def test_a_per_family_setting_is_not_read_as_a_peer_address() -> None:
    """`route-map RM-IN in` lives two levels under the process and is neither a
    neighbour nor an unhandled line."""
    parsed = parse_device(
        "feature bgp\nhostname r1\nrouter bgp 65000\n"
        "  neighbor 10.0.0.1\n    remote-as 65001\n"
        "    address-family ipv4 unicast\n      route-map RM-IN in\n"
    )
    assert [n.address for n in parsed.bgp[0].neighbors] == ["10.0.0.1"]
    assert parsed.unparsed_lines == ()


def test_an_unhandled_bgp_line_is_reported_rather_than_dropped() -> None:
    """`bgp dampening` is a timer this dialect does not read yet. It has to stay
    visible, because an unhandled construct that reports nothing is invisible."""
    parsed = parse_device("feature bgp\nhostname r1\nrouter bgp 65000\n  dampening\n")
    assert parsed.unparsed_lines == ("dampening",)


def test_an_unreadable_peer_setting_still_leaves_the_peering() -> None:
    """Reported, because the parser did not understand the line — and registered,
    because not understanding a setting is not evidence the peer is absent."""
    parsed = parse_device(
        "feature bgp\nhostname r1\nrouter bgp 65000\n"
        "  neighbor 10.0.0.1\n    invented-setting 4\n"
    )
    assert parsed.unparsed_lines == ("invented-setting 4",)
    assert [n.address for n in parsed.bgp[0].neighbors] == ["10.0.0.1"]


# --------------------------------------------------------------------------
# End to end: the cross-device rules, on NX-OS syntax
# --------------------------------------------------------------------------

NXOS_BGP_PAIR: Final = """version 9.3(10)
hostname {name}
feature bgp

interface Ethernet1/1
  no switchport
  ip address 10.0.0.{addr}/31

router bgp {local_as}
  router-id 10.255.0.{rid}
{neighbors}"""


def bgp_pair(
    tmp_path: Path,
    *,
    a_neighbors: str,
    b_neighbors: str = "",
    b_as: str = "65002",
) -> StaticFactPack:
    (tmp_path / "agg-a.cfg").write_text(
        NXOS_BGP_PAIR.format(
            name="agg-a", addr=0, local_as="65000", rid=1, neighbors=a_neighbors
        )
    )
    (tmp_path / "agg-b.cfg").write_text(
        NXOS_BGP_PAIR.format(
            name="agg-b", addr=1, local_as=b_as, rid=2, neighbors=b_neighbors
        )
    )
    pack, unparsed = build_fact_pack(tmp_path)
    assert not any(unparsed.values()), f"unaccounted lines: {unparsed}"
    return pack


def test_nxos_bgp_reaches_the_cross_device_rules(tmp_path: Path) -> None:
    """Two devices, NX-OS syntax, and both rules that read across the pair fire —
    which is only possible if the fact pack collected the processes."""
    pack = bgp_pair(
        tmp_path,
        a_neighbors=(
            "  neighbor 10.0.0.1\n    remote-as 65001\n    description agg-b\n    bfd\n"
        ),
    )
    assert pack.devices[0].nos_family is NosFamily.NX_OS
    fired = {f.rule for f in evaluate(pack)}
    assert "bgp-remote-as-mismatch" in fired
    assert "bgp-session-one-sided" in fired


def test_nxos_reciprocated_bgp_session_is_silent(tmp_path: Path) -> None:
    pack = bgp_pair(
        tmp_path,
        a_neighbors="  neighbor 10.0.0.1\n    remote-as 65002\n",
        b_neighbors="  neighbor 10.0.0.0\n    remote-as 65000\n",
    )
    fired = {f.rule for f in evaluate(pack)}
    assert "bgp-remote-as-mismatch" not in fired
    assert "bgp-session-one-sided" not in fired


def test_a_far_end_known_only_by_a_password_is_not_a_one_sided_session(
    tmp_path: Path,
) -> None:
    """The peering the far end states without a remote-as is still a peering."""
    pack = bgp_pair(
        tmp_path,
        a_neighbors="  neighbor 10.0.0.1\n    remote-as 65002\n",
        b_neighbors="  neighbor 10.0.0.0\n    password 3 0102030405\n",
    )
    assert "bgp-session-one-sided" not in {f.rule for f in evaluate(pack)}


def test_nxos_peer_off_every_local_subnet(tmp_path: Path) -> None:
    pack = bgp_pair(tmp_path, a_neighbors="  neighbor 192.0.2.9\n    remote-as 65001\n")
    assert "bgp-peer-off-subnet" in {f.rule for f in evaluate(pack)}


# --------------------------------------------------------------------------
# `switchport trunk allowed vlan add`, and the fix loop it broke
#
# `native_vlan_not_permitted_on_the_trunk` suggests exactly this line as its
# remedy. With the `add` form unread, applying the tool's own suggested change
# left the finding standing — PROJECT.md section 5.4 broken in the most visible
# way there is.
# --------------------------------------------------------------------------

NATIVE_NOT_ALLOWED: Final = """hostname nx1
feature interface-vlan
!
vlan 120
!
vlan 900
!
interface Ethernet1/1
  switchport
  switchport mode trunk
  switchport trunk native vlan 900
  switchport trunk allowed vlan 120
"""


def test_nxos_reads_the_whole_trunk_allowed_command() -> None:
    parsed = parse_device(
        "hostname nx1\n"
        "feature interface-vlan\n"
        "interface Ethernet1/1\n"
        "  switchport\n"
        "  switchport mode trunk\n"
        "  switchport trunk allowed vlan 120\n"
        "  switchport trunk allowed vlan add 220,900\n",
        device_id="nx1",
    )
    (trunk,) = parsed.device.interfaces
    assert trunk.allowed_vlans == (120, 220, 900)
    assert parsed.unparsed_lines == ()


def test_the_suggested_change_for_a_native_vlan_actually_removes_the_finding(
    tmp_path: Path,
) -> None:
    """The fix loop, closed end to end: take the finding's own `change`, append
    it to the interface it names, and the finding must be gone.

    It was not. The suggested line is `switchport trunk allowed vlan add 900`,
    and no parser read the `add` form, so the second run produced the same
    finding plus one more unparsed line — a tool telling the operator to type
    something it cannot then read.
    """
    (tmp_path / "nx1.cfg").write_text(NATIVE_NOT_ALLOWED)
    pack, _ = build_fact_pack(tmp_path)
    finding = next(
        f for f in evaluate(pack) if f.rule == "trunk-native-vlan-not-allowed"
    )
    assert finding.change, "the rule has to carry a change for this to be testable"

    # Apply it exactly as printed: the interface header names where the rest goes.
    header, *body = finding.change
    assert header == "interface Ethernet1/1"
    fixed = NATIVE_NOT_ALLOWED.replace(
        "  switchport trunk allowed vlan 120\n",
        "  switchport trunk allowed vlan 120\n" + "".join(f"{line}\n" for line in body),
    )
    (tmp_path / "nx1.cfg").write_text(fixed)
    after, unparsed = build_fact_pack(tmp_path)
    assert not any(unparsed.values()), "the tool suggested a line it cannot read"
    assert "trunk-native-vlan-not-allowed" not in {f.rule for f in evaluate(after)}


# --------------------------------------------------------------------------
# Preemption
#
# NX-OS reads HSRP only, and HSRP is the protocol that defaults preemption off,
# so the flag itself does not move here. What is new is that the pack can say
# whether an operator chose that or inherited it — and that `no preempt` reaches
# the parser instead of `unparsed_lines`.
# --------------------------------------------------------------------------

HSRP_SILENT_ON_PREEMPT: Final = """hostname dist-1
feature interface-vlan
feature hsrp
!
interface Vlan14
  ip address 10.14.0.2/24
  hsrp 14
    ip 10.14.0.1
    priority 110
"""


def test_an_hsrp_group_that_says_nothing_does_not_preempt() -> None:
    parsed = parse_device(HSRP_SILENT_ON_PREEMPT, device_id="dist-1")
    (record,) = parsed.fhrp_records
    assert record.member.preempt is False
    assert record.member.preempt_source is TimerSource.PLATFORM_DEFAULT


def test_no_preempt_inside_an_hsrp_block_is_read_rather_than_reported() -> None:
    parsed = parse_device(
        HSRP_SILENT_ON_PREEMPT + "    no preempt\n", device_id="dist-1"
    )
    (record,) = parsed.fhrp_records
    assert record.member.preempt is False
    assert record.member.preempt_source is TimerSource.CONFIGURED
    assert parsed.unparsed_lines == ()


def test_an_hsrp_group_that_writes_preempt_is_marked_as_having_said_so() -> None:
    parsed = parse_device(HSRP_SILENT_ON_PREEMPT + "    preempt\n", device_id="dist-1")
    (record,) = parsed.fhrp_records
    assert record.member.preempt is True
    assert record.member.preempt_source is TimerSource.CONFIGURED
