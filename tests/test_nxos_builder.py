"""The NX-OS dialect, against a config that exercises every construct it claims.

The load-bearing assertion is `test_every_line_is_accounted_for`: a permissive
parser fails by silence, not by error, so the representative config below is
checked line for line rather than field by field only.

The second is `test_hsrp_is_read_out_of_its_sub_block`. NX-OS is the first dialect
where indentation carries meaning — `ip 10.14.0.1` under `hsrp 14` is a virtual
address and `ip address 10.14.0.2/24` one level up is not — and a splitter that
flattened the two would still produce a plausible-looking Fact Pack.
"""

from __future__ import annotations

from typing import Final

import pytest

from cassandra.factpack.builders.common import ParsedDevice
from cassandra.factpack.builders.ios import looks_like_ios
from cassandra.factpack.builders.nxos import looks_like_nxos, parse_device
from cassandra.factpack.schema import (
    FhrpProtocol,
    InterfaceKind,
    NosFamily,
    SwitchportMode,
)

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
    return next(entry for entry in parsed.fhrp if entry[0] == number)


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
    numbers = {entry[0] for entry in parsed.fhrp}
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
    priorities = {entry[0]: entry[2].priority for entry in parsed.fhrp}
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
