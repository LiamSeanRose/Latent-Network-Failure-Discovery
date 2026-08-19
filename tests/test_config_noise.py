"""Real configs are mostly things this tool does not model.

The `unparsed` list exists to warn that a fact is missing. On a device config
that is 90% AAA, SNMP, banners and route-maps, an unfiltered list buries the one
line that matters and trains the reader to skip the section — at which point it
is worse than not having it.

These tests hold both ends: noise is suppressed, and anything that could plausibly
carry a fact is still reported.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack, parse
from cassandra.factpack.builders.common import is_out_of_scope, strip_banners

REALISTIC = """! Command: show running-config
no aaa root
username admin privilege 15 role network-admin secret sha512 $6$x$y
!
banner login
Authorised access only.
Disconnect immediately if you are not an authorised user.
EOF
!
hostname sw1
ntp server vrf default 10.0.0.123 prefer
snmp-server community public ro
spanning-tree mode mstp
!
management api http-commands
   protocol https
   no shutdown
!
route-map RM-OUT permit 10
   match ip address prefix-list PL-DEFAULT
   set metric 100
!
vlan 10
   name SERVERS
!
interface Vlan10
   ip address 10.10.0.2/24
   vrrp 10 ipv4 10.10.0.1
   vrrp 10 priority-level 110
!
end
"""


def test_banner_prose_is_not_read_as_configuration() -> None:
    """Banner text sits at column zero, so a stanza parser reads every line of
    it as a command. It is the largest single source of nonsense in a real
    config."""
    parsed = parse(REALISTIC, device_id="sw1")
    joined = " ".join(parsed.unparsed_lines)
    assert "Authorised access only." not in joined
    assert "Disconnect immediately" not in joined
    assert "EOF" not in parsed.unparsed_lines


def test_out_of_scope_sections_take_their_bodies_with_them() -> None:
    parsed = parse(REALISTIC, device_id="sw1")
    joined = " ".join(parsed.unparsed_lines)
    for noise in (
        "protocol https",
        "match ip address",
        "set metric 100",
        "snmp-server",
    ):
        assert noise not in joined, f"{noise!r} should be filtered"


def test_the_facts_still_come_through_the_noise() -> None:
    parsed = parse(REALISTIC, device_id="sw1")
    assert parsed.device.hostname == "sw1"
    assert [v.vlan_id for v in parsed.vlans] == [10]
    names = {i.name for i in parsed.device.interfaces}
    assert "Vlan10" in names
    assert parsed.fhrp_records, "the VRRP group was lost in the noise"


def test_an_unrecognised_interface_line_is_still_reported() -> None:
    """The filter must not hide a real gap. An interface sub-command this tool
    does not understand may well carry a fact, and silence there is the failure
    mode the unparsed list exists to prevent."""
    # `vrrp 14 bfd ip` couples an FHRP group to a BFD session, which changes how
    # fast the group notices a failure. Nothing here reads it yet, and that is
    # exactly the kind of omission the list exists to make visible.
    parsed = parse(
        "hostname r\ninterface Ethernet1\n   vrrp 14 bfd ip 10.14.0.3\n",
        device_id="r",
    )
    assert any("bfd ip" in line for line in parsed.unparsed_lines)


def test_an_unrecognised_top_level_section_is_still_reported() -> None:
    parsed = parse("hostname r\nsome-future-feature enable\n", device_id="r")
    assert any("some-future-feature" in line for line in parsed.unparsed_lines)


def test_realistic_config_reports_almost_nothing_unparsed(tmp_path: Path) -> None:
    """The measurable version of the claim: this config produced 22 unparsed
    lines before filtering."""
    (tmp_path / "sw1.cfg").write_text(REALISTIC)
    _, unparsed = build_fact_pack(tmp_path)
    assert len(unparsed["sw1"]) <= 2, unparsed["sw1"]


def test_out_of_scope_matcher_is_conservative() -> None:
    """Anything not explicitly listed stays reported."""
    assert is_out_of_scope("snmp-server community public ro")
    assert is_out_of_scope("no aaa root")
    assert not is_out_of_scope("vrrp 10 preempt")
    assert not is_out_of_scope("ip address 10.0.0.1/31")
    assert not is_out_of_scope("bfd interval 300 min_rx 300 multiplier 3")


def test_strip_banners_leaves_ordinary_config_alone() -> None:
    config = "hostname r\ninterface Ethernet1\n   ip address 10.0.0.1/31\n"
    assert strip_banners(config) == config.rstrip("\n")


# Constructs a real campus config carries on almost every interface, none of
# which any tier reads. They were unparsed, which buries the lines that genuinely
# indicate a missing fact under a wall of ACL and DHCP-relay statements.
_ORDINARY_NOISE: Final = {
    "ios": (
        "hostname r1\n"
        "line console\n"
        " exec-timeout 15\n"
        "interface GigabitEthernet0/1\n"
        " switchport trunk encapsulation dot1q\n"
        " switchport mode trunk\n"
        " ip access-group CORE-IN in\n"
        " ip helper-address 10.0.0.9\n"
        " no ip proxy-arp\n"
        "interface Vlan14\n"
        " ip address 10.14.0.2 255.255.255.0\n"
        " standby version 2\n"
        " standby 14 ip 10.14.0.1\n"
    ),
    "eos": (
        "hostname r1\n"
        "interface Vlan14\n"
        "   ip address 10.14.0.2/24\n"
        "   ip access-group CORE-IN in\n"
        "   ip helper-address 10.0.0.9\n"
        "   vrrp 14 ipv4 10.14.0.1\n"
    ),
    "nxos": (
        "hostname r1\n"
        "feature hsrp\n"
        "line console\n"
        "  exec-timeout 15\n"
        "interface Vlan120\n"
        "  ip address 172.16.120.2/24\n"
        "  ip access-group CORE-IN in\n"
        "  ip dhcp relay address 172.16.250.10\n"
        "  hsrp 120\n"
        "    ip 172.16.120.1\n"
    ),
}


@pytest.mark.parametrize("dialect", sorted(_ORDINARY_NOISE))
def test_ordinary_interface_features_do_not_read_as_gaps(dialect: str) -> None:
    """An unparsed line is a claim that something was missed.

    A campus config states an ACL, a DHCP relay and an HSRP version on almost
    every interface. None of them carries a fact any tier reads, so listing them
    spends the reader's attention on lines that are fine and hides the one that
    is not.
    """
    parsed = parse(_ORDINARY_NOISE[dialect], device_id="r1")
    assert parsed.unparsed_lines == ()


@pytest.mark.parametrize("dialect", sorted(_ORDINARY_NOISE))
def test_the_group_still_survives_the_noise(dialect: str) -> None:
    """The guard: a filter wide enough to swallow the group as well would
    satisfy the test above and be much worse than the problem it fixed."""
    parsed = parse(_ORDINARY_NOISE[dialect], device_id="r1")
    assert parsed.fhrp_records, "the group was lost with the noise"
    assert parsed.device.interfaces, "the interfaces were lost with the noise"


def test_a_console_stanza_is_out_of_scope_however_it_is_spelled() -> None:
    """`line con 0` matched and `line console` did not, so a console stanza and
    its whole body leaked on every config that spells the word out."""
    for spelling in ("line con 0", "line console", "line vty 0 4", "line aux 0"):
        assert is_out_of_scope(spelling), spelling
    assert not is_out_of_scope("line protocol")
