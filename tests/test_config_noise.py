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
    assert parsed.fhrp, "the VRRP group was lost in the noise"


def test_an_unrecognised_interface_line_is_still_reported() -> None:
    """The filter must not hide a real gap. An interface sub-command this tool
    does not understand may well carry a fact, and silence there is the failure
    mode the unparsed list exists to prevent."""
    parsed = parse(
        "hostname r\ninterface Ethernet1\n   ip helper-address 10.0.0.9\n",
        device_id="r",
    )
    assert any("helper-address" in line for line in parsed.unparsed_lines)


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
