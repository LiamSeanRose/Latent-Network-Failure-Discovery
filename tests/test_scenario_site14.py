"""Self-consistency checks for the Phase 0 scenario artifacts.

The scenario was written in an environment with no Docker daemon, so none of it
has been booted. These checks catch the errors that are findable without booting
anything: an endpoint naming a node that does not exist, an interface used in the
topology with no stanza in the config, a subnet that does not pair up, a tracked
object nothing defines, a VRRP virtual address outside its own subnet.

The parsing here is deliberately crude and deliberately not reusable. It is a lint
over four known files, not a config parser — `factpack/builders/` is Phase 1 and
owns that job properly. Delete this in favour of the real builders when they land.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Final

import pytest
import yaml

SCENARIO: Final = (
    Path(__file__).resolve().parents[1] / "scenarios" / "site14_vrrp_lockstep"
)
TOPOLOGY: Final = SCENARIO / "topology.clab.yml"
CEOS_NODES: Final = ("core1", "agg-a", "agg-b", "acc1")
AGGS: Final = ("agg-a", "agg-b")
GROUPS: Final = (14, 24, 34)


def topology() -> dict:
    return yaml.safe_load(TOPOLOGY.read_text())["topology"]


def config(node: str) -> str:
    """Config text with comment lines stripped.

    Comments here describe the very asymmetry the tests assert the absence of,
    so matching against raw text produces false positives.
    """
    raw = (SCENARIO / "configs" / f"{node}.cfg").read_text()
    return (
        "\n".join(line for line in raw.splitlines() if not line.startswith("!")) + "\n"
    )


def interface_blocks(text: str) -> dict[str, list[str]]:
    """Map interface name -> its indented lines. Crude on purpose."""
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("interface "):
            current = line.split(None, 1)[1].strip()
            blocks[current] = []
        elif current and line.startswith("   "):
            blocks[current].append(line.strip())
        elif not line.startswith(" "):
            current = None
    return blocks


def addresses(node: str) -> dict[str, ipaddress.IPv4Interface]:
    out: dict[str, ipaddress.IPv4Interface] = {}
    for iface, lines in interface_blocks(config(node)).items():
        for line in lines:
            if m := re.fullmatch(r"ip address (\S+)", line):
                out[iface] = ipaddress.ip_interface(m.group(1))
    return out


def link_endpoints() -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for link in topology()["links"]:
        for endpoint in link["endpoints"]:
            node, iface = endpoint.split(":")
            pairs.append((node, iface))
    return pairs


# --------------------------------------------------------------------------
# Topology integrity
# --------------------------------------------------------------------------


def test_every_link_endpoint_names_a_declared_node() -> None:
    nodes = set(topology()["nodes"])
    for node, _ in link_endpoints():
        assert node in nodes, f"link references undeclared node {node!r}"


def test_every_startup_config_exists() -> None:
    for name, node in topology()["nodes"].items():
        if "startup-config" not in node:
            continue
        path = SCENARIO / node["startup-config"]
        assert path.is_file(), f"{name}: missing {path}"


def test_hostname_matches_node_name() -> None:
    for node in CEOS_NODES:
        assert f"hostname {node}" in config(node).splitlines()


def test_every_topology_interface_is_configured() -> None:
    """clab `ethN` maps to `EthernetN` inside cEOS. An interface wired in the
    topology with no stanza comes up unconfigured and the failure is silent."""
    for node, iface in link_endpoints():
        if node not in CEOS_NODES:
            continue
        eos_name = iface.replace("eth", "Ethernet")
        assert eos_name in interface_blocks(config(node)), (
            f"{node}: {eos_name} unconfigured"
        )


def test_node_resources_are_bounded() -> None:
    """PROJECT.md §3.1: containerlab sets no defaults, and an unbounded node
    destabilises the host."""
    for kind, spec in topology()["kinds"].items():
        assert "memory" in spec, f"{kind}: no memory limit"
        assert "cpu" in spec, f"{kind}: no cpu limit"


# --------------------------------------------------------------------------
# Addressing
# --------------------------------------------------------------------------


def test_no_duplicate_addresses_across_devices() -> None:
    seen: dict[ipaddress.IPv4Address, str] = {}
    for node in CEOS_NODES:
        for iface, addr in addresses(node).items():
            assert addr.ip not in seen, f"{node}:{iface} duplicates {seen[addr.ip]}"
            seen[addr.ip] = f"{node}:{iface}"


def test_point_to_point_links_pair_up() -> None:
    """Both ends of an L3 link must sit in the same subnet, or no adjacency."""
    for link in topology()["links"]:
        (a_node, a_if), (b_node, b_if) = (e.split(":") for e in link["endpoints"])
        if a_node not in CEOS_NODES or b_node not in CEOS_NODES:
            continue
        a = addresses(a_node).get(a_if.replace("eth", "Ethernet"))
        b = addresses(b_node).get(b_if.replace("eth", "Ethernet"))
        if a is None or b is None:
            continue  # L2 trunk, nothing to pair
        assert a.network == b.network, (
            f"{a_node}:{a_if} {a} and {b_node}:{b_if} {b} are not in one subnet"
        )


@pytest.mark.parametrize("group", GROUPS)
def test_svi_pair_shares_a_subnet_with_distinct_addresses(group: int) -> None:
    a = addresses("agg-a")[f"Vlan{group}"]
    b = addresses("agg-b")[f"Vlan{group}"]
    assert a.network == b.network, f"Vlan{group}: aggs in different subnets"
    assert a.ip != b.ip


# --------------------------------------------------------------------------
# VRRP intent
# --------------------------------------------------------------------------


def vrrp_lines(node: str, group: int) -> list[str]:
    return [
        line
        for lines in interface_blocks(config(node)).values()
        for line in lines
        if line.startswith(f"vrrp {group} ")
    ]


def vrrp_value(node: str, group: int, keyword: str) -> str | None:
    for line in vrrp_lines(node, group):
        if m := re.fullmatch(rf"vrrp {group} {keyword} (.+)", line):
            return m.group(1)
    return None


@pytest.mark.parametrize("group", GROUPS)
def test_virtual_address_is_inside_the_svi_subnet_and_agreed(group: int) -> None:
    virtuals = {node: vrrp_value(node, group, "ipv4") for node in AGGS}
    assert len(set(virtuals.values())) == 1, f"group {group}: aggs disagree: {virtuals}"
    virtual = ipaddress.ip_address(virtuals["agg-a"])
    subnet = addresses("agg-a")[f"Vlan{group}"].network
    assert virtual in subnet, f"group {group}: virtual {virtual} outside {subnet}"
    for node in AGGS:
        assert virtual != addresses(node)[f"Vlan{group}"].ip, (
            f"group {group}: virtual address collides with {node}'s real address"
        )


@pytest.mark.parametrize("group", GROUPS)
def test_intended_master_outranks_intended_backup(group: int) -> None:
    a = int(vrrp_value("agg-a", group, "priority-level"))
    b = int(vrrp_value("agg-b", group, "priority-level"))
    assert a > b, f"group {group}: agg-a ({a}) does not outrank agg-b ({b})"


def test_tracked_objects_are_defined_where_referenced() -> None:
    """A `tracked-object` naming an object that does not exist is accepted at
    config time and silently never fires — which would make the scenario quietly
    prove nothing."""
    for node in AGGS:
        text = config(node)
        defined = set(re.findall(r"^track (\S+) ", text, flags=re.M))
        referenced = set(re.findall(r"vrrp \d+ tracked-object (\S+) ", text))
        assert referenced <= defined, (
            f"{node}: undefined tracked objects {referenced - defined}"
        )


def test_the_asymmetry_the_scenario_depends_on_is_present() -> None:
    """If this ever passes trivially, the scenario has stopped testing anything:
    group 14 must preempt back immediately, 24 must wait, 34 must not track."""
    assert vrrp_value("agg-a", 14, "preempt delay minimum") is None
    assert vrrp_value("agg-a", 24, "preempt delay minimum") == "90"
    assert vrrp_value("agg-a", 14, "tracked-object UPLINK decrement") == "40"
    assert vrrp_value("agg-a", 24, "tracked-object UPLINK decrement") == "40"
    assert vrrp_value("agg-a", 34, "tracked-object UPLINK decrement") is None


def test_backup_carries_none_of_the_asymmetry() -> None:
    text = config("agg-b")
    assert "tracked-object" not in text
    assert "preempt delay" not in text


# --------------------------------------------------------------------------
# L2 path
# --------------------------------------------------------------------------


def test_trunks_carry_every_vrrp_vlan() -> None:
    """VRRP advertisements travel over these trunks. A VLAN missing from one of
    them splits the group into two masters that cannot see each other."""
    for node in ("agg-a", "agg-b", "acc1"):
        for iface, lines in interface_blocks(config(node)).items():
            if "switchport mode trunk" not in lines:
                continue
            allowed = next(
                (
                    line.removeprefix("switchport trunk allowed vlan ")
                    for line in lines
                    if line.startswith("switchport trunk allowed vlan ")
                ),
                "",
            )
            carried = {int(v) for v in allowed.split(",") if v.strip().isdigit()}
            assert set(GROUPS) <= carried, (
                f"{node}:{iface} carries {carried}, needs {GROUPS}"
            )


def test_client_access_vlan_is_the_scenario_vlan() -> None:
    blocks = interface_blocks(config("acc1"))
    access = [
        line
        for lines in blocks.values()
        for line in lines
        if line.startswith("switchport access vlan")
    ]
    assert access == ["switchport access vlan 14"]


def test_access_switch_does_not_route() -> None:
    """acc1 must not be able to influence the election it transports."""
    text = config("acc1")
    assert "no ip routing" in text
    assert "interface Vlan" not in text
