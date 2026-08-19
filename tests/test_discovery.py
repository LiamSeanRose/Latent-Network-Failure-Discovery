"""Finding the configs in a real directory, and refusing everything else.

The failure this covers is not a wrong answer, it is a confidently empty one: a
directory holding a hundred device configs in per-site folders, and a tool that
reports nothing because none of them ends in `.cfg`. So the first half of this
file is about what must be found — nested, mixed-extension, extensionless — and
the second half is about what must not, because a README parsed as a device is a
row in every finding that follows it.

The last test is the one that would notice the rewrite changing anything: the
shipped corpus still produces the same four devices under the same four ids.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack import discovery
from cassandra.factpack.builders import build_fact_pack

CORPUS: Final = Path(__file__).resolve().parents[1] / (
    "scenarios/site14_vrrp_lockstep/configs"
)

# Two interfaces and no hostname: enough that a file with its name stripped is
# still a device, which is what a backup tool writes.
TWO_PORTS: Final = (
    "interface Ethernet1\n"
    "   no switchport\n"
    "   ip address 10.0.0.1/31\n"
    "interface Ethernet2\n"
    "   no switchport\n"
    "   ip address 10.0.1.1/31\n"
)


def named(hostname: str) -> str:
    return f"hostname {hostname}\n{TWO_PORTS}"


def ids(config_dir: Path) -> list[str]:
    pack, _ = build_fact_pack(config_dir)
    return [device.id for device in pack.devices]


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


# --------------------------------------------------------------------------
# What must be found
# --------------------------------------------------------------------------


def test_configs_in_subdirectories_are_found(tmp_path: Path) -> None:
    """The whole point. A per-site tree is the normal shape of a collection."""
    write(tmp_path / "site-a" / "agg-a.cfg", named("site-a-agg-a"))
    write(tmp_path / "site-b" / "core" / "core1.cfg", named("core1"))
    # Path order, so a walk of the same tree twice produces the same pack.
    assert ids(tmp_path) == ["site-a-agg-a", "core1"]


def test_same_filename_in_two_folders_is_two_devices(tmp_path: Path) -> None:
    """A file's name is unique only within its folder, so the id carries the
    folder. Merging these would silently halve an inventory."""
    write(tmp_path / "site-a" / "agg-a", TWO_PORTS)
    write(tmp_path / "site-b" / "agg-a", TWO_PORTS)
    assert ids(tmp_path) == ["site-a/agg-a", "site-b/agg-a"]


def test_same_hostname_in_two_folders_is_two_devices(tmp_path: Path) -> None:
    """Harder case: the collision is inside the files, not in their names.

    Both give up the contested hostname rather than one of them keeping it on
    the strength of being read first.
    """
    write(tmp_path / "site-a" / "agg-a.cfg", named("agg-a"))
    write(tmp_path / "site-b" / "agg-a.cfg", named("agg-a"))
    with pytest.warns(discovery.ConfigDiscoveryWarning, match="more than one config"):
        pack, _ = build_fact_pack(tmp_path)
    assert [device.id for device in pack.devices] == ["site-a/agg-a", "site-b/agg-a"]
    # The declared name is not lost, it just stops being the identity.
    assert {device.hostname for device in pack.devices} == {"agg-a"}


def test_a_renamed_device_keeps_its_facts_attached_to_it(tmp_path: Path) -> None:
    """A half-renamed device is worse than a collided one: its interfaces would
    join the topology under a name its device no longer has."""
    gateway = (
        "interface Vlan{vid}\n"
        "   ip address 10.{vid}.0.{host}/24\n"
        "   vrrp {vid} ipv4 10.{vid}.0.1\n"
        "   vrrp {vid} priority-level 110\n"
        "   vrrp {vid} advertisement interval 1\n"
    )
    write(
        tmp_path / "a" / "sw.cfg",
        f"hostname sw\nvlan 10\n{TWO_PORTS}{gateway.format(vid=10, host=2)}",
    )
    write(
        tmp_path / "b" / "sw.cfg",
        f"hostname sw\nvlan 20\n{TWO_PORTS}{gateway.format(vid=20, host=3)}",
    )
    with pytest.warns(discovery.ConfigDiscoveryWarning):
        pack, unparsed = build_fact_pack(tmp_path)
    both = {"a/sw", "b/sw"}
    for device in pack.devices:
        assert {port.device for port in device.interfaces} == {device.id}
    assert {vlan.device for vlan in pack.vlans} == both
    assert set(unparsed) == both
    assert {
        member.device for group in pack.fhrp_groups for member in group.members
    } == both
    assert {timer.scope.device for timer in pack.timers.fhrp} == both


def test_every_accepted_extension_is_read(tmp_path: Path) -> None:
    """`.conf` and `.txt` are as common as `.cfg`, and a backup tool writes the
    hostname with no suffix at all."""
    for name in ("one.cfg", "two.conf", "three.txt", "four"):
        write(tmp_path / name, named(name.split(".")[0]))
    assert ids(tmp_path) == ["four", "one", "three", "two"]


def test_a_dotted_hostname_is_not_an_extension(tmp_path: Path) -> None:
    """`agg-a.example.com` is a device, not a file of type `.com`, so the name
    is kept whole rather than truncated at the first dot."""
    write(tmp_path / "agg-a.example.com", TWO_PORTS)
    assert ids(tmp_path) == ["agg-a.example.com"]


def test_a_config_with_a_long_banner_is_still_a_config(tmp_path: Path) -> None:
    """Banner prose sits at column zero, which is exactly where a content sniff
    looks for commands."""
    banner = "banner login\n" + "".join(
        f"Unauthorised access to this device is prohibited. Line {n}.\n"
        for n in range(40)
    )
    write(tmp_path / "sw.cfg", banner + "EOF\n" + named("sw"))
    assert ids(tmp_path) == ["sw"]


def test_a_symlinked_directory_of_configs_is_followed(tmp_path: Path) -> None:
    """Collections get assembled by symlink. Refusing to follow them would be a
    cheaper way to survive loops and a worse one."""
    write(tmp_path / "real" / "agg-a.cfg", named("agg-a"))
    (tmp_path / "tree").mkdir()
    (tmp_path / "tree" / "site-a").symlink_to(tmp_path / "real")
    assert ids(tmp_path / "tree") == ["agg-a"]


# --------------------------------------------------------------------------
# What must not be found
# --------------------------------------------------------------------------


def test_a_repository_full_of_noise_yields_only_the_configs(tmp_path: Path) -> None:
    write(tmp_path / "agg-a.cfg", named("agg-a"))
    write(tmp_path / "README.md", "# Site 14\n\nThe interface naming is per site.\n")
    write(tmp_path / "inventory.json", '{"devices": ["agg-a"]}\n')
    write(tmp_path / "topology.yml", "nodes:\n  agg-a:\n    kind: ceos\n")
    write(tmp_path / "build.py", "import os\nprint(os.getcwd())\n")
    write(tmp_path / ".git" / "config", "[core]\n\trepositoryformatversion = 0\n")
    write(tmp_path / ".git" / "HEAD", "ref: refs/heads/main\n")
    (tmp_path / "diagram.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    (tmp_path / "backup.tar.gz").write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 64)
    assert ids(tmp_path) == ["agg-a"]


def test_documentation_without_an_extension_is_not_a_device(tmp_path: Path) -> None:
    """The extensionless allowance is what lets a README in.  Prose fails the
    sniff, and the conventional names never reach it."""
    write(tmp_path / "agg-a", TWO_PORTS)
    write(
        tmp_path / "README",
        "Site 14\n=======\n\nEach interface is documented below.\n"
        "Ethernet1 goes to the core. Ethernet2 goes to the access layer.\n",
    )
    write(tmp_path / "NOTES", "Remember to check the vlan list before a change.\n")
    assert ids(tmp_path) == ["agg-a"]


def test_a_binary_file_named_cfg_is_refused_and_reported(tmp_path: Path) -> None:
    """Named like a config, so silence would be wrong; not a config, so a device
    would be worse."""
    (tmp_path / "firmware.cfg").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 512)
    write(tmp_path / "agg-a.cfg", named("agg-a"))
    found = discovery.discover(tmp_path)
    assert [config.device_id for config in found.configs] == ["agg-a"]
    assert any(
        skip.reason is discovery.SkipReason.BINARY and skip.path.name == "firmware.cfg"
        for skip in found.skipped
    )


def test_prose_named_cfg_is_refused_out_loud(tmp_path: Path) -> None:
    write(tmp_path / "agg-a.cfg", named("agg-a"))
    write(
        tmp_path / "handover.cfg",
        "Handover notes for the migration.\n"
        "The team agreed to move the aggregation layer first.\n"
        "Everything else follows in the second window.\n",
    )
    with pytest.warns(discovery.ConfigDiscoveryWarning, match="not-config"):
        pack, _ = build_fact_pack(tmp_path)
    assert [device.id for device in pack.devices] == ["agg-a"]


def test_a_config_that_yields_no_device_is_dropped_and_reported(
    tmp_path: Path,
) -> None:
    """It passes the sniff and still says nothing: no name of its own and not
    enough interfaces to be anything. Counting it would inflate the inventory
    with a device nobody can act on."""
    write(tmp_path / "agg-a.cfg", named("agg-a"))
    write(tmp_path / "leftover.cfg", "no ip domain-lookup\nend\n")
    with pytest.warns(
        discovery.ConfigDiscoveryWarning, match="not treated as a device"
    ):
        pack, _ = build_fact_pack(tmp_path)
    assert [device.id for device in pack.devices] == ["agg-a"]


def test_a_stub_config_that_names_itself_is_kept(tmp_path: Path) -> None:
    """The other side of that rule. A device with a hostname and one interface
    is a real, boring device, not junk."""
    write(tmp_path / "mgmt.cfg", "hostname mgmt\ninterface Management1\n   mtu 1500\n")
    assert ids(tmp_path) == ["mgmt"]


def test_an_oversized_file_is_not_read(tmp_path: Path) -> None:
    big = tmp_path / "capture.txt"
    big.write_text("hostname x\n")
    os.truncate(big, discovery.MAX_CONFIG_BYTES + 1)
    found = discovery.discover(tmp_path)
    assert found.configs == ()
    assert [skip.reason for skip in found.skipped] == [discovery.SkipReason.TOO_LARGE]


# --------------------------------------------------------------------------
# Hostile trees
# --------------------------------------------------------------------------


def test_a_symlink_loop_terminates(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    write(root / "site-a" / "agg-a.cfg", named("agg-a"))
    (root / "site-a" / "loop").symlink_to(root)
    found = discovery.discover(root)
    assert [config.device_id for config in found.configs] == ["site-a/agg-a"]
    assert any(
        skip.reason is discovery.SkipReason.SYMLINK_LOOP for skip in found.skipped
    )


def test_a_dangling_symlink_is_reported_not_raised(tmp_path: Path) -> None:
    write(tmp_path / "agg-a.cfg", named("agg-a"))
    (tmp_path / "agg-b.cfg").symlink_to(tmp_path / "gone.cfg")
    found = discovery.discover(tmp_path)
    assert [config.device_id for config in found.configs] == ["agg-a"]
    assert any(
        skip.reason is discovery.SkipReason.UNREADABLE and skip.path.name == "agg-b.cfg"
        for skip in found.skipped
    )
    assert any("agg-b.cfg" in note for note in found.notes())


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a mode 000 file")
def test_an_unreadable_file_is_reported_not_raised(tmp_path: Path) -> None:
    write(tmp_path / "agg-a.cfg", named("agg-a"))
    denied = write(tmp_path / "agg-b.cfg", named("agg-b"))
    denied.chmod(0o000)
    found = discovery.discover(tmp_path)
    assert [config.device_id for config in found.configs] == ["agg-a"]
    assert any(skip.reason is discovery.SkipReason.UNREADABLE for skip in found.skipped)


def test_a_missing_directory_is_empty_not_an_error(tmp_path: Path) -> None:
    found = discovery.discover(tmp_path / "nope")
    assert found.configs == ()
    assert found.skipped == ()


def test_a_file_passed_as_the_root_is_empty_not_an_error(tmp_path: Path) -> None:
    config = write(tmp_path / "agg-a.cfg", named("agg-a"))
    assert discovery.discover(config).configs == ()


def test_undecodable_bytes_do_not_stop_a_config_being_read(tmp_path: Path) -> None:
    """Devices predate the question of encoding. Latin-1 is a fallback, not a
    way in: the NUL check has already refused anything actually binary."""
    (tmp_path / "agg-a.cfg").write_bytes(
        b"hostname agg-a\ninterface Ethernet1\n   description caf\xe9 link\n"
        b"interface Ethernet2\n   mtu 9214\n"
    )
    assert ids(tmp_path) == ["agg-a"]


# --------------------------------------------------------------------------
# The sniff itself
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "hostname x\n",
        "! Command: show running-config\n!\nhostname x\n!\nend\n",
        "interface Ethernet1\n   switchport mode trunk\n",
        "ip access-list ACL\n   permit ip any any\n   deny ip any any\n",
    ],
)
def test_configuration_is_recognised(text: str) -> None:
    assert discovery.looks_like_config(text)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "# Cassandra\n\nPoint it at a directory of network configs.\n",
        '{"devices": [{"id": "agg-a"}]}\n',
        "nodes:\n  agg-a:\n    kind: ceos\n",
        "Every interface on the aggregation switches was renumbered.\n"
        "The vlan plan is attached to the change record.\n"
        "Nothing else changed.\n",
    ],
)
def test_prose_and_data_are_not_configuration(text: str) -> None:
    assert not discovery.looks_like_config(text)


# --------------------------------------------------------------------------
# Regression
# --------------------------------------------------------------------------


def test_the_shipped_corpus_is_unchanged() -> None:
    """Everything above is new behaviour. This is the promise that none of it
    reached the collection the rest of the suite is written against."""
    pack, unparsed = build_fact_pack(CORPUS)
    assert [device.id for device in pack.devices] == ["acc1", "agg-a", "agg-b", "core1"]
    assert pack.meta.device_count == 4
    assert set(unparsed) == {"acc1", "agg-a", "agg-b", "core1"}
    assert discovery.discover(CORPUS).notes() == ()
