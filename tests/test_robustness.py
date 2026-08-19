"""What the tool does with input nobody designed it for.

A config directory is whatever a network engineer has been backing up into for
years. It holds files in three encodings, files written by a Windows editor,
files a transfer cut in half, files that are not files at all, and directories
that point at themselves. None of that is exotic; it is the normal state of a
backup target that has outlived two toolchains.

So the bar here is not "does not raise". It is that every hazard produces a
stated outcome: the tool reads the file, or it refuses it and says which file
and why. A hazard that yields a confident, wrong answer is the worst case of
the three, and several tests below pin exactly that.

Several of these started as failing tests naming a defect. The defects are
fixed and the tests are now the guard on them, so each one still says what it
used to do — a test whose history is written down is one nobody quietly
weakens later.
"""

from __future__ import annotations

import dataclasses
import os
import signal
import stat
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Final
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import urlopen

import pytest

from cassandra import cli
from cassandra.app import Handler
from cassandra.factpack import discovery
from cassandra.factpack.builders import build_fact_pack, parse
from cassandra.factpack.builders.common import vlan_list
from cassandra.factpack.schema import StaticFactPack

# Two addressed interfaces and no hostname: the minimum a file needs before the
# builder will call it a device, so every fixture below that omits `hostname`
# is still a device on purpose rather than by accident.
TWO_PORTS: Final[str] = (
    "interface Ethernet1\n"
    "   no switchport\n"
    "   ip address 10.0.0.1/31\n"
    "interface Ethernet2\n"
    "   no switchport\n"
    "   ip address 10.0.1.1/31\n"
)

# One device exercising most of what the parsers read: VLANs, a trunk, an SVI, a
# VRRP group with tracking, BFD, OSPF and BGP. Used wherever a test needs to
# compare two readings of the *same* config and see whether they agree.
RICH: Final[str] = """hostname agg-a
!
vlan 10,20,30-32
!
interface Ethernet1
   no switchport
   ip address 10.0.0.1/31
   bfd interval 300 min_rx 300 multiplier 3
   ip ospf hello-interval 1
   ip ospf dead-interval 3
!
interface Ethernet2
   switchport mode trunk
   switchport trunk allowed vlan 10,20,30-32
!
interface Vlan14
   ip address 10.10.14.2/24
   vrrp 14 ipv4 10.10.14.1
   vrrp 14 priority-level 120
   vrrp 14 preempt
   vrrp 14 preempt delay minimum 90
   vrrp 14 tracked-object UPLINK decrement 30
!
track UPLINK interface Ethernet1 line-protocol
!
router bgp 65001
   router-id 10.255.0.1
   neighbor 10.0.0.0 remote-as 65002
!
end
"""

# The whole reading of one config, as a comparable value. Everything the fact
# pack is built from is in here, so two of these being equal means the two
# inputs were understood identically rather than merely both parsed.
type Reading = tuple[object, ...]


def reading(text: str) -> Reading:
    parsed = parse(text, device_id="agg-a")
    return (
        dataclasses.asdict(parsed.device),
        parsed.fhrp,
        parsed.timers,
        parsed.vlans,
        parsed.unparsed_lines,
    )


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def write_bytes(path: Path, raw: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


def device_ids(config_dir: Path) -> list[str]:
    pack, _ = build_fact_pack(config_dir)
    return [device.id for device in pack.devices]


def unparsed_for(config_dir: Path, device: str) -> tuple[str, ...]:
    _, unparsed = build_fact_pack(config_dir)
    return unparsed.get(device, ())


def pack_of(config_dir: Path) -> StaticFactPack:
    pack, _ = build_fact_pack(config_dir)
    return pack


@contextmanager
def deadline(seconds: int) -> Iterator[None]:
    """Fail rather than hang.

    Several of these hazards used to block forever rather than raise, and a
    suite that hangs is worse than one that goes red: nobody reads a build that
    never finishes.
    """
    if not hasattr(signal, "SIGALRM"):  # pragma: no cover - platform dependent
        yield
        return

    def expire(_signum: int, _frame: object) -> None:
        raise TimeoutError(f"took longer than {seconds}s")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


# --------------------------------------------------------------------------
# 1. Encodings
# --------------------------------------------------------------------------


def test_a_byte_order_mark_does_not_swallow_the_hostname(tmp_path: Path) -> None:
    """A UTF-8 BOM sits in front of the first line, and the first line of a
    config is very often `hostname`. Left in place it makes that line match
    nothing, so the device silently answers to its filename instead of its
    name — a wrong answer that looks exactly like a right one."""
    write_bytes(
        tmp_path / "backup01.cfg",
        b"\xef\xbb\xbf" + f"hostname core-1\n{TWO_PORTS}".encode(),
    )
    found = discovery.discover(tmp_path)
    assert [config.declared_hostname for config in found.configs] == ["core-1"]
    assert device_ids(tmp_path) == ["core-1"]
    assert unparsed_for(tmp_path, "core-1") == ()


def test_a_utf16_config_is_read_rather_than_mistaken_for_a_binary(
    tmp_path: Path,
) -> None:
    """UTF-16 is what a config saved out of a Windows management station looks
    like. It is full of NUL bytes by construction, so a binary check that runs
    before the encoding is decided throws the whole device away."""
    write_bytes(
        tmp_path / "core-1.cfg", f"hostname core-1\n{TWO_PORTS}".encode("utf-16")
    )
    assert device_ids(tmp_path) == ["core-1"]
    pack = pack_of(tmp_path)
    assert [i.name for i in pack.devices[0].interfaces] == ["Ethernet1", "Ethernet2"]


def test_utf16_without_a_mark_is_refused_by_name(tmp_path: Path) -> None:
    """Nothing in the bytes says what they are, so refusing is right. Refusing
    quietly is not: the operator named this file `.cfg`, and a run that reports
    one device out of two must say which one it dropped and why."""
    write(tmp_path / "core-1.cfg", f"hostname core-1\n{TWO_PORTS}")
    write_bytes(
        tmp_path / "core-2.cfg", f"hostname core-2\n{TWO_PORTS}".encode("utf-16-le")
    )
    found = discovery.discover(tmp_path)
    assert [config.device_id for config in found.configs] == ["core-1"]
    refused = [skip for skip in found.skipped if skip.path.name == "core-2.cfg"]
    assert [skip.reason for skip in refused] == [discovery.SkipReason.BINARY]
    assert any("core-2.cfg" in note and "binary" in note for note in found.notes())


def test_latin1_accents_in_a_banner_do_not_stop_the_config_being_read(
    tmp_path: Path,
) -> None:
    """An 8-bit encoding is not a refusal condition — it is the normal output of
    a device that predates the question — and the accented banner must not end
    up quoted back as an unparsed configuration line."""
    write_bytes(
        tmp_path / "core-1.cfg",
        b"hostname core-1\n"
        b"banner motd\n"
        b"Acc\xe8s r\xe9serv\xe9 au personnel autoris\xe9.\n"
        b"EOF\n" + TWO_PORTS.encode(),
    )
    assert device_ids(tmp_path) == ["core-1"]
    assert unparsed_for(tmp_path, "core-1") == ()


def test_invalid_utf8_in_the_middle_does_not_cost_the_rest_of_the_file(
    tmp_path: Path,
) -> None:
    """One corrupt byte in a description must not take the interfaces after it
    with it. The file is decoded permissively and read to the end."""
    write_bytes(
        tmp_path / "core-1.cfg",
        b"hostname core-1\n"
        b"interface Ethernet1\n"
        b"   description uplink \xff\xfe to core\n"
        b"   no switchport\n"
        b"   ip address 10.0.0.1/31\n"
        b"interface Ethernet2\n"
        b"   no switchport\n"
        b"   ip address 10.0.1.1/31\n",
    )
    pack = pack_of(tmp_path)
    assert [device.id for device in pack.devices] == ["core-1"]
    assert [i.name for i in pack.devices[0].interfaces] == ["Ethernet1", "Ethernet2"]


# --------------------------------------------------------------------------
# 2. Line endings
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "convert"),
    [
        ("crlf", lambda text: text.replace("\n", "\r\n")),
        ("lone-cr", lambda text: text.replace("\n", "\r")),
        ("mixed", lambda text: text.replace("\n", "\r\n", 6)),
        ("no-trailing-newline", lambda text: text.rstrip("\n")),
    ],
)
def test_a_config_reads_identically_whatever_ended_its_lines(
    label: str, convert: Callable[[str], str]
) -> None:
    """A config a Windows editor has touched is the same config. Anything less
    than byte-identical readings here means every finding depends on which
    machine last saved the file."""
    assert reading(convert(RICH)) == reading(RICH), (
        f"{label} line endings change how the config is read"
    )


def test_the_line_ending_comparison_is_actually_comparing_something() -> None:
    """The guard on the test above: a reading that was empty would compare
    equal to another empty one and prove nothing."""
    device, fhrp, _timers, vlans, unparsed = reading(RICH)
    assert [i.name for i in parse(RICH, device_id="agg-a").device.interfaces] == [
        "Ethernet1",
        "Ethernet2",
        "Vlan14",
    ]
    assert [(number, virtual) for number, _p, _m, _i, virtual in fhrp] == [
        (14, "10.10.14.1")
    ]
    assert [vlan.vlan_id for vlan in vlans] == [10, 20, 30, 31, 32]
    assert unparsed == ()
    assert device["hostname"] == "agg-a"


def test_crlf_configs_produce_the_same_findings_as_unix_ones(tmp_path: Path) -> None:
    """The end-to-end half of the same claim: same rules fire, same devices."""
    unix = tmp_path / "unix"
    dos = tmp_path / "dos"
    write(unix / "agg-a.cfg", RICH)
    write(dos / "agg-a.cfg", RICH.replace("\n", "\r\n"))
    assert cli.main(["check", str(unix)]) == cli.main(["check", str(dos)])
    assert device_ids(unix) == device_ids(dos) == ["agg-a"]


# --------------------------------------------------------------------------
# 3. Truncated and malformed input
# --------------------------------------------------------------------------


def test_a_config_cut_off_mid_stanza_keeps_what_came_before_it(
    tmp_path: Path,
) -> None:
    """A transfer that died halfway through leaves a partial last line. The
    device before it is real and must survive; the fragment must be reported
    rather than guessed at."""
    write(
        tmp_path / "agg-a.cfg",
        "hostname agg-a\n"
        f"{TWO_PORTS}"
        "interface Vlan14\n"
        "   ip address 10.10.14.2/24\n"
        "   vrrp 14 ipv",
    )
    pack = pack_of(tmp_path)
    assert [device.id for device in pack.devices] == ["agg-a"]
    assert [i.name for i in pack.devices[0].interfaces] == [
        "Ethernet1",
        "Ethernet2",
        "Vlan14",
    ]
    # The group has no virtual address because the line naming it was cut in
    # half, and the half-line is reported rather than silently dropped.
    assert [group.virtual_ipv4 for group in pack.fhrp_groups] == [None]
    assert "vrrp 14 ipv" in unparsed_for(tmp_path, "agg-a")


def test_a_stanza_with_no_body_is_an_interface_with_no_settings(
    tmp_path: Path,
) -> None:
    write(
        tmp_path / "agg-a.cfg",
        "hostname agg-a\ninterface Ethernet1\ninterface Ethernet2\n",
    )
    pack = pack_of(tmp_path)
    interfaces = pack.devices[0].interfaces
    assert [i.name for i in interfaces] == ["Ethernet1", "Ethernet2"]
    assert [i.addresses for i in interfaces] == [(), ()]
    assert unparsed_for(tmp_path, "agg-a") == ()


def test_an_interface_block_with_no_name_invents_no_interface(
    tmp_path: Path,
) -> None:
    """`interface` on its own names nothing. An interface with an empty name
    would join the topology and collide with the next device's empty one."""
    write(
        tmp_path / "agg-a.cfg",
        f"hostname agg-a\n{TWO_PORTS}interface\n   ip address 10.9.9.9/24\n",
    )
    pack = pack_of(tmp_path)
    assert [i.name for i in pack.devices[0].interfaces] == ["Ethernet1", "Ethernet2"]
    assert "interface" in unparsed_for(tmp_path, "agg-a")


def test_an_fhrp_group_with_no_virtual_address_is_reported_not_crashed_on(
    tmp_path: Path,
) -> None:
    """Half a group: priority and preempt configured, no address to hold. The
    group is real and must appear, and no rule that reads an address may run."""
    write(
        tmp_path / "agg-a.cfg",
        "hostname agg-a\n"
        f"{TWO_PORTS}"
        "interface Vlan14\n"
        "   ip address 10.10.14.2/24\n"
        "   vrrp 14 priority-level 120\n"
        "   vrrp 14 preempt\n",
    )
    pack = pack_of(tmp_path)
    assert [(g.group_number, g.virtual_ipv4) for g in pack.fhrp_groups] == [(14, None)]
    assert cli.main(["check", str(tmp_path)]) in {0, 1}


# `virtual_address_outside_subnet` called `ipaddress.ip_address` with no guard,
# so one mistyped octet in `vrrp 14 ipv4 10.10.14.300` took the whole run down
# with a ValueError traceback — every finding on every other device with it. A
# typo in an address is the single most likely malformation in a config,
# which makes this the most reachable crash in the tool.
def test_a_mistyped_virtual_address_does_not_crash_the_run(tmp_path: Path) -> None:
    write(
        tmp_path / "agg-a.cfg",
        "hostname agg-a\n"
        f"{TWO_PORTS}"
        "interface Vlan14\n"
        "   ip address 10.10.14.2/24\n"
        "   vrrp 14 ipv4 10.10.14.300\n",
    )
    assert cli.main(["check", str(tmp_path)]) in {0, 1, 2}


# A range whose halves are not both digits used to be dropped without a word,
# so a config that meant to declare VLAN 10 read as a config that declared
# nothing, and the downstream "uses VLAN 10, which is not declared" finding
# blamed the operator for a line the parser could not read. Silence is the one
# answer that misleads.
@pytest.mark.parametrize("line", ["vlan 10-", "vlan abc", "vlan 30-10"])
def test_a_malformed_vlan_range_is_reported_not_silently_dropped(
    tmp_path: Path, line: str
) -> None:
    write(tmp_path / "agg-a.cfg", f"hostname agg-a\n{TWO_PORTS}{line}\n")
    pack = pack_of(tmp_path)
    assert pack.vlans == ()
    reported = unparsed_for(tmp_path, "agg-a")
    assert any(entry.startswith(line) for entry in reported), reported
    assert any("unreadable" in entry for entry in reported), (
        "the line has to say which part could not be read, or the reader is "
        "left comparing it against a parser they cannot see"
    )


# 0 and 4095 are not VLAN ids; 802.1Q reserves both and no device will accept
# them. They used to be recorded as ordinary VLANs, which put a segment in the
# topology that cannot exist and judged interfaces against it.
@pytest.mark.parametrize("vlan_id", ["0", "4095", "9999"])
def test_an_out_of_range_vlan_id_is_not_recorded_as_a_vlan(
    tmp_path: Path, vlan_id: str
) -> None:
    write(tmp_path / "agg-a.cfg", f"hostname agg-a\n{TWO_PORTS}vlan {vlan_id}\n")
    assert pack_of(tmp_path).vlans == ()


# The expansion had no bound on either end, so a fat-fingered
# `switchport trunk allowed vlan 1-99999999` allocated a hundred million
# integers and the process died of memory exhaustion rather than reporting
# anything. There are only 4094 VLAN ids; nothing outside that range can be
# real, so the expansion has a natural bound.
def test_an_absurd_vlan_range_does_not_expand_to_millions() -> None:
    assert len(vlan_list("1-1000000")) <= 4094


# --------------------------------------------------------------------------
# 4. Sizes and shapes
# --------------------------------------------------------------------------


def test_a_single_line_of_several_megabytes_is_read_in_seconds(
    tmp_path: Path,
) -> None:
    """One enormous line is what a flattened ACL or a mangled export looks
    like. It must not turn a directory scan into a wait."""
    write(
        tmp_path / "agg-a.cfg",
        f"hostname agg-a\n{TWO_PORTS}ip access-list ACL\n   remark {'x' * 4_000_000}\n",
    )
    started = time.perf_counter()
    pack = pack_of(tmp_path)
    elapsed = time.perf_counter() - started
    assert [device.id for device in pack.devices] == ["agg-a"]
    assert [i.name for i in pack.devices[0].interfaces] == ["Ethernet1", "Ethernet2"]
    assert elapsed < 5, f"a 4MB line took {elapsed:.1f}s"


def test_a_hundred_thousand_short_lines_are_read_in_seconds(tmp_path: Path) -> None:
    entries = "".join(
        f"   permit ip host 10.1.{n // 250}.{n % 250} any\n" for n in range(100_000)
    )
    write(
        tmp_path / "agg-a.cfg",
        f"hostname agg-a\n{TWO_PORTS}ip access-list ACL\n{entries}",
    )
    started = time.perf_counter()
    pack = pack_of(tmp_path)
    elapsed = time.perf_counter() - started
    assert [device.id for device in pack.devices] == ["agg-a"]
    assert pack.devices[0].config_line_count >= 100_000
    assert elapsed < 5, f"100k lines took {elapsed:.1f}s"


def test_a_config_a_dozen_directories_down_is_still_found(tmp_path: Path) -> None:
    deep = tmp_path.joinpath(*[f"level{n}" for n in range(12)])
    write(deep / "agg-a.cfg", f"hostname agg-a\n{TWO_PORTS}")
    found = discovery.discover(tmp_path)
    assert [config.device_id for config in found.configs] == [
        "/".join([*[f"level{n}" for n in range(12)], "agg-a"])
    ]
    assert device_ids(tmp_path) == ["agg-a"]


def test_a_tree_too_deep_to_walk_says_so_rather_than_reporting_nothing(
    tmp_path: Path,
) -> None:
    """Past the depth bound the walk stops, and everything under that point is
    lost. Losing it quietly is indistinguishable from there being nothing
    there, which is the one answer a discovery tool must never give."""
    deep = tmp_path.joinpath(*[f"l{n}" for n in range(discovery.MAX_DEPTH + 2)])
    write(deep / "agg-a.cfg", f"hostname agg-a\n{TWO_PORTS}")
    found = discovery.discover(tmp_path)
    assert found.configs == ()
    assert any(skip.reason is discovery.SkipReason.TOO_DEEP for skip in found.skipped)
    assert any("too-deep" in note for note in found.notes())


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("empty", ""),
        ("whitespace", "   \n\t\n \n"),
        ("comments", "!\n! decommissioned 2019\n!\n"),
    ],
)
def test_a_file_with_nothing_in_it_is_refused_by_name(
    tmp_path: Path, label: str, text: str
) -> None:
    """Named `.cfg`, so the operator meant it; empty of configuration, so it
    cannot be a device. It is refused, and the refusal is reported."""
    write(tmp_path / "good.cfg", f"hostname good\n{TWO_PORTS}")
    write(tmp_path / f"{label}.cfg", text)
    found = discovery.discover(tmp_path)
    assert [config.device_id for config in found.configs] == ["good"]
    refused = [skip for skip in found.skipped if skip.path.name == f"{label}.cfg"]
    assert [skip.reason for skip in refused] == [discovery.SkipReason.NOT_CONFIG]
    assert any(f"{label}.cfg" in note for note in found.notes())


# --------------------------------------------------------------------------
# 5. Filesystem hazards
# --------------------------------------------------------------------------


def symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as error:  # pragma: no cover - platform
        pytest.skip(f"symlinks unavailable here: {error}")


def test_a_symlink_loop_terminates_and_is_named(tmp_path: Path) -> None:
    site = tmp_path / "site-a"
    write(site / "agg-a.cfg", f"hostname agg-a\n{TWO_PORTS}")
    symlink_or_skip(site / "mirror", tmp_path, directory=True)
    with deadline(20):
        found = discovery.discover(tmp_path)
    assert [config.device_id for config in found.configs] == ["site-a/agg-a"]
    assert any(
        skip.reason is discovery.SkipReason.SYMLINK_LOOP for skip in found.skipped
    )
    assert device_ids(tmp_path) == ["agg-a"]


def test_a_dangling_symlink_is_named_and_the_rest_is_read(tmp_path: Path) -> None:
    write(tmp_path / "agg-a.cfg", f"hostname agg-a\n{TWO_PORTS}")
    symlink_or_skip(tmp_path / "agg-b.cfg", tmp_path / "never-existed.cfg")
    found = discovery.discover(tmp_path)
    assert [config.device_id for config in found.configs] == ["agg-a"]
    assert any(
        skip.path.name == "agg-b.cfg" and skip.reason is discovery.SkipReason.UNREADABLE
        for skip in found.skipped
    )
    assert any("agg-b.cfg" in note for note in found.notes())


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode 000 directory")
def test_a_directory_the_process_cannot_read_is_named(tmp_path: Path) -> None:
    write(tmp_path / "agg-a.cfg", f"hostname agg-a\n{TWO_PORTS}")
    closed = tmp_path / "restricted"
    write(closed / "agg-b.cfg", f"hostname agg-b\n{TWO_PORTS}")
    closed.chmod(0o000)
    try:
        found = discovery.discover(tmp_path)
    finally:
        closed.chmod(stat.S_IRWXU)
    assert [config.device_id for config in found.configs] == ["agg-a"]
    assert any(
        skip.path.name == "restricted"
        and skip.reason is discovery.SkipReason.UNREADABLE
        for skip in found.skipped
    )
    assert any("restricted" in note for note in found.notes())


def test_a_file_that_disappears_between_the_walk_and_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A backup job rotating files under the scan. The walk saw it, the read
    cannot have it; the other configs are still a result."""
    write(tmp_path / "agg-a.cfg", f"hostname agg-a\n{TWO_PORTS}")
    doomed = write(tmp_path / "agg-b.cfg", f"hostname agg-b\n{TWO_PORTS}")
    walk = discovery._walk

    def walk_then_rotate(root: Path, skipped: list[discovery.Skipped]) -> list[Path]:
        paths = walk(root, skipped)
        doomed.unlink()
        return paths

    monkeypatch.setattr(discovery, "_walk", walk_then_rotate)
    found = discovery.discover(tmp_path)
    assert [config.device_id for config in found.configs] == ["agg-a"]
    assert any(
        skip.path.name == "agg-b.cfg" and skip.reason is discovery.SkipReason.UNREADABLE
        for skip in found.skipped
    )


def test_a_named_pipe_is_not_opened(tmp_path: Path) -> None:
    """Opening a FIFO with no writer blocks forever, and a config directory on
    a build host can hold one. Only a regular file is ever a config."""
    if not hasattr(os, "mkfifo"):  # pragma: no cover - platform dependent
        pytest.skip("no mkfifo on this platform")
    write(tmp_path / "agg-a.cfg", f"hostname agg-a\n{TWO_PORTS}")
    try:
        os.mkfifo(tmp_path / "spool.cfg")
    except OSError as error:  # pragma: no cover - filesystem dependent
        pytest.skip(f"cannot create a fifo here: {error}")
    with deadline(20):
        found = discovery.discover(tmp_path)
    assert [config.device_id for config in found.configs] == ["agg-a"]
    assert any(
        skip.path.name == "spool.cfg" and skip.reason is discovery.SkipReason.UNREADABLE
        for skip in found.skipped
    )


# --------------------------------------------------------------------------
# 6. The command line and the web view
# --------------------------------------------------------------------------


def hazard_directories(root: Path) -> dict[str, Path]:
    """One directory per hazard, each also holding one good config so the tool
    has something to report on rather than bailing out at the front door."""
    good = f"hostname good\n{TWO_PORTS}"
    cases: dict[str, Path] = {}

    def case(name: str) -> Path:
        directory = root / name
        write(directory / "good.cfg", good)
        cases[name] = directory
        return directory

    write_bytes(
        case("bom") / "bom.cfg", b"\xef\xbb\xbf" + f"hostname bom\n{TWO_PORTS}".encode()
    )
    write_bytes(
        case("utf16") / "wide.cfg", f"hostname wide\n{TWO_PORTS}".encode("utf-16")
    )
    write_bytes(
        case("latin1") / "accents.cfg",
        b"hostname accents\nbanner motd\nAcc\xe8s interdit\nEOF\n" + TWO_PORTS.encode(),
    )
    write(case("crlf") / "dos.cfg", f"hostname dos\n{TWO_PORTS}".replace("\n", "\r\n"))
    write(
        case("truncated") / "cut.cfg",
        f"hostname cut\n{TWO_PORTS}interface Vlan1\n   ip addr",
    )
    write(
        case("no-name") / "anon.cfg",
        f"hostname anon\n{TWO_PORTS}interface\n   mtu 9214\n",
    )
    write(
        case("bad-vlan") / "vlans.cfg",
        f"hostname vlans\n{TWO_PORTS}vlan 10-\nvlan 4095\n",
    )
    write(case("empty") / "nothing.cfg", "")
    write(case("comments") / "quiet.cfg", "!\n!\n")
    deep = case("deep").joinpath(*[f"d{n}" for n in range(12)])
    write(deep / "buried.cfg", f"hostname buried\n{TWO_PORTS}")
    # The only directory that gets no good config: a folder of documentation
    # is a real thing to point the tool at by mistake, and the answer has to be
    # "there is nothing here", not an empty success.
    barren = root / "no-configs"
    write(barren / "notes.md", "nothing to see")
    write(barren / "README", "backups moved to the archive host\n")
    cases["no-configs"] = barren
    return cases


@pytest.fixture(scope="module")
def hazards(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    return hazard_directories(tmp_path_factory.mktemp("hazards"))


@pytest.fixture(scope="module")
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


HAZARD_NAMES: Final[tuple[str, ...]] = (
    "bom",
    "utf16",
    "latin1",
    "crlf",
    "truncated",
    "no-name",
    "bad-vlan",
    "empty",
    "comments",
    "deep",
    "no-configs",
)


@pytest.mark.parametrize("name", HAZARD_NAMES)
def test_check_gives_a_verdict_on_every_hazard(
    name: str, hazards: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 0 (clean), 1 (findings) or 2 (could not read it). A traceback is
    none of those, and it is what a pre-commit hook sees as a broken tool."""
    status = cli.main(["check", str(hazards[name])])
    assert status in {0, 1, 2}
    captured = capsys.readouterr()
    assert captured.out.strip() or captured.err.strip()


def test_check_on_a_directory_with_nothing_readable_says_so(
    hazards: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["check", str(hazards["no-configs"])]) == 2
    assert "reads like a device config" in capsys.readouterr().err


def test_check_on_a_path_that_is_not_a_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = write(tmp_path / "agg-a.cfg", f"hostname agg-a\n{TWO_PORTS}")
    assert cli.main(["check", str(config)]) == 2
    assert "not a directory" in capsys.readouterr().err
    assert cli.main(["check", str(tmp_path / "absent")]) == 2


def fetch(url: str) -> tuple[int, str]:
    try:
        with urlopen(url) as response:
            return response.status, response.read().decode()
    except URLError as error:  # pragma: no cover - only on a handler that raised
        pytest.fail(f"the web view did not answer: {error}")


@pytest.mark.parametrize("name", HAZARD_NAMES)
def test_the_web_view_answers_on_every_hazard(
    name: str, hazards: dict[str, Path], base_url: str
) -> None:
    status, body = fetch(f"{base_url}/?dir={quote(str(hazards[name]))}")
    assert status == 200
    assert "<html" in body.lower()


# The rule underneath this no longer raises, and the handler catches it if
# anything else ever does. This is the guard on the handler: one that lets an
# exception out drops the connection with no status line at all, so the browser
# shows a network error rather than a page or even a 500.
def test_the_web_view_answers_on_a_mistyped_virtual_address(
    tmp_path: Path, base_url: str
) -> None:
    write(
        tmp_path / "agg-a.cfg",
        "hostname agg-a\n"
        f"{TWO_PORTS}"
        "interface Vlan14\n"
        "   ip address 10.10.14.2/24\n"
        "   vrrp 14 ipv4 10.10.14.300\n",
    )
    status, body = fetch(f"{base_url}/?dir={quote(str(tmp_path))}")
    assert status in {200, 500}
    assert "<html" in body.lower()
