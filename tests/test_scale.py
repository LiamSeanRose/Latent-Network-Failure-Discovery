"""What analysing a large directory costs, and what it must not change.

Someone pointing this at a real config archive is pointing it at hundreds of
devices, not at the four in the shipped corpus. Two properties matter there and
neither is visible on a small pack:

* a site's findings must not depend on what else happens to be filed beside it
* the cost must grow with the collection, not with its square

Both were false. The sequence enumeration compared every FHRP group against
every other one and rebuilt two whole-pack lookups inside every simulation, so a
hundred-device directory took nearly two minutes and a site cost more to analyse
the more unrelated sites shared its directory.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack
from cassandra.facts import rules
from cassandra.findings import Finding
from cassandra.timing import sequences

# One site: a pair of aggregation switches, two VRRP groups tracking the same
# uplink, and a preempt delay on one of them. The lockstep defect, in miniature.
_DEVICE: Final = """hostname s{site}-{role}
vlan {v1},{v2}
track UPLINK interface Ethernet1 line-protocol
interface Ethernet1
   no switchport
   ip address 10.{block}.{index}.{host}/31
interface Vlan{v1}
   ip address 10.{block}.{o1}.{host}/24
   vrrp {v1} ipv4 10.{block}.{o1}.1
   vrrp {v1} priority-level {priority}
   vrrp {v1} preempt
   vrrp {v1} advertisement interval 1
   vrrp {v1} tracked-object UPLINK decrement 40
interface Vlan{v2}
   ip address 10.{block}.{o2}.{host}/24
   vrrp {v2} ipv4 10.{block}.{o2}.1
   vrrp {v2} priority-level {priority}
   vrrp {v2} preempt
   vrrp {v2} preempt delay minimum 90
   vrrp {v2} advertisement interval 1
   vrrp {v2} tracked-object UPLINK decrement 40
"""


def _site(directory: Path, site: int) -> None:
    v1, v2 = 10 * site + 4, 10 * site + 5
    for role, host, priority in (("agg-a", 2, 110), ("agg-b", 3, 100)):
        (directory / f"s{site}-{role}.cfg").write_text(
            _DEVICE.format(
                site=site,
                role=role,
                host=host,
                priority=priority,
                v1=v1,
                v2=v2,
                block=site // 250,
                index=site % 250,
                o1=v1 % 250,
                o2=v2 % 250,
            )
        )


def _collection(root: Path, name: str, sites: range) -> Path:
    directory = root / name
    directory.mkdir()
    for site in sites:
        _site(directory, site)
    return directory


def _timing(directory: Path) -> list[Finding]:
    pack, _ = build_fact_pack(directory)
    return sequences.analyse(pack)


def _describe(findings: list[Finding], site: int) -> set[tuple[str, str, str]]:
    """A site's findings, as tuples that can be compared across packs."""
    prefix = f"s{site}-"
    return {
        (f.rule, f.device, f.title) for f in findings if f.device.startswith(prefix)
    }


def test_a_site_is_analysed_the_same_alone_as_in_a_crowd(tmp_path: Path) -> None:
    """Filing a site next to twenty unrelated ones must not change its verdict.

    The groups in one site cannot see events in another; comparing them was
    wasted work, and any finding that came out of such a comparison would have
    been meaningless.
    """
    alone = _timing(_collection(tmp_path, "alone", range(7, 8)))
    crowd = _timing(_collection(tmp_path, "crowd", range(0, 20)))
    assert _describe(alone, 7)
    assert _describe(crowd, 7) == _describe(alone, 7)


def test_facts_are_the_same_alone_as_in_a_crowd(tmp_path: Path) -> None:
    """Same property for the deterministic tier, which has cross-device rules
    and so is the one where an interaction would be legitimate."""
    pack_alone, _ = build_fact_pack(_collection(tmp_path, "a", range(7, 8)))
    pack_crowd, _ = build_fact_pack(_collection(tmp_path, "c", range(0, 20)))
    assert _describe(rules.evaluate(pack_crowd), 7) == _describe(
        rules.evaluate(pack_alone), 7
    )


@pytest.mark.slow
def test_cost_grows_with_the_collection_not_with_its_square(tmp_path: Path) -> None:
    """Four times the devices must not cost sixteen times the time.

    Deliberately loose — this is a shared machine and wall clock is noisy — but
    the behaviour it rules out was an order of magnitude worse than the bound,
    not a few percent over it.
    """
    small = _collection(tmp_path, "small", range(6))
    large = _collection(tmp_path, "large", range(24))

    def elapsed(directory: Path) -> float:
        start = time.perf_counter()
        _timing(directory)
        return time.perf_counter() - start

    elapsed(small)  # warm the interpreter, not the measurement
    small_seconds = min(elapsed(small) for _ in range(3))
    large_seconds = min(elapsed(large) for _ in range(3))

    assert large_seconds < small_seconds * 12, (
        f"4x the devices cost {large_seconds / small_seconds:.1f}x the time; "
        "linear would be 4x and the quadratic version was far worse"
    )
