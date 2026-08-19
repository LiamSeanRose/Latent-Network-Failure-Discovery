"""What the coverage report claims, held to what the rules actually do.

Two properties matter more than the rest. The report must name every rule that
exists, or the thing it was built to remove — a check that is silently missing —
comes back inside the tool that was supposed to expose it. And a rule that had no
input must say so, rather than passing quietly and being counted as reassurance.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from cassandra import coverage
from cassandra.catalogue import catalogue
from cassandra.cli import main
from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack
from cassandra.facts import rules
from cassandra.timing import sequences, timer_rules

REPO: Final = Path(__file__).resolve().parents[1]
CORPUS: Final = REPO / "scenarios" / "site14_vrrp_lockstep" / "configs"
EXAMPLE: Final = REPO / "examples" / "two-site"

# A pair that trips the checks which cannot be decided from one device: two ends
# of one wire with different masks, one BGP peering only one end knows about, one
# router-id on both, and a group whose members are tied on priority. Nothing here
# is wrong on either device read on its own, which is the point.
PAIR: Final[dict[str, str]] = {
    "pair-a": """hostname pair-a
vlan 14
interface Loopback0
   ip address 10.255.0.1/32
interface Ethernet1
   no switchport
   ip address 10.0.0.1/24
interface Vlan14
   ip address 10.14.0.2/24
   vrrp 14 ipv4 10.14.0.1
   vrrp 14 priority-level 100
   vrrp 14 preempt
router bgp 65000
   router-id 10.255.0.9
   neighbor 10.0.0.2 remote-as 65001
""",
    "pair-b": """hostname pair-b
vlan 14
interface Loopback0
   ip address 10.255.0.2/32
interface Ethernet1
   no switchport
   ip address 10.0.0.2/25
interface Vlan14
   ip address 10.14.0.3/24
   vrrp 14 ipv4 10.14.0.1
   vrrp 14 priority-level 100
   vrrp 14 preempt
router bgp 65001
   router-id 10.255.0.9
""",
}


def build(tmp_path: Path, **configs: str) -> StaticFactPack:
    directory = tmp_path / "-".join(sorted(configs))
    directory.mkdir(parents=True, exist_ok=True)
    for name, text in configs.items():
        (directory / f"{name}.cfg").write_text(text)
    pack, _ = build_fact_pack(directory)
    return pack


def fired(pack: StaticFactPack) -> set[str]:
    """Every rule that produces a finding on this pack, run without a watcher."""
    findings = (
        rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack)
    )
    return {finding.rule for finding in findings}


@pytest.fixture(scope="module")
def corpus() -> StaticFactPack:
    pack, _ = build_fact_pack(CORPUS)
    return pack


@pytest.fixture(scope="module")
def example() -> StaticFactPack:
    pack, _ = build_fact_pack(EXAMPLE)
    return pack


# --------------------------------------------------------------------------
# Nothing may go missing
# --------------------------------------------------------------------------


def test_every_catalogued_rule_is_reported_exactly_once(
    corpus: StaticFactPack, example: StaticFactPack
) -> None:
    """The report has to be complete or it is worse than no report at all.

    A rule absent from the coverage list is a rule whose silence is unexplained
    while the tool implies every silence has been explained.
    """
    known = [doc.id for doc in catalogue()]
    for pack in (corpus, example):
        reported = [entry.rule for entry in coverage.assess(pack)]
        assert reported == known


def test_no_rule_is_reported_as_unassessable(corpus: StaticFactPack) -> None:
    """The escape hatch exists so a gap is visible; nothing should be in it."""
    unassessed = [
        entry.rule
        for entry in coverage.assess(corpus)
        if entry.reason.startswith("could not be assessed")
    ]
    assert unassessed == []


# --------------------------------------------------------------------------
# The watcher must not change what it watches
# --------------------------------------------------------------------------


def test_watching_a_rule_does_not_change_what_it_finds(
    corpus: StaticFactPack, example: StaticFactPack
) -> None:
    """The whole report rests on this.

    Coverage runs the real rules against a stand-in for the fact pack. If that
    stand-in altered a comparison — an identity check, a set membership, a string
    interpolation — the report would describe a tool nobody runs.
    """
    for pack in (corpus, example):
        watched = {entry.rule for entry in coverage.assess(pack) if entry.findings}
        assert watched == fired(pack)


def test_a_rule_that_fired_is_applicable(example: StaticFactPack) -> None:
    for entry in coverage.assess(example):
        if entry.findings:
            assert entry.applicable, entry.rule


# --------------------------------------------------------------------------
# The absences the report names
# --------------------------------------------------------------------------


def test_bgp_checks_are_inert_when_no_bgp_was_parsed(corpus: StaticFactPack) -> None:
    """The corpus is VRRP only. Every BGP check ran over nothing."""
    assert not corpus.bgp
    assessed = {entry.rule: entry for entry in coverage.assess(corpus)}
    bgp = [rule for rule in assessed if rule.startswith("bgp-")]
    assert bgp, "the rule set no longer has any BGP checks"
    for rule in bgp:
        entry = assessed[rule]
        assert not entry.applicable, rule
        assert "BGP" in entry.reason, entry.reason


def test_the_same_checks_are_live_once_bgp_is_parsed(example: StaticFactPack) -> None:
    """The same rule ids, on a pack that does have BGP, are not inert.

    Without this the report could satisfy the previous test by calling every BGP
    check inert always, which would be a constant rather than a measurement.
    """
    assert example.bgp
    assessed = {entry.rule: entry for entry in coverage.assess(example)}
    live = [
        rule
        for rule in assessed
        if rule.startswith("bgp-") and assessed[rule].applicable
    ]
    assert live


def test_an_inert_rule_always_says_why(
    corpus: StaticFactPack, example: StaticFactPack
) -> None:
    for pack in (corpus, example):
        for entry in coverage.inert(coverage.assess(pack)):
            assert entry.reason.strip(), entry.rule


# --------------------------------------------------------------------------
# One device is not a network
# --------------------------------------------------------------------------


def test_every_cross_device_rule_is_inert_on_a_single_device_pack(
    tmp_path: Path,
) -> None:
    """A check that needs two devices must say so, not pass quietly.

    The set of checks that need two is not written down here — writing it down
    is how it would rot. It is measured: run the rule set on a pair configured to
    trip exactly those checks, then on each device alone. A rule that fires on
    the pair and on neither half is one whose subject is the relationship between
    them, and on a half it has nothing to look at.

    Passing quietly is the failure this guards against. Every one of those rules
    is silent on a single-device pack whatever the report says; the question is
    whether the report counts that silence as a check that ran.
    """
    pair = build(tmp_path, **PAIR)
    halves = [build(tmp_path, **{name: text}) for name, text in PAIR.items()]

    on_pair = fired(pair)
    on_halves = set().union(*(fired(half) for half in halves))
    cross_device = on_pair - on_halves
    assert len(cross_device) >= 4, f"the pair no longer trips them: {cross_device}"

    for half in halves:
        assessed = {entry.rule: entry for entry in coverage.assess(half)}
        for rule in sorted(cross_device):
            entry = assessed[rule]
            assert not entry.applicable, f"{rule} passed quietly on one device"
            assert entry.reason.strip()


def test_a_single_device_pack_says_so_in_the_reason(tmp_path: Path) -> None:
    """At least one check names the count itself, rather than a knock-on effect.

    A rule that returns early on `len(pack.devices) < 2` states its own
    precondition in code; the report should be reading it, not paraphrasing
    something further downstream.
    """
    half = build(tmp_path, **{"pair-a": PAIR["pair-a"]})
    reasons = {entry.reason for entry in coverage.inert(coverage.assess(half))}
    assert "only one device in the collection" in reasons


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def test_summary_counts_what_ran(corpus: StaticFactPack) -> None:
    assessed = coverage.assess(corpus)
    quiet = coverage.inert(assessed)
    text = coverage.summary(assessed)
    assert f"{len(assessed) - len(quiet)} of {len(assessed)} checks" in text
    assert f"{len(quiet)} were inert" in text


def test_full_render_names_every_rule(corpus: StaticFactPack) -> None:
    text = coverage.render_text(coverage.assess(corpus))
    for doc in catalogue():
        assert doc.id in text, doc.id


def test_render_survives_an_empty_assessment() -> None:
    assert coverage.render_text(()) == "no rules to report on"
    assert "no rules" in coverage.summary(())


# --------------------------------------------------------------------------
# On the command line
# --------------------------------------------------------------------------


def test_check_prints_a_coverage_summary(capsys: pytest.CaptureFixture[str]) -> None:
    main(["check", str(CORPUS), "--coverage"])
    out = capsys.readouterr().out
    assert "checks had something to look at" in out
    assert "were inert" in out


def test_check_stays_quiet_about_coverage_unless_asked(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main(["check", str(CORPUS)])
    assert "coverage:" not in capsys.readouterr().out


def test_full_coverage_lists_every_check(capsys: pytest.CaptureFixture[str]) -> None:
    main(["check", str(CORPUS), "--coverage", "full"])
    out = capsys.readouterr().out
    assert "bgp-remote-as-mismatch" in out
    assert "INERT" in out


def test_coverage_does_not_pollute_the_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A pipeline parsing findings must not be handed prose in the middle."""
    main(["check", str(CORPUS), "--json", "--coverage"])
    captured = capsys.readouterr()
    assert "coverage:" not in captured.out
    assert "coverage:" in captured.err
