"""What the coverage report claims, held to what the rules actually do.

Two properties matter more than the rest. The report must name every rule that
exists, or the thing it was built to remove — a check that is silently missing —
comes back inside the tool that was supposed to expose it. And a rule that had no
input must say so, rather than passing quietly and being counted as reassurance.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Final

import pytest

from cassandra import coverage
from cassandra.catalogue import catalogue
from cassandra.cli import main
from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import (
    FhrpGroup,
    FhrpProtocol,
    Interface,
    InterfaceKind,
    StaticFactPack,
)
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


# Assessing a pack runs the whole rule set once per rule. Module-scoped, so the
# file reads the two shipped corpora once between them rather than once per
# assertion.
@pytest.fixture(scope="module")
def assessed_corpus(corpus: StaticFactPack) -> tuple[coverage.RuleCoverage, ...]:
    return coverage.assess(corpus)


@pytest.fixture(scope="module")
def assessed_example(example: StaticFactPack) -> tuple[coverage.RuleCoverage, ...]:
    return coverage.assess(example)


# --------------------------------------------------------------------------
# Nothing may go missing
# --------------------------------------------------------------------------


def test_every_catalogued_rule_is_reported_exactly_once(
    assessed_corpus: tuple[coverage.RuleCoverage, ...],
    assessed_example: tuple[coverage.RuleCoverage, ...],
) -> None:
    """The report has to be complete or it is worse than no report at all.

    A rule absent from the coverage list is a rule whose silence is unexplained
    while the tool implies every silence has been explained.
    """
    known = [doc.id for doc in catalogue()]
    for assessed in (assessed_corpus, assessed_example):
        assert [entry.rule for entry in assessed] == known


def test_no_rule_is_reported_as_unassessable(
    assessed_corpus: tuple[coverage.RuleCoverage, ...],
) -> None:
    """The escape hatch exists so a gap is visible; nothing should be in it."""
    unassessed = [
        entry.rule
        for entry in assessed_corpus
        if entry.reason.startswith("could not be assessed")
    ]
    assert unassessed == []


# --------------------------------------------------------------------------
# The watcher must not change what it watches
# --------------------------------------------------------------------------


def test_watching_a_rule_does_not_change_what_it_finds(
    corpus: StaticFactPack,
    example: StaticFactPack,
    assessed_corpus: tuple[coverage.RuleCoverage, ...],
    assessed_example: tuple[coverage.RuleCoverage, ...],
) -> None:
    """The whole report rests on this.

    Coverage runs the real rules against a stand-in for the fact pack. If that
    stand-in altered a comparison — an identity check, a set membership, a string
    interpolation — the report would describe a tool nobody runs.

    The stand-in reuses itself: one object per record per path, so the millionth
    read of an interface hands back the same object as the first. That is a
    correctness claim as much as a speed one, and this is where it is tested.
    """
    for pack, assessed in ((corpus, assessed_corpus), (example, assessed_example)):
        watched = {entry.rule for entry in assessed if entry.findings}
        assert watched == fired(pack)


def test_a_rule_that_fired_is_applicable(
    assessed_example: tuple[coverage.RuleCoverage, ...],
) -> None:
    for entry in assessed_example:
        if entry.findings:
            assert entry.applicable, entry.rule


# --------------------------------------------------------------------------
# The absences the report names
# --------------------------------------------------------------------------


def test_bgp_checks_are_inert_when_no_bgp_was_parsed(
    corpus: StaticFactPack, assessed_corpus: tuple[coverage.RuleCoverage, ...]
) -> None:
    """The corpus is VRRP only. Every BGP check ran over nothing."""
    assert not corpus.bgp
    assessed = {entry.rule: entry for entry in assessed_corpus}
    bgp = [rule for rule in assessed if rule.startswith("bgp-")]
    assert bgp, "the rule set no longer has any BGP checks"
    for rule in bgp:
        entry = assessed[rule]
        assert not entry.applicable, rule
        assert "BGP" in entry.reason, entry.reason


def test_the_same_checks_are_live_once_bgp_is_parsed(
    example: StaticFactPack, assessed_example: tuple[coverage.RuleCoverage, ...]
) -> None:
    """The same rule ids, on a pack that does have BGP, are not inert.

    Without this the report could satisfy the previous test by calling every BGP
    check inert always, which would be a constant rather than a measurement.
    """
    assert example.bgp
    assessed = {entry.rule: entry for entry in assessed_example}
    live = [
        rule
        for rule in assessed
        if rule.startswith("bgp-") and assessed[rule].applicable
    ]
    assert live


def test_a_rule_reports_every_fact_it_wanted_and_did_not_get(
    assessed_example: tuple[coverage.RuleCoverage, ...],
) -> None:
    """One reason is the headline; the rest say what else was missing.

    `bfd-no-faster-than-igp` compares a BFD session against the IGP dead interval
    on the same interface, and the two-site corpus has neither. Both absences
    belong in the entry: configuring BFD alone would not make this check live,
    and a reader shown only the first would believe it would.

    This is also where the line watcher is held honest. It is allowed to stop
    watching a location once it has seen it, and one that stopped too eagerly
    would drop the second absence while every other assertion in this file still
    passed.
    """
    entry = next(
        item for item in assessed_example if item.rule == "bfd-no-faster-than-igp"
    )
    assert not entry.applicable
    assert entry.reason == "no IGP hello timers in these configs"
    assert "no BFD timers in these configs" in entry.detail


@pytest.mark.parametrize("tool_ids", [6, 0], ids=["monitoring", "settrace"])
def test_each_evaluation_is_watched_from_a_clean_slate(
    corpus: StaticFactPack, monkeypatch: pytest.MonkeyPatch, tool_ids: int
) -> None:
    """Running the same rules twice under one watcher must look the same twice.

    The fast watcher switches a location off the first time it fires, which is
    what makes watching forty-five evaluations affordable. Undoing that between
    evaluations is not optional: without it the second rule over a shared helper
    is told the helper never ran, and a rule that never ran is a rule reported
    inert. The consequence would surface as a wrong verdict somewhere eventually;
    this catches it at the mechanism, where it is unambiguous.

    Both watchers are held to it, because a report must not depend on whether a
    debugger happened to have claimed the monitoring slots.
    """
    monkeypatch.setattr(coverage, "_TOOL_IDS", tool_ids)
    trace = coverage._Trace(coverage.SOURCES)
    with trace:
        with trace.watching() as first:
            rules.evaluate(corpus)
            once = set(first)
        with trace.watching() as second:
            rules.evaluate(corpus)
            twice = set(second)
    assert once
    assert once == twice


def test_one_assessment_does_not_leak_into_the_next(
    corpus: StaticFactPack,
    example: StaticFactPack,
    assessed_example: tuple[coverage.RuleCoverage, ...],
) -> None:
    """A pack must be assessed the same whatever was assessed before it.

    Two things here outlive a single assessment: the parsed rule sources, and a
    line watcher that switches locations off as it sees them. Either could carry
    one run's answer into the next — a line already seen would read as a line
    that never ran — and the result would be a report that is right the first
    time and quietly wrong afterwards.
    """
    coverage.assess(corpus)
    assert coverage.assess(example) == assessed_example


def test_an_inert_rule_always_says_why(
    assessed_corpus: tuple[coverage.RuleCoverage, ...],
    assessed_example: tuple[coverage.RuleCoverage, ...],
) -> None:
    for assessed in (assessed_corpus, assessed_example):
        for entry in coverage.inert(assessed):
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
# The shortcuts the recorder takes
# --------------------------------------------------------------------------

# The recorder stops counting a path once its answer can no longer move. Each
# test below sits on the boundary of "can no longer move", because that is where
# a shortcut turns into a wrong answer — and a wrong answer here reads as a
# check that could not run when in truth it ran and found nothing. None of it is
# visible in an end-to-end assertion: the shipped corpora have every MTU unset
# and every group the same size, so the order the records are walked in never
# matters there and would never catch this.

_MTU: Final = "devices[].interfaces[].mtu_bytes"
_MEMBERS: Final = "fhrp_groups[].members"


def _interface(name: str, mtu: int | None = None) -> Interface:
    return Interface(device="a", name=name, kind=InterfaceKind.PHYSICAL, mtu_bytes=mtu)


def test_a_field_set_on_any_record_is_not_reported_unset() -> None:
    """Unset, then set, then unset again leaves the field set.

    Whichever order a rule happens to walk the records in has to give the same
    answer, so the shortcut may only fire once a value has actually been seen.
    """
    reads = coverage._Reads()
    for mtu in (None, 9214, None):
        reads.value(_MTU, Interface, mtu)
    assert reads.never_set("mtu_bytes") == []


def test_a_field_unset_on_every_record_is_reported_unset() -> None:
    reads = coverage._Reads()
    for _ in range(3):
        reads.value(_MTU, Interface, None)
    assert reads.never_set("mtu_bytes") == [_MTU]


def test_a_collection_that_ever_held_two_is_not_solitary() -> None:
    """One group with a single member says nothing while another has two."""
    reads = coverage._Reads()
    reads.collection(_MEMBERS, FhrpGroup, 1, records=True)
    reads.collection(_MEMBERS, FhrpGroup, 3, records=True)
    assert reads.solitary("members") == []


def test_a_collection_that_never_held_two_is_solitary() -> None:
    reads = coverage._Reads()
    for _ in range(3):
        reads.collection(_MEMBERS, FhrpGroup, 1, records=True)
    assert reads.solitary("members") == [_MEMBERS]


def test_a_collection_that_ever_held_anything_is_not_empty() -> None:
    reads = coverage._Reads()
    reads.collection("bgp", StaticFactPack, 0, records=False)
    reads.collection("bgp", StaticFactPack, 2, records=True)
    assert reads.empty() == []


def test_the_stand_in_does_not_short_circuit_an_unsettled_field() -> None:
    """The same boundary, reached the way a rule reaches it.

    Two records at one path share the shortcut, so an interface with no MTU read
    before one that has an MTU is the case that decides whether the shortcut is
    a shortcut or a lie.

    The first read is deliberately made on its own recorder. What a field holds
    is remembered across assessments — it is a property of the schema — while
    what this pack set is not, and the two being confused is exactly how a
    shortcut learned on one directory would silence a field on the next.
    """
    path = "devices[].interfaces[]"
    earlier = coverage._Reads()
    assert coverage._Watched(_interface("Ethernet0", 1500), path, earlier).mtu_bytes

    reads = coverage._Reads()
    assert coverage._Watched(_interface("Ethernet1"), path, reads).mtu_bytes is None
    assert coverage._Watched(_interface("Ethernet2", 9214), path, reads).mtu_bytes == (
        9214
    )
    assert reads.never_set("mtu_bytes") == []


def test_the_stand_in_hands_back_what_the_record_holds() -> None:
    """Whatever the recorder does, a rule must read what is actually there."""
    reads = coverage._Reads()
    group = FhrpGroup(
        id="vrrp-14",
        protocol=FhrpProtocol.VRRP,
        group_number=14,
        virtual_ipv4="10.0.0.1",
    )
    watched = coverage._Watched(group, "fhrp_groups[]", reads)
    assert watched.group_number == 14
    assert watched.virtual_ipv4 == "10.0.0.1"
    assert watched.protocol is FhrpProtocol.VRRP
    assert watched == group


# --------------------------------------------------------------------------
# What it costs, and what the cost must not change
# --------------------------------------------------------------------------

# One site: an aggregation pair with two VRRP groups tracking the same uplink
# and a preempt delay on one of them. Cost has to be measured on a shape the
# rules actually work on — a pack that trips nothing is measuring the parser.
_SITE: Final = """hostname s{site}-{role}
vlan {first},{second}
track UPLINK interface Ethernet1 line-protocol
interface Ethernet1
   no switchport
   ip address 10.0.{site}.{host}/31
interface Vlan{first}
   ip address 10.1.{site}.{host}/24
   vrrp {first} ipv4 10.1.{site}.1
   vrrp {first} priority-level {priority}
   vrrp {first} preempt
   vrrp {first} advertisement interval 1
   vrrp {first} tracked-object UPLINK decrement 40
interface Vlan{second}
   ip address 10.2.{site}.{host}/24
   vrrp {second} ipv4 10.2.{site}.1
   vrrp {second} priority-level {priority}
   vrrp {second} preempt
   vrrp {second} preempt delay minimum 90
   vrrp {second} advertisement interval 1
   vrrp {second} tracked-object UPLINK decrement 40
"""


def sites(root: Path, name: str, count: int) -> StaticFactPack:
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    for site in range(count):
        for role, host, priority in (("agg-a", 2, 110), ("agg-b", 3, 100)):
            (directory / f"s{site}-{role}.cfg").write_text(
                _SITE.format(
                    site=site,
                    role=role,
                    host=host,
                    priority=priority,
                    first=100 + 2 * site,
                    second=101 + 2 * site,
                )
            )
    pack, _ = build_fact_pack(directory)
    return pack


def test_the_verdicts_do_not_depend_on_which_watcher_ran(
    corpus: StaticFactPack,
    assessed_corpus: tuple[coverage.RuleCoverage, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`sys.monitoring` and `sys.settrace` must reach the same verdicts.

    The fast path asks `sys.monitoring` to stop watching a line once it has seen
    it, because every question asked of the answer is "did this ever run" rather
    than "how often". The slow path is there for a process where all six
    monitoring tool ids are already taken — a debugger, a coverage tool — and a
    user under a debugger must not get a different report.

    Pinning that here is also what keeps the optimisation honest: the day the
    two disagree, the fast path has started answering a different question.
    """
    monkeypatch.setattr(coverage, "_TOOL_IDS", 0)
    assert coverage.assess(corpus) == assessed_corpus


@pytest.mark.slow
def test_cost_grows_with_the_collection_not_with_its_square(tmp_path: Path) -> None:
    """Four times the devices must not cost sixteen times the time.

    A coverage report nobody waits for answers nothing, and the collections
    where "which checks never had an input" matters most are the large ones. The
    bound is deliberately loose — this is a shared machine and wall clock is
    noisy — and it bounds how the cost grows, not what it is. A constant that
    doubles is a regression this cannot see; a cost that starts turning on the
    square of the collection is one it can.
    """
    small = sites(tmp_path, "small", 3)
    large = sites(tmp_path, "large", 12)

    def elapsed(pack: StaticFactPack) -> float:
        start = time.perf_counter()
        coverage.assess(pack)
        return time.perf_counter() - start

    elapsed(small)  # warm the caches this measures around, not the measurement
    small_seconds = min(elapsed(small) for _ in range(2))
    large_seconds = min(elapsed(large) for _ in range(2))

    assert large_seconds < small_seconds * 12, (
        f"4x the devices cost {large_seconds / small_seconds:.1f}x the time; "
        "linear would be 4x and watching every line was far worse"
    )


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def test_summary_counts_what_ran(
    assessed_corpus: tuple[coverage.RuleCoverage, ...],
) -> None:
    assessed = assessed_corpus
    quiet = coverage.inert(assessed)
    text = coverage.summary(assessed)
    assert f"{len(assessed) - len(quiet)} of {len(assessed)} checks" in text
    assert f"{len(quiet)} were inert" in text


def test_full_render_names_every_rule(
    assessed_corpus: tuple[coverage.RuleCoverage, ...],
) -> None:
    text = coverage.render_text(assessed_corpus)
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


# --------------------------------------------------------------------------
# Facts nothing reads
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def whole_corpus(corpus: StaticFactPack) -> coverage.Assessment:
    return coverage.assess_all(corpus)


def test_a_fact_in_the_pack_that_no_rule_reads_is_named(
    corpus: StaticFactPack, whole_corpus: coverage.Assessment
) -> None:
    """The rule side of the report answers "did this check have an input". This
    is the same question from the other end, and the two are not the same.

    A pack can hand every rule something to look at and still carry a field that
    was parsed, tested, documented, and consulted by nothing — which is a check
    nobody has written rather than a check that ran. The L2 segments are the
    standing example: `factpack/topology.py` computes them on every build and no
    rule in either tier has ever opened one.
    """
    assert corpus.l2_segments, "the fixture no longer exercises the case"
    unread = {fact.path for fact in whole_corpus.unread}
    assert "l2_segments" in unread
    assert all(fact.records > 0 for fact in whole_corpus.unread)


def test_a_fact_a_rule_does_read_is_not_named(
    whole_corpus: coverage.Assessment,
) -> None:
    """The report is only worth reading if being on it means something."""
    unread = {fact.path for fact in whole_corpus.unread}
    for consulted in (
        "devices[].interfaces[].allowed_vlans",
        "fhrp_groups[].members[].priority",
    ):
        assert consulted not in unread, f"{consulted} is read and is on the list"


def test_a_field_of_an_unopened_collection_is_not_a_second_finding(
    whole_corpus: coverage.Assessment,
) -> None:
    """Listing a collection nothing reads and then each of its fields says one
    fact six times and pushes the other findings off the end of the report."""
    unread = {fact.path for fact in whole_corpus.unread}
    assert "l2_segments" in unread
    assert not [path for path in unread if path.startswith("l2_segments[]")]


def test_nothing_absent_is_reported_as_unread(
    corpus: StaticFactPack, whole_corpus: coverage.Assessment
) -> None:
    """A field unset on every record it could sit on is not a fact this
    collection contains, and reporting it would bury the ones that are."""
    stated = any(
        interface.mtu_bytes
        for device in corpus.devices
        for interface in device.interfaces
    )
    assert not stated, "the fixture no longer exercises the case"
    unread = {fact.path for fact in whole_corpus.unread}
    assert "devices[].interfaces[].mtu_bytes" not in unread


def test_the_citation_machinery_is_not_reported_as_unread(
    whole_corpus: coverage.Assessment,
) -> None:
    """`config_line` and `config_path` exist so a finding can be pointed at a
    file, and they are read — by `findings.locate`, by the figures, by the
    views. None of them is read by a rule, so without the exclusion the report
    would carry thirty true sentences that mean nothing."""
    unread = {fact.path for fact in whole_corpus.unread}
    for bookkeeping in (
        "devices[].config_path",
        "devices[].interfaces[].config_line",
    ):
        assert bookkeeping not in unread


def test_the_unread_list_reaches_the_full_report(
    whole_corpus: coverage.Assessment,
) -> None:
    rendered = coverage.render_text(whole_corpus.rules, whole_corpus.unread)
    assert "read by no check" in rendered
    assert "l2_segments" in rendered
    # And is absent from the report that was not asked for it, because the two
    # answer different questions and only one of them was requested.
    assert "read by no check" not in coverage.render_text(whole_corpus.rules)


def test_assess_still_returns_only_the_rule_verdicts(
    corpus: StaticFactPack, whole_corpus: coverage.Assessment
) -> None:
    """Every existing caller reads a sequence of RuleCoverage, so the second
    half arrives through a new door rather than by changing that one."""
    assert coverage.assess(corpus) == whole_corpus.rules


def test_every_unread_fact_reads_as_a_sentence(
    whole_corpus: coverage.Assessment,
) -> None:
    """The labels are built from the path rather than from a table, so that a
    field added to the schema is described the day it is added. The cost of that
    is that nobody proofreads them, which this stands in for."""
    for fact in whole_corpus.unread:
        assert fact.label == fact.label.strip()
        assert "  " not in fact.label
        assert not fact.label.startswith("on ")
        assert " a L" not in fact.label, f"{fact.label}: an initialism took 'a'"
