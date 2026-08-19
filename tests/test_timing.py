"""The TIMING tier.

The headline test is `test_rediscovers_the_site14_divergence`: Phase 3's "done
when" is that the model finds the failure from the configs alone, having never
been told the scenario exists.

Equally important is the other direction. A model that reports divergence for
every network is worthless, so several tests here assert silence on
configurations that are symmetric, untracked, or otherwise fine.
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Final

from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack
from cassandra.findings import Severity, Tier
from cassandra.timing import sequences
from cassandra.timing.model import Event, EventKind, simulate
from cassandra.timing.sequences import analyse

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)

TEMPLATE: Final = """hostname {name}
vlan 14,24
interface Ethernet1
   no switchport
   ip address 10.0.0.{p2p}/31
interface Ethernet2
   switchport mode trunk
   switchport trunk allowed vlan 14,24
interface Vlan14
   ip address 10.14.0.{host}/24
   vrrp 14 ipv4 10.14.0.1
   vrrp 14 priority-level {priority}
   vrrp 14 preempt
{g14_extra}interface Vlan24
   ip address 10.24.0.{host}/24
   vrrp 24 ipv4 10.24.0.1
   vrrp 24 priority-level {priority}
   vrrp 24 preempt
{g24_extra}track UPLINK interface Ethernet1 line-protocol
"""

TRACK14: Final = "   vrrp 14 tracked-object UPLINK decrement 40\n"
TRACK24: Final = "   vrrp 24 tracked-object UPLINK decrement 40\n"
DELAY24: Final = "   vrrp 24 preempt delay minimum 90\n"


def build(tmp_path: Path, *, g14: str = "", g24: str = "") -> StaticFactPack:
    (tmp_path / "agg-a.cfg").write_text(
        TEMPLATE.format(
            name="agg-a", p2p=1, host=2, priority=110, g14_extra=g14, g24_extra=g24
        )
    )
    (tmp_path / "agg-b.cfg").write_text(
        TEMPLATE.format(
            name="agg-b", p2p=3, host=3, priority=100, g14_extra="", g24_extra=""
        )
    )
    pack, _ = build_fact_pack(tmp_path)
    return pack


def test_rediscovers_the_site14_divergence() -> None:
    """Phase 3 acceptance: found from the configs, not from the scenario docs."""
    pack, _ = build_fact_pack(CORPUS)
    findings = analyse(pack)
    divergences = [f for f in findings if f.rule == "fhrp-divergence"]
    assert divergences, "the timing tier found nothing in the corpus"

    pairs = {f.title for f in divergences}
    assert any("VRRP 14" in title and "VRRP 24" in title for title in pairs), pairs

    worst = max(divergences, key=lambda f: f.severity == Severity.HIGH)
    assert worst.tier is Tier.TIMING
    assert worst.trigger and "flap" in worst.trigger
    assert worst.evidence, "a timing finding must carry the sequence that produced it"


def test_symmetric_groups_produce_no_divergence(tmp_path: Path) -> None:
    """Both groups track the same interface with the same delay, so they move
    together. A model that flags this is crying wolf."""
    pack = build(tmp_path, g14=TRACK14, g24=TRACK24)
    assert [f for f in analyse(pack) if f.rule == "fhrp-divergence"] == []


def test_asymmetric_preempt_delay_is_what_causes_divergence(tmp_path: Path) -> None:
    """Same tracking on both groups; only the preempt delay differs. Isolating the
    single variable proves the model responds to it and not to something else."""
    pack = build(tmp_path, g14=TRACK14, g24=TRACK24 + DELAY24)
    divergences = [f for f in analyse(pack) if f.rule == "fhrp-divergence"]
    assert divergences
    assert "different devices" in divergences[0].title


def test_tracking_asymmetry_alone_diverges_only_while_the_link_is_down(
    tmp_path: Path,
) -> None:
    """Not a finding, and the distinction matters.

    With group 14 tracking and group 24 not, the two split the moment the uplink
    drops — but group 14 has no preempt delay, so it reclaims the instant the link
    returns and the split ends with the outage. A brief divergence *during* an
    event is expected behaviour; a divergence that persists long after recovery is
    the defect. The threshold is what separates them, and reporting the first kind
    would bury the second in noise.
    """
    pack = build(tmp_path, g14=TRACK14, g24="")
    assert [f for f in analyse(pack) if f.rule == "fhrp-divergence"] == []

    # The split is real, just short — confirm the model sees it at all.
    events = [
        Event(at_ms=0, kind=EventKind.LINK_DOWN, device="agg-a", interface="Ethernet1")
    ]
    timeline = simulate(pack, events, until_ms=10_000)
    assert timeline[-1].masters["vrrp-14"] == "agg-b"
    assert timeline[-1].masters["vrrp-24"] == "agg-a"


def test_no_tracking_anywhere_means_nothing_to_simulate(tmp_path: Path) -> None:
    """With nothing tracked, no link event can change an election, so the tier has
    no candidate sequences and must stay silent rather than invent one."""
    assert analyse(build(tmp_path)) == []


def test_election_prefers_higher_priority() -> None:
    pack, _ = build_fact_pack(CORPUS)
    timeline = simulate(pack, [], until_ms=10_000)
    assert timeline[0].masters["vrrp-14"] == "agg-a"
    assert timeline[-1].masters["vrrp-34"] == "agg-a"


def test_tracked_interface_down_moves_the_group() -> None:
    pack, _ = build_fact_pack(CORPUS)
    events = [
        Event(at_ms=0, kind=EventKind.LINK_DOWN, device="agg-a", interface="Ethernet1")
    ]
    timeline = simulate(pack, events, until_ms=20_000)
    assert timeline[-1].masters["vrrp-14"] == "agg-b"
    # Group 34 does not track the uplink, so it must not move.
    assert timeline[-1].masters["vrrp-34"] == "agg-a"


def test_preempt_delay_holds_the_group_on_the_backup() -> None:
    """The mechanism the whole scenario turns on, tested directly."""
    pack, _ = build_fact_pack(CORPUS)
    events = [
        Event(at_ms=0, kind=EventKind.LINK_DOWN, device="agg-a", interface="Ethernet1"),
        Event(
            at_ms=10_000, kind=EventKind.LINK_UP, device="agg-a", interface="Ethernet1"
        ),
    ]
    timeline = simulate(pack, events, until_ms=150_000)
    at = {sample.at_ms: sample.masters for sample in timeline}

    # Group 14 has no preempt delay and reclaims as soon as the link returns.
    assert at[20_000]["vrrp-14"] == "agg-a"
    # Group 24 waits 90s, so it is still on the backup while 14 is home.
    assert at[20_000]["vrrp-24"] == "agg-b"
    assert at[140_000]["vrrp-24"] == "agg-a"


def test_every_timing_finding_says_how_it_was_derived() -> None:
    """This tier can be wrong, so a finding that cannot be argued with is unsafe."""
    pack, _ = build_fact_pack(CORPUS)
    for finding in analyse(pack):
        assert finding.tier is Tier.TIMING
        assert finding.trigger
        assert finding.evidence
        assert finding.remedy


# ---------------------------------------------------------------------------
# Deliberate silence
#
# Oscillation is the model's own claim that a group chases a flapping link, so
# the near misses are the pairs where the flap sequence is enumerated in full
# and the election still does not move.
# ---------------------------------------------------------------------------

WEAK14: Final = "   vrrp 14 tracked-object UPLINK decrement 5\n"
WEAK24: Final = "   vrrp 24 tracked-object UPLINK decrement 5\n"


def without_preempt(pack_dir: Path, *, g14: str, g24: str) -> StaticFactPack:
    """The same pair with preempt removed from both groups on both devices."""
    for name, host, priority in (("agg-a", 2, 110), ("agg-b", 3, 100)):
        text = TEMPLATE.format(
            name=name,
            p2p=1 if name == "agg-a" else 3,
            host=host,
            priority=priority,
            g14_extra=g14 if name == "agg-a" else "",
            g24_extra=g24 if name == "agg-a" else "",
        )
        (pack_dir / f"{name}.cfg").write_text(
            text.replace("   vrrp 14 preempt\n", "").replace("   vrrp 24 preempt\n", "")
        )
    pack, _ = build_fact_pack(pack_dir)
    return pack


def test_tracking_too_weak_to_lose_the_election_cannot_chase(tmp_path: Path) -> None:
    """A decrement that leaves the master above its peer never moves the group, so
    the interface it watches can flap as often as it likes without a single
    handover. The tracking is ineffective, which the FACTS tier reports; it is not
    a group chasing a link."""
    pack = build(tmp_path, g14=WEAK14, g24=WEAK24)
    assert [f for f in analyse(pack) if f.rule == "fhrp-oscillation"] == []


def test_a_group_without_preempt_cannot_be_taken_from_a_live_master(
    tmp_path: Path,
) -> None:
    """Disabling preempt is the standard cure for a group that chases a flapping
    uplink: a backup will not displace a master that is still advertising, however
    far the master's priority has been decremented. Nothing hands the group back
    and forth, so there is nothing to report."""
    pack = without_preempt(tmp_path, g14=TRACK14, g24=TRACK24)
    assert [f for f in analyse(pack) if f.rule == "fhrp-oscillation"] == []


def test_a_split_present_with_no_events_is_not_reported_as_caused_by_one() -> None:
    """PROJECT.md §2.4's no-trigger control, with its criterion inverted.

    A pair that sits split with nothing happening is a configuration that is
    wrong at rest. That is the FACTS tier's finding, and attributing it to a
    flap would send the reader to look at a link that had nothing to do with it.
    """
    pack, _ = build_fact_pack(CORPUS)
    control = sequences._control_timeline(pack, [g.id for g in pack.fhrp_groups])
    for first, second in itertools.combinations(
        [group.id for group in pack.fhrp_groups], 2
    ):
        span = sequences._longest_divergence_ms(control, first, second)
        assert span < sequences.MIN_DIVERGENCE_MS, (
            f"{first} and {second} are split with no events at all"
        )


def test_the_perturbation_control_is_not_three_copies_of_one_run() -> None:
    """Twenty percent of a short interval could round back onto the nominal one,
    which would turn the control into the same run agreeing with itself."""
    for nominal in (5_000, 20_000, 120_000):
        assert len(set(sequences._intervals_around(nominal))) == 3, nominal


def test_the_controls_are_recorded_in_the_evidence() -> None:
    """A reader weighing a model-derived finding needs to know what survived
    what, not just that something did."""
    pack, _ = build_fact_pack(CORPUS)
    findings = sequences.analyse(pack)
    assert findings
    for finding in findings:
        notes = [line for line in finding.evidence if "runs at" in line]
        assert notes, f"{finding.rule} carries no record of its controls"
        assert "absent with no events" in notes[0]


def test_a_knife_edge_result_does_not_survive_perturbation() -> None:
    """A divergence that exists at exactly one interval and nowhere near it is a
    property of the sampling grid, not of the configuration."""
    pack, _ = build_fact_pack(CORPUS)
    reported = {
        (f.rule, f.title)
        for f in sequences.analyse(pack)
        if f.rule == "fhrp-divergence"
    }
    assert reported, "the corpus divergence must survive its own controls"
    # And it survives all three runs, which is what the evidence claims.
    for finding in sequences.analyse(pack):
        if finding.rule == "fhrp-divergence":
            assert "held in 3 of 3" in " ".join(finding.evidence)


def test_two_groups_chasing_say_why_their_triggers_differ() -> None:
    """Two oscillation findings on one device differ only by a number in the
    trigger, which reads as the same finding printed twice.

    The reason they differ is each group's own preempt delay, so each finding
    names it.
    """
    pack, _ = build_fact_pack(CORPUS)
    chasing = [f for f in sequences.analyse(pack) if f.rule == "fhrp-oscillation"]
    assert len(chasing) >= 2, "the corpus should produce more than one"
    assert any("no preempt delay" in f.detail for f in chasing)
    assert any("waits 90s before preempting" in f.detail for f in chasing)


def test_the_fix_does_not_tell_you_to_add_what_you_have() -> None:
    """Telling someone to add a preempt delay they already configured is the
    fastest way to lose them."""
    pack, _ = build_fact_pack(CORPUS)
    for finding in sequences.analyse(pack):
        if finding.rule != "fhrp-oscillation":
            continue
        if "waits" in finding.detail:
            assert "raise the preempt delay" in (finding.remedy or "")
        else:
            assert "add a preempt delay" in (finding.remedy or "")
