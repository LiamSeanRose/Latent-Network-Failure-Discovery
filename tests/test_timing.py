"""The TIMING tier.

The headline test is `test_rediscovers_the_site14_divergence`: Phase 3's "done
when" is that the model finds the failure from the configs alone, having never
been told the scenario exists.

Equally important is the other direction. A model that reports divergence for
every network is worthless, so several tests here assert silence on
configurations that are symmetric, untracked, or otherwise fine.
"""

from __future__ import annotations

import dataclasses
import itertools
import re
from pathlib import Path
from typing import Final

from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import NosFamily, StaticFactPack
from cassandra.findings import Severity, Tier
from cassandra.timing import sequences
from cassandra.timing.model import Event, EventKind, Placement, simulate
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

    # The pair the scenario was built around, and the sequence that reaches it.
    # Named rather than taken as "the first high one": a reload reaches other
    # pairs and would satisfy a looser assertion without proving this.
    lockstep = next(
        f for f in divergences if "VRRP 14" in f.title and "VRRP 24" in f.title
    )
    assert lockstep.severity is Severity.HIGH
    assert lockstep.tier is Tier.TIMING
    assert lockstep.trigger and "flap" in lockstep.trigger
    assert lockstep.evidence, "a timing finding must carry the sequence that made it"


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


def preempt_turned_off(pack_dir: Path, *, g14: str, g24: str) -> StaticFactPack:
    """The same pair with preemption explicitly turned off on both groups.

    `no vrrp <n> preempt` rather than the absence of `vrrp <n> preempt`. RFC 3768
    and RFC 5798 default VRRP preemption on and every platform this tool parses
    ships it that way, so a group that says nothing is a group that preempts;
    removing the line describes the opposite of what it used to be read as.
    """
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
            text.replace("   vrrp 14 preempt\n", "   no vrrp 14 preempt\n").replace(
                "   vrrp 24 preempt\n", "   no vrrp 24 preempt\n"
            )
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


def test_a_group_with_preempt_turned_off_cannot_be_taken_from_a_live_master(
    tmp_path: Path,
) -> None:
    """Disabling preempt is the standard cure for a group that chases a flapping
    uplink: a backup will not displace a master that is still advertising, however
    far the master's priority has been decremented. Nothing hands the group back
    and forth, so there is nothing to report.

    Written as `no vrrp <n> preempt`, because that is the only way a VRRP group
    can be that group. This test used to delete the `preempt` line instead, which
    made it pass for the wrong reason: preemption was on at the device and off in
    the fact pack, and the silence it asserted was the timing tier being switched
    off for the group rather than the group holding steady.
    """
    pack = preempt_turned_off(tmp_path, g14=TRACK14, g24=TRACK24)
    assert not [m for g in pack.fhrp_groups for m in g.members if m.preempt]
    assert [f for f in analyse(pack) if f.rule == "fhrp-oscillation"] == []


def test_a_group_that_states_no_preempt_line_at_all_still_preempts(
    tmp_path: Path,
) -> None:
    """The other half of the same fact, and the one that was wrong.

    A VRRP group omitting `preempt` is the common case, because the default is
    what people want. Reading it as preempt-off silenced the whole TIMING tier
    for those groups — `model._settle` gates every challenger on `member.preempt`
    — so a network that oscillates under a flapping uplink was reported as
    healthy.
    """
    for name, host, priority in (("agg-a", 2, 110), ("agg-b", 3, 100)):
        text = TEMPLATE.format(
            name=name,
            p2p=1 if name == "agg-a" else 3,
            host=host,
            priority=priority,
            g14_extra=TRACK14 if name == "agg-a" else "",
            g24_extra=TRACK24 if name == "agg-a" else "",
        )
        (tmp_path / f"{name}.cfg").write_text(
            text.replace("   vrrp 14 preempt\n", "").replace("   vrrp 24 preempt\n", "")
        )
    pack, _ = build_fact_pack(tmp_path)
    assert all(m.preempt for g in pack.fhrp_groups for m in g.members)
    assert [f for f in analyse(pack) if f.rule == "fhrp-oscillation"]


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
        notes = [line for line in finding.evidence if "no events" in line]
        assert notes, f"{finding.rule} carries no record of its controls"
        if finding.trigger and finding.trigger.startswith("reload"):
            # A reload has a duration, not a rhythm. Claiming it survived a
            # twenty percent change would claim a control that was never run.
            assert "perturbation control does not apply" in notes[0]
        else:
            assert "runs at" in notes[0]


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
    # And every flap-driven one survives both perturbations, which is what its
    # evidence claims. The count is read from the constant rather than written
    # out, because the number in the sentence is exactly what was wrong before:
    # it said three of three when one of the three was the run being tested.
    held = f"held in {sequences.PERTURBED_RUNS} of {sequences.PERTURBED_RUNS}"
    for finding in sequences.analyse(pack):
        if finding.rule == "fhrp-divergence" and finding.trigger:
            if finding.trigger.startswith("flap"):
                assert held in " ".join(finding.evidence)


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


def test_a_reload_is_enumerated_as_well_as_a_flap() -> None:
    """Every interface on a device dropping together is its own event class.

    No sequence of single-interface flaps produces it, and a group that does not
    track the uplink is untouched by a flap and moved by a reload — which is why
    the corpus's third pair only diverges under one of the two.
    """
    pack, _ = build_fact_pack(CORPUS)
    triggers = {f.trigger for f in sequences.analyse(pack) if f.trigger}
    assert any(t.startswith("reload ") for t in triggers)
    assert any(t.startswith("flap ") for t in triggers)


def test_the_reload_finds_a_pair_the_flap_cannot() -> None:
    """VRRP 34 does not track the uplink, so no flap moves it. A reload takes
    its own interface down, and then the difference in preempt delay shows."""
    pack, _ = build_fact_pack(CORPUS)
    reload_only = {
        f.title
        for f in sequences.analyse(pack)
        if f.rule == "fhrp-divergence" and f.trigger and f.trigger.startswith("reload")
    }
    assert reload_only, "the reload should reach at least one pair on its own"
    assert any("VRRP 34" in title for title in reload_only)


def test_a_reload_claims_no_control_it_did_not_run() -> None:
    pack, _ = build_fact_pack(CORPUS)
    for finding in sequences.analyse(pack):
        if finding.trigger and finding.trigger.startswith("reload"):
            joined = " ".join(finding.evidence)
            assert "perturbation control does not apply" in joined
            assert "runs at" not in joined


def test_the_reload_outlasts_the_longest_delay_it_can_find() -> None:
    """A fixed five minutes is a claim about the reader's configuration.

    Against a preempt delay longer than that, the device returns while a timer
    is still running — which is the flap enumeration's job, not this one's, and
    the sequence would silently be testing something other than what it says.
    """
    pack, _ = build_fact_pack(CORPUS)
    assert sequences._reload_down_ms(pack) == sequences.MIN_RELOAD_DOWN_MS

    stretched = dataclasses.replace(
        pack,
        timers=dataclasses.replace(
            pack.timers,
            fhrp=tuple(
                dataclasses.replace(timer, preempt_delay_ms=600_000)
                for timer in pack.timers.fhrp
            ),
        ),
    )
    assert sequences._reload_down_ms(stretched) > 600_000


def test_a_pack_with_no_delays_still_gets_a_floor() -> None:
    """The floor is what makes a reload mean 'nothing is racing' on a corpus
    that configures no delays at all."""
    pack, _ = build_fact_pack(CORPUS)
    bare = dataclasses.replace(pack, timers=dataclasses.replace(pack.timers, fhrp=()))
    assert sequences._reload_down_ms(bare) == sequences.MIN_RELOAD_DOWN_MS


def test_the_trigger_states_the_duration_it_actually_used() -> None:
    """A trigger line naming a number the run did not use is unreproducible."""
    pack, _ = build_fact_pack(CORPUS)
    seconds = sequences._reload_down_ms(pack) // 1000
    for finding in sequences.analyse(pack):
        if finding.trigger and finding.trigger.startswith("reload"):
            assert f"({seconds}s down)" in finding.trigger


def test_a_chasing_group_carries_the_line_that_would_stop_it() -> None:
    """PROJECT.md §5.4: a finding nobody can act on is noise.

    `remedy` says what to do. This says what to type, in the dialect the device
    speaks, which is the difference between advice and a change.
    """
    pack, _ = build_fact_pack(CORPUS)
    chasing = [f for f in sequences.analyse(pack) if f.rule == "fhrp-oscillation"]
    assert chasing
    for finding in chasing:
        assert finding.change, f"{finding.title} suggests no change"
        assert finding.change[0].startswith("interface ")
        assert "preempt delay minimum" in finding.change[-1]


def test_the_suggested_delay_outlasts_the_interval_that_caused_the_finding() -> None:
    """A delay shorter than the flap interval leaves the group still chasing,
    which would make the suggestion worse than useless."""
    pack, _ = build_fact_pack(CORPUS)
    for finding in sequences.analyse(pack):
        if finding.rule != "fhrp-oscillation" or not finding.change:
            continue
        interval = int(re.search(r"(\d+)s up", finding.trigger or "").group(1))
        suggested = int(re.search(r"minimum (\d+)", finding.change[-1]).group(1))
        assert suggested > interval, finding.trigger


def test_the_change_is_written_in_the_dialect_of_the_device() -> None:
    """Three dialects say this three ways, and getting one wrong is worse than
    saying nothing — a line that does not parse costs more than no line."""
    from cassandra.factpack.builders import build_fact_pack as build

    nxos, _ = build(
        Path(__file__).resolve().parents[1]
        / "scenarios"
        / "hsrp_preempt_split"
        / "configs"
    )
    changes = [f.change for f in sequences.analyse(nxos) if f.change]
    assert changes
    for change in changes:
        assert any(line.strip().startswith("hsrp ") for line in change)
        assert not any("vrrp" in line for line in change)


def test_an_unknown_dialect_suggests_nothing_rather_than_guessing() -> None:
    pack, _ = build_fact_pack(CORPUS)
    unknown = dataclasses.replace(
        pack,
        devices=tuple(
            dataclasses.replace(device, nos_family=NosFamily.UNKNOWN)
            for device in pack.devices
        ),
    )
    assert all(not f.change for f in sequences.analyse(unknown))


# ---------------------------------------------------------------------------
# What a divergence pair has to be
#
# `_groups_by_device` pairs two groups as soon as they share one device, which
# is the right question for "can one event move both" and the wrong one for the
# finding: it tells the reader the groups share a device pair and offers a
# remedy that only exists if they do.
# ---------------------------------------------------------------------------

HUB: Final = """hostname agg1
vlan 10,20
{track}interface Ethernet1
   no switchport
   ip address 10.0.0.1/31
interface Vlan10
   ip address 10.10.0.2/24
   vrrp 10 ipv4 10.10.0.1
   vrrp 10 priority-level 110
   vrrp 10 preempt
   vrrp 10 preempt delay minimum 90
{track10}interface Vlan20
   ip address 10.20.0.2/24
   vrrp 20 ipv4 10.20.0.1
   vrrp 20 priority-level 110
   vrrp 20 preempt
{track20}"""

PARTNER: Final = """hostname {name}
vlan {vlan}
interface Ethernet1
   no switchport
   ip address 10.0.0.{p2p}/31
interface Vlan{vlan}
   ip address 10.{vlan}.0.3/24
   vrrp {vlan} ipv4 10.{vlan}.0.1
   vrrp {vlan} priority-level 100
   vrrp {vlan} preempt
"""

TRACK_DEFINITION: Final = "track UPLINK interface Ethernet1 line-protocol\n"
TRACK10: Final = "   vrrp 10 tracked-object UPLINK decrement 40\n"
TRACK20: Final = "   vrrp 20 tracked-object UPLINK decrement 40\n"


def one_device_two_pairs(tmp_path: Path, *, tracked: bool) -> StaticFactPack:
    """agg1 shares VRRP 10 with agg2 and VRRP 20 with agg3, and nothing else.

    Ordinary in a real network: one aggregation switch that ended up paired with
    a different neighbour per VLAN. The two groups have a device in common and
    no device *pair* in common, and agg1 answers an event differently for each —
    group 10 waits 90s to preempt back, group 20 does not.

    `tracked` decides which enumeration reaches it. Untracked, no flap can move
    an election, so only the reload sequence runs; tracked, the flap sequence
    runs as well and reports the same pair sooner.
    """
    (tmp_path / "agg1.cfg").write_text(
        HUB.format(
            track=TRACK_DEFINITION if tracked else "",
            track10=TRACK10 if tracked else "",
            track20=TRACK20 if tracked else "",
        )
    )
    (tmp_path / "agg2.cfg").write_text(PARTNER.format(name="agg2", vlan=10, p2p=3))
    (tmp_path / "agg3.cfg").write_text(PARTNER.format(name="agg3", vlan=20, p2p=5))
    pack, _ = build_fact_pack(tmp_path)
    return pack


def test_two_groups_on_different_device_pairs_are_not_a_divergence(
    tmp_path: Path,
) -> None:
    """The finding says the groups share a device pair, so it may only be made
    about groups that do.

    Before this was filtered, both enumerations reported agg1's two groups HIGH
    — under a reload, which takes the whole device's group set down at once, and
    under a flap where both groups track the same uplink. The remedy offered,
    consistent tracking and preempt delay across the groups on the pair, has
    nowhere to be applied: there is no pair, and no timer on agg1 can stop
    VRRP 10 landing on agg2 while VRRP 20 is on agg3.
    """
    for tracked in (False, True):
        pack = one_device_two_pairs(tmp_path, tracked=tracked)
        assert {
            frozenset(member.device for member in group.members)
            for group in pack.fhrp_groups
        } == {frozenset({"agg1", "agg2"}), frozenset({"agg1", "agg3"})}
        divergences = [
            f for f in sequences.analyse(pack) if f.rule == "fhrp-divergence"
        ]
        assert divergences == [], (tracked, [f.title for f in divergences])


def test_a_group_is_paired_only_with_one_it_shares_a_pair_with() -> None:
    """Sharing a device pair is what the finding's own sentence claims.

    Pinning the choice rather than the code path. Equality of the whole member
    set was the first attempt and is wrong in one direction: a third router
    joining only the wider group, at a priority that can never win, silenced a
    split occurring strictly between the two devices both groups do share — and
    for that split the sentence and the remedy were both true.

    Sharing a pair is necessary and not sufficient, which is why it is only the
    enumeration filter. Whether the split the timeline actually shows falls on
    the shared pair is a question about where each group sat, and it is asked of
    the timeline by `_split_within` rather than guessed at here.
    """
    devices_of = {
        "pair-a": frozenset({"agg1", "agg2"}),
        "pair-b": frozenset({"agg1", "agg2"}),
        "trio": frozenset({"agg1", "agg2", "agg3"}),
        "elsewhere": frozenset({"agg1", "agg3"}),
        "alone": frozenset({"agg1"}),
    }
    paired = sequences._divergence_pairs(list(devices_of), devices_of)

    assert ("pair-a", "pair-b") in paired
    assert ("pair-a", "trio") in paired, "two shared devices is a shared pair"
    # One device in common is not a pair, whichever way round it is read.
    assert ("pair-a", "elsewhere") not in paired
    assert ("elsewhere", "alone") not in paired
    assert all(
        len(devices_of[first] & devices_of[second]) >= 2 for first, second in paired
    )


def test_a_split_outside_the_shared_pair_is_not_reported() -> None:
    """A wider group can land on a device the narrower one has no member on.

    That divergence is real and it is not a disagreement between the two
    configurations: nothing consistent the operator could write about the pair
    they share would prevent it, so the remedy would be pointing at the wrong
    thing. The filter above cannot see it — it knows which devices exist, not
    which one held the group — so the timeline is asked.
    """
    shared = frozenset({"agg1", "agg2"})
    outside = [
        Placement(at_ms=0, masters={"a": "agg1", "b": "agg1"}),
        Placement(at_ms=1000, masters={"a": "agg1", "b": "agg3"}),
    ]
    within = [
        Placement(at_ms=0, masters={"a": "agg1", "b": "agg1"}),
        Placement(at_ms=1000, masters={"a": "agg1", "b": "agg2"}),
    ]
    assert not sequences._split_within(outside, "a", "b", shared)
    assert sequences._split_within(within, "a", "b", shared)
    # A sample where the two agree says nothing about the split, even when the
    # device they agree on is outside the pair.
    agreeing = [
        Placement(at_ms=0, masters={"a": "agg3", "b": "agg3"}),
        Placement(at_ms=1000, masters={"a": "agg1", "b": "agg2"}),
    ]
    assert sequences._split_within(agreeing, "a", "b", shared)


KNIFE_EDGE_MASTER: Final = """hostname agg-a
vlan 10
track UPLINK interface Ethernet1 line-protocol
interface Ethernet1
   no switchport
   ip address 10.0.0.1/31
interface Vlan10
   ip address 10.10.0.2/24
   vrrp 10 ipv4 10.10.0.1
   vrrp 10 priority-level 110
   vrrp 10 preempt
   vrrp 10 preempt delay minimum 200
   vrrp 10 tracked-object UPLINK decrement 40
"""

KNIFE_EDGE_BACKUP: Final = """hostname agg-b
vlan 10
interface Ethernet1
   no switchport
   ip address 10.0.0.3/31
interface Vlan10
   ip address 10.10.0.3/24
   vrrp 10 ipv4 10.10.0.1
   vrrp 10 priority-level 100
   vrrp 10 preempt
"""

KNIFE_EDGE_INTERVAL_MS: Final = 230_000


def knife_edge(tmp_path: Path) -> StaticFactPack:
    """A pair whose chasing exists at one flap interval and not just below it.

    The 200s preempt delay puts `_candidate_intervals` at 230s up, where agg-a
    is eligible again 20s before the next flap and hands the group back and
    forth. Twenty percent lower, the next flap arrives first and agg-a never
    preempts at all — one handover, and no chasing whatever.
    """
    (tmp_path / "agg-a.cfg").write_text(KNIFE_EDGE_MASTER)
    (tmp_path / "agg-b.cfg").write_text(KNIFE_EDGE_BACKUP)
    pack, _ = build_fact_pack(tmp_path)
    return pack


def test_an_observable_absent_at_one_perturbation_is_not_reported(
    tmp_path: Path,
) -> None:
    """The knife-edge case §2.4's perturbation control exists to reject.

    The model does see the chasing at the nominal interval — asserted here, so
    that this cannot pass because the tier found nothing to talk about — and
    sees none of it twenty percent below. Counting the nominal run among the
    perturbed ones made that two of three, which shipped.
    """
    pack = knife_edge(tmp_path)
    nominal, low, high = sequences._intervals_around(KNIFE_EDGE_INTERVAL_MS)
    moves: dict[int, int] = {}
    for interval in (nominal, low, high):
        _, timeline = sequences._run(
            pack, "agg-a", "Ethernet1", 3, interval, ["vrrp-10"]
        )
        moves[interval] = sequences._transitions(timeline, "vrrp-10")
    assert moves[nominal] >= sequences.MIN_TRANSITIONS, moves
    assert moves[low] == 0, moves

    assert [f for f in sequences.analyse(pack) if f.rule == "fhrp-oscillation"] == []


def test_the_evidence_does_not_call_the_unperturbed_run_a_perturbation() -> None:
    """The sentence is what a reader weighs the finding by.

    It used to report three runs at ±20% when one of the three was the run at
    the interval as configured, which reads as a control with a margin it did
    not have.
    """
    assert sequences.PERTURBED_RUNS == 2
    pack, _ = build_fact_pack(CORPUS)
    notes = [
        line
        for finding in sequences.analyse(pack)
        for line in finding.evidence
        if "±" in line
    ]
    assert notes
    for note in notes:
        assert f"of {sequences.PERTURBED_RUNS} runs" in note
        assert "not counting the unperturbed one" in note


def test_an_interval_with_a_one_sided_control_is_tried_last() -> None:
    """The enumeration stops at the first interval that shows the observable,
    so the order decides which control the finding gets to carry.

    Twenty percent below the model's own sampling interval clamps back onto the
    nominal run, so that run is dropped and the control at one second has one
    side. Sorting by interval alone put that one first — and a defect that held
    at every interval tried was reported with the weakest evidence available,
    which is a true finding carrying worse evidence than it was entitled to.
    """
    from datetime import UTC, datetime

    from cassandra.factpack.schema import (
        FactPackMeta,
        FhrpProtocol,
        FhrpTimers,
        StaticFactPack,
        TimerInventory,
        TimerScope,
    )
    from cassandra.timing.sequences import _candidate_intervals, _intervals_around

    def timer(delay_ms: int) -> FhrpTimers:
        return FhrpTimers(
            protocol=FhrpProtocol.VRRP,
            scope=TimerScope(device="agg-a", interface="Vlan14", instance="14"),
            preempt_delay_ms=delay_ms,
        )

    # A three-second preempt delay puts 1000ms into the candidate list, which is
    # exactly the interval whose lower perturbation is unrepresentable.
    pack = StaticFactPack(
        meta=FactPackMeta(
            fact_pack_id="fp",
            schema_version=1,
            config_digest="d",
            source_snapshot="test",
            generated_at=datetime(2026, 8, 20, tzinfo=UTC),
            device_count=0,
        ),
        timers=TimerInventory(fhrp=(timer(3000), timer(60_000))),
    )
    order = _candidate_intervals(pack)
    assert 1000 in order, "the fixture no longer exercises the case"

    sides = [len(_intervals_around(ms)) - 1 for ms in order]
    assert sides[-1] == 1, "the one-sided interval is not last"
    assert all(count == 2 for count in sides[:-1])
    # And within each group the order is still ascending, so the shortest
    # interval that can carry a two-sided control is still preferred.
    two_sided = [ms for ms in order if len(_intervals_around(ms)) > 2]
    assert two_sided == sorted(two_sided)
