"""`scenarios/hsrp_preempt_split` is what PROJECT.md §5.2's claim rests on.

The claim is that only the parser is dialect-aware, and that the FACTS and TIMING
tiers needed no changes to work on a second dialect and a second protocol. Unit
tests over config fragments cannot establish that: a fragment exercises one regex,
not a corpus. This exercises the whole path — discovery, the NX-OS parser, the
FACTS rules, the timer arithmetic, the discrete-event model — over a four-device
site of Cisco NX-OS running HSRP, and asserts the three things that make the
scenario worth having.

1. **Nothing is unread.** A corpus with unparsed lines is a corpus whose silence
   proves nothing: a rule cannot fire on a fact the parser dropped. The filler in
   these configs (a banner, an ACL, SNMP, NTP, syslog, OSPF, `feature` gates) is
   there to make that assertion mean something.
2. **The FACTS tier is silent.** Nothing is planted for it, and every rule is
   correct to say nothing — the README walks through why, rule by rule. A rule
   that later starts firing on a healthy site fails here.
3. **The TIMING tier finds the divergence.** By rule id and device, never by
   prose, so rewording a message is allowed and losing the finding is not.

The fact pack digest is pinned by literal value. An edit to any config changes it,
and a scenario whose configs drifted from the assertions above is a scenario that
silently stopped testing them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack
from cassandra.facts import rules
from cassandra.findings import Finding, Severity, Tier
from cassandra.timing import sequences, timer_rules

CONFIGS: Final = (
    Path(__file__).resolve().parents[1] / "scenarios" / "hsrp_preempt_split" / "configs"
)

DEVICES: Final = ("acc-1", "acc-2", "dist-1", "dist-2")

# The pair the defect lives on, and the two groups that answer one uplink event
# at different speeds.
PAIR: Final = ("dist-1", "dist-2")
DATA_GROUP: Final = "hsrp-120"
VOICE_GROUP: Final = "hsrp-220"

# The planted asymmetry, as numbers. Deliberately unlike site14's 110/100/40/90s
# so the two scenarios share a shape and not a table.
ACTIVE_PRIORITY: Final = 120
STANDBY_PRIORITY: Final = 100
TRACK_DECREMENT: Final = 35
PREEMPT_DELAY_MS: Final = 45_000

# SHA-256 over the config text of every discovered file, in discovery order.
# Pinned by literal value so that editing a config fails here rather than
# quietly changing what every other assertion in this file is about.
CONFIG_DIGEST: Final = (
    "cb6952423cd4f1f8a388e041f81046026100de3c973d25057801cbe1c9d5ebbb"
)


@pytest.fixture(scope="module")
def built() -> tuple[StaticFactPack, dict[str, tuple[str, ...]]]:
    """The fact pack and the lines no parser accounted for.

    Module-scoped because the timing tier runs a simulation per tracked
    interface per candidate interval, and there is no reason to pay for it once
    per test.
    """
    return build_fact_pack(CONFIGS)


@pytest.fixture(scope="module")
def pack(built: tuple[StaticFactPack, dict[str, tuple[str, ...]]]) -> StaticFactPack:
    return built[0]


@pytest.fixture(scope="module")
def timing(pack: StaticFactPack) -> list[Finding]:
    return sequences.analyse(pack)


# --------------------------------------------------------------------------
# The corpus is read whole
# --------------------------------------------------------------------------


def test_the_configs_are_pinned_by_digest(pack: StaticFactPack) -> None:
    """Every other assertion here is about a specific four files."""
    assert pack.meta.config_digest == CONFIG_DIGEST, (
        "the scenario configs have changed; re-read the README's claims about "
        "what the tiers say before updating this digest"
    )
    assert pack.meta.fact_pack_id == f"fp_{CONFIG_DIGEST[:12]}"


def test_every_device_is_present(pack: StaticFactPack) -> None:
    assert sorted(device.id for device in pack.devices) == list(DEVICES)


def test_the_dialect_was_detected_as_nxos(pack: StaticFactPack) -> None:
    """Detection is by marker, not by filename, and getting it wrong would send
    the corpus through a parser that reads `standby` instead of `hsrp`."""
    assert {device.nos_family.value for device in pack.devices} == {"nx-os"}


def test_nothing_in_the_corpus_is_unparsed(
    built: tuple[StaticFactPack, dict[str, tuple[str, ...]]],
) -> None:
    """The load-bearing one.

    A silent FACTS tier over a corpus half of which was dropped on the floor is
    not evidence of anything. Three constructs the NX-OS parser does not read are
    named in the scenario README and deliberately absent from these configs; if
    one of them is added, this fails and says so.
    """
    _pack, unparsed = built
    leftovers = {device: lines for device, lines in unparsed.items() if lines}
    assert leftovers == {}, f"lines no parser accounted for: {leftovers}"


# --------------------------------------------------------------------------
# The planted asymmetry is really in the fact pack
# --------------------------------------------------------------------------


def test_both_groups_are_hsrp_on_the_distribution_pair(pack: StaticFactPack) -> None:
    groups = {group.id: group for group in pack.fhrp_groups}
    assert sorted(groups) == [DATA_GROUP, VOICE_GROUP]
    for group in groups.values():
        assert group.protocol.value == "hsrp"
        assert tuple(sorted(m.device for m in group.members)) == PAIR


def test_both_groups_lose_the_same_points_on_the_same_uplink(
    pack: StaticFactPack,
) -> None:
    """The first half of the defect: they leave together.

    If this stopped being true the scenario would be testing a different failure
    — one where the groups never agree in the first place — and the divergence
    below would no longer be about preemption.
    """
    for group in pack.fhrp_groups:
        active = next(m for m in group.members if m.device == "dist-1")
        standby = next(m for m in group.members if m.device == "dist-2")
        assert active.priority == ACTIVE_PRIORITY
        assert standby.priority == STANDBY_PRIORITY
        assert standby.tracked_objects == ()
        assert [(t.target, t.decrement) for t in active.tracked_objects] == [
            ("Ethernet1/1", TRACK_DECREMENT)
        ]
        assert active.priority - TRACK_DECREMENT < standby.priority


def test_only_the_voice_group_waits_before_preempting(pack: StaticFactPack) -> None:
    """The second half: they do not come back together."""
    delays = {
        (timer.scope.device, timer.scope.instance): timer.preempt_delay_ms
        for timer in pack.timers.fhrp
    }
    assert delays[("dist-1", "220")] == PREEMPT_DELAY_MS
    assert delays[("dist-1", "120")] is None
    assert delays[("dist-2", "120")] is None
    assert delays[("dist-2", "220")] is None


# --------------------------------------------------------------------------
# The FACTS tier has nothing to say
# --------------------------------------------------------------------------


def test_the_facts_tier_is_silent(pack: StaticFactPack) -> None:
    """Nothing is planted for it, and the README argues rule by rule why every
    one of them is right to say nothing."""
    findings = rules.evaluate(pack)
    assert findings == [], [(f.rule, f.device, f.title) for f in findings]


def test_the_timer_arithmetic_is_silent(pack: StaticFactPack) -> None:
    """`timing/timer_rules.py` reports at `Tier.FACTS` because its findings are
    settled by arithmetic rather than by a model, so it belongs to this half of
    the assertion rather than to the divergence below."""
    findings = timer_rules.analyse(pack)
    assert findings == [], [(f.rule, f.device, f.title) for f in findings]


def test_no_finding_anywhere_claims_the_facts_tier(
    pack: StaticFactPack, timing: list[Finding]
) -> None:
    every = rules.evaluate(pack) + timer_rules.analyse(pack) + timing
    assert [f for f in every if f.tier is Tier.FACTS] == []


# --------------------------------------------------------------------------
# The TIMING tier finds what was planted
# --------------------------------------------------------------------------


def test_the_timing_tier_finds_the_divergence(timing: list[Finding]) -> None:
    """By rule id and device. The prose is free to change; this is not."""
    divergences = [f for f in timing if f.rule == "fhrp-divergence"]
    assert len(divergences) == 1, [f.title for f in divergences]

    finding = divergences[0]
    assert finding.device == "dist-1"
    assert finding.tier is Tier.TIMING
    assert finding.severity is Severity.HIGH
    assert "HSRP 120" in finding.title
    assert "HSRP 220" in finding.title


def test_the_divergence_lasts_about_as_long_as_the_preempt_delay(
    timing: list[Finding],
) -> None:
    """The window is read off the model's timeline, not restated from the config.

    They coincide here because the delay is what governs it, and the model
    samples on a one-second grid (A2 in docs/timing-model.md), so the tolerance
    is a sample at each edge.
    """
    finding = next(f for f in timing if f.rule == "fhrp-divergence")
    assert f"{PREEMPT_DELAY_MS // 1000}s" in finding.detail


def test_the_divergence_names_the_uplink_flap_that_causes_it(
    timing: list[Finding],
) -> None:
    """A finding whose trigger a person cannot reproduce is not actionable
    (§5.4), and the trigger is what separates this from a steady-state claim."""
    finding = next(f for f in timing if f.rule == "fhrp-divergence")
    assert finding.trigger is not None
    assert "dist-1:Ethernet1/1" in finding.trigger
    assert any("dist-1:Ethernet1/1 down" in line for line in finding.evidence)
    assert any("dist-1:Ethernet1/1 up" in line for line in finding.evidence)


def test_the_divergence_survived_both_controls(timing: list[Finding]) -> None:
    """§2.4: perturbation and the no-trigger control. A split that is there with
    no events was not caused by the sequence, and one that appears only at an
    exact interval is an artifact of the sampling grid."""
    finding = next(f for f in timing if f.rule == "fhrp-divergence")
    assert any(
        f"held in {sequences.PERTURBED_RUNS} of {sequences.PERTURBED_RUNS} runs" in line
        and "absent with no events" in line
        for line in finding.evidence
    )


def test_both_groups_are_reported_as_chasing_the_flap(timing: list[Finding]) -> None:
    """Consequences of the same asymmetry rather than separate defects, and
    pinned so that losing one is visible.

    Group 120 has no delay and follows the uplink exactly; group 220 chases flaps
    spaced further apart than its 45s delay.
    """
    oscillations = [f for f in timing if f.rule == "fhrp-oscillation"]
    assert {f.device for f in oscillations} == {"dist-1"}
    titles = " ".join(f.title for f in oscillations)
    assert "HSRP 120" in titles
    assert "HSRP 220" in titles


def test_the_timing_tier_reports_nothing_else(timing: list[Finding]) -> None:
    """A scenario that quietly grows a fourth finding has stopped being the
    thing its README describes."""
    assert sorted(f.rule for f in timing) == [
        "fhrp-divergence",
        "fhrp-oscillation",
        "fhrp-oscillation",
    ]
