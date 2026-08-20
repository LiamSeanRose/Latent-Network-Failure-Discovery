"""The example corpus still produces the findings `docs/TUTORIAL.md` quotes.

A tutorial whose output has drifted from the tool is worse than no tutorial: it
teaches a reader to distrust what they see in their own terminal. This is what
stops that.

Findings are pinned by rule id, device and severity, never by prose. Rewording a
message is allowed and should not fail anything; a rule that stops firing, fires
on a different device, or changes what it costs is exactly what has to fail. The
edits the tutorial asks the reader to make are applied here as literal string
substitutions against the shipped configs, so a config that drifts from the
document fails at the substitution rather than silently testing something else.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Final

import pytest

from cassandra import baseline, coverage
from cassandra.cli import render_facts
from cassandra.factpack.builders import build_fact_pack
from cassandra.facts import rules
from cassandra.findings import Finding, Severity, Tier, locate
from cassandra.timing import sequences, timer_rules

CORPUS: Final = Path(__file__).resolve().parents[1] / "examples" / "two-site"

# (rule, device, severity) for every finding the tutorial's first run prints.
# Section 2 of docs/TUTORIAL.md pastes this run whole.
AS_SHIPPED: Final[frozenset[tuple[str, str, Severity]]] = frozenset(
    {
        ("bgp-session-one-sided", "edge1", Severity.HIGH),
        ("access-vlan-not-trunked", "north-acc1", Severity.HIGH),
        ("fhrp-divergence", "north-agg1", Severity.HIGH),
        ("fhrp-oscillation", "north-agg1", Severity.MEDIUM),
        ("fhrp-no-redundancy", "south-agg1", Severity.MEDIUM),
        ("l3-interface-isolated", "south-agg1", Severity.INFO),
    }
)

# The tutorial's count line: high=3 medium=3 info=1 (facts=4, timing=3). The set
# above collapses the two oscillation findings, so the total is pinned here.
EXPECTED_TOTAL: Final = 7


def evaluate(config_dir: Path) -> list[Finding]:
    """Every tier, in the order `cassandra check` runs them.

    `locate` is part of that order: the `source:` line the tutorial explains is
    attached here rather than by the rules, so a test that skipped it would be
    checking something the reader never sees.
    """
    pack, _ = build_fact_pack(config_dir)
    findings = (
        rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack)
    )
    return locate(findings, pack)


def identities(findings: list[Finding]) -> set[tuple[str, str, Severity]]:
    return {(f.rule, f.device, f.severity) for f in findings}


def rules_fired(findings: list[Finding]) -> set[str]:
    return {f.rule for f in findings}


def edit(path: Path, before: str, after: str, *, occurrences: int = 1) -> None:
    """Apply one of the tutorial's edits, or fail saying which one drifted.

    `occurrences` is checked rather than assumed. A reader following the
    tutorial edits the stanza in front of them; a blind `str.replace` reaches
    every match, and an anchor that quietly starts matching one line too many
    builds a config nobody was told to write. That happened once already —
    `interface Vlan20` also matches `passive-interface Vlan20` — and it took an
    `unparsed` line to notice, so the count is asserted here instead.
    """
    text = path.read_text()
    found = text.count(before)
    assert found == occurrences, (
        f"{path.name} contains {found} copies of the text docs/TUTORIAL.md "
        f"tells the reader to change, not {occurrences}:\n{before}"
    )
    path.write_text(text.replace(before, after))


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """A writable copy, so an edit in one test cannot leak into another."""
    destination = tmp_path / "two-site"
    shutil.copytree(CORPUS, destination)
    return destination


def fix_the_trunk(corpus: Path) -> None:
    """Section 3: put VLAN 20 back on north-acc1's two uplink trunks."""
    edit(
        corpus / "north" / "north-acc1.cfg",
        "   switchport trunk allowed vlan 10,99",
        "   switchport trunk allowed vlan 10,20,99",
        occurrences=2,
    )


def fix_the_bgp_session(corpus: Path) -> None:
    """Section 4: give south-agg1 the reciprocal neighbor."""
    edit(
        corpus / "south" / "south-agg1.cfg",
        "router bgp 65003\n   router-id 10.255.0.3\n",
        "router bgp 65003\n   router-id 10.255.0.3\n"
        "   neighbor 10.0.20.0 remote-as 65010\n"
        "   neighbor 10.0.20.0 description edge1\n",
    )


def fix_the_divergence(corpus: Path) -> None:
    """Section 6: give VRRP 10 the preempt delay VRRP 20 already has."""
    edit(
        corpus / "north" / "north-agg1.cfg",
        "   vrrp 10 preempt\n   vrrp 10 advertisement interval 1\n",
        "   vrrp 10 preempt\n   vrrp 10 preempt delay minimum 60\n"
        "   vrrp 10 advertisement interval 1\n",
    )


def add_the_new_vlan(corpus: Path) -> None:
    """Section 7: an SVI for VLAN 21 on each aggregation switch, and no trunk."""
    for device, last_octet in (("north-agg1", "2"), ("north-agg2", "3")):
        path = corpus / "north" / f"{device}.cfg"
        # Anchored to column zero: the same digits appear in the trunk lines,
        # and this edit must reach only the VLAN declaration.
        edit(path, "\nvlan 10,20,99\n", "\nvlan 10,20,21,99\n")
        # The leading `!` is load-bearing: `interface Vlan20` on its own also
        # matches the `passive-interface Vlan20` line in the OSPF stanza.
        edit(
            path,
            "!\ninterface Vlan20\n",
            "!\ninterface Vlan21\n"
            "   description second voice range\n"
            f"   ip address 10.21.0.{last_octet}/24\n"
            "!\n"
            "interface Vlan20\n",
        )


def trunk_the_new_vlan(corpus: Path) -> None:
    """Section 7 again: carry VLAN 21 on the trunks that serve the north site."""
    for device in ("north-agg1", "north-agg2", "north-acc1"):
        path = corpus / "north" / f"{device}.cfg"
        edit(
            path,
            "   switchport trunk allowed vlan 10,20,99",
            "   switchport trunk allowed vlan 10,20,21,99",
            occurrences=2,
        )
    edit(
        corpus / "north" / "north-acc1.cfg",
        "\nvlan 10,20,99\n",
        "\nvlan 10,20,21,99\n",
    )


def test_the_corpus_produces_exactly_the_findings_the_tutorial_prints() -> None:
    findings = evaluate(CORPUS)
    assert identities(findings) == AS_SHIPPED
    assert len(findings) == EXPECTED_TOTAL


def test_both_oscillation_findings_are_on_north_agg1() -> None:
    """The tutorial reads the two triggers against each other, so there are two."""
    oscillations = [f for f in evaluate(CORPUS) if f.rule == "fhrp-oscillation"]
    assert len(oscillations) == 2
    assert {f.device for f in oscillations} == {"north-agg1"}


def test_the_divergence_is_a_timing_finding_triggered_by_the_tracked_uplink() -> None:
    """Section 6 is built on the trigger naming the interface the groups track."""
    (divergence,) = [f for f in evaluate(CORPUS) if f.rule == "fhrp-divergence"]
    assert divergence.tier is Tier.TIMING
    assert divergence.trigger is not None
    assert "north-agg1:Ethernet1" in divergence.trigger


def test_every_line_of_the_corpus_is_understood() -> None:
    """Section 1 tells the reader this corpus has no `unparsed` section."""
    _, unparsed = build_fact_pack(CORPUS)
    assert not {device: rest for device, rest in unparsed.items() if rest}


def test_the_tutorials_edits_leave_a_corpus_that_still_parses(corpus: Path) -> None:
    """Every state the reader is walked through, checked for unparsed lines.

    A tutorial edit that lands in the wrong stanza can still produce the
    findings the document quotes and leave a config nobody was told to write.
    The only trace is a line the parser could not place, so that is what this
    looks for, after each edit rather than only at the end.
    """
    for step in (
        fix_the_trunk,
        fix_the_bgp_session,
        fix_the_divergence,
        add_the_new_vlan,
        trunk_the_new_vlan,
    ):
        step(corpus)
        _, unparsed = build_fact_pack(corpus)
        leftovers = {device: rest for device, rest in unparsed.items() if rest}
        assert not leftovers, f"{step.__name__} left {leftovers}"


def test_every_finding_says_which_file_it_came_from() -> None:
    """Section 3 explains the `source:` line, so every finding must have one."""
    findings = evaluate(CORPUS)
    assert all(f.source is not None for f in findings)
    by_rule = {f.rule: f.source for f in findings}
    # The document quotes this one with a line number and explains that a
    # finding about two devices at once carries a file and no line.
    assert by_rule["access-vlan-not-trunked"].file == "north/north-acc1.cfg"
    assert by_rule["access-vlan-not-trunked"].line is not None
    assert by_rule["bgp-session-one-sided"].line is None


def test_every_timing_finding_records_the_falsification_controls() -> None:
    """Section 6 reads the last evidence line as a claim about the controls.

    The count comes from `sequences.PERTURBED_RUNS` rather than being written
    out, because it moved once: the control used to count the unperturbed run
    among the perturbed ones, so a finding could ship with the observable
    entirely absent at one of the two perturbations. What this test is for is
    that every timing finding states its controls, not what the number is.
    """
    from cassandra.timing.sequences import PERTURBED_RUNS

    timing = [f for f in evaluate(CORPUS) if f.tier is Tier.TIMING]
    assert timing
    held = f"held in {PERTURBED_RUNS} of {PERTURBED_RUNS} runs at"
    for found in timing:
        assert found.evidence[-1].startswith(held)
        assert "absent with no events" in found.evidence[-1]
        assert "not counting the unperturbed one" in found.evidence[-1]


def test_every_trigger_on_this_corpus_is_a_flap() -> None:
    """Section 6 tells the reader the reload was tried and found nothing new.

    The enumerator runs reloads last and skips pairs a flap already reached, so
    a reload trigger appearing here would mean that ordering changed — and the
    section's argument, which walks one link down and up, would no longer
    describe the run it quotes.
    """
    timing = [f for f in evaluate(CORPUS) if f.tier is Tier.TIMING]
    assert timing
    assert all(f.trigger is not None and f.trigger.startswith("flap") for f in timing)


def test_the_fhrp_header_names_the_protocol_not_the_word_group() -> None:
    """Section 1 quotes `fhrp VRRP 10 virtual=…`, which address families moved."""
    pack, _ = build_fact_pack(CORPUS)
    rendered = render_facts(pack, {})
    assert "fhrp VRRP 10 virtual=10.10.0.1" in rendered
    # IPv4 groups carry no family suffix; the corpus has no IPv6 to carry one.
    assert "IPv6" not in rendered


def test_the_two_oscillations_differ_in_trigger_and_in_remedy() -> None:
    """Section 6 makes a point of the two not being one finding twice."""
    a, b = [f for f in evaluate(CORPUS) if f.rule == "fhrp-oscillation"]
    assert a.title != b.title
    assert a.trigger != b.trigger
    assert a.detail != b.detail
    assert a.remedy != b.remedy


def test_nineteen_of_fifty_one_checks_are_inert_on_this_corpus() -> None:
    """Section 8 quotes both numbers and names what the inert ones wanted."""
    pack, _ = build_fact_pack(CORPUS)
    assessed = coverage.assess(pack)
    assert len(assessed) == 51
    assert len(coverage.inert(assessed)) == 19
    # Nothing here configures BFD, so every check that reads a BFD timer is
    # inert for that reason and not because a device happened to be clean.
    inert = {c.rule: c.reason for c in coverage.inert(assessed)}
    assert inert["bfd-no-clients"] == "no BFD timers in these configs"
    assert "mtu-mismatch" in inert
    # The BGP and spanning-tree checks are inert for the same kind of reason,
    # and section 8's argument is that this corpus says nothing about them
    # rather than that it is clean of them.
    assert inert["bgp-timers-disagree"] == "no BGP timers in these configs"
    assert inert["stp-timers-outside-the-standard"] == "no STP timers in these configs"


def test_the_corpus_is_six_devices_across_a_nested_tree() -> None:
    """Discovery walks `north/`, `south/` and `edge/` rather than globbing one."""
    pack, _ = build_fact_pack(CORPUS)
    assert {device.id for device in pack.devices} == {
        "edge1",
        "north-acc1",
        "north-agg1",
        "north-agg2",
        "south-acc1",
        "south-agg1",
    }


def test_trunking_the_vlan_removes_the_access_port_finding(corpus: Path) -> None:
    fix_the_trunk(corpus)
    after = rules_fired(evaluate(corpus))
    assert "access-vlan-not-trunked" not in after
    # Nothing else moved: the fix is local to one switch.
    assert after == {rule for rule, _, _ in AS_SHIPPED} - {"access-vlan-not-trunked"}


def test_the_reciprocal_neighbor_removes_the_one_sided_session(corpus: Path) -> None:
    fix_the_bgp_session(corpus)
    after = rules_fired(evaluate(corpus))
    assert "bgp-session-one-sided" not in after
    assert after == {rule for rule, _, _ in AS_SHIPPED} - {"bgp-session-one-sided"}


def test_matching_the_preempt_delay_removes_the_divergence(corpus: Path) -> None:
    """Section 6's fix, applied after sections 3 and 4 as the tutorial applies it.

    Three claims are made about the run that follows: no HIGH survives, the
    divergence is what went, and both groups still oscillate — now on one
    shared trigger, which is the paragraph about what the fix did not do.
    """
    fix_the_trunk(corpus)
    fix_the_bgp_session(corpus)
    fix_the_divergence(corpus)
    findings = evaluate(corpus)
    assert not [f for f in findings if f.severity is Severity.HIGH]
    assert rules_fired(findings) == {
        "fhrp-oscillation",
        "fhrp-no-redundancy",
        "l3-interface-isolated",
    }
    oscillations = [f for f in findings if f.rule == "fhrp-oscillation"]
    assert len(oscillations) == 2
    assert len({f.trigger for f in oscillations}) == 1


def test_the_new_vlan_is_three_new_findings_against_a_baseline(
    corpus: Path, tmp_path: Path
) -> None:
    """Section 7: the baseline diff reports only what the change introduced.

    Three, because the SVIs added on both aggregation switches are two isolated
    interfaces *and* one subnet in two halves. The per-device finding says the
    VLAN reaches no neighbour; the split says the two halves each answer as the
    whole of 10.21.0.0/24, which is the failure the isolation causes and is
    reported once rather than once per side.
    """
    fix_the_trunk(corpus)
    fix_the_bgp_session(corpus)
    fix_the_divergence(corpus)

    pack, _ = build_fact_pack(corpus)
    recorded = tmp_path / "base.json"
    baseline.save(evaluate(corpus), pack, recorded)
    before = baseline.load(recorded)
    assert len(before.findings) == 4

    add_the_new_vlan(corpus)
    changed, _ = build_fact_pack(corpus)
    diff = baseline.compare(before, baseline.snapshot(evaluate(corpus), changed))
    assert identities(diff.new) == {
        ("svi-vlan-not-trunked", "north-agg1", Severity.MEDIUM),
        ("svi-vlan-not-trunked", "north-agg2", Severity.MEDIUM),
        ("vlan-segment-split", "north-agg2", Severity.HIGH),
    }
    assert len(diff.unchanged) == 4
    assert not diff.fixed

    trunk_the_new_vlan(corpus)
    trunked, _ = build_fact_pack(corpus)
    healed = baseline.compare(before, baseline.snapshot(evaluate(corpus), trunked))
    assert not healed.new
    assert len(healed.unchanged) == 4
    # The configs did change, which is the distinction the diff footer draws.
    assert trunked.meta.config_digest != before.digest


def test_the_fixed_direction_against_the_shipped_corpus(
    corpus: Path, tmp_path: Path
) -> None:
    """Section 7's last run: what a baseline taken before the fixes reports."""
    shipped, _ = build_fact_pack(CORPUS)
    recorded = tmp_path / "shipped.json"
    baseline.save(evaluate(CORPUS), shipped, recorded)

    fix_the_trunk(corpus)
    fix_the_bgp_session(corpus)
    fix_the_divergence(corpus)
    add_the_new_vlan(corpus)
    trunk_the_new_vlan(corpus)

    pack, _ = build_fact_pack(corpus)
    diff = baseline.compare(
        baseline.load(recorded), baseline.snapshot(evaluate(corpus), pack)
    )
    assert not diff.new
    assert {f.rule for f in diff.fixed} == {
        "access-vlan-not-trunked",
        "bgp-session-one-sided",
        "fhrp-divergence",
    }
    assert len(diff.unchanged) == 4
