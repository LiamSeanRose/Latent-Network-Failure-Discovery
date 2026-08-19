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

from cassandra import baseline
from cassandra.factpack.builders import build_fact_pack
from cassandra.facts import rules
from cassandra.findings import Finding, Severity, Tier
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
    """Every tier, in the order `cassandra check` runs them."""
    pack, _ = build_fact_pack(config_dir)
    return rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack)


def identities(findings: list[Finding]) -> set[tuple[str, str, Severity]]:
    return {(f.rule, f.device, f.severity) for f in findings}


def rules_fired(findings: list[Finding]) -> set[str]:
    return {f.rule for f in findings}


def edit(path: Path, before: str, after: str) -> None:
    """Apply one of the tutorial's edits, or fail saying which one drifted."""
    text = path.read_text()
    assert before in text, (
        f"{path.name} no longer contains the text docs/TUTORIAL.md tells the "
        f"reader to change:\n{before}"
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
        edit(
            path,
            "interface Vlan20\n",
            "interface Vlan21\n"
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


def test_the_new_vlan_is_two_new_findings_against_a_baseline(
    corpus: Path, tmp_path: Path
) -> None:
    """Section 7: the baseline diff reports only what the change introduced."""
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
