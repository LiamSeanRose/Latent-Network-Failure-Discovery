"""The inline SVG figures.

A figure that is merely decorative can be wrong without anyone noticing, so these
check the two things that would make it lie: that the timeline reflects the model
it claims to draw, and that a device drawn as detached really is detached.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from cassandra import visuals
from cassandra.factpack.builders import build_fact_pack
from cassandra.timing import sequences

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)


def corpus_pack():
    pack, _ = build_fact_pack(CORPUS)
    return pack


def test_timeline_draws_a_band_for_every_group() -> None:
    pack = corpus_pack()
    finding = next(f for f in sequences.analyse(pack) if f.rule == "fhrp-divergence")
    svg = visuals.timeline_svg(pack, finding)
    for group in pack.fhrp_groups:
        assert f"{group.protocol.value.upper()} {group.group_number}" in svg


def test_timeline_shows_both_devices_holding_groups() -> None:
    """If only one device ever appears, the figure is not showing the divergence
    the finding is about."""
    pack = corpus_pack()
    finding = next(f for f in sequences.analyse(pack) if f.rule == "fhrp-divergence")
    svg = visuals.timeline_svg(pack, finding)
    assert "agg-a" in svg
    assert "agg-b" in svg


def test_timeline_is_empty_when_the_trigger_is_not_a_flap() -> None:
    """A finding with no simulable trigger draws nothing rather than guessing."""
    pack = corpus_pack()
    facts_finding = next((f for f in sequences.analyse(pack) if not f.trigger), None)
    assert visuals.timeline_svg(pack, facts_finding) == "" if facts_finding else True

    from cassandra.findings import Finding, Severity, Tier

    made_up = Finding(
        rule="x",
        tier=Tier.TIMING,
        severity=Severity.LOW,
        device="agg-a",
        title="t",
        detail="d",
        trigger="something the sequence generator would never write",
    )
    assert visuals.timeline_svg(pack, made_up) == ""


def test_topology_marks_a_switch_with_no_addresses_as_layer_two() -> None:
    svg = visuals.topology_svg(corpus_pack())
    assert "acc1" in svg
    assert "L2 only" in svg


def test_topology_distinguishes_addressed_but_unpeered(tmp_path: Path) -> None:
    """An addressed device sharing no subnet is not layer 2. Calling it that was
    a real mislabel: it usually means its peer is not in the corpus."""
    for name, addr in (("a", "10.0.0.0/31"), ("b", "10.0.0.1/31")):
        (tmp_path / f"{name}.cfg").write_text(
            f"hostname {name}\ninterface Ethernet1\n   no switchport\n"
            f"   ip address {addr}\n"
        )
    (tmp_path / "lonely.cfg").write_text(
        "hostname lonely\ninterface Ethernet1\n   no switchport\n"
        "   ip address 192.0.2.1/30\n"
    )
    pack, _ = build_fact_pack(tmp_path)
    svg = visuals.topology_svg(pack)
    assert "no peer here" in svg
    assert "L2 only" not in svg


def test_topology_needs_at_least_one_edge() -> None:
    """With nothing shared there is no topology to draw, and an empty ring of
    unconnected circles says less than nothing."""

    class _Empty:
        devices = ()
        l3_adjacencies = ()

    assert visuals.topology_svg(_Empty()) == ""  # type: ignore[arg-type]


def test_figures_reference_nothing_external() -> None:
    pack = corpus_pack()
    finding = next(f for f in sequences.analyse(pack) if f.rule == "fhrp-divergence")
    for svg in (visuals.timeline_svg(pack, finding), visuals.topology_svg(pack)):
        assert not re.search(r"https?://|<image|xlink:href", svg)


def test_sparkbar_widths_sum_to_a_hundred_percent() -> None:
    bar = visuals.sparkbar({"high": 3, "medium": 1}, {"high": "red", "medium": "blue"})
    widths = [float(w) for w in re.findall(r"width:([\d.]+)%", bar)]
    assert round(sum(widths)) == 100


def test_sparkbar_is_empty_with_no_findings() -> None:
    assert visuals.sparkbar({"high": 0}, {"high": "red"}) == ""


def test_the_map_marks_devices_by_their_worst_finding() -> None:
    """A diagram of the network is less useful than a summary of the result.

    The mark is what makes the map answer 'where is the trouble' before anyone
    reads a finding.
    """
    pack = corpus_pack()
    svg = visuals.topology_svg(pack, marks={"agg-a": "high", "core1": "low"})
    assert 'class="mark high"' in svg
    assert 'class="mark low"' in svg
    assert svg.count('class="mark') == 2, "unmarked devices must stay unmarked"


def test_an_unmarked_map_draws_no_marks() -> None:
    pack = corpus_pack()
    assert 'class="mark' not in visuals.topology_svg(pack)


def test_marks_are_escaped_like_everything_else() -> None:
    pack = corpus_pack()
    svg = visuals.topology_svg(pack, marks={"agg-a": '"><script>'})
    assert "<script>" not in svg
