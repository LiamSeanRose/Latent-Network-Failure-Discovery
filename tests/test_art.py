"""The generated artwork.

These are pictures with no data in them, so there is nothing to check for
correctness against. What is worth pinning down is the property that made the
module separate in the first place — the artwork never claims to be a result —
plus the invariants the rest of the page relies on: well-formed SVG, no external
reference, and a ring whose arcs add up to the circle.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Final

import pytest

from cassandra import art

_COLOURS: Final = {
    "high": "var(--s-critical)",
    "medium": "var(--s-serious)",
    "low": "var(--s-warning)",
    "info": "var(--series-1)",
}


_SHAPES: Final = art.shapes()


@pytest.mark.parametrize(
    "svg",
    [
        art.mark_svg(),
        art.hero_svg(),
        art.severity_ring({"high": 2}, _COLOURS),
        art.steady_svg(),
        *(svg for _, _, svg in _SHAPES),
    ],
    ids=["mark", "hero", "ring", "steady", *(heading for heading, _, _ in _SHAPES)],
)
def test_every_piece_is_well_formed_svg(svg: str) -> None:
    """It goes straight into a page with no sanitiser between here and there."""
    root = ET.fromstring(svg)
    assert root.tag == "svg"


@pytest.mark.parametrize(
    "svg",
    [
        art.mark_svg(),
        art.hero_svg(),
        art.severity_ring({"low": 1}, _COLOURS),
        art.steady_svg(),
        *(svg for _, _, svg in _SHAPES),
    ],
    ids=["mark", "hero", "ring", "steady", *(heading for heading, _, _ in _SHAPES)],
)
def test_nothing_is_fetched(svg: str) -> None:
    for pattern in (r"https?://", r"<image", r"xlink:href", r"@import"):
        assert not re.search(pattern, svg), f"external reference: {pattern}"


def test_the_hero_says_it_is_an_illustration() -> None:
    """The one thing that must never happen is a reader taking it for output.

    The caption lives in the page rather than the SVG, so this checks the SVG at
    least carries no device name, hostname or count that could be read as one.
    """
    svg = art.hero_svg()
    assert "vlan 14" in svg, "the lanes are labelled with the example, not a device"
    assert not re.search(r"\b(dist|acc|core|leaf|spine)\d", svg)


def test_the_hero_describes_itself_to_a_screen_reader() -> None:
    root = ET.fromstring(art.hero_svg())
    assert root.get("role") == "img"
    label = root.get("aria-label") or ""
    assert "different devices" in " ".join(label.split())


def test_the_mark_is_decorative_and_says_so() -> None:
    """It repeats the word next to it; announcing it twice helps nobody."""
    root = ET.fromstring(art.mark_svg())
    assert root.get("aria-hidden") == "true"


def test_an_empty_ring_is_not_drawn() -> None:
    assert art.severity_ring({}, _COLOURS) == ""
    assert art.severity_ring({"high": 0}, _COLOURS) == ""


def test_ring_arcs_cover_the_whole_circle() -> None:
    """Whatever the mix, the segments have to close: a gap in the donut reads as
    findings that were counted and then lost."""
    counts = {"high": 3, "medium": 1, "low": 8, "info": 2}
    svg = art.severity_ring(counts, _COLOURS)
    lengths = [float(m) for m in re.findall(r"--len:([\d.]+)", svg)]
    assert len(lengths) == len(counts)
    assert sum(lengths) == pytest.approx(round(art._RING_C, 2), abs=1e-9)


def test_ring_offsets_run_end_to_end() -> None:
    """Each arc starts where the previous one stopped."""
    svg = art.severity_ring({"high": 1, "medium": 2, "low": 3}, _COLOURS)
    lengths = [float(m) for m in re.findall(r"--len:([\d.]+)", svg)]
    offsets = [float(m) for m in re.findall(r"--off:(-?[\d.]+)", svg)]
    running = 0.0
    for length, offset in zip(lengths, offsets, strict=True):
        assert offset == pytest.approx(-running, rel=1e-6, abs=1e-6)
        running += length


def test_ring_omits_empty_severities() -> None:
    svg = art.severity_ring({"high": 2, "medium": 0, "low": 1}, _COLOURS)
    assert svg.count('<circle class="arc"') == 2
    assert "var(--s-serious)" not in svg


def test_ring_reports_the_total_and_agrees_with_itself() -> None:
    svg = art.severity_ring({"high": 2, "low": 5}, _COLOURS)
    assert ">7</text>" in svg
    assert "7 findings by severity" in svg


def test_ring_says_finding_not_findings_for_one() -> None:
    svg = art.severity_ring({"info": 1}, _COLOURS)
    assert "1 finding by severity" in svg
    assert ">finding</text>" in svg


def test_ring_labels_each_arc_for_a_pointer() -> None:
    """Colour alone does not answer 'which slice is that'."""
    svg = art.severity_ring({"high": 2, "info": 1}, _COLOURS)
    assert "<title>high: 2</title>" in svg
    assert "<title>info: 1</title>" in svg


def test_ring_escapes_its_labels() -> None:
    svg = art.severity_ring({"<b>": 1}, {})
    assert "<b>" not in svg.replace("&lt;b&gt;", "")


# --------------------------------------------------------------------------
# The three shapes
# --------------------------------------------------------------------------


def test_each_shape_describes_itself_to_a_screen_reader() -> None:
    """The caption is the picture's meaning; the label is the picture.

    They are deliberately not the same sentence. The caption says what kind of
    defect this is and the label says what is drawn, because a reader who cannot
    see the drawing still needs to know a row changed colour twice before the
    sentence about oscillation means anything.
    """
    for heading, caption, svg in _SHAPES:
        root = ET.fromstring(svg)
        assert root.get("role") == "img", heading
        label = " ".join((root.get("aria-label") or "").split())
        assert len(label) > 40, f"{heading}: {label!r} does not describe a picture"
        assert label != caption


def test_no_shape_names_a_device() -> None:
    """They are illustrations, and a hostname in one invites it to be read as a
    result — which is the single thing this module exists to prevent."""
    for heading, _, svg in _SHAPES:
        assert not re.search(r"\b(dist|acc|agg|core|leaf|spine|edge)\d", svg), heading


def test_the_shapes_use_the_same_colour_language_as_the_figures() -> None:
    """An illustration whose blue is one shade off the timeline's blue teaches a
    reader to distrust the match. Both sides resolve the same variables, which
    also means both sides follow the theme rather than only one of them."""
    joined = " ".join(svg for _, _, svg in _SHAPES) + art.hero_svg()
    assert "var(--series-1)" in joined
    assert "var(--series-2)" in joined
    # Any literal hex would be a colour that does not move with the theme.
    assert not re.search(r"#[0-9a-fA-F]{6}\b", joined)


def test_no_shape_references_a_pattern_it_does_not_define() -> None:
    """A `url(#id)` crossing between two <svg> roots is not resolved everywhere,
    and when it is not the shape simply loses its hatching — silently, which is
    the worst way for the part that names the defect to go missing."""
    for heading, _, svg in _SHAPES:
        used = set(re.findall(r"url\(#([\w-]+)\)", svg))
        defined = set(re.findall(r'<pattern id="([\w-]+)"', svg))
        assert used <= defined, f"{heading} references {used - defined} from elsewhere"


def test_the_three_shapes_are_three_different_pictures() -> None:
    """Three cards that say the same thing three times is worse than one card."""
    drawings = [svg for _, _, svg in _SHAPES]
    assert len(set(drawings)) == 3
    headings = [heading for heading, _, _ in _SHAPES]
    assert len(set(headings)) == 3


def test_the_steady_picture_is_the_hero_with_the_gap_closed() -> None:
    """A clean run gets a picture for the same reason a failing one does, and
    it has to be recognisably the same picture or it teaches nothing.

    Same two lanes, same event, same geometry: the only difference is that both
    changes happen at the same moment, which is the whole point. The hatch and
    the split outline must not appear — a reader who has learned that the hatch
    means a defect would read one here as a defect that was found.
    """
    steady = art.steady_svg()
    divergence = next(svg for heading, _, svg in _SHAPES if heading == "they separate")
    assert "hatch" not in steady
    assert "split" not in steady
    assert "hatch" in divergence
    # The event is at the same place in both, so a reader comparing them is
    # comparing the answers rather than two differently drawn pictures.
    assert 'x1="58"' in steady and 'x1="58"' in divergence
    assert "one event" in steady


def test_the_steady_picture_describes_itself_to_a_screen_reader() -> None:
    root = ET.fromstring(art.steady_svg())
    assert root.get("role") == "img"
    label = " ".join((root.get("aria-label") or "").split())
    assert "same moment" in label
