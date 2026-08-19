"""Generated artwork for the web view.

`visuals.py` draws figures from facts. This module draws pictures that carry no
data at all, and it is separated for exactly that reason: nothing here should
ever be mistaken for a result. The hero is an illustration of what the tool
looks for, not a rendering of what it found, and the mark is a mark.

Everything is inline SVG built here at request time. There are no image files to
ship, no fetch to fail offline, and no binary in the repository whose contents
nobody can review in a diff.
"""

from __future__ import annotations

import html
import itertools
from typing import Final

# Same categorical slots the figures use, so the illustration and the real
# timeline below it do not teach two different colour languages. Named as CSS
# variables rather than as the hex values `visuals.py` writes inline, because
# these are the only two slots the artwork needs and the variables already carry
# the light and dark value of each — an illustration whose blue stayed the light
# blue in dark mode would be teaching a colour language one shade off the real
# one, which is the whole thing this comment exists to prevent.
_A: Final = "var(--series-1)"
_B: Final = "var(--series-2)"
_SPLIT: Final = "var(--s-critical)"


def mark_svg() -> str:
    """The wordmark glyph: two traces in lockstep until one of them is not.

    A logo that says the thing. The lower trace steps down where the upper one
    holds, and the gap between them is filled — the gap is the product.
    """
    return (
        '<svg class="mark" viewBox="0 0 34 34" width="34" height="34" '
        'aria-hidden="true" focusable="false">'
        '<rect x="1" y="1" width="32" height="32" rx="9" class="mark-plate"/>'
        '<path class="trace a" d="M7 13h9v-4h11"/>'
        '<path class="trace b" d="M7 21h9v4h11"/>'
        '<path class="mark-gap" d="M18 10h6v14h-6z"/>'
        "</svg>"
    )


def _lane(y: int, label: str, colour: str, switch_at: int, *, delay: str) -> str:
    """One gateway lane: held by the left device, then by the right one."""
    return (
        f'<g class="lane" style="--d:{delay}">'
        f'<text class="lane-label" x="0" y="{y + 15}">{html.escape(label)}</text>'
        f'<rect class="held" x="74" y="{y}" width="{switch_at - 74}" height="22" '
        f'rx="5" style="fill:{_A}"/>'
        f'<rect class="held late" x="{switch_at}" y="{y}" width="{404 - switch_at}" '
        f'height="22" rx="5" style="fill:{colour}"/>'
        "</g>"
    )


def hero_svg() -> str:
    """The premise in one picture: a link flaps, and two gateways disagree.

    Deliberately not a real result — the caption says so. It exists because
    "latent, timing-dependent failure mode" is four words that mean nothing until
    someone has seen the shape of one, and the shape is a gap between two bands.
    """
    return f"""<svg class="hero" viewBox="0 0 420 150" role="img"
 aria-label="Two gateway groups follow the same link failure at different speeds,
 leaving a window where they sit on different devices.">
  <defs>
    <pattern id="hatch" width="6" height="6" patternTransform="rotate(45)"
             patternUnits="userSpaceOnUse">
      <line x1="0" y1="0" x2="0" y2="6" style="stroke:{_SPLIT}" stroke-width="2.2"
            opacity=".38"/>
    </pattern>
  </defs>
  <line class="axis" x1="74" y1="128" x2="404" y2="128"/>
  <g class="event">
    <line x1="150" y1="20" x2="150" y2="128"/>
    <text class="tick" x="150" y="142" text-anchor="middle">link fails</text>
  </g>
  {_lane(28, "vlan 14", _B, 176, delay=".15s")}
  {_lane(62, "vlan 24", _B, 300, delay=".3s")}
  <g class="split">
    <rect x="176" y="24" width="124" height="68" rx="6" fill="url(#hatch)"/>
    <rect x="176" y="24" width="124" height="68" rx="6" class="split-edge"/>
    <text class="split-label" x="238" y="108" text-anchor="middle">split</text>
  </g>
</svg>"""


_RING_R: Final = 46
_RING_C: Final = 2 * 3.141592653589793 * _RING_R


def severity_ring(counts: dict[str, int], colours: dict[str, str]) -> str:
    """A donut of the severity mix, with the total in the hole.

    Returns "" for an empty count, because a ring of nothing is a ring that says
    a number is zero in the least legible way available.
    """
    total = sum(counts.values())
    if not total:
        return ""
    present = [(name, count) for name, count in counts.items() if count]

    # Lengths are rounded here and the offsets are derived from the rounded
    # values, with the last arc taking whatever is left. Deriving the offsets
    # from exact lengths instead leaves a hairline gap where the segments meet,
    # and a donut that does not close reads as findings that went missing.
    circumference = round(_RING_C, 2)
    lengths = [round(circumference * count / total, 2) for _, count in present]
    lengths[-1] = round(circumference - sum(lengths[:-1]), 2)

    arcs: list[str] = []
    offset = 0.0
    for index, ((name, count), length) in enumerate(zip(present, lengths, strict=True)):
        colour = colours.get(name, "var(--ink-3)")
        arcs.append(
            f'<circle class="arc" style="--i:{index};'
            f"--len:{length:.2f};--gap:{circumference - length:.2f};"
            f'--off:{-offset:.2f}" cx="60" cy="60" r="{_RING_R}" '
            f'stroke="{colour}"><title>{html.escape(name)}: {count}</title></circle>'
        )
        offset += length
    plural = "" if total == 1 else "s"
    return (
        f'<svg class="ring" viewBox="0 0 120 120" width="120" height="120" '
        f'role="img" aria-label="{total} finding{plural} by severity">'
        f'<circle class="track" cx="60" cy="60" r="{_RING_R}"/>'
        + "".join(arcs)
        + f'<text class="ring-total" x="60" y="58">{total}</text>'
        f'<text class="ring-unit" x="60" y="76">finding{plural}</text>'
        "</svg>"
    )


# --------------------------------------------------------------------------
# The three shapes
#
# One picture per family of finding, on the landing page, for someone who has
# not run anything yet. They are illustrations and the captions say so — the
# point is that "latent, timing-dependent failure mode" is a phrase, and each of
# these is a shape, and a reader who has seen the shape recognises the finding
# when the tool reports it.
#
# All three are the same size and use the same two categorical slots, so the
# differences between them are the differences that matter rather than an
# artefact of three drawings made separately.
# --------------------------------------------------------------------------

_VIGNETTE: Final = "0 0 200 78"


def _tick(x: int, label: str, *, anchor: str = "middle") -> str:
    """The moment the picture is about, and the words for it.

    `anchor` exists because a centred label under a tick at the left edge is
    half outside the viewBox and half of it is simply not drawn — which reads as
    a typo rather than as clipping.
    """
    return (
        f'<g class="tick"><line x1="{x}" y1="4" x2="{x}" y2="62"/>'
        f'<text x="{x}" y="74" text-anchor="{anchor}">{html.escape(label)}</text>'
        "</g>"
    )


def _held(x: int, y: int, width: int, colour: str, *, delay: str) -> str:
    return (
        f'<rect class="held" x="{x}" y="{y}" width="{width}" height="15" rx="4" '
        f'style="fill:{colour};--d:{delay}"/>'
    )


def _divergence_svg() -> str:
    """Two groups answer one event at different speeds, and separate."""
    return (
        f'<svg class="vignette" viewBox="{_VIGNETTE}" role="img" aria-label="Two '
        f"rows follow one event. The upper row changes colour at the event and "
        f"the lower row changes later, so between the two changes the rows are "
        f'different colours.">'
        + _tick(58, "one event")
        + _held(6, 10, 52, _A, delay=".05s")
        + _held(58, 10, 136, _B, delay=".45s")
        + _held(6, 36, 130, _A, delay=".05s")
        + _held(136, 36, 58, _B, delay=".9s")
        # Its own pattern rather than the hero's. A `url(#id)` reference
        # crossing from one <svg> root into another is not something every
        # browser resolves, and the failure is silent — the hatch simply is not
        # painted, and the one part of the picture that names the defect
        # disappears.
        + f'<defs><pattern id="hatch-v" width="6" height="6" '
        f'patternTransform="rotate(45)" patternUnits="userSpaceOnUse">'
        f'<line x1="0" y1="0" x2="0" y2="6" style="stroke:{_SPLIT}" '
        f'stroke-width="2.2" opacity=".38"/></pattern></defs>'
        + '<g class="split"><rect x="58" y="6" width="78" height="49" rx="5" '
        'fill="url(#hatch-v)"/><rect x="58" y="6" width="78" height="49" rx="5" '
        'class="split-edge"/></g>'
        "</svg>"
    )


def _oscillation_svg() -> str:
    """One group answering the same event over and over."""
    edges = (6, 40, 68, 100, 128, 160, 194)
    bands = "".join(
        _held(
            start,
            23,
            end - start - 2,
            _A if index % 2 == 0 else _B,
            delay=f"{0.05 + index * 0.14:.2f}s",
        )
        for index, (start, end) in enumerate(itertools.pairwise(edges))
    )
    return (
        f'<svg class="vignette" viewBox="{_VIGNETTE}" role="img" aria-label="One '
        f"row alternates between two colours six times after a single event, "
        f'each stretch shorter than a gateway takes to be useful.">'
        + _tick(6, "one event", anchor="start")
        + bands
        + '<text class="count" x="100" y="16" text-anchor="middle">'
        "6 changes</text></svg>"
    )


def _margin_svg() -> str:
    """A detection budget with no room in it for an ordinary lost packet."""
    dots = "".join(
        f'<circle class="hello{" lost" if index == 3 else ""}" cx="{14 + index * 30}" '
        f'cy="18" r="4.6" style="--d:{0.05 + index * 0.12:.2f}s"/>'
        for index in range(6)
    )
    return (
        f'<svg class="vignette" viewBox="{_VIGNETTE}" role="img" aria-label="Six '
        f"evenly spaced hellos, one of them missing. The bar underneath shows "
        f"the session torn down immediately after the missing one rather than "
        f'after the two further losses the protocol is meant to tolerate.">'
        + dots
        + _held(6, 36, 94, _A, delay=".1s")
        + '<rect class="down" x="100" y="36" width="94" height="15" rx="4" '
        'style="--d:.75s"/>'
        + '<text class="count" x="147" y="47.5" text-anchor="middle">down</text>'
        + '<text class="tick" x="104" y="70" text-anchor="middle">'
        "one lost hello</text>"
        "</svg>"
    )


def shapes() -> tuple[tuple[str, str, str], ...]:
    """The three shapes, as (heading, caption, svg).

    Returned rather than rendered so the markup around them stays in `view.py`
    with the rest of the page's structure — this module draws, it does not lay
    out.

    Three, and these three, because they are the three families the rule set
    actually splits into: two things that were meant to move together and did
    not, one thing that moved more than once, and a budget with nothing left in
    it for an ordinary loss. Every finding the tool emits is one of those.
    """
    return (
        (
            "they separate",
            "Two gateway groups on the same pair of devices answer one link "
            "failure at different speeds — one preempts back immediately, the "
            "other waits out a delay. Between the two answers the gateways for "
            "two VLANs sit on different devices, and traffic that has to cross "
            "between them does not. At rest, before and after, both "
            "configurations are correct.",
            _divergence_svg(),
        ),
        (
            "they oscillate",
            "One flapping interface, and a group that follows every edge of it "
            "because nothing damps the response. Each change is a forwarding "
            "interruption, and the group is stable at the start and stable at "
            "the end — so a configuration review sees a working design and a "
            "monitoring system sees a counter nobody reads.",
            _oscillation_svg(),
        ),
        (
            "the margin is gone",
            "A hold time worth fewer than three hellos. The protocol sizes that "
            "interval so two may be lost and the session survives; below three, "
            "one packet dropped by ordinary queueing tears it down and "
            "everything it carried is withdrawn. It comes back, so the only "
            "evidence left is a counter.",
            _margin_svg(),
        ),
    )
