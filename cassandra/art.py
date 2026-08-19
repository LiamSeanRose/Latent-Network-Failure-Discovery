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
from typing import Final

# Same categorical slots the figures use, so the illustration and the real
# timeline below it do not teach two different colour languages.
_A: Final = "#2a78d6"
_B: Final = "#eb6834"
_SPLIT: Final = "#d03b3b"


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
        f'rx="5" fill="{_A}"/>'
        f'<rect class="held late" x="{switch_at}" y="{y}" width="{404 - switch_at}" '
        f'height="22" rx="5" fill="{colour}"/>'
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
      <line x1="0" y1="0" x2="0" y2="6" stroke="{_SPLIT}" stroke-width="2.2"
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
