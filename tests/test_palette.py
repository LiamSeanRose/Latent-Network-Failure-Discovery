"""Contrast, checked rather than asserted in a comment.

The page is read on a laptop screen in an office, by someone who may be
colour-blind, at whatever brightness the room happens to have. Every colour
decision here has been justified in prose somewhere; this is the file that
measures whether the justifications are true, in both themes, and it fails when
they stop being.

WCAG 2.1 contrast ratios throughout: 4.5:1 for body text, 3:1 for large text and
for a graphical object that carries meaning on its own.
"""

from __future__ import annotations

import re
from typing import Final

import pytest

from cassandra import art, visuals
from cassandra.style import DARK, LIGHT

BODY_MIN: Final = 4.5
LARGE_MIN: Final = 3.0
OBJECT_MIN: Final = 3.0


def _palette(block: str) -> dict[str, str]:
    """The custom properties declared in one of the two theme blocks."""
    return {
        name: value.strip()
        for name, value in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", block)
    }


LIGHT: Final = _palette(LIGHT)
DARK: Final = _palette(DARK)


def _rgb(colour: str) -> tuple[float, float, float]:
    text = colour.strip()
    if match := re.fullmatch(r"#([0-9a-fA-F]{6})", text):
        raw = match.group(1)
        return tuple(int(raw[i : i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]
    if match := re.fullmatch(r"rgba?\(([^)]+)\)", text):
        parts = [p.strip() for p in match.group(1).split(",")]
        return tuple(float(p) / 255 for p in parts[:3])  # type: ignore[return-value]
    raise AssertionError(f"cannot read colour {colour!r}")


def _luminance(colour: str) -> float:
    def channel(value: float) -> float:
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(c) for c in _rgb(colour))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(first: str, second: str) -> float:
    a, b = _luminance(first), _luminance(second)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


def _resolve(palette: dict[str, str], name: str, fallback: dict[str, str]) -> str:
    """A palette value, falling back to the light block.

    The dark block redefines only what changes; status hues are inherited on
    purpose, because red still has to read as red.
    """
    return palette.get(name) or fallback[name]


def _themes() -> list[tuple[str, dict[str, str]]]:
    return [("light", LIGHT), ("dark", {**LIGHT, **DARK})]


@pytest.mark.parametrize(("theme", "palette"), _themes())
@pytest.mark.parametrize("ink", ["--ink-1", "--ink-2"])
def test_body_text_is_readable_on_every_surface(
    theme: str, palette: dict[str, str], ink: str
) -> None:
    for surface in ("--surface-0", "--surface-1", "--surface-2"):
        ratio = contrast(palette[ink], palette[surface])
        assert ratio >= BODY_MIN, (
            f"{theme}: {ink} on {surface} is {ratio:.2f}:1, below {BODY_MIN}"
        )


@pytest.mark.parametrize(("theme", "palette"), _themes())
def test_the_quietest_ink_still_clears_the_large_text_bar(
    theme: str, palette: dict[str, str]
) -> None:
    """--ink-3 is for captions, tick labels and hints.

    It is allowed to be quiet. It is not allowed to be unreadable, and the
    figures use it at 10 and 11 pixels, which is not large text — so this is the
    floor below which those labels would have to be recoloured, not the target.
    """
    ratio = contrast(palette["--ink-3"], palette["--surface-1"])
    assert ratio >= LARGE_MIN, f"{theme}: --ink-3 is {ratio:.2f}:1"


@pytest.mark.parametrize(("theme", "palette"), _themes())
@pytest.mark.parametrize(
    "status", ["--s-critical", "--s-serious", "--s-warning", "--s-good"]
)
def test_status_colours_are_visible_as_marks(
    theme: str, palette: dict[str, str], status: str
) -> None:
    """Severity is carried by a coloured square beside its name.

    The name is what a colour-blind reader uses, so the square only has to meet
    the graphical-object bar — but it does have to meet it, or the mark is
    decoration pretending to be information.
    """
    ratio = contrast(_resolve(palette, status, LIGHT), palette["--surface-1"])
    assert ratio >= OBJECT_MIN, f"{theme}: {status} is {ratio:.2f}:1"


# --------------------------------------------------------------------------
# Telling colours apart is not the same question as reading text on them
#
# WCAG contrast is a luminance ratio, and two colours can be plainly different
# and share a luminance — blue and orange, most obviously. Categorical slots have
# to be told apart by someone with red-green colour blindness, which is a
# question about hue, so it is measured in a perceptual space after simulating
# the deficiency rather than by the ratio used above.
# --------------------------------------------------------------------------

# Viénot, Brettel and Mollon's linear approximation. Enough to catch a palette
# that collapses; not a substitute for asking someone.
_CVD: Final = {
    "protanopia": (
        (0.0, 2.02344, -2.52581),
        (0.0, 1.0, 0.0),
        (0.0, 0.0, 1.0),
    ),
    "deuteranopia": (
        (1.0, 0.0, 0.0),
        (0.494207, 0.0, 1.24827),
        (0.0, 0.0, 1.0),
    ),
}

_TO_LMS: Final = (
    (0.31399022, 0.63951294, 0.04649755),
    (0.15537241, 0.75789446, 0.08670142),
    (0.01775239, 0.10944209, 0.87256922),
)
_FROM_LMS: Final = (
    (5.47221206, -4.6419601, 0.16963708),
    (-1.1252419, 2.29317094, -0.1678952),
    (0.02980165, -0.19318073, 1.16364789),
)


def _apply(
    matrix: tuple[tuple[float, ...], ...], v: tuple[float, ...]
) -> tuple[float, ...]:
    return tuple(sum(row[i] * v[i] for i in range(3)) for row in matrix)


def _linear(colour: str) -> tuple[float, ...]:
    def channel(value: float) -> float:
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    return tuple(channel(c) for c in _rgb(colour))


def simulate(colour: str, deficiency: str) -> tuple[float, float, float]:
    """The colour as it reaches someone with that deficiency, linear RGB."""
    lms = _apply(_TO_LMS, _linear(colour))
    return _apply(_FROM_LMS, _apply(_CVD[deficiency], lms))  # type: ignore[return-value]


def _lab(linear: tuple[float, float, float]) -> tuple[float, float, float]:
    """CIE L*a*b* under D65, from linear sRGB."""
    x = 0.4124 * linear[0] + 0.3576 * linear[1] + 0.1805 * linear[2]
    y = 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
    z = 0.0193 * linear[0] + 0.1192 * linear[1] + 0.9505 * linear[2]
    white = (0.95047, 1.0, 1.08883)

    def f(t: float) -> float:
        t = max(t, 0.0)
        return t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116

    fx, fy, fz = (f(v / w) for v, w in zip((x, y, z), white, strict=True))
    return (116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz))


def distance(first: str, second: str, deficiency: str | None = None) -> float:
    """CIE76 difference, optionally as a given deficiency would see it."""
    a = _lab(simulate(first, deficiency) if deficiency else _linear(first))  # type: ignore[arg-type]
    b = _lab(simulate(second, deficiency) if deficiency else _linear(second))  # type: ignore[arg-type]
    return sum((x - y) ** 2 for x, y in zip(a, b, strict=True)) ** 0.5


# Roughly "obviously different rather than merely not identical". Chosen by
# measuring the shipped set, then checking the number still rejects a palette
# that collapses — swapping a slot for a near-neighbour of another fails it.
MIN_SEPARATION: Final = 20.0


@pytest.mark.parametrize(("theme", "index"), [("light", 0), ("dark", 1)])
@pytest.mark.parametrize("deficiency", [None, "protanopia", "deuteranopia"])
def test_series_colours_stay_distinct_under_colour_blindness(
    theme: str, index: int, deficiency: str | None
) -> None:
    """Three categorical slots that have to be told apart at a glance.

    Every band is directly labelled with the device that holds it, so colour is
    never the only cue — but two bands that read as one colour make the picture
    say something false before anyone gets to a label.
    """
    slots = [pair[index] for pair in visuals.SERIES]
    for i, first in enumerate(slots):
        for second in slots[i + 1 :]:
            separation = distance(first, second, deficiency)
            assert separation >= MIN_SEPARATION, (
                f"{theme}/{deficiency or 'normal'}: {first} and {second} are "
                f"{separation:.1f} apart, below {MIN_SEPARATION}"
            )


@pytest.mark.parametrize(("theme", "index"), [("light", 0), ("dark", 1)])
@pytest.mark.parametrize("deficiency", [None, "protanopia", "deuteranopia"])
def test_a_split_never_looks_like_a_device(
    theme: str, index: int, deficiency: str | None
) -> None:
    """The split band is the finding. It cannot read as one more device.

    Red against orange is exactly where red-green colour blindness bites, which
    is why this is checked simulated rather than by eye.
    """
    for pair in visuals.SERIES:
        separation = distance(visuals.SPLIT_COLOUR[index], pair[index], deficiency)
        assert separation >= MIN_SEPARATION, (
            f"{theme}/{deficiency or 'normal'}: split reads {separation:.1f} from "
            f"{pair[index]}"
        )


@pytest.mark.parametrize(("theme", "index"), [("light", 0), ("dark", 1)])
def test_a_band_label_is_readable_on_its_band(theme: str, index: int) -> None:
    """Band labels are eleven-pixel bold text on the band's own fill.

    Eleven pixels is not large text by any definition, so this is the 4.5 bar,
    not the 3.0 one. The colour is chosen per fill rather than per theme
    precisely because half these fills cannot carry white.
    """
    for pair in (*visuals.SERIES, visuals.SPLIT_COLOUR, visuals.NO_MASTER):
        fill = pair[index]
        ratio = contrast(visuals.label_for(fill), fill)
        assert ratio >= BODY_MIN, (
            f"{theme}: the chosen label on {fill} is only {ratio:.2f}:1"
        )


def test_the_illustration_uses_the_same_colour_language_as_the_figures() -> None:
    """Teaching one set of colours in the hero and another in the timeline below
    it would make the illustration actively misleading.

    The artwork names the palette's variables and the figures write the hex
    values inline, because a figure's bands need a per-band light and dark value
    and the artwork needs neither. So the agreement is checked where it actually
    has to hold: the variable each theme declares against the value that theme's
    figures use. Comparing the strings would have passed while the hero stayed
    on the light blue in dark mode, which is the state this replaced.
    """
    svg = art.hero_svg() + "".join(drawing for _, _, drawing in art.shapes())
    for name, pair in (
        ("--series-1", visuals.SERIES[0]),
        ("--series-2", visuals.SERIES[1]),
        ("--s-critical", visuals.SPLIT_COLOUR),
    ):
        assert f"var({name})" in svg, f"the artwork does not use {name}"
        for theme, palette, expected in (
            ("light", LIGHT, pair[0]),
            ("dark", {**LIGHT, **DARK}, pair[1]),
        ):
            assert name in palette, f"{theme} declares no {name}"
            assert palette[name] == expected, (
                f"{theme}: {name} is {palette[name]} and the figures draw "
                f"the same slot in {expected}"
            )
