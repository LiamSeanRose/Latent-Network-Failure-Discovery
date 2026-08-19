"""The stylesheet, and the palette it is built from.

Kept apart from the page that uses it for the same reason the rules are kept
apart from the report: one is a set of decisions with reasons, the other is
markup. Every colour here is measured in `tests/test_palette.py` — for contrast
against the surface it sits on, in both themes, and for whether the categorical
slots stay distinguishable under red-green colour blindness. A swatch that looks
right is not the same as one that can be read.
"""

from __future__ import annotations

from typing import Final

# The validated categorical slots and the reserved status palette. Written out
# once each and applied by the block below, because a palette copied into four
# selectors is a palette that drifts in three of them.
LIGHT: Final = """
  --surface-0: #f6f6f4; --surface-1: #fcfcfb; --surface-2: #eeeeea;
  --ink-1: #0b0b0b; --ink-2: #52514e; --ink-3: #85847e;
  --line: #e0e0da; --accent: #256abf;
  --s-critical: #d03b3b; --s-serious: #c84917; --s-warning: #9a6a03;
  --s-good: #0a860a;
  --series-1: #2873cf; --series-2: #c94714; --series-3: #14835c;
  --grid: rgba(37,106,191,.07);
"""

# Stepped for the dark surface, not flipped: same hues, moved to where they read
# on a dark ground. Every value in both blocks is measured in tests/test_palette.py
# against the surface it sits on — the light status colours in particular are
# deeper than the obvious ones because amber text on near-white cannot be read,
# whatever it looks like in a swatch.
DARK: Final = """
  --surface-0: #131312; --surface-1: #1a1a19; --surface-2: #232320;
  --ink-1: #ffffff; --ink-2: #c3c2b7; --ink-3: #8e8d85;
  --line: #2e2c28; --accent: #6da7ec;
  --s-critical: #d85b5b; --s-serious: #ec835a; --s-warning: #fab219;
  --s-good: #0ca30c;
  --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70;
  --grid: rgba(109,167,236,.10);
"""

# Four ways in, one palette each way:
#   default            - the system preference
#   [data-theme]       - an explicit choice, for anything that sets the attribute
#   :has(:checked)     - the in-page toggle, which inverts whatever the system said
# The toggle is a checkbox and a label rather than a button and a script. A page
# with no script at all is one an offline reader, a mail client and a reviewer
# reading the source can all trust, and that is worth more than remembering the
# choice between visits.
THEME: Final = (
    ":root { color-scheme: light dark;" + LIGHT + "}\n"
    "@media (prefers-color-scheme: dark) {"
    ' :root:where(:not([data-theme="light"])) {' + DARK + "} }\n"
    ':root[data-theme="dark"] {' + DARK + "}\n"
    ":root:has(.theme-input:checked) {" + DARK + "}\n"
    "@media (prefers-color-scheme: dark) {"
    " :root:has(.theme-input:checked) {" + LIGHT + "} }\n"
)

STYLE: Final = (
    THEME
    + """
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0; background: var(--surface-0); color: var(--ink-1);
  font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
  background-image:
    linear-gradient(var(--grid) 1px, transparent 1px),
    linear-gradient(90deg, var(--grid) 1px, transparent 1px);
  background-size: 44px 44px, 44px 44px;
}
main { max-width: 60rem; margin: 0 auto; padding: 2.25rem 1.1rem 4rem; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
/* Default browser blue is the one colour on this page nobody chose. */
a { color: var(--accent); text-decoration-color: color-mix(in srgb,
  var(--accent) 45%, transparent); text-underline-offset: 2px; }
a:hover { text-decoration-color: currentColor; }
a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px;
  border-radius: 3px; }

/* ---- masthead ---- */
.masthead { position: relative; margin-bottom: 1.6rem; }
.wordmark {
  display: flex; align-items: center; gap: .6rem;
  font-size: 1.5rem; font-weight: 640; letter-spacing: -.02em; margin: 0;
}
.pulse { width: 11px; height: 11px; border-radius: 50%; background: var(--s-good);
  box-shadow: 0 0 0 0 color-mix(in srgb, var(--s-good) 60%, transparent);
  animation: pulse 2.6s ease-out infinite; flex: none; }
.pulse.alert { background: var(--s-critical);
  box-shadow: 0 0 0 0 color-mix(in srgb, var(--s-critical) 60%, transparent); }
@keyframes pulse {
  0% { box-shadow: 0 0 0 0 color-mix(in srgb, currentColor 0%, transparent); }
  40% { box-shadow: 0 0 0 7px color-mix(in srgb, var(--s-good) 0%, transparent); }
  100% { box-shadow: 0 0 0 0 transparent; }
}
.tagline { color: var(--ink-2); margin: .3rem 0 0; }

/* ---- reading position ---- */
/* Scroll-linked, so it costs no script. A findings page is long and mostly
   uniform; knowing how much of it is left is the one thing scrolling does not
   tell you. Without support the bar stays at zero width and is simply not
   there, which is the right fallback for something purely orienting. */
.progress {
  position: fixed; inset: 0 auto auto 0; height: 3px; width: 100%;
  transform: scaleX(0); transform-origin: 0 50%; z-index: 10;
  background: linear-gradient(90deg, var(--series-1), var(--s-critical));
}
@supports (animation-timeline: scroll()) {
  .progress {
    animation: fill linear;
    animation-timeline: scroll(root block);
  }
}
@keyframes fill { to { transform: scaleX(1); } }

/* ---- mark ---- */
/* The glyph animates once and stops. A logo that never settles is a logo that
   competes with the page it labels. */
.mark { flex: none; overflow: visible; }
.mark-plate { fill: var(--surface-2); stroke: var(--line); }
.mark .trace { fill: none; stroke-width: 2.4; stroke-linecap: round;
  stroke-linejoin: round; stroke-dasharray: 30; stroke-dashoffset: 30;
  animation: draw .7s ease-out .1s forwards; }
.mark .trace.a { stroke: var(--series-1); }
.mark .trace.b { stroke: var(--series-2); animation-delay: .25s; }
.mark-gap { fill: var(--s-critical); opacity: 0;
  animation: gap-in .5s ease-out .95s forwards; }
@keyframes gap-in { to { opacity: .17; } }

/* ---- hero ---- */
.hero { width: 100%; max-width: 34rem; height: auto; display: block;
  margin: .2rem auto .4rem; }
.hero text { font: 10px ui-monospace, SFMono-Regular, Menlo, monospace;
  fill: var(--ink-3); }
.hero .lane-label { fill: var(--ink-2); font-weight: 640; }
.hero .axis { stroke: var(--line); stroke-width: 1; }
.hero .event line { stroke: var(--ink-3); stroke-width: 1; stroke-dasharray: 3 3; }
.hero .held { transform-box: fill-box; transform-origin: left center;
  animation: grow .55s cubic-bezier(.2,.8,.3,1) both;
  animation-delay: var(--d); }
.hero .held.late { animation-delay: calc(var(--d) + .45s); }
.hero .split-edge { fill: none; stroke: var(--s-critical); stroke-width: 1.5;
  stroke-dasharray: 4 3; }
.hero .split-label { fill: var(--s-critical); font-weight: 700;
  letter-spacing: .08em; }
/* The split breathes; nothing else moves once it has drawn. It is the one part
   of the picture a first-time reader has to notice. */
.hero .split { opacity: 0; animation: split-in .6s ease-out 1.3s forwards,
  breathe 3.4s ease-in-out 1.9s infinite; }
@keyframes split-in { to { opacity: 1; } }
@keyframes breathe { 50% { opacity: .55; } }

/* ---- the three shapes ---- */
/* One card per family of finding, on the landing page. Each shape draws itself
   once when it arrives and then holds, except the split, which keeps breathing
   for the same reason it does in the hero: it is the part a first-time reader
   has to notice. */
.shapes { display: grid; gap: 1rem; margin: 1.5rem 0 .4rem;
  grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); }
.shape { background: var(--surface-1); border: 1px solid var(--line);
  border-radius: 12px; padding: .9rem 1rem 1rem;
  animation: rise .5s cubic-bezier(.2,.8,.3,1) both;
  animation-delay: calc(var(--i) * 120ms);
  transition: border-color .18s, transform .18s; }
.shape:hover { transform: translateY(-2px); border-color: var(--ink-3); }
.shape h3 { margin: .55rem 0 .3rem; font-size: .95rem; font-weight: 660;
  letter-spacing: -.005em; }
.shape p { margin: 0; color: var(--ink-2); font-size: .84rem; line-height: 1.55; }
.vignette { width: 100%; height: auto; display: block; }
.vignette text { font: 8.5px ui-monospace, SFMono-Regular, Menlo, monospace;
  fill: var(--ink-3); }
.vignette .tick line { stroke: var(--ink-3); stroke-width: 1;
  stroke-dasharray: 3 3; }
.vignette .held { transform-box: fill-box; transform-origin: left center;
  animation: grow .5s cubic-bezier(.2,.8,.3,1) both;
  animation-delay: calc(var(--d) + var(--start, 0s)); }
.vignette .count { fill: var(--ink-1); font-weight: 700; letter-spacing: .04em; }
.vignette .down { fill: var(--s-critical); transform-box: fill-box;
  transform-origin: left center;
  animation: grow .45s cubic-bezier(.2,.8,.3,1) both; animation-delay: var(--d); }
/* Near-black on the critical fill, in both themes, for the reason
   `visuals.label_for` computes rather than assumes: white on #d03b3b is 4.0:1,
   which eight-and-a-half-pixel text does not carry, and the dark candidate is
   5.0:1 against the same fill. The dark theme's critical is lighter still, so
   the same choice holds there. */
.vignette .down + .count { fill: #0b0b0b; }
.vignette .hello { fill: var(--series-1);
  animation: pop .35s cubic-bezier(.2,1.3,.4,1) both; animation-delay: var(--d); }
/* The missing hello is drawn as the hole it is — outlined, unfilled — rather
   than left out. A gap in a row of six dots reads as a drawing that ran out of
   room; a ring with nothing in it reads as one that did not arrive. */
.vignette .hello.lost { fill: none; stroke: var(--ink-3); stroke-width: 1.4;
  stroke-dasharray: 2.6 2.4; }
.vignette .split-edge { fill: none; stroke: var(--s-critical); stroke-width: 1.4;
  stroke-dasharray: 4 3; }
.vignette .split { opacity: 0;
  animation: split-in .55s ease-out 1.15s forwards,
             breathe 3.4s ease-in-out 1.7s infinite; }

/* ---- ring ---- */
.ring { flex: none; }
.ring .track { fill: none; stroke: var(--surface-2); stroke-width: 13; }
.ring .arc { fill: none; stroke-width: 13;
  transform: rotate(-90deg); transform-origin: 60px 60px;
  stroke-dasharray: var(--len) var(--gap); stroke-dashoffset: var(--off);
  animation: arc-in .65s cubic-bezier(.2,.8,.3,1) both;
  animation-delay: calc(var(--i) * 110ms); }
@keyframes arc-in { from { stroke-dasharray: 0 9999; } }
.ring .ring-total { fill: var(--ink-1); font-size: 26px; font-weight: 680;
  text-anchor: middle; font-variant-numeric: tabular-nums; }
.ring .ring-unit { fill: var(--ink-3); font-size: 9.5px; text-anchor: middle;
  text-transform: uppercase; letter-spacing: .08em; }
.summary { display: flex; align-items: center; gap: 1.6rem; flex-wrap: wrap; }
.summary .totals { flex: 1 1 16rem; min-width: 0; }

/* ---- rulebook ---- */
.rulebook { margin-top: 2.2rem; border-top: 1px solid var(--line);
  padding-top: 1.2rem; }
.rulebook > h2 { font-size: .82rem; text-transform: uppercase; letter-spacing: .07em;
  color: var(--ink-3); margin: 0 0 .15rem; font-weight: 640; }
.rulebook .tier-head { font-size: .78rem; text-transform: uppercase;
  letter-spacing: .07em; color: var(--ink-3); font-weight: 640;
  margin: 1.5rem 0 .5rem; }
.rulebook .tier-head .n { color: var(--ink-3); opacity: .7; font-weight: 500; }
.rule {
  background: var(--surface-1); border: 1px solid var(--line); border-radius: 10px;
  padding: .85rem 1rem; margin-bottom: .6rem; scroll-margin-top: 1rem;
}
.rule h3 { font-size: .92rem; margin: 0 0 .5rem; font-weight: 620;
  display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
.rule p { margin: 0 0 .5rem; }
.rule ul { margin: .3rem 0 .5rem; padding-left: 1.1rem; color: var(--ink-2);
  font-size: .86rem; }
.rule li { margin-bottom: .3rem; }
.rule .src { display: block; color: var(--ink-3); font-size: .74rem; }
/* A test identifier is one unbreakable token about ninety characters long, and
   there are several per rule. Left alone they push the whole page sideways on a
   phone, which is a horizontal scrollbar on the document rather than on the one
   element that is too wide. */
.rule .src, .rule .mono, .cite { overflow-wrap: anywhere; }
.rule .undocumented { color: var(--s-serious); font-size: .88rem; }
.rule .inert-why { color: var(--ink-2); font-size: .88rem; }
/* ---- what the tool read ---- */
.read-appendix > summary { cursor: pointer; font-weight: 640; padding: .5rem 0;
  border-bottom: 1px solid var(--line); margin-bottom: .8rem; }
.device-facts { padding-bottom: .6rem; }
table.facts { width: 100%; border-collapse: collapse; margin: .4rem 0 .9rem;
  font-size: .84rem; display: block; overflow-x: auto; }
table.facts th { text-align: left; font-weight: 640; color: var(--ink-3);
  text-transform: uppercase; letter-spacing: .05em; font-size: .7rem;
  padding: .3rem .6rem .3rem 0; border-bottom: 1px solid var(--line);
  white-space: nowrap; }
table.facts td { padding: .32rem .6rem .32rem 0; border-bottom: 1px solid var(--line);
  color: var(--ink-2); vertical-align: top; }
table.facts tr:last-child td { border-bottom: 0; }
table.facts .mono { color: var(--ink-1); }
.state-shutdown { color: var(--s-serious); font-weight: 640; }
.state-up { color: var(--ink-3); }
.tag.inert { color: var(--s-warning); border-color: var(--s-warning); }
/* The linked rule is marked, not merely scrolled to: landing in a list of
   near-identical boxes and having to work out which one you asked for is the
   failure mode of every in-page anchor. */
.rule:target { border-color: var(--accent);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent); }
a.rule-link { color: var(--ink-3); text-decoration: none;
  border-bottom: 1px dotted var(--ink-3); transition: color .15s; }
a.rule-link:hover { color: var(--accent); border-bottom-color: var(--accent); }

/* ---- theme ---- */
.visually-hidden {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip-path: inset(50%); white-space: nowrap;
}
/* Focusable but invisible: the label is what you see, the checkbox is what the
   keyboard and the selector talk to. */
.theme-input { position: absolute; opacity: 0; width: 0; height: 0; }
.theme {
  position: absolute; top: 0; right: 0; width: 2.1rem; height: 2.1rem;
  border: 1px solid var(--line); border-radius: 999px; background: var(--surface-1);
  color: var(--ink-2); cursor: pointer; font-size: .95rem; line-height: 1;
  display: grid; place-items: center;
  transition: border-color .15s, color .15s, transform .18s;
}
.theme:hover { color: var(--ink-1); border-color: var(--accent);
  transform: rotate(-18deg); }
.theme-input:focus-visible + .theme {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 22%, transparent);
}
/* Show the destination, not the current state: the moon offers dark. */
.theme .sun { display: none; }
:root:has(.theme-input:checked) .theme .sun { display: inline; }
:root:has(.theme-input:checked) .theme .moon { display: none; }
@media (prefers-color-scheme: dark) {
  .theme .sun { display: inline; }
  .theme .moon { display: none; }
  :root:has(.theme-input:checked) .theme .sun { display: none; }
  :root:has(.theme-input:checked) .theme .moon { display: inline; }
}

/* ---- search ---- */
form.finder { display: flex; gap: .5rem; margin: 1.4rem 0 1.6rem; flex-wrap: wrap; }
input[type=text] {
  flex: 1 1 20rem; padding: .62rem .75rem; border: 1px solid var(--line);
  border-radius: 8px; background: var(--surface-1); color: var(--ink-1);
  font: inherit; transition: border-color .18s, box-shadow .18s;
}
input[type=text]:focus {
  outline: none; border-color: var(--accent);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 22%, transparent);
}
input[type=text].since, input[type=text].query {
  flex: 0 1 11rem; font-size: .92rem; }
button.go {
  padding: .62rem 1.15rem; border: 0; border-radius: 8px; background: var(--accent);
  color: #fff; font: inherit; font-weight: 620; cursor: pointer;
  transition: transform .12s ease, filter .18s;
}
button.go:hover { filter: brightness(1.08); transform: translateY(-1px); }

/* ---- figures ---- */
.figure {
  background: var(--surface-1); border: 1px solid var(--line); border-radius: 12px;
  padding: 1rem 1rem .5rem; margin-bottom: 1rem; overflow-x: auto;
}
.figure h2 { font-size: .82rem; text-transform: uppercase; letter-spacing: .07em;
  color: var(--ink-3); margin: 0 0 .1rem; font-weight: 640; }
.figure p.cap { color: var(--ink-2); font-size: .86rem; margin: 0 0 .7rem; }
/* Scroll rather than shrink. Below about 520px the bands and their labels
   stop being readable, and an illegible figure is worse than a scrollbar. */
svg.viz { width: 100%; min-width: 520px; height: auto; display: block; }
svg.viz text { font: 11px ui-monospace, SFMono-Regular, Menlo, monospace;
  fill: var(--ink-2); }
svg.viz .row-label { fill: var(--ink-1); font-weight: 600; }
/* The label sits on the band's own fill, so its colour is chosen per band by
   contrast rather than by theme — see visuals.py. A mid-tone fill cannot carry
   white text at eleven pixels, and half these fills are mid-tone. */
svg.viz .band-label { font-weight: 600; }
svg.viz .tick { fill: var(--ink-3); }
svg.reaction .col { fill: var(--ink-3); font-size: 10px; text-transform: uppercase;
  letter-spacing: .06em; }
svg.reaction .bar rect { fill: var(--accent); opacity: .8;
  transform-origin: left center;
  animation: grow .5s cubic-bezier(.2,.8,.3,1) both;
  animation-delay: calc(var(--i) * 70ms); }
svg.reaction .value { fill: var(--ink-1); font-weight: 620; }
svg.reaction .value.none { fill: var(--ink-3); font-weight: 500; }
svg.viz .ev { stroke: var(--ink-3); stroke-width: 1; opacity: .55; }
/* --c and --cd live on the band element, so the dark variant has to be
   selected here rather than folded into the palette: a custom property declared
   on :root in terms of --c resolves against :root, where --c does not exist. */
svg.viz .band rect {
  fill: var(--c); transform-origin: left center;
  animation: grow .5s cubic-bezier(.2,.8,.3,1) both;
}
svg.viz .band .band-label { fill: var(--l); }
:root[data-theme="dark"] svg.viz .band rect,
:root:has(.theme-input:checked) svg.viz .band rect { fill: var(--cd); }
:root[data-theme="dark"] svg.viz .band .band-label,
:root:has(.theme-input:checked) svg.viz .band .band-label { fill: var(--ld); }
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) svg.viz .band rect { fill: var(--cd); }
  :root:where(:not([data-theme="light"])) svg.viz .band .band-label { fill: var(--ld); }
  :root:has(.theme-input:checked) svg.viz .band rect { fill: var(--c); }
  :root:has(.theme-input:checked) svg.viz .band .band-label { fill: var(--l); }
}
@keyframes grow {
  from { transform: scaleX(0); opacity: .2; }
  to { transform: scaleX(1); opacity: 1; }
}
/* The map has three or four nodes in it. Letting it stretch to the full column
   turns a small graph into a page of whitespace with dots in the corners. */
svg.topology { max-width: 560px; min-width: 380px; margin: 0 auto; }
svg.topology .edge line { stroke: var(--accent); stroke-width: 2; opacity: .5;
  stroke-dasharray: 260; stroke-dashoffset: 260;
  animation: draw .8s ease-out forwards; animation-delay: calc(var(--i) * .09s); }
@keyframes draw { to { stroke-dashoffset: 0; } }
svg.topology .edge-label { fill: var(--ink-3); font-size: 10px;
  paint-order: stroke; stroke: var(--surface-1); stroke-width: 3px;
  stroke-linejoin: round; }
svg.topology .node circle { fill: var(--surface-1); stroke: var(--accent);
  stroke-width: 2.5; animation: pop .45s cubic-bezier(.2,1.3,.4,1) both;
  animation-delay: calc(.35s + var(--i) * .08s); }
svg.topology .node text { fill: var(--ink-1); font-weight: 640; font-size: 11px; }
svg.topology .node.l2only circle { stroke: var(--ink-3); stroke-dasharray: 3 3; }
svg.topology .node circle.mark { stroke: var(--surface-1); stroke-width: 1.5;
  animation: pop .4s cubic-bezier(.2,1.3,.4,1) both;
  animation-delay: calc(.55s + var(--i) * .08s); }
svg.topology .node circle.mark.high { fill: var(--s-critical); }
svg.topology .node circle.mark.medium { fill: var(--s-serious); }
svg.topology .node circle.mark.low { fill: var(--s-warning); }
svg.topology .node circle.mark.info { fill: var(--series-1); }
svg.topology .node .hint { fill: var(--ink-3); font-weight: 500; font-size: 9px; }
@keyframes pop { from { transform: scale(0); } to { transform: scale(1); } }
svg.topology .node { transform-box: fill-box; transform-origin: center; }

/* ---- summary ---- */
.sparkbar { display: flex; height: 8px; border-radius: 999px; overflow: hidden;
  background: var(--surface-2); margin: .1rem 0 1rem; }
.sparkbar .seg { background: var(--c); transform-origin: left center;
  animation: grow .6s cubic-bezier(.2,.8,.3,1) both; }
.counts { display: flex; gap: 1.4rem; flex-wrap: wrap; margin-bottom: .4rem; }
.counts .count b { display: block; font-size: 1.45rem; font-weight: 660;
  line-height: 1.1; }
.counts .count span { color: var(--ink-3); font-size: .74rem; text-transform: uppercase;
  letter-spacing: .05em; }

/* ---- filters ---- */
.chips { display: flex; gap: .4rem; flex-wrap: wrap; margin-bottom: 1.1rem; }
.chip { display: inline-flex; align-items: center; gap: .35rem; padding: .28rem .62rem;
  border: 1px solid var(--line); border-radius: 999px; background: var(--surface-1);
  color: var(--ink-2); text-decoration: none; font-size: .82rem;
  transition: border-color .15s, color .15s, transform .12s; }
.chip:hover { transform: translateY(-1px); color: var(--ink-1);
  border-color: var(--accent); }
.chip.on { background: var(--accent); border-color: var(--accent); color: #fff; }
.chips .label { color: var(--ink-3); font-size: .78rem; text-transform: uppercase;
  letter-spacing: .05em; align-self: center; min-width: 4.2rem; }
/* The node is the hit area, not just its label. */
svg.topology a.node-link { cursor: pointer; }
svg.topology a.node-link:hover circle { stroke-width: 3.5; }
svg.topology a.node-link:hover text { fill: var(--accent); }
svg.topology a.node-link:focus-visible circle { outline: 2px solid var(--accent);
  outline-offset: 3px; }
.chip .n { opacity: .72; font-variant-numeric: tabular-nums; }

/* ---- findings ---- */
.device-group { margin-bottom: 1.5rem; }
.device-group > summary { cursor: pointer; list-style: none; padding: .5rem 0;
  font-weight: 640; display: flex; align-items: center; gap: .5rem;
  border-bottom: 1px solid var(--line); margin-bottom: .8rem; }
.device-group > summary::-webkit-details-marker { display: none; }
.device-group > summary::before { content: "▸"; color: var(--ink-3);
  transition: transform .18s; display: inline-block; }
.device-group[open] > summary::before { transform: rotate(90deg); }
.device-group .n { color: var(--ink-3); font-weight: 500; font-size: .85rem; }
.finding {
  background: var(--surface-1); border: 1px solid var(--line);
  border-left: 3px solid var(--ink-3); border-radius: 10px;
  padding: .9rem 1rem; margin-bottom: .65rem;
  animation: rise .42s cubic-bezier(.2,.8,.3,1) both;
  animation-delay: calc(var(--i, 0) * 45ms);
  transition: transform .16s ease, border-color .16s;
}
.finding:hover { transform: translateY(-2px); border-color: var(--ink-3); }
@keyframes rise {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: none; }
}
/* Where the browser can drive an animation from scroll position, cards rise as
   they arrive rather than all at once on load — on a page of two hundred, a
   staggered load animation is over before most of them are ever seen. The range
   ends inside the entry, so anything already on screen is drawn fully.
   Everywhere else the load animation above still applies. */
@supports (animation-timeline: view()) {
  .finding {
    animation: rise linear both;
    animation-timeline: view();
    animation-range: entry 0% entry 55%;
    animation-delay: 0s;
  }
}
.finding.high { border-left-color: var(--s-critical); }
.finding.medium { border-left-color: var(--s-serious); }
.finding.low { border-left-color: var(--s-warning); }
.finding.info { border-left-color: var(--series-1); }
.finding h2 { font-size: 1rem; margin: 0 0 .3rem; font-weight: 620; }
.meta { color: var(--ink-3); font-size: .8rem; margin: 0 0 .55rem;
  display: flex; gap: .45rem; flex-wrap: wrap; align-items: center; }
.sev { display: inline-flex; align-items: center; gap: .3rem; font-weight: 640; }
.sev::before { content: ""; width: 8px; height: 8px; border-radius: 2px;
  background: currentColor; }
.sev.high { color: var(--s-critical); } .sev.medium { color: var(--s-serious); }
.sev.low { color: var(--s-warning); } .sev.info { color: var(--series-1); }
.tag { border: 1px solid var(--line); border-radius: 999px; padding: 0 .45rem;
  font-size: .72rem; color: var(--ink-3); }
/* Where to open, not what is wrong. Quiet, in the row that already carries the
   device and the rule id. */
.cite { color: var(--ink-3); font-size: .76rem; }
.detail { margin: 0 0 .55rem; }
.trigger, .remedy { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .8rem; background: var(--surface-2); border-radius: 6px;
  padding: .38rem .55rem; margin-bottom: .35rem; overflow-x: auto; }
.remedy { border-left: 2px solid var(--s-good); }
.change { background: var(--surface-2); border-radius: 6px; border-left: 2px solid
  var(--s-good); padding: .4rem .55rem; margin-bottom: .35rem; overflow-x: auto; }
.change .label { display: block; color: var(--ink-3); font-size: .68rem;
  text-transform: uppercase; letter-spacing: .06em; margin-bottom: .2rem; }
.change pre { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .8rem; color: var(--ink-1); white-space: pre; }
details summary { cursor: pointer; color: var(--ink-3); font-size: .82rem; }
details ul { margin: .45rem 0 0; padding-left: 1.1rem; font-family: ui-monospace,
  SFMono-Regular, Menlo, monospace; font-size: .78rem; color: var(--ink-2); }
.offer { margin: .9rem 0 0; padding-top: .8rem;
  border-top: 1px solid var(--line); color: var(--ink-2); }
.empty, .error, .note { background: var(--surface-1); border: 1px solid var(--line);
  border-radius: 10px; padding: 1.1rem; }
.error { border-left: 3px solid var(--s-critical); }
.note.unparsed { border-left: 3px solid var(--s-warning); margin-bottom: 1rem; }
/* ---- comparison ---- */
.compare { background: var(--surface-1); border: 1px solid var(--line);
  border-left: 3px solid var(--s-good); border-radius: 10px;
  padding: 1rem; margin-bottom: 1rem; }
.compare.regressed { border-left-color: var(--s-critical); }
.compare .counts-inline { display: flex; gap: 1rem; flex-wrap: wrap;
  margin: .5rem 0 .3rem; }
.compare .c { font-weight: 640; font-variant-numeric: tabular-nums; }
.compare .c.new { color: var(--s-critical); }
.compare .c.fixed { color: var(--s-good); }
.compare .c.known { color: var(--ink-3); }
.compare .moved { margin: .4rem 0 .3rem; }
.tag.state { font-weight: 660; }
.tag.state.new { color: var(--s-critical); border-color: var(--s-critical); }
.tag.state.fixed { color: var(--s-good); border-color: var(--s-good); }
.finding.is-new { border-left-width: 5px; }
.finding.is-known { opacity: .82; }
.finding.is-known:hover { opacity: 1; }
.finding.is-fixed { border-left-color: var(--s-good); opacity: .78; }
.finding.is-fixed h2 { text-decoration: line-through; text-decoration-thickness: 1px; }
.note.unparsed .mono { color: var(--ink-1); }
.caveat { color: var(--ink-3); font-size: .84rem; margin-top: 2rem;
  border-top: 1px solid var(--line); padding-top: .9rem; }
footer.meta-foot { color: var(--ink-3); font-size: .78rem; margin-top: 1.6rem; }
@media (max-width: 700px) {
  main { padding: 1.4rem .8rem 3rem; }
  .counts { gap: 1rem; }
  .figure { padding: .8rem .7rem .3rem; }
}
/* Print: a finding list is a thing people take into a change review. Drop the
   chrome, keep the figures, and let cards break across pages rather than
   clipping.

   The animation reset is not decoration. Every card's entrance keyframe starts
   at `opacity: 0` and is driven by `animation-timeline: view()`, and a printed
   page has no scroll position to drive it from — the timeline sits at its start
   and the whole finding list prints blank. Cancelling the animation lands each
   element on its natural style, which is the printed state that was wanted all
   along. The same reset is what `prefers-reduced-motion` does below, for the
   same reason: an entrance that never plays must leave nothing hidden. */
@media print {
  *, *::before, *::after { animation: none !important; transition: none !important; }
  body { background: #fff; color: #000; background-image: none; }
  main { max-width: none; padding: 0; }
  form.finder, .chips, .pulse, .theme, .theme-input, .progress { display: none; }
  .finding, .figure { break-inside: avoid; border: 1px solid #ccc; }
  .finding { box-shadow: none; }
  a[href]::after { content: ""; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
  svg.topology .edge line { stroke-dashoffset: 0; }
}
"""
)
