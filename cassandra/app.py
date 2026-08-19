"""A local web view over the same engine the CLI uses.

Standard library only, on purpose: the whole premise of v3 is that installing this
tool is the entire setup, and a UI that drags in a web framework and a build step
walks that back. No external stylesheet, script, font or image either — a page that
fetches anything is a page that does not work on a laptop with no network, which is
where someone reads their own configs.

Binds to loopback. It reads config files from a directory the user names, which is
the tool's job, but that is not something to expose on a network interface.

Everything the view can do is expressed in the query string — the directory, the
severity filter, the tier filter — so any state the page shows is a link someone can
send, bookmark or curl, and `/findings.json` answers the same question as the page it
was linked from.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import asdict, dataclass
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final
from urllib.parse import parse_qs, urlencode, urlparse

from cassandra import art, visuals
from cassandra.catalogue import RuleDoc, catalogue
from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack
from cassandra.facts import rules
from cassandra.findings import Finding, Severity, Tier, rank
from cassandra.timing import sequences, timer_rules

_SEVERITY_ORDER: Final = (
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_TIER_ORDER: Final = (Tier.FACTS, Tier.TIMING)

_TIMING_CAVEAT: Final = (
    "Timing findings come from a model of timer interaction, not from running the "
    "protocols. They tell you a sequence your configuration permits — each one shows "
    "the sequence, so you can judge it."
)

# The validated categorical slots and the reserved status palette. Written out
# once each and applied by the block below, because a palette copied into four
# selectors is a palette that drifts in three of them.
_LIGHT: Final = """
  --surface-0: #f6f6f4; --surface-1: #fcfcfb; --surface-2: #eeeeea;
  --ink-1: #0b0b0b; --ink-2: #52514e; --ink-3: #85847e;
  --line: #e0e0da; --accent: #256abf;
  --s-critical: #d03b3b; --s-serious: #ec835a; --s-warning: #fab219;
  --s-good: #0ca30c;
  --series-1: #2a78d6; --series-2: #eb6834; --series-3: #1baf7a;
  --grid: rgba(37,106,191,.07);
"""

# Stepped for the dark surface, not flipped. Status hues are inherited from the
# light block on purpose: red still has to read as red.
_DARK: Final = """
  --surface-0: #131312; --surface-1: #1a1a19; --surface-2: #232320;
  --ink-1: #ffffff; --ink-2: #c3c2b7; --ink-3: #8e8d85;
  --line: #2e2c28; --accent: #6da7ec;
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
_THEME: Final = (
    ":root { color-scheme: light dark;" + _LIGHT + "}\n"
    "@media (prefers-color-scheme: dark) {"
    ' :root:where(:not([data-theme="light"])) {' + _DARK + "} }\n"
    ':root[data-theme="dark"] {' + _DARK + "}\n"
    ":root:has(.theme-input:checked) {" + _DARK + "}\n"
    "@media (prefers-color-scheme: dark) {"
    " :root:has(.theme-input:checked) {" + _LIGHT + "} }\n"
)

_STYLE: Final = (
    _THEME
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
  margin: .2rem 0 .4rem; }
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
.rule .undocumented { color: var(--s-serious); font-size: .88rem; }
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
svg.viz .band-label { fill: #fff; font-weight: 600; }
svg.viz .tick { fill: var(--ink-3); }
svg.viz .ev { stroke: var(--ink-3); stroke-width: 1; opacity: .55; }
/* --c and --cd live on the band element, so the dark variant has to be
   selected here rather than folded into the palette: a custom property declared
   on :root in terms of --c resolves against :root, where --c does not exist. */
svg.viz .band rect {
  fill: var(--c); transform-origin: left center;
  animation: grow .5s cubic-bezier(.2,.8,.3,1) both;
}
:root[data-theme="dark"] svg.viz .band rect,
:root:has(.theme-input:checked) svg.viz .band rect { fill: var(--cd); }
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) svg.viz .band rect { fill: var(--cd); }
  :root:has(.theme-input:checked) svg.viz .band rect { fill: var(--c); }
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
.detail { margin: 0 0 .55rem; }
.trigger, .remedy { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .8rem; background: var(--surface-2); border-radius: 6px;
  padding: .38rem .55rem; margin-bottom: .35rem; overflow-x: auto; }
.remedy { border-left: 2px solid var(--s-good); }
details summary { cursor: pointer; color: var(--ink-3); font-size: .82rem; }
details ul { margin: .45rem 0 0; padding-left: 1.1rem; font-family: ui-monospace,
  SFMono-Regular, Menlo, monospace; font-size: .78rem; color: var(--ink-2); }
.empty, .error, .note { background: var(--surface-1); border: 1px solid var(--line);
  border-radius: 10px; padding: 1.1rem; }
.error { border-left: 3px solid var(--s-critical); }
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
   clipping. */
@media print {
  body { background: #fff; color: #000; background-image: none; }
  main { max-width: none; padding: 0; }
  form.finder, .chips, .pulse, .theme, .theme-input { display: none; }
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


@lru_cache(maxsize=1)
def _rulebook() -> dict[str, RuleDoc]:
    """The catalogue keyed by rule id.

    Cached because building it parses the rule modules and the test suite, and
    the answer cannot change while the process is running.
    """
    return {doc.id: doc for doc in catalogue()}


@dataclass(frozen=True, slots=True, kw_only=True)
class Analysis:
    """Findings for one directory, plus which configs produced them."""

    findings: tuple[Finding, ...] = ()
    error: str | None = None
    fact_pack_id: str = ""
    digest: str = ""
    device_count: int = 0
    # Kept so the figures can be drawn from the same facts the findings came
    # from, rather than re-parsing and risking a picture of a different network.
    pack: StaticFactPack | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Filters:
    """The view's whole state: which severities and tiers to show.

    An empty set means "no filter on this dimension", not "show nothing" — a link
    with no filter in it has to keep meaning the full result.
    """

    severities: frozenset[Severity] = frozenset()
    tiers: frozenset[Tier] = frozenset()
    devices: frozenset[str] = frozenset()
    unknown: tuple[str, ...] = ()

    @property
    def active(self) -> bool:
        return bool(self.severities or self.tiers or self.devices)

    def matches(self, finding: Finding) -> bool:
        if self.severities and finding.severity not in self.severities:
            return False
        if self.devices and finding.device not in self.devices:
            return False
        return not (self.tiers and finding.tier not in self.tiers)


def analyse(config_dir: Path) -> Analysis:
    """Analyse a directory, keeping the fact pack's identity alongside the result."""
    if not config_dir.is_dir():
        return Analysis(error=f"not a directory: {config_dir}")
    pack, _ = build_fact_pack(config_dir)
    if not pack.devices:
        return Analysis(error=f"no .cfg files in {config_dir}")
    findings = rank(
        rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack)
    )
    return Analysis(
        findings=tuple(findings),
        fact_pack_id=pack.meta.fact_pack_id,
        digest=pack.meta.config_digest,
        device_count=pack.meta.device_count or len(pack.devices),
        pack=pack,
    )


def analyse_directory(config_dir: Path) -> tuple[list[Finding], str | None]:
    """Findings for a directory, or a message explaining why there are none."""
    result = analyse(config_dir)
    return list(result.findings), result.error


def _requested(
    params: dict[str, list[str]], name: str, *, fold: bool = True
) -> list[str]:
    """Filter values, repeated or comma-separated, de-duplicated in order.

    Severities and tiers come from a fixed lower-case vocabulary and are folded.
    Device names do not: they are hostnames the device chose, and folding one
    turns a filter for `AGG-A` into a filter that matches nothing.
    """
    values: list[str] = []
    for raw in params.get(name, []):
        for part in raw.split(","):
            token = part.strip().lower() if fold else part.strip()
            if token and token not in values:
                values.append(token)
    return values


def parse_filters(params: dict[str, list[str]]) -> Filters:
    """Read the filters out of a query string.

    A value naming no severity or tier is reported back rather than silently
    dropped: a filter that quietly does nothing looks exactly like a filter that
    found nothing, and the two deserve different reactions.
    """
    severities: list[Severity] = []
    tiers: list[Tier] = []
    unknown: list[str] = []
    # A device name is not drawn from a fixed vocabulary, so an unrecognised one
    # cannot be told from a typo here. It is reported by the page instead, which
    # knows which devices the pack actually holds.
    devices = _requested(params, "device", fold=False)
    for token in _requested(params, "severity"):
        try:
            severities.append(Severity(token))
        except ValueError:
            unknown.append(token)
    for token in _requested(params, "tier"):
        try:
            tiers.append(Tier(token))
        except ValueError:
            unknown.append(token)
    return Filters(
        severities=frozenset(severities),
        tiers=frozenset(tiers),
        devices=frozenset(devices),
        unknown=tuple(unknown),
    )


def _query_pairs(config_dir: str, filters: Filters) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if config_dir:
        pairs.append(("dir", config_dir))
    pairs.extend(
        ("severity", s.value) for s in _SEVERITY_ORDER if s in filters.severities
    )
    pairs.extend(("tier", t.value) for t in _TIER_ORDER if t in filters.tiers)
    pairs.extend(("device", device) for device in sorted(filters.devices))
    return pairs


def href(path: str, config_dir: str, filters: Filters) -> str:
    """An escaped link to `path` carrying the current view state."""
    query = urlencode(_query_pairs(config_dir, filters))
    return html.escape(f"{path}?{query}" if query else path)


def _toggle[T](values: frozenset[T], value: T) -> frozenset[T]:
    return values - {value} if value in values else values | {value}


def _chip(label: str, count: int, link: str, *, on: bool) -> str:
    return (
        f'<a class="chip{" on" if on else ""}" href="{link}">'
        f'{html.escape(label)} <span class="n">{count}</span></a>'
    )


def _filter_bar(
    config_dir: str, findings: tuple[Finding, ...], filters: Filters
) -> str:
    """Severity and tier chips, each a link that toggles one value.

    Counts are computed with the *other* dimension's filter already applied, so a
    chip promises the number of findings clicking it actually leaves on screen.
    """
    severities = [s for s in _SEVERITY_ORDER if any(f.severity is s for f in findings)]
    tiers = [t for t in _TIER_ORDER if any(f.tier is t for f in findings)]

    by_tier = [f for f in findings if not filters.tiers or f.tier in filters.tiers]
    severity_chips = [
        '<span class="label">severity</span>',
        _chip(
            "all",
            len(by_tier),
            href("/", config_dir, Filters(tiers=filters.tiers)),
            on=not filters.severities,
        ),
    ]
    severity_chips += [
        _chip(
            severity.value,
            sum(1 for f in by_tier if f.severity is severity),
            href(
                "/",
                config_dir,
                Filters(
                    severities=_toggle(filters.severities, severity),
                    tiers=filters.tiers,
                ),
            ),
            on=severity in filters.severities,
        )
        for severity in severities
    ]

    by_severity = [
        f
        for f in findings
        if not filters.severities or f.severity in filters.severities
    ]
    tier_chips = [
        '<span class="label">tier</span>',
        _chip(
            "all",
            len(by_severity),
            href("/", config_dir, Filters(severities=filters.severities)),
            on=not filters.tiers,
        ),
    ]
    tier_chips += [
        _chip(
            tier.value,
            sum(1 for f in by_severity if f.tier is tier),
            href(
                "/",
                config_dir,
                Filters(
                    severities=filters.severities,
                    tiers=_toggle(filters.tiers, tier),
                ),
            ),
            on=tier in filters.tiers,
        )
        for tier in tiers
    ]

    rows = [severity_chips, tier_chips]

    # Only when there is a choice to make. One device means the row would be a
    # label, an "all" chip and that device — three controls that do nothing.
    devices = sorted({f.device for f in findings})
    if len(devices) > 1:
        by_others = [
            f
            for f in findings
            if (not filters.tiers or f.tier in filters.tiers)
            and (not filters.severities or f.severity in filters.severities)
        ]
        device_chips = [
            '<span class="label">device</span>',
            _chip(
                "all",
                len(by_others),
                href(
                    "/",
                    config_dir,
                    Filters(severities=filters.severities, tiers=filters.tiers),
                ),
                on=not filters.devices,
            ),
        ]
        device_chips += [
            _chip(
                device,
                sum(1 for f in by_others if f.device == device),
                href(
                    "/",
                    config_dir,
                    Filters(
                        severities=filters.severities,
                        tiers=filters.tiers,
                        devices=_toggle(filters.devices, device),
                    ),
                ),
                on=device in filters.devices,
            )
            for device in devices
        ]
        rows.append(device_chips)

    return (
        '<div class="filters">'
        + "".join(f'<div class="chips">{"".join(row)}</div>' for row in rows)
        + "</div>"
    )


def _counts_html(visible: list[Finding], total: int) -> str:
    counts = Counter(finding.severity for finding in visible)
    cells = "".join(
        f'<div class="count"><b>{counts[s]}</b><span>{s.value}</span></div>'
        for s in _SEVERITY_ORDER
        if counts[s]
    )
    showing = (
        ""
        if len(visible) == total
        else f'<p class="showing">Showing {len(visible)} of {total} findings.</p>'
    )
    bar = visuals.sparkbar(
        {s.value: counts[s] for s in _SEVERITY_ORDER},
        {
            Severity.HIGH.value: "var(--s-critical)",
            Severity.MEDIUM.value: "var(--s-serious)",
            Severity.LOW.value: "var(--s-warning)",
            Severity.INFO.value: "var(--series-1)",
        },
    )
    ring = art.severity_ring(
        {s.value: counts[s] for s in _SEVERITY_ORDER if counts[s]},
        {
            Severity.HIGH.value: "var(--s-critical)",
            Severity.MEDIUM.value: "var(--s-serious)",
            Severity.LOW.value: "var(--s-warning)",
            Severity.INFO.value: "var(--series-1)",
        },
    )
    return (
        f'<div class="summary">{ring}'
        f'<div class="totals">{showing}<div class="counts">{cells}</div>{bar}</div>'
        "</div>"
    )


def _finding_html(finding: Finding, figure: str = "") -> str:
    parts = [
        f'<article class="finding {html.escape(finding.severity.value)}">',
        f"<h2>{html.escape(finding.title)}</h2>",
        f'<p class="meta"><span class="mono">{html.escape(finding.device)}</span>'
        f'<span class="sev {html.escape(finding.severity.value)}">'
        f"{html.escape(finding.severity.value)}</span>"
        f"<span>{html.escape(finding.tier.value)} tier</span>"
        f'<a class="mono rule-link" href="#rule-{html.escape(finding.rule)}">'
        f"{html.escape(finding.rule)}</a>"
        + (
            ' <span class="tag">model-derived</span>'
            if finding.tier is Tier.TIMING
            else ""
        )
        + "</p>",
        f'<p class="detail">{html.escape(finding.detail)}</p>',
    ]
    if finding.trigger:
        parts.append(
            f'<div class="trigger">trigger: {html.escape(finding.trigger)}</div>'
        )
    if finding.remedy:
        parts.append(f'<div class="remedy">fix: {html.escape(finding.remedy)}</div>')
    if figure:
        parts.append(
            '<div class="figure"><h2>gateway ownership over time</h2>'
            '<p class="cap">The model advanced through this trigger. Each band is '
            "the device holding that group; a split is where two groups sit on "
            "different devices.</p>" + figure + "</div>"
        )
    if finding.evidence:
        items = "".join(f"<li>{html.escape(item)}</li>" for item in finding.evidence)
        parts.append(f"<details><summary>evidence</summary><ul>{items}</ul></details>")
    parts.append("</article>")
    return "".join(parts)


def _by_device(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    """Group in rank order, so devices arrive worst-first and so do their findings."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.device, []).append(finding)
    return list(grouped.items())


def _device_html(
    device: str, findings: list[Finding], pack: StaticFactPack | None = None
) -> str:
    """One device's findings.

    The first timing finding on a device carries the timeline figure. Drawing it
    on every one would repeat the same picture three times, since they all come
    from the same simulated sequence.
    """
    plural = "" if len(findings) == 1 else "s"
    cards: list[str] = []
    drawn = False
    for index, finding in enumerate(findings):
        figure = ""
        if pack is not None and not drawn and finding.tier is Tier.TIMING:
            figure = visuals.timeline_svg(pack, finding)
            drawn = bool(figure)
        cards.append(
            _finding_html(finding, figure).replace(
                '<article class="finding',
                f'<article style="--i:{index}" class="finding',
                1,
            )
        )
    return (
        '<details class="device-group" open>'
        f"<summary>{html.escape(device)}"
        f'<span class="n">{len(findings)} finding{plural}</span></summary>'
        + "".join(cards)
        + "</details>"
    )


def _rule_entry(doc: RuleDoc) -> str:
    """One rule, opened by clicking its identifier in a finding."""
    # Plain sections rather than <details>: whether a closed <details> opens
    # when a link targets it is browser-dependent, and a link that lands on a
    # collapsed box has failed. Only the rules that fired are listed, so the
    # panel stays short enough to leave open.
    parts = [
        f'<article class="rule" id="rule-{html.escape(doc.id)}">',
        f'<h3><span class="mono">{html.escape(doc.id)}</span>'
        f'<span class="sev {html.escape(doc.severity.value)}">'
        f"{html.escape(doc.severity.value)}</span>"
        f'<span class="tag">{html.escape(doc.tier.value)}</span></h3>',
    ]
    if doc.summary is None:
        # Said out loud rather than papered over. An entry that reads
        # "undocumented" is a defect anyone can see, which is the point.
        parts.append(
            '<p class="undocumented">This rule ships with no explanation of '
            "itself. What it reports is below; why it matters is not written "
            "down anywhere yet.</p>"
        )
    for paragraph in (doc.summary, *doc.checks):
        if paragraph:
            parts.append(f"<p>{html.escape(paragraph)}</p>")
    if doc.reports:
        # The message template, with {…} where a value is filled in. It is what
        # someone matches against when they see a finding and want to know which
        # rule wrote it.
        parts.append(f'<div class="trigger">reports: {html.escape(doc.reports)}</div>')
    if doc.remedy:
        parts.append(f'<div class="remedy">fix: {html.escape(doc.remedy)}</div>')
    if doc.silence:
        # The half of a rule a clean run depends on: a check that never fires is
        # indistinguishable from a check that found nothing until you know what
        # it declines to look at.
        notes = "".join(
            f"<li>{html.escape(note.note)}"
            f'<span class="src mono">{html.escape(note.source)}</span></li>'
            for note in doc.silence
        )
        parts.append(f'<p class="cap">Stays silent when:</p><ul>{notes}</ul>')
    else:
        parts.append(
            '<p class="cap">No test asserts that this rule stays quiet, so its '
            "silence is not evidence of anything.</p>"
        )
    parts.append(
        f'<p class="cap mono">{html.escape(doc.module)}.'
        f"{html.escape(doc.function)}</p></article>"
    )
    return "".join(parts)


def _rulebook_html(findings: list[Finding]) -> str:
    """What each rule on screen actually checks, and when it declines to fire.

    Only the rules that fired are listed. The full catalogue is a document; this
    is the footnote to the page someone is reading, and twenty-five entries under
    four findings would bury it.
    """
    book = _rulebook()
    seen: list[RuleDoc] = []
    for finding in findings:
        doc = book.get(finding.rule)
        if doc is not None and doc not in seen:
            seen.append(doc)
    if not seen:
        return ""
    plural = "" if len(seen) == 1 else "s"
    return (
        '<section class="rulebook"><h2>The rule{}</h2>'
        '<p class="cap">Each identifier above links here. Generated from the '
        "rules themselves, so it cannot describe a check the tool no longer "
        "makes.</p>{}</section>"
    ).format(plural, "".join(_rule_entry(doc) for doc in seen))


def _hidden_filters(filters: Filters) -> str:
    """Keep the active filters when the directory form is submitted."""
    return "".join(
        f'<input type="hidden" name="{name}" value="{html.escape(value)}">'
        for name, value in _query_pairs("", filters)
    )


def page(config_dir: str, analysis: Analysis, filters: Filters) -> str:
    visible = [finding for finding in analysis.findings if filters.matches(finding)]
    sections: list[str] = []

    if filters.unknown:
        ignored = ", ".join(
            f"<code>{html.escape(value)}</code>" for value in filters.unknown
        )
        sections.append(
            f'<p class="note">Ignored filter values that name no severity or tier: '
            f"{ignored}.</p>"
        )

    # A device name is free text, so a filter for one that is not in the pack has
    # to be reported here rather than at parse time. Silently showing nothing
    # looks identical to a device that is genuinely clean.
    known = {finding.device for finding in analysis.findings}
    if analysis.pack is not None:
        known |= {device.id for device in analysis.pack.devices}
    absent = sorted(device for device in filters.devices if device not in known)
    if absent:
        named = ", ".join(f"<code>{html.escape(device)}</code>" for device in absent)
        sections.append(
            f'<p class="note">No device here is called {named}. '
            "Names come from each config's own hostname line.</p>"
        )

    if analysis.error:
        sections.append(f'<div class="error">{html.escape(analysis.error)}</div>')
    elif not config_dir:
        sections.append(
            '<div class="empty landing">'
            "<p><strong>Enter a directory of device configs</strong> "
            "(<code>.cfg</code> files) to analyse. Nothing leaves this machine "
            "and nothing is written to the directory.</p>"
            f"{art.hero_svg()}"
            '<p class="cap">Illustration, not a result. Two gateway groups '
            "follow the same link failure at different speeds — one preempts "
            "back early, the other waits out a delay — and the hatched window "
            "is the stretch where they sit on different devices. Steady-state "
            "analysis never sees it, because at rest the configuration is "
            "correct.</p></div>"
        )
    elif not analysis.findings:
        sections.append(
            '<div class="empty"><strong>No findings.</strong><br>Nothing in these '
            "configs trips a consistency rule, and no event sequence the timing "
            "model explored produced a sustained divergence."
            '<p class="cap">That is not proof the network is sound. The timing '
            "tier searches a neighbourhood of sequences derived from the timers "
            "it found, not the whole space, and it only models what the parsers "
            "understood.</p></div>"
        )
    else:
        sections.append(_filter_bar(config_dir, analysis.findings, filters))
        if visible:
            sections.append(_counts_html(visible, len(analysis.findings)))
            sections.extend(
                _device_html(device, group, analysis.pack)
                for device, group in _by_device(visible)
            )
        else:
            clear = href("/", config_dir, Filters())
            sections.append(
                '<div class="empty">No findings match these filters. '
                f'<a href="{clear}">Show all {len(analysis.findings)}</a>.</div>'
            )

    if visible:
        sections.append(_rulebook_html(visible))

    if any(finding.tier is Tier.TIMING for finding in visible):
        sections.append(f'<p class="caveat">{_TIMING_CAVEAT}</p>')

    if analysis.digest:
        devices = f"{analysis.device_count} device"
        devices += "" if analysis.device_count == 1 else "s"
        sections.append(
            '<p class="provenance">'
            f"fact pack <code>{html.escape(analysis.fact_pack_id)}</code> · "
            f"{devices} · digest <code>{html.escape(analysis.digest[:12])}</code> · "
            f'<a href="{href("/findings.json", config_dir, filters)}">'
            "findings.json</a> · "
            '<a href="/rules.json">rules.json</a></p>'
        )

    worst = min(
        (f.severity for f in visible),
        key=lambda s: list(Severity).index(s),
        default=None,
    )
    pulse = "pulse alert" if worst is Severity.HIGH else "pulse"
    topology = ""
    if analysis.pack is not None:
        with_findings = {f.device for f in analysis.findings}
        drawn = visuals.topology_svg(
            analysis.pack,
            lambda device: (
                href(
                    "/",
                    config_dir,
                    Filters(
                        severities=filters.severities,
                        tiers=filters.tiers,
                        devices=_toggle(filters.devices, device),
                    ),
                )
                if device in with_findings
                else ""
            ),
        )
        if drawn:
            topology = (
                '<div class="figure"><h2>adjacency</h2>'
                '<p class="cap">Devices, and the subnets they share. A device '
                "with findings is a link to them.</p>"
                f"{drawn}</div>"
            )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cassandra</title><style>{_STYLE}</style></head>
<body><main>
<header class="masthead">
  <input class="theme-input" type="checkbox" id="theme-toggle">
  <label class="theme" for="theme-toggle" title="switch between light and dark">
    <span class="moon" aria-hidden="true">&#9789;</span>
    <span class="sun" aria-hidden="true">&#9788;</span>
    <span class="visually-hidden">switch between light and dark</span>
  </label>
  <h1 class="wordmark">{art.mark_svg()}<span class="{pulse}"></span>Cassandra</h1>
  <p class="tagline">Latent failure modes in network configuration &mdash; the ones
  that only exist between events.</p>
</header>
<form class="finder" method="get" action="/">
  <input type="text" name="dir" placeholder="/path/to/configs"
         value="{html.escape(config_dir)}" autofocus accesskey="d"
         aria-label="directory of device configs to analyse"
         spellcheck="false" autocapitalize="off" autocorrect="off">
  {_hidden_filters(filters)}
  <button class="go" type="submit">Analyse</button>
</form>
{topology}
{"".join(sections)}
</main></body></html>"""


def as_json(findings: list[Finding]) -> str:
    return json.dumps(
        [
            {
                "rule": finding.rule,
                "tier": finding.tier.value,
                "severity": finding.severity.value,
                "device": finding.device,
                "title": finding.title,
                "detail": finding.detail,
                "trigger": finding.trigger,
                "remedy": finding.remedy,
                "evidence": list(finding.evidence),
            }
            for finding in findings
        ],
        indent=2,
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "cassandra"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        config_dir = (params.get("dir") or [""])[0].strip()
        filters = parse_filters(params)

        analysis = Analysis()
        if config_dir:
            try:
                analysis = analyse(Path(config_dir).expanduser())
            except OSError as exc:
                analysis = Analysis(error=f"could not read {config_dir}: {exc}")

        if parsed.path == "/rules.json":
            self._respond(
                json.dumps([asdict(doc) for doc in catalogue()], indent=2),
                "application/json",
            )
            return

        if parsed.path == "/findings.json":
            visible = [f for f in analysis.findings if filters.matches(f)]
            self._respond(as_json(visible), "application/json")
            return

        if parsed.path != "/":
            self._respond("not found", "text/plain", status=404)
            return

        self._respond(page(config_dir, analysis, filters), "text/html; charset=utf-8")

    def _respond(self, body: str, content_type: str, *, status: int = 200) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: object) -> None:
        """Quiet by default; a local tool should not narrate every request."""


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"cassandra: http://{host}:{port}  (ctrl-c to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
