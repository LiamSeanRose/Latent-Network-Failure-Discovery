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
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final
from urllib.parse import parse_qs, urlencode, urlparse

from cassandra.factpack.builders import build_fact_pack
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

_STYLE: Final = """
:root {
  color-scheme: light dark;
  --bg: #fbfbfa; --fg: #1a1a19; --muted: #6b6b68; --line: #e3e3e0;
  --card: #ffffff; --high: #b3261e; --medium: #8a5a00; --low: #3d5a80;
  --accent: #2f5d50; --on-bg: #2f5d50; --on-fg: #ffffff;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161614; --fg: #ece9e4; --muted: #9a978f; --line: #2e2c28;
    --card: #1e1c1a; --high: #f2857a; --medium: #e0b062; --low: #8fb4d9;
    --accent: #7fc4ad; --on-bg: #7fc4ad; --on-fg: #14201c;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.25rem; background: var(--bg); color: var(--fg);
  font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 62rem; margin: 0 auto; }
h1 { font-size: 1.35rem; margin: 0 0 .25rem; letter-spacing: -0.01em; }
.sub { color: var(--muted); margin: 0 0 1.75rem; }
a { color: var(--accent); }
form { display: flex; gap: .5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
input[type=text] {
  flex: 1 1 22rem; padding: .6rem .7rem; border: 1px solid var(--line);
  border-radius: 6px; background: var(--card); color: var(--fg); font: inherit;
}
button {
  padding: .6rem 1.1rem; border: 0; border-radius: 6px; background: var(--accent);
  color: var(--on-fg); font: inherit; font-weight: 600; cursor: pointer;
}
.filters { margin: 0 0 1.25rem; }
.chips { display: flex; flex-wrap: wrap; gap: .4rem; align-items: center;
  margin-bottom: .4rem; }
.chips .label {
  color: var(--muted); font-size: .74rem; text-transform: uppercase;
  letter-spacing: .05em; min-width: 4.5rem;
}
.chip {
  display: inline-flex; gap: .4rem; align-items: baseline; padding: .3rem .7rem;
  border: 1px solid var(--line); border-radius: 999px; background: var(--card);
  color: var(--fg); text-decoration: none; font-size: .84rem;
}
.chip:hover { border-color: var(--accent); }
.chip .n { color: var(--muted); font-variant-numeric: tabular-nums; }
.chip.on {
  background: var(--on-bg); border-color: var(--on-bg); color: var(--on-fg);
  font-weight: 600;
}
.chip.on .n { color: inherit; opacity: .8; }
.showing, .note { color: var(--muted); font-size: .84rem; margin: .6rem 0 1rem; }
.counts {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(7rem, 1fr));
  gap: .75rem 1.25rem; margin-bottom: 1.5rem;
}
.count b { font-size: 1.5rem; font-weight: 650; display: block; }
.count span { color: var(--muted); font-size: .82rem; text-transform: uppercase;
  letter-spacing: .04em; }
details.device { margin: 0 0 1.1rem; border-top: 1px solid var(--line); }
details.device > summary {
  display: flex; gap: .5rem; align-items: baseline; list-style: none;
  cursor: pointer; padding: .65rem .1rem; color: var(--fg); font-size: .95rem;
  font-weight: 650;
}
details.device > summary::-webkit-details-marker { display: none; }
details.device > summary::before { content: "▾"; color: var(--muted);
  font-size: .75rem; }
details.device:not([open]) > summary::before { content: "▸"; }
details.device > summary .n { color: var(--muted); font-weight: 400;
  font-size: .84rem; }
.finding {
  background: var(--card); border: 1px solid var(--line); border-left: 3px solid;
  border-radius: 6px; padding: .9rem 1rem; margin-bottom: .7rem;
}
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low, .finding.info { border-left-color: var(--low); }
.finding h2 { font-size: 1rem; margin: 0 0 .3rem; font-weight: 600; }
.meta { color: var(--muted); font-size: .82rem; margin-bottom: .5rem; }
.tag {
  display: inline-block; border: 1px solid var(--line); border-radius: 999px;
  padding: 0 .45rem; font-size: .76rem;
}
.detail { margin: 0 0 .6rem; }
.trigger, .remedy {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem;
  background: var(--bg); border: 1px solid var(--line); border-radius: 4px;
  padding: .35rem .5rem; margin-bottom: .4rem; overflow-x: auto;
}
details summary { cursor: pointer; color: var(--muted); font-size: .85rem; }
details ul { margin: .5rem 0 0; padding-left: 1.1rem; font-family: ui-monospace,
  SFMono-Regular, Menlo, monospace; font-size: .8rem; color: var(--muted); }
.empty, .error {
  background: var(--card); border: 1px solid var(--line); border-radius: 6px;
  padding: 1.25rem;
}
.error { border-left: 3px solid var(--high); }
.caveat { color: var(--muted); font-size: .85rem; margin-top: 2rem;
  border-top: 1px solid var(--line); padding-top: 1rem; }
.provenance { color: var(--muted); font-size: .78rem; margin-top: 1.25rem; }
.provenance code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
@media (max-width: 700px) {
  body { padding: 1.25rem .85rem; }
  main { max-width: none; }
  form { flex-direction: column; align-items: stretch; }
  input[type=text] { flex: 0 0 auto; width: 100%; }
  button { width: 100%; }
  .counts { grid-template-columns: 1fr; gap: .3rem; }
  .count { display: flex; align-items: baseline; gap: .5rem; }
  .count b { font-size: 1.15rem; display: inline; }
  .chips .label { min-width: 100%; }
}
"""


@dataclass(frozen=True, slots=True, kw_only=True)
class Analysis:
    """Findings for one directory, plus which configs produced them."""

    findings: tuple[Finding, ...] = ()
    error: str | None = None
    fact_pack_id: str = ""
    digest: str = ""
    device_count: int = 0


@dataclass(frozen=True, slots=True, kw_only=True)
class Filters:
    """The view's whole state: which severities and tiers to show.

    An empty set means "no filter on this dimension", not "show nothing" — a link
    with no filter in it has to keep meaning the full result.
    """

    severities: frozenset[Severity] = frozenset()
    tiers: frozenset[Tier] = frozenset()
    unknown: tuple[str, ...] = ()

    @property
    def active(self) -> bool:
        return bool(self.severities or self.tiers)

    def matches(self, finding: Finding) -> bool:
        if self.severities and finding.severity not in self.severities:
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
    )


def analyse_directory(config_dir: Path) -> tuple[list[Finding], str | None]:
    """Findings for a directory, or a message explaining why there are none."""
    result = analyse(config_dir)
    return list(result.findings), result.error


def _requested(params: dict[str, list[str]], name: str) -> list[str]:
    """Filter values, repeated or comma-separated, de-duplicated in order."""
    values: list[str] = []
    for raw in params.get(name, []):
        for part in raw.split(","):
            token = part.strip().lower()
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

    return (
        '<div class="filters">'
        f'<div class="chips">{"".join(severity_chips)}</div>'
        f'<div class="chips">{"".join(tier_chips)}</div>'
        "</div>"
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
    return f'{showing}<div class="counts">{cells}</div>'


def _finding_html(finding: Finding) -> str:
    parts = [
        f'<article class="finding {html.escape(finding.severity.value)}">',
        f"<h2>{html.escape(finding.title)}</h2>",
        f'<p class="meta">{html.escape(finding.device)} · '
        f"{html.escape(finding.severity.value)} · "
        f"{html.escape(finding.tier.value)} tier · "
        f"{html.escape(finding.rule)}"
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


def _device_html(device: str, findings: list[Finding]) -> str:
    plural = "" if len(findings) == 1 else "s"
    return (
        '<details class="device" open>'
        f"<summary>{html.escape(device)}"
        f'<span class="n">{len(findings)} finding{plural}</span></summary>'
        + "".join(_finding_html(finding) for finding in findings)
        + "</details>"
    )


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

    if analysis.error:
        sections.append(f'<div class="error">{html.escape(analysis.error)}</div>')
    elif not config_dir:
        sections.append(
            '<div class="empty">Enter a directory of device configs '
            "(<code>.cfg</code> files) to analyse.</div>"
        )
    elif not analysis.findings:
        sections.append(
            '<div class="empty">No findings. Nothing in these configs trips a '
            "consistency rule, and no event sequence the timing model explored "
            "produced a sustained divergence.</div>"
        )
    else:
        sections.append(_filter_bar(config_dir, analysis.findings, filters))
        if visible:
            sections.append(_counts_html(visible, len(analysis.findings)))
            sections.extend(
                _device_html(device, group) for device, group in _by_device(visible)
            )
        else:
            clear = href("/", config_dir, Filters())
            sections.append(
                '<div class="empty">No findings match these filters. '
                f'<a href="{clear}">Show all {len(analysis.findings)}</a>.</div>'
            )

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
            "findings.json</a></p>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cassandra</title><style>{_STYLE}</style></head>
<body><main>
<h1>Cassandra</h1>
<p class="sub">Latent failure modes in network configuration.</p>
<form method="get" action="/">
  <input type="text" name="dir" placeholder="/path/to/configs"
         value="{html.escape(config_dir)}" autofocus>
  {_hidden_filters(filters)}
  <button type="submit">Analyse</button>
</form>
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
