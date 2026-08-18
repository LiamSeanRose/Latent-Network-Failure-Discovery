"""A local web view over the same engine the CLI uses.

Standard library only, on purpose: the whole premise of v3 is that installing this
tool is the entire setup, and a UI that drags in a web framework and a build step
walks that back.

Binds to loopback. It reads config files from a directory the user names, which is
the tool's job, but that is not something to expose on a network interface.
"""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final
from urllib.parse import parse_qs, urlparse

from cassandra.factpack.builders import build_fact_pack
from cassandra.facts import rules
from cassandra.findings import Finding, Severity, Tier, rank
from cassandra.timing import sequences

_SEVERITY_ORDER: Final = (
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_STYLE: Final = """
:root {
  color-scheme: light dark;
  --bg: #fbfbfa; --fg: #1a1a19; --muted: #6b6b68; --line: #e3e3e0;
  --card: #ffffff; --high: #b3261e; --medium: #8a5a00; --low: #3d5a80;
  --accent: #2f5d50;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161614; --fg: #ece9e4; --muted: #9a978f; --line: #2e2c28;
    --card: #1e1c1a; --high: #f2857a; --medium: #e0b062; --low: #8fb4d9;
    --accent: #7fc4ad;
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
form { display: flex; gap: .5rem; margin-bottom: 1.75rem; flex-wrap: wrap; }
input[type=text] {
  flex: 1 1 22rem; padding: .6rem .7rem; border: 1px solid var(--line);
  border-radius: 6px; background: var(--card); color: var(--fg); font: inherit;
}
button {
  padding: .6rem 1.1rem; border: 0; border-radius: 6px; background: var(--accent);
  color: #fff; font: inherit; font-weight: 600; cursor: pointer;
}
.counts { display: flex; gap: 1.25rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
.count b { font-size: 1.5rem; font-weight: 650; display: block; }
.count span { color: var(--muted); font-size: .82rem; text-transform: uppercase;
  letter-spacing: .04em; }
.finding {
  background: var(--card); border: 1px solid var(--line); border-left: 3px solid;
  border-radius: 6px; padding: .9rem 1rem; margin-bottom: .7rem;
}
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low, .finding.info { border-left-color: var(--low); }
.finding h2 { font-size: 1rem; margin: 0 0 .3rem; font-weight: 600; }
.meta { color: var(--muted); font-size: .82rem; margin-bottom: .5rem; }
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
"""


def analyse_directory(config_dir: Path) -> tuple[list[Finding], str | None]:
    """Findings for a directory, or a message explaining why there are none."""
    if not config_dir.is_dir():
        return [], f"not a directory: {config_dir}"
    pack, _ = build_fact_pack(config_dir)
    if not pack.devices:
        return [], f"no .cfg files in {config_dir}"
    return rank(rules.evaluate(pack) + sequences.analyse(pack)), None


def _finding_html(finding: Finding) -> str:
    parts = [
        f'<article class="finding {html.escape(finding.severity.value)}">',
        f"<h2>{html.escape(finding.title)}</h2>",
        f'<p class="meta">{html.escape(finding.device)} · '
        f"{html.escape(finding.severity.value)} · "
        f"{html.escape(finding.tier.value)} tier · "
        f"{html.escape(finding.rule)}</p>",
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


def page(config_dir: str, findings: list[Finding], error: str | None) -> str:
    counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1

    if error:
        body = f'<div class="error">{html.escape(error)}</div>'
    elif not config_dir:
        body = (
            '<div class="empty">Enter a directory of device configs '
            "(<code>.cfg</code> files) to analyse.</div>"
        )
    elif not findings:
        body = (
            '<div class="empty">No findings. Nothing in these configs trips a '
            "consistency rule, and no event sequence the timing model explored "
            "produced a sustained divergence.</div>"
        )
    else:
        summary = "".join(
            f'<div class="count"><b>{counts[s]}</b><span>{s.value}</span></div>'
            for s in _SEVERITY_ORDER
            if counts[s]
        )
        body = f'<div class="counts">{summary}</div>' + "".join(
            _finding_html(f) for f in findings
        )

    timing = any(f.tier is Tier.TIMING for f in findings)
    caveat = (
        '<p class="caveat">Timing findings come from a model of timer interaction, '
        "not from running the protocols. They tell you a sequence your configuration "
        "permits — each one shows the sequence, so you can judge it.</p>"
        if timing
        else ""
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
  <button type="submit">Analyse</button>
</form>
{body}{caveat}
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "cassandra"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        config_dir = (params.get("dir") or [""])[0].strip()

        findings: list[Finding] = []
        error: str | None = None
        if config_dir:
            try:
                findings, error = analyse_directory(Path(config_dir).expanduser())
            except OSError as exc:
                error = f"could not read {config_dir}: {exc}"

        if parsed.path == "/findings.json":
            payload = json.dumps(
                [
                    {
                        "rule": f.rule,
                        "tier": f.tier.value,
                        "severity": f.severity.value,
                        "device": f.device,
                        "title": f.title,
                        "detail": f.detail,
                        "trigger": f.trigger,
                        "remedy": f.remedy,
                        "evidence": list(f.evidence),
                    }
                    for f in findings
                ],
                indent=2,
            )
            self._respond(payload, "application/json")
            return

        if parsed.path != "/":
            self._respond("not found", "text/plain", status=404)
            return

        self._respond(page(config_dir, findings, error), "text/html; charset=utf-8")

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
