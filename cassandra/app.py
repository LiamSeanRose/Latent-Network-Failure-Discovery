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

import traceback
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from cassandra import report
from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack
from cassandra.facts import rules
from cassandra.findings import Finding, locate, rank
from cassandra.timing import sequences, timer_rules
from cassandra.view import (
    Comparison,
    Filters,
    as_json,
    compare_with,
    facts_page,
    page,
    parse_filters,
    rules_json,
    rules_page,
)

# Re-exported because this module is where the rest of the program asks for the
# view. Splitting the rendering out was a change of file, not of interface.
__all__ = [
    "Analysis",
    "Comparison",
    "Filters",
    "Handler",
    "analyse",
    "analyse_directory",
    "as_json",
    "compare_with",
    "facts_page",
    "page",
    "parse_filters",
    "rules_json",
    "rules_page",
    "serve",
]


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
    # Lines the parsers did not understand, per device. Carried because a result
    # is only as complete as the reading that produced it, and a page that shows
    # findings without showing what it failed to read is overstating itself.
    unparsed: tuple[tuple[str, int], ...] = ()


def analyse(config_dir: Path) -> Analysis:
    """Analyse a directory, keeping the fact pack's identity alongside the result."""
    if not config_dir.is_dir():
        return Analysis(error=f"not a directory: {config_dir}")
    pack, unparsed = build_fact_pack(config_dir)
    if not pack.devices:
        # Not "no .cfg files". Discovery takes several extensions and settles
        # the ambiguous ones by reading them, so naming one turns away the
        # person whose backups are .conf — whose files would have worked.
        return Analysis(error=f"nothing in {config_dir} reads like a device config")
    findings = rank(
        locate(
            rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack),
            pack,
        )
    )
    return Analysis(
        findings=tuple(findings),
        fact_pack_id=pack.meta.fact_pack_id,
        digest=pack.meta.config_digest,
        device_count=pack.meta.device_count or len(pack.devices),
        pack=pack,
        unparsed=tuple(
            (device, len(lines)) for device, lines in sorted(unparsed.items()) if lines
        ),
    )


def analyse_directory(config_dir: Path) -> tuple[list[Finding], str | None]:
    """Findings for a directory, or a message explaining why there are none."""
    result = analyse(config_dir)
    return list(result.findings), result.error


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
            except Exception as exc:
                # A rule or a parser raised. That is a bug in this tool, not in
                # the configs, and the page has to say so rather than returning
                # a blank 500 that looks like the configs are unreadable. The
                # traceback still goes to stderr, where a bug report can find it.
                traceback.print_exc()
                analysis = Analysis(
                    error=(
                        f"{type(exc).__name__} while analysing {config_dir}. "
                        "This is a defect in the tool, not in your configs — the "
                        "traceback is on the terminal running `cassandra serve`."
                    )
                )

        comparison = compare_with(analysis, filters.since)

        if parsed.path == "/report.html":
            # Imported here rather than at module scope: report_html imports
            # this module for the renderer, and one of the two has to be late.
            from cassandra.report_html import render

            self._respond(
                render(analysis, Path(config_dir)),
                "text/html; charset=utf-8",
                filename="cassandra-report.html",
            )
            return

        if parsed.path == "/facts":
            self._respond(
                facts_page(
                    analysis.pack, analysis.unparsed, config_dir, analysis.error
                ),
                "text/html; charset=utf-8",
            )
            return

        if parsed.path == "/rules":
            # With a directory, the catalogue also says which checks had
            # nothing in those configs to look at.
            self._respond(
                rules_page(analysis.pack, config_dir),
                "text/html; charset=utf-8",
            )
            return

        if parsed.path == "/rules.json":
            self._respond(rules_json(), "application/json")
            return

        if parsed.path == "/findings.json":
            visible = [f for f in analysis.findings if filters.matches(f)]
            self._respond(
                report.as_json(
                    visible,
                    pack_id=analysis.fact_pack_id,
                    digest=analysis.digest,
                ),
                "application/json",
            )
            return

        if parsed.path != "/":
            self._respond("not found", "text/plain", status=404)
            return

        self._respond(
            page(config_dir, analysis, filters, comparison),
            "text/html; charset=utf-8",
        )

    def _respond(
        self,
        body: str,
        content_type: str,
        *,
        status: int = 200,
        filename: str | None = None,
    ) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        if filename is not None:
            self.send_header(
                "Content-Disposition", f'attachment; filename="{filename}"'
            )
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: object) -> None:
        """Quiet by default; a local tool should not narrate every request."""


def serve(
    host: str = "127.0.0.1", port: int = 8765, config_dir: Path | None = None
) -> None:
    try:
        server = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        # Almost always a second copy already running. Saying which port, and
        # what to do about it, beats a traceback for a condition this ordinary.
        raise SystemExit(
            f"cannot listen on {host}:{port}: {exc}\n"
            f"another copy may already be running — try --port {port + 1}"
        ) from exc
    # A directory given on the command line becomes the link that is printed,
    # rather than something to paste into the page. It is a query string like
    # any other, so the running server needs to know nothing about it.
    query = f"/?{urlencode({'dir': str(config_dir)})}" if config_dir else ""
    print(f"cassandra: http://{host}:{port}{query}  (ctrl-c to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
