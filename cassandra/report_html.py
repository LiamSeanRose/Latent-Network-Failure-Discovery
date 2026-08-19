"""Write the web view to a single file you can send someone.

The view is already self-contained — inline styles, inline SVG, no scripts — so a
shareable report is the same renderer pointed at a file instead of a socket.
Keeping one renderer means the report cannot drift from what the app shows, which
is the usual failure of a separate export path.
"""

from __future__ import annotations

import re
from pathlib import Path

from cassandra.app import Analysis, Comparison, Filters, page
from cassandra.view import facts_cards


def render(
    analysis: Analysis, config_dir: Path, comparison: Comparison | None = None
) -> str:
    """The standalone page, as a string."""
    since = "" if comparison is None else comparison.path
    # Everything, not the page's first two hundred. The cap exists because a
    # served page can offer to render the rest; a file cannot, and a link
    # inviting the reader to click for the remainder is a dead end in one.
    html = page(
        str(config_dir),
        analysis,
        Filters(since=since, show_all=True),
        comparison,
    )
    # Remove the search form outright rather than commenting it out. It posts to
    # a server a reader of the file does not have, and a commented-out control
    # still ships its markup for anyone reading the source.
    html = re.sub(r'<form class="finder".*?</form>', "", html, flags=re.S)
    # The filter bar goes with it. Every chip is a link to a query this file
    # cannot answer, and the counts they carry are already in the summary below.
    html = re.sub(r'<div class="filters">.*?</div>\s*</div>', "", html, flags=re.S)
    html = html.replace("</main>", _what_was_read(analysis) + "</main>", 1)
    # Then every remaining link to the server itself. A dead link in a file
    # someone was sent reads as the file being broken, and naming the routes one
    # at a time meant each new one had to remember to come here. In-page anchors
    # start with "#" and are untouched.
    html = re.sub(r'<a [^>]*href="/[^"]*"[^>]*>[^<]*</a>\s*(·\s*)?', "", html)
    # The map's nodes are links wrapping markup rather than text, so they need
    # unwrapping rather than deleting — the node still has to be drawn.
    html = re.sub(
        r'<a href="/[^"]*" class="node-link">(.*?)</a>',
        r"\1",
        html,
        flags=re.S,
    )
    # And the separator left dangling where the last link on a line used to be.
    return re.sub(r"\s*·\s*</p>", "</p>", html)


def _what_was_read(analysis: Analysis) -> str:
    """The fact pack the findings rest on, folded into the file.

    A report is the copy that travels, and its reader is the one least able to
    go and check the configs it was made from — they may not have them. Folded
    rather than shown, because it is the appendix to the findings and not the
    point of the document.
    """
    if analysis.pack is None:
        return ""
    devices = len(analysis.pack.devices)
    return (
        '<section class="rulebook"><details class="read-appendix">'
        f"<summary>What the tool read from {devices} device"
        f"{'' if devices == 1 else 's'}</summary>"
        '<p class="cap">A finding is only as good as the reading under it. '
        "This is that reading, as it stood when this file was written.</p>"
        + facts_cards(analysis.pack, analysis.unparsed)
        + "</details></section>"
    )


def write(
    analysis: Analysis,
    config_dir: Path,
    destination: Path,
    comparison: Comparison | None = None,
) -> Path:
    """Render an analysis to a standalone HTML file and return the path."""
    destination.write_text(render(analysis, config_dir, comparison), encoding="utf-8")
    return destination
