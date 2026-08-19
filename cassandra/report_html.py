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
    # Same for the links to endpoints only the server has. A dead link in a file
    # someone was sent reads as the file being broken.
    return re.sub(r'<a href="/rules(\.json)?">[^<]*</a>\s*(·\s*)?', "", html)


def write(
    analysis: Analysis,
    config_dir: Path,
    destination: Path,
    comparison: Comparison | None = None,
) -> Path:
    """Render an analysis to a standalone HTML file and return the path."""
    destination.write_text(render(analysis, config_dir, comparison), encoding="utf-8")
    return destination
