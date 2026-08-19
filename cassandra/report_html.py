"""Write the web view to a single file you can send someone.

The view is already self-contained — inline styles, inline SVG, no scripts — so a
shareable report is the same renderer pointed at a file instead of a socket.
Keeping one renderer means the report cannot drift from what the app shows, which
is the usual failure of a separate export path.
"""

from __future__ import annotations

import re
from pathlib import Path

from cassandra.app import Analysis, Filters, page


def write(analysis: Analysis, config_dir: Path, destination: Path) -> Path:
    """Render an analysis to a standalone HTML file and return the path."""
    html = page(str(config_dir), analysis, Filters())
    # Remove the search form outright rather than commenting it out. It posts to
    # a server a reader of the file does not have, and a commented-out control
    # still ships its markup for anyone reading the source.
    html = re.sub(r'<form class="finder".*?</form>', "", html, flags=re.S)
    destination.write_text(html, encoding="utf-8")
    return destination
