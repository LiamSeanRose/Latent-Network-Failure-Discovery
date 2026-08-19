"""The standalone HTML report.

One renderer serves both the app and the file, so the test that matters is that
the file is genuinely standalone: a reader who opens it offline, with no server
and no network, sees the same findings and figures.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from cassandra.app import analyse
from cassandra.report_html import write

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)


def test_report_contains_the_findings_and_the_figures(tmp_path: Path) -> None:
    out = write(analyse(CORPUS), CORPUS, tmp_path / "r.html")
    body = out.read_text()
    assert "different devices" in body
    assert "fhrp-divergence" in body
    assert body.count("<svg") >= 2, (
        "timeline and adjacency figures should both be there"
    )


def test_report_has_no_external_references(tmp_path: Path) -> None:
    """No stylesheet, script, font or image may be fetched: the file has to work
    on a laptop with no network, which is the point of sending it to someone."""
    body = write(analyse(CORPUS), CORPUS, tmp_path / "r.html").read_text()
    for pattern in (r"<script", r"https?://", r"<link[^>]+href", r"@import", r"<img"):
        assert not re.search(pattern, body), f"external reference: {pattern}"


def test_the_search_form_is_removed(tmp_path: Path) -> None:
    """It posts to a server that does not exist for a reader of the file."""
    body = write(analyse(CORPUS), CORPUS, tmp_path / "r.html").read_text()
    assert "<form" not in body
    assert "<button" not in body


def test_report_is_theme_aware(tmp_path: Path) -> None:
    body = write(analyse(CORPUS), CORPUS, tmp_path / "r.html").read_text()
    assert "prefers-color-scheme: dark" in body
    assert 'data-theme="dark"' in body


def test_clean_directory_produces_a_report_saying_so(tmp_path: Path) -> None:
    configs = tmp_path / "configs"
    configs.mkdir()
    (configs / "r.cfg").write_text(
        "hostname r\ninterface Ethernet1\n   no switchport\n   ip address 10.0.0.1/31\n"
    )
    body = write(analyse(configs), configs, tmp_path / "r.html").read_text()
    assert "No findings" in body
