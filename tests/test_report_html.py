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


def test_the_report_holds_every_finding(tmp_path: Path) -> None:
    """The page caps what it renders because it can offer to render the rest.

    A file cannot, so a report that stopped at two hundred would end with a link
    inviting the reader to click for findings that are not in the file.
    """
    configs = tmp_path / "many"
    configs.mkdir()
    for site in range(260):
        for role, host, priority in (("agg-a", 2, 110), ("agg-b", 3, 100)):
            vlan = 10 * site + 4
            (configs / f"s{site}-{role}.cfg").write_text(
                f"hostname s{site}-{role}\nvlan {vlan}\n"
                "track UPLINK interface Ethernet1 line-protocol\n"
                "interface Ethernet1\n   no switchport\n"
                f"   ip address 10.{site // 250}.{site % 250}.{host}/31\n"
                f"interface Vlan{vlan}\n"
                f"   ip address 10.{site // 250}.{vlan % 250}.{host}/24\n"
                f"   vrrp {vlan} ipv4 10.{site // 250}.{vlan % 250}.1\n"
                f"   vrrp {vlan} priority-level {priority}\n"
                f"   vrrp {vlan} preempt\n"
                f"   vrrp {vlan} tracked-object UPLINK decrement 40\n"
            )
    result = analyse(configs)
    body = write(result, configs, tmp_path / "r.html").read_text()
    assert len(result.findings) > 200
    assert body.count('<article style="--i:') == len(result.findings)
    assert "Render all" not in body
    assert "Showing the worst" not in body


def test_the_report_carries_the_reading_it_rests_on(tmp_path: Path) -> None:
    """A report is the copy that travels, and its reader is the one least able
    to go and check the configs it was made from — they may not have them."""
    body = write(analyse(CORPUS), CORPUS, tmp_path / "r.html").read_text()
    assert "What the tool read from 4 devices" in body
    for device in ("agg-a", "agg-b", "acc1", "core1"):
        assert device in body
    # Folded: it is the appendix to the findings, not the point of the document.
    assert 'class="read-appendix"' in body
    assert "<details" in body


def test_the_report_has_no_link_to_a_page_it_cannot_reach(tmp_path: Path) -> None:
    """A dead link in a file someone was sent reads as the file being broken.

    Checked as a class rather than route by route: every new endpoint would
    otherwise have to remember to come and be stripped.
    """
    body = write(analyse(CORPUS), CORPUS, tmp_path / "r.html").read_text()
    assert not re.findall(r'href="/[^"]*"', body)
    # In-page anchors are the point of the rule panel and must survive.
    assert re.findall(r'href="#rule-', body)


def test_the_map_still_draws_its_nodes_after_the_links_come_out(
    tmp_path: Path,
) -> None:
    """A node is a link wrapping markup, not text, so it needs unwrapping rather
    than deleting — deleting takes the device off the map with it."""
    body = write(analyse(CORPUS), CORPUS, tmp_path / "r.html").read_text()
    assert body.count('class="node') == 4, "one per device in the corpus"


def test_the_provenance_line_has_no_dangling_separator(tmp_path: Path) -> None:
    body = write(analyse(CORPUS), CORPUS, tmp_path / "r.html").read_text()
    line = re.search(r'<p class="provenance">.*?</p>', body, re.S)
    assert line and "digest" in line.group(0)
    assert not line.group(0).rstrip().endswith("· </p>")
