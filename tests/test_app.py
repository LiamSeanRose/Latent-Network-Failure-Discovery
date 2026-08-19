"""The local web view, driven through a real server socket.

Rendering is exercised end to end rather than by calling `page()` directly,
because the things that break a local UI — a bad query string, a path that does
not exist, an unescaped character — live in the request path.
"""

from __future__ import annotations

import json
import re
import shutil
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Final
from urllib.parse import quote
from urllib.request import urlopen

import pytest

from cassandra.app import Handler, analyse_directory
from cassandra.factpack.builders import build_fact_pack

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)


@pytest.fixture(scope="module")
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def get(url: str) -> tuple[int, str]:
    with urlopen(url) as response:
        return response.status, response.read().decode()


def test_landing_page_asks_for_a_directory(base_url: str) -> None:
    status, body = get(base_url + "/")
    assert status == 200
    assert "Enter a directory" in body
    assert "<form" in body


def test_analysing_the_corpus_shows_the_timing_finding(base_url: str) -> None:
    status, body = get(f"{base_url}/?dir={quote(str(CORPUS))}")
    assert status == 200
    assert "different devices" in body
    assert "fhrp-divergence" in body
    assert "trigger:" in body


def test_timing_findings_carry_their_caveat(base_url: str) -> None:
    """A model-derived finding presented as fact is the failure mode this tier
    has. The UI must not drop the caveat the CLI prints."""
    _, body = get(f"{base_url}/?dir={quote(str(CORPUS))}")
    assert "not from running the protocols" in body


def test_json_endpoint_matches_the_page(base_url: str) -> None:
    status, body = get(f"{base_url}/findings.json?dir={quote(str(CORPUS))}")
    assert status == 200
    payload = json.loads(body)
    assert payload
    assert {f["rule"] for f in payload} >= {"fhrp-divergence"}
    for finding in payload:
        assert finding["severity"] in {"high", "medium", "low", "info"}
        assert finding["tier"] in {"facts", "timing"}


def test_missing_directory_reports_instead_of_crashing(base_url: str) -> None:
    status, body = get(f"{base_url}/?dir={quote('/definitely/not/here')}")
    assert status == 200
    assert "not a directory" in body


def test_empty_directory_reports_instead_of_crashing(
    base_url: str, tmp_path: Path
) -> None:
    _, body = get(f"{base_url}/?dir={quote(str(tmp_path))}")
    assert "no .cfg files" in body


def test_unknown_path_is_404(base_url: str) -> None:
    with pytest.raises(Exception) as excinfo:
        get(base_url + "/nope")
    assert "404" in str(excinfo.value)


def test_directory_names_are_escaped_not_injected(
    base_url: str, tmp_path: Path
) -> None:
    """The directory string is echoed into the page. It must be escaped."""
    hostile = tmp_path / "<script>alert(1)</script>"
    _, body = get(f"{base_url}/?dir={quote(str(hostile))}")
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_analyse_directory_is_the_same_engine_as_the_cli() -> None:
    findings, error = analyse_directory(CORPUS)
    assert error is None
    assert {f.tier.value for f in findings} == {"timing"}


# VLAN 99 is declared but carried by no trunk: exactly one planted defect.
# It previously declared only VLAN 20, which meant the SVI also tripped
# `vlan-not-declared` — a second, unintended finding that made the counts below
# ambiguous about which defect they were counting.
MIXED_EXTRA: Final = """hostname edge1
vlan 20,99
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 20
interface Vlan99
   ip address 10.77.0.1/24
"""


@pytest.fixture(scope="module")
def mixed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The corpus plus one planted FACTS defect on a second device.

    The clean corpus produces timing findings on a single device, which cannot
    show whether filtering or grouping works. This adds an SVI whose VLAN no
    trunk carries, so the fixture spans two devices, both tiers and two
    severities.
    """
    configs = tmp_path_factory.mktemp("mixed") / "configs"
    shutil.copytree(CORPUS, configs)
    (configs / "edge1.cfg").write_text(MIXED_EXTRA)
    return configs


def view(base_url: str, config_dir: Path, query: str = "", path: str = "/") -> str:
    url = f"{base_url}{path}?dir={quote(str(config_dir))}"
    return get(f"{url}&{query}" if query else url)[1]


def test_the_mixed_fixture_spans_both_tiers(base_url: str, mixed: Path) -> None:
    """Guards the fixture itself: the filter tests below are meaningless if it
    ever stops containing both tiers."""
    payload = json.loads(view(base_url, mixed, path="/findings.json"))
    assert {f["tier"] for f in payload} == {"facts", "timing"}
    assert {f["device"] for f in payload} == {"agg-a", "edge1"}


def test_severity_filter_narrows_the_page(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed, "severity=high")
    assert "fhrp-divergence" in body
    assert "fhrp-oscillation" not in body
    assert "svi-vlan-not-trunked" not in body
    assert "Showing 2 of" in body


def test_tier_filter_narrows_the_page(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed, "tier=facts")
    assert "svi-vlan-not-trunked" in body
    assert "fhrp-divergence" not in body


def test_filters_combine(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed, "severity=medium&tier=facts")
    assert "svi-vlan-not-trunked" in body
    assert "fhrp-oscillation" not in body


def test_repeated_and_comma_separated_values_are_both_accepted(
    base_url: str, mixed: Path
) -> None:
    for query in ("severity=high&severity=medium", "severity=high,medium"):
        body = view(base_url, mixed, query)
        assert "fhrp-divergence" in body, query
        assert "fhrp-oscillation" in body, query


def test_filter_chips_are_links_that_carry_the_directory(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed)
    assert 'class="chip"' in body
    for expected in ("severity=high", "severity=medium", "tier=facts", "tier=timing"):
        assert f"dir={quote(str(mixed), safe='')}&amp;{expected}" in body, expected


def test_the_active_chip_is_marked_and_offers_a_way_back(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed, "severity=high")
    assert 'class="chip on"' in body
    # "all" clears severity while keeping the directory.
    assert f'href="/?dir={quote(str(mixed), safe="")}"' in body


def test_filters_survive_in_the_json_link_and_the_form(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed, "severity=high&tier=timing")
    assert "/findings.json?dir=" in body
    assert "severity=high&amp;tier=timing" in body
    assert '<input type="hidden" name="severity" value="high">' in body
    assert '<input type="hidden" name="tier" value="timing">' in body


def test_json_endpoint_honours_the_same_filters(base_url: str, mixed: Path) -> None:
    high = json.loads(view(base_url, mixed, "severity=high", "/findings.json"))
    assert high
    assert {f["severity"] for f in high} == {"high"}

    facts = json.loads(view(base_url, mixed, "tier=facts", "/findings.json"))
    assert {f["tier"] for f in facts} == {"facts"}
    # Containment, not equality: this test is about filtering, and pinning the
    # exact rule set would break every time the FACTS registry grows.
    assert "svi-vlan-not-trunked" in {f["rule"] for f in facts}

    both = json.loads(
        view(base_url, mixed, "severity=high&tier=facts", "/findings.json")
    )
    assert [f["rule"] for f in both] == []


def test_findings_are_grouped_by_device_with_a_count(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed)
    assert body.count('<details class="device" open>') == 2
    # Match the grouping, not today's counts. Pinning exact numbers couples this
    # test to the FACTS rule registry, which grows.
    for device in ("agg-a", "edge1"):
        assert re.search(
            rf"<summary>{device}<span class=\"n\">\d+ findings?</span></summary>", body
        ), f"no grouped summary for {device}"
    assert "1 finding<" in body or "1 findings<" not in body


def test_a_filter_matching_nothing_says_so_and_links_back(
    base_url: str, mixed: Path
) -> None:
    # Find a severity+tier combination that genuinely has no findings, rather
    # than assuming one exists. Every severity may be populated as rules grow,
    # but a full cross-product rarely is.
    findings = json.loads(view(base_url, mixed, path="/findings.json"))
    assert findings, "fixture must produce findings for this test to mean anything"
    present = {(f["severity"], f["tier"]) for f in findings}
    severity, tier = next(
        (s, t)
        for s in ("info", "low", "medium", "high")
        for t in ("facts", "timing")
        if (s, t) not in present
    )

    body = view(base_url, mixed, f"severity={severity}&tier={tier}")
    assert "No findings match these filters" in body
    assert "Show all" in body


def test_unknown_filter_values_are_reported_and_escaped(
    base_url: str, mixed: Path
) -> None:
    """Filter values are echoed into the page, so they are an injection route."""
    body = view(base_url, mixed, "severity=" + quote("<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "Ignored filter values" in body
    # An unusable filter must not silently hide findings.
    assert "fhrp-divergence" in body


def test_timing_findings_keep_their_caveat_under_every_filter(
    base_url: str, mixed: Path
) -> None:
    for query in ("", "severity=high", "tier=timing", "severity=medium&tier=timing"):
        body = view(base_url, mixed, query)
        assert "not from running the protocols" in body, query
        assert "model-derived" in body, query


def test_the_fact_pack_identity_is_on_the_page(base_url: str, mixed: Path) -> None:
    """Which configs produced this view, so two tabs cannot be confused."""
    pack, _ = build_fact_pack(mixed)
    body = view(base_url, mixed)
    assert pack.meta.fact_pack_id in body
    assert pack.meta.config_digest[:12] in body
    assert "5 devices" in body


def test_the_page_is_self_contained(base_url: str, mixed: Path) -> None:
    """No external CSS, JS, font or image: it has to work offline."""
    body = view(base_url, mixed)
    assert "http://" not in body
    assert "https://" not in body
    assert "<script" not in body
    assert "<link" not in body
    assert "<img" not in body


def test_the_page_is_theme_aware_and_responsive(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed)
    assert "prefers-color-scheme: dark" in body
    assert "@media (max-width: 700px)" in body
    assert 'name="viewport"' in body
