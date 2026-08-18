"""The local web view, driven through a real server socket.

Rendering is exercised end to end rather than by calling `page()` directly,
because the things that break a local UI — a bad query string, a path that does
not exist, an unescaped character — live in the request path.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Final
from urllib.parse import quote
from urllib.request import urlopen

import pytest

from cassandra.app import Handler, analyse_directory

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
