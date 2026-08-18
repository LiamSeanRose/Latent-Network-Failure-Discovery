"""The `cassandra` command, end to end on the corpus."""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from cassandra.cli import main

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)


def test_facts_renders_the_corpus(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["facts", str(CORPUS)]) == 0
    out = capsys.readouterr().out
    for expected in (
        "device agg-a",
        "fhrp vrrp group=14 virtual=10.14.0.1",
        "priority=110",
        "tracks=UPLINK->Ethernet1 -40",
        "preempt-delay=90000ms",
    ):
        assert expected in out, f"missing {expected!r}"


def test_facts_reports_nothing_unparsed_for_the_corpus(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main(["facts", str(CORPUS)])
    assert "unparsed" not in capsys.readouterr().out


def test_unparsed_lines_are_shown_not_hidden(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A construct the parser does not know must be visible in the output. Silent
    omission is how a fact pack quietly stops describing the network."""
    (tmp_path / "r.cfg").write_text(
        "hostname r\ninterface Ethernet1\n   ip helper-address 10.0.0.9\n"
    )
    main(["facts", str(tmp_path)])
    out = capsys.readouterr().out
    assert "unparsed" in out
    assert "ip helper-address 10.0.0.9" in out


def test_missing_directory_is_an_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["facts", "/nonexistent"]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_empty_directory_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["facts", str(tmp_path)]) == 2
    assert "no .cfg files" in capsys.readouterr().err
