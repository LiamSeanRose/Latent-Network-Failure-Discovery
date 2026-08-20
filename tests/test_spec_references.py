"""Every §-reference in the repository must resolve to a heading in PROJECT.md.

PROJECT.md is the spec, and the standing rules make it load-bearing: code and docs
cite it by section throughout. Those citations rot silently — a section gets
renumbered during a revision and the reference still looks authoritative while
pointing somewhere else, or nowhere.

This is cheap to check and expensive to notice by eye, which is the whole argument
for it being a test.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

ROOT: Final = Path(__file__).resolve().parents[1]
SPEC: Final = ROOT / "PROJECT.md"
CONVENTIONS: Final = ROOT / "docs" / "CONVENTIONS.md"
SEARCHED_SUFFIXES: Final = frozenset({".py", ".md", ".sh", ".yml", ".yaml", ".toml"})
SKIP_DIRS: Final = frozenset({".git", ".venv", ".ruff_cache", ".pytest_cache", "runs"})

REFERENCE: Final = re.compile(r"§(\d+(?:\.\d+)?)")
HEADING: Final = re.compile(r"^#{2,3} (\d+(?:\.\d+)?)[.\s]", re.M)


def spec_sections() -> set[str]:
    """Sections defined by the two normative documents.

    PROJECT.md is the spec; CONVENTIONS.md carries the standing rules and is cited
    the same way. A reference to either resolves.
    """
    return set(HEADING.findall(SPEC.read_text())) | set(
        HEADING.findall(CONVENTIONS.read_text())
    )


def searched_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.suffix in SEARCHED_SUFFIXES
        and path.is_file()
        and not SKIP_DIRS & set(path.relative_to(ROOT).parts)
    )


def test_spec_defines_sections() -> None:
    """Guard the guard: a parser that finds nothing would pass every other test."""
    sections = spec_sections()
    assert len(sections) > 10, f"only found {sections} — heading parser is broken"


@pytest.mark.parametrize(
    "path", searched_files(), ids=lambda p: str(p.relative_to(ROOT))
)
def test_every_spec_reference_resolves(path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="ignore")
    # A document citing its own sections is not citing the spec.
    sections = spec_sections() | set(HEADING.findall(text))
    missing = set(REFERENCE.findall(text)) - sections
    assert not missing, (
        f"{path.relative_to(ROOT)} cites {sorted('§' + m for m in missing)}, "
        f"which neither PROJECT.md nor CONVENTIONS.md defines"
    )


# --------------------------------------------------------------------------
# Commands the documentation tells people to run
# --------------------------------------------------------------------------

_DOCS: Final = (ROOT / "README.md", *(ROOT / "docs").glob("*.md"))

# `$ uv run cassandra check ./configs --explain`, and the same without the
# prompt or the runner. Stops at a pipe or a redirect, because what follows one
# is the shell's business rather than this parser's, and at a `#`, because the
# README annotates its examples in a column and the annotation is prose.
_INVOCATION: Final = re.compile(r"(?:uv run )?cassandra ((?:(?!\||>|&&|#|\n).)*)")


def _documented_commands() -> set[str]:
    found: set[str] = set()
    # `cassandra` with no arguments is documented and deliberately left out:
    # it takes no arguments to get wrong, and what it prints has its own tests
    # in `test_cli.py`.
    for path in _DOCS:
        for line in path.read_text().splitlines():
            # Only the lines that are commands. Prose says "cassandra facts"
            # mid-sentence, and a sentence is not an invocation.
            stripped = line.strip()
            if not stripped.startswith(("$ ", "uv run cassandra", "cassandra ")):
                continue
            match = _INVOCATION.search(stripped)
            if match and (invocation := match.group(1).strip().rstrip(".")):
                found.add(invocation)
    return found


def test_the_documentation_quotes_at_least_the_commands_it_used_to() -> None:
    """A guard on the guard: if the extraction stops matching, the test below
    passes by finding nothing, which is the failure mode a corpus-driven check
    has."""
    assert len(_documented_commands()) >= 12


@pytest.mark.parametrize("command", sorted(_documented_commands()))
def test_every_documented_command_still_parses(command: str) -> None:
    """The docs tell people to type these. A renamed flag makes every one of
    them a lie, and nothing else in this suite would notice.

    Parsing, not running: whether `--explain` still exists is a fact about the
    tool, and whether `/tmp/tutorial` exists is a fact about the reader's
    machine. Only the first is this repository's to keep true.

    One limit worth knowing, found by trying it: argparse accepts an unambiguous
    prefix of a long option, so renaming `--explain` to `--explain-it` leaves
    every documented command working and this test green. That is argparse being
    right — the reader's command still does what the docs say — and it is why
    this catches a flag that was renamed rather than a flag that was extended.
    """
    import argparse
    import contextlib
    import io

    from cassandra.cli import build_parser

    parser = build_parser()
    # argparse writes to stderr and raises SystemExit on a bad argument; the
    # message is what a reader would see, so it is what the failure reports.
    complaint = io.StringIO()
    try:
        with contextlib.redirect_stderr(complaint):
            parser.parse_args(command.split())
    except SystemExit:  # pragma: no cover - only on a real regression
        pytest.fail(
            f"the docs say `cassandra {command}` and the tool rejects it:\n"
            f"{complaint.getvalue().strip()}"
        )
    except argparse.ArgumentError as exc:  # pragma: no cover
        pytest.fail(f"the docs say `cassandra {command}`: {exc}")
