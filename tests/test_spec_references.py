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
