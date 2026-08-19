"""The distribution: metadata, and every package directory reaching the wheel.

A subpackage that exists on disk but is missing from the built wheel is the
classic packaging defect — the tool installs, imports, and then fails on the
first call into the part that was left behind. These tests hold the build
configuration to the packages that actually exist, and, when a wheel has been
built, read it and check the same thing directly.
"""

from __future__ import annotations

import fnmatch
import importlib
import os
import subprocess
import tomllib
import zipfile
from pathlib import Path
from typing import Any, Final

import pytest

REPO: Final = Path(__file__).resolve().parents[1]
PYPROJECT: Final = REPO / "pyproject.toml"
REPO_URL: Final = "https://github.com/LiamSeanRose/Latent-Network-Failure-Discovery"

# PROJECT.md §4.1 names these. Every one is an importable package directory and
# every one has to ship.
REQUIRED_PACKAGES: Final = frozenset(
    {
        "cassandra",
        "cassandra.factpack",
        "cassandra.factpack.builders",
        "cassandra.facts",
        "cassandra.timing",
    }
)


def _config() -> dict[str, Any]:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


def _package_dirs() -> dict[str, Path]:
    """Every package directory on disk, dotted name -> directory."""
    found: dict[str, Path] = {}
    for init in REPO.glob("cassandra/**/__init__.py"):
        directory = init.parent
        found[".".join(directory.relative_to(REPO).parts)] = directory
    return found


def _wheel_target() -> dict[str, Any]:
    hatch = _config().get("tool", {}).get("hatch", {})
    return hatch.get("build", {}).get("targets", {}).get("wheel", {})


def _matches(patterns: list[str], relative: str) -> str | None:
    """The first pattern that would drop `relative` from the build, if any."""
    segments = relative.split("/")
    for pattern in patterns:
        needle = pattern.strip("/")
        if fnmatch.fnmatch(relative, needle) or any(
            fnmatch.fnmatch(segment, needle) for segment in segments
        ):
            return pattern
    return None


def _built_wheel() -> Path | None:
    """The newest wheel in `dist/`, or in $CASSANDRA_WHEEL_DIR if that is set.

    `dist/` is not in .gitignore, so `uv build --out-dir` somewhere outside the
    tree plus that variable keeps the working tree clean while still exercising
    the check below.
    """
    directory = Path(os.environ.get("CASSANDRA_WHEEL_DIR", REPO / "dist"))
    wheels = sorted(directory.glob("*.whl")) if directory.is_dir() else []
    return wheels[-1] if wheels else None


def test_every_required_package_exists_on_disk() -> None:
    missing = REQUIRED_PACKAGES - set(_package_dirs())
    assert not missing, f"PROJECT.md §4.1 packages absent from the tree: {missing}"


def test_wheel_config_covers_every_package_directory() -> None:
    roots = _wheel_target().get("packages", [])
    assert roots, "the wheel target declares no packages; nothing would ship"
    uncovered = {
        name
        for name in _package_dirs()
        if not any(
            name == root or name.startswith(f"{root.replace('/', '.')}.")
            for root in (r.strip("/") for r in roots)
        )
    }
    assert not uncovered, f"package directories outside the wheel roots: {uncovered}"


def test_no_exclude_pattern_drops_a_package() -> None:
    target = _wheel_target()
    assert "only-include" not in target, (
        "only-include narrows the wheel to an explicit list, which is how a "
        "subpackage goes missing; keep the single `packages` root instead"
    )
    excludes = list(target.get("exclude", []))
    for name, directory in _package_dirs().items():
        relative = directory.relative_to(REPO).as_posix()
        hit = _matches(excludes, f"{relative}/__init__.py")
        assert hit is None, f"exclude pattern {hit!r} would drop package {name}"


def test_no_package_file_is_ignored_by_git() -> None:
    """Hatchling honours .gitignore, so an ignored source file silently vanishes."""
    paths = [
        str(path.relative_to(REPO))
        for directory in _package_dirs().values()
        for path in sorted(directory.glob("*.py"))
    ]
    result = subprocess.run(
        ["git", "check-ignore", "--stdin"],
        cwd=REPO,
        input="\n".join(paths),
        capture_output=True,
        text=True,
        check=False,
    )
    ignored = [line for line in result.stdout.splitlines() if line.strip()]
    assert not ignored, f"source files excluded from the build by .gitignore: {ignored}"


def test_console_script_points_at_a_real_callable() -> None:
    scripts = _config()["project"]["scripts"]
    assert scripts == {"cassandra": "cassandra.cli:main"}
    module_name, _, attribute = scripts["cassandra"].partition(":")
    entry = getattr(importlib.import_module(module_name), attribute)
    assert callable(entry)


def test_the_tool_declares_no_runtime_dependencies() -> None:
    """Standard library only, deliberately (PROJECT.md §0: no lab, no account)."""
    project = _config()["project"]
    assert project["dependencies"] == []
    assert "optional-dependencies" not in project


def test_metadata_is_complete_enough_to_publish() -> None:
    project = _config()["project"]
    assert project["description"].strip()
    assert (REPO / project["readme"]).is_file()
    assert project["requires-python"].startswith(">=3.12")
    assert project["keywords"]
    assert project["classifiers"]
    urls = project["urls"]
    assert urls["Homepage"] == REPO_URL
    assert urls["Repository"] == REPO_URL
    assert all(url.startswith(REPO_URL) for url in urls.values())


def test_install_doc_exists_and_names_the_entry_point() -> None:
    doc = (REPO / "docs" / "INSTALL.md").read_text(encoding="utf-8")
    assert "cassandra check" in doc
    assert REPO_URL in doc


def test_built_wheel_contains_every_package() -> None:
    """Reads `dist/` when a wheel is there; nothing is built by the test itself."""
    wheel = _built_wheel()
    if wheel is None:
        pytest.skip("no wheel found; run `uv build` to exercise this check")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        entry_points = next(
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        )
        text = archive.read(entry_points).decode("utf-8")
    for package in sorted(REQUIRED_PACKAGES):
        expected = package.replace(".", "/") + "/__init__.py"
        assert expected in names, f"{package} missing from {wheel.name}"
    assert "cassandra = cassandra.cli:main" in text
