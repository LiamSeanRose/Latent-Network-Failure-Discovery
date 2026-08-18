"""Score one scenario run against the Phase 0 criteria.

    python score.py runs/20260818T173000-trigger

Exit status is the verdict: 0 if the run matches what its mode should produce,
1 if it does not. That makes it usable as a hard condition (PROJECT.md §2.4
wants exit codes, not judgment) rather than something a human eyeballs.

The scoring logic and the log parsing are deliberately separated. The logic is
fully tested against synthetic timelines and needs no lab. The parsing is a best
guess at `show vrrp` output, written without a cEOS to check against — when it
fails on real output, fix `parse_run_log` and leave everything else alone.

Phase 3's `tiers/emulation/collect.py` generalises this. Until it exists, this is
scenario-local on purpose.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

type Json = str | int | float | bool | list[Json] | dict[str, Json] | None

MASTER: Final = "master"
VRRP_STATES: Final = frozenset({"master", "backup", "initialize", "init", "stopped"})

# Criteria from docs/phase0-design.md.
GROUP_UNDER_TEST: Final = 14
DIVERGENCE_PAIR: Final = (24, 34)
MIN_TRANSITIONS: Final = 4
MIN_DIVERGENCE_S: Final = 60

RECORD_DELIMITER: Final = re.compile(r"^### (\d+) (\S+)$", re.M)


@dataclass(frozen=True, slots=True)
class Sample:
    """One observation of one group's state on one device."""

    t: int
    node: str
    group: int
    state: str


@dataclass(frozen=True, slots=True)
class Verdict:
    mode: str
    transitions: int
    longest_divergence_s: int
    observable_present: bool
    passed: bool
    notes: tuple[str, ...]

    def render(self) -> str:
        lines = [
            f"mode                  {self.mode}",
            f"group {GROUP_UNDER_TEST} transitions   {self.transitions} "
            f"(need >= {MIN_TRANSITIONS})",
            f"divergence {DIVERGENCE_PAIR[0]} vs {DIVERGENCE_PAIR[1]}   "
            f"{self.longest_divergence_s}s (need >= {MIN_DIVERGENCE_S}s)",
            f"observable            "
            f"{'PRESENT' if self.observable_present else 'absent'}",
            f"verdict               {'PASS' if self.passed else 'FAIL'}",
        ]
        lines.extend(f"note                  {note}" for note in self.notes)
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Parsing — the part that needs a real lab to validate
# --------------------------------------------------------------------------


def _walk_json(blob: Json, group_hint: int | None = None) -> list[tuple[int, str]]:
    """Pull (group, state) pairs out of arbitrarily shaped `| json` output.

    Written generically because the exact schema of `show vrrp | json` was not
    verifiable when this was written. It looks for any mapping carrying a
    state-like key with a VRRP state value, and takes the group from a sibling
    key or from the mapping key it was found under.
    """
    found: list[tuple[int, str]] = []
    if isinstance(blob, dict):
        state = next(
            (
                str(v).lower()
                for k, v in blob.items()
                if "state" in k.lower() and str(v).lower() in VRRP_STATES
            ),
            None,
        )
        group = next(
            (
                int(v)
                for k, v in blob.items()
                if re.search(r"group|vrid|vrf?id", k, re.I) and str(v).isdigit()
            ),
            group_hint,
        )
        if state is not None and group is not None:
            found.append((group, state))
        for key, value in blob.items():
            hint = int(key) if str(key).isdigit() else group_hint
            found.extend(_walk_json(value, hint))
    elif isinstance(blob, list):
        for item in blob:
            found.extend(_walk_json(item, group_hint))
    return found


def _parse_text(body: str) -> list[tuple[int, str]]:
    """Fallback for the human-readable `show vrrp` output."""
    found: list[tuple[int, str]] = []
    group: int | None = None
    for line in body.splitlines():
        if m := re.search(r"(?:group|virtual router)\s+(\d+)", line, re.I):
            group = int(m.group(1))
        if m := re.search(r"\b(master|backup|initialize|init|stopped)\b", line, re.I):
            if group is not None:
                found.append((group, m.group(1).lower()))
    return found


def parse_run_log(text: str) -> list[Sample]:
    """Split `### <epoch> <node>` delimited records and extract samples."""
    samples: list[Sample] = []
    matches = list(RECORD_DELIMITER.finditer(text))
    for i, match in enumerate(matches):
        t, node = int(match.group(1)), match.group(2)
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[match.end() : end]
        try:
            pairs = _walk_json(json.loads(body))
        except (json.JSONDecodeError, ValueError):
            pairs = _parse_text(body)
        samples.extend(Sample(t=t, node=node, group=g, state=s) for g, s in pairs)
    return samples


# --------------------------------------------------------------------------
# Scoring — fully testable without a lab
# --------------------------------------------------------------------------


def build_timeline(samples: list[Sample]) -> list[tuple[int, dict[int, str | None]]]:
    """Step function of group -> master node over time.

    The two devices are sampled a moment apart, so state is carried forward
    rather than requiring both ends to report at the same instant.
    """
    state: dict[tuple[str, int], str] = {}
    timeline: list[tuple[int, dict[int, str | None]]] = []
    for t in sorted({s.t for s in samples}):
        for sample in (s for s in samples if s.t == t):
            state[(sample.node, sample.group)] = sample.state
        masters: dict[int, str | None] = {}
        for (node, group), value in state.items():
            if value == MASTER:
                # Two masters at once is split brain, not a placement.
                masters[group] = "SPLIT" if masters.get(group) else node
        for _, group in state:
            masters.setdefault(group, None)
        timeline.append((t, masters))
    return timeline


def count_transitions(
    timeline: list[tuple[int, dict[int, str | None]]], group: int
) -> int:
    """Master changes for one group. The first observation is not a transition."""
    transitions = 0
    previous: str | None = None
    for _, masters in timeline:
        current = masters.get(group)
        if current is None:
            continue
        if previous is not None and current != previous:
            transitions += 1
        previous = current
    return transitions


def longest_divergence_s(
    timeline: list[tuple[int, dict[int, str | None]]], a: int, b: int
) -> int:
    """Longest contiguous span where two groups sit on different devices."""
    longest = 0
    start: int | None = None
    for t, masters in timeline:
        ma, mb = masters.get(a), masters.get(b)
        diverged = ma is not None and mb is not None and ma != mb
        if diverged and start is None:
            start = t
        elif not diverged and start is not None:
            longest = max(longest, t - start)
            start = None
    if start is not None and timeline:
        longest = max(longest, timeline[-1][0] - start)
    return longest


def score(mode: str, samples: list[Sample]) -> Verdict:
    timeline = build_timeline(samples)
    transitions = count_transitions(timeline, GROUP_UNDER_TEST)
    divergence = longest_divergence_s(timeline, *DIVERGENCE_PAIR)
    present = transitions >= MIN_TRANSITIONS and divergence >= MIN_DIVERGENCE_S

    notes: list[str] = []
    if not samples:
        notes.append("no samples parsed — check parse_run_log against real output")
    if any("SPLIT" in m.values() for _, m in timeline):
        notes.append("split brain observed: two masters for one group")

    # A control run passes by NOT showing the observable. Inverting the criterion
    # rather than skipping it is what makes the control a real control.
    passed = not present if mode == "control" else present
    return Verdict(
        mode=mode,
        transitions=transitions,
        longest_divergence_s=divergence,
        observable_present=present,
        passed=passed,
        notes=tuple(notes),
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    run_dir = Path(argv[1])
    mode_file = run_dir / "mode"
    mode = mode_file.read_text().strip() if mode_file.is_file() else "trigger"

    log = run_dir / "vrrp.json.log"
    if not log.is_file():
        log = run_dir / "vrrp.log"
    if not log.is_file():
        print(f"no sample log in {run_dir}")
        return 2

    verdict = score(mode, parse_run_log(log.read_text()))
    print(verdict.render())
    return 0 if verdict.passed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
