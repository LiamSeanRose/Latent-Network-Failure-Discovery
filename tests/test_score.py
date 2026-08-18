"""Scoring logic for the Phase 0 scenario, exercised on synthetic timelines.

The point of these is that the verdict logic is provably right before any lab
exists. When `score.py` first meets real `show vrrp` output the parser will
probably need fixing; these tests make sure that is the *only* thing that needs
fixing.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCENARIO = Path(__file__).resolve().parents[1] / "scenarios" / "site14_vrrp_lockstep"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("score", SCENARIO / "score.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["score"] = module
    spec.loader.exec_module(module)
    return module


score_mod = _load()
Sample = score_mod.Sample


def samples_at(t: int, **groups: tuple[str, str]) -> list[object]:
    """samples_at(10, g14=("agg-a", "agg-b")) -> agg-a master, agg-b backup."""
    out = []
    for key, (master, backup) in groups.items():
        group = int(key.removeprefix("g"))
        out.append(Sample(t=t, node=master, group=group, state="master"))
        out.append(Sample(t=t, node=backup, group=group, state="backup"))
    return out


def test_first_observation_is_not_a_transition() -> None:
    timeline = score_mod.build_timeline(samples_at(0, g14=("agg-a", "agg-b")))
    assert score_mod.count_transitions(timeline, 14) == 0


def test_counts_each_master_change() -> None:
    samples = (
        samples_at(0, g14=("agg-a", "agg-b"))
        + samples_at(10, g14=("agg-b", "agg-a"))
        + samples_at(20, g14=("agg-a", "agg-b"))
        + samples_at(30, g14=("agg-b", "agg-a"))
    )
    timeline = score_mod.build_timeline(samples)
    assert score_mod.count_transitions(timeline, 14) == 3


def test_state_carries_forward_between_unevenly_sampled_devices() -> None:
    """agg-a and agg-b are sampled a moment apart. A group must not read as
    'no master' just because only one device reported at that instant."""
    samples = [
        Sample(t=0, node="agg-a", group=14, state="master"),
        Sample(t=1, node="agg-b", group=14, state="backup"),
        Sample(t=2, node="agg-a", group=14, state="master"),
    ]
    timeline = score_mod.build_timeline(samples)
    assert [masters[14] for _, masters in timeline] == ["agg-a"] * 3
    assert score_mod.count_transitions(timeline, 14) == 0


def test_divergence_measures_contiguous_seconds() -> None:
    samples = (
        samples_at(0, g24=("agg-a", "agg-b"), g34=("agg-a", "agg-b"))
        + samples_at(10, g24=("agg-b", "agg-a"), g34=("agg-a", "agg-b"))
        + samples_at(70, g24=("agg-b", "agg-a"), g34=("agg-a", "agg-b"))
        + samples_at(80, g24=("agg-a", "agg-b"), g34=("agg-a", "agg-b"))
    )
    timeline = score_mod.build_timeline(samples)
    assert score_mod.longest_divergence_s(timeline, 24, 34) == 70


def test_divergence_does_not_sum_separate_spans() -> None:
    """Two 40s divergences are not one 80s divergence. The criterion is
    contiguous, because a sustained split is the failure and flapping is not."""
    samples = (
        samples_at(0, g24=("agg-b", "agg-a"), g34=("agg-a", "agg-b"))
        + samples_at(40, g24=("agg-a", "agg-b"), g34=("agg-a", "agg-b"))
        + samples_at(50, g24=("agg-b", "agg-a"), g34=("agg-a", "agg-b"))
        + samples_at(90, g24=("agg-a", "agg-b"), g34=("agg-a", "agg-b"))
    )
    timeline = score_mod.build_timeline(samples)
    assert score_mod.longest_divergence_s(timeline, 24, 34) == 40


def test_split_brain_is_surfaced_not_silently_scored() -> None:
    samples = [
        Sample(t=0, node="agg-a", group=14, state="master"),
        Sample(t=0, node="agg-b", group=14, state="master"),
    ]
    verdict = score_mod.score("trigger", samples)
    assert any("split brain" in note for note in verdict.notes)


def _failing_run() -> list[object]:
    """A run that exhibits the observable: 6 transitions, sustained divergence."""
    samples = samples_at(
        0, g14=("agg-a", "agg-b"), g24=("agg-a", "agg-b"), g34=("agg-a", "agg-b")
    )
    flip = ("agg-b", "agg-a")
    stay = ("agg-a", "agg-b")
    for i, t in enumerate(range(10, 130, 10)):
        samples += samples_at(
            t,
            g14=flip if i % 2 == 0 else stay,
            g24=flip,
            g34=stay,
        )
    return samples


def test_trigger_run_passes_when_the_observable_appears() -> None:
    verdict = score_mod.score("trigger", _failing_run())
    assert verdict.transitions >= score_mod.MIN_TRANSITIONS
    assert verdict.longest_divergence_s >= score_mod.MIN_DIVERGENCE_S
    assert verdict.observable_present
    assert verdict.passed


def test_control_run_fails_when_the_observable_appears() -> None:
    """The control's criterion is inverted, not skipped. A control that shows the
    failure means the trigger was not what caused it — the finding is refuted,
    and the run must be scored as a failure rather than quietly passing."""
    verdict = score_mod.score("control", _failing_run())
    assert verdict.observable_present
    assert not verdict.passed


def test_control_run_passes_when_quiet() -> None:
    quiet = samples_at(
        0, g14=("agg-a", "agg-b"), g24=("agg-a", "agg-b"), g34=("agg-a", "agg-b")
    )
    quiet += samples_at(
        200, g14=("agg-a", "agg-b"), g24=("agg-a", "agg-b"), g34=("agg-a", "agg-b")
    )
    verdict = score_mod.score("control", quiet)
    assert not verdict.observable_present
    assert verdict.passed


def test_empty_log_never_passes_silently() -> None:
    """A parser that matches nothing must not read as 'no failure observed'."""
    verdict = score_mod.score("trigger", [])
    assert not verdict.passed
    assert any("no samples parsed" in note for note in verdict.notes)


# --------------------------------------------------------------------------
# Parsing — best-effort until real output exists
# --------------------------------------------------------------------------


def test_parses_delimited_json_records() -> None:
    log = (
        '### 100 agg-a\n{"virtualRouters": [{"groupId": 14, "state": "master"}]}\n'
        '### 100 agg-b\n{"virtualRouters": [{"groupId": 14, "state": "backup"}]}\n'
    )
    samples = score_mod.parse_run_log(log)
    assert {(s.node, s.group, s.state) for s in samples} == {
        ("agg-a", 14, "master"),
        ("agg-b", 14, "backup"),
    }


def test_falls_back_to_text_when_body_is_not_json() -> None:
    log = "### 100 agg-a\nVRRP Group 14\n  State is Master\n"
    samples = score_mod.parse_run_log(log)
    assert (samples[0].group, samples[0].state) == (14, "master")


@pytest.mark.parametrize("mode", ["trigger", "control", "perturb"])
def test_score_accepts_every_runner_mode(mode: str) -> None:
    assert score_mod.score(mode, []).mode == mode
