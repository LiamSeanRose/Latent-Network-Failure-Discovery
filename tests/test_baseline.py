"""Regression detection: the diff between this run and one recorded earlier.

The load-bearing question is identity — what makes two findings the same finding
across two runs. Most of these tests are about the two ways that goes wrong: too
coarse, and two separate defects collapse into one so fixing one of them shows
nothing; too fine, and rewording a message or a timer moving by 50ms reads as a
regression. Both make the feature worse than not having it, because a regression
check that cries wolf gets switched off.

The rest hold the file itself honest: a missing, empty, hand-edited or truncated
baseline is an ordinary thing to run into, and none of them may produce a
traceback.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from unittest import mock

import pytest

from cassandra import baseline
from cassandra.baseline import (
    BaselineError,
    BaselineMismatch,
    Diff,
    compare,
    identity,
    load,
    render_diff,
    save,
    snapshot,
)
from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import Device, FactPackMeta, StaticFactPack
from cassandra.facts import rules
from cassandra.findings import Finding, Severity, Tier
from cassandra.timing import sequences, timer_rules

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)

# Two sessions on one device: the case that rule id plus device gets wrong.
BFD_ONE: Final = Finding(
    rule="bfd-no-clients",
    tier=Tier.FACTS,
    severity=Severity.MEDIUM,
    device="agg-a",
    title="BFD session on agg-a:Ethernet1 has no registered client",
    detail="the session is configured (300ms x 5 = 1500ms) but no protocol is "
    "registered against it, so nothing reacts when it goes down",
    evidence=("agg-a:Ethernet1  bfd interval 300 min_rx 300 multiplier 5",),
    trigger="loss of agg-a:Ethernet1",
    remedy="register a client, or remove the session",
)
BFD_TWO: Final = replace(
    BFD_ONE,
    title="BFD session on agg-a:Ethernet3 has no registered client",
    evidence=("agg-a:Ethernet3  bfd interval 300 min_rx 300 multiplier 5",),
    trigger="loss of agg-a:Ethernet3",
)
DIVERGENCE: Final = Finding(
    rule="fhrp-divergence",
    tier=Tier.TIMING,
    severity=Severity.HIGH,
    device="agg-a",
    title="VRRP 14 and VRRP 24 can end up on different devices",
    detail="they share a device pair but respond to the same event differently, "
    "leaving the gateways split for about 90s",
    evidence=("t=0s agg-a:Ethernet1 down", "t=10s agg-a:Ethernet1 up"),
    trigger="flap agg-a:Ethernet1 1x (10s down, 20s up)",
)


def pack_of(*devices: str, digest: str = "a" * 64) -> StaticFactPack:
    return StaticFactPack(
        meta=FactPackMeta(
            fact_pack_id=f"fp_{digest[:12]}",
            schema_version=1,
            config_digest=digest,
            source_snapshot="test",
            generated_at=datetime(2026, 8, 18, 9, 12, tzinfo=UTC),
            device_count=len(devices),
        ),
        devices=tuple(Device(id=name, hostname=name) for name in devices),
    )


def diff_of(
    before: list[Finding],
    after: list[Finding],
    *,
    before_digest: str = "a" * 64,
    after_digest: str = "a" * 64,
    devices: tuple[str, ...] = ("agg-a", "agg-b"),
) -> Diff:
    return compare(
        snapshot(before, pack_of(*devices, digest=before_digest)),
        snapshot(after, pack_of(*devices, digest=after_digest)),
    )


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------


def test_one_rule_twice_on_one_device_stays_two_findings() -> None:
    """Rule id plus device is too coarse: these are two sessions, not one."""
    assert identity(BFD_ONE) != identity(BFD_TWO)


def test_identity_survives_rewording_and_retiming() -> None:
    """The message was rewritten and the timers moved; the defect did not."""
    reworded = replace(
        BFD_ONE,
        title="nothing is registered against the BFD session on agg-a:Ethernet1",
        detail="it runs at 250ms x 3 = 750ms and no protocol ever asks it, so the "
        "detection time buys nothing at all",
        evidence=("agg-a:Ethernet1  bfd interval 250 min_rx 250 multiplier 3",),
        remedy="register a client (for example `ip ospf bfd`), or remove it",
        severity=Severity.LOW,
    )
    assert identity(reworded) == identity(BFD_ONE)

    diff = diff_of([BFD_ONE], [reworded])
    assert diff.new == []
    assert diff.fixed == []
    assert diff.unchanged == [reworded]


def test_identity_keeps_the_objects_a_finding_names() -> None:
    """A different group pair is a different finding, however alike it reads."""
    other_pair = replace(
        DIVERGENCE, title="VRRP 24 and VRRP 34 can end up on different devices"
    )
    assert identity(other_pair) != identity(DIVERGENCE)


def test_identity_ignores_the_sequence_that_triggered_it() -> None:
    """Timing evidence is a sampled trace: flap counts and clock offsets move
    whenever any timer in the network moves, and the divergence is the finding."""
    longer = replace(
        DIVERGENCE,
        detail="they share a device pair but respond to the same event "
        "differently, leaving the gateways split for about 140s",
        evidence=(
            "t=0s agg-a:Ethernet1 down",
            "t=10s agg-a:Ethernet1 up",
            "t=130s agg-a:Ethernet1 down",
            "t=140s agg-a:Ethernet1 up",
        ),
        trigger="flap agg-a:Ethernet1 2x (10s down, 120s up)",
    )
    assert identity(longer) == identity(DIVERGENCE)


def test_identity_falls_back_to_evidence_when_nothing_else_names_an_object() -> None:
    bare = Finding(
        rule="dampening-exceeds-sla",
        tier=Tier.FACTS,
        severity=Severity.HIGH,
        device="agg-a",
        title="bgp-route dampening can suppress a prefix for 30m",
        detail="max-suppress is 30m against an SLA of 5m",
        evidence=("agg-a:Ethernet1  interface dampening max-suppress 1800s",),
    )
    assert identity(bare)[2] == ("agg-a:ethernet1", "ethernet1")


def test_findings_sharing_an_identity_are_still_counted_separately() -> None:
    """Identity is a heuristic, so the diff counts rather than tests membership:
    two undefined tracked objects on one group read alike and are two problems."""
    first = Finding(
        rule="fhrp-tracked-object-undefined",
        tier=Tier.FACTS,
        severity=Severity.HIGH,
        device="agg-a",
        title="tracked object is referenced but never defined",
        detail="the group references it, so the decrement can never fire",
        evidence=("agg-a:Vlan14 vrrp 14",),
    )
    diff = diff_of([first, first], [first])
    assert len(diff.fixed) == 1
    assert len(diff.unchanged) == 1
    assert diff.new == []


# --------------------------------------------------------------------------
# The diff
# --------------------------------------------------------------------------


def test_a_finding_the_baseline_did_not_have_is_new() -> None:
    diff = diff_of([BFD_ONE], [BFD_ONE, DIVERGENCE])
    assert diff.new == [DIVERGENCE]
    assert diff.fixed == []
    assert diff.regressed


def test_a_finding_the_baseline_had_and_this_run_does_not_is_fixed() -> None:
    diff = diff_of([BFD_ONE, DIVERGENCE], [BFD_ONE])
    assert diff.fixed == [DIVERGENCE]
    assert diff.new == []
    assert not diff.regressed


def test_an_unchanged_finding_is_neither_new_nor_fixed() -> None:
    diff = diff_of([BFD_ONE, BFD_TWO], [BFD_ONE, BFD_TWO])
    assert diff.new == []
    assert diff.fixed == []
    assert diff.unchanged == [BFD_ONE, BFD_TWO]


def test_an_empty_baseline_makes_everything_new() -> None:
    diff = diff_of([], [BFD_ONE, DIVERGENCE])
    assert diff.new == [DIVERGENCE, BFD_ONE]
    assert diff.fixed == []
    assert diff.unchanged == []


def test_an_empty_run_against_a_baseline_fixes_everything() -> None:
    diff = diff_of([BFD_ONE, DIVERGENCE], [])
    assert diff.fixed == [DIVERGENCE, BFD_ONE]
    assert not diff.regressed


# --------------------------------------------------------------------------
# The config digest
# --------------------------------------------------------------------------


def test_edited_configs_are_information_not_an_error() -> None:
    """The normal case: the user changed their configs, which is why they ran it."""
    diff = diff_of(
        [BFD_ONE], [BFD_ONE, DIVERGENCE], before_digest="a" * 64, after_digest="b" * 64
    )
    assert diff.configs_changed
    assert diff.new == [DIVERGENCE]
    assert "configs changed since baseline" in render_diff(diff)


def test_identical_configs_say_the_difference_came_from_the_checks() -> None:
    diff = diff_of([BFD_ONE], [BFD_ONE, DIVERGENCE])
    assert not diff.configs_changed
    assert "configs unchanged since baseline" in render_diff(diff)


def test_a_baseline_from_another_network_is_refused() -> None:
    """Every finding new and every finding fixed is an answer with no meaning."""
    with pytest.raises(BaselineMismatch) as raised:
        compare(
            snapshot([BFD_ONE], pack_of("core1", "core2")),
            snapshot([BFD_ONE], pack_of("agg-a", "agg-b")),
        )
    assert "no device in common" in str(raised.value)


def test_a_partly_overlapping_network_compares_and_says_what_moved() -> None:
    diff = compare(
        snapshot([BFD_ONE], pack_of("agg-a", "agg-b")),
        snapshot([BFD_ONE], pack_of("agg-a", "acc1")),
    )
    assert diff.devices_added == ("acc1",)
    assert diff.devices_removed == ("agg-b",)
    assert diff.unchanged == [BFD_ONE]
    rendered = render_diff(diff)
    assert "devices added: acc1" in rendered
    assert "devices removed: agg-b" in rendered


# --------------------------------------------------------------------------
# The file
# --------------------------------------------------------------------------


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    path = tmp_path / ".cassandra" / "baseline.json"
    pack = pack_of("agg-a", "agg-b", digest="c" * 64)
    save([DIVERGENCE, BFD_ONE], pack, path)

    loaded = load(path)
    assert loaded.findings == [DIVERGENCE, BFD_ONE]
    assert loaded.digest == "c" * 64
    assert loaded.devices == ("agg-a", "agg-b")
    assert loaded.taken_at == pack.meta.generated_at


def test_saving_an_empty_run_is_a_usable_baseline(tmp_path: Path) -> None:
    """A clean network is the baseline worth having — everything after it is new."""
    path = tmp_path / "baseline.json"
    save([], pack_of("agg-a"), path)
    loaded = load(path)
    assert loaded.findings == []

    diff = compare(loaded, snapshot([BFD_ONE], pack_of("agg-a")))
    assert diff.new == [BFD_ONE]


def test_a_missing_baseline_says_so(tmp_path: Path) -> None:
    with pytest.raises(BaselineError) as raised:
        load(tmp_path / "nowhere.json")
    assert "no baseline at" in str(raised.value)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("garbage", "not json at all\n"),
        ("truncated", '{"format": "cassandra-baseline", "version": 1, "find'),
        ("not-a-baseline", '{"findings": []}'),
        ("wrong-root", '["cassandra-baseline"]'),
    ],
)
def test_a_corrupt_baseline_is_an_error_not_a_traceback(
    tmp_path: Path, name: str, text: str
) -> None:
    path = tmp_path / f"{name}.json"
    path.write_text(text)
    with pytest.raises(BaselineError) as raised:
        load(path)
    assert str(path) in str(raised.value)


def test_a_hand_edited_finding_is_an_error_not_a_traceback(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    save([BFD_ONE], pack_of("agg-a"), path)
    document = json.loads(path.read_text())
    document["findings"][0]["severity"] = "catastrophic"
    path.write_text(json.dumps(document))

    with pytest.raises(BaselineError) as raised:
        load(path)
    assert "corrupt" in str(raised.value)


def test_a_missing_field_is_an_error_not_a_traceback(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    save([BFD_ONE], pack_of("agg-a"), path)
    document = json.loads(path.read_text())
    del document["findings"][0]["title"]
    path.write_text(json.dumps(document))

    with pytest.raises(BaselineError):
        load(path)


def test_a_newer_format_says_to_re_record(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    save([BFD_ONE], pack_of("agg-a"), path)
    document = json.loads(path.read_text())
    document["version"] = 99
    path.write_text(json.dumps(document))

    with pytest.raises(BaselineError) as raised:
        load(path)
    assert "newer version" in str(raised.value)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def test_the_first_line_is_what_is_new() -> None:
    rendered = render_diff(diff_of([BFD_ONE], [BFD_ONE, DIVERGENCE]))
    assert rendered.splitlines()[0] == "1 new since baseline"
    assert rendered.splitlines()[2].startswith("HIGH  agg-a  VRRP 14 and VRRP 24")


def test_nothing_new_says_so_first() -> None:
    rendered = render_diff(diff_of([BFD_ONE, DIVERGENCE], [BFD_ONE]))
    assert rendered.splitlines()[0] == "no new findings since baseline"
    assert "1 fixed since baseline" in rendered
    assert "1 unchanged" in rendered


def test_new_is_rendered_before_fixed() -> None:
    rendered = render_diff(diff_of([BFD_ONE], [DIVERGENCE]))
    assert rendered.index("1 new since baseline") < rendered.index("1 fixed")


def test_explain_shows_evidence_and_rule_ids() -> None:
    rendered = render_diff(diff_of([], [DIVERGENCE]), explain=True)
    assert "evidence: t=0s agg-a:Ethernet1 down" in rendered
    assert "rule: fhrp-divergence (timing)" in rendered


# --------------------------------------------------------------------------
# Against the real corpus
# --------------------------------------------------------------------------


def test_the_corpus_compared_against_itself_reports_nothing() -> None:
    """End to end on real findings: every one of them keeps its identity across a
    save and a reload, and none of them collapses into another."""
    pack, _ = build_fact_pack(CORPUS)
    findings = (
        rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack)
    )
    assert findings, "the corpus should produce findings for this to mean anything"

    current = snapshot(findings, pack)
    diff = compare(current, current)
    assert diff.new == []
    assert diff.fixed == []
    assert len(diff.unchanged) == len(findings)


def test_the_corpus_baseline_survives_a_save_and_reload(tmp_path: Path) -> None:
    pack, _ = build_fact_pack(CORPUS)
    findings = rules.evaluate(pack) + timer_rules.analyse(pack)
    path = tmp_path / "baseline.json"
    save(findings, pack, path)

    diff = compare(load(path), snapshot(findings, pack))
    assert diff.new == []
    assert diff.fixed == []


def test_a_finding_that_names_no_object_is_identified_by_rule_and_device() -> None:
    """Coarse on purpose: there is nothing here to tell two of them apart, and
    inventing a difference would be worse than counting them."""
    vague = Finding(
        rule="some-rule",
        tier=Tier.FACTS,
        severity=Severity.LOW,
        device="agg-a",
        title="this network has a problem",
        detail="no object is named anywhere in this finding",
    )
    assert identity(vague) == ("some-rule", "agg-a", ())


def test_an_unwritable_baseline_path_is_an_error_not_a_traceback(
    tmp_path: Path,
) -> None:
    blocked = tmp_path / "file"
    blocked.write_text("not a directory\n")
    with pytest.raises(BaselineError) as raised:
        save([BFD_ONE], pack_of("agg-a"), blocked / "baseline.json")
    assert "cannot write baseline" in str(raised.value)


def test_a_diff_cites_the_same_source_a_check_does(tmp_path: Path) -> None:
    """A diff and a check describing one finding differently is a difference
    someone will read as meaning something."""
    from cassandra.app import analyse

    examples = Path(__file__).resolve().parents[1] / "examples" / "two-site"
    result = analyse(examples)
    cited = [f for f in result.findings if f.source and f.source.line]
    assert cited, "the example corpus should place at least one finding"

    diff = Diff(
        new=cited[:1],
        fixed=[],
        unchanged=[],
        baseline_digest="a",
        current_digest="b",
        baseline_taken_at=datetime.now(UTC),
    )
    rendered = render_diff(diff, explain=True)
    assert f"source: {cited[0].source}" in rendered
    assert "source:" not in render_diff(diff), "not in the default view"


# --------------------------------------------------------------------------
# Which checks produced the baseline
# --------------------------------------------------------------------------


def test_a_baseline_records_the_rule_set_that_produced_it(tmp_path: Path) -> None:
    """Without it the footer points the reader at exactly the wrong place.

    A run against unchanged configs after the rule set has grown reports the new
    findings as a regression, and says the configs did not change — so the
    reader goes looking at a network that did nothing. This tool went from
    forty-one checks to forty-eight in one day; anybody holding a morning
    baseline would have spent the afternoon on it.
    """
    pack = pack_of("agg-a", "agg-b")
    recorded = tmp_path / "base.json"
    baseline.save([], pack, recorded)
    document = json.loads(recorded.read_text())
    assert document["rules_digest"] == baseline.rules_digest()
    assert baseline.load(recorded).rules == baseline.rules_digest()


def test_the_digest_moves_with_the_rule_set_and_not_with_its_prose() -> None:
    """Built from each rule's id, tier and severity, and nothing else.

    Those decide whether a finding appears and how it is ranked. Hashing the
    source instead would move the digest on every reworded docstring, the
    warning would fire on every commit, and a warning that always fires is one
    nobody reads.
    """
    from cassandra import catalogue as catalogue_module

    unchanged = baseline.rules_digest()
    assert unchanged == baseline.rules_digest()
    assert len(unchanged) == 12

    real = catalogue_module.catalogue()
    trimmed = real[:-1]
    with mock.patch.object(catalogue_module, "catalogue", lambda: trimmed):
        assert baseline.rules_digest() != unchanged

    reworded = [replace(real[0], summary="something else entirely"), *real[1:]]
    with mock.patch.object(catalogue_module, "catalogue", lambda: reworded):
        assert baseline.rules_digest() == unchanged


def test_a_diff_says_when_the_checks_moved(tmp_path: Path) -> None:
    """ "The configs changed" invites a reader to blame the network for every new
    finding, and that is wrong whenever the rule set moved underneath too."""
    pack = pack_of("agg-a", "agg-b")
    recorded = tmp_path / "base.json"
    baseline.save([], pack, recorded)
    before = baseline.load(recorded)

    same = baseline.compare(before, baseline.snapshot([], pack))
    assert same.rules_known
    assert not same.rules_changed

    moved = baseline.compare(
        replace(before, rules="deadbeef1234"), baseline.snapshot([], pack)
    )
    assert moved.rules_changed
    assert "checks also changed" in baseline.render_diff(moved, explain=False)


def test_a_baseline_written_before_the_field_says_it_cannot_tell(
    tmp_path: Path,
) -> None:
    """Absent is not "unchanged". A baseline written before this tool recorded
    the rule set cannot testify about it, and claiming it did not move would be
    inventing evidence — which is the failure this whole field exists to fix."""
    pack = pack_of("agg-a", "agg-b")
    recorded = tmp_path / "base.json"
    baseline.save([], pack, recorded)
    document = json.loads(recorded.read_text())
    del document["rules_digest"]
    document["version"] = 1
    recorded.write_text(json.dumps(document))

    old = baseline.load(recorded)
    assert old.rules == ""
    diff = baseline.compare(old, baseline.snapshot([], pack))
    assert not diff.rules_known
    assert not diff.rules_changed, "absent must not read as changed either"
    assert "predates" in baseline.render_diff(diff, explain=False)
