"""The CI formats, held to the corpus a reader can run for themselves.

Two properties carry most of the weight. Every finding must survive the trip
into either format — a report that drops one is worse than no report, because
the build goes green — and both must be byte-identical across two runs, since a
file that changes on every run cannot be diffed and stops being worth keeping.

The rest is structure: SARIF a code scanning ingest would accept, a location for
every result including the ones with no line and the ones with no file, and the
inert-to-skipped mapping that is the reason the JUnit format exists at all.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path
from typing import Any, Final

import pytest

from cassandra import coverage, exchange
from cassandra.catalogue import catalogue
from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack
from cassandra.facts import rules
from cassandra.findings import Finding, Severity, SourceRef, Tier, locate, rank
from cassandra.timing import sequences, timer_rules

CORPUS: Final = Path(__file__).resolve().parents[1] / "examples" / "two-site"
# Read from the module rather than written out. The key is versioned precisely
# so it can move when the identity improves, and a test that pins the literal
# turns every such improvement into a test edit that says nothing.
FINGERPRINT: Final = exchange._FINGERPRINT_KEY


@pytest.fixture(scope="module")
def pack() -> StaticFactPack:
    built, _ = build_fact_pack(CORPUS)
    return built


@pytest.fixture(scope="module")
def findings(pack: StaticFactPack) -> list[Finding]:
    """Every tier, in the order `cassandra check` runs them, `locate` included.

    Located, because the citation is what a SARIF result is built out of; a
    fixture that skipped it would be testing a shape the CLI never produces.
    """
    return locate(
        rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack),
        pack,
    )


@pytest.fixture(scope="module")
def assessed(pack: StaticFactPack) -> tuple[coverage.RuleCoverage, ...]:
    return coverage.assess(pack)


@pytest.fixture(scope="module")
def run(findings: list[Finding]) -> dict[str, Any]:
    log = json.loads(exchange.sarif(findings, base="examples/two-site"))
    assert log["version"] == "2.1.0"
    return log["runs"][0]


@pytest.fixture(scope="module")
def suites(
    findings: list[Finding], assessed: tuple[coverage.RuleCoverage, ...]
) -> ET.Element:
    return ET.fromstring(exchange.junit(findings, assessed))


def _cases(suites: ET.Element) -> dict[str, ET.Element]:
    return {case.get("name", ""): case for case in suites.iter("testcase")}


def _fingerprint(finding: Finding) -> str:
    """The fingerprint as a reader of the file would find it."""
    log = json.loads(exchange.sarif([finding]))
    prints = log["runs"][0]["results"][0]["partialFingerprints"]
    return str(prints[FINGERPRINT])


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------


def test_the_log_is_a_single_sarif_run(findings: list[Finding]) -> None:
    log = json.loads(exchange.sarif(findings))
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(log["runs"]) == 1
    assert log["runs"][0]["tool"]["driver"]["name"] == "cassandra"
    assert log["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_every_rule_is_described_from_the_catalogue(run: dict[str, Any]) -> None:
    """The descriptors are the catalogue, not a second copy of it.

    A hand-written list would be right until the first rule someone adds, so
    what is asserted is that the descriptor set *is* the catalogue and that each
    entry carries that rule's own prose.
    """
    docs = catalogue()
    described = run["tool"]["driver"]["rules"]
    assert [entry["id"] for entry in described] == [doc.id for doc in docs]
    for doc, entry in zip(docs, described, strict=True):
        assert doc.summary is not None, f"{doc.id} lost its docstring"
        assert entry["shortDescription"]["text"] == doc.summary
        assert doc.summary in entry["fullDescription"]["text"]
        assert entry["defaultConfiguration"]["level"] in {"error", "warning", "note"}
        assert entry["properties"]["tier"] == doc.tier.value
        # The silence notes are what tell a reader whether this rule reporting
        # nothing about the rest of their configs means anything.
        assert "Stays silent when:" in entry["help"]["text"]
        for note in doc.silence:
            assert note.source in entry["help"]["text"]


def test_a_result_points_back_at_the_rule_that_produced_it(
    run: dict[str, Any],
) -> None:
    described = run["tool"]["driver"]["rules"]
    assert run["results"], "the example corpus must produce findings"
    for result in run["results"]:
        assert described[result["ruleIndex"]]["id"] == result["ruleId"]


def test_every_finding_survives_as_a_result(
    findings: list[Finding], run: dict[str, Any]
) -> None:
    """Nothing may be dropped, and nothing a finding carries may be lost.

    `evidence`, `trigger`, `remedy` and `change` are the parts a reader acts on;
    a result that kept only the title would turn a finding into an assertion
    nobody can check.
    """
    results = run["results"]
    assert len(results) == len(findings)
    assert len({result["partialFingerprints"][FINGERPRINT] for result in results}) == (
        len(findings)
    ), "two findings share one fingerprint and would be reported as one"

    for finding, result in zip(rank(findings), results, strict=True):
        assert result["ruleId"] == finding.rule
        message = result["message"]["text"]
        assert finding.title in message
        assert finding.detail in message
        for item in (finding.trigger, finding.remedy, *finding.evidence):
            assert item is None or item in message
        for line in finding.change:
            assert line in message
        properties = result["properties"]
        assert properties["device"] == finding.device
        assert properties["evidence"] == list(finding.evidence)
        assert properties["change"] == list(finding.change)
        assert properties["trigger"] == finding.trigger
        assert properties["remedy"] == finding.remedy


def test_no_result_offers_an_autofix(run: dict[str, Any]) -> None:
    """`change` is lines to type, sometimes on another device — not a patch.

    `bgp-session-one-sided` is located on the device that has the neighbor
    statement, and its change is typed on the device that does not; a fix built
    from it would edit the wrong file. Deliberately absent, and this fails if
    one is added without that being revisited.
    """
    assert not any("fixes" in result for result in run["results"])
    change = next(
        result
        for result in run["results"]
        if result["ruleId"] == "bgp-session-one-sided"
    )["properties"]["change"]
    assert change, "the finding this reasoning rests on has stopped carrying a change"


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ],
)
def test_severity_becomes_the_matching_sarif_level(
    severity: Severity, level: str
) -> None:
    finding = Finding(
        rule="fhrp-no-redundancy",
        tier=Tier.FACTS,
        severity=severity,
        device="agg-a",
        title="t",
        detail="d",
        source=SourceRef(file="agg-a.cfg", line=3),
    )
    log = json.loads(exchange.sarif([finding]))
    assert log["runs"][0]["results"][0]["level"] == level


def test_a_finding_with_a_line_is_annotated_on_it(run: dict[str, Any]) -> None:
    physical = next(
        result["locations"][0]["physicalLocation"]
        for result in run["results"]
        if result["ruleId"] == "access-vlan-not-trunked"
    )
    assert physical["artifactLocation"]["uri"] == (
        "examples/two-site/north/north-acc1.cfg"
    )
    assert physical["region"]["startLine"] == 24


def test_a_finding_with_no_line_keeps_the_file_and_invents_no_region(
    run: dict[str, Any],
) -> None:
    """A made-up line sends a reader to configuration that is not the finding."""
    physical = next(
        result["locations"][0]["physicalLocation"]
        for result in run["results"]
        if result["ruleId"] == "bgp-session-one-sided"
    )
    assert physical["artifactLocation"]["uri"].endswith("edge/edge1.cfg")
    assert "region" not in physical


def test_a_finding_with_no_source_falls_back_to_the_invocation() -> None:
    """SARIF requires a location; a path the tool made up is not one."""
    finding = Finding(
        rule="fhrp-no-redundancy",
        tier=Tier.FACTS,
        severity=Severity.MEDIUM,
        device="nowhere",
        title="a device the fact pack could not place",
        detail="d",
    )
    run = json.loads(exchange.sarif([finding], base="configs"))["runs"][0]
    physical = run["results"][0]["locations"][0]["physicalLocation"]
    assert (
        physical["artifactLocation"]["uri"]
        == (run["invocations"][0]["workingDirectory"]["uri"])
    )
    assert "region" not in physical


def test_uris_resolve_from_where_the_command_was_run(findings: list[Finding]) -> None:
    """A finding's file is relative to the directory checked and an annotation
    is relative to the repository; the two agree only once the directory the
    user typed is put back in front."""
    log = json.loads(exchange.sarif(findings, base="./examples/two-site"))
    uris = {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in log["runs"][0]["results"]
    }
    assert uris == {
        "examples/two-site/edge/edge1.cfg",
        "examples/two-site/north/north-acc1.cfg",
        "examples/two-site/north/north-agg1.cfg",
        "examples/two-site/south/south-agg1.cfg",
    }
    for uri in uris:
        assert (Path(__file__).resolve().parents[1] / uri).is_file()


def test_a_fingerprint_does_not_move_when_the_lines_do() -> None:
    """The whole point of the fingerprint: an edit above a finding must not
    re-report it as new, and two different findings must not merge into one."""
    base = Finding(
        rule="fhrp-oscillation",
        tier=Tier.TIMING,
        severity=Severity.MEDIUM,
        device="agg-a",
        title="VRRP 14 changes master 5 times under a single flap sequence",
        detail="this group has no preempt delay",
        source=SourceRef(file="agg-a.cfg", line=12),
    )
    moved = replace(base, source=SourceRef(file="agg-a.cfg", line=310))
    reworded = replace(base, detail="it follows the interface immediately")
    assert _fingerprint(base) == _fingerprint(moved)
    assert _fingerprint(base) == _fingerprint(reworded)

    other_group = replace(
        base, title="VRRP 24 changes master 5 times under a single flap sequence"
    )
    assert _fingerprint(base) != _fingerprint(other_group)
    assert _fingerprint(base) != _fingerprint(replace(base, device="agg-b"))
    assert _fingerprint(base) != _fingerprint(replace(base, rule="fhrp-divergence"))


def test_sarif_is_byte_identical_across_two_runs(findings: list[Finding]) -> None:
    first = exchange.sarif(findings, base="examples/two-site", digest="abc")
    second = exchange.sarif(findings, base="examples/two-site", digest="abc")
    assert first == second
    assert "timestamp" not in first.lower()
    assert "startTimeUtc" not in first


# --------------------------------------------------------------------------
# JUnit
# --------------------------------------------------------------------------


def test_one_testcase_per_rule_whatever_it_did(
    suites: ET.Element, assessed: tuple[coverage.RuleCoverage, ...]
) -> None:
    """A rule that found nothing still has to appear, or the suite shrinks as
    the network improves and a CI dashboard reads that as tests disappearing."""
    cases = _cases(suites)
    assert set(cases) == {entry.rule for entry in assessed}
    assert len(cases) == len(assessed)
    assert suites.get("tests") == str(len(assessed))


def test_a_rule_that_fired_is_a_failure_carrying_every_finding(
    suites: ET.Element, findings: list[Finding]
) -> None:
    cases = _cases(suites)
    for finding in findings:
        failure = cases[finding.rule].find("failure")
        assert failure is not None, f"{finding.rule} fired but did not fail"
        assert failure.text is not None
        assert finding.title in failure.text
        assert finding.detail in failure.text
        assert str(finding.source) in failure.text
        for item in (finding.trigger, finding.remedy, *finding.evidence):
            assert item is None or item in failure.text
        for line in finding.change:
            assert line in failure.text

    fired = {finding.rule for finding in findings}
    failed = {name for name, case in cases.items() if case.find("failure") is not None}
    assert failed == fired
    assert suites.get("failures") == str(len(fired))


def test_two_findings_from_one_rule_are_one_case_that_says_so(
    suites: ET.Element, findings: list[Finding]
) -> None:
    """The corpus trips `fhrp-oscillation` twice, on VRRP 10 and on VRRP 20."""
    oscillation = [f for f in findings if f.rule == "fhrp-oscillation"]
    assert len(oscillation) == 2
    failure = _cases(suites)["fhrp-oscillation"].find("failure")
    assert failure is not None
    assert "and 1 more" in (failure.get("message") or "")
    assert failure.text is not None
    for finding in oscillation:
        assert finding.title in failure.text


def test_an_inert_rule_is_skipped_with_the_reason_it_was_inert(
    suites: ET.Element, assessed: tuple[coverage.RuleCoverage, ...]
) -> None:
    """The distinction the whole coverage feature exists to draw, put where a
    CI report already renders it."""
    quiet = coverage.inert(assessed)
    assert quiet, "the example corpus must leave some checks with no input"
    cases = _cases(suites)
    for entry in quiet:
        skipped = cases[entry.rule].find("skipped")
        assert skipped is not None, f"{entry.rule} was inert but is not skipped"
        assert skipped.get("message") == entry.reason
    marked = {name for name, case in cases.items() if case.find("skipped") is not None}
    assert marked == {entry.rule for entry in quiet}
    assert suites.get("skipped") == str(len(quiet))


def test_a_rule_that_ran_and_found_nothing_is_a_pass(
    suites: ET.Element, assessed: tuple[coverage.RuleCoverage, ...]
) -> None:
    cases = _cases(suites)
    clean = [entry for entry in assessed if entry.applicable and not entry.findings]
    assert clean, "the example corpus must leave some checks satisfied"
    for entry in clean:
        assert list(cases[entry.rule]) == [], f"{entry.rule} passed but is marked"


def test_suite_counts_add_up_to_the_file(suites: ET.Element) -> None:
    for attribute in ("tests", "failures", "skipped"):
        total = sum(int(suite.get(attribute) or 0) for suite in suites)
        assert suites.get(attribute) == str(total)
    assert suites.get("errors") == "0"


def test_a_finding_whose_rule_was_not_assessed_still_appears() -> None:
    """Should never happen — and if it does, the finding must not vanish."""
    finding = Finding(
        rule="rule-nobody-assessed",
        tier=Tier.TIMING,
        severity=Severity.HIGH,
        device="agg-a",
        title="something the coverage module never reported on",
        detail="d",
    )
    suites = ET.fromstring(exchange.junit([finding], ()))
    assert _cases(suites)["rule-nobody-assessed"].find("failure") is not None
    assert suites.get("tests") == "1"
    assert suites.get("failures") == "1"


def test_junit_is_byte_identical_across_two_runs(
    findings: list[Finding], assessed: tuple[coverage.RuleCoverage, ...]
) -> None:
    first = exchange.junit(findings, assessed)
    second = exchange.junit(findings, assessed)
    assert first == second
    assert "time=" not in first, "a duration measures the machine, not the network"


def test_junit_declares_an_encoding_that_covers_the_prose(
    findings: list[Finding], assessed: tuple[coverage.RuleCoverage, ...]
) -> None:
    """The messages contain em dashes. A parser left to assume ASCII fails on
    the whole file rather than on the one finding that carries them."""
    document = exchange.junit(findings, assessed)
    assert document.startswith('<?xml version="1.0" encoding="UTF-8"?>\n')
    assert ET.fromstring(document.encode()).tag == "testsuites"


def test_sarif_carries_the_rule_set_beside_the_configs(
    findings: list[Finding],
) -> None:
    """Two uploads that differ mean nothing until a reader knows which moved.

    The config digest answers half of it. Without the rule set, an upload made
    after a check was added looks exactly like one made after the network
    changed, and code scanning will show the new annotation either way.
    """
    from cassandra import baseline

    document = json.loads(
        exchange.sarif(findings, base=str(CORPUS), pack_id="fp_x", digest="d" * 64)
    )
    properties = document["runs"][0]["properties"]
    assert properties["rulesDigest"] == baseline.rules_digest()
    assert properties["configDigest"] == "d" * 64


def test_a_dual_stack_group_does_not_share_one_fingerprint() -> None:
    """`VRRP 14` and `VRRP 14 IPv6` are two groups, and the identity said one.

    `assemble_fhrp_groups` gives them separate ids precisely because they are
    separate elections, and the number alone cannot tell them apart. A consumer
    keyed on (ruleId, fingerprint) — which is how code scanning establishes
    alert identity — saw one alert where the tool found two.

    On `examples/xr-metro` rather than the corpus the rest of this file uses:
    two-site has no dual-stack group, so the existing uniqueness assertion
    passed on a fixture that could not contain the case.
    """
    dual_stack = Path(__file__).resolve().parents[1] / "examples" / "xr-metro"
    pack, _ = build_fact_pack(dual_stack)
    found = locate(
        rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack),
        pack,
    )
    labels = {group.label for group in pack.fhrp_groups}
    assert {"VRRP 14", "VRRP 14 IPv6"} <= labels, "the fixture lost the case"

    document = json.loads(
        exchange.sarif(found, base=str(dual_stack), pack_id="fp", digest="d" * 64)
    )
    keyed = [
        (result["ruleId"], *result["partialFingerprints"].values())
        for result in document["runs"][0]["results"]
    ]
    assert len(set(keyed)) == len(keyed), "two results would arrive as one alert"


def test_the_family_qualifier_reaches_the_identity() -> None:
    """Asserted on `identity` itself, not only through SARIF: the collision was
    in the identity, and `check --since` reads the same function."""
    from cassandra.baseline import identity

    def sample(title: str) -> Finding:
        return Finding(
            rule="fhrp-oscillation",
            tier=Tier.TIMING,
            severity=Severity.MEDIUM,
            device="metro-a",
            title=title,
            detail="",
        )

    v4 = identity(sample("VRRP 14 changes master 5 times"))
    v6 = identity(sample("VRRP 14 IPv6 changes master 5 times"))
    assert v4 != v6
    # The IPv4 side keeps the references it had, so its fingerprint is stable
    # across this change and only the qualified ones move.
    assert set(v4[2]) <= set(v6[2])
