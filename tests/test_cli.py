"""The `cassandra` command, end to end on the corpus."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Final
from xml.etree import ElementTree

import pytest

from cassandra.catalogue import catalogue
from cassandra.cli import main, render_facts
from cassandra.factpack.builders import build_fact_pack

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
        "fhrp VRRP 14 virtual=10.14.0.1",
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
        "hostname r\ninterface Ethernet1\n   vrrp 14 bfd ip 10.14.0.3\n"
    )
    main(["facts", str(tmp_path)])
    out = capsys.readouterr().out
    assert "unparsed" in out
    assert "vrrp 14 bfd ip 10.14.0.3" in out


def test_missing_directory_is_an_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["facts", "/nonexistent"]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_empty_directory_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["facts", str(tmp_path)]) == 2
    assert "reads like a device config" in capsys.readouterr().err


# A pair whose only defect is a tie for the top priority: one medium finding and
# nothing worse. Enough to tell "found nothing" from "found nothing that blocks".
TIED_PAIR: Final = """hostname {name}
vlan 14
interface Vlan14
   ip address 10.14.0.{host}/24
   vrrp 14 ip 10.14.0.1
   vrrp 14 priority 100
"""


@pytest.fixture
def tied(tmp_path: Path) -> Path:
    for index, name in enumerate(("agg-a", "agg-b"), start=2):
        (tmp_path / f"{name}.cfg").write_text(TIED_PAIR.format(name=name, host=index))
    return tmp_path


def test_fail_on_narrows_the_verdict_without_narrowing_the_report(
    tied: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pipeline that blocks only on high still wants the rest printed.

    Otherwise the way to get a green build is to stop looking, which is how a
    check gets switched off.
    """
    assert main(["check", str(tied)]) == 1
    assert main(["check", str(tied), "--fail-on", "high"]) == 0
    printed = capsys.readouterr().out
    assert "fhrp-priority-tie" not in printed  # not without --explain
    assert "no preferred master" in printed


def test_fail_on_at_or_below_the_worst_finding_still_fails(tied: Path) -> None:
    assert main(["check", str(tied), "--fail-on", "medium"]) == 1
    assert main(["check", str(tied), "--fail-on", "low"]) == 1
    assert main(["check", str(tied), "--fail-on", "info"]) == 1


def test_fail_on_rejects_a_severity_that_does_not_exist(tied: Path) -> None:
    """A typo must not quietly become 'never fail'."""
    with pytest.raises(SystemExit) as exit_info:
        main(["check", str(tied), "--fail-on", "critical"])
    assert exit_info.value.code == 2


def test_rules_lists_every_check(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 0
    printed = capsys.readouterr().out
    for rule_id in {doc.id for doc in catalogue()}:
        assert rule_id in printed


def test_rules_explains_one_check(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules", "fhrp-divergence"]) == 0
    printed = capsys.readouterr().out
    assert "fhrp-divergence" in printed
    assert "stays silent when" in printed


def test_rules_rejects_a_name_that_is_not_a_rule(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Mistyping a rule id is a user error, not a result. It must not exit 0."""
    assert main(["rules", "fhrp-divergance"]) == 2
    assert "no such rule" in capsys.readouterr().err


def test_check_says_how_much_it_did_not_understand(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Findings derived from a partial reading must not read as complete ones."""
    (tmp_path / "odd1.cfg").write_text(
        "hostname odd1\n"
        "interface Ethernet1\n"
        "   no switchport\n"
        "   ip address 10.0.0.1/31\n"
        "   some-feature that-nobody-parses\n"
    )
    main(["check", str(tmp_path)])
    assert "were not understood" in capsys.readouterr().err


def test_check_is_quiet_when_it_read_everything(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main(["check", str(CORPUS)])
    assert "not understood" not in capsys.readouterr().err


def test_facts_json_is_the_whole_pack(capsys: pytest.CaptureFixture[str]) -> None:
    """Handing out the fact pack whole is how someone checks the tool's reading
    of their configs against their own — the only way to catch a parser that is
    quietly wrong rather than quietly silent."""
    assert main(["facts", str(CORPUS), "--json"]) == 0
    pack = json.loads(capsys.readouterr().out)
    assert sorted(pack) == [
        "devices",
        "fhrp_groups",
        "meta",
        "timers",
        "unparsed",
        "vlans",
    ]
    assert {d["id"] for d in pack["devices"]} == {"acc1", "agg-a", "agg-b", "core1"}
    assert len(pack["fhrp_groups"]) == 3
    assert pack["meta"]["config_digest"]
    assert pack["unparsed"] == {}, "the shipped corpus must be read completely"


def test_facts_json_carries_the_digest_that_produced_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A fact pack that cannot be tied back to the configs it came from cannot
    be checked against them later."""
    main(["facts", str(CORPUS), "--json"])
    first = json.loads(capsys.readouterr().out)
    main(["facts", str(CORPUS), "--json"])
    second = json.loads(capsys.readouterr().out)
    assert first["meta"]["config_digest"] == second["meta"]["config_digest"]


def test_report_since_marks_new_findings_and_judges_only_those(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With a baseline the verdict is the regression, not the backlog."""
    configs = tmp_path / "configs"
    shutil.copytree(CORPUS, configs)
    base = tmp_path / "base.json"
    assert main(["check", str(configs), "--save-baseline", str(base)]) == 1
    capsys.readouterr()

    out = tmp_path / "same.html"
    assert main(["report", str(configs), "-o", str(out), "--since", str(base)]) == 0
    body = out.read_text()
    assert "Compared with a baseline taken" in body
    assert "state new" not in body

    config = configs / "agg-a.cfg"
    config.write_text(config.read_text().replace("decrement 40", "decrement 5", 1))
    changed = tmp_path / "changed.html"
    assert main(["report", str(configs), "-o", str(changed), "--since", str(base)]) == 1
    assert "1 new" in changed.read_text()


def test_report_since_refuses_a_baseline_it_cannot_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "r.html"
    assert main(["report", str(CORPUS), "-o", str(out), "--since", "/nope.json"]) == 2
    assert "nope.json" in capsys.readouterr().err
    assert not out.exists(), "a report nobody asked for should not be written"


def test_serve_refuses_a_directory_that_is_not_there(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Failing at the point of the mistake beats binding a socket and waiting for
    someone to notice the page is empty."""
    assert main(["serve", "/definitely/not/here"]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_serve_prints_a_link_that_already_has_the_directory_in_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The directory is a query string like any other, so the running server
    needs to know nothing about it — the link carries it."""
    started: dict[str, object] = {}

    def fake_serve(**kwargs: object) -> None:
        started.update(kwargs)
        print(f"cassandra: http://127.0.0.1:8765/?dir={kwargs['config_dir']}")

    monkeypatch.setattr("cassandra.cli.serve", fake_serve)
    assert main(["serve", str(CORPUS)]) == 0
    assert started["config_dir"] == CORPUS
    assert str(CORPUS) in capsys.readouterr().out


def test_check_format_sarif_is_a_log_a_scanner_can_ingest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Stdout has to be the log and nothing else — a pipeline pipes it into a
    file and hands it to an upload step that will not tolerate a note in it."""
    assert main(["check", str(CORPUS), "--format", "sarif"]) == 1
    log = json.loads(capsys.readouterr().out)
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["results"], "the corpus must produce results"
    located = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert located["artifactLocation"]["uri"].startswith(str(CORPUS))


def test_check_format_junit_marks_an_inert_check_skipped(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The whole reason for this format: a check that never ran must not be
    counted as a check that passed."""
    assert main(["check", str(CORPUS), "--format", "junit"]) == 1
    suites = ElementTree.fromstring(capsys.readouterr().out)
    cases = list(suites.iter("testcase"))
    assert len(cases) == len(catalogue())
    assert any(case.find("skipped") is not None for case in cases)
    assert int(suites.get("skipped") or 0) > 0


def test_format_json_is_what_the_json_flag_always_meant(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main(["check", str(CORPUS), "--json"])
    flag = capsys.readouterr().out
    main(["check", str(CORPUS), "--format", "json"])
    assert capsys.readouterr().out == flag


def test_check_rejects_a_format_that_does_not_exist() -> None:
    """A typo must not quietly fall back to text and be piped into a parser."""
    with pytest.raises(SystemExit) as exit_info:
        main(["check", str(CORPUS), "--format", "sarrif"])
    assert exit_info.value.code == 2


def test_coverage_beside_a_machine_format_stays_out_of_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["check", str(CORPUS), "--format", "sarif", "--coverage"]) == 1
    printed = capsys.readouterr()
    json.loads(printed.out)
    assert "coverage:" in printed.err


def test_facts_prints_every_timer_family_the_pack_holds(tmp_path: Path) -> None:
    """`facts` is documented as the materialised fact pack, so a family that is
    in the pack and not in the output is the output lying by omission.

    It printed one heading, `timers`, holding only the FHRP records — for long
    enough that BGP and spanning-tree timing could be read into the pack, checked
    by four rules and reported on, while the command that exists to show what was
    read said the pack had none of it. The families are rendered from a table
    rather than one block each so that a family added to the schema and filled by
    a builder cannot go missing here the same way twice.
    """
    (tmp_path / "sw1.cfg").write_text(
        "hostname sw1\n"
        "!\n"
        "vlan 10\n"
        "!\n"
        "spanning-tree mode rapid-pvst\n"
        "spanning-tree hello-time 2000\n"
        "spanning-tree forward-time 15\n"
        "spanning-tree max-age 20\n"
        "!\n"
        "interface Ethernet1\n"
        "   no switchport\n"
        "   ip address 198.51.100.1/31\n"
        "   ip ospf hello-interval 5\n"
        "   ip ospf dead-interval 20\n"
        "!\n"
        "router bgp 64512\n"
        "   router-id 198.51.100.1\n"
        "   timers bgp 10 30\n"
        "   graceful-restart restart-time 300\n"
        "   graceful-restart stalepath-time 150\n"
        "   neighbor 198.51.100.0 remote-as 64513\n"
        "!\n"
    )
    pack, unparsed = build_fact_pack(tmp_path)
    rendered = render_facts(pack, unparsed)

    assert pack.timers.stp and pack.timers.bgp and pack.timers.igp_hello
    for heading in ("stp timers", "bgp timers", "igp hello timers"):
        assert heading in rendered, f"the pack holds {heading} and nothing prints them"
    # The bare heading was the other half of the problem: it named the section
    # after every timer and showed one family.
    assert "\ntimers\n" not in rendered
    assert "fhrp timers" in rendered or not pack.timers.fhrp
    assert "restart-time=300s" in rendered
    assert "max-age=20000ms" in rendered
    assert "vlans" in rendered
    assert "bgp sw1  as=64512" in rendered


def test_facts_omits_a_timer_the_config_does_not_state(tmp_path: Path) -> None:
    """A value the config never set and a value this tool could not read look
    identical in a dump that prints `None` for both, and telling them apart is
    the entire subject of the coverage report."""
    (tmp_path / "sw1.cfg").write_text(
        "hostname sw1\n"
        "!\n"
        "interface Ethernet1\n"
        "   no switchport\n"
        "   ip address 198.51.100.1/31\n"
        "   ip ospf hello-interval 5\n"
        "!\n"
    )
    pack, unparsed = build_fact_pack(tmp_path)
    rendered = render_facts(pack, unparsed)
    assert "hello=5000ms" in rendered
    assert "None" not in rendered
    assert "dead=" not in rendered


def test_the_help_text_names_the_commands_that_exist() -> None:
    """The description argparse prints above the subcommand list came from the
    module docstring, and the docstring still said the tool provided `facts`
    only and that something called `analyze` was coming. Neither was true, and
    the contradicting list was three lines below it on every `--help`."""
    from cassandra import cli

    described = cli.__doc__ or ""
    assert "analyze" not in described
    assert "Phase 1" not in described
    for command in ("facts", "check", "report", "rules", "serve"):
        assert command in described


def test_facts_says_whether_preempt_was_written_down(tmp_path: Path) -> None:
    """`preempt=yes` for a flag somebody typed and for one the protocol
    supplied is one word covering two situations.

    They are the same yes to a rule that reads the flag and two different things
    to be looking at when a group is not where the priorities say it should be,
    so the pack carries the provenance and this prints it.
    """
    (tmp_path / "dist-1.cfg").write_text(
        "hostname dist-1\n!\nvlan 14\n!\ninterface Vlan14\n"
        " ip address 198.51.100.2 255.255.255.0\n"
        " standby 14 ip 198.51.100.1\n"
        " standby 14 priority 120\n!\n"
    )
    (tmp_path / "dist-2.cfg").write_text(
        "hostname dist-2\n!\nvlan 14\n!\ninterface Vlan14\n"
        " ip address 198.51.100.3 255.255.255.0\n"
        " standby 14 ip 198.51.100.1\n"
        " standby 14 priority 100\n"
        " standby 14 preempt\n!\n"
    )
    pack, unparsed = build_fact_pack(tmp_path)
    rendered = render_facts(pack, unparsed)
    assert "preempt=no(platform-default)" in rendered
    # The one that was written down carries no qualifier: the unadorned form is
    # the configuration, and every annotation on it is something this tool
    # supplied.
    assert "preempt=yes\n" in rendered or "preempt=yes " in rendered
    assert "preempt=yes(" not in rendered


def test_facts_omits_a_timer_family_that_states_nothing(tmp_path: Path) -> None:
    """A record whose every printed value is unset says only that the parser
    ran, and a heading over a list of scopes with nothing beside them reads as
    a family this tool failed at rather than one nobody configured."""
    (tmp_path / "dist-1.cfg").write_text(
        "hostname dist-1\n!\nvlan 14\n!\ninterface Vlan14\n"
        " ip address 198.51.100.2 255.255.255.0\n"
        " standby 14 ip 198.51.100.1\n"
        " standby 14 priority 120\n!\n"
    )
    pack, unparsed = build_fact_pack(tmp_path)
    assert pack.timers.fhrp, "the fixture no longer exercises the case"
    assert not any(timer.hello_interval_ms for timer in pack.timers.fhrp)
    rendered = render_facts(pack, unparsed)
    assert "fhrp timers" not in rendered
    assert "no timers in these configs" in rendered
