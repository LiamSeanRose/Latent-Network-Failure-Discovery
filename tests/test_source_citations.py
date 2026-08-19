"""A finding has to say which configuration it is about (PROJECT.md §5.4).

Three things are pinned here. That every device carries the file it was parsed
from, relative to the directory that was checked. That an interface, a VLAN
declaration and an FHRP group each carry the line they start on, and that a
banner earlier in the file does not shift them. And that citing all of this
changes neither the fact pack's identity nor a finding's — a saved baseline that
matched before must still match, or the first run after this change reads as a
wall of new findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

import pytest

from cassandra import baseline
from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack
from cassandra.facts import rules
from cassandra.findings import Finding, Severity, SourceRef, Tier, locate
from cassandra.report import as_json, render
from cassandra.timing import sequences, timer_rules

EXAMPLES: Final = Path(__file__).resolve().parents[1] / "examples" / "two-site"
SITE14: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)

# The digest is what ties a finding to a revision of the configs, and it is read
# from the config text alone. Carrying the path and the line must not move it, so
# both shipped corpora are pinned by value rather than by construction.
EXAMPLES_DIGEST: Final = (
    "cd6b8292e4ebeef2f3c9dddfb8f2661641448c09628b36788a3c8c63f0981269"
)
SITE14_DIGEST: Final = (
    "93f0bf2e6a7aa87d4b883b7f148138783defba0d0ebbd70c6878fb3d93af45a8"
)

IOS: Final = """hostname branch1
!
vlan 30
!
interface GigabitEthernet0/1
 ip address 10.30.0.2 255.255.255.0
 standby 30 ip 10.30.0.1
 standby 30 priority 110
 standby 30 preempt
!
end
"""

NXOS: Final = """hostname spine1
feature hsrp
!
vlan 40
!
interface Vlan40
  ip address 10.40.0.2/24
  hsrp 40
    ip 10.40.0.1
    priority 110
    preempt
!
"""

BANNERED: Final = """hostname agg-x
!
banner motd
this line is prose
so is this one
EOF
!
vlan 50
!
interface Vlan50
   ip address 10.50.0.2/24
   vrrp 50 ipv4 10.50.0.1
!
"""


@pytest.fixture(scope="module")
def examples() -> StaticFactPack:
    pack, _ = build_fact_pack(EXAMPLES)
    return pack


def evaluate(pack: StaticFactPack) -> list[Finding]:
    """Every tier, in the order `cassandra check` runs them."""
    return rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack)


def device(pack: StaticFactPack, name: str) -> object:
    return next(d for d in pack.devices if d.id == name)


def built(text: str, tmp_path: Path, name: str = "device.cfg") -> StaticFactPack:
    (tmp_path / name).write_text(text)
    pack, _ = build_fact_pack(tmp_path)
    return pack


# --------------------------------------------------------------------------
# Device -> file
# --------------------------------------------------------------------------


def test_every_device_names_the_file_it_was_parsed_from(
    examples: StaticFactPack,
) -> None:
    paths = {d.id: d.config_path for d in examples.devices}
    assert paths == {
        "edge1": "edge/edge1.cfg",
        "north-acc1": "north/north-acc1.cfg",
        "north-agg1": "north/north-agg1.cfg",
        "north-agg2": "north/north-agg2.cfg",
        "south-acc1": "south/south-acc1.cfg",
        "south-agg1": "south/south-agg1.cfg",
    }


def test_the_path_is_relative_to_the_checked_directory(
    examples: StaticFactPack,
) -> None:
    """An absolute path from the machine that ran the check is noise to whoever
    reads the report next — and it must still resolve against that directory."""
    for record in examples.devices:
        assert record.config_path is not None
        assert not Path(record.config_path).is_absolute()
        assert (EXAMPLES / record.config_path).is_file()


# --------------------------------------------------------------------------
# Stanza -> line
# --------------------------------------------------------------------------


def test_interfaces_vlans_and_groups_carry_the_line_they_start_on(
    examples: StaticFactPack,
) -> None:
    agg1 = device(examples, "north-agg1")
    lines = {i.name: i.config_line for i in agg1.interfaces}  # type: ignore[attr-defined]
    assert lines["Ethernet1"] == 13
    assert lines["Vlan10"] == 33

    declarations = {
        v.vlan_id: v.config_line for v in examples.vlans if v.device == "north-agg1"
    }
    assert declarations == {10: 6, 20: 6, 99: 6}

    group = next(g for g in examples.fhrp_groups if g.group_number == 10)
    member = next(m for m in group.members if m.device == "north-agg1")
    assert member.config_line == 36


def test_a_group_cites_its_first_line_not_its_last(examples: StaticFactPack) -> None:
    """Five `vrrp 10` lines configure one group; the citation opens at the first."""
    text = (EXAMPLES / "north" / "north-agg1.cfg").read_text().splitlines()
    group = next(g for g in examples.fhrp_groups if g.group_number == 10)
    member = next(m for m in group.members if m.device == "north-agg1")
    assert text[member.config_line - 1].strip() == "vrrp 10 ipv4 10.10.0.1"


def test_a_banner_does_not_shift_the_lines_after_it(tmp_path: Path) -> None:
    """Banner bodies are removed before parsing. If they were removed rather
    than blanked, everything below one would be cited three lines early."""
    pack = built(BANNERED, tmp_path)
    text = BANNERED.splitlines()
    interface = pack.devices[0].interfaces[0]
    assert text[interface.config_line - 1] == "interface Vlan50"
    member = pack.fhrp_groups[0].members[0]
    assert text[member.config_line - 1].strip() == "vrrp 50 ipv4 10.50.0.1"
    assert text[pack.vlans[0].config_line - 1] == "vlan 50"


def test_ios_records_its_own_lines(tmp_path: Path) -> None:
    pack = built(IOS, tmp_path)
    text = IOS.splitlines()
    interface = pack.devices[0].interfaces[0]
    assert text[interface.config_line - 1] == "interface GigabitEthernet0/1"
    member = pack.fhrp_groups[0].members[0]
    assert text[member.config_line - 1].strip() == "standby 30 ip 10.30.0.1"


def test_nxos_records_the_line_its_nested_group_opens_on(tmp_path: Path) -> None:
    pack = built(NXOS, tmp_path)
    text = NXOS.splitlines()
    interface = pack.devices[0].interfaces[0]
    assert text[interface.config_line - 1] == "interface Vlan40"
    member = pack.fhrp_groups[0].members[0]
    assert text[member.config_line - 1].strip() == "hsrp 40"


# --------------------------------------------------------------------------
# Finding -> citation
# --------------------------------------------------------------------------


def test_every_finding_cites_at_least_the_file(examples: StaticFactPack) -> None:
    for finding in locate(evaluate(examples), examples):
        assert finding.source is not None
        assert finding.source.file.endswith(".cfg")


def test_a_finding_about_one_group_cites_the_line_that_configures_it(
    examples: StaticFactPack,
) -> None:
    located = locate(evaluate(examples), examples)
    (single,) = [f for f in located if f.rule == "fhrp-no-redundancy"]
    assert str(single.source) == "south/south-agg1.cfg:24"

    isolated = next(f for f in located if f.rule == "l3-interface-isolated")
    assert str(isolated.source) == "south/south-agg1.cfg:21"

    access = next(f for f in located if f.rule == "access-vlan-not-trunked")
    assert str(access.source) == "north/north-acc1.cfg:24"


def test_a_finding_that_cannot_narrow_past_the_device_cites_the_file_alone(
    examples: StaticFactPack,
) -> None:
    """Two groups on one device diverge from each other, so neither is *the*
    line. A cited line that is only half the answer is worse than none."""
    located = locate(evaluate(examples), examples)
    (divergence,) = [f for f in located if f.rule == "fhrp-divergence"]
    assert divergence.source == SourceRef(file="north/north-agg1.cfg")
    assert str(divergence.source) == "north/north-agg1.cfg"


def test_the_trigger_is_not_read_as_a_citation(examples: StaticFactPack) -> None:
    """The divergence trigger flaps `north-agg1:Ethernet1`. That is the event
    that exposes the defect, not the configuration responsible for it."""
    located = locate(evaluate(examples), examples)
    (divergence,) = [f for f in located if f.rule == "fhrp-divergence"]
    assert divergence.trigger is not None
    assert "Ethernet1" in divergence.trigger
    assert divergence.source is not None
    assert divergence.source.line is None


def test_a_finding_on_a_device_outside_the_pack_is_left_alone(
    examples: StaticFactPack,
) -> None:
    orphan = Finding(
        rule="synthetic",
        tier=Tier.FACTS,
        severity=Severity.LOW,
        device="not-in-this-pack",
        title="nothing to cite",
        detail="",
    )
    assert locate([orphan], examples) == [orphan]


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def test_explain_shows_the_citation_and_the_plain_view_does_not(
    examples: StaticFactPack,
) -> None:
    located = locate(evaluate(examples), examples)
    explained = render(located, explain=True)
    assert "        source: south/south-agg1.cfg:24" in explained
    assert "source:" not in render(located)


def test_json_carries_the_file_and_the_line_apart(examples: StaticFactPack) -> None:
    """A path can contain a colon; splitting `file:line` back up is guesswork."""
    document = json.loads(as_json(locate(evaluate(examples), examples)))
    sources = {f["rule"]: f["source"] for f in document["findings"]}
    assert sources["fhrp-no-redundancy"] == {
        "file": "south/south-agg1.cfg",
        "line": 24,
    }
    assert sources["fhrp-divergence"] == {"file": "north/north-agg1.cfg", "line": None}


def test_json_says_null_when_nothing_located_the_finding() -> None:
    unlocated = Finding(
        rule="synthetic",
        tier=Tier.FACTS,
        severity=Severity.LOW,
        device="somewhere",
        title="nothing to cite",
        detail="",
    )
    assert json.loads(as_json([unlocated]))["findings"][0]["source"] is None


# --------------------------------------------------------------------------
# What must not have changed
# --------------------------------------------------------------------------


def test_the_shipped_corpora_keep_their_digests() -> None:
    """The digest reads the config text and nothing else. A fact pack that
    tracks where its facts came from is the same fact pack."""
    examples_pack, _ = build_fact_pack(EXAMPLES)
    site14, _ = build_fact_pack(SITE14)
    assert examples_pack.meta.config_digest == EXAMPLES_DIGEST
    assert examples_pack.meta.fact_pack_id == f"fp_{EXAMPLES_DIGEST[:12]}"
    assert site14.meta.config_digest == SITE14_DIGEST


def test_a_baseline_recorded_without_citations_still_matches(
    examples: StaticFactPack, tmp_path: Path
) -> None:
    """The case this change could have broken: a baseline taken by the previous
    release, compared against a run that now cites its sources. Identity is read
    from the references in a finding's text, and the citation is not in the text,
    so nothing here should read as new or as fixed."""
    recorded = tmp_path / "baseline.json"
    baseline.save(evaluate(examples), examples, recorded)

    diff = baseline.compare(
        baseline.load(recorded),
        baseline.snapshot(locate(evaluate(examples), examples), examples),
    )
    assert diff.new == []
    assert diff.fixed == []
    assert len(diff.unchanged) == len(evaluate(examples))
    assert not diff.regressed


def test_the_citation_is_not_part_of_a_finding_identity(
    examples: StaticFactPack,
) -> None:
    """Stated directly, so a later change that moves the citation into the
    rendered text fails here rather than in someone's baseline."""
    for before, after in zip(
        evaluate(examples), locate(evaluate(examples), examples), strict=True
    ):
        assert after.source is not None
        assert baseline.identity(before) == baseline.identity(after)
