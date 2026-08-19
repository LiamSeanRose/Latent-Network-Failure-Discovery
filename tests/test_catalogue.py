"""The catalogue, and the two things that keep it honest.

A catalogue maintained beside the code is wrong the first time someone adds a
rule and forgets it. These tests remove that possibility from both directions:
every rule the source constructs must appear in the catalogue, and the committed
`docs/RULES.md` must be what the catalogue renders right now. Adding a rule
without regenerating the file fails the build, and the regenerated file names the
new rule — undocumented, if that is what it is.

The discovery here is deliberately not the discovery `cassandra/catalogue.py`
does. It is a regex over the three source files, so a bug in the module's AST
walk cannot hide behind the same bug in its test.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

from cassandra import catalogue as cat
from cassandra.factpack.builders import build_fact_pack
from cassandra.facts import rules as facts_rules
from cassandra.findings import Severity, Tier
from cassandra.timing import sequences, timer_rules

REPO: Final = Path(__file__).resolve().parents[1]
DOCS: Final = REPO / "docs" / "RULES.md"
CORPUS: Final = REPO / "scenarios" / "site14_vrrp_lockstep" / "configs"

SOURCE_FILES: Final = (
    REPO / "cassandra" / "facts" / "rules.py",
    REPO / "cassandra" / "timing" / "timer_rules.py",
    REPO / "cassandra" / "timing" / "sequences.py",
)

RULE_LITERAL: Final = re.compile(r'\brule="([a-z0-9][a-z0-9-]*)"')

REGENERATE: Final = (
    "docs/RULES.md is out of date. Regenerate it with "
    "`python -m cassandra.catalogue --write` and commit the result."
)


def rule_ids_in_source() -> set[str]:
    return {
        match
        for path in SOURCE_FILES
        for match in RULE_LITERAL.findall(path.read_text())
    }


# --------------------------------------------------------------------------
# The mechanism: nothing ships undocumented and unnoticed
# --------------------------------------------------------------------------


def test_every_rule_in_the_source_appears_in_the_catalogue():
    """The point of the whole module. A rule that is not here is a rule nobody
    can ask about, and this is what makes adding one without documenting it a
    build failure rather than a quiet omission."""
    assert {doc.id for doc in cat.catalogue()} == rule_ids_in_source()


def test_every_registered_rule_function_is_represented():
    """Discovery runs off the registries, so a registered function that produces
    no catalogue entry means the extraction missed it."""
    registered = {fn.__name__ for fn in facts_rules.RULES} | {
        fn.__name__ for fn in timer_rules.RULES
    }
    assert registered <= {doc.function for doc in cat.catalogue()}


def test_the_committed_catalogue_is_what_the_code_renders():
    assert DOCS.read_text() == cat.render_markdown(), REGENERATE


def test_all_three_rule_sets_are_covered():
    """`sequences` keeps no registry — its findings come out of the enumeration
    itself — so a discovery that only understood `RULES` would silently omit the
    whole TIMING tier."""
    modules = {doc.module for doc in cat.catalogue()}
    assert modules == {
        facts_rules.__name__,
        timer_rules.__name__,
        sequences.__name__,
    }


# --------------------------------------------------------------------------
# What each entry says
# --------------------------------------------------------------------------


def test_tier_and_severity_match_what_the_rules_actually_emit():
    """The catalogue reads the source; the tool runs it. This is the one test
    that compares the two, on findings the shipped corpus really produces."""
    pack, _ = build_fact_pack(CORPUS)
    emitted = (
        facts_rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack)
    )
    assert emitted, "the corpus produces no findings, so this test proves nothing"
    documented = {doc.id: doc for doc in cat.catalogue()}
    for finding in emitted:
        doc = documented[finding.rule]
        assert doc.tier is finding.tier
        assert doc.severity is finding.severity


def test_every_entry_names_its_tier_severity_and_message():
    for doc in cat.catalogue():
        assert doc.tier in Tier
        assert doc.severity in Severity
        assert doc.reports, f"{doc.id} has no title to show"


def test_message_templates_keep_the_literal_text_and_hide_the_values():
    doc = next(d for d in cat.catalogue() if d.id == "bgp-peer-off-subnet")
    assert doc.reports == "BGP peer {…} is not on any subnet {…} has"


def test_an_undocumented_rule_says_so_rather_than_inventing_an_explanation():
    """Where a rule has no docstring the entry has to admit it. An entry that
    reads plausibly without being derived from anything is the failure mode this
    module exists to avoid."""
    markdown = cat.render_markdown()
    for doc in cat.catalogue():
        if doc.documented:
            continue
        entry = markdown.split(f"### `{doc.id}`", 1)[1]
        assert "Undocumented" in entry.split("###", 1)[0]


def test_a_rule_with_a_docstring_is_summarised_from_it():
    doc = next(d for d in cat.catalogue() if d.id == "mtu-mismatch")
    assert doc.documented
    assert doc.summary == "Neighbours that disagree about how large a frame may be."


# --------------------------------------------------------------------------
# When a rule deliberately stays silent
# --------------------------------------------------------------------------


def test_deliberate_silence_is_captured_for_peers_outside_the_corpus():
    """The class of information a user cannot get anywhere else: `bgp-session-
    one-sided` ignores a peer it cannot see, because an upstream provider is not
    a defect. If that stops being recorded the catalogue has lost the part of it
    that answers 'why did this not fire'."""
    doc = next(d for d in cat.catalogue() if d.id == "bgp-session-one-sided")
    assert doc.silence, "no silence note survived extraction"
    assert any("corpus" in note.source for note in doc.silence)


def test_silence_is_read_out_of_the_tests_that_assert_it(tmp_path: Path):
    """Both shapes the assertion takes, against a synthetic suite so the check
    does not depend on how any real test happens to be written today."""
    (tmp_path / "test_synthetic.py").write_text(
        "from cassandra.facts.rules import evaluate\n"
        "\n"
        "def test_a_peer_outside_the_corpus_is_not_flagged():\n"
        '    """An upstream provider is not a defect."""\n'
        '    assert "bgp-session-one-sided" not in fired(pack)\n'
        "\n"
        "def test_symmetric_groups_do_not_diverge():\n"
        '    assert [f for f in analyse(pack) if f.rule == "fhrp-divergence"] == []\n'
        "\n"
        "def test_a_clean_pair_is_quiet():\n"
        "    assert evaluate(pack) == []\n"
    )
    docs = {doc.id: doc for doc in cat.catalogue(tmp_path)}

    one_sided = docs["bgp-session-one-sided"].silence
    assert [note.note for note in one_sided] == [
        "An upstream provider is not a defect."
    ]
    assert one_sided[0].source == (
        "test_synthetic.py::test_a_peer_outside_the_corpus_is_not_flagged"
    )

    divergence = docs["fhrp-divergence"].silence
    assert [note.source for note in divergence] == [
        "test_synthetic.py::test_symmetric_groups_do_not_diverge"
    ]
    # No docstring, so the test's own name is the note.
    assert divergence[0].note == "Symmetric groups do not diverge"

    # Named no rule, so it constrains the rule set rather than any one rule.
    facts = next(
        r for r in cat.registries(tmp_path) if r.module == facts_rules.__name__
    )
    assert [note.note for note in facts.silence] == ["A clean pair is quiet"]
    assert docs["mtu-mismatch"].silence == ()


def test_a_test_that_never_imports_a_rule_set_is_not_a_silence_note(tmp_path: Path):
    """The web view's filter tests assert a rule id is absent from a rendered
    page. That is a statement about the filter, not about the rule."""
    (tmp_path / "test_view.py").write_text(
        "def test_the_tier_filter_narrows_the_page():\n"
        '    assert "fhrp-oscillation" not in body\n'
    )
    docs = {doc.id: doc for doc in cat.catalogue(tmp_path)}
    assert docs["fhrp-oscillation"].silence == ()


def test_the_catalogue_still_works_without_the_tests_beside_it(tmp_path: Path):
    """The wheel ships the package and not the suite, so a `cassandra rules`
    command has to degrade to 'no silence notes' rather than fail."""
    docs = cat.catalogue(tmp_path)
    assert {doc.id for doc in docs} == rule_ids_in_source()
    assert all(doc.silence == () for doc in docs)


# --------------------------------------------------------------------------
# The rendered document
# --------------------------------------------------------------------------


def test_the_index_links_every_rule():
    markdown = cat.render_markdown()
    index = markdown.split("## FACTS tier", 1)[0]
    for doc in cat.catalogue():
        assert f"[`{doc.id}`](#{doc.id})" in index
        assert f"### `{doc.id}`" in markdown


def test_entries_are_grouped_by_tier_and_ranked_by_severity():
    docs = cat.catalogue()
    assert [doc.sort_key for doc in docs] == sorted(doc.sort_key for doc in docs)
    tiers = [doc.tier for doc in docs]
    assert tiers == sorted(tiers, key=cat.TIER_ORDER.index)


def test_every_rule_has_a_silence_section_even_when_nothing_asserts_it():
    """An untested silence is worth saying out loud: it is the difference between
    'this is deliberate' and 'nobody has checked'."""
    markdown = cat.render_markdown()
    for doc in cat.catalogue():
        entry = markdown.split(f"### `{doc.id}`", 1)[1].split("###", 1)[0]
        assert "**Stays silent when:**" in entry


def test_writing_the_document_is_what_the_docs_say_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    target = tmp_path / "docs" / "RULES.md"
    monkeypatch.setattr(cat, "DOCS_PATH", target)
    assert cat.main(["--write"]) == 0
    assert target.read_text() == cat.render_markdown()


# --------------------------------------------------------------------------
# The terminal form a `cassandra rules` command would print
# --------------------------------------------------------------------------


def test_the_listing_has_a_line_for_every_rule():
    listing = cat.render_text()
    assert len(listing.splitlines()) == len(cat.catalogue())
    for doc in cat.catalogue():
        assert doc.id in listing


def test_one_rule_prints_what_it_checks_and_when_it_stays_quiet():
    text = cat.render_text("bgp-peer-off-subnet")
    assert text.startswith("bgp-peer-off-subnet  [facts / medium]")
    assert "cassandra.facts.rules.bgp_peer_on_no_local_subnet" in text
    assert "stays silent when:" in text
    assert "test_multihop_peer_off_subnet_is_intentional" in text


def test_a_test_identifier_is_never_wrapped():
    """It is only useful if it can be pasted back into pytest."""
    for doc in cat.catalogue():
        for note in doc.silence:
            assert note.source in cat.render_text(doc.id)


def test_an_unknown_rule_says_so_and_lists_the_real_ones():
    text = cat.render_text("bgp-peer-off-subnetz")
    assert text.startswith("no such rule: bgp-peer-off-subnetz")
    assert "bgp-peer-off-subnet" in text
