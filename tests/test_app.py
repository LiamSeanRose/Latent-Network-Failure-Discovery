"""The local web view, driven through a real server socket.

Rendering is exercised end to end rather than by calling `page()` directly,
because the things that break a local UI — a bad query string, a path that does
not exist, an unescaped character — live in the request path.
"""

from __future__ import annotations

import json
import re
import shutil
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Final
from urllib.parse import quote
from urllib.request import urlopen

import pytest

from cassandra import baseline
from cassandra.app import Handler, analyse, analyse_directory
from cassandra.factpack.builders import build_fact_pack

CORPUS: Final = (
    Path(__file__).resolve().parents[1]
    / "scenarios"
    / "site14_vrrp_lockstep"
    / "configs"
)


@pytest.fixture(scope="module")
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def get(url: str) -> tuple[int, str]:
    with urlopen(url) as response:
        return response.status, response.read().decode()


def test_landing_page_asks_for_a_directory(base_url: str) -> None:
    status, body = get(base_url + "/")
    assert status == 200
    assert "Enter a directory" in body
    assert "<form" in body


def test_analysing_the_corpus_shows_the_timing_finding(base_url: str) -> None:
    status, body = get(f"{base_url}/?dir={quote(str(CORPUS))}")
    assert status == 200
    assert "different devices" in body
    assert "fhrp-divergence" in body
    assert "trigger:" in body


def test_timing_findings_carry_their_caveat(base_url: str) -> None:
    """A model-derived finding presented as fact is the failure mode this tier
    has. The UI must not drop the caveat the CLI prints."""
    _, body = get(f"{base_url}/?dir={quote(str(CORPUS))}")
    assert "not from running the protocols" in body


def test_json_endpoint_matches_the_page(base_url: str) -> None:
    status, body = get(f"{base_url}/findings.json?dir={quote(str(CORPUS))}")
    assert status == 200
    payload = json.loads(body)["findings"]
    assert payload
    assert {f["rule"] for f in payload} >= {"fhrp-divergence"}
    for finding in payload:
        assert finding["severity"] in {"high", "medium", "low", "info"}
        assert finding["tier"] in {"facts", "timing"}


def test_missing_directory_reports_instead_of_crashing(base_url: str) -> None:
    status, body = get(f"{base_url}/?dir={quote('/definitely/not/here')}")
    assert status == 200
    assert "not a directory" in body


def test_empty_directory_reports_instead_of_crashing(
    base_url: str, tmp_path: Path
) -> None:
    _, body = get(f"{base_url}/?dir={quote(str(tmp_path))}")
    assert "no .cfg files" in body


def test_unknown_path_is_404(base_url: str) -> None:
    with pytest.raises(Exception) as excinfo:
        get(base_url + "/nope")
    assert "404" in str(excinfo.value)


def test_directory_names_are_escaped_not_injected(
    base_url: str, tmp_path: Path
) -> None:
    """The directory string is echoed into the page. It must be escaped."""
    hostile = tmp_path / "<script>alert(1)</script>"
    _, body = get(f"{base_url}/?dir={quote(str(hostile))}")
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_analyse_directory_is_the_same_engine_as_the_cli() -> None:
    findings, error = analyse_directory(CORPUS)
    assert error is None
    assert {f.tier.value for f in findings} == {"timing"}


# VLAN 99 is declared but carried by no trunk: exactly one planted defect.
# It previously declared only VLAN 20, which meant the SVI also tripped
# `vlan-not-declared` — a second, unintended finding that made the counts below
# ambiguous about which defect they were counting.
MIXED_EXTRA: Final = """hostname edge1
vlan 20,99
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 20
interface Vlan99
   ip address 10.77.0.1/24
"""


@pytest.fixture(scope="module")
def mixed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The corpus plus one planted FACTS defect on a second device.

    The clean corpus produces timing findings on a single device, which cannot
    show whether filtering or grouping works. This adds an SVI whose VLAN no
    trunk carries, so the fixture spans two devices, both tiers and two
    severities.
    """
    configs = tmp_path_factory.mktemp("mixed") / "configs"
    shutil.copytree(CORPUS, configs)
    (configs / "edge1.cfg").write_text(MIXED_EXTRA)
    return configs


def view(base_url: str, config_dir: Path, query: str = "", path: str = "/") -> str:
    url = f"{base_url}{path}?dir={quote(str(config_dir))}"
    return get(f"{url}&{query}" if query else url)[1]


def test_the_mixed_fixture_spans_both_tiers(base_url: str, mixed: Path) -> None:
    """Guards the fixture itself: the filter tests below are meaningless if it
    ever stops containing both tiers."""
    payload = json.loads(view(base_url, mixed, path="/findings.json"))["findings"]
    assert {f["tier"] for f in payload} == {"facts", "timing"}
    assert {f["device"] for f in payload} == {"agg-a", "edge1"}


def test_severity_filter_narrows_the_page(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed, "severity=high")
    assert "fhrp-divergence" in body
    assert "fhrp-oscillation" not in body
    assert "svi-vlan-not-trunked" not in body
    assert "Showing 2 of" in body


def test_tier_filter_narrows_the_page(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed, "tier=facts")
    assert "svi-vlan-not-trunked" in body
    assert "fhrp-divergence" not in body


def test_filters_combine(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed, "severity=medium&tier=facts")
    assert "svi-vlan-not-trunked" in body
    assert "fhrp-oscillation" not in body


def test_repeated_and_comma_separated_values_are_both_accepted(
    base_url: str, mixed: Path
) -> None:
    for query in ("severity=high&severity=medium", "severity=high,medium"):
        body = view(base_url, mixed, query)
        assert "fhrp-divergence" in body, query
        assert "fhrp-oscillation" in body, query


def test_filter_chips_are_links_that_carry_the_directory(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed)
    assert 'class="chip"' in body
    for expected in ("severity=high", "severity=medium", "tier=facts", "tier=timing"):
        assert f"dir={quote(str(mixed), safe='')}&amp;{expected}" in body, expected


def test_the_active_chip_is_marked_and_offers_a_way_back(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed, "severity=high")
    assert 'class="chip on"' in body
    # "all" clears severity while keeping the directory.
    assert f'href="/?dir={quote(str(mixed), safe="")}"' in body


def test_filters_survive_in_the_json_link_and_the_form(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed, "severity=high&tier=timing")
    assert "/findings.json?dir=" in body
    assert "severity=high&amp;tier=timing" in body
    assert '<input type="hidden" name="severity" value="high">' in body
    assert '<input type="hidden" name="tier" value="timing">' in body


def test_json_endpoint_honours_the_same_filters(base_url: str, mixed: Path) -> None:
    high = json.loads(view(base_url, mixed, "severity=high", "/findings.json"))[
        "findings"
    ]
    assert high
    assert {f["severity"] for f in high} == {"high"}

    facts = json.loads(view(base_url, mixed, "tier=facts", "/findings.json"))[
        "findings"
    ]
    assert {f["tier"] for f in facts} == {"facts"}
    # Containment, not equality: this test is about filtering, and pinning the
    # exact rule set would break every time the FACTS registry grows.
    assert "svi-vlan-not-trunked" in {f["rule"] for f in facts}

    both = json.loads(
        view(base_url, mixed, "severity=high&tier=facts", "/findings.json")
    )["findings"]
    assert [f["rule"] for f in both] == []


def test_findings_are_grouped_by_device_with_a_count(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed)
    assert body.count('<details class="device-group" open>') == 2
    # Match the grouping, not today's counts. Pinning exact numbers couples this
    # test to the FACTS rule registry, which grows.
    for device in ("agg-a", "edge1"):
        assert re.search(
            rf"<summary>{device}<span class=\"n\">\d+ findings?</span></summary>", body
        ), f"no grouped summary for {device}"
    assert "1 finding<" in body or "1 findings<" not in body


def test_a_filter_matching_nothing_says_so_and_links_back(
    base_url: str, mixed: Path
) -> None:
    # Find a severity+tier combination that genuinely has no findings, rather
    # than assuming one exists. Every severity may be populated as rules grow,
    # but a full cross-product rarely is.
    findings = json.loads(view(base_url, mixed, path="/findings.json"))["findings"]
    assert findings, "fixture must produce findings for this test to mean anything"
    present = {(f["severity"], f["tier"]) for f in findings}
    severity, tier = next(
        (s, t)
        for s in ("info", "low", "medium", "high")
        for t in ("facts", "timing")
        if (s, t) not in present
    )

    body = view(base_url, mixed, f"severity={severity}&tier={tier}")
    assert "No findings match these filters" in body
    assert "Show all" in body


def test_unknown_filter_values_are_reported_and_escaped(
    base_url: str, mixed: Path
) -> None:
    """Filter values are echoed into the page, so they are an injection route."""
    body = view(base_url, mixed, "severity=" + quote("<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "Ignored filter values" in body
    # An unusable filter must not silently hide findings.
    assert "fhrp-divergence" in body


def test_timing_findings_keep_their_caveat_under_every_filter(
    base_url: str, mixed: Path
) -> None:
    for query in ("", "severity=high", "tier=timing", "severity=medium&tier=timing"):
        body = view(base_url, mixed, query)
        assert "not from running the protocols" in body, query
        assert "model-derived" in body, query


def test_the_fact_pack_identity_is_on_the_page(base_url: str, mixed: Path) -> None:
    """Which configs produced this view, so two tabs cannot be confused."""
    pack, _ = build_fact_pack(mixed)
    body = view(base_url, mixed)
    assert pack.meta.fact_pack_id in body
    assert pack.meta.config_digest[:12] in body
    assert "5 devices" in body


def test_the_page_is_self_contained(base_url: str, mixed: Path) -> None:
    """No external CSS, JS, font or image: it has to work offline."""
    body = view(base_url, mixed)
    assert "http://" not in body
    assert "https://" not in body
    assert "<script" not in body
    assert "<link" not in body
    assert "<img" not in body


def test_the_page_is_theme_aware_and_responsive(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed)
    assert "prefers-color-scheme: dark" in body
    assert "@media (max-width: 700px)" in body
    assert 'name="viewport"' in body


def _root_blocks() -> list[str]:
    """The bodies of every rule whose selector is the root element."""
    from cassandra.style import STYLE

    return [
        body
        for selector, body in re.findall(r"(:root[^{]*)\{([^{}]*)\}", STYLE)
        if "svg" not in selector and " " not in selector.strip().rstrip("{")
    ]


def test_root_variables_only_reference_other_root_variables() -> None:
    """A custom property on :root is substituted against :root.

    Declaring `--band: var(--c)` there looks like it forwards a per-element
    colour; it does not. --c is set on the band elements, so at :root the
    reference is invalid, the property becomes guaranteed-invalid, and every
    band falls back to the initial value — which for `fill` is black. This is
    the check that caught it.
    """
    declared: set[str] = set()
    referenced: dict[str, str] = {}
    for body in _root_blocks():
        for name, value in re.findall(r"(--[\w-]+)\s*:\s*([^;]+)", body):
            declared.add(name)
            for used in re.findall(r"var\((--[\w-]+)", value):
                referenced[used] = name
    assert declared, "no root-level custom properties found; the parse is wrong"
    for used, by in referenced.items():
        assert used in declared, (
            f"{by} on :root references {used}, which :root does not define"
        )


def test_the_rules_behind_the_findings_are_explained_on_the_page(
    base_url: str, mixed: Path
) -> None:
    """A rule identifier is useless on its own.

    Someone reading `fhrp-priority-tie` needs to know what it checks and, more
    to the point, what it declines to check — a rule's silence is only
    reassuring if you know what it is silent about.
    """
    body = view(base_url, mixed)
    assert 'class="rulebook"' in body
    for rule in {f.rule for f in analyse(mixed).findings}:
        assert f'id="rule-{rule}"' in body, f"{rule} fired but is not explained"
        assert f'href="#rule-{rule}"' in body, f"{rule} is not linked from its finding"


def test_only_the_rules_that_fired_are_explained(base_url: str, mixed: Path) -> None:
    """Twenty-five entries under four findings would bury the four."""
    body = view(base_url, mixed)
    fired = {f.rule for f in analyse(mixed).findings}
    assert body.count('<article class="rule"') == len(fired)


def test_the_rule_catalogue_is_served_as_json(base_url: str) -> None:
    with urlopen(f"{base_url}/rules.json") as response:
        assert response.headers["Content-Type"] == "application/json"
        docs = json.load(response)
    assert docs, "the catalogue should never be empty"
    first = docs[0]
    assert {"id", "tier", "severity", "summary", "silence"} <= set(first)


def test_every_served_rule_explains_itself(base_url: str) -> None:
    """An undocumented rule is a defect. This is where it becomes visible."""
    with urlopen(f"{base_url}/rules.json") as response:
        docs = json.load(response)
    undocumented = [doc["id"] for doc in docs if doc["summary"] is None]
    assert not undocumented, f"rules with no docstring: {', '.join(undocumented)}"


def test_device_filter_narrows_the_page(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed, "device=edge1")
    assert "svi-vlan-not-trunked" in body
    assert "fhrp-divergence" not in body


def test_device_filter_keeps_the_case_it_was_given(base_url: str, mixed: Path) -> None:
    """Device names are hostnames, not a fixed vocabulary.

    Folding them turns a filter for a device that really is called `AGG-A` into
    a filter that matches nothing, which looks exactly like a clean device.
    """
    body = view(base_url, mixed, "device=EDGE1")
    assert "No device here is called" in body
    assert "<code>EDGE1</code>" in body


def test_a_device_that_is_not_here_is_reported_not_ignored(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed, "device=nowhere")
    assert "No device here is called" in body
    assert "<code>nowhere</code>" in body


def test_device_and_severity_filters_combine(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed, "device=agg-a&severity=high")
    assert "fhrp-divergence" in body
    assert "fhrp-oscillation" not in body
    assert "svi-vlan-not-trunked" not in body


def test_the_map_links_devices_that_have_findings(base_url: str, mixed: Path) -> None:
    """The map is the only place a device with no findings appears at all, so a
    node that is clickable has to be one there is something to see."""
    body = view(base_url, mixed)
    assert "device=agg-a" in body
    # core1 is in the corpus and clean; a link to an empty result is a dead end.
    assert "device=core1" not in body


def test_the_device_row_appears_only_when_there_is_a_choice(
    base_url: str, mixed: Path
) -> None:
    single = view(base_url, CORPUS)
    assert '<span class="label">device</span>' not in single
    both = view(base_url, mixed)
    assert '<span class="label">device</span>' in both


def test_device_filter_survives_the_form_and_the_json_link(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed, "device=edge1")
    assert '<input type="hidden" name="device" value="edge1">' in body
    assert "device=edge1" in body


def test_the_full_catalogue_has_its_own_page(base_url: str) -> None:
    """The panel under a result explains the rules that fired. This answers the
    question that comes first: what does the tool look for at all."""
    status, body = get(f"{base_url}/rules")
    assert status == 200
    from cassandra.catalogue import catalogue

    for doc in catalogue():
        assert f'id="rule-{doc.id}"' in body, f"{doc.id} missing from /rules"
    assert "facts tier" in body
    assert "timing tier" in body


def test_the_catalogue_page_states_its_own_documentation_debt(base_url: str) -> None:
    """Both counts are measures of this tool's own gaps. Hiding them would be the
    one dishonest thing a page about honesty could do."""
    _, body = get(f"{base_url}/rules")
    assert "carry no explanation of themselves" in body
    assert "no test asserting they stay quiet" in body


def test_the_catalogue_page_is_reachable_from_a_result(
    base_url: str, mixed: Path
) -> None:
    assert 'href="/rules"' in view(base_url, mixed)


def test_the_catalogue_page_fetches_nothing_either(base_url: str) -> None:
    _, body = get(f"{base_url}/rules")
    for pattern in (r"<script", r"https?://", r"<link[^>]+href", r"@import", r"<img"):
        assert not re.search(pattern, body), f"external reference: {pattern}"


def test_the_report_can_be_downloaded_from_the_page(base_url: str, mixed: Path) -> None:
    """Someone reading findings in the browser is one step from wanting to send
    them to a colleague. Making them go back to a shell for that is a step."""
    body = view(base_url, mixed)
    assert "/report.html?dir=" in body

    with urlopen(f"{base_url}/report.html?dir={quote(str(mixed))}") as response:
        assert "attachment" in response.headers["Content-Disposition"]
        report = response.read().decode()
    assert "svi-vlan-not-trunked" in report
    assert "<form" not in report, "the search form posts to a server the file has not"


def test_the_downloaded_report_has_no_links_to_this_server(
    base_url: str, mixed: Path
) -> None:
    """A dead link in a file someone was sent reads as the file being broken."""
    with urlopen(f"{base_url}/report.html?dir={quote(str(mixed))}") as response:
        report = response.read().decode()
    assert 'href="/rules"' not in report
    assert 'href="/rules.json"' not in report


UNREADABLE: Final = """hostname odd1
vlan 20
interface Ethernet1
   switchport mode trunk
   switchport trunk allowed vlan 20
   some-feature that-nobody-parses here
   another-unknown directive
"""


def test_lines_that_were_not_read_are_reported_beside_the_findings(
    base_url: str, tmp_path: Path
) -> None:
    """A rule can only reason about facts that were extracted.

    A group whose priority line was missed still produces findings, and they
    are confident and wrong. Showing what was not read is what stops a partial
    reading from being taken for a complete one.
    """
    shutil.copytree(CORPUS, tmp_path / "configs")
    (tmp_path / "configs" / "odd1.cfg").write_text(UNREADABLE)
    body = view(base_url, tmp_path / "configs")
    assert "Not everything was read" in body
    assert "odd1" in body
    assert "cassandra facts" in body


def test_a_fully_understood_directory_says_nothing_about_reading(base_url: str) -> None:
    """The notice has to mean something when it appears."""
    assert "Not everything was read" not in view(base_url, CORPUS)


@pytest.fixture
def regressed(tmp_path: Path) -> tuple[Path, Path]:
    """A corpus, a baseline of it, and then a change that makes things worse.

    Shrinking a tracking decrement produces one new finding and, because the
    group can no longer lose the election, removes another — a fix that masks a
    problem, which is exactly the shape a comparison exists to show.
    """
    configs = tmp_path / "configs"
    shutil.copytree(CORPUS, configs)
    before = analyse(configs)
    base = tmp_path / "base.json"
    baseline.save(list(before.findings), before.pack, base)

    config = configs / "agg-a.cfg"
    config.write_text(config.read_text().replace("decrement 40", "decrement 5", 1))
    return configs, base


def test_a_baseline_splits_findings_into_new_and_known(
    base_url: str, regressed: tuple[Path, Path]
) -> None:
    configs, base = regressed
    body = view(base_url, configs, f"since={quote(str(base))}")
    assert "Compared with a baseline taken" in body
    assert "1 new" in body
    assert '<span class="tag state new">new</span>' in body
    assert '<span class="tag state known">known</span>' in body


def test_a_baseline_shows_what_stopped_being_reported(
    base_url: str, regressed: tuple[Path, Path]
) -> None:
    """A finding that disappeared is the only copy left of itself, and the
    reason it went may be a fix or may be a second defect masking the first."""
    configs, base = regressed
    body = view(base_url, configs, f"since={quote(str(base))}")
    assert "no longer reported" in body
    assert "1 fixed" in body


def test_the_baseline_survives_clicking_a_filter(
    base_url: str, regressed: tuple[Path, Path]
) -> None:
    """A comparison that falls off the moment you narrow the view is one nobody
    can use."""
    configs, base = regressed
    body = view(base_url, configs, f"since={quote(str(base))}&severity=high")
    assert "Compared with a baseline taken" in body
    assert f"since={quote(str(base), safe='')}" in body


def test_a_baseline_that_is_not_there_is_reported(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed, "since=/definitely/not/here.json")
    assert "Baseline" in body
    assert "/definitely/not/here.json" in body
    # The findings are still shown: a missing baseline is not a reason to
    # withhold the answer to the question that was actually asked.
    assert "fhrp-divergence" in body


def test_a_baseline_of_a_different_network_is_refused(
    base_url: str, tmp_path: Path, mixed: Path
) -> None:
    """Comparing two networks with no device in common has an answer for every
    finding and a meaning for none of them."""
    other = tmp_path / "other"
    other.mkdir()
    (other / "far1.cfg").write_text(
        "hostname far1\nvlan 20\ninterface Ethernet1\n"
        "   switchport mode trunk\n   switchport trunk allowed vlan 20\n"
        "interface Vlan99\n   ip address 10.88.0.1/24\n"
    )
    elsewhere = analyse(other)
    base = tmp_path / "far.json"
    baseline.save(list(elsewhere.findings), elsewhere.pack, base)

    body = view(base_url, mixed, f"since={quote(str(base))}")
    assert "Baseline" in body
    assert "fhrp-divergence" in body


def test_no_baseline_means_no_comparison_on_the_page(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed)
    assert "Compared with a baseline" not in body
    assert 'class="tag state' not in body


def test_the_endpoint_and_the_command_line_answer_in_one_shape(
    base_url: str, mixed: Path
) -> None:
    """Two shapes for one question is how a consumer ends up handling one."""
    document = json.loads(view(base_url, mixed, path="/findings.json"))
    assert sorted(document) == ["config_digest", "counts", "fact_pack_id", "findings"]
    assert document["config_digest"] == analyse(mixed).digest
    assert document["counts"]


def test_the_endpoint_reports_the_digest_of_what_it_read(
    base_url: str, mixed: Path
) -> None:
    """A result that cannot be tied to the configs that produced it is a result
    nobody can act on later."""
    document = json.loads(view(base_url, mixed, "severity=high", "/findings.json"))
    assert document["config_digest"], "filtered output still describes a real pack"
    assert document["fact_pack_id"]


def test_a_defect_in_a_rule_is_reported_as_a_defect_in_the_tool(
    base_url: str, mixed: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A blank 500 reads as 'your configs are unreadable', which is a lie.

    A rule that raises is this tool's bug, and the page has to name it as one so
    nobody spends an afternoon on a config that was never the problem.
    """
    import cassandra.app as app

    def explode(_: object) -> None:
        raise ZeroDivisionError("a rule divided by a VLAN")

    monkeypatch.setattr(app, "analyse", explode)
    status, body = get(f"{base_url}/?dir={quote(str(mixed))}")
    assert status == 200
    assert "ZeroDivisionError" in body
    assert "defect in the tool" in body


def test_serve_says_what_to_do_when_the_port_is_taken(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Almost always a second copy already running — an ordinary condition that
    should not produce a traceback."""
    import cassandra.app as app

    def refuse(*_: object, **__: object) -> None:
        raise OSError(98, "Address already in use")

    monkeypatch.setattr(app, "ThreadingHTTPServer", refuse)
    with pytest.raises(SystemExit) as exit_info:
        app.serve(port=9999)
    message = str(exit_info.value)
    assert "9999" in message
    assert "--port 10000" in message


@pytest.fixture(scope="module")
def crowded(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """More findings than the page will render. Built once: the analysis of five
    hundred devices is not something to repeat per test."""
    return _many(tmp_path_factory.mktemp("crowded"), 260)


@pytest.fixture(scope="module")
def busy(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Enough devices with timing findings to exceed the figure cap."""
    return _many(tmp_path_factory.mktemp("busy"), 40)


def _many(tmp_path: Path, sites: int) -> Path:
    """A directory of independent two-device sites, each with its own defect."""
    configs = tmp_path / "many"
    configs.mkdir()
    for site in range(sites):
        vlan = 10 * site + 4
        for role, host, priority in (("agg-a", 2, 110), ("agg-b", 3, 100)):
            (configs / f"s{site}-{role}.cfg").write_text(
                f"hostname s{site}-{role}\n"
                f"vlan {vlan}\n"
                "track UPLINK interface Ethernet1 line-protocol\n"
                "interface Ethernet1\n   no switchport\n"
                f"   ip address 10.{site}.0.{host}/31\n"
                f"interface Vlan{vlan}\n"
                f"   ip address 10.{site}.{vlan % 250}.{host}/24\n"
                f"   vrrp {vlan} ipv4 10.{site}.{vlan % 250}.1\n"
                f"   vrrp {vlan} priority-level {priority}\n"
                f"   vrrp {vlan} preempt\n"
                f"   vrrp {vlan} tracked-object UPLINK decrement 40\n"
            )
    return configs


def test_a_large_result_is_capped_and_says_so(base_url: str, crowded: Path) -> None:
    """A thousand findings is a real answer on a real archive. Rendering all of
    them is a seven-megabyte page; rendering some of them without saying so is
    worse than either."""
    from cassandra.app import PAGE_LIMIT

    configs = crowded
    result = analyse(configs)
    assert len(result.findings) > PAGE_LIMIT, "fixture must exceed the cap"

    body = view(base_url, configs)
    assert f"Showing the worst {PAGE_LIMIT} of {len(result.findings)}" in body
    assert "Nothing was dropped from the count" in body
    assert "Render all" in body


def test_nothing_is_capped_out_of_the_json(base_url: str, crowded: Path) -> None:
    """The cap is on the page, not on the analysis."""
    from cassandra.app import PAGE_LIMIT

    configs = crowded
    document = json.loads(view(base_url, configs, path="/findings.json"))
    assert len(document["findings"]) > PAGE_LIMIT


def test_asking_for_all_of_them_renders_all_of_them(
    base_url: str, crowded: Path
) -> None:
    configs = crowded
    total = len(analyse(configs).findings)
    body = view(base_url, configs, "all=1")
    assert "Showing the worst" not in body
    assert body.count('<article style="--i:') == total


def test_a_small_result_is_not_capped(base_url: str, mixed: Path) -> None:
    """The notice has to mean something when it appears."""
    assert "Showing the worst" not in view(base_url, mixed)


def test_timelines_are_limited_and_the_page_says_where(
    base_url: str, busy: Path
) -> None:
    """They repeat the same shape and dominate the weight of the page."""
    from cassandra.app import FIGURE_LIMIT

    configs = busy
    body = view(base_url, configs)
    assert body.count("gateway ownership over time") == FIGURE_LIMIT
    assert f"first {FIGURE_LIMIT} devices" in body


def test_the_cap_survives_clicking_a_filter(base_url: str, crowded: Path) -> None:
    configs = crowded
    body = view(base_url, configs, "all=1&severity=high")
    assert "Showing the worst" not in body
    assert "all=1" in body


def test_free_text_narrows_to_what_was_typed(base_url: str, mixed: Path) -> None:
    """The chips cover the dimensions the tool knows about. This covers the one
    it does not: an interface, a VLAN, an address someone is chasing."""
    body = view(base_url, mixed, "q=Vlan99")
    assert "svi-vlan-not-trunked" in body
    assert "fhrp-divergence" not in body


def test_free_text_reaches_the_evidence(base_url: str) -> None:
    """Someone searching for an interface is often searching for it because it
    turned up in the evidence of something else."""
    body = view(base_url, CORPUS, "q=Ethernet1")
    assert "fhrp-divergence" in body


def test_free_text_is_case_insensitive(base_url: str, mixed: Path) -> None:
    assert "svi-vlan-not-trunked" in view(base_url, mixed, "q=VLAN99")


def test_free_text_that_matches_nothing_says_so_and_offers_a_way_back(
    base_url: str, mixed: Path
) -> None:
    body = view(base_url, mixed, "q=nothinghere")
    assert "No findings match these filters" in body
    assert "Show all" in body


def test_free_text_survives_the_form_and_the_chips(base_url: str, mixed: Path) -> None:
    body = view(base_url, mixed, "q=Vlan99")
    assert 'name="q"' in body
    assert 'value="Vlan99"' in body
    assert "q=Vlan99" in body
    # ...and is not also sent as a hidden field, which would submit it twice.
    assert '<input type="hidden" name="q"' not in body


def test_free_text_reaches_the_json_endpoint(base_url: str, mixed: Path) -> None:
    document = json.loads(view(base_url, mixed, "q=Vlan99", "/findings.json"))
    assert {f["rule"] for f in document["findings"]} == {"svi-vlan-not-trunked"}


def test_identical_configs_with_different_findings_say_which_changed(
    base_url: str, tmp_path: Path
) -> None:
    """The most useful sentence this tool can print, and the easiest to bury.

    If the configs are byte-identical and the findings are not, the network did
    not change — the checks did. Nobody expects to be told that by a diff, and
    nobody works it out on their own either.
    """
    configs = tmp_path / "configs"
    shutil.copytree(CORPUS, configs)
    result = analyse(configs)
    base = tmp_path / "base.json"
    baseline.save(list(result.findings)[:-1], result.pack, base)  # one short

    body = view(base_url, configs, f"since={quote(str(base))}")
    assert "byte-identical to the baseline" in body
    assert "change in the checks, not in the network" in body


def test_changed_configs_do_not_claim_the_checks_moved(
    base_url: str, regressed: tuple[Path, Path]
) -> None:
    configs, base = regressed
    body = view(base_url, configs, f"since={quote(str(base))}")
    assert "change in the checks" not in body


def test_a_finding_says_which_file_to_open(base_url: str) -> None:
    """PROJECT.md §5.4. On a corpus filed in per-site directories, naming the
    device leaves the reader to go and find the file."""
    examples = Path(__file__).resolve().parents[1] / "examples" / "two-site"
    body = view(base_url, examples)
    assert "north/north-agg1.cfg:" in body
    assert 'class="mono cite"' in body


def test_the_citation_reaches_the_json(base_url: str) -> None:
    examples = Path(__file__).resolve().parents[1] / "examples" / "two-site"
    document = json.loads(view(base_url, examples, path="/findings.json"))
    cited = [f for f in document["findings"] if f["source"]]
    assert cited, "something should be locatable"
    for finding in cited:
        # Split rather than "file:line": a path may contain a colon and a
        # consumer should not have to guess where to cut.
        assert set(finding["source"]) == {"file", "line"}
        assert not finding["source"]["file"].startswith("/"), (
            "an absolute path from someone else's machine is noise in a report"
        )


def test_long_identifiers_are_allowed_to_wrap() -> None:
    """A test identifier is one unbreakable token about ninety characters long.

    Several of them sit in every rule entry. Left unwrapped they pushed the
    whole document sideways on a phone — a horizontal scrollbar on the page
    rather than on the one element that is genuinely too wide.
    """
    from cassandra.style import STYLE

    rules = re.findall(r"([^{}]*)\{([^{}]*)\}", STYLE)
    wrapping = {
        selector.strip()
        for selector, body in rules
        if "overflow-wrap" in body or "word-break" in body
    }
    covered = " ".join(wrapping)
    for needed in (".rule .src", ".cite"):
        assert needed in covered, f"{needed} can push the page sideways"


def test_wide_figures_scroll_inside_their_own_card() -> None:
    """Below about 520px the timeline's band labels stop being readable, so it
    must not shrink — but the scrollbar belongs to the figure, not the page."""
    from cassandra.style import STYLE

    assert "svg.viz { width: 100%; min-width: 520px" in STYLE
    figure = re.search(r"\.figure \{([^}]*)\}", STYLE)
    assert figure and "overflow-x: auto" in figure.group(1)
