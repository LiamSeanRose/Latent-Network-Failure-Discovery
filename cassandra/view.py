"""The page, and everything that turns findings into it.

Split from the server for the reason every long module gets split: this one is
markup and the decisions behind it, and the other is a socket. They change for
different reasons and neither should have to be read to work on the other.

Standard library only, on purpose: the premise of v3 is that installing this
tool is the entire setup, and a UI that drags in a web framework and a build
step walks that back. No external stylesheet, script, font or image either — a
page that fetches anything is a page that does not work on a laptop with no
network, which is where someone reads their own configs. There is no script tag
at all, including for the light and dark toggle, so a saved report is a file
anyone can read the source of before opening.

Everything the view can do is expressed in the query string — the directory, the
severity, tier and device filters, a free-text search, a baseline to compare
against — so any state the page shows is a link someone can send, bookmark or
curl, and `/findings.json` answers the same question as the page it was linked
from.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Final
from urllib.parse import urlencode

from cassandra import art, baseline, coverage, visuals
from cassandra.catalogue import RuleDoc, catalogue
from cassandra.coverage import RuleCoverage
from cassandra.factpack import discovery
from cassandra.factpack.builders.common import fhrp_instance
from cassandra.factpack.schema import TimerSource
from cassandra.findings import Finding, Severity, Tier
from cassandra.style import STYLE

if TYPE_CHECKING:  # pragma: no cover - types, not dependencies
    from cassandra.app import Analysis
    from cassandra.factpack.schema import Device, StaticFactPack


_SEVERITY_ORDER: Final = (
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_TIER_ORDER: Final = (Tier.FACTS, Tier.TIMING)

# A thousand findings is a real answer on a real archive, and rendering all of
# them is a seven-megabyte page that takes eight seconds to build. The caps are
# on the page, not on the analysis: every finding is in the JSON, in the report
# and in the count, and the page says exactly what it left out and links to it.
PAGE_LIMIT: Final = 200

# The timelines dominate the cost and repeat themselves — one per device, all
# drawn from the same kind of sequence. A dozen is enough to see the shape.
FIGURE_LIMIT: Final = 12

_TIMING_CAVEAT: Final = (
    "Timing findings come from a model of timer interaction, not from running the "
    "protocols. They tell you a sequence your configuration permits — each one shows "
    "the sequence, so you can judge it."
)


@lru_cache(maxsize=1)
def _rulebook() -> dict[str, RuleDoc]:
    """The catalogue keyed by rule id.

    Cached because building it parses the rule modules and the test suite, and
    the answer cannot change while the process is running.
    """
    return {doc.id: doc for doc in catalogue()}


@dataclass(frozen=True, slots=True, kw_only=True)
class Filters:
    """The view's whole state: which severities and tiers to show.

    An empty set means "no filter on this dimension", not "show nothing" — a link
    with no filter in it has to keep meaning the full result.
    """

    severities: frozenset[Severity] = frozenset()
    tiers: frozenset[Tier] = frozenset()
    devices: frozenset[str] = frozenset()
    # Free text, matched against everything a finding says. The chips cover the
    # dimensions the tool knows about; this covers the one it does not — an
    # interface name, a VLAN, an address someone is chasing across a change.
    query: str = ""
    unknown: tuple[str, ...] = ()
    # Not a filter: it selects nothing and hides nothing. It lives here because
    # every link and every hidden form field on the page is built from this
    # object, and a comparison that falls off the moment you click a severity is
    # a comparison nobody can use.
    since: str = ""
    # Also carried state rather than a filter: it widens the view instead of
    # narrowing it, and it has to survive clicking a chip like everything else.
    show_all: bool = False

    @property
    def active(self) -> bool:
        return bool(self.severities or self.tiers or self.devices or self.query)

    def matches(self, finding: Finding) -> bool:
        if self.severities and finding.severity not in self.severities:
            return False
        if self.devices and finding.device not in self.devices:
            return False
        if self.tiers and finding.tier not in self.tiers:
            return False
        return not self.query or self.query.lower() in _searchable(finding)


def _searchable(finding: Finding) -> str:
    """Everything a finding says, folded, for a free-text match.

    Evidence is included: someone searching for an interface name is often
    searching for it because it appeared in the evidence of something else.
    """
    return "\n".join(
        part
        for part in (
            finding.rule,
            finding.device,
            finding.title,
            finding.detail,
            finding.trigger or "",
            finding.remedy or "",
            *finding.evidence,
        )
        if part
    ).lower()


@dataclass(frozen=True, slots=True, kw_only=True)
class Comparison:
    """A run measured against a saved one, or the reason there is no measure."""

    diff: baseline.Diff | None = None
    error: str | None = None
    path: str = ""

    def state(self, finding: Finding) -> str:
        """ "new" for a finding the baseline did not have, "known" otherwise.

        Identity comes from `baseline`, not from the rendered text, for the same
        reason it does there: rewording a finding is not a regression.
        """
        if self.diff is None:
            return ""
        fresh = {baseline.identity(f) for f in self.diff.new}
        return "new" if baseline.identity(finding) in fresh else "known"


def compare_with(analysis: Analysis, path: str) -> Comparison:
    """Diff this analysis against a saved baseline named by the query string."""
    if not path:
        return Comparison()
    if analysis.pack is None:
        return Comparison(path=path, error="nothing to compare: no configs were read")
    try:
        previous = baseline.load(Path(path).expanduser())
        current = baseline.snapshot(list(analysis.findings), analysis.pack)
        return Comparison(diff=baseline.compare(previous, current), path=path)
    except baseline.BaselineError as error:
        return Comparison(path=path, error=str(error))
    except OSError as error:
        return Comparison(path=path, error=f"could not read {path}: {error}")


def _requested(
    params: dict[str, list[str]], name: str, *, fold: bool = True
) -> list[str]:
    """Filter values, repeated or comma-separated, de-duplicated in order.

    Severities and tiers come from a fixed lower-case vocabulary and are folded.
    Device names do not: they are hostnames the device chose, and folding one
    turns a filter for `AGG-A` into a filter that matches nothing.
    """
    values: list[str] = []
    for raw in params.get(name, []):
        for part in raw.split(","):
            token = part.strip().lower() if fold else part.strip()
            if token and token not in values:
                values.append(token)
    return values


def parse_filters(params: dict[str, list[str]]) -> Filters:
    """Read the filters out of a query string.

    A value naming no severity or tier is reported back rather than silently
    dropped: a filter that quietly does nothing looks exactly like a filter that
    found nothing, and the two deserve different reactions.
    """
    severities: list[Severity] = []
    tiers: list[Tier] = []
    unknown: list[str] = []
    # A device name is not drawn from a fixed vocabulary, so an unrecognised one
    # cannot be told from a typo here. It is reported by the page instead, which
    # knows which devices the pack actually holds.
    devices = _requested(params, "device", fold=False)
    for token in _requested(params, "severity"):
        try:
            severities.append(Severity(token))
        except ValueError:
            unknown.append(token)
    for token in _requested(params, "tier"):
        try:
            tiers.append(Tier(token))
        except ValueError:
            unknown.append(token)
    return Filters(
        severities=frozenset(severities),
        tiers=frozenset(tiers),
        devices=frozenset(devices),
        unknown=tuple(unknown),
        query=(params.get("q") or [""])[0].strip(),
        since=(params.get("since") or [""])[0].strip(),
        show_all=bool(params.get("all")),
    )


def _query_pairs(config_dir: str, filters: Filters) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if config_dir:
        pairs.append(("dir", config_dir))
    pairs.extend(
        ("severity", s.value) for s in _SEVERITY_ORDER if s in filters.severities
    )
    pairs.extend(("tier", t.value) for t in _TIER_ORDER if t in filters.tiers)
    pairs.extend(("device", device) for device in sorted(filters.devices))
    if filters.query:
        pairs.append(("q", filters.query))
    if filters.since:
        pairs.append(("since", filters.since))
    if filters.show_all:
        pairs.append(("all", "1"))
    return pairs


def href(path: str, config_dir: str, filters: Filters) -> str:
    """An escaped link to `path` carrying the current view state."""
    query = urlencode(_query_pairs(config_dir, filters))
    return html.escape(f"{path}?{query}" if query else path)


def _toggle[T](values: frozenset[T], value: T) -> frozenset[T]:
    return values - {value} if value in values else values | {value}


def _chip(label: str, count: int, link: str, *, on: bool) -> str:
    return (
        f'<a class="chip{" on" if on else ""}" href="{link}">'
        f'{html.escape(label)} <span class="n">{count}</span></a>'
    )


def _filter_bar(
    config_dir: str, findings: tuple[Finding, ...], filters: Filters
) -> str:
    """Severity and tier chips, each a link that toggles one value.

    Counts are computed with the *other* dimension's filter already applied, so a
    chip promises the number of findings clicking it actually leaves on screen.
    """
    severities = [s for s in _SEVERITY_ORDER if any(f.severity is s for f in findings)]
    tiers = [t for t in _TIER_ORDER if any(f.tier is t for f in findings)]

    by_tier = [f for f in findings if not filters.tiers or f.tier in filters.tiers]
    severity_chips = [
        '<span class="label">severity</span>',
        _chip(
            "all",
            len(by_tier),
            href("/", config_dir, replace(filters, severities=frozenset())),
            on=not filters.severities,
        ),
    ]
    severity_chips += [
        _chip(
            severity.value,
            sum(1 for f in by_tier if f.severity is severity),
            href(
                "/",
                config_dir,
                replace(filters, severities=_toggle(filters.severities, severity)),
            ),
            on=severity in filters.severities,
        )
        for severity in severities
    ]

    by_severity = [
        f
        for f in findings
        if not filters.severities or f.severity in filters.severities
    ]
    tier_chips = [
        '<span class="label">tier</span>',
        _chip(
            "all",
            len(by_severity),
            href("/", config_dir, replace(filters, tiers=frozenset())),
            on=not filters.tiers,
        ),
    ]
    tier_chips += [
        _chip(
            tier.value,
            sum(1 for f in by_severity if f.tier is tier),
            href(
                "/",
                config_dir,
                replace(filters, tiers=_toggle(filters.tiers, tier)),
            ),
            on=tier in filters.tiers,
        )
        for tier in tiers
    ]

    rows = [severity_chips, tier_chips]

    # Only when there is a choice to make. One device means the row would be a
    # label, an "all" chip and that device — three controls that do nothing.
    devices = sorted({f.device for f in findings})
    if len(devices) > 1:
        by_others = [
            f
            for f in findings
            if (not filters.tiers or f.tier in filters.tiers)
            and (not filters.severities or f.severity in filters.severities)
        ]
        device_chips = [
            '<span class="label">device</span>',
            _chip(
                "all",
                len(by_others),
                href(
                    "/",
                    config_dir,
                    replace(filters, devices=frozenset()),
                ),
                on=not filters.devices,
            ),
        ]
        device_chips += [
            _chip(
                device,
                sum(1 for f in by_others if f.device == device),
                href(
                    "/",
                    config_dir,
                    replace(filters, devices=_toggle(filters.devices, device)),
                ),
                on=device in filters.devices,
            )
            for device in devices
        ]
        rows.append(device_chips)

    return (
        '<div class="filters">'
        + "".join(f'<div class="chips">{"".join(row)}</div>' for row in rows)
        + "</div>"
    )


def _counts_html(visible: list[Finding], total: int) -> str:
    counts = Counter(finding.severity for finding in visible)
    cells = "".join(
        f'<div class="count"><b>{counts[s]}</b><span>{s.value}</span></div>'
        for s in _SEVERITY_ORDER
        if counts[s]
    )
    showing = (
        ""
        if len(visible) == total
        else f'<p class="showing">Showing {len(visible)} of {total} findings.</p>'
    )
    bar = visuals.sparkbar(
        {s.value: counts[s] for s in _SEVERITY_ORDER},
        {
            Severity.HIGH.value: "var(--s-critical)",
            Severity.MEDIUM.value: "var(--s-serious)",
            Severity.LOW.value: "var(--s-warning)",
            Severity.INFO.value: "var(--series-1)",
        },
    )
    ring = art.severity_ring(
        {s.value: counts[s] for s in _SEVERITY_ORDER if counts[s]},
        {
            Severity.HIGH.value: "var(--s-critical)",
            Severity.MEDIUM.value: "var(--s-serious)",
            Severity.LOW.value: "var(--s-warning)",
            Severity.INFO.value: "var(--series-1)",
        },
    )
    return (
        f'<div class="summary">{ring}'
        f'<div class="totals">{showing}<div class="counts">{cells}</div>{bar}</div>'
        "</div>"
    )


def _finding_html(finding: Finding, figure: str = "", state: str = "") -> str:
    classes = f"finding {html.escape(finding.severity.value)}"
    if state:
        classes += f" is-{state}"
    parts = [
        f'<article class="{classes}">',
        f"<h2>{html.escape(finding.title)}</h2>",
        f'<p class="meta"><span class="mono">{html.escape(finding.device)}</span>'
        f'<span class="sev {html.escape(finding.severity.value)}">'
        f"{html.escape(finding.severity.value)}</span>"
        f"<span>{html.escape(finding.tier.value)} tier</span>"
        f'<a class="mono rule-link" href="#rule-{html.escape(finding.rule)}">'
        f"{html.escape(finding.rule)}</a>"
        + (
            ' <span class="tag">model-derived</span>'
            if finding.tier is Tier.TIMING
            else ""
        )
        + (f' <span class="tag state {state}">{state}</span>' if state else "")
        + (
            f' <span class="mono cite">{html.escape(str(finding.source))}</span>'
            if finding.source
            else ""
        )
        + "</p>",
        f'<p class="detail">{html.escape(finding.detail)}</p>',
    ]
    if finding.trigger:
        parts.append(
            f'<div class="trigger">trigger: {html.escape(finding.trigger)}</div>'
        )
    if finding.remedy:
        parts.append(f'<div class="remedy">fix: {html.escape(finding.remedy)}</div>')
    if finding.change:
        # The edit, in the dialect the device speaks. Marked as a suggestion
        # because it is one: the tool knows the timers, not the change window,
        # the standards or whatever else the operator is holding in their head.
        lines = "\n".join(html.escape(line) for line in finding.change)
        parts.append(
            f'<div class="change"><span class="label">suggested change</span>'
            f"<pre>{lines}</pre></div>"
        )
    if figure:
        parts.append(
            '<div class="figure"><h2>gateway ownership over time</h2>'
            '<p class="cap">The model advanced through this trigger. Each band is '
            "the device holding that group; a split is where two groups sit on "
            "different devices.</p>" + figure + "</div>"
        )
    if finding.evidence:
        items = "".join(f"<li>{html.escape(item)}</li>" for item in finding.evidence)
        parts.append(f"<details><summary>evidence</summary><ul>{items}</ul></details>")
    parts.append("</article>")
    return "".join(parts)


def _by_device(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    """Group in rank order, so devices arrive worst-first and so do their findings."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.device, []).append(finding)
    return list(grouped.items())


def _device_html(
    device: str,
    findings: list[Finding],
    pack: StaticFactPack | None = None,
    comparison: Comparison | None = None,
    *,
    draw_figures: bool = True,
) -> str:
    """One device's findings.

    The first timing finding on a device carries the timeline figure. Drawing it
    on every one would repeat the same picture three times, since they all come
    from the same simulated sequence.
    """
    plural = "" if len(findings) == 1 else "s"
    cards: list[str] = []
    drawn = False
    for index, finding in enumerate(findings):
        figure = ""
        wanted = draw_figures and not drawn and finding.tier is Tier.TIMING
        if wanted and pack is not None:
            figure = visuals.timeline_svg(pack, finding)
            drawn = bool(figure)
        state = comparison.state(finding) if comparison is not None else ""
        cards.append(
            _finding_html(finding, figure, state).replace(
                '<article class="finding',
                f'<article style="--i:{index}" class="finding',
                1,
            )
        )
    return (
        '<details class="device-group" open>'
        f"<summary>{html.escape(device)}"
        f'<span class="n">{len(findings)} finding{plural}</span></summary>'
        + "".join(cards)
        + "</details>"
    )


def _rule_entry(doc: RuleDoc, inert: RuleCoverage | None = None) -> str:
    """One rule, opened by clicking its identifier in a finding.

    `inert` is set when a directory was named and this rule had nothing in it to
    look at. That is the difference between a check that ran and found nothing
    and a check that never ran, which is the whole reason a clean result is hard
    to read.
    """
    # Plain sections rather than <details>: whether a closed <details> opens
    # when a link targets it is browser-dependent, and a link that lands on a
    # collapsed box has failed. Only the rules that fired are listed, so the
    # panel stays short enough to leave open.
    parts = [
        f'<article class="rule" id="rule-{html.escape(doc.id)}">',
        f'<h3><span class="mono">{html.escape(doc.id)}</span>'
        f'<span class="sev {html.escape(doc.severity.value)}">'
        f"{html.escape(doc.severity.value)}</span>"
        f'<span class="tag">{html.escape(doc.tier.value)}</span>'
        + (
            '<span class="tag inert">nothing to look at</span>'
            if inert is not None
            else ""
        )
        + "</h3>",
    ]
    if inert is not None:
        parts.append(
            f'<p class="inert-why">This check did not run on these configs: '
            f"{html.escape(inert.reason)}.</p>"
        )
    if doc.summary is None:
        # Said out loud rather than papered over. An entry that reads
        # "undocumented" is a defect anyone can see, which is the point.
        parts.append(
            '<p class="undocumented">This rule ships with no explanation of '
            "itself. What it reports is below; why it matters is not written "
            "down anywhere yet.</p>"
        )
    for paragraph in (doc.summary, *doc.checks):
        if paragraph:
            parts.append(f"<p>{html.escape(paragraph)}</p>")
    if doc.reports:
        # The message template, with {…} where a value is filled in. It is what
        # someone matches against when they see a finding and want to know which
        # rule wrote it.
        parts.append(f'<div class="trigger">reports: {html.escape(doc.reports)}</div>')
    if doc.remedy:
        parts.append(f'<div class="remedy">fix: {html.escape(doc.remedy)}</div>')
    if doc.silence:
        # The half of a rule a clean run depends on: a check that never fires is
        # indistinguishable from a check that found nothing until you know what
        # it declines to look at.
        notes = "".join(
            f"<li>{html.escape(note.note)}"
            f'<span class="src mono">{html.escape(note.source)}</span></li>'
            for note in doc.silence
        )
        parts.append(f'<p class="cap">Stays silent when:</p><ul>{notes}</ul>')
    else:
        parts.append(
            '<p class="cap">No test asserts that this rule stays quiet, so its '
            "silence is not evidence of anything.</p>"
        )
    parts.append(
        f'<p class="cap mono">{html.escape(doc.module)}.'
        f"{html.escape(doc.function)}</p></article>"
    )
    return "".join(parts)


def _rulebook_html(findings: list[Finding], config_dir: str = "") -> str:
    """What each rule on screen actually checks, and when it declines to fire.

    Only the rules that fired are listed. The full catalogue is a document; this
    is the footnote to the page someone is reading, and twenty-five entries under
    four findings would bury it.
    """
    book = _rulebook()
    seen: list[RuleDoc] = []
    for finding in findings:
        doc = book.get(finding.rule)
        if doc is not None and doc not in seen:
            seen.append(doc)
    if not seen:
        return ""
    plural = "" if len(seen) == 1 else "s"
    return (
        '<section class="rulebook"><h2>The rule{}</h2>'
        '<p class="cap">Each identifier above links here. Generated from the '
        "rules themselves, so it cannot describe a check the tool no longer "
        'makes. <a href="{}">See all {} checks</a>.</p>{}</section>'
    ).format(
        plural,
        html.escape(
            f"/rules?{urlencode({'dir': config_dir})}" if config_dir else "/rules"
        ),
        len(book),
        "".join(_rule_entry(doc) for doc in seen),
    )


def _comparison_html(comparison: Comparison) -> str:
    """What changed since the baseline, above the findings it changes.

    Only new findings mean a regression. The pre-existing ones were known and
    accepted when the baseline was taken, and treating them as failures makes
    every run red until a backlog is cleared, which is how a check gets ignored.
    """
    if comparison.error:
        return (
            '<div class="error">Baseline '
            f"<code>{html.escape(comparison.path)}</code>: "
            f"{html.escape(comparison.error)}</div>"
        )
    diff = comparison.diff
    if diff is None:
        return ""

    taken = diff.baseline_taken_at.strftime("%Y-%m-%d %H:%M")
    verdict = "regressed" if diff.new else "clean"

    # The most useful sentence this tool can print, and the easiest to bury. If
    # the configs are byte-identical and the findings are not, the network did
    # not change — the checks did. Nobody reading a diff expects to be told
    # that, and nobody works it out on their own either.
    unchanged_configs = not diff.configs_changed
    differences = bool(diff.new or diff.fixed)
    moved = ""
    if unchanged_configs and differences:
        moved = (
            "<strong>The configs are byte-identical to the baseline.</strong> "
            "Every difference below is a change in the checks, not in the "
            "network."
        )
    elif unchanged_configs:
        moved = "The configs are byte-identical to the baseline."
    # The other half of it. "The configs changed" invites a reader to attribute
    # every new finding to the network, which is wrong whenever the rule set
    # moved underneath the baseline too — and it moves more often than anyone
    # expects.
    if diff.rules_changed:
        moved += (
            " <strong>The checks changed too</strong> "
            f"({html.escape(diff.baseline_rules)} &rarr; "
            f"{html.escape(diff.current_rules)}), so a finding below may be a "
            "new check rather than a new defect."
        )
    elif not diff.rules_known:
        moved += (
            " This baseline predates the recording of which checks produced it, "
            "so whether the rule set has moved is unknown."
        )
    moved = moved.strip()
    counts = (
        f'<span class="c new">{len(diff.new)} new</span>'
        f'<span class="c fixed">{len(diff.fixed)} fixed</span>'
        f'<span class="c known">{len(diff.unchanged)} unchanged</span>'
    )
    churn = ""
    if diff.devices_added or diff.devices_removed:
        # A device appearing or leaving explains a pile of new or fixed findings
        # that would otherwise read as a change in the network's health.
        bits = []
        if diff.devices_added:
            bits.append("added " + ", ".join(diff.devices_added))
        if diff.devices_removed:
            bits.append("gone " + ", ".join(diff.devices_removed))
        churn = f'<p class="cap">Devices: {html.escape("; ".join(bits))}.</p>'

    fixed = ""
    if diff.fixed:
        cards = "".join(_finding_html(f, state="fixed") for f in diff.fixed)
        fixed = (
            '<details class="device-group"><summary>no longer reported'
            f'<span class="n">{len(diff.fixed)}</span></summary>{cards}</details>'
        )

    return (
        f'<div class="compare {verdict}"><strong>Compared with a baseline taken '
        f"{html.escape(taken)}.</strong> "
        f'<div class="counts-inline">{counts}</div>'
        + (f'<p class="moved">{moved}</p>' if moved else "")
        + '<p class="cap">Only new findings are a regression: the rest were '
        "known when the baseline was taken.</p>"
        f"{churn}</div>{fixed}"
    )


# Only when running from a checkout. An installed copy has no examples
# directory, and offering a link to one that is not there is worse than not
# offering it.
_EXAMPLE: Final = Path(__file__).resolve().parents[1] / "examples" / "two-site"


def _shapes_html() -> str:
    """The three shapes, under the hero, for someone who has not run anything.

    The landing page's job is to make one idea land: that a configuration can be
    correct at rest and still contain a failure. The hero shows one instance of
    that. These show that it is a family — there are three ways it happens, they
    look different from each other, and every finding the tool emits is one of
    the three.

    Each card says it is an illustration by sitting under a caption that
    describes a kind of defect rather than a device, and by naming no device at
    all. Nothing here is read from a fact pack, and there is no fact pack to read
    from on this page.
    """
    cards = "".join(
        f'<div class="shape" style="--i:{index}">{svg}'
        f"<h3>{html.escape(heading)}</h3><p>{html.escape(caption)}</p></div>"
        for index, (heading, caption, svg) in enumerate(art.shapes())
    )
    return f'<div class="shapes">{cards}</div>'


def _here_offer() -> str:
    """The directory the server was started in, if it holds any configs.

    Typing an absolute path into a box is the one piece of work this tool asks
    for before it does anything, and most of the time the answer is the
    directory the user was already standing in when they ran `serve`. Offering
    it as a link costs a walk of one directory and removes the whole step.

    Offered, never assumed. The page says which directory it is and the user
    clicks it, so nothing is read that was not asked for — which is the promise
    the paragraph above this offer makes.
    """
    here = Path.cwd()
    try:
        found = discovery.discover(here)
    except OSError:
        return ""
    if not found.configs:
        return ""
    link = html.escape(f"/?{urlencode({'dir': str(here)})}")
    count = len(found.configs)
    plural = "" if count == 1 else "s"
    return (
        f'<p class="offer">Started in <code>{html.escape(str(here))}</code>, '
        f'which holds {count} config{plural}. <a href="{link}">Analyse '
        f"{'it' if count == 1 else 'them'}</a>.</p>"
    )


def _example_offer() -> str:
    """A way in for someone who has not got a directory of configs to hand.

    The whole premise is that installing the tool is the entire setup. Landing
    on a text box and having nothing to type into it walks that back.
    """
    if not _EXAMPLE.is_dir():
        return ""
    link = html.escape(f"/?{urlencode({'dir': str(_EXAMPLE)})}")
    return (
        f'<p class="offer">No configs to hand? '
        f'<a href="{link}">Analyse the example network</a> — two sites, six '
        "devices, four planted defects, walked through in "
        "<code>docs/TUTORIAL.md</code>.</p>"
    )


def _unparsed_html(analysis: Analysis) -> str:
    """What the parsers did not understand, said out loud.

    A rule can only reason about facts that were extracted. Lines nobody read
    are not neutral — a group whose priority line was missed still produces
    findings, and they will be confident and wrong. Showing the count next to
    the result is what stops a partial reading from reading as a complete one.
    """
    total = sum(count for _, count in analysis.unparsed)
    devices = len(analysis.unparsed)
    lines = "line" if total == 1 else "lines"
    where = "device" if devices == 1 else "devices"
    worst = sorted(analysis.unparsed, key=lambda item: -item[1])[:6]
    listed = ", ".join(
        f'<span class="mono">{html.escape(device)}</span> ({count})'
        for device, count in worst
    )
    if devices > len(worst):
        listed += f", and {devices - len(worst)} more"
    return (
        '<div class="note unparsed"><strong>Not everything was read.</strong> '
        f"{total} {lines} across {devices} {where} are not represented in these "
        "findings, so anything that depended on them was not checked. "
        f"{listed}. Run <code>cassandra facts</code> on the same directory to "
        "see them.</div>"
    )


def _hidden_filters(filters: Filters) -> str:
    """Keep the active filters when the directory form is submitted.

    `since` and `q` are skipped: the form carries both in visible fields, and
    submitting two inputs of the same name sends both.
    """
    return "".join(
        f'<input type="hidden" name="{name}" value="{html.escape(value)}">'
        for name, value in _query_pairs("", filters)
        if name not in {"since", "q"}
    )


def page(
    config_dir: str,
    analysis: Analysis,
    filters: Filters,
    comparison: Comparison | None = None,
) -> str:
    visible = [finding for finding in analysis.findings if filters.matches(finding)]
    sections: list[str] = []

    if filters.unknown:
        ignored = ", ".join(
            f"<code>{html.escape(value)}</code>" for value in filters.unknown
        )
        sections.append(
            f'<p class="note">Ignored filter values that name no severity or tier: '
            f"{ignored}.</p>"
        )

    # A device name is free text, so a filter for one that is not in the pack has
    # to be reported here rather than at parse time. Silently showing nothing
    # looks identical to a device that is genuinely clean.
    known = {finding.device for finding in analysis.findings}
    if analysis.pack is not None:
        known |= {device.id for device in analysis.pack.devices}
    absent = sorted(device for device in filters.devices if device not in known)
    if absent:
        named = ", ".join(f"<code>{html.escape(device)}</code>" for device in absent)
        sections.append(
            f'<p class="note">No device here is called {named}. '
            "Names come from each config's own hostname line.</p>"
        )

    if comparison is not None and (comparison.diff or comparison.error):
        sections.append(_comparison_html(comparison))

    if analysis.error:
        sections.append(f'<div class="error">{html.escape(analysis.error)}</div>')
    elif not config_dir:
        sections.append(
            '<div class="empty landing">'
            "<p><strong>Enter a directory of device configs.</strong> "
            "It is walked, not globbed: nested directories are followed, and "
            "anything that reads like a config is read whether it is called "
            "<code>.cfg</code>, <code>.conf</code>, <code>.txt</code> or "
            "nothing at all. Documents, inventories and binaries are skipped. "
            "Nothing leaves this machine and nothing is written to the "
            "directory.</p>"
            f"{art.hero_svg()}"
            '<p class="cap">Illustration, not a result. Two gateway groups '
            "follow the same link failure at different speeds — one preempts "
            "back early, the other waits out a delay — and the hatched window "
            "is the stretch where they sit on different devices. Steady-state "
            "analysis never sees it, because at rest the configuration is "
            "correct.</p>"
            + _shapes_html()
            + _here_offer()
            + _example_offer()
            + "</div>"
        )
    elif not analysis.findings:
        sections.append(
            '<div class="empty"><strong>No findings.</strong><br>Nothing in these '
            "configs trips a consistency rule, and no event sequence the timing "
            "model explored produced a sustained divergence."
            # The same two lanes and the same event as the landing page's hero,
            # with the gap closed. A clean run is a claim about what was
            # searched rather than about the network, and showing what was
            # searched is a smaller and more honest thing to say than "fine".
            f"{art.steady_svg()}"
            '<p class="cap">Both groups answered the event at the same moment, '
            "so there is no window between them. That is not proof the network "
            "is sound: the timing tier searches a neighbourhood of sequences "
            "derived from the timers it found, not the whole space, and it only "
            "models what the parsers understood.</p></div>"
        )
    else:
        sections.append(_filter_bar(config_dir, analysis.findings, filters))
        if visible:
            sections.append(_counts_html(visible, len(analysis.findings)))
            shown = visible if filters.show_all else visible[:PAGE_LIMIT]
            if len(shown) < len(visible):
                more = href("/", config_dir, replace(filters, show_all=True))
                sections.append(
                    f'<p class="note">Showing the worst {len(shown)} of '
                    f"{len(visible)} on this page. Nothing was dropped from the "
                    f"count, the report or "
                    f'<a href="{href("/findings.json", config_dir, filters)}">'
                    f'findings.json</a>. <a href="{more}">Render all '
                    f"{len(visible)}</a> — expect a slow page.</p>"
                )
            figures = 0
            for device, group in _by_device(shown):
                draw = figures < FIGURE_LIMIT
                sections.append(
                    _device_html(
                        device,
                        group,
                        analysis.pack,
                        comparison,
                        draw_figures=draw,
                    )
                )
                if draw and any(f.tier is Tier.TIMING for f in group):
                    figures += 1
            if figures >= FIGURE_LIMIT:
                sections.append(
                    f'<p class="note">Timelines are drawn for the first '
                    f"{FIGURE_LIMIT} devices. They repeat the same shape and "
                    f"dominate the size of the page; filter to one device to "
                    f"see its own.</p>"
                )
        else:
            clear = href(
                "/",
                config_dir,
                replace(
                    filters,
                    severities=frozenset(),
                    tiers=frozenset(),
                    devices=frozenset(),
                    query="",
                ),
            )
            sections.append(
                '<div class="empty">No findings match these filters. '
                f'<a href="{clear}">Show all {len(analysis.findings)}</a>.</div>'
            )

    if visible:
        sections.append(_rulebook_html(visible, config_dir))

    if analysis.unparsed:
        sections.append(_unparsed_html(analysis))

    if any(finding.tier is Tier.TIMING for finding in visible):
        sections.append(f'<p class="caveat">{_TIMING_CAVEAT}</p>')

    if analysis.digest:
        devices = f"{analysis.device_count} device"
        devices += "" if analysis.device_count == 1 else "s"
        sections.append(
            '<p class="provenance">'
            f"fact pack <code>{html.escape(analysis.fact_pack_id)}</code> · "
            f"{devices} · digest <code>{html.escape(analysis.digest[:12])}</code> · "
            f'<a href="{href("/facts", config_dir, Filters())}">'
            "what was read</a> · "
            f'<a href="{href("/report.html", config_dir, filters)}">'
            "download report</a> · "
            f'<a href="{href("/findings.json", config_dir, filters)}">'
            "findings.json</a> · "
            '<a href="/rules.json">rules.json</a></p>'
        )

    worst = min(
        (f.severity for f in visible),
        key=lambda s: list(Severity).index(s),
        default=None,
    )
    pulse = "pulse alert" if worst is Severity.HIGH else "pulse"
    topology = ""
    if analysis.pack is not None:
        with_findings = {f.device for f in analysis.findings}
        # Findings arrive ranked, so the first one seen for a device is its
        # worst: a device with one high and three lows is marked high.
        worst_by_device: dict[str, str] = {}
        for finding in analysis.findings:
            worst_by_device.setdefault(finding.device, finding.severity.value)
        drawn = visuals.topology_svg(
            analysis.pack,
            lambda device: (
                href(
                    "/",
                    config_dir,
                    replace(filters, devices=_toggle(filters.devices, device)),
                )
                if device in with_findings
                else ""
            ),
            worst_by_device,
        )
        if drawn:
            topology = (
                '<div class="figure"><h2>adjacency</h2>'
                '<p class="cap">Devices, and the subnets they share. A marked '
                "device has findings, coloured by the worst of them, and is a "
                "link to them.</p>"
                f"{drawn}</div>"
            )
        reaction = visuals.reaction_svg(analysis.pack)
        if reaction:
            topology += (
                '<div class="figure"><h2>how each group reacts</h2>'
                '<p class="cap">The timeline below draws the effect; this draws '
                "the cause. Two rows that do not match are two groups that will "
                "answer the same event at different speeds.</p>"
                f"{reaction}</div>"
            )

    finder = f"""<form class="finder" method="get" action="/">
  <input type="text" name="dir" placeholder="/path/to/configs"
         value="{html.escape(config_dir)}" autofocus accesskey="d"
         aria-label="directory of device configs to analyse"
         spellcheck="false" autocapitalize="off" autocorrect="off">
  <input type="text" name="q" class="query" placeholder="search findings"
         value="{html.escape(filters.query)}" spellcheck="false"
         aria-label="filter findings by text"
         autocapitalize="off" autocorrect="off">
  <input type="text" name="since" class="since" placeholder="baseline.json"
         value="{html.escape(filters.since)}" spellcheck="false"
         aria-label="a saved baseline to compare this run against"
         autocapitalize="off" autocorrect="off">
  {_hidden_filters(filters)}
  <button class="go" type="submit">Analyse</button>
</form>"""
    return _shell(finder + topology + "".join(sections), pulse=pulse)


def rules_page(pack: StaticFactPack | None = None, config_dir: str = "") -> str:
    """The whole catalogue, not just the rules something tripped.

    The panel under a result answers "what does this finding mean". This answers
    the question that comes before running anything at all: what does this tool
    look for, and — the half that decides whether a clean run means anything —
    what does it decline to look at.

    Given a fact pack, it also answers the sharper version of that question: of
    these checks, which ones had anything in *your* configs to examine.
    """
    docs = catalogue()
    inert: dict[str, RuleCoverage] = {}
    unread: tuple[coverage.UnreadFact, ...] = ()
    if pack is not None:
        assessment = coverage.assess_all(pack)
        inert = {
            entry.rule: entry for entry in assessment.rules if not entry.applicable
        }
        unread = assessment.unread
    undocumented = sum(1 for doc in docs if not doc.documented)
    untested = sum(1 for doc in docs if not doc.silence)
    by_tier: list[str] = []
    for tier in _TIER_ORDER:
        entries = [doc for doc in docs if doc.tier is tier]
        if not entries:
            continue
        by_tier.append(
            f'<h2 class="tier-head">{html.escape(tier.value)} tier '
            f'<span class="n">{len(entries)}</span></h2>'
            + "".join(_rule_entry(doc, inert.get(doc.id)) for doc in entries)
        )

    # Stated rather than left for someone to count. Both numbers measure this
    # tool's own documentation debt, and hiding them would be the one dishonest
    # thing a page about honesty could do.
    health = (
        f'<p class="cap">{len(docs)} rules. '
        f"{undocumented} carry no explanation of themselves. "
        f"{untested} have no test asserting they stay quiet, so their silence "
        "is not evidence of anything.</p>"
    )
    if pack is not None:
        live = len(docs) - len(inert)
        health += (
            f'<p class="offer"><strong>{live} of {len(docs)} had something to '
            f"look at in {html.escape(config_dir or 'these configs')}.</strong> "
            f"The other {len(inert)} are marked below with what they were "
            "missing. A check that could not run is not a check that passed."
            "</p>"
        )
    return _shell(
        '<section class="rulebook">'
        "<h2>Every check this tool makes</h2>"
        '<p class="cap">Generated from the rules themselves, so it cannot '
        "describe a check the tool no longer makes, and cannot omit one it "
        'does. <a href="/">Back to findings</a>.</p>'
        + health
        + _unread_html(unread, config_dir)
        + "".join(by_tier)
        + "</section>"
    )


def _unread_html(unread: tuple[coverage.UnreadFact, ...], config_dir: str) -> str:
    """Facts these configs state that no check on this page consults.

    On the page that lists every check, because that is where the question
    belongs: a reader is here to find out what this tool looks for, and the
    honest answer includes what it read out of their files and then did nothing
    with. Every entry is a check nobody has written rather than a check that
    passed, and saying so on the catalogue rather than beside a finding keeps it
    a statement about the tool instead of about the network.
    """
    if not unread:
        return ""
    items = "".join(
        f"<li>{html.escape(fact.label)} "
        f'<span class="src mono">{html.escape(fact.path)}</span> '
        f'<span class="n">{fact.records}</span></li>'
        for fact in unread
    )
    where = html.escape(config_dir) if config_dir else "these configs"
    return (
        f'<details class="device-group unread-facts"><summary>'
        f"{len(unread)} facts read out of {where} that no check read"
        "</summary>"
        f'<p class="cap">Each was parsed into the fact pack and nothing above '
        f"opened it on this run — either because no rule reads it at all, which "
        f"is a check nobody has written, or because the only rule that does "
        f"returned before it got there. The number is how many records state "
        f"it.</p>"
        f"<ul>{items}</ul></details>"
    )


def _row(cells: list[str], *, head: bool = False) -> str:
    tag = "th" if head else "td"
    return "<tr>" + "".join(f"<{tag}>{cell}</{tag}>" for cell in cells) + "</tr>"


def _interface_rows(device: Device) -> str:
    rows = [
        _row(["interface", "kind", "addresses", "mode", "vlans", "state"], head=True)
    ]
    for interface in device.interfaces:
        addresses = ", ".join(a.prefix for a in interface.addresses) or "—"
        vlans = "—"
        if interface.access_vlan:
            vlans = str(interface.access_vlan)
        elif interface.allowed_vlans:
            vlans = ",".join(str(v) for v in interface.allowed_vlans)
        state = "up" if interface.admin_enabled else "shutdown"
        rows.append(
            _row(
                [
                    f'<span class="mono">{html.escape(interface.name)}</span>',
                    html.escape(interface.kind.value),
                    f'<span class="mono">{html.escape(addresses)}</span>',
                    html.escape(interface.switchport_mode.value),
                    f'<span class="mono">{html.escape(vlans)}</span>',
                    f'<span class="state-{state}">{state}</span>',
                ]
            )
        )
    return '<table class="facts">' + "".join(rows) + "</table>"


def _group_rows(pack: StaticFactPack, device: str) -> str:
    """The FHRP groups this device is a member of, with what decides them."""
    delays = {
        (t.scope.device, t.scope.interface, t.scope.instance): t.preempt_delay_ms
        for t in pack.timers.fhrp
    }
    rows = [
        _row(
            ["group", "interface", "virtual", "priority", "preempt", "tracks"],
            head=True,
        )
    ]
    found = False
    for group in pack.fhrp_groups:
        for member in group.members:
            if member.device != device:
                continue
            found = True
            delay = delays.get(
                (
                    member.device,
                    member.interface,
                    fhrp_instance(group.group_number, group.family),
                )
            )
            preempt = "no"
            if member.preempt:
                preempt = f"after {delay // 1000}s" if delay else "immediately"
            # A flag nobody wrote down reads the same as one somebody chose
            # until the provenance is beside it, and the two are different
            # things to be looking at when a group is not where it should be.
            if member.preempt_source is not TimerSource.CONFIGURED:
                preempt += f" ({member.preempt_source.value})"
            tracks = (
                ", ".join(
                    f"{t.target or t.id} \u2212{t.decrement}"
                    for t in member.tracked_objects
                )
                or "—"
            )
            rows.append(
                _row(
                    [
                        html.escape(group.label),
                        f'<span class="mono">{html.escape(member.interface)}</span>',
                        f'<span class="mono">'
                        f"{html.escape(group.virtual_address or '—')}</span>",
                        str(member.priority),
                        html.escape(preempt),
                        f'<span class="mono">{html.escape(tracks)}</span>',
                    ]
                )
            )
    if not found:
        return ""
    return '<table class="facts">' + "".join(rows) + "</table>"


def facts_page(
    pack: StaticFactPack | None,
    unparsed: tuple[tuple[str, int], ...],
    config_dir: str,
    error: str | None = None,
) -> str:
    """What the tool understood, device by device.

    The command line has printed this from the start and the page never has,
    which left the one question a reader most needs answered — *did it read my
    configs the way I read them?* — reachable only from a shell. A finding is
    only as good as the reading under it, and the reading is not something to
    take on trust.
    """
    if error or pack is None:
        message = error or "Enter a directory of device configs."
        return _shell(
            '<section class="rulebook"><h2>What the tool read</h2>'
            f'<div class="{"error" if error else "empty"}">'
            f"{html.escape(message)}</div></section>"
        )
    back = href("/", config_dir, Filters())
    return _shell(
        '<section class="rulebook"><h2>What the tool read</h2>'
        '<p class="cap">A finding is only as good as the reading under it. '
        f'This is that reading. <a href="{back}">Back to findings</a>.</p>'
        + facts_cards(pack, unparsed)
        + "</section>"
    )


def _bgp_rows(pack: StaticFactPack, device: str) -> str:
    """This device's BGP peerings, as one-sided statements about a peer.

    One-sided on purpose, because that is what the configuration is: this table
    says what this device asked for, and the disagreement between two ends is a
    finding rather than a fact.
    """
    processes = [process for process in pack.bgp if process.device == device]
    if not processes:
        return ""
    rows = [_row(["peer", "remote as", "update source", "bfd"], head=True)]
    for process in processes:
        for neighbor in process.neighbors:
            rows.append(
                _row(
                    [
                        f'<span class="mono">{html.escape(neighbor.address)}</span>',
                        html.escape(neighbor.remote_as or "—"),
                        f'<span class="mono">'
                        f"{html.escape(neighbor.update_source or '—')}</span>",
                        "yes" if neighbor.bfd else "—",
                    ]
                )
            )
    local = ", ".join(
        f"AS {html.escape(process.local_as)}"
        + (
            f" · router-id {html.escape(process.router_id)}"
            if process.router_id
            else ""
        )
        for process in processes
    )
    body = '<table class="facts">' + "".join(rows) + "</table>" if len(rows) > 1 else ""
    return f'<p class="cap">BGP — {local}</p>{body}'


# Every timer family, the words for it, and how to say one record's values. The
# page and `cassandra facts` show the same eight because they answer the same
# question; a family printed by one and not the other would be a fact the tool
# read and one of its two windows onto the reading did not admit to.
_TIMER_FAMILIES: Final = (
    ("fhrp", ("hello_interval_ms", "hold_time_ms", "preempt_delay_ms")),
    ("igp hello", ("hello_interval_ms", "dead_interval_ms")),
    ("bfd", ("desired_min_tx_ms", "required_min_rx_ms", "detect_multiplier")),
    ("bgp", ("keepalive_ms", "hold_time_ms", "graceful_restart_time_s")),
    ("stp", ("hello_time_ms", "forward_delay_ms", "max_age_ms")),
    ("spf throttle", ("initial_delay_ms", "min_hold_ms", "max_wait_ms")),
    ("carrier delay", ("up_ms", "down_ms")),
    ("dampening", ("half_life_s", "suppress_threshold", "max_suppress_s")),
)


def _timer_value(name: str, value: object) -> str:
    if value is None:
        return ""
    label = name.removesuffix("_ms").removesuffix("_s").replace("_", " ")
    unit = "ms" if name.endswith("_ms") else "s" if name.endswith("_s") else ""
    return f"{label} {value}{unit}"


def _timer_rows(pack: StaticFactPack, device: str) -> str:
    """Every timer record scoped to this device, whatever family it is in.

    Grouped by family rather than by scope because the families are what a
    reader is checking for — the question this table answers is "did it read my
    BGP timers", and the answer is the row's presence.
    """
    rows = [_row(["family", "scope", "values"], head=True)]
    for family, fields in _TIMER_FAMILIES:
        for record in getattr(pack.timers, family.replace(" ", "_"), ()):
            if record.scope.device != device:
                continue
            stated = [
                said
                for name in fields
                if (said := _timer_value(name, getattr(record, name, None)))
            ]
            if not stated:
                continue
            scope = record.scope.interface or record.scope.neighbor or "device"
            if record.scope.instance:
                scope = f"{scope} [{record.scope.instance}]"
            rows.append(
                _row(
                    [
                        html.escape(family),
                        f'<span class="mono">{html.escape(scope)}</span>',
                        f'<span class="mono">{html.escape("  ".join(stated))}</span>',
                    ]
                )
            )
    if len(rows) == 1:
        return ""
    return '<p class="cap">Timers</p><table class="facts">' + "".join(rows) + "</table>"


def facts_cards(pack: StaticFactPack, unparsed: tuple[tuple[str, int], ...]) -> str:
    """The reading itself, without a page around it.

    Separate so the standalone report can carry it too. A report is the copy
    that travels, and its reader is the one least able to go and check the
    configs it was made from.
    """
    missed = dict(unparsed)
    cards: list[str] = []
    for device in pack.devices:
        groups = _group_rows(pack, device.id)
        left = missed.get(device.id, 0)
        note = ""
        if left:
            note = (
                f'<p class="note unparsed">{left} line'
                f"{'' if left == 1 else 's'} on this device were not understood "
                "and are in no finding. <code>cassandra facts</code> lists "
                "them.</p>"
            )
        cards.append(
            f'<article class="rule device-facts">'
            f'<h3><span class="mono">{html.escape(device.id)}</span>'
            f'<span class="tag">{html.escape(device.nos_family.value)}</span>'
            + (
                f'<span class="cite mono">{html.escape(device.config_path)}</span>'
                if device.config_path
                else ""
            )
            + "</h3>"
            + note
            + _interface_rows(device)
            + (
                f'<p class="cap">FHRP</p>{groups}'
                if groups
                else '<p class="cap">No FHRP group on this device.</p>'
            )
            + _bgp_rows(pack, device.id)
            + _timer_rows(pack, device.id)
            + "</article>"
        )

    total_missed = sum(count for _, count in unparsed)
    summary = (
        f'<p class="cap">{len(pack.devices)} devices, '
        f"{sum(len(d.interfaces) for d in pack.devices)} interfaces, "
        f"{len(pack.fhrp_groups)} FHRP groups. "
        + (
            f"{total_missed} lines were not understood."
            if total_missed
            else "Every line was read."
        )
        + "</p>"
    )
    return summary + "".join(cards)


def _shell(body: str, *, pulse: str = "pulse") -> str:
    """The page around the content: head, masthead, theme control.

    One shell for every page, so the findings view, the catalogue and the
    standalone report cannot drift into looking like three different tools.
    """
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cassandra</title><style>{STYLE}</style></head>
<body>
<div class="progress" aria-hidden="true"></div>
<main>
<header class="masthead">
  <input class="theme-input" type="checkbox" id="theme-toggle">
  <label class="theme" for="theme-toggle" title="switch between light and dark">
    <span class="moon" aria-hidden="true">&#9789;</span>
    <span class="sun" aria-hidden="true">&#9788;</span>
    <span class="visually-hidden">switch between light and dark</span>
  </label>
  <h1 class="wordmark">{art.mark_svg()}<span class="{pulse}"></span>Cassandra</h1>
  <p class="tagline">Latent failure modes in network configuration &mdash; the ones
  that only exist between events.</p>
</header>
{body}
</main></body></html>"""


def rules_json() -> str:
    """The whole catalogue, structured. Lives here with the page that renders
    the same data, so the two cannot describe different rule sets."""
    return json.dumps([asdict(doc) for doc in catalogue()], indent=2)


def as_json(findings: list[Finding]) -> str:
    """The findings alone, without the pack identity.

    Kept because it is the shape callers already read. `/findings.json` sends
    the full document from `report.as_json`, which carries the digest of the
    configs the findings came from — the same answer the CLI's `--json` gives,
    because two shapes for one question is how a consumer ends up handling only
    one of them.
    """
    return json.dumps(_finding_dicts(findings), indent=2)


def _finding_dicts(findings: list[Finding]) -> list[dict[str, object]]:
    return [
        {
            "rule": finding.rule,
            "tier": finding.tier.value,
            "severity": finding.severity.value,
            "device": finding.device,
            "title": finding.title,
            "detail": finding.detail,
            "trigger": finding.trigger,
            "remedy": finding.remedy,
            "evidence": list(finding.evidence),
            # Split rather than "file:line", because a path may contain a colon
            # and a consumer should not have to guess where to cut.
            "source": (
                None
                if finding.source is None
                else {"file": finding.source.file, "line": finding.source.line}
            ),
        }
        for finding in findings
    ]
