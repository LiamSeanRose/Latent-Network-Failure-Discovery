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

from cassandra import art, baseline, visuals
from cassandra.catalogue import RuleDoc, catalogue
from cassandra.findings import Finding, Severity, Tier
from cassandra.style import STYLE

if TYPE_CHECKING:  # pragma: no cover - types, not dependencies
    from cassandra.app import Analysis
    from cassandra.factpack.schema import StaticFactPack


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


def _rule_entry(doc: RuleDoc) -> str:
    """One rule, opened by clicking its identifier in a finding."""
    # Plain sections rather than <details>: whether a closed <details> opens
    # when a link targets it is browser-dependent, and a link that lands on a
    # collapsed box has failed. Only the rules that fired are listed, so the
    # panel stays short enough to leave open.
    parts = [
        f'<article class="rule" id="rule-{html.escape(doc.id)}">',
        f'<h3><span class="mono">{html.escape(doc.id)}</span>'
        f'<span class="sev {html.escape(doc.severity.value)}">'
        f"{html.escape(doc.severity.value)}</span>"
        f'<span class="tag">{html.escape(doc.tier.value)}</span></h3>',
    ]
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


def _rulebook_html(findings: list[Finding]) -> str:
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
        'makes. <a href="/rules">See all {} checks</a>.</p>{}</section>'
    ).format(plural, len(book), "".join(_rule_entry(doc) for doc in seen))


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
            "correct.</p>" + _example_offer() + "</div>"
        )
    elif not analysis.findings:
        sections.append(
            '<div class="empty"><strong>No findings.</strong><br>Nothing in these '
            "configs trips a consistency rule, and no event sequence the timing "
            "model explored produced a sustained divergence."
            '<p class="cap">That is not proof the network is sound. The timing '
            "tier searches a neighbourhood of sequences derived from the timers "
            "it found, not the whole space, and it only models what the parsers "
            "understood.</p></div>"
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
        sections.append(_rulebook_html(visible))

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


def rules_page() -> str:
    """The whole catalogue, not just the rules something tripped.

    The panel under a result answers "what does this finding mean". This answers
    the question that comes before running anything at all: what does this tool
    look for, and — the half that decides whether a clean run means anything —
    what does it decline to look at.
    """
    docs = catalogue()
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
            + "".join(_rule_entry(doc) for doc in entries)
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
    return _shell(
        '<section class="rulebook">'
        "<h2>Every check this tool makes</h2>"
        '<p class="cap">Generated from the rules themselves, so it cannot '
        "describe a check the tool no longer makes, and cannot omit one it "
        'does. <a href="/">Back to findings</a>.</p>'
        + health
        + "".join(by_tier)
        + "</section>"
    )


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
