"""Command line entry point.

Phase 1 provides `facts` only. `check` and `analyze` arrive with the FACTS and
TIMING tiers (PROJECT.md §4.2).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from cassandra import baseline, coverage
from cassandra.app import analyse, compare_with, serve
from cassandra.catalogue import catalogue, render_text
from cassandra.factpack import discovery
from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack
from cassandra.facts import rules
from cassandra.findings import Finding, Severity, locate
from cassandra.report import as_json, render
from cassandra.report_html import write as write_html
from cassandra.timing import sequences, timer_rules


def render_facts(pack: StaticFactPack, unparsed: dict[str, tuple[str, ...]]) -> str:
    """Newline-delimited structured text, not JSON — denser and easier to scan."""
    lines: list[str] = [
        f"fact-pack {pack.meta.fact_pack_id}  devices={pack.meta.device_count}"
        f"  digest={pack.meta.config_digest[:12]}",
        "",
    ]
    for device in pack.devices:
        lines.append(f"device {device.id}  nos={device.nos_family.value}")
        for interface in device.interfaces:
            bits = [f"  {interface.name}", f"kind={interface.kind.value}"]
            if interface.addresses:
                bits.append(",".join(a.prefix for a in interface.addresses))
            if interface.switchport_mode.value != "none":
                bits.append(f"mode={interface.switchport_mode.value}")
            if interface.access_vlan:
                bits.append(f"access-vlan={interface.access_vlan}")
            if interface.allowed_vlans:
                bits.append(
                    "trunk-vlans=" + ",".join(str(v) for v in interface.allowed_vlans)
                )
            if not interface.admin_enabled:
                bits.append("shutdown")
            lines.append("  ".join(bits))
        lines.append("")

    for group in pack.fhrp_groups:
        lines.append(f"fhrp {group.label} virtual={group.virtual_address}")
        for member in group.members:
            tracked = ", ".join(
                f"{t.id}->{t.target} -{t.decrement}" for t in member.tracked_objects
            )
            lines.append(
                f"  {member.device}:{member.interface}  priority={member.priority}"
                f"  preempt={'yes' if member.preempt else 'no'}"
                + (f"  tracks={tracked}" if tracked else "  tracks=none")
            )
    lines.append("")

    lines.append("timers")
    for timer in pack.timers.fhrp:
        parts = [
            f"  {timer.scope.device}:{timer.scope.interface}",
            f"group={timer.scope.instance}",
            f"hello={timer.hello_interval_ms}ms",
        ]
        if timer.preempt_delay_ms is not None:
            parts.append(f"preempt-delay={timer.preempt_delay_ms}ms")
        parts.append(f"source={timer.scope.source.value}")
        lines.append("  ".join(parts))

    leftovers = {device: rest for device, rest in unparsed.items() if rest}
    if leftovers:
        lines.extend(["", "unparsed (not represented in the fact pack)"])
        for device, rest in sorted(leftovers.items()):
            lines.extend(f"  {device}: {line}" for line in rest)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cassandra", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    facts = sub.add_parser("facts", help="materialise a fact pack from configs")
    facts.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit the whole fact pack as JSON instead of structured text",
    )
    facts.add_argument("config_dir", type=Path)

    check = sub.add_parser("check", help="report latent failure modes in configs")
    check.add_argument("config_dir", type=Path)
    check.add_argument(
        "--explain",
        action="store_true",
        help="show evidence, suggested fixes and rule ids",
    )
    check.add_argument(
        "--save-baseline",
        type=Path,
        metavar="FILE",
        help=(
            "record this run so a later one can be compared against it. The exit "
            "status still reports the check, so a run with findings exits 1 even "
            "when the baseline is written"
        ),
    )
    check.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit findings as JSON for a pipeline instead of text",
    )
    check.add_argument(
        "--fail-on",
        choices=[severity.value for severity in Severity],
        metavar="SEVERITY",
        help=(
            "exit non-zero only at this severity or worse "
            f"({', '.join(s.value for s in Severity)}). The report is unchanged; "
            "this decides the verdict, so a pipeline can block on high while "
            "still printing everything"
        ),
    )
    check.add_argument(
        "--since",
        type=Path,
        metavar="FILE",
        help="report only what changed since a saved baseline",
    )
    check.add_argument(
        "--coverage",
        nargs="?",
        const="summary",
        choices=("summary", "full"),
        metavar="summary|full",
        help=(
            "say which checks had facts to work with and which were inert. A "
            "clean run and a run where most of the rule set never had an input "
            "look identical without this. `full` lists every check"
        ),
    )

    report = sub.add_parser("report", help="write a shareable HTML report")
    report.add_argument("config_dir", type=Path)
    report.add_argument(
        "-o", "--output", type=Path, default=Path("cassandra-report.html")
    )
    report.add_argument(
        "--since",
        type=Path,
        metavar="FILE",
        help=(
            "mark each finding new or known against a saved baseline, and list "
            "the ones that stopped being reported"
        ),
    )

    explain_rules = sub.add_parser("rules", help="explain the checks this tool makes")
    explain_rules.add_argument(
        "rule",
        nargs="?",
        help="a rule id as printed by a finding; omit to list every rule",
    )

    app = sub.add_parser("serve", help="open the local web view")
    app.add_argument(
        "config_dir",
        type=Path,
        nargs="?",
        help="open on this directory instead of an empty page",
    )
    app.add_argument("--port", type=int, default=8765)
    app.add_argument("--host", default="127.0.0.1")

    args = parser.parse_args(argv)
    if args.command == "facts":
        loaded = _load(args.config_dir)
        if loaded is None:
            return 2
        pack, unparsed = loaded
        if args.as_json:
            # The fact pack is what every tier reasons over. Handing it out
            # whole lets someone check the tool's reading of their configs
            # against their own, which is the only way to catch a parser that is
            # quietly wrong rather than quietly silent.
            print(
                json.dumps(
                    {
                        "meta": asdict(pack.meta),
                        "devices": [asdict(device) for device in pack.devices],
                        "vlans": [asdict(vlan) for vlan in pack.vlans],
                        "fhrp_groups": [asdict(g) for g in pack.fhrp_groups],
                        "timers": asdict(pack.timers),
                        "unparsed": {
                            device: list(rest)
                            for device, rest in sorted(unparsed.items())
                            if rest
                        },
                    },
                    indent=2,
                    default=str,
                )
            )
            return 0
        print(render_facts(pack, unparsed))
        return 0

    if args.command == "check":
        loaded = _load(args.config_dir)
        if loaded is None:
            return 2
        pack, unparsed = loaded
        _warn_unparsed(unparsed)
        # Located here rather than in each rule: a rule states what it found and
        # names the objects it found it on, and reading those back out of the
        # text is the one place that knows how to turn them into a file and a
        # line (PROJECT.md §5.4).
        findings = locate(
            rules.evaluate(pack) + timer_rules.analyse(pack) + sequences.analyse(pack),
            pack,
        )

        if args.save_baseline:
            try:
                baseline.save(findings, pack, args.save_baseline)
            except baseline.BaselineError as error:
                print(error, file=sys.stderr)
                return 2
            print(f"baseline written to {args.save_baseline}", file=sys.stderr)

        if args.since:
            try:
                previous = baseline.load(args.since)
                diff = baseline.compare(previous, baseline.snapshot(findings, pack))
            except baseline.BaselineError as error:
                print(error, file=sys.stderr)
                return 2
            print(baseline.render_diff(diff, explain=args.explain))
            _report_coverage(pack, args.coverage, quiet=False)
            # Only NEW findings fail a regression check. The pre-existing ones
            # were known and accepted when the baseline was taken, and failing on
            # them would make every run red until the backlog is cleared, which
            # is how a check gets switched off.
            return 1 if diff.new else 0

        if args.as_json:
            print(
                as_json(
                    findings,
                    pack_id=pack.meta.fact_pack_id,
                    digest=pack.meta.config_digest,
                )
            )
        else:
            print(render(findings, explain=args.explain))
        _report_coverage(pack, args.coverage, quiet=args.as_json)
        # Exit status is the verdict: non-zero when something needs attention, so
        # this is usable in a pre-commit hook or CI without parsing the output.
        # --fail-on narrows what counts as attention without narrowing the
        # report, because a pipeline that only blocks on high still wants the
        # low ones printed where someone will see them.
        return 1 if _blocking(findings, args.fail_on) else 0

    if args.command == "report":
        analysis = analyse(args.config_dir)
        if analysis.error:
            print(analysis.error, file=sys.stderr)
            return 2
        comparison = compare_with(analysis, str(args.since) if args.since else "")
        if comparison.error:
            print(comparison.error, file=sys.stderr)
            return 2
        written = write_html(analysis, args.config_dir, args.output, comparison)
        print(f"wrote {written}", file=sys.stderr)
        # With a baseline the verdict is the regression, not the backlog: the
        # findings that were already there were accepted when it was taken.
        if comparison.diff is not None:
            return 1 if comparison.diff.new else 0
        return 1 if analysis.findings else 0

    if args.command == "rules":
        if args.rule and args.rule not in {doc.id for doc in catalogue()}:
            # A lookup that names no rule is the user mistyping, not a result.
            print(f"no such rule: {args.rule}", file=sys.stderr)
            print(render_text(), file=sys.stderr)
            return 2
        print(render_text(args.rule))
        return 0

    if args.command == "serve":
        if args.config_dir is not None and not args.config_dir.is_dir():
            print(f"not a directory: {args.config_dir}", file=sys.stderr)
            return 2
        serve(host=args.host, port=args.port, config_dir=args.config_dir)
        return 0

    return 2


def _report_coverage(pack: StaticFactPack, wanted: str | None, *, quiet: bool) -> None:
    """Say which checks had something to look at, after saying what they found.

    After, because the findings are what the user came for. The coverage line is
    the caveat on them — thirty of forty-five checks inert is a different result
    from a clean run, and it is not visible in a report that says nothing.

    Goes to stderr alongside the JSON, so a pipeline parsing the findings is not
    handed a paragraph of prose in the middle of them.
    """
    if wanted is None:
        return
    assessed = coverage.assess(pack)
    text = (
        coverage.render_text(assessed)
        if wanted == "full"
        else coverage.summary(assessed)
    )
    print(text, file=sys.stderr if quiet else sys.stdout)


def _warn_unparsed(unparsed: dict[str, tuple[str, ...]]) -> None:
    """Say how much of the input was not understood, before the findings.

    A rule can only reason about facts that were extracted, and a line nobody
    read is not neutral: a group whose priority line was missed still produces
    findings, and they are confident and wrong. This goes to stderr so it does
    not pollute a piped result, and it goes first so it is read.
    """
    leftovers = {device: rest for device, rest in unparsed.items() if rest}
    if not leftovers:
        return
    total = sum(len(rest) for rest in leftovers.values())
    lines = "line" if total == 1 else "lines"
    where = "device" if len(leftovers) == 1 else "devices"
    print(
        f"note: {total} {lines} across {len(leftovers)} {where} were not "
        "understood and are not represented in these findings. "
        "`cassandra facts` on the same directory lists them.",
        file=sys.stderr,
    )


def _blocking(findings: list[Finding], threshold: str | None) -> list[Finding]:
    """The findings that decide the exit status."""
    if threshold is None:
        return findings
    order = list(Severity)
    limit = order.index(Severity(threshold))
    return [f for f in findings if order.index(f.severity) <= limit]


def _load(config_dir: Path) -> tuple[StaticFactPack, dict[str, tuple[str, ...]]] | None:
    if not config_dir.is_dir():
        print(f"not a directory: {config_dir}", file=sys.stderr)
        return None
    pack, unparsed = build_fact_pack(config_dir)
    if not pack.devices:
        _explain_empty(config_dir)
        return None
    return pack, unparsed


def _explain_empty(config_dir: Path) -> None:
    """Say that nothing was recognised, and say what was passed over.

    Not "no .cfg files in here". Discovery takes `.cfg`, `.conf`, `.txt`,
    extensionless files and anything not on its ignore list, and settles the
    ambiguous ones by reading them — so a message naming one extension turns away
    the person whose backups are `.conf`, whose files would have worked. The
    skips discovery thought worth mentioning follow the message, because "there
    was nothing there" and "there was something there and I would not open it"
    are different problems with different fixes.
    """
    print(f"nothing in {config_dir} reads like a device config", file=sys.stderr)
    found = discovery.discover(config_dir)
    for note in found.notes():
        print(f"  {note}", file=sys.stderr)
    if not found.notes() and found.skipped:
        passed = len(found.skipped)
        print(
            f"  {passed} path{'' if passed == 1 else 's'} passed over as "
            f"documents, data or binaries",
            file=sys.stderr,
        )


if __name__ == "__main__":
    raise SystemExit(main())
