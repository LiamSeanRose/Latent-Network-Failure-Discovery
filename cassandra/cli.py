"""Command line entry point.

`facts` prints the fact pack the other four rest on; `check` runs the rules
against it; `report` writes the standalone HTML; `rules` prints the catalogue;
`serve` puts the same views behind a local port. README.md covers each.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Final

from cassandra import baseline, coverage, exchange
from cassandra.app import analyse, compare_with, serve
from cassandra.catalogue import catalogue, render_text
from cassandra.factpack import discovery
from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import (
    StaticFactPack,
    TimerInventory,
    TimerScope,
    TimerSource,
)
from cassandra.facts import rules
from cassandra.findings import Finding, Severity, locate
from cassandra.report import as_json, render
from cassandra.report_html import write as write_html
from cassandra.timing import sequences, timer_rules

# What `check` can print, in the order --help offers them. `text` is for a
# person; the other three are for something downstream, and which one is right
# depends on what is already reading it rather than on which is best.
FORMATS: Final[tuple[str, ...]] = ("text", "json", "sarif", "junit")


def _scope(scope: TimerScope) -> str:
    """`device:interface instance` — as much of a scope as the record carries."""
    where = scope.device
    if scope.interface:
        where += f":{scope.interface}"
    if scope.neighbor:
        where += f" neighbor {scope.neighbor}"
    if scope.instance:
        where += f" [{scope.instance}]"
    return where


def _values(**named: object) -> str:
    """`name=value` for each value the record actually states.

    Absent is written by leaving the name out rather than by printing `None`. A
    timer this tool did not read and a timer the config does not set look
    identical in a dump that prints both, and the difference is the whole
    subject of the coverage report.
    """
    return "  ".join(
        f"{name.replace('_', '-')}={value}"
        for name, value in named.items()
        if value is not None and value is not False
    )


def _timer_lines(timers: TimerInventory) -> list[str]:
    """Every timer family the inventory holds, one section each.

    Written as a loop over the families rather than one block per family so that
    a family added to the schema and filled by a builder cannot be silently
    missing here — which is what the FHRP-only version of this function was, for
    long enough that a reader could conclude the pack held no BGP or spanning
    tree timing when it held both.
    """
    families: tuple[tuple[str, tuple[object, ...], Callable[[object], str]], ...] = (
        (
            "fhrp timers",
            timers.fhrp,
            lambda t: _values(
                hello=_ms_or_none(t.hello_interval_ms),
                hold=_ms_or_none(t.hold_time_ms),
                preempt_delay=_ms_or_none(t.preempt_delay_ms),
                preempt_delay_reload=_ms_or_none(t.preempt_delay_reload_ms),
            ),
        ),
        (
            "igp hello timers",
            timers.igp_hello,
            lambda t: _values(
                protocol=t.protocol.value,
                hello=_ms_or_none(t.hello_interval_ms),
                dead=_ms_or_none(t.dead_interval_ms),
                area=t.ospf_area,
            ),
        ),
        (
            "bfd timers",
            timers.bfd,
            lambda t: _values(
                tx=_ms_or_none(t.desired_min_tx_ms),
                rx=_ms_or_none(t.required_min_rx_ms),
                multiplier=t.detect_multiplier,
                echo=t.echo_enabled,
                echo_rx=_ms_or_none(t.echo_rx_interval_ms),
            ),
        ),
        (
            "bgp timers",
            timers.bgp,
            lambda t: _values(
                keepalive=_ms_or_none(t.keepalive_ms),
                hold=_ms_or_none(t.hold_time_ms),
                min_hold=_ms_or_none(t.min_hold_time_ms),
                restart_time=_s_or_none(t.graceful_restart_time_s),
                stalepath_time=_s_or_none(t.stalepath_time_s),
            ),
        ),
        (
            "stp timers",
            timers.stp,
            lambda t: _values(
                mode=t.mode.value,
                vlans=",".join(str(v) for v in t.vlans) or None,
                hello=_ms_or_none(t.hello_time_ms),
                forward_delay=_ms_or_none(t.forward_delay_ms),
                max_age=_ms_or_none(t.max_age_ms),
            ),
        ),
        (
            "spf throttle",
            timers.spf_throttle,
            lambda t: _values(
                initial=_ms_or_none(t.initial_delay_ms),
                minimum=_ms_or_none(t.min_hold_ms),
                maximum=_ms_or_none(t.max_wait_ms),
            ),
        ),
        (
            "carrier delay",
            timers.carrier_delay,
            lambda t: _values(
                up=_ms_or_none(t.up_ms),
                down=_ms_or_none(t.down_ms),
            ),
        ),
        (
            "dampening",
            timers.dampening,
            lambda t: _values(
                half_life=_s_or_none(t.half_life_s),
                reuse=t.reuse_threshold,
                suppress=t.suppress_threshold,
                max_suppress=_s_or_none(t.max_suppress_s),
            ),
        ),
    )
    lines: list[str] = []
    for heading, records, values_of in families:
        if not records:
            continue
        # A record that states none of the values this prints is a record the
        # parser made because something named the scope, and printing it as a
        # scope with a source and nothing between them says only that the
        # parser ran.
        said = [(record, values_of(record)) for record in records]
        said = [(record, stated) for record, stated in said if stated]
        if not said:
            continue
        lines.append(heading)
        lines += [
            f"  {_scope(record.scope)}  {stated}  source={record.scope.source.value}"
            for record, stated in said
        ]
        lines.append("")
    return lines or ["no timers in these configs"]


def _ms_or_none(value: int | None) -> str | None:
    return None if value is None else f"{value}ms"


def _s_or_none(value: int | None) -> str | None:
    return None if value is None else f"{value}s"


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
            # Whether the flag was written down or inherited from the
            # protocol's own default. A yes that nobody typed and a yes
            # somebody chose are the same yes to a rule and two different
            # sentences to a reader, which is why the pack carries both.
            preempt = "yes" if member.preempt else "no"
            if member.preempt_source is not TimerSource.CONFIGURED:
                preempt += f"({member.preempt_source.value})"
            lines.append(
                f"  {member.device}:{member.interface}  priority={member.priority}"
                f"  preempt={preempt}"
                + (f"  tracks={tracked}" if tracked else "  tracks=none")
            )
    lines.append("")

    if pack.vlans:
        lines.append("vlans")
        for vlan in pack.vlans:
            named = f"  {vlan.name}" if vlan.name else ""
            instance = (
                f"  stp-instance={vlan.stp_instance}"
                if vlan.stp_instance is not None
                else ""
            )
            lines.append(f"  {vlan.device}  vlan {vlan.vlan_id}{named}{instance}")
        lines.append("")

    for process in pack.bgp:
        router_id = f"  router-id={process.router_id}" if process.router_id else ""
        lines.append(f"bgp {process.device}  as={process.local_as}{router_id}")
        for neighbor in process.neighbors:
            bits = [f"  {neighbor.address}"]
            if neighbor.remote_as:
                bits.append(f"remote-as={neighbor.remote_as}")
            if neighbor.update_source:
                bits.append(f"update-source={neighbor.update_source}")
            if neighbor.bfd:
                bits.append("bfd")
            if neighbor.multihop:
                bits.append("multihop")
            lines.append("  ".join(bits))
    if pack.bgp:
        lines.append("")

    if pack.l3_adjacencies:
        lines.append("l3 adjacencies")
        for adjacency in pack.l3_adjacencies:
            members = ", ".join(
                f"{member.device}:{member.interface}" for member in adjacency.members
            )
            lines.append(f"  {adjacency.prefix}  {members}")
        lines.append("")

    lines.extend(_timer_lines(pack.timers))

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
        help="emit findings as JSON for a pipeline instead of text; "
        "the same as --format json",
    )
    check.add_argument(
        "--format",
        choices=tuple(FORMATS),
        dest="output_format",
        metavar="|".join(FORMATS),
        help=(
            "the shape of the output. `json` is this tool's own; `sarif` and "
            "`junit` are formats a CI system already reads — SARIF turns "
            "findings into annotations on the configuration lines responsible, "
            "and JUnit turns the rule set into a test report where an inert "
            "check is a skip rather than a pass. All go to stdout"
        ),
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
            _report_coverage(pack, args.coverage, assessed=None, quiet=False)
            # Only NEW findings fail a regression check. The pre-existing ones
            # were known and accepted when the baseline was taken, and failing on
            # them would make every run red until the backlog is cleared, which
            # is how a check gets switched off.
            return 1 if diff.new else 0

        # `--json` predates `--format` and still means what it always meant.
        # An explicit `--format` wins over it, because the one the user typed
        # last is the one they meant, and the alias is the older habit.
        chosen = args.output_format or ("json" if args.as_json else "text")
        # Assessed once. JUnit needs the verdict to tell a check that passed
        # from one that never ran, and `--coverage` prints the same thing; two
        # traced runs of the whole rule set to say it twice is pure waste.
        assessed = (
            coverage.assess_all(pack)
            if chosen == "junit" or args.coverage is not None
            else None
        )
        print(_emit(findings, pack, chosen, args, assessed))
        # Alongside a machine format rather than inside it: a parser handed the
        # findings should not have to skip a paragraph of prose to reach them.
        _report_coverage(pack, args.coverage, assessed=assessed, quiet=chosen != "text")
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


def _emit(
    findings: list[Finding],
    pack: StaticFactPack,
    chosen: str,
    args: argparse.Namespace,
    assessed: coverage.Assessment | None,
) -> str:
    """The findings in the shape that was asked for.

    The verdict does not move with the shape: every format exits the same way,
    because a pipeline reading SARIF still wants a build that fails, and one
    that had to parse the output to learn that would be reading the exit status
    for nothing.
    """
    if chosen == "json":
        return as_json(
            findings,
            pack_id=pack.meta.fact_pack_id,
            digest=pack.meta.config_digest,
        )
    if chosen == "sarif":
        # The directory as it was typed, because that is what makes a result URI
        # resolve from where the command was run — see `exchange.sarif`.
        return exchange.sarif(
            findings,
            base=str(args.config_dir),
            pack_id=pack.meta.fact_pack_id,
            digest=pack.meta.config_digest,
        )
    if chosen == "junit":
        return exchange.junit(findings, assessed.rules if assessed else ())
    return render(findings, explain=args.explain)


def _report_coverage(
    pack: StaticFactPack,
    wanted: str | None,
    *,
    assessed: coverage.Assessment | None,
    quiet: bool,
) -> None:
    """Say which checks had something to look at, after saying what they found.

    After, because the findings are what the user came for. The coverage line is
    the caveat on them — thirty of forty-five checks inert is a different result
    from a clean run, and it is not visible in a report that says nothing.

    Goes to stderr alongside the JSON, so a pipeline parsing the findings is not
    handed a paragraph of prose in the middle of them.
    """
    if wanted is None:
        return
    measured = coverage.assess_all(pack) if assessed is None else assessed
    text = (
        coverage.render_text(measured.rules, measured.unread)
        if wanted == "full"
        else coverage.summary(measured.rules)
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
