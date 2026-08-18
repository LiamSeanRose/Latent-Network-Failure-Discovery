"""Command line entry point.

Phase 1 provides `facts` only. `check` and `analyze` arrive with the FACTS and
TIMING tiers (PROJECT.md §4.2).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cassandra.app import serve
from cassandra.factpack.builders import build_fact_pack
from cassandra.factpack.schema import StaticFactPack
from cassandra.facts import rules
from cassandra.report import render
from cassandra.timing import sequences


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
        lines.append(
            f"fhrp {group.protocol.value} group={group.group_number} "
            f"virtual={group.virtual_ipv4}"
        )
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
    facts.add_argument("config_dir", type=Path)

    check = sub.add_parser("check", help="report latent failure modes in configs")
    check.add_argument("config_dir", type=Path)
    check.add_argument(
        "--explain",
        action="store_true",
        help="show evidence, suggested fixes and rule ids",
    )

    app = sub.add_parser("serve", help="open the local web view")
    app.add_argument("--port", type=int, default=8765)
    app.add_argument("--host", default="127.0.0.1")

    args = parser.parse_args(argv)
    if args.command == "facts":
        loaded = _load(args.config_dir)
        if loaded is None:
            return 2
        pack, unparsed = loaded
        print(render_facts(pack, unparsed))
        return 0

    if args.command == "check":
        loaded = _load(args.config_dir)
        if loaded is None:
            return 2
        pack, _ = loaded
        findings = rules.evaluate(pack) + sequences.analyse(pack)
        print(render(findings, explain=args.explain))
        # Exit status is the verdict: non-zero when something needs attention, so
        # this is usable in a pre-commit hook or CI without parsing the output.
        return 1 if findings else 0

    if args.command == "serve":
        serve(host=args.host, port=args.port)
        return 0

    return 2


def _load(config_dir: Path) -> tuple[StaticFactPack, dict[str, tuple[str, ...]]] | None:
    if not config_dir.is_dir():
        print(f"not a directory: {config_dir}", file=sys.stderr)
        return None
    pack, unparsed = build_fact_pack(config_dir)
    if not pack.devices:
        print(f"no .cfg files in {config_dir}", file=sys.stderr)
        return None
    return pack, unparsed


if __name__ == "__main__":
    raise SystemExit(main())
