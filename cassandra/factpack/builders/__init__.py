"""Config text -> Fact Pack, dialect chosen automatically.

The user should not have to tell the tool what wrote their configs. Detection
tries the dialect whose markers appear, then falls back to whichever parser
accounts for more of the file — a parser that leaves half a config unexplained is
the wrong parser, and that is measurable rather than a guess.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Final

from cassandra.factpack.builders import eos, ios
from cassandra.factpack.builders.common import ParsedDevice
from cassandra.factpack.schema import (
    Device,
    FactPackMeta,
    FhrpGroup,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    StaticFactPack,
    TimerInventory,
    TrackedObject,
)

SCHEMA_VERSION: Final = 1
DIALECTS: Final[tuple[ModuleType, ...]] = (ios, eos)


def parse(text: str, *, device_id: str | None = None) -> ParsedDevice:
    """Parse with the best-fitting dialect."""
    if ios.looks_like_ios(text):
        return ios.parse_device(text, device_id=device_id)

    # No decisive marker: run both and keep whichever explains more of the file.
    candidates = [module.parse_device(text, device_id=device_id) for module in DIALECTS]
    return min(candidates, key=lambda parsed: len(parsed.unparsed_lines))


def build_fact_pack(
    config_dir: Path,
) -> tuple[StaticFactPack, dict[str, tuple[str, ...]]]:
    """Parse every `.cfg` in a directory into one Fact Pack.

    Returns the pack and, per device, the lines no parser accounted for.
    """
    devices: list[Device] = []
    groups: dict[tuple[FhrpProtocol, int], list[FhrpMember]] = {}
    virtuals: dict[tuple[FhrpProtocol, int], str | None] = {}
    fhrp_timers: list[FhrpTimers] = []
    unparsed: dict[str, tuple[str, ...]] = {}
    digest = hashlib.sha256()

    for path in sorted(config_dir.glob("*.cfg")):
        text = path.read_text()
        digest.update(text.encode())
        parsed = parse(text, device_id=path.stem)
        devices.append(parsed.device)
        fhrp_timers.extend(parsed.timers)
        unparsed[parsed.device.id] = parsed.unparsed_lines

        # Tracked objects are defined at top level; join them to the groups that
        # reference them, or a decrement has nothing to watch.
        targets = {tracked.id: tracked.target for tracked in parsed.tracked}
        for number, protocol, member, _interface, virtual in parsed.fhrp:
            groups.setdefault((protocol, number), []).append(
                FhrpMember(
                    device=member.device,
                    interface=member.interface,
                    priority=member.priority,
                    preempt=member.preempt,
                    tracked_objects=tuple(
                        TrackedObject(
                            id=obj.id,
                            device=obj.device,
                            kind=obj.kind,
                            target=targets.get(obj.id, ""),
                            decrement=obj.decrement,
                        )
                        for obj in member.tracked_objects
                    ),
                )
            )
            virtuals.setdefault((protocol, number), virtual)

    pack = StaticFactPack(
        meta=FactPackMeta(
            fact_pack_id=f"fp_{digest.hexdigest()[:12]}",
            schema_version=SCHEMA_VERSION,
            config_digest=digest.hexdigest(),
            source_snapshot=str(config_dir),
            generated_at=datetime.now(UTC),
            device_count=len(devices),
        ),
        devices=tuple(devices),
        fhrp_groups=tuple(
            FhrpGroup(
                id=f"{protocol.value}-{number}",
                protocol=protocol,
                group_number=number,
                members=tuple(members),
                virtual_ipv4=virtuals[(protocol, number)],
            )
            for (protocol, number), members in sorted(
                groups.items(), key=lambda item: (item[0][0].value, item[0][1])
            )
        ),
        timers=TimerInventory(fhrp=tuple(fhrp_timers)),
    )
    return pack, unparsed
