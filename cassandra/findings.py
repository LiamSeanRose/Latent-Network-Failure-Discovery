"""What the tool emits.

One type for every tier, because a user does not care which engine found a problem
— they care what it is, how bad it is, and how it was established. `tier` and
`evidence` carry the latter so a finding can be argued with rather than trusted.

`source` carries the other half of acting on one: the file, and where the rule
narrowed that far the line, that has to change. `locate` fills it in from the
fact pack after the rules have run, so a rule states what is wrong and the fact
pack says where it is written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final

from cassandra.factpack.schema import StaticFactPack


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Tier(StrEnum):
    FACTS = "facts"
    TIMING = "timing"


_ORDER: Final = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.INFO: 3,
}


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    rule: str
    tier: Tier
    severity: Severity
    device: str
    title: str
    detail: str
    evidence: tuple[str, ...] = ()
    trigger: str | None = None
    remedy: str | None = None
    source: SourceRef | None = None

    @property
    def sort_key(self) -> tuple[int, str, str]:
        return (_ORDER[self.severity], self.device, self.rule)


def rank(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.sort_key)


# --------------------------------------------------------------------------
# Where a finding came from
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceRef:
    """The configuration a finding is about, as a place a reader can open.

    `file` is relative to the directory that was checked, so the citation still
    means something in a report read on another machine. `line` is absent when
    the rule could not narrow past the device — an invented line number sends a
    reader to configuration that has nothing to do with the finding, which costs
    more than no line at all.
    """

    file: str
    line: int | None = None

    def __str__(self) -> str:
        return self.file if self.line is None else f"{self.file}:{self.line}"


# A group is named by its protocol and number — `VRRP 14`, `hsrp 20`. The
# protocol word is required: a bare number in a finding is a count or a priority
# far more often than it is a group.
_GROUP_NAMED: Final = re.compile(r"\b(vrrp|hsrp|glbp)\s+(\d+)", re.I)
_VLAN_NAMED: Final = re.compile(r"\bvlan\s+(\d+)", re.I)


def _interface_named(text: str, name: str) -> bool:
    """Does `text` name this interface, rather than one whose name starts the same?

    A colon may precede it, because `device:interface` is the form every rule
    writes its evidence in; a word character, a dot, a slash or a dash may not,
    or `Ethernet1` would match inside `Ethernet1/1`.
    """
    return bool(re.search(rf"(?<![\w./-]){re.escape(name)}(?![\w./-])", text))


@dataclass(frozen=True, slots=True, kw_only=True)
class _DeviceSource:
    """Every place in one device's config that a finding could be pointed at.

    A line is `None` where the same name maps to more than one of them — two
    members of one group on one device, a VLAN declared twice. Ambiguity here is
    resolved by declining to cite, never by picking the first.
    """

    file: str
    interfaces: dict[str, int | None]
    groups: dict[tuple[str, int], int | None]
    vlans: dict[int, int | None]


def _sources(pack: StaticFactPack) -> dict[str, _DeviceSource]:
    interfaces: dict[str, dict[str, list[int | None]]] = {}
    groups: dict[str, dict[tuple[str, int], list[int | None]]] = {}
    vlans: dict[str, dict[int, list[int | None]]] = {}

    for device in pack.devices:
        for interface in device.interfaces:
            interfaces.setdefault(device.id, {}).setdefault(interface.name, []).append(
                interface.config_line
            )
    for group in pack.fhrp_groups:
        key = (group.protocol.value, group.group_number)
        for member in group.members:
            groups.setdefault(member.device, {}).setdefault(key, []).append(
                member.config_line
            )
    for vlan in pack.vlans:
        vlans.setdefault(vlan.device, {}).setdefault(vlan.vlan_id, []).append(
            vlan.config_line
        )

    return {
        device.id: _DeviceSource(
            file=device.config_path or "",
            interfaces=_unambiguous(interfaces.get(device.id, {})),
            groups=_unambiguous(groups.get(device.id, {})),
            vlans=_unambiguous(vlans.get(device.id, {})),
        )
        for device in pack.devices
        if device.config_path
    }


def _unambiguous[K](found: dict[K, list[int | None]]) -> dict[K, int | None]:
    return {
        key: lines[0] if len(set(lines)) == 1 else None for key, lines in found.items()
    }


def _line_in(text: str, source: _DeviceSource) -> tuple[int | None, bool]:
    """The line `text` points at, and whether it named anything on this device.

    Most specific first: a group is configured inside an interface, so naming
    both means the group's line, which is the narrower of the two.
    """
    named_groups = {
        (match.group(1).lower(), int(match.group(2)))
        for match in _GROUP_NAMED.finditer(text)
    }
    named_vlans = {int(match.group(1)) for match in _VLAN_NAMED.finditer(text)}
    candidates = (
        [source.groups[key] for key in named_groups if key in source.groups],
        [
            line
            for name, line in source.interfaces.items()
            if _interface_named(text, name)
        ],
        [source.vlans[vlan] for vlan in named_vlans if vlan in source.vlans],
    )
    named = any(candidates)
    for group in candidates:
        lines = {line for line in group if line is not None}
        if len(lines) == 1:
            return lines.pop(), named
    return None, named


def locate(findings: list[Finding], pack: StaticFactPack) -> list[Finding]:
    """Attach the configuration each finding is about (PROJECT.md §5.4).

    Rules state what they found in prose and name the objects they found it on;
    nothing in a `Finding` says which stanza it came from. So the objects are
    read back out of the text and looked up in the fact pack, which is the same
    move `baseline.identity` makes for the same reason, and it is read from the
    same fields in the same order: `title` and `detail` say what the finding is
    about, and `evidence` is consulted only when those name nothing, because a
    rule may cite a whole list there.

    `trigger` is deliberately not read. It names the event that exposes the
    defect — an interface being flapped — which is not the configuration
    responsible for it.

    A finding whose device the fact pack cannot place is returned untouched.
    """
    sources = _sources(pack)
    located: list[Finding] = []
    for finding in findings:
        source = sources.get(finding.device)
        if source is None:
            located.append(finding)
            continue
        described = "\n".join(part for part in (finding.title, finding.detail) if part)
        line, named = _line_in(described, source)
        if line is None and not named:
            line, _ = _line_in("\n".join(finding.evidence), source)
        located.append(replace(finding, source=SourceRef(file=source.file, line=line)))
    return located
