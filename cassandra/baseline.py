"""Did this run break something the last run did not?

`check` answers "is this broken?". A tool pointed at the same network week after
week needs the other question — what is different since last time — and that is a
diff between two runs. A diff needs an answer to "is this the same finding as
that one?", which is the whole design problem here.

Identity
--------

A finding is identified by its rule, its device, and the network objects it
names — never by the sentences it names them in.

* Rule id and device are stable by construction: a rule keeps its id across
  rewordings, and the device is a fact rather than a phrasing.
* Rule and device alone are too coarse. Two BFD sessions on one device produce
  two `bfd-no-clients` findings, and fixing one of them has to read as fixed.
* The rendered text is too fine. Rewording a title, or a timer moving from 150ms
  to 100ms while the defect stands, is not a regression; reporting it as one
  (fixed here, new there) teaches the user to ignore the output.

So identity keeps the *references* a finding makes and discards the prose around
them: interface references (`agg-a:Ethernet1`), bare interface names, IPv4
addresses and prefixes, numbered objects (`VRRP 14`, `VLAN 99`) and quoted object
ids (`'track1'`). Measured quantities, counts and explanation are dropped,
because those are exactly what moves when nothing has changed.

References are read from `title`, `detail` and `trigger`. `evidence` is consulted
only when those name nothing: evidence answers "how do I know", and a rule may
legitimately cite a variable set there — `svi-vlan-not-trunked` lists every trunk
on the device — so letting it into identity would make an unrelated new trunk
read as a regression. `remedy` is never read; it is advice, it is the field most
likely to be reworded, and it names nothing the other fields do not.

Severity and tier are not part of identity. A rule that changes its mind about
how bad something is, or which engine established it, has not found a different
thing, and a HIGH becoming a MED should not read as one problem fixed and another
introduced.

Identity is a heuristic and it degrades in both directions: too coarse and two
findings share one, too fine and one finding becomes two. Comparison is therefore
by *count* per identity rather than by presence — two findings sharing an
identity stay two findings, and fixing one of them shows up as exactly one fixed.

The config digest
-----------------

A changed `config_digest` is information, not an error. The user edited their
configs; that is why they are running this at all, and refusing to compare would
make the feature useless on its only intended workflow. It is reported instead.
An *unchanged* digest is worth saying out loud too: the configs are identical, so
anything in the diff came from the checks changing, not from the network.

What is worth refusing is a baseline taken from a *different network*, where
every finding is new and every finding is fixed and none of it means anything.
The digest cannot detect that — any edit changes it — so the network is
identified by its device set instead. Nothing in common (with devices on both
sides) raises `BaselineMismatch`; a partial overlap compares and names the
devices that came and went.

Exit status
-----------

A pre-commit or CI user needs the status to mean "you made this worse", not "this
network has findings" — a backlog that fails every build gets the check disabled
on day one. `Diff.regressed` is that signal, and it is true only when something
is new.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from cassandra.factpack.schema import StaticFactPack
from cassandra.findings import Finding, Severity, Tier, rank

FORMAT: Final = "cassandra-baseline"
VERSION: Final = 1

# Beside the configs it describes, not in the configs directory: a baseline is
# about a network but it is not part of one.
DEFAULT_PATH: Final = Path(".cassandra/baseline.json")

type Identity = tuple[str, str, tuple[str, ...]]


class BaselineError(Exception):
    """A baseline that cannot be used, with a message meant for the user.

    Every raise site states the path and what to do about it, because a missing
    or hand-edited baseline is an ordinary thing to hit and a traceback is not an
    answer to it.
    """


class BaselineMismatch(BaselineError):
    """The baseline describes a different network from the one being checked."""


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

# Longest first: `ethernet` must win over `eth` at the same position.
_INTERFACE_FAMILIES: Final = (
    "tengigabitethernet",
    "gigabitethernet",
    "twentyfivegige",
    "bundle-ether",
    "port-channel",
    "hundredgige",
    "portchannel",
    "management",
    "fortygige",
    "ethernet",
    "loopback",
    "tunnel",
    "serial",
    "vlan",
    "mgmt",
    "eth",
    "po",
    "lo",
    "ae",
)

_REFERENCES: Final = (
    # `device:interface`, the form every rule writes its evidence in.
    re.compile(r"(?<![\w.:-])[A-Za-z][\w.-]*:[A-Za-z][\w./-]*"),
    # An IPv4 address or prefix.
    re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b"),
    # A bare interface name, for the rules that name one in the title.
    re.compile(r"(?<![\w-])(?:" + "|".join(_INTERFACE_FAMILIES) + r")\d[\w./-]*", re.I),
)

# A number is only an identifier when something says what it numbers. Bare
# integers are counts and measurements ("changes master 5 times", "priority
# 110") and must not reach the identity.
_NUMBERED: Final = re.compile(
    r"\b(?:vrrp|hsrp|glbp|vlans?|groups?|tracks?|area|level|instance|process)\s+"
    r"(\d+(?:\s*(?:,|and|&|/)\s*\d+)*)",
    re.I,
)
_QUOTED: Final = re.compile(r"'([\w.\-/]{1,64})'")
_INTEGER: Final = re.compile(r"\d+")
_TRAILING: Final = ".,;:/-"


def references(text: str) -> set[str]:
    """Every network object `text` names, normalised and stripped of prose."""
    found = {
        match.group(0).casefold().rstrip(_TRAILING)
        for pattern in _REFERENCES
        for match in pattern.finditer(text)
    }
    found |= {
        f"#{number}"
        for match in _NUMBERED.finditer(text)
        for number in _INTEGER.findall(match.group(1))
    }
    found |= {match.group(1).casefold() for match in _QUOTED.finditer(text)}
    return {ref for ref in found if ref}


def identity(finding: Finding) -> Identity:
    """What makes this finding the same finding in a later run.

    See the module docstring for why it is these fields and not the text.
    """
    described = "\n".join(
        part for part in (finding.title, finding.detail, finding.trigger) if part
    )
    refs = references(described)
    if not refs:
        refs = references("\n".join(finding.evidence))
    return (finding.rule, finding.device, tuple(sorted(refs)))


# --------------------------------------------------------------------------
# Snapshots
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class Snapshot:
    """One run's findings, with enough of the fact pack to know what they describe.

    A baseline is a snapshot that was saved; the run being checked is a snapshot
    that was not. Comparing them is symmetric, so they are the same type.
    """

    digest: str
    devices: tuple[str, ...]
    taken_at: datetime
    source: str
    findings: list[Finding]


def snapshot(findings: list[Finding], pack: StaticFactPack) -> Snapshot:
    return Snapshot(
        digest=pack.meta.config_digest,
        devices=tuple(sorted(device.id for device in pack.devices)),
        taken_at=pack.meta.generated_at,
        source=pack.meta.source_snapshot,
        findings=rank(findings),
    )


def _finding_to_json(finding: Finding) -> dict[str, Any]:
    return {
        "rule": finding.rule,
        "tier": finding.tier.value,
        "severity": finding.severity.value,
        "device": finding.device,
        "title": finding.title,
        "detail": finding.detail,
        "evidence": list(finding.evidence),
        "trigger": finding.trigger,
        "remedy": finding.remedy,
    }


def save(findings: list[Finding], pack: StaticFactPack, path: Path) -> None:
    """Write the baseline `path` that a later run compares itself against.

    Findings are stored whole rather than as identities: a diff has to *print*
    what was fixed, and the only copy of a fixed finding is the one in here.
    """
    taken = snapshot(findings, pack)
    document = {
        "format": FORMAT,
        "version": VERSION,
        "config_digest": taken.digest,
        "devices": list(taken.devices),
        "taken_at": taken.taken_at.isoformat(),
        "source": taken.source,
        "findings": [_finding_to_json(finding) for finding in taken.findings],
    }
    text = json.dumps(document, indent=2, sort_keys=False) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Written beside the target and moved into place: a baseline half-written
        # by an interrupted run is a corrupt baseline the next run has to explain.
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            handle.write(text)
            temporary = Path(handle.name)
        os.replace(temporary, path)
    except OSError as error:
        raise BaselineError(f"cannot write baseline {path}: {error.strerror}") from None


def _string(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise BaselineError(f"{path} is corrupt: {key!r} is missing or not text")
    return value


def _finding_from_json(raw: object, path: Path) -> Finding:
    if not isinstance(raw, dict):
        raise BaselineError(f"{path} is corrupt: a finding is not an object")
    evidence = raw.get("evidence", [])
    if not isinstance(evidence, list) or any(
        not isinstance(item, str) for item in evidence
    ):
        raise BaselineError(f"{path} is corrupt: 'evidence' is not a list of text")
    for key in ("trigger", "remedy"):
        if raw.get(key) is not None and not isinstance(raw.get(key), str):
            raise BaselineError(f"{path} is corrupt: {key!r} is not text")
    try:
        severity = Severity(_string(raw, "severity", path))
        tier = Tier(_string(raw, "tier", path))
    except ValueError as error:
        raise BaselineError(f"{path} is corrupt: {error}") from None
    return Finding(
        rule=_string(raw, "rule", path),
        tier=tier,
        severity=severity,
        device=_string(raw, "device", path),
        title=_string(raw, "title", path),
        detail=_string(raw, "detail", path),
        evidence=tuple(evidence),
        trigger=raw.get("trigger"),
        remedy=raw.get("remedy"),
    )


def load(path: Path) -> Snapshot:
    """Read a baseline, or raise `BaselineError` saying why it could not be read."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise BaselineError(
            f"no baseline at {path} — record one from a run you trust first"
        ) from None
    except OSError as error:
        raise BaselineError(f"cannot read baseline {path}: {error.strerror}") from None

    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise BaselineError(f"{path} is not readable JSON: {error}") from None
    if not isinstance(raw, dict) or raw.get("format") != FORMAT:
        raise BaselineError(f"{path} is not a {FORMAT} file")

    version = raw.get("version")
    if not isinstance(version, int):
        raise BaselineError(f"{path} is corrupt: 'version' is missing or not a number")
    if version > VERSION:
        raise BaselineError(
            f"{path} was written by a newer version (format {version}, "
            f"this reads {VERSION}) — record a fresh baseline"
        )

    devices = raw.get("devices", [])
    findings = raw.get("findings")
    if not isinstance(devices, list) or any(
        not isinstance(item, str) for item in devices
    ):
        raise BaselineError(f"{path} is corrupt: 'devices' is not a list of names")
    if not isinstance(findings, list):
        raise BaselineError(f"{path} is corrupt: 'findings' is missing or not a list")
    try:
        taken_at = datetime.fromisoformat(_string(raw, "taken_at", path))
    except ValueError:
        raise BaselineError(
            f"{path} is corrupt: 'taken_at' is not a timestamp"
        ) from None

    return Snapshot(
        digest=_string(raw, "config_digest", path),
        devices=tuple(devices),
        taken_at=taken_at,
        source=raw.get("source", "") if isinstance(raw.get("source"), str) else "",
        findings=[_finding_from_json(item, path) for item in findings],
    )


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class Diff:
    """What changed between a baseline and the run being checked.

    `new` and `unchanged` carry the current findings — current phrasing and
    current severity are the truth. `fixed` carries the baseline's copies,
    because that is the only copy left of a finding that no longer occurs.
    """

    new: list[Finding]
    fixed: list[Finding]
    unchanged: list[Finding]
    baseline_digest: str
    current_digest: str
    baseline_taken_at: datetime
    devices_added: tuple[str, ...] = ()
    devices_removed: tuple[str, ...] = ()

    @property
    def regressed(self) -> bool:
        """True when this run found something the baseline did not."""
        return bool(self.new)

    @property
    def configs_changed(self) -> bool:
        return self.baseline_digest != self.current_digest


def _by_identity(findings: list[Finding]) -> dict[Identity, list[Finding]]:
    grouped: dict[Identity, list[Finding]] = defaultdict(list)
    for finding in rank(findings):
        grouped[identity(finding)].append(finding)
    return grouped


def compare(baseline: Snapshot, current: Snapshot) -> Diff:
    """Diff two snapshots, newest-first in every list.

    Raises `BaselineMismatch` when the two describe networks with no device in
    common — that comparison has an answer for every finding and a meaning for
    none of them.
    """
    before_devices, now_devices = set(baseline.devices), set(current.devices)
    if before_devices and now_devices and not before_devices & now_devices:
        raise BaselineMismatch(
            "baseline is from a different network: it covers "
            f"{', '.join(sorted(before_devices))} and this run covers "
            f"{', '.join(sorted(now_devices))}, with no device in common"
        )

    before = _by_identity(baseline.findings)
    now = _by_identity(current.findings)

    new: list[Finding] = []
    fixed: list[Finding] = []
    unchanged: list[Finding] = []
    for key, findings in now.items():
        carried = min(len(before.get(key, ())), len(findings))
        unchanged.extend(findings[:carried])
        new.extend(findings[carried:])
    for key, findings in before.items():
        carried = min(len(now.get(key, ())), len(findings))
        fixed.extend(findings[carried:])

    return Diff(
        new=rank(new),
        fixed=rank(fixed),
        unchanged=rank(unchanged),
        baseline_digest=baseline.digest,
        current_digest=current.digest,
        baseline_taken_at=baseline.taken_at,
        devices_added=tuple(sorted(now_devices - before_devices)),
        devices_removed=tuple(sorted(before_devices - now_devices)),
    )


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

# Mirrors report.render's shape deliberately: a diff should read like a check.
_LABEL: Final = {
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
    Severity.INFO: "INFO",
}


def _lines_for(finding: Finding, *, explain: bool) -> list[str]:
    lines = [
        f"{_LABEL[finding.severity]}  {finding.device}  {finding.title}",
        f"        {finding.detail}",
    ]
    if finding.trigger:
        lines.append(f"        trigger: {finding.trigger}")
    if explain:
        # Same shape as `report._lines_for`. A diff and a check that describe the
        # same finding differently is a difference someone will read as meaning
        # something.
        if finding.source:
            lines.append(f"        source: {finding.source}")
        lines.extend(f"        evidence: {item}" for item in finding.evidence)
        if finding.remedy:
            lines.append(f"        fix: {finding.remedy}")
        for change in finding.change:
            lines.append(f"          {change}")
        lines.append(f"        rule: {finding.rule} ({finding.tier.value})")
    lines.append("")
    return lines


def render_diff(diff: Diff, *, explain: bool = False) -> str:
    """Text for a person, leading with what is new — that is the question asked."""
    lines: list[str] = []
    if diff.new:
        lines.append(f"{len(diff.new)} new since baseline")
        lines.append("")
        for finding in diff.new:
            lines.extend(_lines_for(finding, explain=explain))
    else:
        lines.append("no new findings since baseline")
        lines.append("")

    if diff.fixed:
        lines.append(f"{len(diff.fixed)} fixed since baseline")
        lines.append("")
        for finding in diff.fixed:
            lines.extend(_lines_for(finding, explain=explain))

    if diff.unchanged:
        lines.append(f"{len(diff.unchanged)} unchanged")
        lines.append("")
        if explain:
            for finding in diff.unchanged:
                lines.extend(_lines_for(finding, explain=explain))

    lines.append(
        f"baseline taken {diff.baseline_taken_at.astimezone(UTC):%Y-%m-%d %H:%M}Z"
    )
    if diff.configs_changed:
        lines.append(
            f"configs changed since baseline "
            f"({diff.baseline_digest[:12]} -> {diff.current_digest[:12]})"
        )
    else:
        # Worth saying: with identical configs, a difference above came from the
        # checks changing rather than from the network.
        lines.append("configs unchanged since baseline — any difference above is a")
        lines.append("change in the checks, not in the network")
    if diff.devices_added:
        lines.append("devices added: " + ", ".join(diff.devices_added))
    if diff.devices_removed:
        lines.append("devices removed: " + ", ".join(diff.devices_removed))
    if not explain:
        lines.append("run with --explain for evidence, fixes and rule ids")
    return "\n".join(lines)
