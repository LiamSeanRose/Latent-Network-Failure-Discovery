"""Shared parsing machinery for IOS-style configuration dialects.

Arista EOS and Cisco IOS differ in the lines that matter here — `vrrp` versus
`standby`, CIDR versus netmask — but share their overall shape: top-level stanzas
with indented bodies. That shape lives here so a dialect module only has to
describe its differences.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

from cassandra.factpack.schema import (
    Device,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    InterfaceKind,
    TrackedObject,
    Vlan,
)

_KINDS: Final = (
    ("Vlan", InterfaceKind.SVI),
    ("Loopback", InterfaceKind.LOOPBACK),
    ("Management", InterfaceKind.MANAGEMENT),
    ("Port-Channel", InterfaceKind.LAG),
    ("Port-channel", InterfaceKind.LAG),
    ("Tunnel", InterfaceKind.TUNNEL),
    ("Ethernet", InterfaceKind.PHYSICAL),
    ("GigabitEthernet", InterfaceKind.PHYSICAL),
    ("TenGigabitEthernet", InterfaceKind.PHYSICAL),
    ("FastEthernet", InterfaceKind.PHYSICAL),
)


def interface_kind(name: str) -> InterfaceKind:
    for prefix, kind in _KINDS:
        if name.startswith(prefix):
            return kind
    return InterfaceKind.UNKNOWN


@dataclass(slots=True)
class Stanza:
    """A top-level config line plus the indented lines beneath it."""

    header: str
    body: list[str] = field(default_factory=list)


def stanzas(text: str) -> list[Stanza]:
    out: list[Stanza] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if raw[0].isspace():
            if out:
                out[-1].body.append(raw.strip())
            continue
        out.append(Stanza(header=raw.strip()))
    return out


def vlan_list(spec: str) -> tuple[int, ...]:
    """Expand `14,24,34` and `10-12` into explicit VLAN ids."""
    vlans: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit():
                vlans.extend(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            vlans.append(int(part))
    return tuple(vlans)


def netmask_to_prefix_length(netmask: str) -> int | None:
    """`255.255.255.0` -> 24. IOS writes masks; the schema stores prefixes."""
    try:
        octets = [int(part) for part in netmask.split(".")]
    except ValueError:
        return None
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        return None
    bits = "".join(f"{octet:08b}" for octet in octets)
    if "01" in bits:  # non-contiguous mask
        return None
    return bits.count("1")


def seconds_to_ms(value: str | None) -> int | None:
    return None if value is None else int(value) * 1000


@dataclass(slots=True)
class ParsedDevice:
    """One device's facts, plus what the parser could not account for."""

    device: Device
    fhrp: tuple[tuple[int, FhrpProtocol, FhrpMember, str, str | None], ...]
    tracked: tuple[TrackedObject, ...]
    timers: tuple[FhrpTimers, ...]
    unparsed_lines: tuple[str, ...]
    vlans: tuple[Vlan, ...] = ()


def declared_vlans_from(device: str, stanza: Stanza) -> list[Vlan]:
    """`vlan 10,20` plus an optional indented `name`, which only binds when the
    stanza declares exactly one id."""
    ids = vlan_list(stanza.header.split(None, 1)[1])
    name = next(
        (
            line.split(None, 1)[1]
            for line in stanza.body
            if line.startswith("name ") and len(line.split(None, 1)) == 2
        ),
        None,
    )
    return [
        Vlan(device=device, vlan_id=vid, name=name if len(ids) == 1 else None)
        for vid in ids
    ]


# Top-level configuration domains this tool does not model, by design. They carry
# no fact any tier reads, and listing them as "unparsed" buries the lines that
# genuinely indicate a missing fact under a wall of AAA and SNMP.
#
# Deliberately conservative: anything not listed here is still reported, because
# the cost of a surprising line going unnoticed is higher than the cost of one
# extra line of output.
OUT_OF_SCOPE: Final = re.compile(
    r"^(?:no )?("
    r"aaa|username|role|enable |privilege|tacacs|radius|"
    r"banner|alias|prompt|terminal|"
    r"boot |service |transceiver|hardware|agent |daemon|platform|"
    r"clock|ntp|dns |ip name-server|ip domain|ip host|"
    r"snmp-server|logging|event-handler|sflow|monitor |archive|"
    r"management|line (con|vty|aux)|"
    r"crypto|certificate|key |pki|ssl|"
    r"ip (prefix-list|access-list|community-list|as-path)|"
    r"mac access-list|route-map|class-map|policy-map|qos |errdisable|"
    r"lldp|cdp|spanning-tree|queue-monitor|load-interval|"
    r"end|exit"
    r")\b"
)


def is_out_of_scope(line: str) -> bool:
    """True for configuration this tool intentionally does not model."""
    return bool(OUT_OF_SCOPE.match(line.strip()))


def strip_banners(text: str) -> str:
    """Remove banner bodies before stanza parsing.

    Banner text sits at column zero and is arbitrary prose, so a stanza parser
    reads every line of it as a separate top-level command. On a real device
    config that is the single largest source of nonsense.
    """
    out: list[str] = []
    in_banner = False
    for line in text.splitlines():
        if not in_banner and line.strip().startswith("banner "):
            in_banner = True
            continue
        if in_banner:
            # EOS terminates with a lone EOF; IOS uses a delimiter character.
            if line.strip() in {"EOF", "!", ""} or line.strip().startswith("^"):
                in_banner = False
            continue
        out.append(line)
    return "\n".join(out)
