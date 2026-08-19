"""Shared parsing machinery for IOS-style configuration dialects.

Arista EOS and Cisco IOS differ in the lines that matter here — `vrrp` versus
`standby`, CIDR versus netmask — but share their overall shape: top-level stanzas
with indented bodies. That shape lives here so a dialect module only has to
describe its differences.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from cassandra.factpack.schema import (
    BgpNeighbor,
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
    """A top-level config line plus the indented lines beneath it.

    `line` and `body_lines` number the header and each body line from one, so a
    fact can carry the place it was configured. They count lines of the file the
    operator has open, which is why `strip_banners` blanks a banner out rather
    than deleting it.
    """

    header: str
    body: list[str] = field(default_factory=list)
    line: int = 0
    body_lines: list[int] = field(default_factory=list)


def stanzas(text: str) -> list[Stanza]:
    out: list[Stanza] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        if raw[0].isspace():
            if out:
                out[-1].body.append(raw.strip())
                out[-1].body_lines.append(number)
            continue
        out.append(Stanza(header=raw.strip(), line=number))
    return out


# 802.1Q: 1 to 4094. Zero is the priority-tag id and 4095 is reserved, so
# neither can be a VLAN a port belongs to, and nothing exists above 4094.
MIN_VLAN_ID: Final = 1
MAX_VLAN_ID: Final = 4094


def vlan_list(spec: str) -> tuple[int, ...]:
    """Expand `14,24,34` and `10-12` into explicit VLAN ids.

    Returns only the ids it could read. Anything it could not is reported by
    `unreadable_vlans` so the caller can list it as unparsed rather than let it
    vanish — a dropped VLAN spec makes the next rule blame the operator for a
    port in a VLAN "that is not declared", when the declaration was there and
    this function could not read it.
    """
    vlans, _ = _read_vlans(spec)
    return vlans


def unreadable_vlans(spec: str) -> tuple[str, ...]:
    """The parts of a VLAN spec that named no usable id."""
    _, rejected = _read_vlans(spec)
    return rejected


def _read_vlans(spec: str) -> tuple[tuple[int, ...], tuple[str, ...]]:
    vlans: list[int] = []
    rejected: list[str] = []
    for raw in spec.split(","):
        part = raw.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if not (lo.isdigit() and hi.isdigit()):
                rejected.append(part)
                continue
            first, last = int(lo), int(hi)
            # Clamped, not expanded. `1-99999999` is a typo, and expanding it
            # allocates until the process is killed; there are only 4094 ids it
            # could have meant.
            low = max(first, MIN_VLAN_ID)
            high = min(last, MAX_VLAN_ID)
            if first > last or high < low:
                rejected.append(part)
                continue
            if first < MIN_VLAN_ID or last > MAX_VLAN_ID:
                rejected.append(part)
            vlans.extend(range(low, high + 1))
        elif part.isdigit():
            value = int(part)
            if MIN_VLAN_ID <= value <= MAX_VLAN_ID:
                vlans.append(value)
            else:
                # A VLAN id outside the standard is not a VLAN. Recording one
                # puts a segment in the topology that cannot exist, and judges
                # interfaces against it.
                rejected.append(part)
        else:
            rejected.append(part)
    return tuple(vlans), tuple(rejected)


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
        Vlan(
            device=device,
            vlan_id=vid,
            name=name if len(ids) == 1 else None,
            config_line=stanza.line or None,
        )
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

    A removed line is replaced by an empty one rather than dropped. Every stanza
    after a banner would otherwise sit at a lower number than it does in the
    file, and a citation that points a reader at the wrong line is worse than one
    that points at none.
    """
    out: list[str] = []
    in_banner = False
    for line in text.splitlines():
        if not in_banner and line.strip().startswith("banner "):
            in_banner = True
            out.append("")
            continue
        if in_banner:
            # EOS terminates with a lone EOF; IOS uses a delimiter character.
            if line.strip() in {"EOF", "!", ""} or line.strip().startswith("^"):
                in_banner = False
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


# --------------------------------------------------------------------------
# BGP peerings
# --------------------------------------------------------------------------

# Cisco IOS and NX-OS name a peering's settings with the same words — `remote-as`,
# `description`, `update-source`, `ebgp-multihop` — and differ only in where they
# put them. IOS writes one flat `neighbor <ip> <setting>` line per setting; NX-OS
# indents the same settings under a `neighbor <ip>` block header. That makes the
# setting half genuinely shared and the structural half genuinely not, which is
# where this seam is drawn: the vocabulary lives here, the nesting stays in the
# dialect module.
#
# EOS reads the same way but spells two of these differently (`peer group`,
# `maximum-routes`) and grew its parser first, so it keeps its own copy rather
# than being migrated behind a translation layer that would be longer than the
# duplication.

type BgpPeerSettings = dict[str, str | bool]

# `neighbor <ip> fall-over bfd` on IOS, a bare `bfd` inside the sub-block on
# NX-OS, and the hop-count qualifiers either of them may carry.
_BGP_PEER_BFD: Final = re.compile(
    r"(?:fall-over )?bfd(?: (?:multihop|singlehop|multi-hop|single-hop))?"
)

# Per-neighbour settings that are understood but carry no fact any tier reads
# yet. They are matched rather than ignored because matching them is what keeps
# `unparsed_lines` a list of genuinely unhandled constructs.
_BGP_PEER_UNREAD: Final = re.compile(
    r"(?:activate|additional-paths|advertise-map|advertisement-interval|"
    r"allowas-in|as-override|capability|default-originate|"
    r"disable-connected-check|disable-peer-as-check|distribute-list|"
    r"dont-capability-negotiate|fall-over|filter-list|"
    r"inherit peer-(?:policy|session)|local-as|log-neighbor-changes|"
    r"low-memory|maximum-prefix|maximum-routes|next-hop-self|password|"
    r"prefix-list|remote-private-as|remove-private-as|route-map|"
    r"route-reflector-client|send-community|soft-reconfiguration|"
    r"suppress-inactive|timers|transport|ttl-security|unsuppress-map|"
    r"version|weight)\b.*"
)


def apply_bgp_peer_setting(settings: BgpPeerSettings, setting: str) -> bool:
    """Fold one per-neighbour setting into `settings`; False if unrecognised.

    `setting` is whatever follows `neighbor <ip> ` on IOS, and one line of the
    indented sub-block on NX-OS.

    A setting this understands but does not store still returns True. A peer
    configured only with a password and a route-map is a real peering, and
    losing it would make the reciprocity rule report a one-sided session that
    is not one.
    """
    if m := re.fullmatch(r"remote-as (\S+)", setting):
        settings["remote_as"] = m.group(1)
    elif m := re.fullmatch(r"description (.+)", setting):
        settings["description"] = m.group(1)
    elif m := re.fullmatch(r"update-source (\S+)", setting):
        settings["update_source"] = m.group(1)
    elif re.fullmatch(r"ebgp-multihop(?: \d+)?", setting):
        settings["multihop"] = True
    elif setting == "shutdown":
        settings["shutdown"] = True
    elif setting == "no shutdown":
        settings["shutdown"] = False
    # IOS joins a peer-group by name; NX-OS inherits a peer template. Both name
    # a bag of settings the peer does not restate, resolved by `bgp_neighbors_from`.
    elif m := re.fullmatch(r"(?:peer-group|inherit peer) (\S+)", setting):
        settings["peer_group"] = m.group(1)
    elif _BGP_PEER_BFD.fullmatch(setting):
        settings["bfd"] = True
    elif _BGP_PEER_UNREAD.fullmatch(setting):
        pass
    else:
        return False
    return True


def register_bgp_peer(
    peers: dict[str, BgpPeerSettings],
    groups: dict[str, BgpPeerSettings],
    token: str,
) -> BgpPeerSettings:
    """The settings `token` names, created if this is the first sight of it.

    An address names a peering; anything else names a peer-group or a peer
    template. Registering on sight rather than once a setting has been
    understood is deliberate — a peering the parser can only half read is still
    a peering, and the reciprocity rule reads the address, not the settings.
    """
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return groups.setdefault(token, {})
    return peers.setdefault(token, {})


def bgp_neighbors_from(
    device: str,
    peers: Mapping[str, BgpPeerSettings],
    groups: Mapping[str, BgpPeerSettings] | None = None,
) -> tuple[BgpNeighbor, ...]:
    """Accumulated settings -> schema records, with peer-groups resolved.

    A peer-group holds what its members do not restate, and `remote-as` is very
    often exactly that, so the group's settings go underneath the member's own
    rather than being dropped — otherwise the AS a config states plainly would
    read as unstated.
    """
    resolved = groups or {}
    out: list[BgpNeighbor] = []
    for address, settings in sorted(peers.items()):
        inherited = settings.get("peer_group")
        merged: BgpPeerSettings = dict(
            resolved.get(inherited, {}) if isinstance(inherited, str) else {}
        )
        merged.update(settings)
        out.append(
            BgpNeighbor(
                device=device,
                address=address,
                remote_as=_text(merged.get("remote_as")),
                description=_text(merged.get("description")),
                update_source=_text(merged.get("update_source")),
                bfd=bool(merged.get("bfd", False)),
                multihop=bool(merged.get("multihop", False)),
                shutdown=bool(merged.get("shutdown", False)),
                peer_group=_text(merged.get("peer_group")),
            )
        )
    return tuple(out)


def _text(value: str | bool | None) -> str | None:
    """Settings are accumulated as `str | bool`; the schema wants only the strings."""
    return value if isinstance(value, str) else None
