"""Arista EOS config text -> Fact Pack.

Line-oriented and deliberately narrow. The tool needs interfaces, addressing,
VLANs, FHRP, tracking and timers — not RIB computation — so this parses the
constructs the FACTS and TIMING tiers actually read and ignores everything else
rather than failing on it.

Ignoring the rest is a choice with a cost: a construct this does not understand is
invisible, not flagged. `unparsed_lines` on the result exists so that cost is
visible instead of silent, and so a corpus can be checked for constructs worth
adding.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, replace
from typing import Final

from cassandra.factpack.builders.common import (
    ParsedDevice,
    declared_vlans_from,
    interface_kind,
    is_out_of_scope,
    seconds_to_ms,
    stanzas,
    strip_banners,
    vlan_list,
)
from cassandra.factpack.schema import (
    AddressFamily,
    BfdTimers,
    DampeningKind,
    DampeningProfile,
    Device,
    DeviceRole,
    FhrpMember,
    FhrpProtocol,
    FhrpTimers,
    IgpHelloTimers,
    IgpProtocol,
    Interface,
    IpAssignment,
    NosFamily,
    SwitchportMode,
    TimerScope,
    TimerSource,
    TrackedObject,
    TrackedObjectKind,
    Vlan,
)

SCHEMA_VERSION: Final = 1

# `bgp dampening` written bare takes these. EOS states half-life and
# max-suppress-time in minutes; the schema stores seconds, so they are converted
# on the way in and never again.
DEFAULT_HALF_LIFE_MIN: Final = 15
DEFAULT_REUSE: Final = 750
DEFAULT_SUPPRESS: Final = 2000
DEFAULT_MAX_SUPPRESS_MIN: Final = 60

# `bgp dampening half-life 15 reuse 750 suppress 2000 max-suppress-time 60`.
# EOS accepts the longer `reuse-limit` / `suppress-limit` spellings for the same
# two thresholds.
_DAMPENING_KEYS: Final = {
    "half-life": "half_life_min",
    "reuse": "reuse",
    "reuse-limit": "reuse",
    "suppress": "suppress",
    "suppress-limit": "suppress",
    "max-suppress-time": "max_suppress_min",
}


# Lines that carry no fact this tool reads. Matched to keep `unparsed_lines`
# meaningful — a long list of `end` and `!` would hide the constructs that matter.
_UNINTERESTING: Final = re.compile(
    r"^(end|!.*|no ip routing|ip routing|spanning-tree portfast|"
    r"router ospf .*|\s*(network|router-id|passive-interface|max-lsa) .*|"
    r"\s*ip ospf network .*|\s*description .*|\s*no switchport)$"
)


@dataclass(slots=True)
class EosDevice(ParsedDevice):
    """`ParsedDevice` plus the timer families only this dialect reads so far.

    The shared record carries FHRP timers because that is what every dialect
    produced when it was written. BFD, IGP hello/dead and dampening are additive
    here rather than in `common.py` so the IOS parser is untouched until it grows
    the same constructs.
    """

    bfd: tuple[BfdTimers, ...] = ()
    igp_hello: tuple[IgpHelloTimers, ...] = ()
    dampening: tuple[DampeningProfile, ...] = ()


def _minutes_to_s(value: str | int | None) -> int | None:
    return None if value is None else int(value) * 60


def _networks_by_interface(
    interfaces: list[Interface],
) -> dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    out: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
    for interface in interfaces:
        nets = []
        for assignment in interface.addresses:
            try:
                nets.append(ipaddress.ip_interface(assignment.prefix).network)
            except ValueError:
                continue
        if nets:
            out[interface.name] = nets
    return out


def parse_device(text: str, *, device_id: str | None = None) -> EosDevice:
    text = strip_banners(text)
    hostname = device_id or "unknown"
    interfaces: list[Interface] = []
    tracked: list[TrackedObject] = []
    fhrp: list[tuple[int, FhrpProtocol, FhrpMember, str, str | None]] = []
    timers: list[FhrpTimers] = []
    bfd: list[BfdTimers] = []
    igp_hello: list[IgpHelloTimers] = []
    dampening: list[DampeningProfile] = []
    unparsed: list[str] = []
    declared_vlans: list[Vlan] = []

    # Resolved once every interface is known: a BGP peer address names a session
    # by subnet, and `bfd default` names every session on the device.
    bgp_bfd_neighbors: list[str] = []
    device_wide_bfd_clients: set[str] = set()

    for stanza in stanzas(text):
        header = stanza.header

        if m := re.fullmatch(r"hostname (\S+)", header):
            hostname = m.group(1)
            continue

        if m := re.fullmatch(r"vlan (\S+)", header):
            declared_vlans.extend(declared_vlans_from(hostname, stanza))
            continue

        # EOS: `track <name> interface <intf> line-protocol`
        if m := re.fullmatch(r"track (\S+) interface (\S+) (\S+)", header):
            tracked.append(
                TrackedObject(
                    id=m.group(1),
                    device=hostname,
                    kind=TrackedObjectKind.INTERFACE,
                    target=m.group(2),
                )
            )
            continue

        if m := re.fullmatch(r"interface (\S+)", header):
            name = m.group(1)
            (
                iface,
                iface_fhrp,
                iface_timers,
                iface_bfd,
                iface_igp,
                iface_unparsed,
            ) = _parse_interface(hostname, name, stanza.body)
            interfaces.append(iface)
            fhrp.extend(iface_fhrp)
            timers.extend(iface_timers)
            bfd.extend(iface_bfd)
            igp_hello.extend(iface_igp)
            unparsed.extend(iface_unparsed)
            continue

        if m := re.fullmatch(r"router bgp (\S+)", header):
            profiles, neighbors, bgp_unparsed = _parse_router_bgp(
                hostname, m.group(1), stanza.body
            )
            dampening.extend(profiles)
            bgp_bfd_neighbors.extend(neighbors)
            unparsed.extend(bgp_unparsed)
            continue

        if m := re.fullmatch(r"router (ospf|isis) (\S+)", header):
            protocol = "ospf" if m.group(1) == "ospf" else "isis"
            for line in stanza.body:
                # `bfd default` turns BFD on for every adjacency the process has,
                # so it registers the process as a client of every session here.
                if line in {"bfd default", "bfd all-interfaces"}:
                    device_wide_bfd_clients.add(protocol)
                elif not _UNINTERESTING.fullmatch(line):
                    unparsed.append(line)
            continue

        # An out-of-scope section takes its body with it. Reporting the body
        # of a route-map or a management stanza is the same noise as reporting
        # its header, and it is the noise that makes the list unreadable.
        if is_out_of_scope(header):
            continue
        if not _UNINTERESTING.fullmatch(header):
            unparsed.append(header)
        unparsed.extend(
            line
            for line in stanza.body
            if not _UNINTERESTING.fullmatch(line) and not is_out_of_scope(line)
        )

    if bgp_bfd_neighbors or device_wide_bfd_clients:
        networks = _networks_by_interface(interfaces)
        bfd = [
            replace(
                session,
                clients=tuple(
                    sorted(
                        set(session.clients)
                        | device_wide_bfd_clients
                        | _bgp_clients(session, networks, bgp_bfd_neighbors)
                    )
                ),
            )
            for session in bfd
        ]

    device = Device(
        id=hostname,
        hostname=hostname,
        role=DeviceRole.UNKNOWN,
        nos_family=NosFamily.EOS,
        interfaces=tuple(interfaces),
        config_line_count=len(text.splitlines()),
    )
    return EosDevice(
        device=device,
        fhrp=tuple(fhrp),
        tracked=tuple(tracked),
        timers=tuple(timers),
        unparsed_lines=tuple(unparsed),
        vlans=tuple(declared_vlans),
        bfd=tuple(bfd),
        igp_hello=tuple(igp_hello),
        dampening=tuple(dampening),
    )


def _bgp_clients(
    session: BfdTimers,
    networks: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]],
    neighbors: list[str],
) -> set[str]:
    """BGP registers against a session by peer address, not by interface name."""
    nets = networks.get(session.scope.interface or "", [])
    for neighbor in neighbors:
        try:
            address = ipaddress.ip_address(neighbor)
        except ValueError:
            continue
        if any(address in net for net in nets):
            return {"bgp"}
    return set()


def _parse_router_bgp(
    device: str, asn: str, body: list[str]
) -> tuple[list[DampeningProfile], list[str], list[str]]:
    profiles: list[DampeningProfile] = []
    neighbors: list[str] = []
    unparsed: list[str] = []
    scope = TimerScope(device=device, instance=asn, source=TimerSource.CONFIGURED)

    for line in body:
        if m := re.fullmatch(r"neighbor (\S+) bfd", line):
            neighbors.append(m.group(1))
        elif m := re.fullmatch(r"bgp dampening(?: (.+))?", line):
            profile = _dampening_profile(scope, m.group(1))
            if profile is None:
                unparsed.append(line)
            else:
                profiles.append(profile)
        elif not _UNINTERESTING.fullmatch(line):
            unparsed.append(line)
    return profiles, neighbors, unparsed


def _dampening_profile(
    scope: TimerScope, arguments: str | None
) -> DampeningProfile | None:
    """`bgp dampening [half-life M reuse R suppress S max-suppress-time M]`.

    A bare `bgp dampening` is not a missing fact — it selects the platform
    defaults, which is exactly the case where an hour-long suppression is
    inherited rather than chosen, so the defaults are recorded with the
    provenance that says so.
    """
    values: dict[str, int] = {}
    if arguments:
        tokens = arguments.split()
        if len(tokens) % 2:
            return None
        for key, value in zip(tokens[::2], tokens[1::2], strict=True):
            field = _DAMPENING_KEYS.get(key)
            if field is None or not value.isdigit():
                return None
            values[field] = int(value)
        source = TimerSource.CONFIGURED
    else:
        source = TimerSource.PLATFORM_DEFAULT
        values = {
            "half_life_min": DEFAULT_HALF_LIFE_MIN,
            "reuse": DEFAULT_REUSE,
            "suppress": DEFAULT_SUPPRESS,
            "max_suppress_min": DEFAULT_MAX_SUPPRESS_MIN,
        }

    return DampeningProfile(
        scope=replace(scope, source=source),
        kind=DampeningKind.BGP_ROUTE,
        half_life_s=_minutes_to_s(values.get("half_life_min")),
        reuse_threshold=values.get("reuse"),
        suppress_threshold=values.get("suppress"),
        max_suppress_s=_minutes_to_s(values.get("max_suppress_min")),
    )


def _parse_interface(
    device: str, name: str, body: list[str]
) -> tuple[
    Interface,
    list[tuple[int, FhrpProtocol, FhrpMember, str, str | None]],
    list[FhrpTimers],
    list[BfdTimers],
    list[IgpHelloTimers],
    list[str],
]:
    description: str | None = None
    enabled = True
    mtu: int | None = None
    mode = SwitchportMode.NONE
    access_vlan: int | None = None
    allowed: tuple[int, ...] = ()
    addresses: list[IpAssignment] = []
    unparsed: list[str] = []

    # group -> accumulated VRRP settings
    groups: dict[int, dict[str, str]] = {}
    group_tracks: dict[int, list[tuple[str, int]]] = {}

    bfd_settings: dict[str, str] = {}
    bfd_echo = False
    bfd_clients: set[str] = set()
    ospf: dict[str, str] = {}
    isis: dict[str, str] = {}

    for line in body:
        if m := re.fullmatch(r"description (.+)", line):
            description = m.group(1)
        elif line == "shutdown":
            enabled = False
        elif m := re.fullmatch(r"mtu (\d+)", line):
            mtu = int(m.group(1))
        elif line == "no switchport":
            mode = SwitchportMode.ROUTED
        elif line == "switchport mode trunk":
            mode = SwitchportMode.TRUNK
        elif line == "switchport mode access":
            mode = SwitchportMode.ACCESS
        elif m := re.fullmatch(r"switchport access vlan (\d+)", line):
            access_vlan = int(m.group(1))
        elif m := re.fullmatch(r"switchport trunk allowed vlan (\S+)", line):
            allowed = vlan_list(m.group(1))
        elif m := re.fullmatch(r"ip address (\S+?)/(\d+)( secondary)?", line):
            addresses.append(
                IpAssignment(
                    address=m.group(1),
                    prefix=f"{m.group(1)}/{m.group(2)}",
                    family=AddressFamily.IPV4_UNICAST,
                    secondary=bool(m.group(3)),
                )
            )
        # `bfd interval 300 min_rx 300 multiplier 3`
        elif m := re.fullmatch(
            r"bfd interval (\d+) min[_-]rx (\d+) multiplier (\d+)", line
        ):
            bfd_settings["tx"] = m.group(1)
            bfd_settings["rx"] = m.group(2)
            bfd_settings["multiplier"] = m.group(3)
        elif m := re.fullmatch(r"bfd echo(?: rx interval (\d+))?", line):
            bfd_echo = True
            if m.group(1):
                bfd_settings["echo_rx"] = m.group(1)
        elif line == "no bfd echo":
            bfd_echo = False
        elif m := re.fullmatch(r"ip ospf (hello|dead)-interval (\d+)", line):
            ospf[f"{m.group(1)}_s"] = m.group(2)
        elif m := re.fullmatch(r"ip ospf area (\S+)", line):
            ospf["area"] = m.group(1)
        elif line == "ip ospf bfd":
            bfd_clients.add("ospf")
        elif m := re.fullmatch(r"isis hello-interval (\d+)", line):
            isis["hello_s"] = m.group(1)
        elif m := re.fullmatch(r"isis hello-multiplier (\d+)", line):
            isis["multiplier"] = m.group(1)
        elif line == "isis bfd":
            bfd_clients.add("isis")
        elif m := re.fullmatch(r"vrrp (\d+) (.+)", line):
            group = int(m.group(1))
            rest = m.group(2)
            settings = groups.setdefault(group, {})
            if t := re.fullmatch(r"tracked-object (\S+) decrement (\d+)", rest):
                group_tracks.setdefault(group, []).append((t.group(1), int(t.group(2))))
            elif t := re.fullmatch(r"ipv4 (\S+)", rest):
                settings["virtual_ipv4"] = t.group(1)
            elif t := re.fullmatch(r"priority-level (\d+)", rest):
                settings["priority"] = t.group(1)
            elif rest == "preempt":
                settings["preempt"] = "true"
            elif t := re.fullmatch(r"preempt delay minimum (\d+)", rest):
                settings["preempt_delay_minimum_s"] = t.group(1)
            elif t := re.fullmatch(r"preempt delay reload (\d+)", rest):
                settings["preempt_delay_reload_s"] = t.group(1)
            elif t := re.fullmatch(r"advertisement interval (\d+)", rest):
                settings["advertisement_interval_s"] = t.group(1)
            elif rest == "bfd":
                bfd_clients.add(f"vrrp-{group}")
            else:
                unparsed.append(line)
        elif not _UNINTERESTING.fullmatch(line):
            unparsed.append(line)

    interface = Interface(
        device=device,
        name=name,
        kind=interface_kind(name),
        description=description,
        admin_enabled=enabled,
        mtu_bytes=mtu,
        switchport_mode=mode,
        access_vlan=access_vlan,
        allowed_vlans=allowed,
        addresses=tuple(addresses),
    )

    scope = TimerScope(device=device, interface=name, source=TimerSource.CONFIGURED)

    bfd_timers: list[BfdTimers] = []
    if bfd_settings:
        bfd_timers.append(
            BfdTimers(
                scope=scope,
                desired_min_tx_ms=_int_or_none(bfd_settings.get("tx")),
                required_min_rx_ms=_int_or_none(bfd_settings.get("rx")),
                detect_multiplier=_int_or_none(bfd_settings.get("multiplier")),
                echo_enabled=bfd_echo,
                echo_rx_interval_ms=_int_or_none(bfd_settings.get("echo_rx")),
                clients=tuple(sorted(bfd_clients)),
            )
        )

    igp_timers: list[IgpHelloTimers] = []
    if ospf:
        igp_timers.append(
            IgpHelloTimers(
                scope=scope,
                protocol=IgpProtocol.OSPFV2,
                hello_interval_ms=seconds_to_ms(ospf.get("hello_s")),
                dead_interval_ms=seconds_to_ms(ospf.get("dead_s")),
                ospf_area=ospf.get("area"),
            )
        )
    if isis:
        # IS-IS states its hold time as a multiple of the hello interval rather
        # than directly; both halves are recorded and the product is left to
        # whoever needs it, so nothing here is derived.
        igp_timers.append(
            IgpHelloTimers(
                scope=scope,
                protocol=IgpProtocol.ISIS,
                hello_interval_ms=seconds_to_ms(isis.get("hello_s")),
                hello_multiplier=_int_or_none(isis.get("multiplier")),
            )
        )

    members: list[tuple[int, FhrpProtocol, FhrpMember, str, str | None]] = []
    timers: list[FhrpTimers] = []
    for group, settings in sorted(groups.items()):
        group_scope = TimerScope(
            device=device,
            interface=name,
            instance=str(group),
            source=TimerSource.CONFIGURED,
        )
        member = FhrpMember(
            device=device,
            interface=name,
            priority=int(settings.get("priority", "100")),
            preempt="preempt" in settings
            or "preempt_delay_minimum_s" in settings
            or "preempt_delay_reload_s" in settings,
            tracked_objects=tuple(
                TrackedObject(
                    id=track_id,
                    device=device,
                    kind=TrackedObjectKind.INTERFACE,
                    target="",
                    decrement=decrement,
                )
                for track_id, decrement in group_tracks.get(group, [])
            ),
        )
        members.append(
            (group, FhrpProtocol.VRRP, member, name, settings.get("virtual_ipv4"))
        )
        timers.append(
            FhrpTimers(
                scope=group_scope,
                protocol=FhrpProtocol.VRRP,
                hello_interval_ms=seconds_to_ms(
                    settings.get("advertisement_interval_s")
                ),
                preempt_delay_ms=seconds_to_ms(settings.get("preempt_delay_minimum_s")),
                preempt_delay_reload_ms=seconds_to_ms(
                    settings.get("preempt_delay_reload_s")
                ),
            )
        )
    return interface, members, timers, bfd_timers, igp_timers, unparsed


def _int_or_none(value: str | None) -> int | None:
    return None if value is None else int(value)
