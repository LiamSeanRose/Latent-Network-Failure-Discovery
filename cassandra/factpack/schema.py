"""Static Fact Pack schema.

Implements the subset of PROJECT.md §3 covering device inventory, L1/L2/L3
adjacency, FHRP groups, and the timer inventory. The remaining §3 bullets
(per-protocol adjacency graphs, VRF/RT matrix, redistribution points,
summarization points, ECMP fan-out, historical incident index) are deliberately
absent and land with their own builders.

Design rules this module holds to:

* Declarations only. No parsing, no serialization, no derivation, no
  validation logic. Builders produce these objects; `serialize.py` renders
  them. Neither exists yet.
* Everything is frozen and composed of tuples, so a built Fact Pack is
  immutable and hashable. A cached prompt prefix that can mutate underneath
  the cache is a correctness bug (§3.1).
* The timer inventory is the single owner of every timer value in the
  network. Timers are not duplicated onto the objects they configure —
  `FhrpGroup` carries preempt on/off but not preempt delay, `Interface`
  carries MTU but not carrier-delay. Every timer record instead carries a
  `TimerScope` naming what it applies to. Timer races are a first-class
  question a scenario can ask (§1.4), so timers must be enumerable as one flat set
  rather than scattered across the topology.
* Configured value and provenance are kept together. `TimerSource`
  distinguishes an explicitly configured timer from a platform default;
  the difference decides whether a timer race is an operator decision or an
  inherited accident.
* A fact carries where it was written. `Device.config_path` names the file, and
  `config_line` on the objects a stanza declares names the line inside it, so a
  finding can send a reader to the configuration responsible rather than to a
  device name (§5.4). The path is relative to the directory that was checked:
  an absolute path from the machine that ran the check means nothing in a report
  someone else reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

# --------------------------------------------------------------------------
# Primitive aliases
# --------------------------------------------------------------------------

type DeviceId = str
type InterfaceName = str
type LinkId = str
type SegmentId = str
type GroupId = str
type VlanId = int
type IpAddress = str
type IpPrefix = str
type MacAddress = str
type VrfName = str

type Milliseconds = int
type Seconds = int
type Minutes = int


# --------------------------------------------------------------------------
# Shared enumerations
# --------------------------------------------------------------------------


class NosFamily(StrEnum):
    """Network OS family. Drives timer-default and fidelity reasoning (§5.3)."""

    IOS_XE = "ios-xe"
    IOS_XR = "ios-xr"
    NX_OS = "nx-os"
    EOS = "eos"
    SR_LINUX = "sr-linux"
    FRR = "frr"
    UNKNOWN = "unknown"


class DeviceRole(StrEnum):
    CORE = "core"
    AGGREGATION = "aggregation"
    METRO = "metro"
    ACCESS = "access"
    EDGE = "edge"
    UNKNOWN = "unknown"


class InterfaceKind(StrEnum):
    PHYSICAL = "physical"
    SUBINTERFACE = "subinterface"
    LAG = "lag"
    SVI = "svi"
    LOOPBACK = "loopback"
    TUNNEL = "tunnel"
    MANAGEMENT = "management"
    UNKNOWN = "unknown"


class LinkMedia(StrEnum):
    FIBER = "fiber"
    COPPER = "copper"
    VIRTUAL = "virtual"
    UNKNOWN = "unknown"


class SwitchportMode(StrEnum):
    ROUTED = "routed"
    ACCESS = "access"
    TRUNK = "trunk"
    NONE = "none"


class AddressFamily(StrEnum):
    IPV4_UNICAST = "ipv4-unicast"
    IPV6_UNICAST = "ipv6-unicast"


class IgpProtocol(StrEnum):
    OSPFV2 = "ospfv2"
    OSPFV3 = "ospfv3"
    ISIS = "isis"


class FhrpProtocol(StrEnum):
    HSRP = "hsrp"
    VRRP = "vrrp"
    GLBP = "glbp"


class TrackedObjectKind(StrEnum):
    INTERFACE = "interface"
    ROUTE = "route"
    IP_SLA = "ip-sla"
    BFD_SESSION = "bfd-session"
    OBJECT_LIST = "object-list"
    UNKNOWN = "unknown"


class StpMode(StrEnum):
    STP = "stp"
    RSTP = "rstp"
    PVST = "pvst"
    RAPID_PVST = "rapid-pvst"
    MST = "mst"
    NONE = "none"


class LagProtocol(StrEnum):
    LACP = "lacp"
    STATIC = "static"
    PAGP = "pagp"


class BfdSessionKind(StrEnum):
    SINGLE_HOP = "single-hop"
    MULTI_HOP = "multi-hop"
    ECHO = "echo"


class DampeningKind(StrEnum):
    BGP_ROUTE = "bgp-route"
    INTERFACE = "interface"
    IGP_ROUTE = "igp-route"


class TimerSource(StrEnum):
    """Where a timer value came from.

    A platform default that happens to race with a configured timer reads very
    differently from two values an operator chose, and only one of them is worth
    writing a scenario about.
    """

    CONFIGURED = "configured"
    PLATFORM_DEFAULT = "platform-default"
    INHERITED = "inherited"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------
# References
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class InterfaceRef:
    """Stable pointer to one interface. The unit of L1/L2/L3 adjacency."""

    device: DeviceId
    interface: InterfaceName


# --------------------------------------------------------------------------
# Device inventory
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class IpAssignment:
    address: IpAddress
    prefix: IpPrefix
    family: AddressFamily
    secondary: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class Interface:
    device: DeviceId
    name: InterfaceName
    kind: InterfaceKind
    description: str | None = None
    admin_enabled: bool = True
    speed_mbps: int | None = None
    mtu_bytes: int | None = None
    l3_mtu_bytes: int | None = None
    switchport_mode: SwitchportMode = SwitchportMode.NONE
    access_vlan: VlanId | None = None
    allowed_vlans: tuple[VlanId, ...] = ()
    native_vlan: VlanId | None = None
    vrf: VrfName | None = None
    addresses: tuple[IpAssignment, ...] = ()
    mac_address: MacAddress | None = None
    parent: InterfaceName | None = None
    lag_member_of: InterfaceName | None = None
    dot1q_vlan: VlanId | None = None
    config_line: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Device:
    id: DeviceId
    hostname: str
    role: DeviceRole = DeviceRole.UNKNOWN
    nos_family: NosFamily = NosFamily.UNKNOWN
    platform: str | None = None
    os_version: str | None = None
    site: str | None = None
    vrfs: tuple[VrfName, ...] = ()
    interfaces: tuple[Interface, ...] = ()
    config_line_count: int | None = None
    config_path: str | None = None


# --------------------------------------------------------------------------
# Layer 1
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class L1Link:
    """One physical link.

    Mirrors what Batfish consumes as `layer1_topology.json` (§1.3): downing one
    end downs the other, which is what makes symbolic failure analysis and
    emulated link flap describe the same event.
    """

    id: LinkId
    a: InterfaceRef
    b: InterfaceRef
    media: LinkMedia = LinkMedia.UNKNOWN
    capacity_mbps: int | None = None
    latency_ms: float | None = None
    shared_risk_groups: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class LinkAggregationGroup:
    device: DeviceId
    name: InterfaceName
    protocol: LagProtocol = LagProtocol.STATIC
    members: tuple[InterfaceName, ...] = ()
    min_links: int | None = None
    peer_device: DeviceId | None = None
    multi_chassis: bool = False


# --------------------------------------------------------------------------
# Layer 2
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class Vlan:
    device: DeviceId
    vlan_id: VlanId
    name: str | None = None
    stp_instance: int | None = None
    config_line: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class L2Segment:
    """One broadcast domain: the members of a VLAN that can actually reach
    each other over enabled, trunk-permitted, non-STP-blocked links."""

    id: SegmentId
    vlan_id: VlanId | None = None
    members: tuple[InterfaceRef, ...] = ()
    stp_mode: StpMode = StpMode.NONE
    stp_instance: int | None = None
    root_bridge: DeviceId | None = None
    bridge_priorities: tuple[tuple[DeviceId, int], ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class L2Adjacency:
    a: InterfaceRef
    b: InterfaceRef
    vlans: tuple[VlanId, ...] = ()
    segment: SegmentId | None = None
    over_lag: bool = False


# --------------------------------------------------------------------------
# Layer 3
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class L3Adjacency:
    """Interfaces sharing an IP subnet in one VRF: who can be an IGP, BGP, BFD,
    or FHRP peer of whom before any protocol config is considered."""

    prefix: IpPrefix
    family: AddressFamily
    vrf: VrfName | None = None
    members: tuple[InterfaceRef, ...] = ()
    over_l2_segment: SegmentId | None = None


# --------------------------------------------------------------------------
# FHRP
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class TrackedObject:
    """A tracked object as referenced by an FHRP member. Tracking *delays* are
    timers and live in the timer inventory, not here."""

    id: str
    device: DeviceId
    kind: TrackedObjectKind
    target: str
    decrement: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class FhrpMember:
    device: DeviceId
    interface: InterfaceName
    priority: int
    preempt: bool = False
    tracked_objects: tuple[TrackedObject, ...] = ()
    version: int | None = None
    authenticated: bool = False
    config_line: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class FhrpGroup:
    """One first-hop redundancy group across its members.

    Whether groups on the same pair of devices move in lockstep or
    independently is not answerable from this object alone — it depends on
    priorities, tracked objects, preempt, and the timers in `TimerInventory`.
    That is precisely what a scenario in the sense of §2.1 exists to answer.
    """

    id: GroupId
    protocol: FhrpProtocol
    group_number: int
    members: tuple[FhrpMember, ...] = ()
    virtual_ipv4: IpAddress | None = None
    virtual_ipv6: IpAddress | None = None
    virtual_mac: MacAddress | None = None
    subnet: IpPrefix | None = None
    vrf: VrfName | None = None
    l2_segment: SegmentId | None = None
    l3_adjacency_prefix: IpPrefix | None = None


# --------------------------------------------------------------------------
# BGP
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class BgpNeighbor:
    """One configured peering, as the local device sees it.

    Deliberately one-sided: this is what a device says about a peer, not a
    negotiated session. The interesting defects live in the disagreement between
    the two ends, which is only visible when both are in the same fact pack.
    """

    device: DeviceId
    address: IpAddress
    remote_as: str | None = None
    description: str | None = None
    update_source: InterfaceName | None = None
    bfd: bool = False
    multihop: bool = False
    shutdown: bool = False
    peer_group: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class BgpProcess:
    device: DeviceId
    local_as: str
    router_id: IpAddress | None = None
    neighbors: tuple[BgpNeighbor, ...] = ()


# --------------------------------------------------------------------------
# Timer inventory
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class TimerScope:
    """What a timer record applies to.

    `instance` carries whatever names the protocol context — an OSPF process
    and area, an IS-IS level, a BGP peer group, an STP instance, an FHRP group
    id, a VRF. Left as an opaque string on purpose: the builders that populate
    it do not exist yet, and inventing a taxonomy before they do is guesswork.
    """

    device: DeviceId
    interface: InterfaceName | None = None
    neighbor: str | None = None
    instance: str | None = None
    vrf: VrfName | None = None
    source: TimerSource = TimerSource.UNKNOWN


@dataclass(frozen=True, slots=True, kw_only=True)
class IgpHelloTimers:
    """OSPF and IS-IS adjacency-maintenance timers."""

    scope: TimerScope
    protocol: IgpProtocol
    hello_interval_ms: Milliseconds | None = None
    dead_interval_ms: Milliseconds | None = None
    hold_time_ms: Milliseconds | None = None
    hello_multiplier: int | None = None
    retransmit_interval_ms: Milliseconds | None = None
    transmit_delay_ms: Milliseconds | None = None
    wait_interval_ms: Milliseconds | None = None
    csnp_interval_ms: Milliseconds | None = None
    psnp_interval_ms: Milliseconds | None = None
    isis_level: int | None = None
    ospf_area: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class BfdTimers:
    """BFD session parameters.

    `clients` is the field that makes "does BFD detect before or after the IGP
    hold timer?" (§1.4) expressible: a BFD session nothing has registered
    against cannot accelerate any convergence.
    """

    scope: TimerScope
    kind: BfdSessionKind = BfdSessionKind.SINGLE_HOP
    desired_min_tx_ms: Milliseconds | None = None
    required_min_rx_ms: Milliseconds | None = None
    detect_multiplier: int | None = None
    echo_enabled: bool = False
    echo_rx_interval_ms: Milliseconds | None = None
    dampening_hold_down_ms: Milliseconds | None = None
    clients: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class BgpTimers:
    scope: TimerScope
    keepalive_ms: Milliseconds | None = None
    hold_time_ms: Milliseconds | None = None
    min_hold_time_ms: Milliseconds | None = None
    advertisement_interval_ms: Milliseconds | None = None
    connect_retry_ms: Milliseconds | None = None
    next_hop_trigger_delay_critical_ms: Milliseconds | None = None
    next_hop_trigger_delay_non_critical_ms: Milliseconds | None = None
    update_delay_ms: Milliseconds | None = None
    graceful_restart_time_s: Seconds | None = None
    stalepath_time_s: Seconds | None = None
    as_origination_interval_ms: Milliseconds | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class DampeningProfile:
    """Route or interface dampening.

    Directly backs a dampening-versus-SLA scenario: max-suppress bounds
    how long a prefix can stay withdrawn after the network is otherwise
    healthy, which is comparable against an SLA and invisible to steady-state
    analysis.
    """

    scope: TimerScope
    kind: DampeningKind
    half_life_s: Seconds | None = None
    reuse_threshold: int | None = None
    suppress_threshold: int | None = None
    max_suppress_s: Seconds | None = None
    restart_penalty: int | None = None
    decay_half_life_unreachable_s: Seconds | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class SpfThrottleTimers:
    """Exponential backoff on route computation and LSA/LSP origination."""

    scope: TimerScope
    protocol: IgpProtocol
    spf_initial_delay_ms: Milliseconds | None = None
    spf_hold_ms: Milliseconds | None = None
    spf_max_wait_ms: Milliseconds | None = None
    lsa_initial_delay_ms: Milliseconds | None = None
    lsa_hold_ms: Milliseconds | None = None
    lsa_max_wait_ms: Milliseconds | None = None
    lsa_arrival_ms: Milliseconds | None = None
    prc_initial_delay_ms: Milliseconds | None = None
    prc_hold_ms: Milliseconds | None = None
    prc_max_wait_ms: Milliseconds | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CarrierDelayTimers:
    """Interface link-state debounce.

    Asymmetric up/down values are the usual source of a flap being invisible
    to the control plane in one direction and not the other.
    """

    scope: TimerScope
    carrier_delay_up_ms: Milliseconds | None = None
    carrier_delay_down_ms: Milliseconds | None = None
    debounce_time_ms: Milliseconds | None = None
    hold_time_ms: Milliseconds | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class StpTimers:
    scope: TimerScope
    mode: StpMode = StpMode.NONE
    hello_time_ms: Milliseconds | None = None
    forward_delay_ms: Milliseconds | None = None
    max_age_ms: Milliseconds | None = None
    transmit_hold_count: int | None = None
    max_hops: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class FhrpTimers:
    """Per-group, per-member FHRP timing. `scope.instance` is the group id."""

    scope: TimerScope
    protocol: FhrpProtocol
    hello_interval_ms: Milliseconds | None = None
    hold_time_ms: Milliseconds | None = None
    preempt_delay_ms: Milliseconds | None = None
    preempt_delay_reload_ms: Milliseconds | None = None
    preempt_delay_minimum_ms: Milliseconds | None = None
    mac_refresh_ms: Milliseconds | None = None
    redirect_ms: Milliseconds | None = None
    forwarder_timeout_ms: Milliseconds | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class TimerInventory:
    """Every timer in the network, in one enumerable place.

    Any question carrying a time quantity has to be answered by emulation rather
    than symbolically (§1.4), and the ±20% perturbation control (§2.4) needs the
    configured values to perturb around. Both read from here.
    """

    igp_hello: tuple[IgpHelloTimers, ...] = ()
    bfd: tuple[BfdTimers, ...] = ()
    bgp: tuple[BgpTimers, ...] = ()
    dampening: tuple[DampeningProfile, ...] = ()
    spf_throttle: tuple[SpfThrottleTimers, ...] = ()
    carrier_delay: tuple[CarrierDelayTimers, ...] = ()
    stp: tuple[StpTimers, ...] = ()
    fhrp: tuple[FhrpTimers, ...] = ()


# --------------------------------------------------------------------------
# Root
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class FactPackMeta:
    """Identity of one built Fact Pack.

    `config_digest` is what decides whether a cached prompt prefix is still
    valid, and identifies which configs a finding was derived from (§3).
    """

    fact_pack_id: str
    schema_version: int
    config_digest: str
    source_snapshot: str
    generated_at: datetime
    device_count: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class StaticFactPack:
    """The cacheable half of the Fact Pack (§3).

    Fields for the §3 bullets not yet implemented — per-protocol adjacency
    graphs, VRF/RT import-export matrix, redistribution points, summarization
    points, ECMP fan-out, historical incident index — are absent rather than
    stubbed, and arrive with their builders.
    """

    meta: FactPackMeta
    devices: tuple[Device, ...] = ()
    l1_links: tuple[L1Link, ...] = ()
    lags: tuple[LinkAggregationGroup, ...] = ()
    vlans: tuple[Vlan, ...] = ()
    l2_segments: tuple[L2Segment, ...] = ()
    l2_adjacencies: tuple[L2Adjacency, ...] = ()
    l3_adjacencies: tuple[L3Adjacency, ...] = ()
    fhrp_groups: tuple[FhrpGroup, ...] = ()
    bgp: tuple[BgpProcess, ...] = ()
    timers: TimerInventory = field(default_factory=TimerInventory)
