# Rule catalogue

Every check this tool can report, what trips it, and — the part a clean run
depends on — when it deliberately stays quiet.

Generated from the rules themselves by `python -m cassandra.catalogue --write`.
Do not edit by hand: `tests/test_catalogue.py` regenerates it and fails on any
difference, so an edit here is lost and a new rule that is not documented here
breaks the build.

## Index

| Rule | Tier | Severity | Summary |
| --- | --- | --- | --- |
| [`bgp-remote-as-mismatch`](#bgp-remote-as-mismatch) | facts | high | One end expects an AS the other does not use. |
| [`bgp-session-one-sided`](#bgp-session-one-sided) | facts | high | A peering only one end knows about. |
| [`dampening-exceeds-sla`](#dampening-exceeds-sla) | facts | high | Max-suppress bounds how long a prefix stays withdrawn after the fault ends. |
| [`duplicate-address`](#duplicate-address) | facts | high | One IPv4 address configured on two interfaces in the collection. |
| [`fhrp-duplicate-member`](#fhrp-duplicate-member) | facts | high | One device holding two memberships of the same group on one subnet. |
| [`fhrp-track-target-shutdown`](#fhrp-track-target-shutdown) | facts | high | A track whose target is administratively down. |
| [`fhrp-track-undefined`](#fhrp-track-undefined) | facts | high | A group that decrements its priority for a track nobody defined. |
| [`fhrp-virtual-collides`](#fhrp-virtual-collides) | facts | high | A virtual address a real interface on the same pair already owns. |
| [`fhrp-virtual-not-a-host-address`](#fhrp-virtual-not-a-host-address) | facts | high | A virtual address that is not a host address at all. |
| [`fhrp-virtual-outside-subnet`](#fhrp-virtual-outside-subnet) | facts | high | A virtual address outside every subnet the member interface is on. |
| [`fhrp-virtual-shared`](#fhrp-virtual-shared) | facts | high | Two groups on one interface answering for the same virtual address. |
| [`mtu-mismatch`](#mtu-mismatch) | facts | high | Neighbours that disagree about how large a frame may be. |
| [`vlan-not-declared`](#vlan-not-declared) | facts | high | A port assigned to a VLAN the device never creates. |
| [`bfd-no-clients`](#bfd-no-clients) | facts | medium | A session nothing registered against comes up, runs, and is never asked. |
| [`bfd-no-faster-than-igp`](#bfd-no-faster-than-igp) | facts | medium | BFD exists to detect faster than the IGP. One that does not is decoration. |
| [`bgp-peer-off-subnet`](#bgp-peer-off-subnet) | facts | medium | A directly-connected peer address that is on none of this device's subnets. |
| [`fhrp-no-redundancy`](#fhrp-no-redundancy) | facts | medium | A redundancy group with fewer than two members in the collection. |
| [`fhrp-priority-tie`](#fhrp-priority-tie) | facts | medium | Members sharing the top priority, so nothing decides the master. |
| [`fhrp-track-ineffective`](#fhrp-track-ineffective) | facts | medium | A decrement too small to lose the election is tracking that does nothing. |
| [`svi-vlan-not-trunked`](#svi-vlan-not-trunked) | facts | medium | An addressed SVI for a VLAN no trunk on the device carries. |
| [`fhrp-no-preempt-on-preferred`](#fhrp-no-preempt-on-preferred) | facts | low | The highest-priority member has preempt off, so it never takes back. |
| [`trunk-vlan-dead`](#trunk-vlan-dead) | facts | low | A VLAN permitted on a trunk that no device in the topology terminates. |
| [`l3-interface-isolated`](#l3-interface-isolated) | facts | info | An addressed interface on a subnet no other device shares. |
| [`fhrp-divergence`](#fhrp-divergence) | timing | high | Two FHRP groups on the same device pair that stop agreeing who is master. |
| [`fhrp-oscillation`](#fhrp-oscillation) | timing | medium | A group that changes master repeatedly while one interface flaps. |

## FACTS tier

Decidable from the configuration text alone (PROJECT.md §2.1). A finding here is either true of the text or a bug in the rule — no model stands between the config and the claim.

### `bgp-remote-as-mismatch`

**high** · `cassandra.facts.rules.bgp_remote_as_disagrees`

One end expects an AS the other does not use.

**Reports:** BGP expects {…} to be AS {…}, but it runs AS {…}

**Detail:** the OPEN is rejected on AS mismatch, so the session stays down while both configurations look reasonable in isolation

**Remedy:** correct the remote-as on {…} to {…}, or the local AS on {…}

**Stays silent when:**

- An upstream provider is not in your config directory and is not a defect.  
  `test_facts_rules.py::test_peer_outside_the_corpus_is_not_a_one_sided_session`
- Ios reciprocated bgp session is silent  
  `test_ios_builder.py::test_ios_reciprocated_bgp_session_is_silent`
- Nxos reciprocated bgp session is silent  
  `test_nxos_builder.py::test_nxos_reciprocated_bgp_session_is_silent`

### `bgp-session-one-sided`

**high** · `cassandra.facts.rules.bgp_session_configured_on_one_side`

A peering only one end knows about.

Decidable only when both devices are present, so it stays silent on a single-device pack or a peer outside the corpus — an upstream provider is not a defect.

**Reports:** BGP peering with {…} is configured on one side only

**Detail:** {…} peers to {…}, but {…} has no neighbor statement back. The session never establishes and the config looks complete on this device

**Remedy:** add the reciprocal neighbor on {…}, or remove this one

**Stays silent when:**

- An upstream provider is not in your config directory and is not a defect.  
  `test_facts_rules.py::test_peer_outside_the_corpus_is_not_a_one_sided_session`
- Ios reciprocated bgp session is silent  
  `test_ios_builder.py::test_ios_reciprocated_bgp_session_is_silent`
- The peering the far end states without a remote-as is still a peering.  
  `test_ios_builder.py::test_a_far_end_known_only_by_a_password_is_not_a_one_sided_session`
- Nxos reciprocated bgp session is silent  
  `test_nxos_builder.py::test_nxos_reciprocated_bgp_session_is_silent`
- The peering the far end states without a remote-as is still a peering.  
  `test_nxos_builder.py::test_a_far_end_known_only_by_a_password_is_not_a_one_sided_session`

### `dampening-exceeds-sla`

**high** · `cassandra.timing.timer_rules.dampening_outlasts_the_sla`

Max-suppress bounds how long a prefix stays withdrawn after the fault ends.

That window is invisible to steady-state analysis — every device is healthy, every adjacency is up, and the route is still gone — which is exactly why it reaches production.

**Reports:** {…} dampening can suppress a prefix for {…}

**Detail:** max-suppress is {…} against an SLA of {…}. A prefix that reaches the suppress threshold stays withdrawn for that long after the network is otherwise healthy.{…}

**Remedy:** lower max-suppress-time below {…}, or remove dampening

**Stays silent when:**

- _No test asserts this rule staying quiet. Its silence is untested, so read it as an absence of evidence._

### `duplicate-address`

**high** · `cassandra.facts.rules.duplicate_addresses`

One IPv4 address configured on two interfaces in the collection.

Whichever device answers first wins, and which one that is depends on ARP timing rather than on anything written down. The usual cause is a config copied between devices and edited everywhere except the address, so the duplicate is often on the device that was working yesterday.

Compares addresses, not prefixes: the same address with two different masks is still one address two devices claim.

**Reports:** {…} is configured twice

**Detail:** also on {…}

**Remedy:** renumber one of them

**Stays silent when:**

- _No test asserts this rule staying quiet. Its silence is untested, so read it as an absence of evidence._

### `fhrp-duplicate-member`

**high** · `cassandra.facts.rules.duplicate_group_member`

One device holding two memberships of the same group on one subnet.

Group numbers are legitimately reused across unrelated subnets — group 1 on every SVI is ordinary practice — so the subnet is what makes this decidable. Two memberships of one group in one subnet on one device means the device contends with itself: it sends advertisements from two interfaces, and which of them holds the virtual address is not something the config decides.

**Reports:** {…} is a member of {…} twice on {…}

**Detail:** {…} and {…} both run {…} in the same subnet, so the device competes with itself and one of the two interfaces silently loses the election

**Remedy:** remove {…} from one of the two interfaces, or renumber one group

**Stays silent when:**

- Group 14 on two unrelated subnets is ordinary practice, not a defect.  
  `test_facts_rules.py::test_group_number_reused_on_another_subnet_is_not_a_duplicate`

### `fhrp-track-target-shutdown`

**high** · `cassandra.facts.rules.tracked_interface_is_shut_down`

A track whose target is administratively down.

The track is down for as long as the config stands, so the decrement is not a response to a failure — it is the steady state, and the group can never return to its configured priority.

**Reports:** tracked object {…} watches {…}, which is shut down

**Detail:** {…} is administratively down, so the track is down permanently and the {…}-point decrement applies at all times; {…} runs {…} at {…}, not {…}, and nothing short of a config change restores it

**Remedy:** bring {…} up, or point the track at the interface that is actually carrying the traffic

**Stays silent when:**

- Tracked interface that is up does not fire  
  `test_facts_rules.py::test_tracked_interface_that_is_up_does_not_fire`

### `fhrp-track-undefined`

**high** · `cassandra.facts.rules.tracked_object_unresolved`

A group that decrements its priority for a track nobody defined.

The intent is legible — the operator meant this group to step aside when something fails — and the configuration will not do it. Nothing complains, because a track that does not exist simply never fires, so the group holds its priority through exactly the failure the track was written for.

High severity for a rule about an absent line: this is failover that looks configured and is not.

**Reports:** tracked object {…} is referenced but never defined

**Detail:** the group references it, so the decrement is configured but can never fire — the failover it is meant to cause will not happen

**Remedy:** define {…} or remove the reference

**Stays silent when:**

- _No test asserts this rule staying quiet. Its silence is untested, so read it as an absence of evidence._

### `fhrp-virtual-collides`

**high** · `cassandra.facts.rules.virtual_address_collides`

A virtual address a real interface on the same pair already owns.

The virtual address is meant to be answered by whichever member is master. When one member also carries it as its own interface address, that member answers for it whether or not it holds the group, so failover moves the group without moving the traffic.

**Reports:** {…} {…} virtual address collides with a real interface address

**Detail:** {…} is also configured on {…}

**Remedy:** give the group a virtual address no device owns

**Stays silent when:**

- _No test asserts this rule staying quiet. Its silence is untested, so read it as an absence of evidence._

### `fhrp-virtual-not-a-host-address`

**high** · `cassandra.facts.rules.virtual_address_is_network_or_broadcast`

A virtual address that is not a host address at all.

Distinct from `fhrp-virtual-outside-subnet`: this address *is* inside the subnet, which is why that rule stays quiet, but no host may hold it.

**Reports:** {…} {…} virtual address is the {…} of its subnet

**Detail:** {…} is the {…} of {…}; hosts will not ARP for it as a gateway and stacks routinely refuse to configure it as a default route

**Remedy:** choose a host address inside {…}

**Stays silent when:**

- Host virtual address is not flagged  
  `test_facts_rules.py::test_host_virtual_address_is_not_flagged`

### `fhrp-virtual-outside-subnet`

**high** · `cassandra.facts.rules.virtual_address_outside_subnet`

A virtual address outside every subnet the member interface is on.

Hosts reach their gateway by ARPing for an address on their own subnet. One outside it is unreachable from the segment it is supposed to serve, and the group otherwise looks healthy: it elects, it advertises, and nothing uses it.

Silent when the interface has no address at all, since there is then no subnet to be outside of.

**Reports:** {…} {…} virtual address is outside its own subnet

**Detail:** {…} is not in {…}

**Remedy:** move the virtual address into the interface subnet

**Stays silent when:**

- Virtual address is network or broadcast  
  `test_facts_rules.py::test_virtual_address_is_network_or_broadcast`

### `fhrp-virtual-shared`

**high** · `cassandra.facts.rules.virtual_address_shared_by_two_groups`

Two groups on one interface answering for the same virtual address.

Each group derives its own virtual MAC from its group number, so one address resolves to two MACs and every host's ARP entry follows whichever advertised last.

**Reports:** two groups on {…} claim {…}

**Detail:** {…} and {…} are both configured with virtual address {…}; each has its own virtual MAC, so hosts resolve the gateway to whichever group advertised most recently

**Remedy:** give each group its own virtual address, or collapse them into one group

**Stays silent when:**

- Distinct virtual addresses are not shared  
  `test_facts_rules.py::test_distinct_virtual_addresses_are_not_shared`

### `mtu-mismatch`

**high** · `cassandra.facts.rules.mtu_mismatch_across_a_subnet`

Neighbours that disagree about how large a frame may be.

Only explicitly configured values are compared. An unset MTU is a platform default this tool does not claim to know, and guessing one would invent findings rather than report them.

**Reports:** MTU is not agreed across {…}

**Detail:** interfaces sharing this subnet are configured with {…} bytes; anything larger than {…} is dropped without an ICMP hint on a bridged path, and OSPF will not leave ExStart

**Remedy:** set one MTU for the subnet — {…} everywhere, or raise the smaller interface to match

**Stays silent when:**

- Matching mtu does not fire  
  `test_facts_rules.py::test_matching_mtu_does_not_fire`
- An unset MTU is a platform default the tool does not claim to know.  
  `test_facts_rules.py::test_one_configured_mtu_is_not_a_mismatch`

### `vlan-not-declared`

**high** · `cassandra.facts.rules.vlan_used_but_not_declared`

A port assigned to a VLAN the device never creates.

On most platforms the port stays down or blackholes rather than erroring, so the config reads as correct and the traffic goes nowhere. Only devices that declare VLANs at all are checked — a pure L3 router declares none and is not doing anything wrong.

**Reports:** {…} uses VLAN {…}, which {…} does not declare

**Detail:** the {…} references a VLAN that is not created on this device, so the port does not forward and the configuration still reads as correct

**Remedy:** add `vlan {…}` to {…}, or point the interface at a VLAN that exists

**Stays silent when:**

- Declared access vlan is silent  
  `test_facts_rules.py::test_declared_access_vlan_is_silent`
- A pure L3 device declares no VLANs and is doing nothing wrong.  
  `test_facts_rules.py::test_a_router_declaring_no_vlans_is_not_flagged`

### `bfd-no-clients`

**medium** · `cassandra.timing.timer_rules.bfd_session_has_no_clients`

A session nothing registered against comes up, runs, and is never asked.

`BfdTimers.clients` is populated by the builder from the protocols that reference the session. Empty means no protocol on this device asked BFD to tell it anything, so the detection time — however fast — reaches no decision.

**Reports:** BFD session on {…} has no registered client

**Detail:** the session is configured{…} but no protocol is registered against it, so nothing reacts when it goes down — the detection time buys nothing

**Remedy:** register a client (for example `ip ospf bfd` on the interface, or `neighbor <peer> bfd` under the BGP process), or remove the session

**Stays silent when:**

- An ospf client on the interface silences it  
  `test_timer_rules.py::test_an_ospf_client_on_the_interface_silences_it`
- BGP registers by peer address, not by interface name. A session the peer sits on top of has a client even though no interface line says so.  
  `test_timer_rules.py::test_a_bgp_peer_in_the_subnet_counts_as_a_client`

### `bfd-no-faster-than-igp`

**medium** · `cassandra.timing.timer_rules.bfd_detects_no_sooner_than_the_igp`

BFD exists to detect faster than the IGP. One that does not is decoration.

The cost is not neutral. The session is configured, monitored and believed, and every design decision downstream of it assumes sub-second detection that the numbers say cannot happen.

**Reports:** BFD detection ({…}) is no faster than the {…} dead interval ({…})

**Detail:** {…}ms x {…} = {…}, and the adjacency drops on its own after {…}. The session accelerates nothing, so the fast failure detection the config implies does not exist.

**Remedy:** lower the BFD interval or multiplier so detection is well under {…}, or drop the session and rely on the IGP

**Stays silent when:**

- Silence over a guess: without a configured dead interval there is no second number, and inventing one would fabricate the finding.  
  `test_timer_rules.py::test_no_igp_on_the_interface_means_nothing_to_compare_against`

### `bgp-peer-off-subnet`

**medium** · `cassandra.facts.rules.bgp_peer_on_no_local_subnet`

A directly-connected peer address that is on none of this device's subnets.

Skipped when the peering is explicitly not directly connected — an update-source or ebgp-multihop says the operator meant it.

**Reports:** BGP peer {…} is not on any subnet {…} has

**Detail:** the peering is neither multihop nor sourced from a loopback, so it is meant to be directly connected — and the address is not reachable on any interface here

**Remedy:** correct the peer address, or add update-source / ebgp-multihop if the peering really is not direct

**Stays silent when:**

- update-source or ebgp-multihop says the operator meant it.  
  `test_facts_rules.py::test_multihop_peer_off_subnet_is_intentional`

### `fhrp-no-redundancy`

**medium** · `cassandra.facts.rules.group_has_no_redundancy`

A redundancy group with fewer than two members in the collection.

Either the peer's configuration is not in the directory — in which case the finding is telling you the analysis is incomplete, which is worth knowing — or the group really is configured on one device, and the virtual address is a second name for a single point of failure.

**Reports:** {…} {…} has only {…} member

**Detail:** a redundancy group with one member provides no redundancy

**Remedy:** configure the group on the peer device, or remove it

**Stays silent when:**

- _No test asserts this rule staying quiet. Its silence is untested, so read it as an absence of evidence._

### `fhrp-priority-tie`

**medium** · `cassandra.facts.rules.priority_tie`

Members sharing the top priority, so nothing decides the master.

The protocols break the tie on address comparison, which is deterministic but not chosen: the master is whichever device happens to have the higher interface address. That holds until a reboot changes who advertises first, and then the placement people have been assuming quietly stops being true.

**Reports:** {…} {…} has no preferred master

**Detail:** {…} members share priority {…}, so the master is decided by address comparison and can change on reboot

**Remedy:** give the intended master a higher priority

**Stays silent when:**

- _No test asserts this rule staying quiet. Its silence is untested, so read it as an absence of evidence._

### `fhrp-track-ineffective`

**medium** · `cassandra.facts.rules.tracking_cannot_change_the_outcome`

A decrement too small to lose the election is tracking that does nothing.

This is the quiet one: the config looks correct, the intent is visible, and the failover silently never happens.

**Reports:** {…} {…} tracking can never cause a failover

**Detail:** priority {…} minus the total decrement {…} is {…}, still above the highest peer priority {…}

**Remedy:** increase the decrement past {…}

**Stays silent when:**

- Sufficient decrement does not fire  
  `test_facts_rules.py::test_sufficient_decrement_does_not_fire`

### `svi-vlan-not-trunked`

**medium** · `cassandra.facts.rules.svi_vlan_missing_from_every_trunk`

An addressed SVI for a VLAN no trunk on the device carries.

The interface is up and has an address, so the device can route for the VLAN; nothing can reach it, because the VLAN leaves on no uplink. It is the shape a VLAN takes after it is removed from a trunk's allowed list during some unrelated cleanup and the SVI is left behind.

Only checked on devices that have at least one trunk. A device with none is not carrying VLANs anywhere, which is a different thing entirely.

**Reports:** {…} has no trunk carrying VLAN {…}

**Detail:** the interface is up and addressed but the VLAN reaches no neighbour, so anything relying on it is isolated

**Remedy:** add VLAN {…} to the relevant trunk

**Stays silent when:**

- _No test asserts this rule staying quiet. Its silence is untested, so read it as an absence of evidence._

### `fhrp-no-preempt-on-preferred`

**low** · `cassandra.facts.rules.preferred_master_will_not_reclaim`

The highest-priority member has preempt off, so it never takes back.

After the first failover the group stays on the backup for good. That is a legitimate choice — it avoids a second interruption to move back — but it means the priorities in the configuration no longer describe where traffic is, and the next person to read them will be wrong about the current state.

Low severity because it is a defensible configuration. It is reported so the choice is visible rather than assumed.

**Reports:** {…} {…} will not return to its preferred master

**Detail:** {…} has the highest priority ({…}) but preempt is off, so after any failover the group stays on the backup indefinitely

**Remedy:** enable preempt, or accept the placement is not deterministic

**Stays silent when:**

- _No test asserts this rule staying quiet. Its silence is untested, so read it as an absence of evidence._

### `trunk-vlan-dead`

**low** · `cassandra.facts.rules.trunk_carries_a_vlan_nothing_terminates`

A VLAN permitted on a trunk that no device in the topology terminates.

Terminating means an SVI or an access port somewhere in the corpus. A VLAN with neither is carried, learned and flooded for nothing — usually the residue of a service that was decommissioned at the edges and left on the trunks.

**Reports:** {…} trunks VLAN {…}, which nothing terminates

**Detail:** no device in these configs has an SVI or an access port in VLAN {…}, so the trunk carries broadcast and MAC-learning load for a broadcast domain with no members

**Remedy:** remove VLAN {…} from the trunk, or add the access ports and SVIs that were meant to use it

**Stays silent when:**

- Trunk vlan with an access port somewhere is alive  
  `test_facts_rules.py::test_trunk_vlan_with_an_access_port_somewhere_is_alive`
- Trunk vlan with an svi somewhere is alive  
  `test_facts_rules.py::test_trunk_vlan_with_an_svi_somewhere_is_alive`

### `l3-interface-isolated`

**info** · `cassandra.facts.rules.isolated_l3_interface`

An addressed interface on a subnet no other device shares.

INFO, not a defect: a subnet whose other end is a server, a firewall, or a device outside the directory looks exactly like this. It is reported because the alternative — a typo in one octet that quietly split a working subnet in two — looks exactly like this too, and only the operator can tell them apart.

**Reports:** {…} is the only interface on {…}

**Detail:** no other device in these configs is addressed in this subnet, so nothing here can be an IGP, BFD or FHRP peer of it

**Remedy:** confirm the far end is outside these configs; if it is not, check the address for a wrong octet or prefix length

**Stays silent when:**

- Shared subnet is not isolated  
  `test_facts_rules.py::test_shared_subnet_is_not_isolated`
- A /30 or /31 whose far end is not in the directory is the normal case.  
  `test_facts_rules.py::test_point_to_point_link_off_the_corpus_is_not_isolated`
- Configs from a second site in the same directory share nothing with the first. Reporting every one of their interfaces says nothing about any of them.  
  `test_facts_rules.py::test_a_device_sharing_no_subnet_at_all_is_not_reported_interface_by_interface`
- Loopback is not isolated  
  `test_facts_rules.py::test_loopback_is_not_isolated`

## TIMING tier

Derived from the discrete-event timer model (PROJECT.md §2.2). These are candidates: they say a sequence your configs permit produces the behaviour, and they carry that sequence so a human can judge it.

### `fhrp-divergence`

**high** · `cassandra.timing.sequences._divergence`

Two FHRP groups on the same device pair that stop agreeing who is master.

Both groups see one event. They answer it at different speeds — a different tracking decrement, a preempt delay on one and not the other — and for the stretch between their two answers, traffic for one VLAN leaves through one device and traffic for the next VLAN leaves through the other. Everything that assumes a single default gateway per site (a stateful firewall, a NAT table, an asymmetric-path check) breaks for exactly that window and then heals, which is what makes it so hard to catch after the fact.

Reported only past MIN_DIVERGENCE_MS. A brief divergence *during* an event is expected behaviour; one that persists long after recovery is the defect.

**Reports:** {…} and {…} can end up on different devices

**Detail:** they share a device pair but respond to the same event differently, leaving the gateways split for about {…}s

**Remedy:** make tracking and preempt delay consistent across groups on the same pair

**Stays silent when:**

- Both groups track the same interface with the same delay, so they move together. A model that flags this is crying wolf.  
  `test_timing.py::test_symmetric_groups_produce_no_divergence`
- Not a finding, and the distinction matters. With group 14 tracking and group 24 not, the two split the moment the uplink drops — but group 14 has no preempt delay, so it reclaims the instant the link returns and the split ends with the outage. A brief divergence *during* an event is expected behaviour; a divergence that persists long after recovery is the defect. The threshold is what separates them, and reporting the first kind would bury the second in noise.  
  `test_timing.py::test_tracking_asymmetry_alone_diverges_only_while_the_link_is_down`

### `fhrp-oscillation`

**medium** · `cassandra.timing.sequences._oscillation`

A group that changes master repeatedly while one interface flaps.

A group with preempt and no preempt delay follows its tracked interface exactly: every flap hands mastership back and forth. Each handover is a short forwarding interruption for every host using that gateway, so a link that flaps five times does not cost one outage, it costs five — and the configuration looks correct at rest, because at rest it is.

Reported past MIN_TRANSITIONS, which is high enough that the one handover a genuine failure causes does not count as chasing.

**Reports:** {…} changes master {…} times under a single flap sequence

**Detail:** each transition is a forwarding interruption for everything using that gateway

**Remedy:** add a preempt delay so the group does not chase a flapping interface

**Stays silent when:**

- _No test asserts this rule staying quiet. Its silence is untested, so read it as an absence of evidence._

## Silence across a whole rule set

These tests assert that a rule set reports nothing at all on a given input. They constrain every rule in the module rather than one of them, which is what makes a clean run mean something.

- **`cassandra.facts.rules`** — Clean pair produces nothing  
  `test_facts_rules.py::test_clean_pair_produces_nothing`
- **`cassandra.facts.rules`** — The shipped corpus is well-formed apart from its timing asymmetry, which is the TIMING tier's job. If a FACTS rule fires here it is a false positive.  
  `test_facts_rules.py::test_real_corpus_produces_nothing`
- **`cassandra.facts.rules`** — Reciprocated bgp session is silent  
  `test_facts_rules.py::test_reciprocated_bgp_session_is_silent`
- **`cassandra.timing.timer_rules`** — Fast bfd alongside the same igp is silent  
  `test_timer_rules.py::test_fast_bfd_alongside_the_same_igp_is_silent`
- **`cassandra.timing.timer_rules`** — Dampening inside the sla is silent  
  `test_timer_rules.py::test_dampening_inside_the_sla_is_silent`
- **`cassandra.timing.timer_rules`** — The sla is the users number  
  `test_timer_rules.py::test_the_sla_is_the_users_number`
- **`cassandra.timing.timer_rules`** — A profile without a max suppress is not guessed at  
  `test_timer_rules.py::test_a_profile_without_a_max_suppress_is_not_guessed_at`
- **`cassandra.timing.timer_rules`** — The strongest silence test available: real configs, no invented timers.  
  `test_timer_rules.py::test_silent_on_a_corpus_with_no_bfd_and_no_dampening`
- **`cassandra.timing.sequences`** — With nothing tracked, no link event can change an election, so the tier has no candidate sequences and must stay silent rather than invent one.  
  `test_timing.py::test_no_tracking_anywhere_means_nothing_to_simulate`
