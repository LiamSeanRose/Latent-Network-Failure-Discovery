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
| [`access-vlan-not-trunked`](#access-vlan-not-trunked) | facts | high | An access port in a VLAN that cannot leave the switch it is on. |
| [`bfd-multiplier-of-one`](#bfd-multiplier-of-one) | facts | high | A detect multiplier of 1 makes one lost packet a routing event. |
| [`bgp-peer-behind-shutdown`](#bgp-peer-behind-shutdown) | facts | high | A peering that can only run over an interface that is shut down. |
| [`bgp-remote-as-mismatch`](#bgp-remote-as-mismatch) | facts | high | One end expects an AS the other does not use. |
| [`bgp-router-id-duplicate`](#bgp-router-id-duplicate) | facts | high | One BGP router-id claimed by two devices. |
| [`bgp-session-one-sided`](#bgp-session-one-sided) | facts | high | A peering only one end knows about. |
| [`dampening-exceeds-sla`](#dampening-exceeds-sla) | facts | high | Max-suppress bounds how long a prefix stays withdrawn after the fault ends. |
| [`device-isolated-by-shutdown`](#device-isolated-by-shutdown) | facts | high | A device whose every link into these configs is administratively down. |
| [`duplicate-address`](#duplicate-address) | facts | high | One address configured on two interfaces in the collection. |
| [`fhrp-duplicate-member`](#fhrp-duplicate-member) | facts | high | One device holding two memberships of the same group on one subnet. |
| [`fhrp-hold-under-peer-hello`](#fhrp-hold-under-peer-hello) | facts | high | A member that gives up before its peer is next due to speak is not a standby, it is a second active gateway. |
| [`fhrp-members-on-different-subnets`](#fhrp-members-on-different-subnets) | facts | high | A redundancy group whose two halves are not on the same subnet. |
| [`fhrp-track-target-shutdown`](#fhrp-track-target-shutdown) | facts | high | A track whose target is administratively down. |
| [`fhrp-track-undefined`](#fhrp-track-undefined) | facts | high | A group that decrements its priority for a track nobody defined. |
| [`fhrp-virtual-collides`](#fhrp-virtual-collides) | facts | high | A virtual address a real interface on the same pair already owns. |
| [`fhrp-virtual-not-a-host-address`](#fhrp-virtual-not-a-host-address) | facts | high | A virtual address that is not a host address at all. |
| [`fhrp-virtual-not-an-address`](#fhrp-virtual-not-an-address) | facts | high | A virtual address that is not an IP address at all. |
| [`fhrp-virtual-outside-subnet`](#fhrp-virtual-outside-subnet) | facts | high | A virtual address outside every subnet the member interface is on. |
| [`fhrp-virtual-shared`](#fhrp-virtual-shared) | facts | high | Two groups on one interface answering for the same virtual address. |
| [`mtu-mismatch`](#mtu-mismatch) | facts | high | Neighbours that disagree about how large a frame may be. |
| [`ospf-timers-disagree`](#ospf-timers-disagree) | facts | high | OSPF refuses an adjacency whose hello and dead intervals do not match. |
| [`subnet-mask-disagreement`](#subnet-mask-disagreement) | facts | high | Two devices on one wire that disagree about how wide the wire is. |
| [`vlan-not-declared`](#vlan-not-declared) | facts | high | A port assigned to a VLAN the device never creates. |
| [`bfd-detection-below-floor`](#bfd-detection-below-floor) | facts | medium | A BFD session too fast to survive a control-plane pause takes the IGP down. |
| [`bfd-no-clients`](#bfd-no-clients) | facts | medium | A session nothing registered against comes up, runs, and is never asked. |
| [`bfd-no-faster-than-igp`](#bfd-no-faster-than-igp) | facts | medium | BFD exists to detect faster than the IGP. One that does not is decoration. |
| [`bgp-peer-off-subnet`](#bgp-peer-off-subnet) | facts | medium | A directly-connected peer address that is on none of this device's subnets. |
| [`dampening-never-suppresses`](#dampening-never-suppresses) | facts | medium | A dampening profile whose suppress threshold is above its own penalty ceiling never suppresses anything. |
| [`fhrp-hold-under-three-hellos`](#fhrp-hold-under-three-hellos) | facts | medium | An FHRP hold time worth fewer than three hellos fails the gateway over on one lost advertisement. |
| [`fhrp-no-redundancy`](#fhrp-no-redundancy) | facts | medium | A redundancy group with fewer than two members in the collection. |
| [`fhrp-priority-tie`](#fhrp-priority-tie) | facts | medium | Members sharing the top priority, so nothing decides the master. |
| [`fhrp-track-ineffective`](#fhrp-track-ineffective) | facts | medium | A decrement too small to lose the election is tracking that does nothing. |
| [`igp-dead-under-three-hellos`](#igp-dead-under-three-hellos) | facts | medium | A dead interval worth fewer than three hellos drops healthy adjacencies. |
| [`svi-vlan-not-trunked`](#svi-vlan-not-trunked) | facts | medium | An addressed SVI for a VLAN no trunk on the device carries. |
| [`trunk-native-vlan-not-allowed`](#trunk-native-vlan-not-allowed) | facts | medium | A trunk whose native VLAN is missing from its own allowed list. |
| [`fhrp-no-preempt-on-preferred`](#fhrp-no-preempt-on-preferred) | facts | low | The highest-priority member has preempt off, so it never takes back. |
| [`igp-dead-not-a-multiple-of-hello`](#igp-dead-not-a-multiple-of-hello) | facts | low | A dead interval that is not a whole number of hellos wastes its remainder. |
| [`trunk-vlan-dead`](#trunk-vlan-dead) | facts | low | A VLAN permitted on a trunk that no device in the topology terminates. |
| [`l3-interface-isolated`](#l3-interface-isolated) | facts | info | An addressed interface on a subnet no other device shares. |
| [`fhrp-divergence`](#fhrp-divergence) | timing | high | Two FHRP groups on the same device pair that stop agreeing who is master. |
| [`fhrp-oscillation`](#fhrp-oscillation) | timing | medium | A group that changes master repeatedly while one interface flaps. |

## FACTS tier

Decidable from the configuration text alone (PROJECT.md §2.1). A finding here is either true of the text or a bug in the rule — no model stands between the config and the claim.

### `access-vlan-not-trunked`

**high** · `cassandra.facts.rules.access_vlan_leaves_on_no_trunk`

An access port in a VLAN that cannot leave the switch it is on.

The port's VLAN is used elsewhere — another device has an SVI or an access port in it — but on this device no trunk permits it and no SVI terminates it. Whatever is plugged in comes up, learns MAC addresses from nothing, and reaches neither its gateway nor any other member of the VLAN. The usual cause is a port moved into a service VLAN that the uplink's allowed list was never extended to carry.

Silent when a trunk on the device permits the VLAN, when the device has an SVI for it, and when the device has no trunk at all — a standalone switch is not failing to forward anywhere. Silent, too, when the VLAN appears nowhere else in the collection: unused ports parked in a spare VLAN look exactly like this and are deliberate.

**Reports:** {…} is in VLAN {…}, which leaves {…} on no trunk

**Detail:** VLAN {…} is terminated on {…}, but no trunk on {…} permits it and there is no SVI for it here, so anything on {…} is confined to this switch and has no route to its gateway

**Remedy:** add VLAN {…} to the trunk that carries this switch's uplink, or move the port to a VLAN the uplink already carries

**Stays silent when:**

- A VLAN the trunk permits leaves the switch, which is the whole of what the rule asks: the port is in a live broadcast domain and reaches its gateway.  
  `test_facts_rules.py::test_access_vlan_the_uplink_carries_is_silent`
- Spare ports parked in a VLAN nothing else terminates are deliberate, and indistinguishable from this rule's defect except by that fact.  
  `test_facts_rules.py::test_a_vlan_used_nowhere_else_is_a_parking_vlan_not_a_defect`

### `bfd-multiplier-of-one`

**high** · `cassandra.timing.timer_rules.bfd_multiplier_leaves_no_margin`

A detect multiplier of 1 makes one lost packet a routing event.

The multiplier is the whole tolerance a BFD session has: it is how many control packets may go missing before the neighbour is declared down. At 1 there is none. A single frame lost to a CRC error, a microburst drop or a queue overrun tears down the session and every client protocol registered against it, and does it again the next time — which on a link with any loss at all is a permanently flapping adjacency whose interface counters look clean.

Silent when no multiplier is configured, since the platform default is not a number this tool invents.

**Reports:** BFD on {…} has a detect multiplier of 1

**Detail:** control packets are sent{…} and exactly one may not arrive before the session is declared down, so a single dropped frame is a routing event. Packet loss that would otherwise be invisible becomes a reconvergence, repeatedly.

**Remedy:** set the detect multiplier to 3, the value every platform defaults to, and shorten the interval instead if the detection time has to stay where it is

**Stays silent when:**

- The rule is about the absence of tolerance, not about how thin it is. A multiplier of two is aggressive, and it still survives the single lost packet that a multiplier of one turns into a reconvergence.  
  `test_timer_rules.py::test_a_multiplier_of_two_still_has_a_margin`
- The site-14 configs are a working network apart from one preempt delay: the VRRP groups advertise every second and agree with each other, no interface carries BFD or per-interface OSPF timers, and no BGP process dampens anything. Every rule here is measuring something that corpus does correctly, so a finding on it would be a false positive rather than a discovery.  
  `test_timer_rules.py::test_the_shipped_corpus_trips_none_of_these_rules`

### `bgp-peer-behind-shutdown`

**high** · `cassandra.facts.rules.bgp_peer_behind_a_shutdown_interface`

A peering that can only run over an interface that is shut down.

Two shapes, one consequence. The peer address is on a subnet this device reaches through shut interfaces only, or the session's update source is itself shut. Either way the session cannot open, and the configuration reads as a healthy peering — the neighbour statement is present, the remote AS is right, and there is no `shutdown` under the BGP process to explain it.

Silent when the neighbour is explicitly shut, which says the operator meant it, and when any interface carrying the peer's subnet is up. Silent when the peer address is on no local subnet at all: an update source, a multihop session or a plain typo are somebody else's finding.

**Reports:** BGP peer {…} is only reachable over an interface that is shut down

**Detail:** every interface on this device addressed in the peer's subnet is administratively down, so the TCP session cannot be established and the peering stays in Idle or Active

**Remedy:** bring the interface up, or move the peering to one that is carrying traffic

**Stays silent when:**

- The interface carrying the peer's subnet is up, so nothing about the peering is prevented by administrative state and the rule has no claim.  
  `test_facts_rules.py::test_bgp_peer_over_a_live_interface_is_silent`
- `neighbor ... shutdown` says the operator meant the session to be down, so the interface underneath it being down as well is not news.  
  `test_facts_rules.py::test_a_deliberately_shut_neighbour_is_not_a_broken_peering`

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

### `bgp-router-id-duplicate`

**high** · `cassandra.facts.rules.bgp_router_id_duplicated`

One BGP router-id claimed by two devices.

The router-id is the BGP identifier in the OPEN message and the tie-breaker in best-path selection, and it has to be unique. Two devices sharing one cannot peer with each other at all — the OPEN is rejected as a collision — and where they peer with a common neighbour instead, that neighbour treats the second session as a duplicate of the first and the two routers take turns holding it.

Silent for a device that states no router-id, since the platform then derives one from an interface address this tool cannot predict, and silent where one device declares the same id twice, which is one router, not two.

**Reports:** BGP router-id {…} is claimed by {…}

**Detail:** the router-id is the BGP identifier and has to be unique; two devices carrying the same one cannot peer with each other, and a common neighbour sees the second session as a duplicate of the first

**Remedy:** give each device its own router-id, conventionally its loopback address

**Stays silent when:**

- Two devices with router-ids of their own collide over nothing; the rule is about the identifier being shared, not about it being configured.  
  `test_facts_rules.py::test_distinct_router_ids_are_silent`

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
- A peer address is checked against the subnets the device is addressed in. With IPv6 addressing unread those subnets did not exist, so every IPv6 peering in every config looked like a peer on no local subnet — a defect reported wholesale about configurations that were correct.  
  `test_ipv6.py::test_an_ipv6_bgp_peer_is_found_on_its_own_subnet`
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

- Dampening is not itself a defect — a prefix that flaps hard should be held down. What is reported is a hold-down longer than the outage the site has committed to, and a max-suppress under that limit is the feature working.  
  `test_timer_rules.py::test_a_bounded_suppression_window_inside_the_sla`
- A window equal to the commitment is inside it. The finding claims the prefix stays withdrawn for longer than the SLA allows, and at the boundary that claim is not yet true.  
  `test_timer_rules.py::test_a_suppression_window_landing_exactly_on_the_sla`
- The threshold is the operator's number, not the tool's. The same hour-long max-suppress that breaks a five-minute commitment is a deliberate, documented hold-down on a site that allows two hours.  
  `test_timer_rules.py::test_an_hour_long_window_a_looser_sla_permits`

### `device-isolated-by-shutdown`

**high** · `cassandra.facts.rules.device_reachable_only_through_shutdown_interfaces`

A device whose every link into these configs is administratively down.

The device is addressed in a subnet another device also uses, and every one of its own interfaces in such a subnet is shut. Nothing here can be an IGP, BGP, BFD or FHRP neighbour of it, so it is off the network while its configuration still reads as a fully connected device — the shape a box takes after a maintenance shutdown nobody undid.

Reads the derived L3 adjacency graph, which already omits shut interfaces, and then asks whether re-admitting them would connect the device. Silent for a device that has a live neighbour, for a device that shares no subnet with anything in the pack — a peer outside the corpus is an incomplete collection rather than a defect — and for a pure layer-2 switch, which has no addresses to share in the first place.

**Reports:** every interface joining {…} to these configs is shut down

**Detail:** {…} is addressed in {…}, which other devices here also use, but each of its own interfaces in those subnets is administratively down; no neighbour in this collection can reach it and none of its adjacencies can come up

**Remedy:** bring one of those interfaces up, or take the device out of the collection if it is genuinely decommissioned

**Stays silent when:**

- The rule is about a device with no way in at all, not about any shut interface: a second subnet that is up still carries every adjacency.  
  `test_facts_rules.py::test_one_shut_interface_beside_a_live_one_does_not_isolate_a_device`
- A device with no addresses shares no subnet with anything, so there is no adjacency for a shutdown to have taken away.  
  `test_facts_rules.py::test_a_layer_two_switch_is_not_isolated`

### `duplicate-address`

**high** · `cassandra.facts.rules.duplicate_addresses`

One address configured on two interfaces in the collection.

Whichever device answers first wins, and which one that is depends on ARP timing rather than on anything written down. The usual cause is a config copied between devices and edited everywhere except the address, so the duplicate is often on the device that was working yesterday.

Compares addresses, not prefixes: the same address with two different masks is still one address two devices claim. Compares them as addresses rather than as text, because IPv6 has many spellings of one address and two configs that wrote `2001:db8::1` and `2001:0DB8:0:0:0:0:0:1` have made exactly this mistake.

Scoped per VRF, like every other subnet-shaped rule in this module. Two VRFs reusing an address is the reason VRFs exist, and the mechanism this rule describes — whoever answers ARP first wins — cannot happen between segments that never see each other's ARP.

**Reports:** {…} is configured twice

**Detail:** also on {…}

**Remedy:** renumber one of them

**Stays silent when:**

- Both members of a group name the same virtual address — that is what makes them one group. Only an address configured on an interface is claimed by a device, so a virtual address repeated across the pair is not a duplicate.  
  `test_facts_rules.py::test_a_virtual_address_written_on_both_members`
- Two VRFs are two separate address spaces, so the same address in each is a deliberate design rather than a collision. Nothing on either segment ever sees the other's ARP, which is the mechanism the rule is written about.  
  `test_facts_rules.py::test_the_same_address_in_two_vrfs_on_one_device`
- An interface's IPv4 address and its IPv6 address are two addresses on one interface. A rule that indexed them together, or compared them as text without knowing which family they belonged to, would report the pair as two devices contending for one address.  
  `test_ipv6.py::test_two_families_on_one_interface_are_not_one_address_claimed_twice`

### `fhrp-duplicate-member`

**high** · `cassandra.facts.rules.duplicate_group_member`

One device holding two memberships of the same group on one subnet.

Group numbers are legitimately reused across unrelated subnets — group 1 on every SVI is ordinary practice — so the subnet is what makes this decidable, and the subnet is read in the group's own address family: a dual-stack pair of interfaces shares an IPv4 subnet and an IPv6 one, and an IPv6 group's two memberships are only in contention if they share the IPv6 one. Two memberships of one group in one subnet on one device means the device contends with itself: it sends advertisements from two interfaces, and which of them holds the virtual address is not something the config decides.

**Reports:** {…} is a member of {…} twice on {…}

**Detail:** {…} and {…} both run {…} in the same subnet, so the device competes with itself and one of the two interfaces silently loses the election

**Remedy:** remove {…} from one of the two interfaces, or renumber one group

**Stays silent when:**

- Group 14 on two unrelated subnets is ordinary practice, not a defect.  
  `test_facts_rules.py::test_group_number_reused_on_another_subnet_is_not_a_duplicate`
- The IPv4 and IPv6 halves of one group number hold different virtual addresses on the same interfaces. Read without their families they are two groups claiming one interface — a device contending with itself, and two groups answering for one address.  
  `test_ipv6.py::test_the_two_families_of_one_group_do_not_collide_or_share`

### `fhrp-hold-under-peer-hello`

**high** · `cassandra.timing.timer_rules.fhrp_hold_time_is_shorter_than_a_peer_hello`

A member that gives up before its peer is next due to speak is not a standby, it is a second active gateway.

FHRP timers have to match across a group, and the way a mismatch bites is arithmetical: if one member's hold time is no longer than another member's advertisement interval, the on-time advertisement arrives after the timer it was meant to reset has already expired. The member takes the virtual address while the peer still holds it, both answer for the same IP and MAC, and the segment gets duplicate replies until something flaps. Each device on its own is configured with a hold longer than its own hello, so the defect is invisible one config at a time.

Silent when only one member of the group is in the collection, and silent for timers that merely differ — mismatched values whose arithmetic still works are untidy, not broken.

**Reports:** {…}: {…} holds for {…} while {…} advertises every {…}

**Detail:** {…} declares the group's active gone after {…}, which is no later than {…}'s next advertisement is due. When {…} is holding the group, every advertisement it sends arrives after {…} has already timed it out, so both answer for {…} at once.

**Remedy:** configure the same hello and hold time on every member of {…}

**Stays silent when:**

- Members of one group ought to share their timers, and untidy is not the same as broken. A hold of 4s against a peer advertising every 3s still resets on every advertisement that arrives on time, so no member ever declares a live gateway dead.  
  `test_timer_rules.py::test_mismatched_timers_whose_arithmetic_still_works_are_silent`
- A hold time is only short relative to somebody else's hello. With one member of the group in the collection the comparison has no second term, and the missing device is a gap in the capture rather than evidence about it.  
  `test_timer_rules.py::test_one_member_of_a_group_says_nothing_about_its_peer`
- The site-14 configs are a working network apart from one preempt delay: the VRRP groups advertise every second and agree with each other, no interface carries BFD or per-interface OSPF timers, and no BGP process dampens anything. Every rule here is measuring something that corpus does correctly, so a finding on it would be a false positive rather than a discovery.  
  `test_timer_rules.py::test_the_shipped_corpus_trips_none_of_these_rules`

### `fhrp-members-on-different-subnets`

**high** · `cassandra.facts.rules.fhrp_members_addressed_on_different_subnets`

A redundancy group whose two halves are not on the same subnet.

Two devices run the same protocol, the same group number and the same virtual address, which is as explicit as intent gets — and their interfaces are addressed in different subnets, so the Fact Pack holds them as two separate one-member groups rather than one pair. Each device is master of its own group, neither backs the other up, and the failover the numbers describe does not exist. A wrong octet or a wrong mask on one side produces exactly this, and both configurations look correct read on their own.

Requires the group number *and* the virtual address to match, so reusing group 1 on every SVI — ordinary practice — stays silent. Silent, too, when the members share a subnet, which is the case where the group really is one group, and across address families: a group's IPv4 half being on 10.14.0.0/24 while its IPv6 half is on 2001:db8:14::/64 is what a dual-stack segment looks like, not a split.

**Reports:** {…} is split across {…}

**Detail:** {…} all run {…} with virtual address {…}, but their interfaces are addressed in different subnets, so they are not members of one group: each is master of its own and none of them backs up any other

**Remedy:** put every member of {…} in one subnet, or give the groups that are genuinely separate their own numbers and virtual addresses

**Stays silent when:**

- Group 14 reused on an unrelated subnet with its own virtual address is ordinary practice: the intent to pair two devices is what the matching virtual address establishes, and it is absent here.  
  `test_facts_rules.py::test_one_group_number_on_two_subnets_with_its_own_address_each`
- The IPv4 half of a group is on 10.14.0.0/24 and the IPv6 half on 2001:db8:14::/64. That is what one dual-stack segment looks like, not two devices that were meant to be in one subnet and are not.  
  `test_ipv6.py::test_a_group_spanning_two_families_is_not_a_group_split_in_two`

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

- A tracked object is resolved wherever in the file it is written, so a definition that precedes the group referencing it is as good as one that follows. Only a name nothing defines anywhere is a dangling reference.  
  `test_facts_rules.py::test_a_track_defined_above_the_group_that_references_it`
- Tracked objects are device-local: each member resolves the definition in its own configuration. A pair that both use the name UPLINK for their own uplink is the normal way a symmetric pair is written, not one device borrowing the other's track.  
  `test_facts_rules.py::test_both_devices_defining_their_own_copy_of_a_track_name`

### `fhrp-virtual-collides`

**high** · `cassandra.facts.rules.virtual_address_collides`

A virtual address a real interface on the same pair already owns.

The virtual address is meant to be answered by whichever member is master. When one member also carries it as its own interface address, that member answers for it whether or not it holds the group, so failover moves the group without moving the traffic.

**Reports:** {…} virtual address collides with a real interface address

**Detail:** {…} is also configured on {…}

**Remedy:** give the group a virtual address no device owns

**Stays silent when:**

- Every member of a group is configured with the identical virtual address; a group whose members disagreed about it would not be a group. The collision is a member owning that address as its own interface address, which is a different line entirely.  
  `test_facts_rules.py::test_both_members_advertising_the_same_virtual_address`
- A member interface may carry several real addresses on the segment it serves. Sharing the subnet with the virtual address is the requirement, not the defect — only an interface configured with the virtual address itself answers for it while it is backup.  
  `test_facts_rules.py::test_a_virtual_address_beside_a_secondary_on_the_same_subnet`
- The IPv4 and IPv6 halves of one group number hold different virtual addresses on the same interfaces. Read without their families they are two groups claiming one interface — a device contending with itself, and two groups answering for one address.  
  `test_ipv6.py::test_the_two_families_of_one_group_do_not_collide_or_share`

### `fhrp-virtual-not-a-host-address`

**high** · `cassandra.facts.rules.virtual_address_is_network_or_broadcast`

A virtual address that is not a host address at all.

Distinct from `fhrp-virtual-outside-subnet`: this address *is* inside the subnet, which is why that rule stays quiet, but no host may hold it.

**Reports:** {…} virtual address is the {…} of its subnet

**Detail:** {…} is the {…} of {…}; hosts will not ARP for it as a gateway and stacks routinely refuse to configure it as a default route

**Remedy:** choose a host address inside {…}

**Stays silent when:**

- Host virtual address is not flagged  
  `test_facts_rules.py::test_host_virtual_address_is_not_flagged`
- IPv6 has no broadcast address. The last address of a prefix is a host address like any other, and a gateway numbered there is fine; applying IPv4's broadcast rule to it would condemn a working configuration.  
  `test_ipv6.py::test_the_last_address_of_an_ipv6_prefix_is_an_ordinary_host_address`

### `fhrp-virtual-not-an-address`

**high** · `cassandra.facts.rules.virtual_address_is_not_an_address`

A virtual address that is not an IP address at all.

A mistyped octet — `10.14.0.300` — is the commonest malformation a config has, and the parsers accept whatever token follows the keyword rather than guessing at what was meant. Every other rule about the virtual address skips a group it cannot read, so without this one the group would be checked by nothing and reported as healthy.

**Reports:** {…} virtual address is not an address

**Detail:** {…} does not name an IP address, so the group has no gateway to answer for and every other check on it was skipped

**Remedy:** correct the address

**Stays silent when:**

- The rule exists for a string that names no address, not for one that names an address someone dislikes.  
  `test_facts_rules.py::test_a_readable_virtual_address_is_not_reported_as_unreadable`
- Every rule about a virtual address skips a group whose address it cannot read, and `fhrp-virtual-not-an-address` is what stops that being silent. It has to look in the field the group's own family uses — reading `virtual_ipv4` on an IPv6 group finds nothing there and reports a healthy group as broken, or skips it entirely.  
  `test_ipv6.py::test_an_ipv6_virtual_address_is_read_as_an_address`

### `fhrp-virtual-outside-subnet`

**high** · `cassandra.facts.rules.virtual_address_outside_subnet`

A virtual address outside every subnet the member interface is on.

Hosts reach their gateway by ARPing for an address on their own subnet. One outside it is unreachable from the segment it is supposed to serve, and the group otherwise looks healthy: it elects, it advertises, and nothing uses it.

Silent when the interface has no address at all, since there is then no subnet to be outside of, and silent when it has no address in the group's own family: an IPv6 group on an interface that is only numbered for IPv4 is missing an address, not holding one in the wrong place, and comparing its virtual address against the IPv4 subnet would report every dual-stack group on a half-numbered interface.

Silent, too, for an IPv6 virtual address in fe80::/10. RFC 5798 makes the link-local address a VRRPv3 group's primary virtual address precisely because every interface on the segment already has one, so there is no subnet for it to be outside of.

**Reports:** {…} virtual address is outside its own subnet

**Detail:** {…} is not in {…}

**Remedy:** move the virtual address into the interface subnet

**Stays silent when:**

- Virtual address is network or broadcast  
  `test_facts_rules.py::test_virtual_address_is_network_or_broadcast`
- A dual-stack interface is on two subnets, and a virtual address can only be inside one of them. Judged against both, every group on every dual-stack interface in the world is outside a subnet it was never meant to be in.  
  `test_ipv6.py::test_an_ipv4_virtual_address_is_not_judged_against_an_ipv6_subnet`
- An IPv6 group whose interface carries no IPv6 address is missing an address, not holding one in the wrong place. The interface's IPv4 subnet is not a subnet its virtual address could have been inside, so reporting it as the one the address should have been in would name an unrelated prefix.  
  `test_ipv6.py::test_an_ipv6_group_on_an_ipv4_only_interface_is_not_outside_its_subnet`
- RFC 5798 makes an IPv6 group's primary virtual address link-local, which is exactly why the IOS configs here write `address FE80::1 primary`. Every interface on the segment is already on fe80::/10, so there is no subnet for that address to be outside of and no defect to report.  
  `test_ipv6.py::test_a_link_local_virtual_address_is_not_outside_its_subnet`

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
- The IPv4 and IPv6 halves of one group number hold different virtual addresses on the same interfaces. Read without their families they are two groups claiming one interface — a device contending with itself, and two groups answering for one address.  
  `test_ipv6.py::test_the_two_families_of_one_group_do_not_collide_or_share`

### `mtu-mismatch`

**high** · `cassandra.facts.rules.mtu_mismatch_across_a_subnet`

Neighbours that disagree about how large a frame may be.

Only explicitly configured values are compared. An unset MTU is a platform default this tool does not claim to know, and guessing one would invent findings rather than report them.

Reported once per set of interfaces rather than once per subnet. A dual-stack link is one wire in two subnets and its MTU is one setting, so naming it twice would tell the reader they have two problems to fix when one edit fixes both.

**Reports:** MTU is not agreed across {…}

**Detail:** interfaces sharing this subnet are configured with {…} bytes; anything larger than {…} is dropped without an ICMP hint on a bridged path, and OSPF will not leave ExStart

**Remedy:** set one MTU for the subnet — {…} everywhere, or raise the smaller interface to match

**Stays silent when:**

- Matching mtu does not fire  
  `test_facts_rules.py::test_matching_mtu_does_not_fire`
- An unset MTU is a platform default the tool does not claim to know.  
  `test_facts_rules.py::test_one_configured_mtu_is_not_a_mismatch`
- Both ends of the link are 9214 bytes and the link is in two subnets. The rule walks subnets, so it looks at this wire twice and has to reach the same answer both times.  
  `test_ipv6.py::test_a_dual_stack_wire_whose_ends_agree_reports_no_mtu_mismatch`

### `ospf-timers-disagree`

**high** · `cassandra.timing.timer_rules.ospf_timers_disagree_across_a_subnet`

OSPF refuses an adjacency whose hello and dead intervals do not match.

Both values ride in every hello packet and both are checked on receipt, so a disagreement is not a slower adjacency, it is no adjacency. Each device reads perfectly well on its own — the defect exists only in the pair — and nothing alarms about a neighbour it never had, so this survives change windows that look successful from either console.

IS-IS is deliberately excluded. It advertises its own hold time inside each hello and the receiver honours what it is told, so two IS-IS routers on one wire need not agree on anything here, and reporting the difference would be reporting the protocol working as designed.

Silent unless both ends state the same interval and state it differently. One end configured and the other left on its platform default is a comparison against a number this tool does not have.

**Reports:** {…} timers on {…} and {…} disagree across {…}

**Detail:** {…}. Both values are carried in every hello and checked by the receiver, so the two never reach a full adjacency and neither device reports losing a neighbour it never had. Whatever routes over {…} is reaching its destination another way, or not at all.

**Remedy:** make the hello and dead intervals identical on both ends of {…}

**Stays silent when:**

- The rule reports a disagreement, not the presence of tuned timers. Two routers running the same non-default hello and dead form an adjacency exactly as a pair on the defaults would.  
  `test_timer_rules.py::test_two_ends_that_agree_are_silent`
- A device that states no hello interval is running its platform default, which this tool has not read. The pair may well be misconfigured, but saying so would mean comparing the configured value against an invented one.  
  `test_timer_rules.py::test_one_end_tuned_and_the_other_silent_is_not_a_disagreement`
- IS-IS carries its hold time inside every hello and the receiver honours what it is told, so two IS-IS routers on one wire are under no obligation to use the same interval. Reporting the difference would be reporting a correctly configured link.  
  `test_timer_rules.py::test_isis_hellos_that_differ_are_the_protocol_working`
- Half a link is an incomplete capture, not a defect. One router with tuned OSPF timers and nothing else in the directory says nothing about whether the device at the far end agrees with it.  
  `test_timer_rules.py::test_a_neighbour_missing_from_the_collection_reports_nothing`
- The site-14 configs are a working network apart from one preempt delay: the VRRP groups advertise every second and agree with each other, no interface carries BFD or per-interface OSPF timers, and no BGP process dampens anything. Every rule here is measuring something that corpus does correctly, so a finding on it would be a false positive rather than a discovery.  
  `test_timer_rules.py::test_the_shipped_corpus_trips_none_of_these_rules`

### `subnet-mask-disagreement`

**high** · `cassandra.facts.rules.prefix_length_disagreement`

Two devices on one wire that disagree about how wide the wire is.

One address falls inside the other's subnet, so by the operator's own arithmetic the two interfaces are on one segment — but the masks differ, so the ends hold different beliefs about which destinations are local. The end with the wider mask ARPs for addresses the end with the narrower mask sends to its default gateway, and the range where they disagree is reachable in one direction only. Every ping between the two interface addresses succeeds, which is what lets this survive for years.

Silent when the prefix lengths agree, and when neither address is inside the other's subnet — two unrelated subnets are not a disagreement about one. Silent on loopbacks and host addresses, which describe no segment, and across VRFs, where two devices sharing a subnet is the point of the VRF.

**Reports:** {…} and {…} share a segment with different masks

**Detail:** {…} and {…} overlap — one of them is inside the other's subnet — so the two interfaces are on one wire with two different ideas of how far it reaches; the addresses in {…} but outside {…} are local to one end and remote to the other, so traffic to them is delivered in one direction only

**Remedy:** agree one mask for the segment: /{…} at both ends, or /{…} at both

**Stays silent when:**

- A /32 states a routing identity, not the width of a wire, so a loopback numbered out of a LAN prefix is not two devices disagreeing about a segment.  
  `test_facts_rules.py::test_a_host_address_inside_another_subnet_is_not_a_mask_disagreement`
- Neither address falls inside the other's subnet, so the two interfaces make no competing claim about one segment and there is nothing to reconcile.  
  `test_facts_rules.py::test_unrelated_subnets_with_different_masks_are_not_a_disagreement`
- A /24 and a /64 on the same pair of interfaces are two masks, and they are not a disagreement: they describe different address families. The rule only compares addresses of one version, and this is what says so.  
  `test_ipv6.py::test_two_families_on_one_wire_do_not_disagree_about_its_mask`

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

### `bfd-detection-below-floor`

**medium** · `cassandra.timing.timer_rules.bfd_detection_is_below_the_safe_floor`

A BFD session too fast to survive a control-plane pause takes the IGP down.

BFD failing over in tens of milliseconds is only useful if nothing else on the box ever stops for that long. A supervisor switchover, a software upgrade, a route-processor spike or a large table churn all pause packet handling for longer than a handful of milliseconds, and the session that notices drops every client protocol registered against it. The outage is manufactured by the detection rather than found by it, and it recurs on exactly the maintenance events that were supposed to be non-disruptive.

The floor is `Limits.bfd_min_detection_ms`, so a site whose platform genuinely maintains the session in forwarding hardware can lower it.

Silent when either the interval or the multiplier is unconfigured — the detection time is then a platform default this tool refuses to guess.

**Reports:** BFD on {…} declares the neighbour down after {…}

**Detail:** {…}ms x {…} = {…}, under the {…} a session is expected to survive an ordinary control-plane pause at. Anything that stops packet handling for longer than that — a supervisor switchover, an upgrade, a CPU spike — drops the session and every protocol registered against it, on a link that never failed.

**Remedy:** raise the interval or the multiplier so detection is at least {…}

**Stays silent when:**

- Three 50ms intervals is the fastest session platforms document as survivable, and the finding claims the session is below what a control-plane pause allows. At the floor that claim is not yet true.  
  `test_timer_rules.py::test_detection_landing_exactly_on_the_floor_is_silent`
- A platform that genuinely maintains the session in forwarding hardware survives what a software implementation cannot, and the same 60ms session is then a deliberate choice rather than a fragile one.  
  `test_timer_rules.py::test_the_floor_is_the_operators_number`
- The site-14 configs are a working network apart from one preempt delay: the VRRP groups advertise every second and agree with each other, no interface carries BFD or per-interface OSPF timers, and no BGP process dampens anything. Every rule here is measuring something that corpus does correctly, so a finding on it would be a false positive rather than a discovery.  
  `test_timer_rules.py::test_the_shipped_corpus_trips_none_of_these_rules`

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
- A peer address is checked against the subnets the device is addressed in. With IPv6 addressing unread those subnets did not exist, so every IPv6 peering in every config looked like a peer on no local subnet — a defect reported wholesale about configurations that were correct.  
  `test_ipv6.py::test_an_ipv6_bgp_peer_is_found_on_its_own_subnet`

### `dampening-never-suppresses`

**medium** · `cassandra.timing.timer_rules.dampening_can_never_suppress`

A dampening profile whose suppress threshold is above its own penalty ceiling never suppresses anything.

The four values are not independent. A penalty halves every half-life and is abandoned altogether after max-suppress, so the most a prefix can ever accumulate is `reuse x 2 ^ (max-suppress / half-life)`. Set the suppress threshold above that and no amount of flapping reaches it: the profile is configured, shows up in review, is believed to be protecting the RIB, and does nothing at all.

This is the opposite failure to `dampening-exceeds-sla` and they cannot both be true of one profile. That one reports dampening that holds a prefix down too long; this one reports dampening that was never going to hold anything.

Silent when any of the four values is absent, since the ceiling is a product of all of them.

**Reports:** {…} dampening on {…} can never reach its suppress threshold

**Detail:** a penalty cannot exceed {…} x 2 ^ ({…}s / {…}s) = {…}, and suppression begins at {…}. No sequence of flaps reaches that number, so no prefix is ever dampened and the protection the profile appears to provide does not exist.

**Remedy:** lower the suppress threshold below {…}, or raise max-suppress-time or the reuse threshold until the ceiling clears it

**Stays silent when:**

- The rule reports dampening that cannot act, not dampening that is set high. With the same thresholds and a shorter half-life the penalty climbs to 12000, so a prefix that keeps flapping is suppressed as intended.  
  `test_timer_rules.py::test_a_threshold_the_penalty_can_reach_is_silent`
- A bare `bgp dampening` inherits values that work: an hour of suppression against a fifteen-minute half-life puts the ceiling at sixteen times the reuse limit, far above the threshold. The inherited profile has a different problem, and `dampening-exceeds-sla` is the rule that reports it.  
  `test_timer_rules.py::test_the_platform_defaults_are_coherent`
- The ceiling is a product of the reuse limit, the half-life and the max-suppress time. Any one of them absent makes it unknowable, and a rule that filled in the gap would be reporting its own default.  
  `test_timer_rules.py::test_a_profile_missing_a_term_of_the_product_is_silent`
- The site-14 configs are a working network apart from one preempt delay: the VRRP groups advertise every second and agree with each other, no interface carries BFD or per-interface OSPF timers, and no BGP process dampens anything. Every rule here is measuring something that corpus does correctly, so a finding on it would be a false positive rather than a discovery.  
  `test_timer_rules.py::test_the_shipped_corpus_trips_none_of_these_rules`

### `fhrp-hold-under-three-hellos`

**medium** · `cassandra.timing.timer_rules.fhrp_hold_time_leaves_too_few_hellos`

An FHRP hold time worth fewer than three hellos fails the gateway over on one lost advertisement.

A standby that gives up after two advertisements is one dropped frame away from taking the virtual address, and on a group with preempt configured it hands it straight back — so the cost is not one failover but a pair of them, plus whatever the ARP caches on the segment do in between. HSRP's own default holds for 3.3 hellos and VRRP fixes its master-down interval at three advertisements, for exactly this reason.

Silent when the hold time is not in the fact pack: VRRP on some platforms states only the advertisement interval and derives the rest, and a hold time this tool did not read is not a hold time it can measure.

**Reports:** {…} on {…} holds for only {…} hellos

**Detail:** advertisements are sent every {…} and the group declares the active gone after {…}, so fewer than {…} may be lost before the standby claims the virtual address. Every default in this space allows at least {…}, because a gateway that moves on one dropped frame moves for no reason.

**Remedy:** raise the hold time to at least {…}, or lower the hello interval to keep the failover time and regain the margin

**Stays silent when:**

- Three advertisements is what VRRP fixes its master-down interval at and what HSRP's own default exceeds. A group holding for exactly that long has the margin the rule asks for.  
  `test_timer_rules.py::test_a_hold_time_of_exactly_three_hellos_is_silent`
- VRRP as this dialect writes it states an advertisement interval and derives the rest, so there is no configured hold time to measure. The ratio would have to be assumed, and an assumed ratio is not a finding.  
  `test_timer_rules.py::test_a_group_with_no_hold_time_in_the_pack_is_silent`
- The site-14 configs are a working network apart from one preempt delay: the VRRP groups advertise every second and agree with each other, no interface carries BFD or per-interface OSPF timers, and no BGP process dampens anything. Every rule here is measuring something that corpus does correctly, so a finding on it would be a false positive rather than a discovery.  
  `test_timer_rules.py::test_the_shipped_corpus_trips_none_of_these_rules`

### `fhrp-no-redundancy`

**medium** · `cassandra.facts.rules.group_has_no_redundancy`

A redundancy group with fewer than two members in the collection.

Either the peer's configuration is not in the directory — in which case the finding is telling you the analysis is incomplete, which is worth knowing — or the group really is configured on one device, and the virtual address is a second name for a single point of failure.

**Reports:** {…} has only {…} member

**Detail:** a redundancy group with one member provides no redundancy

**Remedy:** configure the group on the peer device, or remove it

**Stays silent when:**

- Membership is decided by group number and subnet, not by interface name: an SVI on one device and a routed port on the other are still each other's peer, and the group has the second device it needs.  
  `test_facts_rules.py::test_members_of_one_group_on_differently_named_interfaces`
- Reusing a group number on another VLAN is ordinary practice, and each subnet keeps its own pair of members. Counting members by group number alone would split them into single-member groups that do not exist.  
  `test_facts_rules.py::test_one_group_number_reused_on_a_second_subnet`

### `fhrp-priority-tie`

**medium** · `cassandra.facts.rules.priority_tie`

Members sharing the top priority, so nothing decides the master.

The protocols break the tie on address comparison, which is deterministic but not chosen: the master is whichever device happens to have the higher interface address. That holds until a reboot changes who advertises first, and then the placement people have been assuming quietly stops being true.

**Reports:** {…} has no preferred master

**Detail:** {…} members share priority {…}, so the master is decided by address comparison and can change on reboot

**Remedy:** give the intended master a higher priority

**Stays silent when:**

- The tie that matters is between peers contending for one virtual address. Two groups on two VLANs may use whatever priorities they like, including the same numbers, because they never stand in the same election.  
  `test_facts_rules.py::test_equal_priorities_in_two_different_groups`
- Only the members contending for master can be tied. A third device sharing the backup's priority decides nothing: the group still has one member above both of them, so who holds it is not left to address comparison.  
  `test_facts_rules.py::test_a_tie_below_the_top_priority`

### `fhrp-track-ineffective`

**medium** · `cassandra.facts.rules.tracking_cannot_change_the_outcome`

A decrement too small to lose the election is tracking that does nothing.

This is the quiet one: the config looks correct, the intent is visible, and the failover silently never happens.

**Reports:** {…} tracking can never cause a failover

**Detail:** priority {…} minus the total decrement {…} is {…}, still above the highest peer priority {…}

**Remedy:** increase the decrement past {…}

**Stays silent when:**

- Sufficient decrement does not fire  
  `test_facts_rules.py::test_sufficient_decrement_does_not_fire`

### `igp-dead-under-three-hellos`

**medium** · `cassandra.timing.timer_rules.igp_dead_interval_leaves_too_few_hellos`

A dead interval worth fewer than three hellos drops healthy adjacencies.

The ratio, not the interval, is what buys tolerance: every default in the business — four hellos for OSPF, three for IS-IS — exists so that a lost packet costs a retransmission rather than a reconvergence. Below three, one dropped hello and ordinary jitter are enough to tear down an adjacency that was never broken, and the SPF run, the route churn and the traffic loss that follow are all caused by the timer rather than by any fault.

Silent when only one of the two numbers is configured, because the ratio cannot be computed from a value nobody wrote down.

**Reports:** {…} on {…} gives up after {…} hellos

**Detail:** the adjacency drops after {…} of silence while hellos are sent every {…}, so fewer than {…} may be lost before the neighbour is declared dead. Every default in this space allows at least {…} for the reason that transient loss is normal and reconvergence is expensive.

**Remedy:** raise the dead interval to at least {…}, or lower the hello interval to keep the detection time and regain the margin

**Stays silent when:**

- Three is the floor every default in this space sits on or above, so a dead interval landing exactly on it is inside the margin the rule asks for, not one short of it.  
  `test_timer_rules.py::test_a_dead_interval_of_exactly_three_hellos_is_silent`
- An aggressively tuned IGP is a design decision, and the rule does not have an opinion about it. Hellos every 250ms with a dead interval of a second still tolerate four losses, which is what the check is about.  
  `test_timer_rules.py::test_sub_second_hellos_are_judged_on_the_ratio_not_the_interval`
- The site-14 configs are a working network apart from one preempt delay: the VRRP groups advertise every second and agree with each other, no interface carries BFD or per-interface OSPF timers, and no BGP process dampens anything. Every rule here is measuring something that corpus does correctly, so a finding on it would be a false positive rather than a discovery.  
  `test_timer_rules.py::test_the_shipped_corpus_trips_none_of_these_rules`

### `svi-vlan-not-trunked`

**medium** · `cassandra.facts.rules.svi_vlan_missing_from_every_trunk`

An addressed SVI for a VLAN no trunk on the device carries.

The interface is up and has an address, so the device can route for the VLAN; nothing can reach it, because the VLAN leaves on no uplink. It is the shape a VLAN takes after it is removed from a trunk's allowed list during some unrelated cleanup and the SVI is left behind.

Only checked on devices that have at least one trunk. A device with none is not carrying VLANs anywhere, which is a different thing entirely.

**Reports:** {…} has no trunk carrying VLAN {…}

**Detail:** the interface is up and addressed but the VLAN reaches no neighbour, so anything relying on it is isolated

**Remedy:** add VLAN {…} to the relevant trunk

**Stays silent when:**

- A router terminating a VLAN it does not bridge onward has no trunks to omit it from. The rule is about a VLAN that leaves on no uplink; a device with no uplinks carrying VLANs at all is a different design, not a broken one.  
  `test_facts_rules.py::test_an_svi_on_a_device_that_trunks_nothing`
- A VLAN needs one trunk that carries it, not every trunk. Trunks are pruned to what the neighbour behind them needs, so a VLAN absent from a trunk to a device that has no use for it is the allowed list doing its job.  
  `test_facts_rules.py::test_a_vlan_carried_on_one_trunk_but_not_another`

### `trunk-native-vlan-not-allowed`

**medium** · `cassandra.facts.rules.native_vlan_not_permitted_on_the_trunk`

A trunk whose native VLAN is missing from its own allowed list.

The native VLAN is the one the trunk sends and expects untagged. When the allowed list does not contain it the untagged traffic is discarded at both ends, silently and in both directions — the trunk comes up, every tagged VLAN on it works, and only the one service that was never tagged fails.

Only checked where both facts are present: a trunk stating no allowed list permits everything on real hardware, and the Fact Pack does not distinguish that from a construct the parser did not read, so it is left alone.

**Reports:** {…} is native in VLAN {…} but does not permit it

**Detail:** the trunk sends VLAN {…} untagged and its allowed list is {…}, so every untagged frame on the link is dropped while the tagged VLANs keep working

**Remedy:** add VLAN {…} to the allowed list, or make a permitted VLAN the native one

**Stays silent when:**

- A native VLAN the trunk also permits is the ordinary configuration: the untagged frames belong to a VLAN the link is allowed to carry.  
  `test_facts_rules.py::test_native_vlan_inside_the_allowed_list_is_silent`

### `fhrp-no-preempt-on-preferred`

**low** · `cassandra.facts.rules.preferred_master_will_not_reclaim`

The highest-priority member has preempt off, so it never takes back.

After the first failover the group stays on the backup for good. That is a legitimate choice — it avoids a second interruption to move back — but it means the priorities in the configuration no longer describe where traffic is, and the next person to read them will be wrong about the current state.

Low severity because it is a defensible configuration. It is reported so the choice is visible rather than assumed.

Silent when the top priority is shared. There is then no preferred master to fail to reclaim — firing once per tied member would state, twice and contradictorily, that each of them is the preferred one. `fhrp-priority-tie` is the finding for that group.

**Reports:** {…} will not return to its preferred master

**Detail:** {…} has the highest priority ({…}) but preempt is off, so after any failover the group stays on the backup indefinitely

**Remedy:** enable preempt, or accept the placement is not deterministic

**Stays silent when:**

- Preempt on a backup governs nothing: it never has a higher priority to reclaim with. Only the highest-priority member can fail to take the group back, so the setting is reported there and nowhere else.  
  `test_facts_rules.py::test_preempt_left_off_on_the_backup`
- With every member at the same priority there is no preferred master to fail to return to — whoever wins the address comparison is entitled to keep the group. The tie is worth reporting, and `fhrp-priority-tie` is what reports it.  
  `test_facts_rules.py::test_every_member_sharing_one_priority_has_no_master_to_reclaim`

### `igp-dead-not-a-multiple-of-hello`

**low** · `cassandra.timing.timer_rules.igp_dead_interval_is_not_a_multiple_of_the_hello`

A dead interval that is not a whole number of hellos wastes its remainder.

Adjacency loss is only ever detected on a hello that does not arrive, so the part of the dead interval past the last whole hello is time in which nothing can be learned. A router configured `hello 10` and `dead 35` tolerates three lost hellos, exactly as `dead 30` would, and then waits five more seconds before acting on it.

Reported as low because nothing fails: the adjacency works and the detection time is merely not the one the ratio implies. It is almost always a typo in one of the two numbers, which is worth seeing before someone tunes the other one to match it.

Silent below three hellos, where the ratio itself is the defect and `igp-dead-under-three-hellos` says so instead.

**Reports:** {…} on {…} waits {…} for hellos sent every {…}

**Detail:** that is {…} whole hellos and {…} in which no further hello is due, so the adjacency tolerates the same {…} losses a dead interval of {…} would and detects the failure {…} later. One of the two numbers is not the one that was meant.

**Remedy:** set the dead interval to a whole multiple of the hello — {…} keeps the current tolerance, {…} keeps the current detection time

**Stays silent when:**

- `hello 10` with `dead 40` is the OSPF default written out. Every second of the dead interval is one in which a hello was due, so nothing is wasted.  
  `test_timer_rules.py::test_the_conventional_four_hellos_is_silent`
- `hello 10` with `dead 25` is both a fraction of a hello and too few hellos, and the second is the finding worth acting on. Reporting the remainder as well would be two findings about one pair of numbers.  
  `test_timer_rules.py::test_an_aggressive_ratio_is_left_to_the_rule_about_ratios`
- The site-14 configs are a working network apart from one preempt delay: the VRRP groups advertise every second and agree with each other, no interface carries BFD or per-interface OSPF timers, and no BGP process dampens anything. Every rule here is measuring something that corpus does correctly, so a finding on it would be a false positive rather than a discovery.  
  `test_timer_rules.py::test_the_shipped_corpus_trips_none_of_these_rules`

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
- Both aggregation switches are addressed in 2001:db8:14::/64, so neither is alone on it. The IPv4 threshold that decides when a missing far end is unremarkable would have exempted every /64 there is, which is the same silence for the wrong reason.  
  `test_ipv6.py::test_a_shared_ipv6_subnet_is_not_an_isolated_interface`

## TIMING tier

Derived from the discrete-event timer model (PROJECT.md §2.2). These are candidates: they say a sequence your configs permit produces the behaviour, and they carry that sequence so a human can judge it.

### `fhrp-divergence`

**high** · `cassandra.timing.sequences._divergence`

Two FHRP groups on the same device pair that stop agreeing who is master.

Both groups see one event. They answer it at different speeds — a different tracking decrement, a preempt delay on one and not the other — and for the stretch between their two answers, traffic for one VLAN leaves through one device and traffic for the next VLAN leaves through the other. Everything that assumes a single default gateway per site (a stateful firewall, a NAT table, an asymmetric-path check) breaks for exactly that window and then heals, which is what makes it so hard to catch after the fact.

Reported only past MIN_DIVERGENCE_MS. A brief divergence *during* an event is expected behaviour; one that persists long after recovery is the defect.

Silent unless the split survives the flap interval being twenty percent either side of the one that produced it, and silent if the same split is there with no events at all. Those two controls are what separate a property of the configuration from an artifact of the model's sampling grid.

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

Silent unless the chasing survives the flap interval being twenty percent either side, and silent if the group moves that often with no events at all.

The finding names the group's own preempt delay, because two groups on one device can both chase and need different flap intervals to do it — and without the delays written down, two findings whose only visible difference is a number in the trigger look like the same finding printed twice.

**Reports:** {…} changes master {…} times under a single flap sequence

**Detail:** each transition is a forwarding interruption for everything using that gateway{…}

**Remedy:** {…}

**Stays silent when:**

- A decrement that leaves the master above its peer never moves the group, so the interface it watches can flap as often as it likes without a single handover. The tracking is ineffective, which the FACTS tier reports; it is not a group chasing a link.  
  `test_timing.py::test_tracking_too_weak_to_lose_the_election_cannot_chase`
- Disabling preempt is the standard cure for a group that chases a flapping uplink: a backup will not displace a master that is still advertising, however far the master's priority has been decremented. Nothing hands the group back and forth, so there is nothing to report.  
  `test_timing.py::test_a_group_without_preempt_cannot_be_taken_from_a_live_master`

## Silence across a whole rule set

These tests assert that a rule set reports nothing at all on a given input. They constrain every rule in the module rather than one of them, which is what makes a clean run mean something.

- **`cassandra.facts.rules`** — Clean pair produces nothing  
  `test_facts_rules.py::test_clean_pair_produces_nothing`
- **`cassandra.facts.rules`** — The shipped corpus is well-formed apart from its timing asymmetry, which is the TIMING tier's job. If a FACTS rule fires here it is a false positive.  
  `test_facts_rules.py::test_real_corpus_produces_nothing`
- **`cassandra.facts.rules`** — Reciprocated bgp session is silent  
  `test_facts_rules.py::test_reciprocated_bgp_session_is_silent`
- **`cassandra.facts.rules`** — The whole FACTS tier against a dual-stack pair with nothing wrong with it. Every cross-family false positive there is would show up here.  
  `test_ipv6.py::test_a_clean_dual_stack_eos_pair_produces_nothing`
- **`cassandra.facts.rules`** — The same claim for the dialect that writes its IPv6 group in a sub-mode rather than on one line, whose virtual address is link-local.  
  `test_ipv6.py::test_a_clean_dual_stack_ios_pair_produces_nothing`
- **`cassandra.facts.rules`** — The same claim again for HSRP, whose IPv6 group is a separate block with its own priority rather than a second address on a shared one.  
  `test_ipv6.py::test_a_clean_dual_stack_nxos_pair_produces_nothing`
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
