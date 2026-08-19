# The timing model's assumptions

`cassandra/timing/model.py` decides who holds every FHRP group at every instant, and every
TIMING finding the tool produces is a statement about its output. PROJECT.md §2.2 is blunt
about what that means: this is the tier that can lie. §2.3 exists to check it against real
firmware, and that check has never run — the attempt is recorded in `DECISIONS.md`.

Until it does run, the next best thing is this: **every claim the model makes about real
routers, written down, individually, with the observation that would prove it wrong.** Nothing
here is validated. The point of the document is to make the unvalidated parts enumerable, so
that whoever eventually boots a lab has a checklist instead of a codebase to read.

## How to read an entry

- **Model** — what the code actually does. Not what it intends.
- **Believed real behaviour** — what firmware is thought to do, stated so it can be disagreed
  with.
- **Confidence** — one of three, and they mean different things:
  - *documented* — a protocol standard or vendor manual states it. Still unverified here.
  - *inferred* — reasoned from how the protocol must work, or generalised from one vendor to
    all. This is where the interesting errors will be.
  - *guessed* — chosen because the model needed a number and nobody checked. Treat as wrong
    until measured.
- **Falsified by** — the specific thing to observe in a lab that would make the entry false. A
  falsifier naming no observable is not a falsifier; if an entry ever reads "timers may differ
  on hardware", delete it and write a real one.
- **Test** — the test in `tests/test_timing_model_assumptions.py` that pins the model to the
  claim, or `none` with the reason it cannot be tested at this interface.

The `A<n>` identifiers appear as markers in `model.py` comments, so an entry and the code that
implements it can be found from each other. `tests/test_timing_model_assumptions.py` fails if
an entry loses its test, or if the code cites an identifier this document does not define.

**A test here proves the model does what this register says. It proves nothing about real
routers.** That is what §2.3 is for.

---

## Timing and time resolution

### A1 — Every group advertises once per second

**Model:** `DEFAULT_ADVERT_MS = 1000` for every group in every fact pack. The per-group
`FhrpTimers.hello_interval_ms` the builders parse from `vrrp N advertisement interval 4` or
`standby N timers 3 10` is never read by the model.

**Believed real behaviour:** VRRP defaults to 1s and the corpus configures 1s explicitly, so
the corpus happens to agree. HSRP's default hello is 3s with a 10s hold, so an HSRP group is
modelled three times faster than it runs, and any group with a non-default advertisement
interval is modelled wrong in both directions — detection time (A3) and sample resolution (A2)
are both derived from this one number.

**Confidence:** documented for VRRP's default, wrong by construction for anything else — the
inventory holds the real value and the model ignores it.

**Falsified by:** configure `advertisement interval 4` (or an HSRP group with default timers)
on a group, drop the master's tracked uplink, and measure the time to takeover. The model
predicts the same time as for a 1s group; real firmware will not.

**Test:** `test_a1_the_configured_advertisement_interval_is_ignored`

### A2 — The timeline is sampled on a fixed 1s grid, not event-stepped

**Model:** `simulate()` steps `SAMPLE_INTERVAL_MS` at a time, applies every event with
`at_ms <= now_ms` at the top of the step, and records one `Placement` per step. An event at
t=2500ms takes effect at t=3000ms. Every duration measured off the timeline is a multiple of
1s and carries up to one sample of error at each edge.

**Believed real behaviour:** real transitions happen at arbitrary instants. Nothing in the
modelled dynamics resolves finer than one advertisement, so the grid does not lose information
the model had — but it does silently round the *inputs*, and a caller who asks about a 500ms
event gets an answer about a 1000ms event.

**Confidence:** inferred. The rounding direction (always up, never down) is a choice, not a
protocol fact.

**Falsified by:** any finding whose truth depends on sub-second ordering — two events 300ms
apart that the model collapses into one sample and real hardware does not. The tool currently
has no such finding, which is the reason this is tolerable rather than a defect.

**Test:** `test_a2_events_take_effect_at_the_next_sample`

### A3 — A silent master is detected after three advertisement intervals, and the group is masterless until then

**Model:** when the master's own FHRP interface goes down (A15) the group's master becomes
`None`, and no other member may claim it until `MASTER_DOWN_INTERVAL_MS` (3 × advert) has
passed. Backups do not take over instantly, and nobody forwards during the gap.

**Believed real behaviour:** RFC 5798's master-down interval is `3 × advert + skew`, where skew
is `(256 − priority) / 256` advertisement intervals — up to nearly a full interval, and
different for every backup. That skew is what staggers backups so they do not all claim at
once; it is not modelled. HSRP's equivalent is the hold time, which defaults to 10s, not 3s.

**Confidence:** documented for VRRP, minus the skew term. Wrong for HSRP defaults (A1).

**Falsified by:** shut the master's SVI and timestamp the backup's first advertisement. Under
3s means the model is slow; a value that varies with the backup's priority means the skew term
matters and the model's fixed 3s is an average at best. With three or more members, watch
whether they claim simultaneously — the model says they cannot, because it elects globally
(A16).

**Test:** `test_a3_a_silent_master_leaves_the_group_vacant_for_three_adverts`

### A4 — Preemption of a live master takes effect with no propagation delay

**Model:** when a member's priority rises above the live master's and it is allowed to preempt,
the takeover appears in the same sample as the priority change. No advertisement has to arrive
first.

**Believed real behaviour:** the challenger must receive one advertisement carrying the lower
priority (or send one the master defers to), so a real takeover trails the priority change by
up to one advertisement interval. The model's answer is early by 0–1 advert; because samples
are one advert wide (A2), the error is invisible on the timeline and understates every
divergence by up to one second at each edge.

**Confidence:** inferred, and deliberately not corrected — adding a latency the sample grid
cannot represent would be false precision.

**Falsified by:** timestamp the tracked interface going down and the backup's first
advertisement as master. A consistent sub-second lag confirms the model; a lag near or beyond
one advertisement interval means every reported divergence duration is off by that much per
transition.

**Test:** `test_a4_preemption_lands_in_the_same_sample_as_the_priority_change`

---

## Election

### A5 — Election is decided by current priority alone

**Model:** a member's priority is its configured priority minus the decrements of the tracked
interfaces that are down *right now*. There is no history: no dampening, no penalty
accumulation across flaps, no hold-down after a transition, no memory that the interface was
down a second ago. Two sequences that leave the same interfaces down leave the same election.

**Believed real behaviour:** FHRP itself is memoryless in the same way. The memory in a real
network lives one layer down — interface dampening, carrier delay (A18), IGP flap damping — so
the assumption is that all such damping is absent or irrelevant, which is a much stronger
statement than "FHRP is memoryless".

**Confidence:** documented for the protocol, inferred for the surrounding system.

**Falsified by:** flap a tracked interface repeatedly and watch whether the *n*-th flap behaves
like the first. Any suppression, backoff, or "interface held down" message means something
outside FHRP has memory the model does not.

**Test:** `test_a5_only_the_current_down_set_decides_the_election`

### A6 — Equal priority never displaces a live master

**Model:** a challenger must be *strictly* higher than the incumbent to take over. Restoring a
tracked interface so both members sit at the same priority leaves the group where it is.

**Believed real behaviour:** both VRRP and HSRP require strictly greater for preemption; equal
priority favours the incumbent. Standard behaviour and unlikely to be wrong.

**Confidence:** documented.

**Falsified by:** two members at identical priority with preempt enabled, and the group moving
anyway — or oscillating, which would mean the tie is being resolved by something the model does
not model (advert arrival order, MAC, source IP).

**Test:** `test_a6_equal_priority_does_not_displace_the_master`

### A7 — Ties are broken by the higher primary IPv4, and by device name when no address is known

**Model:** among equal-priority candidates the one whose FHRP interface has the numerically
higher primary IPv4 address wins. If the fact pack has no IPv4 for one of them, the model falls
back to the alphabetically lower device name.

**Believed real behaviour:** VRRP (RFC 5798, section 6.4.3) and HSRP both break ties on the higher
primary address. The fallback has no counterpart in any firmware whatsoever — it exists only so
the model is deterministic and does not invent a flap.

**Confidence:** documented for the address rule; the fallback is a fabrication and is only
reachable for a member whose address the parser did not capture.

**Falsified by:** two members at equal priority where the alphabetically first device has the
*lower* address; the model and reality agree only if the higher address wins. Separately: if
renaming a device ever changes a prediction, the fallback is being used and the answer is not
about the network.

**Test:** `test_a7_equal_priority_is_broken_by_the_higher_address`

### A8 — Tracking decrements are additive, and the result is clamped at 1

**Model:** every tracked interface that is down subtracts its decrement; the decrements sum;
the result is floored at `MIN_EFFECTIVE_PRIORITY = 1`.

**Believed real behaviour:** vendors do sum concurrent decrements, and clamp rather than wrap or
go negative — VRRP's priority is one octet where 0 means "the master is resigning" and 255 means
"address owner", so neither 0 nor a negative value is expressible. The clamp matters only in
configurations that over-decrement, where it can turn what the model would call a loss into a
tie (and then A6 keeps the incumbent).

**Confidence:** inferred. Vendors document the summation; the exact floor (1 vs 0) is
generalised from Cisco's documented behaviour to every platform.

**Falsified by:** configure decrements summing past the configured priority and read the
priority off the box. A displayed 0, or a wrap, or a group that resigns entirely, all break
this. Also worth watching: whether two members both bottomed out are treated as tied.

**Test:** `test_a8_decrements_are_additive_and_clamped`

### A9 — Every tracked object is an interface track, and a missing decrement is worth nothing

**Model:** each `TrackedObject` on a member becomes `(target, decrement)`, and the target is
matched against link event names. `TrackedObjectKind` is not consulted: a route track, an IP SLA
track, a BFD-session track and an object list are all treated as interface tracks that only ever
fire if an event happens to name the same string. A tracked object whose decrement the parser
did not record contributes exactly zero.

**Believed real behaviour:** those track kinds go down for reasons that are not link events at
all, so the model cannot see them fail — it silently reports the group as stable. And a bare
`standby N track X` on IOS decrements by **10** by default; the IOS builder only matches an
explicit `decrement <n>`, so such a line becomes a track worth nothing, and the model concludes
the group never moves.

**Confidence:** documented that the default exists (NX-OS's builder already applies 10);
the model's zero is a straightforward defect in the input path, not a modelling choice.

**Falsified by:** a config with a bare `standby 1 track 1` whose object goes down. Real firmware
drops the priority by 10 and may lose the election; the model predicts no change at all. This is
the assumption most likely to make the tool silently miss a real failure rather than invent one.

**Test:** `test_a9_a_missing_decrement_is_inert`

### A10 — An interface is identified by exact string match

**Model:** a tracked target matches an event only if the strings are identical. `Ethernet1`,
`ethernet1` and `Et1` are three different interfaces to the model.

**Believed real behaviour:** firmware normalises abbreviations and case; `interface Et1` and
`interface Ethernet1` are the same port. If a config abbreviates a tracked interface and spells
the interface definition out, the model sees a track on an interface that does not exist and no
event ever reaches it.

**Confidence:** documented that firmware normalises; whether the corpus can produce a mismatch
depends on the builders, which currently pass names through verbatim.

**Falsified by:** any config in which the tracked name and the interface stanza differ in case
or abbreviation, where real firmware tracks it and the model does not react.

**Test:** `test_a10_interface_names_match_exactly`

---

## Preemption and preempt delay

### A11 — Preempt delay is measured from interface recovery

**Model:** when an interface a member cares about comes back up, that member's preempt delay
restarts from that instant: `eligible_from_ms = now + preempt_delay`. Until it expires the
member cannot take the group back, even though its priority is already restored.

**Believed real behaviour:** this is the single assumption the tool's headline finding rests on,
and the vendors do not agree with each other.

- Arista EOS `vrrp N preempt delay minimum <s>` is described as the minimum time to wait before
  preempting, which is roughly what is modelled.
- Cisco IOS `standby N delay minimum <s>` delays **HSRP group initialisation after the group's
  own interface comes up**. On that reading, an uplink that is merely *tracked* flapping does not
  start the delay at all, because the SVI the group runs on never went down — so an IOS group
  would preempt back immediately and the divergence the tool reports would not happen.

The model implements the EOS reading and applies it to both dialects.

**Confidence:** inferred, and the inference is known to be contested. This is the riskiest entry
in the register.

**Falsified by:** on an IOS/HSRP pair with `standby N delay minimum 90`, flap only a *tracked*
uplink (never the SVI) and time how long the group takes to come back. If it returns in seconds
rather than 90, the model's central mechanism does not exist on that platform and every
divergence finding derived from an IOS config is an artifact.

**Test:** `test_a11_preempt_delay_runs_from_recovery_not_from_priority_restoration`

### A12 — The delay restarts only for members the event actually touches

**Model:** a link-up restarts the preempt delay only for members that track that interface or
run their group on it. An unrelated interface coming up on the same device does not move any
other group's clock.

**Believed real behaviour:** on the EOS reading of A11 the delay follows a state change of the
group, so an event that changes nothing for a group should not restart its delay. On the IOS
reading the delay is tied to the group's own interface, which this rule also respects.

**Confidence:** inferred. Consistent with both readings, which is the argument for it.

**Falsified by:** bring up an interface no group tracks and watch a group that was about to
preempt lose its place in the queue. That would mean the delay is a device-level or
process-level timer rather than a per-group one.

**Test:** `test_a12_an_untouched_group_keeps_its_preempt_clock`

### A13 — A vacant group is claimed immediately, regardless of preempt or preempt delay

**Model:** once a group has no master (A3, A15), the best available member takes it as soon as
the detection interval expires. It does not need `preempt` configured and its preempt delay is
not consulted, because claiming an empty group is not preemption.

**Believed real behaviour:** true for VRRP — a backup that hears nothing becomes master whether
or not preemption is configured. But it is exactly where the IOS reading of A11 disagrees: if
`standby delay minimum` delays *group initialisation*, then a member whose interface just
recovered may not claim a vacant group for the length of the delay, leaving the group with no
gateway for far longer than the model says.

**Confidence:** documented for VRRP's backup-becomes-master rule; inferred, and contested, for
the interaction with a configured delay.

**Falsified by:** take the master away entirely, and watch a backup that has `preempt` disabled
(or a long delay pending). If it does not take over, an outage the model reports as 3s is
unbounded in reality.

**Test:** `test_a13_a_vacant_group_ignores_preempt_and_delay`

### A14 — Nothing is delayed at t=0, and `preempt delay reload` is never read

**Model:** the initial election settles instantly at t=0 with every preempt delay treated as
expired. `FhrpTimers.preempt_delay_reload_ms` — which the builders parse — is not read by the
model at all.

**Believed real behaviour:** a router that has just booted holds off exactly as long as the
reload delay says, precisely because a freshly booted box has an empty forwarding state. The
model has no boot event, so it cannot express the failure mode where a reloading master claims
the group back before it can forward.

**Confidence:** documented that the timer exists and does something; the model's silence is a
scope limit, not a claim.

**Falsified by:** nothing in a lab — the model has no reload event to compare against. The
observation that matters is the inverse: a real incident caused by a reload delay is a finding
class this tier cannot produce, and enumerating boot events is the change that would fix it.

**Test:** `test_a14_the_reload_delay_is_not_read`

---

## What a member is

### A15 — A member is available exactly when its own FHRP interface is up

**Model:** a member can serve its group if and only if the interface the group is configured on
is not currently down. Nothing else disqualifies it.

**Believed real behaviour:** many things disqualify a real member — the SVI going down when the
last port in the VLAN goes down, the peer link failing, the box reloading, the FHRP process
dying, an ACL eating advertisements. The model sees exactly one of them, and only when a caller
happens to send an event naming the group's own interface. Note that the fact pack knows which
VLAN an SVI depends on, so "the trunk that carries VLAN 24 went down" *could* be turned into an
SVI-down event and is not.

**Confidence:** inferred. It is a lower bound on what makes a member unavailable, never an
upper one.

**Falsified by:** shut the last trunk port carrying a VLAN and watch the SVI go down with it —
the model keeps that member eligible and reports the group as healthy, because no event named
the SVI. Any real outage caused by an SVI dropping for a reason other than an explicit link
event is outside this model.

**Test:** `test_a15_a_member_with_its_own_interface_down_cannot_hold_the_group`

### A16 — There is exactly one master per group, always

**Model:** `Placement.masters` maps a group to one device or to `None`. Two devices holding one
group is not representable. The election is computed from an omniscient global view of every
member's state, so members cannot disagree.

**Believed real behaviour:** dual master is the classic FHRP failure, and it is caused precisely
by the thing the model does not have: a path between members. A trunk that omits the group's
VLAN, an ACL dropping multicast, an MTU mismatch black-holing advertisements — each produces two
masters, one ARP-level war, and a duplicate-IP incident. PROJECT.md §2.4 requires that
ambiguity be *surfaced rather than resolved*; here it is resolved by construction.

**Confidence:** this is a structural limit of the model, not a belief about firmware.

**Falsified by:** it cannot be falsified — it can only be exceeded. Break the L2 path between
two members in a lab and observe two masters where the model reports one. The tool's FACTS tier
catches some of the configurations that cause this (a trunk missing a VLAN an SVI depends on),
which is the only reason the gap is currently acceptable.

**Test:** none — the model has no representation for two masters, so any test would assert a
property of the return type rather than of the model's behaviour. The register entry is the
honest form of this one.

### A17 — Nothing is lost, jittered, or late

**Model:** every timer fires exactly on its nominal value. No advertisement is dropped, no
scheduler is late, no CPU is busy. The simulation is fully deterministic: the same fact pack and
the same events produce a byte-identical timeline every time.

**Believed real behaviour:** a lost advertisement on a congested link is one of the two common
causes of a spurious failover (the other is a busy control plane). PROJECT.md §2.4 requires a
±20% timing perturbation control for exactly this reason, and the model, having no jitter, is
the thing being perturbed rather than a participant.

**Confidence:** guessed, in the sense that the loss rate assumed is zero and no real network has
one.

**Falsified by:** a lab run in which the same event sequence produces different placements
across the three repetitions §2.4 requires. Determinism in the model plus non-determinism in
reality is the definition of a knife-edge finding, and a finding that survives only at exact
timings must be discarded.

**Test:** `test_a17_the_simulation_is_deterministic`

### A18 — Link state is binary and instantaneous

**Model:** a `LINK_DOWN` event makes the interface down at the next sample and a `LINK_UP` makes
it up at the next sample. `CarrierDelayTimers` — carrier delay, debounce, hold — are in the
timer inventory and are not read.

**Believed real behaviour:** carrier delay and debounce exist precisely to hide short flaps from
the control plane, and they are routinely asymmetric between up and down. A 2s debounce means a
1s flap never reaches FHRP at all; the model reports a failover that would not happen. This
cuts both ways: an asymmetric carrier delay is itself a cause of divergence between groups, and
the model cannot find it.

**Confidence:** documented that the timers exist and what they do; the model's silence about
them is a scope limit that directly changes answers.

**Falsified by:** configure `carrier-delay 2` on a tracked interface, flap it for one second,
and observe that nothing happens. The model predicts a failover.

**Test:** `test_a18_carrier_delay_is_ignored`

### A19 — Preempt delay is looked up per device, group number and protocol

**Model:** the delay comes from `TimerInventory.fhrp`, keyed on `(device, scope.instance,
protocol)`, where the builders write the group *number* into `scope.instance`. A member with no
matching record has no delay. The protocol is part of the key because HSRP 14 and VRRP 14 can
coexist on one device, and the number alone would let one group's delay leak into the other's.

**Believed real behaviour:** timers are per group per protocol on every platform, so the key is
right. The residual risk is in the fact pack rather than the model: if a builder ever writes
something other than the bare group number into `scope.instance`, every delay silently becomes
zero and every group preempts immediately — which reads as a *cleaner* network, not a broken
tool.

**Confidence:** inferred from the builders' current behaviour; the failure mode is silent.

**Falsified by:** none needed in a lab — this is checkable here. Compare the delays the model
resolves against the `preempt-delay=` values `cassandra facts` prints; a group that shows a
delay in the fact pack and none in the model is this bug.

**Test:** `test_a19_delay_lookup_is_per_protocol_not_just_group_number`

### A20 — Groups are independent

**Model:** each group is advanced separately. Two groups on the same pair of devices interact
only through the interfaces their members track.

**Believed real behaviour:** mostly true, and it is the assumption that makes the tool's central
finding *possible* — groups drifting apart is exactly what independence permits. But real groups
share a control plane, a CPU, and often a physical interface; a box that is losing
advertisements for one group is likely losing them for all of them, which correlates failures
the model treats as independent.

**Confidence:** inferred.

**Falsified by:** a lab in which one group's transition reliably drags another group with it
where no shared tracked interface explains it. That would mean the failure unit is the device,
not the group, and lockstep would be the default rather than the thing to check for.

**Test:** `test_a20_groups_only_interact_through_tracked_interfaces`

---

## The interface of `simulate()`

### A21 — An event applies to every member on the named device

**Model:** an `Event` names a device and an interface. It is offered to every member of every
group on that device, and reaches the ones that run on that interface or track it (A10, A12).
An event for a device with no members is silently a no-op.

**Believed real behaviour:** correct — a physical interface going down is visible to every group
on the box. The silent no-op is the risk: a typo in a device or interface name produces an
entirely healthy-looking simulation rather than an error.

**Confidence:** documented for the propagation; the silence on unknown names is a design choice
with a failure mode.

**Falsified by:** not falsifiable in a lab; it is an interface property. The check that matters
is that a caller cannot tell "nothing happened" from "the name was wrong", and `sequences.py`
only generates names taken from the fact pack, which is what keeps it safe today.

**Test:** `test_a21_an_event_for_an_unknown_device_is_a_silent_no_op`

### A22 — Simultaneous events are applied in the order given

**Model:** events are sorted by `at_ms` with a stable sort, so events sharing a timestamp are
applied in the order the caller listed them, and the last one wins for a given interface. A
`LINK_UP` and a `LINK_DOWN` at the same instant resolve to whichever came second in the list.

**Believed real behaviour:** a caller who writes two contradictory events at one instant is
asking a question with no answer. The model resolves rather than rejecting.

**Confidence:** a documented property of this implementation, not a claim about routers.

**Falsified by:** nothing in a lab. It is recorded because the resolution is arbitrary and a
caller relying on it is relying on `sorted()` being stable.

**Test:** `test_a22_simultaneous_events_resolve_in_list_order`

### A23 — The horizon is inclusive and rounds up

**Model:** samples run from 0 to `until_ms` inclusive, rounded up to the next multiple of the
sample interval. A state entered before the horizon and still current at it is reported as
current at the horizon, and `sequences.py` measures such a divergence as ending there.

**Believed real behaviour:** a divergence still in progress at the end of the window is
open-ended in reality. Every duration the tool reports is therefore a *lower bound*, and a
divergence exactly as long as the simulation window means the window is too short, not that the
divergence is that long.

**Confidence:** a property of this implementation. The consequence for findings is real.

**Falsified by:** not applicable; the check is that no finding's duration equals its horizon.

**Test:** `test_a23_the_horizon_is_inclusive_and_rounds_up`

### A24 — A group with no available member has no master; one available member always wins

**Model:** if every member's interface is down the group's master is `None`. A group with a
single member elects it regardless of priority, and a group with no members at all is `None`
forever.

**Believed real behaviour:** correct, and worth stating because `None` is a value downstream
code has to handle — `sequences.py` treats `None` as "not diverged", so a group nobody can serve
is not reported as a divergence. A total outage looks quieter than a split.

**Confidence:** documented for the election; the downstream consequence is this project's
choice.

**Falsified by:** not applicable in a lab. The consequence to check is in the tool: an event
sequence that leaves a group masterless for minutes should not be silent.

**Test:** `test_a24_no_available_member_means_no_master`

---

## Corrections made while compiling this register

Extracting the assumptions turned up four things that were not "unvalidated" but wrong, and they
were fixed rather than documented:

1. **`FAILOVER_MS` was defined, documented as the failover rule, and never used.** The module
   claimed a three-advert failover in a constant while the code handed the group over in the
   sample the priority changed. It is now `MASTER_DOWN_INTERVAL_MS` and it governs the path it
   always described (A3) — a master that has stopped advertising.
2. **A member whose own FHRP interface went down stayed eligible and kept the group.** An event
   naming an SVI was accepted by `simulate()` and silently changed nothing, so the model
   answered "healthy" to the most basic failure there is. Members now have availability (A15),
   a group can be vacant (A24), and the master-down interval applies to the gap.
3. **The preempt delay restarted on *any* link-up on the device**, including interfaces the
   member neither ran on nor tracked. It now restarts only for members the event touches (A12).
4. **Preempt delay was keyed on `(device, group number)` alone**, so HSRP 14 and VRRP 14 on one
   device shared a delay — the first record parsed won. The protocol is now part of the key
   (A19).

Two further changes were fidelity, not defects: tracked priority is clamped at 1 rather than
allowed to go negative (A8), and equal-priority ties are broken by the higher primary address
rather than by the alphabetically lower hostname (A7). Neither changes any prediction on the
corpus — no corpus group has equal priorities or over-decrements — which is precisely why they
were safe to correct now and would have been expensive to discover later.

None of this is validation. It is the difference between a model that is wrong in ways nobody
wrote down and one that is wrong in ways anybody can check.
