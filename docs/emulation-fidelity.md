# Emulation target feasibility

Feeds PROJECT.md §5.3 (slice fidelity) and gates §4.2 Phase 0. Written before any
image was downloaded or any lab was booted, so that the image acquisition and the
scenario design happen in the right order.

## The problem

§4.1 names the Phase 0 ground-truth scenario `site14_hsrp_lockstep`, and the
conjecture schema in §2.3 uses `hsrp group 14 active role changes >2 times within
120s` as its worked example.

**HSRP is Cisco-proprietary.** No non-Cisco NOS implements it. So Phase 0 as
literally specified requires a Cisco image, and every free container NOS forces a
translation of the scenario into VRRP. That translation is not free: the two
protocols differ in preemption defaults, timer granularity, and how tracking
affects priority — which is to say, they differ in exactly the dimensions the
scenario is about.

## What each candidate can express

The rows are the knobs the lockstep scenario actually turns. A NOS that cannot
express a row cannot host the scenario, regardless of how good its routing is.

| | Cisco IOS-XE / IOL | Arista cEOS | Nokia SR Linux | FRR |
|---|---|---|---|---|
| HSRP | yes | no | no | no |
| VRRP | yes | yes (v2/v3) | yes | yes (v2/v3) |
| Preempt delay | yes (`minimum`, `reload`) | yes (`minimum`, `reload`) | yes (`preempt-delay`) | **no — toggle only** |
| Object tracking w/ decrement | yes | yes (`decrement`, `shutdown`) | yes (`priority-decrement`) | **no** |
| Sub-second advert interval | yes (msec) | yes | yes (`advertise-interval`) | yes (10 ms steps, centisecond wire) |
| Image acquisition | licensed | free account, manual download | freely downloadable | fully open |
| Packaging | IOL native / vrnetlab VM | native container | native container | `linux` kind, not a first-class kind |

### FRR is disqualified for this scenario

FRR's VRRP implementation has no preempt delay — preemption is a boolean — and no
object tracking of any kind. Those are the two mechanisms the lockstep failure
turns on: groups diverge because tracked objects decrement priority at different
times and preempt delays expire at different times. On FRR both are inexpressible,
so a scenario built there would be a different failure, not a cheaper one.

Additional FRR constraints, relevant even if it is used elsewhere in the fabric:
macvlan devices must be created outside FRR with correct virtual MACs, VRRPv2 has
no authentication and no IPv6, `Accept_Mode` is unimplemented, and it needs Linux
5.1+.

### Arista cEOS is the viable free-ish target

cEOS expresses both required knobs: `vrrp <n> preempt delay minimum <s>` and
`preempt delay reload <s>`, and `vrrp <n> tracked-object <name> decrement <n>` (or
`shutdown`). Note that if `decrement` and `shutdown` are both configured on the
same interface for the same group, shutdown wins — a footgun worth encoding as a
config-lint conjecture in its own right.

Cost: the image is not on a public registry. It needs a free Arista account, a
manual browser download, and `docker import`. That is a human step and cannot be
automated from a session like this one.

## Consequences for Phase 0

Three options, in descending fidelity:

1. **Cisco IOL or vrnetlab-packaged IOS-XE — keeps HSRP.** The scenario stays
   literally what the outage was. Highest fidelity, hardest image acquisition, and
   vrnetlab VM packaging is materially heavier per node than a container, which
   works directly against §3.1's slice-minimisation economics later.
2. **cEOS — translate the scenario to VRRP.** Both knobs available, container
   weight, one manual download. The finding then carries a translation caveat as
   well as the §5.3 container-vs-hardware caveat: two layers of "may not hold on
   the real box" rather than one.
3. **SR Linux — fully open image, capabilities now verified.** See below. This is
   the recommended target.

### SR Linux expresses the scenario, and adds a timer worth having

Checked against the SR Linux data model rather than assumed. Under
`vrrp/vrrp-group` the model carries `priority`, `preempt`, `preempt-delay`,
`advertise-interval`, `version`, `accept-mode`, `init-delay`,
`master-inherit-interval`, and an `interface-tracking` container with
`track-interface` and `priority-decrement`.

That covers both knobs the lockstep failure needs, with no manual image
acquisition — the image is on a public registry.

`init-delay` is a bonus and worth designing the scenario around: it is a startup
timer, so it only bites on reload, which is the §4.2 Phase 0 event and exactly the
kind of dormant, rarely-exercised value the whole project is meant to hunt. It has
no HSRP equivalent, so it is a genuine addition rather than a translation artifact.

## Not yet verified

Stated explicitly so none of it is mistaken for a checked fact:

- Whether cEOS honours sub-second VRRP timers *accurately under container
  scheduling*, which is the question that actually decides whether a timer-race
  finding means anything. Container CPU contention can dominate a 100 ms timer.
- BFD client registration behaviour on any of these (needed for the §1.4 "BFD
  before or after IGP hold timer" class).
- Interface dampening and carrier-delay equivalents outside IOS.
- Whether any of them reproduce IOS carrier-delay semantics closely enough that a
  flap-timing finding transfers.

The second bullet is the important one. If container scheduling jitter is wider
than the timer margins the scenario depends on, emulation confirms nothing and
§2.5's ±20% perturbation control is measuring the host, not the network. That
should be measured on the first booted lab, before any scenario is trusted.

## Recommendation

**Build Phase 0 on SR Linux.** It expresses both required knobs, needs no account
and no manual download, and is a native container rather than a VM, which keeps
the §3.1 slice-minimisation economics intact when Phase 3 arrives.

Accept the HSRP→VRRP translation caveat and record it on every finding. Keep cEOS
as a second opinion if a finding looks implementation-specific, and the Cisco path
in reserve for validating a high-severity finding on the real protocol — which is
what §5.3 proposes vrnetlab for anyway.

Do not choose Cisco for Phase 0 on fidelity grounds alone. Phase 0 has to prove
that a timing-dependent failure is real and that static analysis misses it. That
proof survives the protocol translation. Image licensing friction on day one does
not.
