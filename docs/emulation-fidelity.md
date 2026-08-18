# Emulation target feasibility

Feeds PROJECT.md §5.3 (slice fidelity) and gates §4.2 Phase 0. Written before any
image was downloaded or any lab was booted, so that image acquisition and scenario
design happen in the right order.

**Conclusion: build Phase 0 on Arista cEOS.** The reasoning below is worth reading
before accepting that, because the deciding constraint is not the one you would
expect.

## The problem

§4.1 names the Phase 0 ground-truth scenario `site14_hsrp_lockstep`, and the
conjecture schema in §2.3 uses `hsrp group 14 active role changes >2 times within
120s` as its worked example.

**HSRP is Cisco-proprietary.** No non-Cisco NOS implements it. So Phase 0 as
literally specified requires a Cisco image, and every other candidate forces a
translation of the scenario into VRRP. That translation is not free: the two
protocols differ in preemption defaults, timer granularity, and how tracking
affects priority — which is to say, they differ in exactly the dimensions the
scenario is about.

## Two requirements, not one

Phase 0 is not "build a lab that breaks." It is "build a lab that breaks **and**
show Batfish calls the same configs healthy." The second half constrains the NOS
choice for reasons that have nothing to do with emulation quality: the target has
to be a platform Batfish can parse.

Almost nothing satisfies both.

| Candidate | Expresses the failure | Batfish reads it | Viable |
|---|---|---|---|
| FRR / Cumulus / SONiC | no — no preempt delay, no tracking | yes | **no** |
| Nokia SR Linux | yes | **no** | **no** |
| Arista cEOS | yes | yes | **yes** |
| Cisco IOL / IOS-XE | yes, natively | yes | yes, with licensing friction |

Batfish's supported list covers Arista, Cisco (IOS, IOS-XE, IOS-XR, NX-OS, ASA),
Cumulus, FRR, SONiC, Juniper and others. Nokia SR Linux is not on it.

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
| Batfish parses its configs | yes | yes | **no** | yes |
| Image acquisition | licensed | free account, manual download | freely downloadable | fully open |
| Packaging | IOL native / vrnetlab VM | native container | native container | `linux` kind, not a first-class kind |

### FRR is disqualified

FRR's VRRP has no preempt delay — preemption is a boolean — and no object tracking
of any kind. Those are the two mechanisms the lockstep failure turns on: groups
diverge because tracked objects decrement priority at different times and preempt
delays expire at different times. On FRR both are inexpressible, so a scenario
built there would be a different failure, not a cheaper one. Cumulus and SONiC
inherit this, since their FHRP comes from FRR.

Other FRR constraints, relevant if it appears elsewhere in the fabric: macvlan
devices must be created outside FRR with correct virtual MACs, VRRPv2 has no
authentication and no IPv6, `Accept_Mode` is unimplemented, and it needs Linux
5.1+.

### SR Linux would have been ideal, and is ruled out anyway

Checked against the SR Linux data model rather than assumed. Under
`vrrp/vrrp-group` it carries `priority`, `preempt`, `preempt-delay`,
`advertise-interval`, `version`, `accept-mode`, `init-delay`,
`master-inherit-interval`, and an `interface-tracking` container with
`track-interface` and `priority-decrement`.

That covers both required knobs with no manual image acquisition — the image is on
a public registry — and it is the only candidate with no human step at all. The
Batfish constraint rules it out regardless. It remains a good target for later
phases that do not need a symbolic comparison against the same configs.

One thing worth stealing from it: `init-delay` is a startup-only timer with no
HSRP equivalent. It bites only on reload, which makes it exactly the kind of
dormant, rarely-exercised value this project exists to find. Worth a conjecture
class of its own once the target platform supports something equivalent.

### Arista cEOS is the answer

cEOS expresses both required knobs: `vrrp <n> preempt delay minimum <s>` and
`preempt delay reload <s>`, and `vrrp <n> tracked-object <name> decrement <n>` (or
`shutdown`). It is a native container rather than a VM, which keeps §3.1's
slice-minimisation economics intact when Phase 3 arrives, and Batfish parses
Arista configs.

Note that if `decrement` and `shutdown` are both configured on the same interface
for the same group, shutdown wins. That is a config-lint conjecture in its own
right and costs nothing to add later.

The cost is a one-time manual step that cannot be automated from a headless
session: register a free Arista account, download the cEOS image, `docker import`
it.

## Does Batfish model FHRP at all? Yes — which is what makes the proof work

This decides what a healthy Batfish verdict is worth, so it was checked rather
than assumed.

Batfish's vendor-independent model exposes `HSRP_Groups`, `HSRP_Version` and
`VRRP_Groups` as interface property specifiers, and it has support for interface,
route and reachability tracking as applied to HSRP/VRRP priority.

This is the favourable outcome. Batfish computes FHRP election in steady state, so
a healthy verdict on the scenario means static analysis looked at the redundancy
design, got the steady state right, and still missed the failure — precisely the
§1.3 escalation boundary. Had Batfish been blind to FHRP, a healthy verdict would
have been trivially true and would have demonstrated a vendor coverage gap rather
than the boundary the thesis claims.

**Turn it into an acceptance step rather than an assumption.** Batfish's tracking
support is described as initial, and documented support is not the same as correct
behaviour on these specific configs. Phase 0 should assert, in order:

1. Batfish parsed the configs with no unrecognised-line warnings on the FHRP
   stanzas — silent parse failure is the failure mode that would fake this result.
2. Batfish reports the VRRP groups on the expected interfaces and elects the
   expected master, i.e. it genuinely modelled the redundancy rather than skipping
   it.
3. *Then* the reachability verdict is healthy.

Only with 1 and 2 passing does 3 mean anything. A `batfish_says: healthy` field in
a finding (§2.5) that came from a config Batfish failed to parse is worse than no
field at all, and this is the cheapest possible place to build that check in.

## Not yet verified

Stated explicitly so none of it is mistaken for a checked fact:

- Whether cEOS honours sub-second VRRP timers *accurately under container
  scheduling*. This is the question that actually decides whether any timer-race
  finding means anything: if host scheduling jitter is wider than the margins the
  scenario depends on, §2.5's ±20% perturbation control is measuring the host, not
  the network. Measure it on the first booted lab, before trusting any scenario.
- BFD client registration behaviour, needed for the §1.4 "BFD before or after IGP
  hold timer" class.
- Interface dampening and carrier-delay equivalents outside IOS.
- Whether any container NOS reproduces IOS carrier-delay semantics closely enough
  that a flap-timing finding transfers to hardware.

## Consequences to accept

Choosing cEOS means each Phase 0 finding carries two caveats rather than one: the
§5.3 container-versus-hardware caveat, and an HSRP→VRRP translation caveat. Record
both on the finding artifact.

Keep the Cisco path in reserve for validating a high-severity finding on the real
protocol, which is what §5.3 proposes vrnetlab for anyway. Do not reach for it on
day one: Phase 0 has to prove that a timing-dependent failure is real and that
static analysis misses it, and that proof survives the protocol translation.
Licensing friction on day one does not.
