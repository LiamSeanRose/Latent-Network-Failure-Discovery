# Phase 0 scenario design

**Status: provisional.** The failure mechanism below is a reconstruction, not the
confirmed outage. Everything except §"The mechanism" survives a correction; that
section is the one to overwrite.

Target platform is Arista cEOS, for the reasons in `emulation-fidelity.md`.
Topology and addressing here are synthetic and invented for this document, per
rule 4.

## What Phase 0 has to prove

From PROJECT.md §4.2 and the §4.3 kill criteria, in order:

1. A timing-dependent failure reproduces in Containerlab, deterministically enough
   to be scored.
2. Batfish, given the **identical configs**, reports the network healthy.
3. If Batfish catches it, the escalation boundary in §1.4 is wrong and the project
   stops.

Point 2 carries a trap worth restating: a healthy verdict is only meaningful if
Batfish actually modelled the redundancy. Assert parse-clean, then
groups-and-master-as-expected, then healthy. In that order.

## Topology

Six nodes. Small on purpose — the smallest topology that can exhibit the behaviour
is the right one (§3.1), and every
node added here is a node the Phase 3 slicer will later have to justify.

```
                    ┌─────────┐
                    │  core1  │   10.0.0.0/31, 10.0.0.2/31
                    └──┬───┬──┘   Lo0 10.255.0.1  (probe target)
                 Et1 ──┘   └── Et2
                  │             │
            ┌─────┴─────┐ ┌─────┴─────┐
            │   agg-a   │ │   agg-b   │
            │ intended  │ │ intended  │
            │  master   │ │  backup   │
            └─────┬─────┘ └─────┬─────┘
               Et2│             │Et2
                  └──┐       ┌──┘
                  ┌──┴───────┴──┐
                  │    acc1     │  L2 only, no SVIs
                  └──────┬──────┘
                         │ Et3, access vlan 14
                    ┌────┴────┐
                    │ client1 │  linux probe source
                    └─────────┘
```

**No direct agg-a ↔ agg-b peer link.** The pair shares its VLANs through acc1.
A peer link would close an L2 loop and put STP convergence in the middle of a
VRRP timing measurement — one variable too many for the scenario that has to
prove the thesis. Real designs have one; this slice does not need it.

`core1`, `agg-a`, `agg-b`, `acc1` are cEOS. `client1` is a plain linux container.

**Uplink A** (`agg-a:Et1 ↔ core1:Et1`) is the tracked object and the flap target.

## Addressing and groups

Synthetic throughout.

| VLAN | Subnet | VRRP group | Purpose |
|---|---|---|---|
| 14 | 10.14.0.0/24 | 14 | client subnet — the one that breaks |
| 24 | 10.24.0.0/24 | 24 | second group, same pair |
| 34 | 10.34.0.0/24 | 34 | third group, same pair |
| 99 | 10.99.0.0/30 | — | transit between the aggs, OSPF, no VRRP |

All three intended master on `agg-a`. Virtual address `.1`, `agg-a` `.2`,
`agg-b` `.3`.

**VLAN 99 is not decoration.** It carries an OSPF adjacency between the two
aggregation routers across the acc1 trunks, so a router holding a group while its
own uplink is down forwards via its peer instead of blackholing. Without it,
group 34 — which does not track the uplink — turns every uplink failure into a
reachability failure, and reachability under single-link failure is a SYMBOLIC
question (§1.4). Batfish would catch it, and §4.3 reads Batfish catching the
Phase 0 outage as the escalation boundary being wrong.

The scenario must be **resilient to every single link failure in steady state and
broken only by timing.** That is the whole discipline of designing this proof, and
it is easy to violate by accident.

Three groups rather than one is the entire point: lockstep-versus-independent is
not observable with a single group, and the `fhrp_lockstep` class (§6) is about
groups on the same pair diverging.

## The mechanism (provisional — confirm or replace)

A race between **tracked-object recovery** and **preempt delay**, exposed only by
repeated flapping.

Per-group configuration asymmetry, of the kind that accumulates over years of
piecemeal changes:

| Group | Priority on agg-a | Tracks uplink A | Decrement | Preempt delay minimum |
|---|---|---|---|---|
| 14 | 110 | yes | 40 | 0 s |
| 24 | 110 | yes | 40 | 90 s |
| 34 | 110 | no | — | 90 s |

`agg-b` holds priority 100 on all three, preempt enabled.

Sequence on a single flap of uplink A:

1. Uplink A drops. Groups 14 and 24 decrement to 70, below agg-b's 100. Both fail
   over. Group 34 does not track, so it stays on agg-a — **first divergence**.
2. Uplink A returns. Group 14 has no preempt delay and reclaims master
   immediately. Group 24 must wait 90 s — **second divergence**.
3. If the next flap arrives inside that 90 s window, group 24 never returns, and
   group 14 has moved twice more.

Three flaps at 30 s intervals therefore leave the three gateways distributed
across both routers, with group 14 having changed master four or more times —
which is verbatim the `predicted_observable` in the §6 worked example.

**Why this is invisible to Batfish, and why that is not a Batfish deficiency.**
Batfish converges to a single steady state deterministically, by design (§1.3).
Ask it about this network and it computes: uplink A up, all tracked objects up,
all priorities at base, all three groups master on agg-a. Healthy — and correct.
The failure exists only in the interval between events, and its existence depends
on the *ratio* of flap interval to preempt delay. There is no steady state in
which it is visible, so no steady-state analysis can find it. That is the §1.4
escalation boundary stated as a concrete example rather than a table row.

**What makes it an outage rather than an inefficiency** is the part most dependent
on your actual incident, and the part I am least confident reconstructing. The
candidates, in order of how well they fit a seven-hour duration:

- Split gateway placement plus an asymmetric-path drop (stateful device, uRPF, or
  an ACL applied on one agg and not the other).
- Oscillation never settling, so the client sees repeated multi-second outages
  rather than one clean failover.
- A group landing on the router whose uplink is down, blackholing until something
  else moves.

The third would likely be caught by Batfish's failure analysis, which makes it the
*wrong* choice for Phase 0 — §1.4 classifies "after link X fails, is A still
reachable" as SYMBOLIC. Prefer the first or second.

## Event sequence

`run.sh baseline` deploys and settles first; `run.sh trigger` then runs, with t=0
at its invocation:

```
t=0      flap 1: uplink A down 10 s, up 20 s
t=30     flap 2: down 10 s, up 20 s
t=60     flap 3: down 10 s, up 20 s
t=90     observation window opens
t=210    observation window closes, collect
```

**Timing arithmetic that the criteria depend on.** Group 24's preempt delay is
90 s and restarts on each uplink recovery, so it is held on agg-b until t≈180 —
90 s after the last recovery at t=90. Group 34 never moves at all. Group 14
oscillates throughout.

So the groups are split across both routers from roughly t=10 to t=180, and
**re-converge before the window closes.** Any check of final placement therefore
sees a healthy, co-located network. That is not a failed run; it is the failure
being transient, which is the entire point. Assert against the sampled timeline,
never against the end state.

## Observables and pass/fail

Hard conditions, per §2.5 — not judgment. All are evaluated over the sampled
timeline in `runs/<stamp>/vrrp.log`, not over the final state.

- **Primary:** group 14 master transitions ≥ 4 within the window. Six are
  expected: one each way per flap.
- **Secondary:** the three groups are non-co-located for a sustained period —
  ≥ 60 s of contiguous samples in which group 24's master differs from group 34's.
- **Impact:** client1 loss exceeds the single-failover baseline established by
  `run.sh baseline`.

Confirmation requires the observable in ≥ 2 of 3 runs **and** absent in the
no-trigger control. Controls to run, all three from §2.5:

1. No-trigger control — same lab, no flap. Observable must not appear.
2. Timing perturbation — flap intervals randomized ±20%. If the result only
   appears at exactly 30 s, it is a knife-edge artifact, not a finding.
3. Repetition — 3 identical runs, to separate deterministic from flaky.

Control 2 has a prerequisite that must be measured first: **container scheduling
jitter**. If host jitter is comparable to the timer margins, the ±20% control is
measuring the machine. Measure observed VRRP advertisement intervals against
configured before trusting any of this.

Note that control 2 interacts with the arithmetic above. Perturbing the flap
interval by ±20% moves it between 24 s and 36 s, which stays well inside group
24's 90 s preempt delay, so the divergence should survive the perturbation. A
result that vanishes under ±20% would mean the mechanism is not what this document
claims.

## Batfish control

Same config files, no modification:

1. Parse — zero unrecognised-line warnings on the VRRP stanzas.
2. Model check — `VRRP_Groups` present on the expected SVIs, master computed as
   agg-a for all three.
3. Verdict — reachability client1 → upstream healthy.

Only 1 and 2 passing makes 3 meaningful.

## Deliverable

Per §4.2: one directory, one README, one asciinema.

```
scenarios/site14_vrrp_lockstep/
  topology.clab.yml
  configs/{core1,agg-a,agg-b,acc1}.cfg
  events.yml
  batfish/            # snapshot dir Batfish consumes
  README.md
  run.sh
```

Named `vrrp` rather than `hsrp`, since it is VRRP on cEOS. Note the translation
caveat in the README.

## Open before this can be built

1. **The real mechanism.** The table above is my reconstruction. If the outage was
   dampening, a microloop, or convergence stall, the topology mostly survives but
   the mechanism section is rewritten.
2. **cEOS version.** Arista has two VRRP syntaxes: legacy (`vrrp 14 ip …`,
   `vrrp 14 priority …`) and current (`vrrp 14 ipv4 …`,
   `vrrp 14 priority-level …`). Writing configs against the wrong one wastes an
   evening. `show version` on the imported image settles it.
3. Whether Batfish parses cEOS-generated running-config as cleanly as it parses
   hand-written EOS config — a five-minute check once the lab is up.
