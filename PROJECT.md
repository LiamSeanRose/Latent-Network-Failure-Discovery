# Latent Network Failure Discovery

> Working name: **Cassandra**
> Status: Phase 0 in progress. This document is the source of truth for implementation.
> Revised 2026-08-18 — reframed from an autonomous discovery engine to a personal QA
> application. The conjecture-generation pipeline is deferred, not deleted: see §6.
> Section numbers referenced elsewhere in the repo were deliberately preserved; §7 records
> the two that moved.

---

## 0. What this is

A QA tool for network labs you own.

You describe a scenario — a topology, an event sequence, and hard conditions for what must
and must not happen. The tool runs it in emulation with real protocol timing, scores it
against those conditions, and separately asks a static analyser the same question about the
same configs.

**The interesting output is the disagreement.** A failure that is real under timing and
invisible to steady-state analysis is a class of bug that config verification structurally
cannot reach, and reproducing one on demand is the point of the whole exercise.

It is a thing you run, not a service that runs. No continuous loop, no autonomous
generation, no fleet. Those were the previous shape of this document and are deferred to §6.

---

## 1. Why this is worth building

### 1.1 The gap

Config verification answers steady-state questions: is A reachable from B, does this ACL
line ever match, is there a forwarding loop. It answers them well, quickly, and offline.

It cannot answer questions containing a time quantity, a repetition count, or an ordering
claim, because those have no steady state to evaluate. What happens if a link flaps three
times in ninety seconds is not a property of a configuration. It is a property of a
configuration *plus* a sequence of events *plus* the timers that govern how the control
plane reacts.

That second class is where a large share of real outages live, and it is unserved by the
tools that are otherwise excellent.

### 1.2 What existing tools do

Commercial network digital twins (Forward Networks, NetBrain, Cisco Crosswork) and research
systems (Aether, arXiv:2604.18233) are **reactive** — a change is proposed, and the system
validates it — and predominantly **steady-state**. Aether's own results are instructive:
0.94 error detection at 0.64 precision, with its natural-language-to-graph-query agent
consuming 68% of the reasoning budget and producing most of the precision loss. Its stated
conclusion was that tool-based verification substantially outperformed query-based
verification.

The durable lesson, and it survives the reframing: **facts should be materialised by
deterministic code, not fetched by something that has to compose a query.** If a future
version of this ever grows an agent layer (§6), that constraint holds.

### 1.3 Batfish — capability boundary

Batfish computes real RIB/FIB by running BGP best-path selection, OSPF SPF, IS-IS, and
redistribution to convergence, offline from config text. It supports differential questions
(`snapshot` vs `reference_snapshot`), `differentialReachability`, ACL analysis, loop
detection, traceroute simulation, and L1-topology-aware failure analysis
(`layer1_topology.json` — downing an interface also downs its L1-paired peer).

**The decisive detail:** Batfish converges *deterministically by design*. Per the SIGCOMM
2023 evolution paper, it uses protocol-specific graph colouring plus logical clocks on RIBs
specifically to eliminate race conditions caused by neighbours exchanging routes from
partially-converged state, so results stay stable across runs.

Batfish deliberately suppresses the exact failure class this project hunts. That is not a
defect — determinism is what makes it useful — but it means **timing-dependent failures are
structurally invisible to it.** That is the escalation boundary, and it is a principled one.

Practical constraints discovered while building Phase 0 are recorded in
`docs/emulation-fidelity.md`: Batfish does not parse Nokia SR Linux, it *does* model
HSRP/VRRP election, and FRR cannot express VRRP preempt delay or object tracking. Together
those pin the emulation target to Arista cEOS.

### 1.4 Escalation boundary — canonical table

| Question shape | Tier | Rationale |
|---|---|---|
| Is A reachable from B? | SYMBOLIC | Batfish core competency |
| Does this ACL line ever match? | SYMBOLIC | Static analysis |
| After link X fails, is A still reachable? | SYMBOLIC | Batfish L1 failure analysis, steady state |
| Do these two snapshots differ in reachability? | SYMBOLIC | `differentialReachability` |
| Is there a forwarding loop in steady state? | SYMBOLIC | Batfish loop detection |
| MTU / config consistency | SYMBOLIC | Direct fact-pack assertion, no tool call |
| Does the network converge *at all* after event E? | **EMULATE** | Requires running control plane |
| What happens if X flaps 3× in 90s? | **EMULATE** | Requires timers |
| Do FHRP groups move in lockstep or independently? | **EMULATE** | Requires real state machines |
| Is there a microloop during reconvergence? | **EMULATE** | Transient, not steady state |
| Does preemption ordering cause oscillation? | **EMULATE** | Race condition |
| Does dampening suppress a route longer than the SLA? | **EMULATE** | Timer interaction |
| Does BFD detect before or after the IGP hold timer? | **EMULATE** | Timer race |

Rule of thumb: **if the question contains a time quantity, a repetition count, or an
ordering claim, it cannot be answered symbolically.**

A scenario that fails on the SYMBOLIC side of this line is a scenario in the wrong place.
It should be a static check, not an emulated run — and if a scenario's failure *is* visible
to Batfish, that is a signal the scenario is mis-designed, not a success.

---

## 2. The application

### 2.1 What a scenario is

The unit of work. A directory containing:

- **topology** — a Containerlab file, synthetic, resource-bounded (§3.1)
- **configs** — device configs, the same text handed to both emulation and the symbolic tier
- **events** — what is done to the running lab and when
- **conditions** — what must be observed, and what must not
- **README** — the mechanism, why it is invisible to static analysis, and its caveats

A scenario is self-contained and runnable on its own. `scenarios/site14_vrrp_lockstep/` is
the reference implementation and Phase 0 deliverable.

### 2.2 The Fact Pack

Structured facts materialised from configs by deterministic code: device inventory, L1/L2/L3
adjacency, FHRP groups, and a complete timer inventory. Implemented as frozen dataclasses in
`cassandra/factpack/schema.py`.

Two uses in this shape of the project:

1. **Authoring** — reading a fact pack for a lab is how you find the asymmetries worth
   writing a scenario about. A timer inventory that lists every hello, hold, preempt delay,
   dampening profile and carrier delay in one place is a list of candidate failure modes.
2. **Cheap assertions** — consistency questions (MTU mismatch, a tracked object nothing
   defines, a trunk missing a VLAN its SVI needs) are answerable directly from facts with no
   tool call and no lab.

The builders that populate it are Phase 2.

### 2.3 The runner

Deploys a scenario, injects its events with real timing, samples state throughout, and
tears down. Sampling records both human-readable and machine-parseable output, because
scoring should never depend on a text format that is not a stable interface.

Modes: `baseline`, `trigger`, `control`, `perturb`, and `suite` — which runs the full
control set (§2.5) with a fresh deployment between runs, so repeated runs are independent
rather than each inheriting the previous run's state.

### 2.4 Scoring and verdicts

**Hard conditions, evaluated by code, reported as an exit status.** Not a judgment, not a
summary for a human to interpret.

Conditions are evaluated over the *sampled timeline*, never the end state. A transient
failure has re-converged by the time a run finishes, so a correct run ends looking healthy —
checking the final state scores a working scenario as a failure.

Two properties the scorer must hold to:

- **An empty parse is never a pass.** A collector that matched nothing must report that,
  not silently read as "no failure observed." This is the single most likely way for the
  tool to lie to you.
- **Ambiguity is surfaced, not resolved.** Two masters for one group is split brain; it gets
  reported as such rather than folded into a placement.

### 2.5 Falsification controls

A scenario that only ever runs its happy path proves nothing. Every result must survive:

1. **No-trigger control** — same lab, same window, no events. The observable must be absent.
   A control that exhibits the observable means the trigger did not cause it, and the run
   **fails**. The control's criterion is inverted, not skipped.
2. **Timing perturbation** — event intervals randomised ±20%. A result that only appears at
   exact timings is a knife-edge artifact, not a finding.
3. **Repetition** — 3 runs. Confirmation requires the observable in ≥2 of 3, to separate
   deterministic behaviour from flaky.

Perturbation has a prerequisite: **measure container scheduling jitter first.** If host
jitter is comparable to the timer margins a scenario depends on, the ±20% control is
measuring the machine rather than the network, and every timing result inherits the problem.

### 2.6 The symbolic comparison

The other half of every scenario: hand the identical configs to Batfish and record what it
says.

Order matters, and it is the difference between a real result and a fake one:

1. The snapshot parses with no init issues. Silent parse failure is what would fake this.
2. Batfish modelled the relevant construct — it reports the VRRP groups, elects the expected
   master, computed the routes. A healthy verdict from an analyser that skipped the feature
   proves a coverage gap, not the escalation boundary.
3. *Then* the verdict is worth recording.

A scenario where Batfish reports the failure is not a failed scenario — it is a scenario
that belongs on the SYMBOLIC side of §1.4, and should be moved there.

---

## 3. Running labs

### 3.1 Resource bounding and slice size

Containerlab imposes no default memory or CPU limits, and an unbounded node will destabilise
the host. **Set `memory:` and `cpu:` explicitly on every node**, in every scenario, without
exception.

Keep scenarios minimal. Every node in a scenario is a node that boots on every run, and the
smallest topology that can exhibit the behaviour is the right one — not the most realistic.
The Phase 0 scenario deliberately omits an aggregation peer link, because including it would
add STP convergence to a VRRP timing measurement.

Where booting is slow enough to discourage running scenarios at all, snapshot/restore of a
warm base topology is the fix. Not needed yet.

---

## 4. Implementation

### 4.1 Repository layout

```
cassandra/
  factpack/
    schema.py          # frozen dataclasses: inventory, adjacency, FHRP, timers
    builders/          # config text -> facts. deterministic. Phase 2.
  symbolic/            # pybatfish wrapper. Phase 2.
  harness/             # scenario discovery, run orchestration, history. Phase 1.
scenarios/
  site14_vrrp_lockstep/
    topology.clab.yml
    configs/
    run.sh
    score.py
    batfish_check.py
    README.md
docs/
  CONVENTIONS.md       # standing rules
  emulation-fidelity.md
  phase0-design.md
tests/
```

`run.sh` and `score.py` currently live inside the scenario. Phase 1 lifts the general parts
into `cassandra/harness/` and leaves the scenario-specific parts behind.

### 4.2 Phases

**Phase 0 — one scenario, end to end.** Reproduce a timing-dependent failure in Containerlab
as a scored scenario, and demonstrate that Batfish reports the identical configs healthy.
One directory, one README, one asciinema. This is the existence proof; nothing else gets
built until it runs.

**Phase 1 — generalise the harness.** Lift the runner and scorer out of the scenario:
scenario discovery, a declarative conditions format, run history on disk, and a summary
across scenarios. The test is a *second* scenario that reuses the harness without copying it.

**Phase 2 — Fact Pack + symbolic tier.** Config ingest → fact pack → pybatfish wrapper.
Cheap fact-only assertions run without a lab. The test is whether a human can read a fact
pack for a lab and form a scenario from it alone.

**Phase 3 — regression detection.** Run history becomes useful: what changed since last run,
which scenario started failing, which timing margin moved. This is where a personal QA tool
earns its keep, because it answers "did I break something" rather than "is this broken."

**Phase 4 — UI.** Scenario list, run history, timeline view of a failing run, the
Batfish-versus-emulation disagreement made visible.

**Phase 5 — the discovery layer, if ever.** See §6.

### 4.3 Kill criteria

Stop and reconsider if:

- **Phase 0** shows Batfish catching the failure → the escalation boundary (§1.4) is wrong,
  or the scenario is mis-designed. Diagnose which before continuing.
- **Phase 0** shows container scheduling jitter comparable to the scenario's timer margins →
  emulated timing results are not trustworthy on this host, and the fidelity question has to
  be solved before anything else is built on top.
- **Phase 1** cannot produce a second scenario without copy-pasting the first → the harness
  is not a harness.
- **Phase 3** shows scenarios that pass and fail at random → the falsification controls in
  §2.5 are not doing their job, and every result to date is suspect.

---

## 5. Open questions

1. **Scenario sourcing.** Where do scenarios come from once the obvious ones are written?
   Public post-mortems, protocol documentation read adversarially, and timer-inventory
   asymmetries visible in the fact pack are the candidates. This is the question §6 was
   originally an answer to.
2. **Conditions format.** Phase 0 hard-codes its conditions in `score.py`. A declarative
   format is obviously right and easy to get wrong; defer until three scenarios exist and
   the common shape is visible rather than guessed.
3. **Slice fidelity.** cEOS does not perfectly reproduce IOS-XE/NX-OS timer behaviour, and a
   result on a container may not hold on hardware. Every finding carries an explicit fidelity
   caveat. Where a scenario translates a protocol (HSRP → VRRP), it carries a second one.
   See `docs/emulation-fidelity.md`.
4. **How much of this is worth automating** versus writing by hand. A personal tool used
   occasionally has very different automation economics from a service. Resist building
   machinery before the manual version is annoying.

---

## 6. Deferred: the discovery layer

The previous version of this document specified an autonomous pipeline: a cheap model
(SCOUT) generating ~2,000 conjectures per cycle, a deterministic filter and scheduler
(WARDEN) killing ~85% before any tool call, and a frontier model (PROSECUTOR) attempting to
falsify the survivors in emulation. With a conjecture schema, a learned per-class escalation
policy, prompt-cached fact packs, batched generation, and a circuit breaker on
findings-per-dollar.

**Why it is deferred.** All of that machinery exists to make *volume* affordable. At the
scale of one person and their own labs, the volume is not there, so the machinery is cost
without benefit — and it sits on top of a scenario harness that does not exist yet. The
harness is the substrate either way; the generator is optional.

**What it would take to bring it back.** Phases 1–3 complete, a library of hand-written
scenarios large enough to see what a generated one should look like, and a real answer to
§5.1. At that point the discovery layer becomes "propose new scenarios," which is a much
better-defined job than "find bugs," and it inherits the runner, scorer, and controls that
already work.

**What survives from it regardless**, and is already reflected above:

- Facts are materialised by deterministic code; nothing composes a query (§1.2).
- Verdicts are hard conditions with exit codes, never model judgment (§2.4).
- A survivor is only meaningful if something genuinely tried to kill it (§2.5).
- A result that static analysis could have found is not a result (§2.6).

The full prior specification is in git history.

---

## 7. Notes on this revision

Section numbers referenced from code and docs were preserved: §1.3, §1.4, §2.2, §2.5, §3.1,
§4.1, §4.2, §4.3, §5.3. Two moved:

- **§2.3** was the conjecture schema; it is now the runner. The conjecture schema is in §6.
- **§4.4** was the scale target (25 nodes, Aether-comparable). It is gone: comparability
  with a research benchmark is not a goal of a personal tool. Scenario size is governed by
  §3.1 instead.

## 8. Source index

- SIGCOMM 2023 — Lessons from the evolution of the Batfish configuration analysis tool
- arXiv:2604.18233 — Aether, network validation using agentic AI and digital twin
- SIGCOMM 2024 — Relational Network Verification
- PLDI 2024 — Diffy: data-driven bug finding for configurations
- containerlab.dev — kinds, resource limits, multi-node
- batfish.readthedocs.io — supported devices, differential questions, question framework
