# Latent Network Failure Discovery — Project Dossier

> Working name: **Cassandra**
> Status: pre-implementation. This document is the source of truth for implementation.
> Last research pass: 2026-08-18

---

## 0. One-paragraph statement

Existing network verification is **reactive** (triggered by a proposed change) and **static**
(reasons about steady-state configuration). This project is **proactive** and **dynamic**: a
continuously-running agent loop that generates conjectures about latent failure modes already
present in a network, filters them cheaply, and escalates only the survivors into real protocol
emulation where timing-dependent failures become observable. Output is a ranked, deduplicated
list of dormant failure modes, each with a runnable reproduction.

---

## 1. Prior art (verified, not assumed)

### 1.1 Aether — the closest existing system

**Paper:** *Aether: Network Validation Using Agentic AI and Digital Twin*, arXiv:2604.18233,
20 Apr 2026. Cisco (Paris/London) + Swisscom (Zurich).

What it is: five specialized NetOps agents (Assistant, NDM Query, Impact Assessment, Test
Planner, Test Executor) over a Network Digital Twin. ReAct loops, GPT-4o, tools exposed via
MCP, A2A protocol over SLIM, ArangoDB knowledge graph on an OpenConfig-derived schema,
git-like snapshot/fork/rebase semantics for network state.

**Measured results:**

| Metric | Synthetic (8 scenarios) | Production ISP (2 incidents) |
|---|---|---|
| Error detection | 0.94 | 1.00 |
| Precision (all) | 0.64 | 0.57 – 0.90 |
| Precision (main error) | 0.89 | 1.00 |
| Test plan coverage | — | 91.7% – 95.6% |
| Test efficiency (useful/generated) | — | 95.7% – 98.3% |
| Redundancy | — | 1.7% – 24.6% |
| Time to answer | ~223 s | ~400 s |

Test network: 25 routers (CORE / Aggregation / Metro), 277 IPv4/IPv6 addresses, 263 VRFs
across 613 instances, 76 ACLs / 274 rules, >30,000 lines of production-equivalent IOS-XR.

**Compute breakdown (critical finding):**

- 55% of runtime = tool execution (irreducible)
- 45% = agentic reasoning, of which:
  - NDM Query agent: **68%**
  - Impact Assessment: 18%
  - Test Executor: 12%
  - Test Planner: 2%

The natural-language-to-graph-query agent consumed two thirds of the reasoning budget **and**
was the dominant source of precision loss (malformed AQL, misinterpreted results). Their stated
failure pattern: the OpenConfig schema offers multiple expression paths for the same concept,
and the agent picks the path lacking data without exploring alternatives.

Their own conclusion: *tool-based verifications significantly outperformed query-based
approaches.*

**→ DESIGN CONSTRAINT #1: no agent in this system authors a database query. Ever.**
All network facts are materialized by deterministic code into a Fact Pack. Agents consume
facts; they never fetch them.

### 1.2 Gaps Aether left open

1. **Emulation tier unimplemented.** Their NDT supports model-based (Batfish) and
   simulation-based (RouteNet, NS-3) verification. Emulation is listed as *planned*.
2. **Entirely reactive.** Every workflow begins with a change request and an ITSM ticket ID.
   Dormant-failure discovery gets exactly one of eight scenarios (S1, router maintenance /
   backup path).
3. **Precision is the unsolved problem.** 0.94 detection with 0.64 precision means operators
   drown in false positives. Their future work explicitly lists "operational tooling for false
   positive management."
4. Scenarios are all statically expressible. None involve timers, flap intervals, convergence
   races, or preemption ordering.

Their stated future work — protocol knowledge injection via skills, multi-agent collaboration,
feedback loops from production failures, false-positive tooling — is a roadmap this project
should treat as a competitive map, not a to-do list.

### 1.3 Batfish — capability boundary

Batfish computes real RIB/FIB by running BGP best-path selection, OSPF SPF, IS-IS, and
redistribution to convergence, offline from config text. It supports differential questions
(`snapshot` vs `reference_snapshot`), `differentialReachability`, ACL analysis, loop detection,
traceroute simulation, and L1-topology-aware failure analysis (`layer1_topology.json` — downing
an interface also downs its L1-paired peer).

**The decisive detail:** Batfish converges *deterministically by design*. From the SIGCOMM 2023
evolution paper, it uses protocol-specific graph coloring (only same-colored nodes exchange
routes in a round) plus logical clocks on RIBs, specifically to *eliminate race conditions
caused by neighbors exchanging routes from partially-converged state*, so results stay stable
across runs.

Batfish deliberately suppresses the exact failure class this project hunts. This is not a bug
in Batfish — determinism is what makes it useful — but it means **timing-dependent failures are
structurally invisible to it.** That is the escalation boundary, and it is a principled one.

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

Rule of thumb for the WARDEN: **if the conjecture contains a time quantity, a repetition count,
or an ordering claim, it cannot be answered symbolically.**

### 1.5 Market context

- Gartner: agentic NetOps adoption <1% of organizations; 80% of network automation vendors
  expected to ship agentic AI capability by end of 2027, up from <20% in early 2026.
- Incumbents: Forward Networks (network digital twin, strong federal/FedRAMP positioning,
  sells static reachability + compliance verification), NetBrain (Agentic NetOps, Deep
  Diagnosis, 150+ vendor context model, Blackstone majority investment Jan 2026), Cisco
  Crosswork AI, Versa, Netskope AgentSkope, Selector.
- All of the above are reactive and/or steady-state. None ship continuous adversarial
  hypothesis generation at emulation fidelity.

### 1.6 Known agent-loop failure modes to design against

Documented across 2026 production post-mortems:

- **Token runaway** — a goal loop with no `max_iterations` can burn hundreds of dollars per hour.
- **Context rot** — long-lived loops appending to one window degrade in quality; fix with fresh
  context per unit of work or hierarchical compaction every 10–20 steps.
- **Overconfident termination** — agent declares success having checked half the space. Requires
  hard conditions (test exit codes), not soft judgment.
- **Circular dependency deadlock** — A waits on B waits on A.
- **Semantic invisibility** — an agent loops 18 steps, calls the same tool six times, finds
  nothing, and reports success. Every span returns 200, latency normal, dashboard green. This is
  the failure mode structural tracing cannot see, and the one this system must instrument for
  explicitly.
- **Lost in the middle** — models attend most strongly to the start and end of context. Mitigate
  with goal recitation at the end of context every turn.

---

## 2. Architecture

### 2.1 Economic shape

An inverted pyramid. Cost per unit of work must *rise* as volume *falls*.

```
   SCOUT      ~2,000 conjectures/cycle   cheapest model, batched, cached, ~$0.00X each
     ↓        deterministic filters kill ~85% before any further spend
   WARDEN     ~300 survive to symbolic   mostly non-LLM code
     ↓        symbolic checks kill ~90% of those
 PROSECUTOR   ~10-30 reach emulation     expensive model, minutes each
     ↓
  FINDINGS    ~1-5 confirmed/cycle
```

If cost per stage does not fall by roughly an order of magnitude per level, the design is wrong.

### 2.2 The Fact Pack (no agent queries anything)

Built by deterministic Python before any agent runs. Two parts:

**Static Fact Pack** — changes only when configs change. Cached as a prompt prefix.
- Device inventory, platform, OS version
- L1 topology (adjacency list) + L2/L3 adjacency
- Per-protocol adjacency graphs (OSPF areas, IS-IS levels, BGP sessions incl. RR topology)
- FHRP groups: group ID, members, priorities, preempt on/off, tracked objects
- Timer inventory: hello/hold/dead, BFD intervals, dampening params, SPF throttle,
  BGP advertisement-interval, carrier-delay, STP timers
- VRF/RT import-export matrix
- Redistribution points (source proto, dest proto, route-map, metric-type, tags)
- Route summarization points and their backing prefixes
- ECMP fan-out per prefix
- Historical incident index (structured post-mortems)

**Dynamic Slice** — the rotating focus for this cycle. Small.
- One k-hop neighborhood, or one protocol domain, or one recently-changed region
- Recent telemetry deltas for that slice
- Conjectures already refuted in this region (negative cache)

Serialization: newline-delimited structured text, not JSON blobs. Denser per token and models
parse it reliably. Target ≤ 25k tokens static, ≤ 3k tokens dynamic.

### 2.3 Agent 1 — SCOUT (conjecture generation)

- **Model tier:** cheapest capable (small-model tier). Never the frontier model.
- **Volume:** highest in the system.
- **Context:** Static Fact Pack (cached) + Dynamic Slice + refuted-list for this region.
- **Output:** strict JSON array of conjectures. No prose. No explanation. No preamble.
- **Batching:** emit **N=20 conjectures per API call**, not one. This amortizes the cached-read
  cost across 20 units of work and is the single largest lever on Scout cost.
- **Context discipline:** fresh context every call. Scout never accumulates history. Cross-call
  memory lives in the refuted-list, which is data, not conversation.
- **Delivery:** Batch API where cycle latency is tolerable. Batch (50% off) and prompt caching
  (~90% off cached input reads) stack.
- **Prompting:** give it the failure taxonomy explicitly. Do not expect zero-shot derivation of
  protocol interaction knowledge — Aether's own conclusion was that specialized knowledge
  injection is mandatory and is itself the high-value artifact.

**Conjecture schema:**

```json
{
  "id": "cnj_<ulid>",
  "region": "site-14-agg",
  "class": "fhrp_lockstep | microloop | dampening_sla | timer_race |
            redistribution_loop | summarization_blackhole | ecmp_asymmetry |
            convergence_stall | preemption_oscillation",
  "claim": "Single falsifiable sentence.",
  "entities": ["rtr-14-a", "rtr-14-b", "Gi0/0/1"],
  "trigger": {
    "event": "link_flap",
    "target": "rtr-14-a:Gi0/0/1",
    "count": 3,
    "interval_s": 30
  },
  "predicted_observable": "hsrp group 14 active role changes >2 times within 120s",
  "temporal": true,
  "severity_hint": "high",
  "confidence": 0.4
}
```

`temporal: true` is the routing signal. It must be derivable mechanically from `trigger`
(presence of count / interval / ordering), not trusted from the model.

### 2.4 Agent 2 — WARDEN (triage and scheduling)

**This is the product.** It should be as close to zero LLM as possible.

Deterministic pipeline, in order, cheapest gate first:

1. **Schema validation** — malformed → DROP. No LLM.
2. **Entity existence** — do all referenced devices/interfaces exist in the Fact Pack? Non-existent →
   DROP as hallucination. Log to hallucination-rate metric. No LLM.
3. **Structural dedup** — normalized hash of `(class, sorted(entities), trigger)`. Exact dup → DROP,
   increment support count on the original. No LLM.
4. **Semantic dedup** — embedding of `claim`, cosine against region index, threshold ~0.92.
   No LLM (embedding model only).
5. **Refuted cache** — has this conjecture shape been falsified in this region since last config
   change? → DROP. No LLM.
6. **Routing** — `temporal == true` OR class ∈ {microloop, timer_race, preemption_oscillation,
   convergence_stall} → EMULATE queue. Else → SYMBOLIC queue. Pure rules.
7. **Scoring** — priority = `blast_radius × prior_class_yield × recency_weight / expected_cost`.
   - `blast_radius`: computed from Fact Pack (how many prefixes/sites traverse affected nodes)
   - `prior_class_yield`: learned. Confirmed findings ÷ emulations run, per conjecture class.
     This is the escalation policy and it is a table, not a model.
8. **LLM tiebreak** — *only* for conjectures that pass all gates and land in a scoring band where
   rules cannot separate them. Small model, batched, one call per cycle for the whole band.

**Budget enforcement lives here:**
- per-cycle token ceiling (hard)
- per-cycle emulation-minute ceiling (hard)
- per-conjecture wall-clock timeout
- global circuit breaker: if confirmed-findings-per-dollar over trailing 5 cycles drops below
  threshold, halt and alert rather than continue

### 2.5 Agent 3 — PROSECUTOR (falsification)

- **Model tier:** frontier. Justified only because volume is ~10–30 per cycle.
- **Framing:** adversarial. Its stated job is to **kill** the conjecture. A survivor is meaningful
  precisely because something tried to destroy it. This is the direct countermeasure to Aether's
  0.64 precision.
- **Loop:** bounded ReAct. Hard cap 12 steps. Goal recitation appended at end of context each
  turn (counters lost-in-the-middle).

Procedure per conjecture:

1. **Slice minimization** — compute the minimal topology that can exhibit the claim. k-hop
   neighborhood of `entities`, k typically 2, plus any node in the FHRP group / IGP area / BGP
   RR cluster that could participate. Never boot the full fabric. This is the largest single
   lever on emulation cost.
2. **Slice validation** — assert the slice reproduces baseline steady-state behavior matching
   Batfish's model for the same region. If it does not, the slice is wrong; widen k and retry
   once, then DROP with reason `slice_invalid`. Prevents confirming artifacts of over-trimming.
3. **Event injection** — execute `trigger` against the running slice with real timing.
4. **Observation** — collect against `predicted_observable`. Structured collectors, not CLI
   scraping by the model.
5. **Falsification attempts** — at minimum:
   - re-run with the trigger removed (does the observable appear anyway? → not causal)
   - re-run with randomized event timing within ±20% (is it a knife-edge artifact?)
   - re-run 3× (is it deterministic or flaky?)
6. **Verdict** — `CONFIRMED` / `REFUTED` / `INCONCLUSIVE`. Confirmation requires the observable
   to appear in ≥2 of 3 runs AND be absent in the no-trigger control. Hard conditions, not
   judgment.
7. **Finding artifact** — on CONFIRMED, emit the reproduction.

**Finding schema:**

```json
{
  "id": "fnd_<ulid>",
  "conjecture_id": "cnj_<ulid>",
  "verdict": "CONFIRMED",
  "severity": "high",
  "blast_radius": {"prefixes": 412, "sites": 3},
  "repro": {
    "topology": "slices/site-14-agg-k2.clab.yml",
    "configs": "slices/site-14-agg-k2/configs/",
    "events": "slices/site-14-agg-k2/events.yml",
    "expected": "hsrp group 14 active role changes 4x within 118s"
  },
  "control_runs": {"with_trigger": [true, true, true], "without_trigger": [false, false, false]},
  "batfish_says": "healthy",
  "cost": {"usd": 0.83, "emulation_seconds": 240}
}
```

`batfish_says: healthy` is the money field. It is the proof that the finding was unreachable by
static analysis, which is the entire thesis of the project.

### 2.6 What the three agents are NOT

- No agent writes database queries (Aether lesson §1.1).
- No agent talks to another agent conversationally. Handoffs are typed artifacts on a queue.
  Agent-to-agent chat is where circular-dependency deadlock comes from and it buys nothing here.
- No orchestrator/assistant agent. The loop driver is `asyncio` code with a state machine.
  An LLM orchestrator is pure overhead for a pipeline with fixed topology.

---

## 3. Cost engineering

Prices move; verify against current provider pricing before relying on the arithmetic. Ratios
below are what matter and are stable.

### 3.1 Levers, in order of impact

1. **Prompt caching on the Static Fact Pack.**
   Cache writes cost ~25% premium over base input; cache reads ~10% of base input. Break-even at
   2+ hits. Minimum 1,024 tokens per checkpoint, up to 4 checkpoints per request. TTL 5 min
   default, 1 hour available at extra cost.
   Structure: static content first (system instructions → tool schemas → Fact Pack), dynamic
   content last. **Changing one character in the cached prefix invalidates it** — regenerate the
   Fact Pack on a fixed schedule, never mid-cycle.
   Use the 1-hour TTL for the Fact Pack; a cycle should complete inside one TTL window.

2. **Batching conjectures 20-per-call.** Divides the per-call cached-read cost by 20.

3. **Batch API for Scout.** Flat 50% off input and output, results typically within 1–2 hours,
   guaranteed 24. Stacks with caching. Scout has no latency requirement.

4. **Model routing by tier.** Scout on cheapest, Warden tiebreak on cheapest, Prosecutor on
   frontier. Reported 60–80% bill reduction from routing alone in comparable pipelines.

5. **Emulation slice minimization.** Booting a 4-node slice instead of a 25-node fabric is a
   >6× reduction in the dominant non-token cost.

6. **Warm slice pool.** Keep base topologies pre-booted; snapshot/restore instead of cold boot
   per conjecture. Containerlab has no node cap and imposes no default memory/CPU limits — set
   `memory:` and `cpu:` per node explicitly or a runaway slice destabilizes the host.

Independent evaluation across providers found prompt caching delivers 41–80% cost reduction on
long-horizon agentic tasks, statistically significant across all models tested.

### 3.2 Instrumentation — the metrics that matter

Standard tracing will show all-green while the system produces nothing. Track:

| Metric | Definition | Why |
|---|---|---|
| **Yield** | confirmed findings ÷ total USD | the only number that matters |
| Hallucination rate | conjectures dropped at entity-existence ÷ total | Scout quality |
| Dedup rate | dropped at structural+semantic dedup ÷ total | Scout diversity |
| Survival ratio | reached emulation ÷ generated | Warden calibration |
| Confirmation rate | confirmed ÷ emulated | Prosecutor discrimination |
| Class yield | confirmed ÷ emulated, per conjecture class | feeds escalation policy |
| Cost per confirmed finding | USD ÷ confirmed | trend must fall over time |
| Repeated-tool-call count | per Prosecutor run | catches the silent-loop failure |
| Steps-to-verdict | per Prosecutor run | catches drift |

**Falsification economics — the go/no-go.** The project is viable iff:

```
cost(generate + filter one conjecture)  <<  cost(emulate one conjecture)
                                        AND
confirmation_rate × value(finding)  >  cost per emulation
```

If Scout must generate 10,000 conjectures to yield one confirmed finding and each emulation
costs four minutes, the arithmetic does not close. **Measure this before building the UI.**

Baseline reference: Aether achieved 95.7–98.3% test efficiency, but for *intent-directed*
generation — it was told what changed. Open-ended conjecture will be far worse. Treat Aether's
number as an unreachable ceiling, not a target.

---

## 4. Implementation plan

### 4.1 Repository layout

```
cassandra/
  factpack/
    builders/          # config → structured facts. deterministic. no LLM.
    schema.py
    serialize.py       # → cacheable prompt prefix
  agents/
    scout.py
    warden/
      gates.py         # ordered deterministic filters
      routing.py       # symbolic vs emulate
      scoring.py       # blast radius, class yield
      policy.py        # learned escalation table
    prosecutor.py
  tiers/
    symbolic.py        # pybatfish wrapper
    emulation/
      slicer.py        # k-hop minimal topology extraction
      pool.py          # warm slice pool, snapshot/restore
      inject.py        # event injection with real timing
      collect.py       # structured observation
  loop/
    driver.py          # asyncio state machine. NOT an agent.
    budget.py          # ceilings + circuit breaker
    metrics.py
  store/
    conjectures.db
    findings.db
    refuted.db         # negative cache
  scenarios/
    site14_hsrp_lockstep/   # ground truth #1 — the real outage
  ui/
```

### 4.2 Phases

**Phase 0 — Ground truth (do this first, alone).**
Reproduce the real seven-hour site outage in Containerlab as a scored scenario. Then run Batfish
against the identical configs and demonstrate it reports healthy. Deliverable: one directory, one
README, one asciinema. This is the existence proof for the entire thesis and it either works or
the project is dead. Nothing else gets built until this exists.

**Phase 1 — Fact Pack + symbolic tier.**
Config ingest → Fact Pack → pybatfish wrapper. No agents. Verify the Fact Pack is complete enough
that a human can form conjectures from it alone. If a human can't, Scout can't.

**Phase 2 — Scout + Warden, symbolic only.**
No emulation yet. Measure hallucination rate, dedup rate, and how many conjectures survive
deterministic gating. **Target: ≥85% of conjectures die before reaching a tool.** If Scout's
hallucination rate exceeds ~15%, the Fact Pack is underspecified — fix the facts, not the prompt.

**Phase 3 — Prosecutor + emulation.**
Slicer first, then injection, then falsification controls. Run against the Phase 0 scenario as a
regression: the system must independently rediscover the known outage. That is the acceptance test.

**Phase 4 — Escalation policy learning.**
Class yield table starts uniform, updates from Prosecutor verdicts. Measure whether cost per
confirmed finding falls over successive cycles. If it doesn't, the policy isn't learning and the
"adaptive fidelity" claim is unsupported.

**Phase 5 — UI.**
Only now. Conjecture funnel, live emulation view, ranked findings, cost-per-finding trend.

### 4.3 Kill criteria

Stop and reconsider if:
- Phase 0 shows Batfish *does* catch the outage → the escalation boundary is wrong
- Phase 2 hallucination rate stays >25% after Fact Pack improvement → Scout tier too weak
- Phase 3 confirmation rate <2% → falsification cost exceeds generation value
- Phase 4 cost per finding flat across 10 cycles → no learning, it's a token furnace

### 4.4 Scale target

Match Aether's for comparability: 25 nodes, ~30k lines of config, multi-VRF, mixed IGP.
Do not exceed this until Phase 4 is measurably working.

---

## 5. Open questions

1. **Cold start.** The escalation policy needs ground truth to learn from, and ground truth means
   real outages. Bootstrap options: seed from public post-mortems, seed from the Phase 0 scenario
   family, or accept uniform priors for the first N cycles. Unresolved.
2. **Conjecture diversity collapse.** A cheap model given the same Fact Pack will converge on the
   same conjecture shapes. Mitigations to test: rotating focus slice, temperature scheduling,
   explicit anti-repetition via the refuted cache, class quotas per cycle.
3. **Slice fidelity.** cEOS/SR Linux/FRR do not perfectly reproduce IOS-XE/NX-OS timer behavior.
   A confirmed finding on a container may not hold on hardware. Requires an explicit fidelity
   caveat per finding and, eventually, vrnetlab-based validation of high-severity findings.
4. **Cisco releases their benchmark.** They committed to publishing scenarios, datasets, and
   expert ground truth. When it lands, run against it — but the differentiating suite is the
   emulation-tier one they cannot express.

---

## 6. Source index

- arXiv:2604.18233 — Aether (Cisco/Swisscom), Apr 2026
- SIGCOMM 2023 — Lessons from the evolution of the Batfish configuration analysis tool
- SIGCOMM 2024 — Relational Network Verification
- POPL 2026 — Network Change Validation with Relational NetKAT
- PLDI 2024 — Diffy: data-driven bug finding for configurations
- arXiv:2601.06007 — Don't Break the Cache: prompt caching for long-horizon agentic tasks
- Gartner via NTT Data — agentic NetOps <1% adoption
- Gartner via NetBrain — 80% of vendors shipping agentic capability by end 2027
- containerlab.dev — nodes, multi-node, config management
- batfish.readthedocs.io — differential questions, question framework
